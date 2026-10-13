use std::{
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::OwnedSemaphorePermit,
};
use tokio_util::sync::{CancellationToken, PollSemaphore};

use crate::{
    network_stream::*,
    tcp_gateway::{ConnectionEnd, TcpConnectionInner, TcpGatewayContract, MAX_PAYLOAD_CHUNK},
};

use super::{ForwardProxyHandlers, ProxyReceiveBuffer, ProxyReceiveClose};

/// What `to_plain_frame` puts around the payload of a `ForwardPayload`: the frame length, the
/// type and the connection id.
const FORWARD_PAYLOAD_FRAME_OVERHEAD: usize = 4 + 1 + 4;

/// The reason in the `RST` of a connection this side resets.
const RESET_BY_INITIATOR: &str = "The initiator reset the connection";

/// Stream of one proxy (outbound) connection.
///
/// Clones share one connection. The connection is closed once the last clone
/// is dropped - callers such as the h1 pipeline never close an upstream
/// explicitly, they drop it, and without this the peer's connection to the
/// upstream would stay open until the upstream itself gave up on it.
///
/// A close - a drop, a shutdown - ends the connection cleanly: the target gets
/// the end of the stream. A caller which failed resets it instead
/// ([`Self::abort`]): the target gets an error, not a stream which looks whole.
///
/// A stream split into halves ([`Self::split_halves`]) lives only while both
/// halves live: whichever is dropped first closes the connection.
///
/// It is also a `tokio::io::AsyncRead + AsyncWrite`, for the hyper based
/// clients (`my_http_client`) the http2 endpoints use.
pub struct TcpGatewayProxyForwardStream {
    shared: Arc<ProxyStreamShared>,
    _half: Option<Arc<StreamHalf>>,
    /// Where `poll_write` waits for write budget. Created on the first `poll_write` and never
    /// carried over to a clone: a wait in progress belongs to the stream that started it.
    write_budget: Option<PollSemaphore>,
    /// The permit count of the budget request `poll_write` is waiting on. Kept until it is
    /// granted, whatever the caller passes meanwhile: asking for another count would requeue the
    /// request behind every producer which queued since - and a hyper h2 client grows its buffer
    /// with every new stream, so it would never get its turn under load.
    pending_budget: Option<u32>,
    /// Where `poll_write` waits for the peer's credit. Like the budget wait, never carried over
    /// to a clone.
    window_wait: Option<PollSemaphore>,
    /// Credit `poll_write` holds while it waits for budget. Dropping it - with the stream, or on
    /// an error - gives the credit back.
    held_credit: Option<OwnedSemaphorePermit>,
}

impl Clone for TcpGatewayProxyForwardStream {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
            _half: self._half.clone(),
            write_budget: None,
            pending_budget: None,
            window_wait: None,
            held_credit: None,
        }
    }
}

struct ProxyStreamShared {
    connection_id: u32,
    gateway_connection_inner: Arc<TcpConnectionInner>,
    receive_buffer: Arc<ProxyReceiveBuffer>,
    handlers_map: Weak<ForwardProxyHandlers>,
}

/// One half of a split stream. A byte pump drops its half when its loop ends - on an error, a
/// timeout or the other side going away - and a connection with one direction gone is of no use:
/// closing it raises the connection's flag, so the loops holding the other half stop too instead
/// of waiting for their own timeouts.
struct StreamHalf {
    shared: Arc<ProxyStreamShared>,
}

impl Drop for StreamHalf {
    fn drop(&mut self) {
        self.shared.close();
    }
}

impl TcpGatewayProxyForwardStream {
    pub fn new(
        connection_id: u32,
        gateway_connection_inner: Arc<TcpConnectionInner>,
        receive_buffer: Arc<ProxyReceiveBuffer>,
        handlers_map: Weak<ForwardProxyHandlers>,
    ) -> Self {
        Self {
            shared: Arc::new(ProxyStreamShared {
                connection_id,
                gateway_connection_inner,
                receive_buffer,
                handlers_map,
            }),
            _half: None,
            write_budget: None,
            pending_budget: None,
            window_wait: None,
            held_credit: None,
        }
    }

    /// Credit for what this stream may still send.
    pub(crate) fn send_credit_available(&self) -> usize {
        self.shared.receive_buffer.send_window().available_permits()
    }

    /// Bytes received and not yet read.
    #[cfg(test)]
    pub fn buffered_for_tests(&self) -> usize {
        self.shared.receive_buffer.buffered_len()
    }

    #[cfg(test)]
    pub fn send_window_for_tests(&self) -> std::sync::Arc<tokio::sync::Semaphore> {
        self.shared.receive_buffer.send_window().clone()
    }

    /// Splits into a read and a write half; dropping either one closes the connection.
    pub fn split_halves(self) -> (Self, Self) {
        let half = |shared: &Arc<ProxyStreamShared>| Self {
            shared: shared.clone(),
            _half: Some(Arc::new(StreamHalf {
                shared: shared.clone(),
            })),
            write_budget: None,
            pending_budget: None,
            window_wait: None,
            held_credit: None,
        };

        (half(&self.shared), half(&self.shared))
    }

    /// Sends `payload` to the peer as frames of at most [`MAX_PAYLOAD_CHUNK`], each waiting for
    /// the peer's credit, then for room in the gateway write budget.
    pub async fn send_payload(&self, payload: &[u8]) -> bool {
        let closed = self.shared.receive_buffer.closed_token();
        let window = self.shared.receive_buffer.send_window();

        for chunk in payload.chunks(MAX_PAYLOAD_CHUNK) {
            // Closed - by the peer or locally: there is nobody to deliver to any more.
            if closed.is_cancelled() {
                return false;
            }

            let frame = TcpGatewayContract::ForwardPayload {
                connection_id: self.shared.connection_id,
                payload: chunk.into(),
            }
            .to_plain_frame();

            let send = async {
                // Credit first, budget second: waiting for the peer's reader never holds budget.
                let credit = match window.acquire_many(chunk.len() as u32).await {
                    Ok(permit) => permit,
                    // Closed together with the connection.
                    Err(_) => return false,
                };

                let sent = self
                    .shared
                    .gateway_connection_inner
                    .send_payload_with_backpressure(frame)
                    .await;

                // Spent once queued. A future dropped before - the close below, the caller's
                // write timeout - gives the credit back.
                credit.forget();

                sent
            };

            let sent = tokio::select! {
                sent = send => sent,
                // Closed while waiting for credit or for room in the write budget.
                _ = closed.cancelled() => false,
            };

            if !sent {
                self.reset_if_gateway_lost();
                return false;
            }
        }

        true
    }

    pub fn disconnect(&self) {
        self.shared.close();
    }

    /// Resets the connection: the peer resets its target connection, and this side's reader gets
    /// an error after what is buffered.
    pub fn abort(&self) {
        self.shared.abort();
    }

    /// Resets the connection from outside the stream - for code which hands the stream over to a
    /// library which keeps it, such as a websocket codec.
    pub fn abort_handle(&self) -> ProxyConnectionAbort {
        ProxyConnectionAbort {
            shared: Arc::downgrade(&self.shared),
        }
    }

    /// After a send which failed: a connection still open when a send fails has lost its gateway
    /// connection - its writer failed. The connection is cut short, and is reset here, before the
    /// gateway connection's teardown gets to it: a caller which shuts the stream down after a failed
    /// write would otherwise close it cleanly first. A connection closed already stays as it is.
    fn reset_if_gateway_lost(&self) {
        self.shared.abort();
    }

    /// Drops a budget request in progress, which hands its partly granted permits on - a request
    /// left queued would collect permits and hold them for as long as the stream lives - and the
    /// credit held or waited for, which goes back to the window.
    fn stop_waiting(&mut self) {
        self.write_budget = None;
        self.pending_budget = None;
        self.window_wait = None;
        self.held_credit = None;
    }

    /// Spends `used` bytes of the credit `poll_write` holds; the rest goes back to the window.
    fn spend_credit(&mut self, used: usize) {
        if let Some(mut credit) = self.held_credit.take() {
            let rest = credit.num_permits().saturating_sub(used);
            if rest > 0 {
                drop(credit.split(rest));
            }
            credit.forget();
        }
    }

    fn queue_chunk(&self, chunk: &[u8], budget: Option<u32>) -> Poll<std::io::Result<usize>> {
        let frame = TcpGatewayContract::ForwardPayload {
            connection_id: self.shared.connection_id,
            payload: chunk.into(),
        }
        .to_plain_frame();

        let inner = &self.shared.gateway_connection_inner;

        let queued = match budget {
            Some(budget) => inner.send_payload_with_reserved_budget(frame, budget),
            None => inner.send_payload(frame),
        };

        if queued {
            Poll::Ready(Ok(chunk.len()))
        } else {
            self.reset_if_gateway_lost();
            Poll::Ready(Err(not_connected()))
        }
    }
}

impl ProxyStreamShared {
    fn close(&self) {
        self.end(ConnectionEnd::Closed);
    }

    fn abort(&self) {
        self.end(ConnectionEnd::Reset(RESET_BY_INITIATOR));
    }

    fn end(&self, end: ConnectionEnd) {
        let close = match end {
            ConnectionEnd::Closed => ProxyReceiveClose::Closed,
            ConnectionEnd::Reset(_) => ProxyReceiveClose::Aborted,
        };

        // `close()` returns `true` only for whoever closes the buffer first. If it returns
        // `false` the connection was already torn down (by the peer, or together with the
        // gateway connection), so there is nothing left to clean up or notify.
        if !self.receive_buffer.close(close) {
            return;
        }

        // We ended the connection locally — notify the peer so it ends the matching forward
        // connection the same way. Queued behind the payloads sent before: the target gets them
        // all ahead of the end.
        let frame = end.to_contract(self.connection_id).to_plain_frame();

        self.gateway_connection_inner.send_payload(frame);

        // Drop our own handler from the registry so the proxy-connection count
        // goes down. Peer-initiated closes already remove it.
        if let Some(handlers_map) = self.handlers_map.upgrade() {
            handlers_map.lock().remove(&self.connection_id);
        }
    }
}

impl Drop for ProxyStreamShared {
    fn drop(&mut self) {
        self.close();
    }
}

/// Resets a proxy connection; see [`TcpGatewayProxyForwardStream::abort_handle`]. It does not keep
/// the connection: once every stream of it is dropped - which closes it - the handle does nothing.
#[derive(Clone)]
pub struct ProxyConnectionAbort {
    shared: Weak<ProxyStreamShared>,
}

impl ProxyConnectionAbort {
    pub fn abort(&self) {
        if let Some(shared) = self.shared.upgrade() {
            shared.abort();
        }
    }
}

#[async_trait::async_trait]
impl NetworkStreamReadPart for TcpGatewayProxyForwardStream {
    async fn read_from_socket(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        self.shared.receive_buffer.get_data(buf).await
    }

    fn abort_connection(&mut self) {
        self.abort();
    }
}

#[async_trait::async_trait]
impl NetworkStreamWritePart for TcpGatewayProxyForwardStream {
    async fn shutdown_socket(&mut self) {
        self.disconnect();
    }

    async fn abort_socket(&mut self) {
        self.abort();
    }

    async fn write_to_socket(&mut self, buffer: &[u8]) -> Result<(), std::io::Error> {
        if !self.send_payload(buffer).await {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "No connection",
            ));
        }

        Ok(())
    }

    async fn flush_it(&mut self) -> Result<(), NetworkError> {
        self.shared.gateway_connection_inner.flush().await?;
        Ok(())
    }

    fn connection_closed(&self) -> Option<CancellationToken> {
        Some(self.shared.receive_buffer.closed_token())
    }
}

impl AsyncRead for TcpGatewayProxyForwardStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let out = buf.initialize_unfilled();

        match self.shared.receive_buffer.poll_read(cx, out) {
            Poll::Ready(Ok(read_size)) => {
                buf.advance(read_size);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for TcpGatewayProxyForwardStream {
    /// Takes at most one frame's payload ([`MAX_PAYLOAD_CHUNK`]) per call, and only once the
    /// peer's credit for it and then its share of the write budget are acquired - until then it
    /// is `Pending` and nothing is taken, which is what
    /// backpressures the caller to the speed of the peer's reader and of the gateway link.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        if this.shared.receive_buffer.closed_token().is_cancelled() {
            this.stop_waiting();
            return Poll::Ready(Err(not_connected()));
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut want = buf.len().min(MAX_PAYLOAD_CHUNK);

        // Credit first. Not sticky, unlike the budget: only this connection's writers wait on its
        // window. Budget is asked for only while credit is held, so waiting for credit never
        // holds budget.
        if this.held_credit.is_none() {
            let window = this.shared.receive_buffer.send_window().clone();
            let acquired = this
                .window_wait
                .get_or_insert_with(|| PollSemaphore::new(window))
                .poll_acquire_many(cx, want as u32);

            match acquired {
                Poll::Ready(Some(credit)) => this.held_credit = Some(credit),
                // The window is closed together with the connection.
                Poll::Ready(None) => {
                    this.stop_waiting();
                    return Poll::Ready(Err(not_connected()));
                }
                // Woken by the peer's credit, or by the window closing with the connection.
                Poll::Pending => return Poll::Pending,
            }
        }

        // A buffer which grew since the credit was taken gets a short write.
        want = want.min(this.held_credit.as_ref().map_or(0, |c| c.num_permits()));

        let Some(semaphore) = this.shared.gateway_connection_inner.write_budget() else {
            // Not a gateway peer writer: there is no budget to wait for.
            this.spend_credit(want);
            return this.queue_chunk(&buf[..want], None);
        };

        let budget = *this.pending_budget.get_or_insert_with(|| {
            TcpConnectionInner::budget_for(FORWARD_PAYLOAD_FRAME_OVERHEAD + want)
        });

        let acquired = this
            .write_budget
            .get_or_insert_with(|| PollSemaphore::new(semaphore))
            .poll_acquire_many(cx, budget);

        match acquired {
            Poll::Ready(Some(permit)) => {
                permit.forget();
                this.pending_budget = None;
            }
            // The budget is closed together with the gateway connection.
            Poll::Ready(None) => {
                this.stop_waiting();
                this.reset_if_gateway_lost();
                return Poll::Ready(Err(not_connected()));
            }
            Poll::Pending => {
                // Woken by the budget, or by the connection closing meanwhile.
                if !this.shared.receive_buffer.register_writer(cx.waker()) {
                    this.stop_waiting();
                    return Poll::Ready(Err(not_connected()));
                }
                return Poll::Pending;
            }
        }

        // The budget may have been asked for an earlier, different buffer: write what it covers
        // (a short write is fine) and give the rest back.
        let covered = (budget as usize)
            .saturating_sub(FORWARD_PAYLOAD_FRAME_OVERHEAD)
            .max(1);
        let chunk_len = want.min(covered);
        let used = TcpConnectionInner::budget_for(FORWARD_PAYLOAD_FRAME_OVERHEAD + chunk_len);

        if used < budget {
            this.shared
                .gateway_connection_inner
                .return_budget(budget - used);
        }

        // The credit the chunk takes is spent; the rest goes back to the window.
        this.spend_credit(chunk_len);
        this.queue_chunk(&buf[..chunk_len], Some(used))
    }

    /// Queued frames are the gateway writer's to send; there is nothing to flush here.
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.disconnect();
        Poll::Ready(Ok(()))
    }
}

fn not_connected() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::NotConnected, "No connection")
}

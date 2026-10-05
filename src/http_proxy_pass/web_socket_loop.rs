use std::{
    panic::AssertUnwindSafe,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use futures::{
    stream::{SplitSink, SplitStream},
    FutureExt, SinkExt, StreamExt,
};
use hyper_tungstenite::{
    tungstenite::Message, HyperWebsocket, HyperWebsocketStream, WebSocketStream,
};
use my_http_client::MyHttpClientDisconnect;

use crate::{
    tcp_gateway::forwarded_connection::ProxyConnectionAbort, tcp_utils::ConnectionPumps,
    types::HttpTimeouts,
};

/// The upstream side of a websocket. Once a write to it fails - the upstream is gone - further
/// writes are dropped instead of failing, and `gone` says so. tungstenite answers a Ping it reads
/// with a Pong written from inside the read, and a failed write would fail the read: the
/// upstream's last frames, its Close among them, which are still to be delivered, would be lost.
struct UpstreamStream<S> {
    inner: S,
    gone: Arc<AtomicBool>,
}

impl<S> UpstreamStream<S> {
    /// Handles a write result: an error marks the upstream gone and reads as done.
    fn written<T>(&self, result: Poll<std::io::Result<T>>, done: T) -> Poll<std::io::Result<T>> {
        match result {
            Poll::Ready(Err(_)) => {
                self.gone.store(true, Ordering::Relaxed);
                Poll::Ready(Ok(done))
            }
            result => result,
        }
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for UpstreamStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for UpstreamStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.gone.load(Ordering::Relaxed) {
            return Poll::Ready(Ok(buf.len()));
        }
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        this.written(result, buf.len())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.gone.load(Ordering::Relaxed) {
            return Poll::Ready(Ok(()));
        }
        let result = Pin::new(&mut this.inner).poll_flush(cx);
        this.written(result, ())
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.gone.load(Ordering::Relaxed) {
            return Poll::Ready(Ok(()));
        }
        let result = Pin::new(&mut this.inner).poll_shutdown(cx);
        this.written(result, ())
    }
}

fn ws_message_payload_len(msg: &Message) -> u64 {
    match msg {
        Message::Text(s) => s.len() as u64,
        Message::Binary(b) => b.len() as u64,
        Message::Ping(b) | Message::Pong(b) => b.len() as u64,
        Message::Close(_) => 0,
        Message::Frame(f) => f.payload().len() as u64,
    }
}

/// What a websocket pump needs besides the two streams it links.
pub struct WebSocketPumpContext {
    pub log_scope: crate::app::ProxyLogScope,
    pub disconnection: Arc<dyn MyHttpClientDisconnect + Send + Sync + 'static>,
    pub trace_payload: bool,
    pub domain: Option<String>,
    pub timeouts: HttpTimeouts,
    /// Resets the upstream connection when the session fails: a gateway tunnel connection, which
    /// dropping would end as a clean close - its target would take a session cut short for a
    /// whole one. `None` for other upstreams.
    pub upstream_abort: Option<ProxyConnectionAbort>,
}

/// Resets the upstream connection of a failed session. Called while the caller still holds its
/// part of the upstream: once every part is dropped the connection is closed, cleanly.
pub(crate) fn reset_upstream(upstream_abort: Option<&ProxyConnectionAbort>) {
    if let Some(upstream_abort) = upstream_abort {
        upstream_abort.abort();
    }
}

pub async fn start_web_socket_loop<
    TStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
>(
    server_web_socket: HyperWebsocket,
    to_remote_stream: TStream,
    to_remote_leftover: Vec<u8>,
    ctx: WebSocketPumpContext,
) {
    let WebSocketPumpContext {
        log_scope,
        disconnection,
        trace_payload,
        domain,
        timeouts,
        upstream_abort,
    } = ctx;

    let panic_log_scope = log_scope.clone();
    let result = AssertUnwindSafe(async move {
        web_socket_loop(
            server_web_socket,
            to_remote_stream,
            to_remote_leftover,
            log_scope,
            trace_payload,
            domain,
            timeouts,
            upstream_abort,
        )
        .await;
    })
    .catch_unwind()
    .await;

    if result.is_err() {
        panic_log_scope.write("ws_loop_main panicked".to_string());
    }

    disconnection.web_socket_disconnect();
}

#[allow(clippy::too_many_arguments)]
async fn web_socket_loop<
    TStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
>(
    server_web_socket: HyperWebsocket,
    to_remote_stream: TStream,
    to_remote_leftover: Vec<u8>,
    log_scope: crate::app::ProxyLogScope,
    trace_payload: bool,
    domain: Option<String>,
    timeouts: HttpTimeouts,
    upstream_abort: Option<ProxyConnectionAbort>,
) {
    let ws_stream = server_web_socket.await;

    let upstream_gone = Arc::new(AtomicBool::new(false));
    let to_remote_stream = UpstreamStream {
        inner: to_remote_stream,
        gone: upstream_gone.clone(),
    };

    // `from_raw_socket` would start the decoder on an empty buffer and silently
    // drop whatever the upstream client had already read off the socket — for a
    // server that writes its first frame from the on-connected callback that is
    // usually the frame itself, glued to the `101` in one read(). Seed the
    // decoder with it instead.
    let to_remote = WebSocketStream::from_partially_read(
        to_remote_stream,
        to_remote_leftover,
        hyper_tungstenite::tungstenite::protocol::Role::Client,
        None,
    )
    .await;

    let (to_remote_write, mut from_remote_read) = to_remote.split();

    match ws_stream {
        Ok(ws_stream) => {
            let (mut ws_sender, ws_receiver) = ws_stream.split();

            // A write which timed out takes the other direction down with it: the peer is stuck,
            // and a write abandoned on a timeout may still be queued for gateway write budget,
            // holding it for as long as the stream lives. So does a read error, and a session which
            // went idle: neither direction moved a message for read_timeout. A silent direction
            // alone ends nothing - one side may just be pushing. Nor does a direction which ends
            // with a close or a failed write: its peer is gone, and the other direction still
            // forwards what that peer sent before going - a tunnelled upstream which answered and
            // closed refuses writes while its last frames, the Close among them, are still to be
            // read. A session which failed - a read error, a write timeout - resets the upstream
            // connection; one which went idle closes it.
            let session_over = tokio_util::sync::CancellationToken::new();
            let pumps = Arc::new(ConnectionPumps::new(timeouts));

            let client_to_upstream = crate::app::spawn_named("ws_loop_server_to_client", {
                let session_over = session_over.clone();
                let pumps = pumps.clone();
                let log_scope = log_scope.clone();
                let domain = domain.clone();
                let upstream_gone = upstream_gone.clone();
                let upstream_abort = upstream_abort.clone();
                async move {
                    let ended = serve_from_server_to_client(
                        ws_receiver,
                        to_remote_write,
                        log_scope,
                        trace_payload,
                        domain,
                        pumps,
                        upstream_gone,
                        upstream_abort,
                    )
                    .await;

                    if !matches!(ended, ClientToUpstreamEnd::Done) {
                        session_over.cancel();
                    }
                }
            });

            if trace_payload {
                log_scope.write("WS is starting reading message from remote".to_string());
            }

            let mut have_traced_message = false;

            let write_timeout = pumps.write_timeout();

            let mut end_the_other_direction = false;

            loop {
                let Some(time_left) = pumps.read_time_left() else {
                    end_the_other_direction = true;
                    break;
                };

                let future = from_remote_read.next();

                let result = tokio::select! {
                    result = tokio::time::timeout(time_left, future) => result,
                    _ = session_over.cancelled() => break,
                };

                // Nothing from the upstream: whether the session is idle depends on the client side.
                let Ok(result) = result else {
                    continue;
                };

                if result.is_none() {
                    break;
                }

                let message = result.unwrap();

                if message.is_err() {
                    log_scope.write(format!("Error in websocket connection: {:?}", message));

                    reset_upstream(upstream_abort.as_ref());
                    end_the_other_direction = true;
                    break;
                }

                let message = message.unwrap();
                pumps.bytes_moved();

                if trace_payload && !have_traced_message {
                    //println!("WS Message from remote: {:?}", message);
                    have_traced_message = true;
                }

                if let Some(d) = domain.as_deref() {
                    let bytes = ws_message_payload_len(&message);
                    crate::app::APP_CTX.traffic.record_ws_s2c(d, bytes);
                }

                match tokio::time::timeout(write_timeout, ws_sender.send(message)).await {
                    Err(_) => {
                        log_scope.write(format!(
                            "ws_sender.send timed out after {:?}",
                            write_timeout
                        ));
                        reset_upstream(upstream_abort.as_ref());
                        end_the_other_direction = true;
                        break;
                    }
                    Ok(Err(err)) => {
                        log_scope.write(format!("ws_sender.send error: {:?}", err));
                        break;
                    }
                    // A send which took its time still moved bytes.
                    Ok(Ok(())) => pumps.bytes_moved(),
                }
            }

            if end_the_other_direction {
                client_to_upstream.abort();
            }
        }
        Err(err) => {
            log_scope.write(format!("Error in websocket connection: {}", err));
            reset_upstream(upstream_abort.as_ref());
        }
    }
}

/// How the client-to-upstream direction of a websocket session ended.
enum ClientToUpstreamEnd {
    /// The client closed, or the upstream is gone: the other direction goes on.
    Done,
    /// Neither direction moved a message for read_timeout: the session ends.
    Idle,
    /// A read from the client failed, or a write to the upstream timed out: the session ends, and
    /// the upstream connection is reset.
    Failed,
}

#[allow(clippy::too_many_arguments)]
async fn serve_from_server_to_client<
    TStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
>(
    mut websocket: SplitStream<HyperWebsocketStream>,
    mut to_remote_write: SplitSink<WebSocketStream<TStream>, Message>,
    log_scope: crate::app::ProxyLogScope,
    trace_payload: bool,
    domain: Option<String>,
    pumps: Arc<ConnectionPumps>,
    upstream_gone: Arc<AtomicBool>,
    upstream_abort: Option<ProxyConnectionAbort>,
) -> ClientToUpstreamEnd {
    if trace_payload {
        log_scope.write("WS is starting reading message to remote".to_string());
    }

    let mut have_traced_message = false;

    // Set once the client's Close went to the upstream: the session is over on the client's side,
    // and how its transport ends then - a TLS client often drops it without a close_notify - is no
    // failure.
    let mut client_closed = false;

    let write_timeout = pumps.write_timeout();
    loop {
        let Some(time_left) = pumps.read_time_left() else {
            return ClientToUpstreamEnd::Idle;
        };

        let future = websocket.next();

        // Nothing from the client: whether the session is idle depends on the upstream side.
        let Ok(next_one) = tokio::time::timeout(time_left, future).await else {
            continue;
        };

        let Some(message) = next_one else {
            break;
        };

        let msg: Message = match message {
            Ok(msg) => msg,
            Err(_) if client_closed => break,
            Err(err) => {
                log_scope.write(format!(
                    "Error reading the websocket client in server_to_client loop: {:?}",
                    err
                ));
                reset_upstream(upstream_abort.as_ref());
                return ClientToUpstreamEnd::Failed;
            }
        };
        pumps.bytes_moved();
        let is_close = matches!(msg, Message::Close(_));

        if trace_payload && !have_traced_message {
            log_scope.write(format!("WS Message to remote: {:?}", msg));
            have_traced_message = true;
        }

        if let Some(d) = domain.as_deref() {
            let bytes = ws_message_payload_len(&msg);
            crate::app::APP_CTX.traffic.record_ws_c2s(d, bytes);
        }

        match tokio::time::timeout(write_timeout, to_remote_write.send(msg)).await {
            Err(_) => {
                log_scope.write(format!(
                    "to_remote_write.send timed out after {:?} in server_to_client loop",
                    write_timeout
                ));
                reset_upstream(upstream_abort.as_ref());
                return ClientToUpstreamEnd::Failed;
            }
            Ok(Err(err)) => {
                log_scope.write(format!(
                    "Error in websocket server_to_client loop: {:?}",
                    err
                ));
                return ClientToUpstreamEnd::Done;
            }
            Ok(Ok(())) => pumps.bytes_moved(),
        }

        client_closed |= is_close;

        // The upstream is gone: what was sent went nowhere, and the other direction still
        // delivers what the upstream sent before.
        if upstream_gone.load(Ordering::Relaxed) {
            log_scope.write("The upstream is gone - client_to_upstream ends".to_string());
            return ClientToUpstreamEnd::Done;
        }
    }

    ClientToUpstreamEnd::Done
}

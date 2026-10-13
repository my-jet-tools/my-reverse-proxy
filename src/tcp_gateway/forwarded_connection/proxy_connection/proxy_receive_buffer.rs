use std::{
    collections::VecDeque,
    sync::Arc,
    task::{Context, Poll, Waker},
};

use parking_lot::Mutex;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::tcp_gateway::ReceiveWindow;

/// Small payloads join the last chunk while it stays within this size: a backlog of tiny payloads
/// costs about its bytes, not a `Vec` per payload.
const COALESCE_LIMIT: usize = 64 * 1024;

/// Why a [`ProxyReceiveBuffer`] stopped taking data. Either way the reader first gets everything
/// already buffered - the peer sends a connection's last payloads right before it closes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyReceiveClose {
    /// The connection is closed cleanly - by the peer or locally. The reader then sees EOF.
    Closed,
    /// The connection is reset - by the peer or locally - or the gateway connection carrying it
    /// went down. The reader then gets an error: the stream may have been cut short.
    Aborted,
}

#[derive(Default)]
struct ReceiveState {
    chunks: VecDeque<Vec<u8>>,
    /// Bytes of the front chunk already handed to the reader.
    front_offset: usize,
    close: Option<ProxyReceiveClose>,
    /// The reader waiting for data or the close. There is a single reader per connection.
    reader: Option<Waker>,
    /// A `poll_write` waiting for write budget, woken when the connection closes meanwhile. One
    /// is enough: a budget wait ends anyway, when the budget comes or the gateway closes it. A
    /// wait for credit ends through the send window, which closes with the connection.
    writer: Option<Waker>,
}

impl ReceiveState {
    fn read_into(&mut self, out: &mut [u8]) -> usize {
        let mut written = 0;

        while written < out.len() {
            let Some(front) = self.chunks.front() else {
                break;
            };

            let available = &front[self.front_offset..];
            let size = available.len().min(out.len() - written);
            out[written..written + size].copy_from_slice(&available[..size]);
            written += size;
            self.front_offset += size;

            if self.front_offset == front.len() {
                self.chunks.pop_front();
                self.front_offset = 0;
            }
        }

        written
    }
}

/// Payloads received for one proxy connection, waiting for its reader. Its close state is the
/// state of the whole connection.
pub struct ProxyReceiveBuffer {
    state: Mutex<ReceiveState>,
    /// Cancelled together with the close, whatever closed the connection: the flag every loop
    /// working for this connection watches, so that a failure anywhere stops all of them -
    /// including a loop blocked in a read on its other side, which a plain flag would not wake.
    closed: CancellationToken,
    /// This side's window for what the peer sends.
    receive_window: ReceiveWindow,
    /// The peer's credit for what this side sends. Closed with the connection, which stops every
    /// writer waiting on it - however many clones wait.
    send_window: Arc<Semaphore>,
}

impl ProxyReceiveBuffer {
    /// The send window is empty until the peer's first credit, which comes ahead of its
    /// `CONNECT_OK`.
    pub fn new(receive_window: ReceiveWindow) -> Self {
        Self {
            state: Mutex::default(),
            closed: CancellationToken::new(),
            receive_window,
            send_window: Arc::new(Semaphore::new(0)),
        }
    }

    pub fn send_window(&self) -> &Arc<Semaphore> {
        &self.send_window
    }

    pub async fn get_data(&self, out: &mut [u8]) -> Result<usize, std::io::Error> {
        std::future::poll_fn(|cx| self.poll_read(cx, out)).await
    }

    /// Reads buffered data into `out`. Once the buffer is drained after a close: `Ok(0)` for a
    /// closed connection, an error for an aborted one.
    pub fn poll_read(
        &self,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let mut state = self.state.lock();

        let read_size = state.read_into(out);
        if read_size > 0 {
            let open = state.close.is_none();
            drop(state);

            // Credit for what the reader now has. Not after a close: the peer no longer knows
            // the id.
            if open {
                self.receive_window.consumed(read_size);
            }

            return Poll::Ready(Ok(read_size));
        }

        if out.is_empty() {
            return Poll::Ready(Ok(0));
        }

        match state.close {
            Some(ProxyReceiveClose::Closed) => Poll::Ready(Ok(0)),
            Some(ProxyReceiveClose::Aborted) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "The tunnelled connection is reset, or its gateway connection is lost",
            ))),
            None => {
                state.reader = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    /// Registers a `poll_write` which waits for write budget, so that a close wakes it. Returns
    /// `false` when the connection is already closed.
    pub fn register_writer(&self, waker: &Waker) -> bool {
        let mut state = self.state.lock();

        if state.close.is_some() {
            return false;
        }

        state.writer = Some(waker.clone());
        true
    }

    /// Buffers a payload from the peer. `false`: the peer sent past this side's window - the
    /// payload is not buffered, and the caller closes the connection.
    pub fn extend_from_slice(&self, payload: &[u8]) -> bool {
        let reader = {
            let mut state = self.state.lock();

            // Dropped, and not counted: the connection is closed.
            if state.close.is_some() {
                return true;
            }

            if !self.receive_window.received(payload.len()) {
                return false;
            }

            // Joining the front chunk is safe while the reader is in it: it reads what is past
            // `front_offset`, under the lock, and pops a chunk it read to the end.
            match state.chunks.back_mut() {
                Some(back) if back.len() + payload.len() <= COALESCE_LIMIT => {
                    back.extend_from_slice(payload)
                }
                _ => state.chunks.push_back(payload.to_vec()),
            }

            state.reader.take()
        };

        if let Some(reader) = reader {
            reader.wake();
        }

        true
    }

    /// Stops taking data. Returns `true` only for the call which closed the buffer.
    pub fn close(&self, reason: ProxyReceiveClose) -> bool {
        let (reader, writer) = {
            let mut state = self.state.lock();
            if state.close.is_some() {
                return false;
            }
            state.close = Some(reason);
            (state.reader.take(), state.writer.take())
        };

        self.closed.cancel();

        self.send_window.close();

        if let Some(reader) = reader {
            reader.wake();
        }

        if let Some(writer) = writer {
            writer.wake();
        }

        true
    }

    /// The connection's flag - cancelled once the connection is closed for any reason.
    pub fn closed_token(&self) -> CancellationToken {
        self.closed.clone()
    }

    /// Bytes received and not yet read.
    #[cfg(test)]
    pub fn buffered_len(&self) -> usize {
        let state = self.state.lock();
        state.chunks.iter().map(Vec::len).sum::<usize>() - state.front_offset
    }

    #[cfg(test)]
    pub fn chunk_count(&self) -> usize {
        self.state.lock().chunks.len()
    }
}

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, OnceLock,
};

use encryption::aes::AesKey;
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::network_stream::{MyOwnedWriteHalf, NetworkError};
use crate::tcp_gateway::ReceiveWindow;

/// Bytes of data frames a gateway peer lets queue up ahead of its socket. A producer which
/// finds the budget spent waits for the writer to catch up - that is what slows an upstream
/// read down to the speed of the gateway link instead of piling its data up in memory.
pub(crate) const GATEWAY_WRITE_BUDGET: usize = 2 * 1024 * 1024;

/// A frame on its way to the writer task. `budget` is the share of the write budget the frame
/// holds; the writer gives it back once the frame is on the socket.
pub struct OutgoingFrame {
    pub payload: Vec<u8>,
    pub budget: u32,
    /// `WINDOW_UPDATE`: the gateway writer sends it with its next batch, ahead of the frames
    /// queued before it.
    pub expedite: bool,
}

/// Channel-backed writer wrapper used by both gateway peer and forwarded
/// downstream connections.
///
/// In **gateway peer** mode the writer treats `send_payload` items as
/// plaintext inner frames (`[u32 LEN][u8 TYPE][PAYLOAD]`) and on each flush
/// either encrypts each one individually (no compression) or wraps the
/// batch into a `COMPRESSED_BATCH` frame and encrypts that.
///
/// In **raw passthrough** mode the writer just concatenates whatever bytes
/// it receives and writes them to the socket unmodified — used for the
/// forwarded TCP stream toward the downstream service.
///
/// The channel itself is unbounded, so a frame is never dropped for want of room: data frames
/// of a gateway peer are bounded by the write budget instead, see
/// [`Self::send_payload_with_backpressure`].
pub struct TcpConnectionInner {
    sender: parking_lot::Mutex<Option<mpsc::UnboundedSender<OutgoingFrame>>>,
    is_connected: AtomicBool,
    disconnected: CancellationToken,
    /// Cancelled when the raw passthrough writer task has ended - its last bytes handed to the
    /// socket and the write side shut down, or given up on. Never cancelled for a gateway peer.
    writer_finished: CancellationToken,
    /// Cancelled when the raw passthrough writer failed to hand bytes to its socket. Never
    /// cancelled for a gateway peer.
    write_failed: CancellationToken,
    /// Cancelled when the raw passthrough connection is reset: the writer drops what it holds and
    /// resets the target connection instead of flushing and shutting it down. Never cancelled for
    /// a gateway peer.
    reset: CancellationToken,
    write_budget: Option<Arc<Semaphore>>,
    aes_key_opt: Option<Arc<AesKey>>,
    /// Gateway peer: the capabilities both ends have, once the peer's are known - which of the
    /// extensions' frames may go to the peer. Fixed for the life of the gateway connection.
    negotiated: OnceLock<u8>,
}

impl TcpConnectionInner {
    pub fn new_gateway_peer(
        write_half: MyOwnedWriteHalf,
        aes_key: Arc<AesKey>,
        compress_outbound: bool,
    ) -> Arc<Self> {
        let (sender, receiver) = mpsc::unbounded_channel();
        let disconnected = CancellationToken::new();
        let write_budget = Arc::new(Semaphore::new(GATEWAY_WRITE_BUDGET));

        let result = Arc::new(Self {
            sender: parking_lot::Mutex::new(Some(sender)),
            is_connected: AtomicBool::new(true),
            disconnected: disconnected.clone(),
            writer_finished: CancellationToken::new(),
            write_failed: CancellationToken::new(),
            reset: CancellationToken::new(),
            write_budget: Some(write_budget.clone()),
            aes_key_opt: Some(aes_key.clone()),
            negotiated: OnceLock::new(),
        });

        crate::app::spawn_named(
            "tcp_gateway_write_loop_encrypted",
            crate::tcp_gateway::session::gateway_write_loop(
                write_half,
                receiver,
                aes_key,
                compress_outbound,
                disconnected,
                write_budget,
            ),
        );

        result
    }

    /// `receive_window`: the connection's window for the payload the raw writer hands to the
    /// target - `Some` on a flow-controlled connection, credited back as the target takes it.
    pub fn new_raw_passthrough(
        write_half: MyOwnedWriteHalf,
        receive_window: Option<Arc<ReceiveWindow>>,
    ) -> Arc<Self> {
        let (sender, receiver) = mpsc::unbounded_channel();
        let disconnected = CancellationToken::new();
        let writer_finished = CancellationToken::new();
        let write_failed = CancellationToken::new();
        let reset = CancellationToken::new();
        let result = Arc::new(Self {
            sender: parking_lot::Mutex::new(Some(sender)),
            is_connected: AtomicBool::new(true),
            disconnected: disconnected.clone(),
            writer_finished: writer_finished.clone(),
            write_failed: write_failed.clone(),
            reset: reset.clone(),
            write_budget: None,
            aes_key_opt: None,
            negotiated: OnceLock::new(),
        });

        crate::app::spawn_named(
            "tcp_gateway_write_loop_raw",
            crate::tcp_gateway::session::raw_write_loop(
                write_half,
                receiver,
                crate::tcp_gateway::session::RawWriterSignals {
                    disconnected,
                    writer_finished,
                    write_failed,
                    reset,
                },
                receive_window,
            ),
        );

        result
    }

    /// Fixes the capabilities both ends have. Returns `false` when they were fixed already - by an
    /// earlier PING or PONG - and are left as they are.
    pub fn set_negotiated_capabilities(&self, capabilities: u8) -> bool {
        self.negotiated.set(capabilities).is_ok()
    }

    /// The capabilities both ends have; `None` while the peer's are not known yet.
    pub fn negotiated_capabilities(&self) -> Option<u8> {
        self.negotiated.get().copied()
    }

    /// Whether the peer is known to take the frames of `capability`.
    pub fn peer_takes(&self, capability: u8) -> bool {
        self.negotiated
            .get()
            .is_some_and(|negotiated| negotiated & capability == capability)
    }

    /// Returns the gateway peer's AES key. Panics if invoked on a raw
    /// passthrough writer (which is a programming error: only gateway peer
    /// inners hold a key).
    pub fn aes_key(&self) -> &Arc<AesKey> {
        self.aes_key_opt
            .as_ref()
            .expect("aes_key() invoked on raw passthrough writer")
    }

    /// Queues a frame outside the write budget. Used for control frames - they are small, and
    /// the read loop must never wait for budget - and by the raw passthrough writer, which has no
    /// budget. A control frame still queues behind the frames already in the queue.
    pub fn send_payload(&self, payload: Vec<u8>) -> bool {
        self.enqueue(OutgoingFrame {
            payload,
            budget: 0,
            expedite: false,
        })
    }

    /// Queues a `WINDOW_UPDATE`: no write budget, never waits, and it goes out with the gateway
    /// writer's next batch, ahead of everything queued before it - credit which waited behind
    /// other connections' data would tie one connection's speed to the others'. Never used for a
    /// ping: pings keep their place in the queue.
    pub fn send_expedited(&self, payload: Vec<u8>) -> bool {
        self.enqueue(OutgoingFrame {
            payload,
            budget: 0,
            expedite: true,
        })
    }

    /// Queues a data frame, first waiting for its share of the write budget.
    ///
    /// Never call it from a gateway read loop: a read loop waiting for its own writer stops
    /// reading, and the peer it stops reading from may be waiting on it in just the same way.
    pub async fn send_payload_with_backpressure(&self, payload: Vec<u8>) -> bool {
        let Some(write_budget) = self.write_budget.as_ref() else {
            return self.send_payload(payload);
        };

        let budget = Self::budget_for(payload.len());

        match write_budget.acquire_many(budget).await {
            Ok(permit) => permit.forget(),
            // Closed: the connection is gone.
            Err(_) => return false,
        }

        self.send_payload_with_reserved_budget(payload, budget)
    }

    /// The share of the write budget a frame of `frame_len` bytes takes.
    pub fn budget_for(frame_len: usize) -> u32 {
        frame_len.clamp(1, GATEWAY_WRITE_BUDGET) as u32
    }

    /// The write budget, for a caller which has to wait for it in a `poll_*` function - `None`
    /// for the raw passthrough writer, which has no budget.
    pub fn write_budget(&self) -> Option<Arc<Semaphore>> {
        self.write_budget.clone()
    }

    /// Queues a data frame for which the caller has already taken `budget` permits of the write
    /// budget (and forgotten them). They go back if the frame can not be queued.
    pub fn send_payload_with_reserved_budget(&self, payload: Vec<u8>, budget: u32) -> bool {
        if self.enqueue(OutgoingFrame {
            payload,
            budget,
            expedite: false,
        }) {
            return true;
        }

        self.return_budget(budget);
        false
    }

    /// Gives back permits a caller took from the write budget and does not use.
    pub fn return_budget(&self, budget: u32) {
        if let Some(write_budget) = self.write_budget.as_ref() {
            write_budget.add_permits(budget as usize);
        }
    }

    fn enqueue(&self, frame: OutgoingFrame) -> bool {
        if !self.is_connected.load(Ordering::Relaxed) {
            return false;
        }
        let guard = self.sender.lock();
        let Some(sender) = guard.as_ref() else {
            return false;
        };
        sender.send(frame).is_ok()
    }

    pub fn is_connected(&self) -> bool {
        self.is_connected.load(Ordering::Relaxed) && !self.disconnected.is_cancelled()
    }

    /// Cancelled once the connection is disconnected - from this side, or because the gateway
    /// writer could not write any more.
    pub fn disconnected_token(&self) -> CancellationToken {
        self.disconnected.clone()
    }

    pub fn writer_finished_token(&self) -> CancellationToken {
        self.writer_finished.clone()
    }

    /// The raw passthrough writer failed to hand bytes to its socket.
    pub fn write_failed(&self) -> bool {
        self.write_failed.is_cancelled()
    }

    /// The state after a failed write to the target: the flag down, the writer stopped.
    #[cfg(test)]
    pub(crate) fn fail_writes_for_tests(&self) {
        self.write_failed.cancel();
        self.disconnect();
    }

    /// Raw passthrough: closes the connection with a reset - the writer drops what it holds and
    /// resets the target connection, which gets an error instead of the end of the stream.
    pub fn reset(&self) {
        // Before the disconnect: the writer, seeing its queue end, looks at it to tell a reset
        // from a close.
        self.reset.cancel();
        self.disconnect();
    }

    pub fn is_reset(&self) -> bool {
        self.reset.is_cancelled()
    }

    pub fn reset_token(&self) -> CancellationToken {
        self.reset.clone()
    }

    /// Stops taking frames. A raw passthrough writer still flushes what it has queued before it
    /// shuts its socket down; a gateway peer writer stops at once.
    pub fn disconnect(&self) -> bool {
        let was_connected = self.is_connected.swap(false, Ordering::Relaxed);
        self.sender.lock().take();
        self.disconnected.cancel();
        if let Some(write_budget) = self.write_budget.as_ref() {
            // Wakes the producers waiting for budget - there is nothing to wait for any more.
            write_budget.close();
        }
        was_connected
    }

    pub async fn flush(&self) -> Result<(), NetworkError> {
        Ok(())
    }
}

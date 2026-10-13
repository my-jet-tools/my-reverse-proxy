use std::{collections::VecDeque, future::Future, pin::Pin, sync::Arc, time::Duration};

use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;

use crate::network_stream::{MyOwnedWriteHalf, NetworkStreamWritePart};
use crate::tcp_gateway::{OutgoingFrame, ReceiveWindow};

/// How long a closing connection may take to hand its last bytes to the downstream service.
const CLOSE_FLUSH_TIMEOUT: Duration = Duration::from_secs(30);

/// The most bytes handed to the downstream service in one write. The connection's credit goes
/// back after each write, so it returns in steps of this size, not once per backlog.
const RAW_WRITE_BATCH: usize = 256 * 1024;

type WriteFuture = Pin<Box<dyn Future<Output = Result<(), std::io::Error>> + Send>>;

/// What the raw writer of one connection shares with the rest of the connection.
pub struct RawWriterSignals {
    /// The connection's flag: the writer lowers it when a write fails.
    pub disconnected: CancellationToken,
    /// Cancelled however the writer ends.
    pub writer_finished: CancellationToken,
    /// Cancelled when a write failed, or the close flush gave up.
    pub write_failed: CancellationToken,
    /// Cancelled when the connection is reset.
    pub reset: CancellationToken,
}

/// Raw passthrough writer task — used by `TcpGatewayForwardConnection` to
/// shovel bytes toward a downstream service. No encryption, no framing.
///
/// When the connection is closed (the sender is dropped) everything received
/// before the close still goes to the downstream service before the socket is
/// shut down: a peer which sends its last bytes and closes right after must not
/// lose the tail of the stream. A tail the service does not take within
/// [`CLOSE_FLUSH_TIMEOUT`] is given up on, and the connection is reset rather
/// than shut down, so the service does not take what it got for all of it.
///
/// When the connection is reset - the peer reset it, or the gateway connection
/// is gone - what is not written yet is dropped and the connection is reset at
/// once, whatever the writer was doing: the stream is broken, and the service
/// must not see it end as a whole one.
///
/// A failed write cancels `write_failed`, and `disconnected`, the connection's
/// flag: the upstream read loop of the same connection sees it, stops, and the
/// peer is told.
///
/// `receive_window` gets the bytes each write handed to the service: the peer
/// may send as many more.
pub async fn raw_write_loop(
    write_half: MyOwnedWriteHalf,
    mut rx: mpsc::UnboundedReceiver<OutgoingFrame>,
    signals: RawWriterSignals,
    receive_window: Arc<ReceiveWindow>,
) {
    let RawWriterSignals {
        disconnected,
        writer_finished,
        write_failed,
        reset,
    } = signals;

    // However the writer ends, the connection's read loop waits for it before it lets the
    // socket go.
    let _finished = writer_finished.drop_guard();

    // A write in flight locks the write half while it writes. Dropping the write - on a reset, or
    // when the close flush gives up - unlocks it again, so the socket can still be reset then.
    let write_half = Arc::new(Mutex::new(write_half));

    let mut queue: VecDeque<Vec<u8>> = VecDeque::new();
    let mut write_fut: Option<WriteFuture> = None;
    let mut in_flight = 0usize;

    loop {
        if write_fut.is_none() {
            if let Some(batch) = queue.pop_front() {
                in_flight = batch.len();
                write_fut = Some(write_batch(write_half.clone(), batch));
            }
        }

        // Not biased: neither taking frames nor writing them may starve the other. A reset ends
        // the queue too, so the loop may end on either - which is told apart after it.
        tokio::select! {
            _ = reset.cancelled() => break,

            msg = rx.recv() => {
                match msg {
                    Some(frame) => push_coalesced(&mut queue, frame.payload),
                    None => break,
                }
            }

            io_res = async { write_fut.as_mut().unwrap().as_mut().await }, if write_fut.is_some() => {
                write_fut = None;
                if let Err(err) = io_res {
                    // Before anything else: a read loop which sees the upstream close right now
                    // looks at it to tell a clean close from one which lost data.
                    write_failed.cancel();
                    disconnected.cancel();
                    eprintln!("raw_write_loop: write failure: {:?}", err);
                    // Dropping the write half shuts the socket down. No credit for what is
                    // dropped: the connection is ending.
                    return;
                }

                // The service took these bytes: the peer may send as many more.
                receive_window.consumed(std::mem::take(&mut in_flight));
            }
        }
    }

    // No credit from here on: the connection is closed, the peer no longer knows its id.
    let flush = async {
        if let Some(write_fut) = write_fut.take() {
            if write_fut.await.is_err() {
                return false;
            }
        }

        let mut half = write_half.lock().await;

        for batch in queue.drain(..) {
            if half.write_to_socket(&batch).await.is_err() {
                return false;
            }
        }

        half.shutdown_socket().await;
        true
    };

    // A reset - also one which ended the loop above - is looked at first: it is never taken for a
    // close.
    let flushed = tokio::select! {
        biased;
        _ = reset.cancelled() => None,
        flushed = tokio::time::timeout(CLOSE_FLUSH_TIMEOUT, flush) => Some(flushed),
    };

    match flushed {
        Some(Ok(true)) => {}
        // The write failed: the socket is broken already.
        Some(Ok(false)) => write_failed.cancel(),
        Some(Err(_)) => {
            write_failed.cancel();
            eprintln!(
                "raw_write_loop: the downstream service took no more within {:?}; resetting the connection",
                CLOSE_FLUSH_TIMEOUT
            );

            reset_write_half(write_fut, write_half);
        }
        None => reset_write_half(write_fut, write_half),
    }
}

/// Resets the connection through `write_half` - see [`MyOwnedWriteHalf::reset`] - once the write
/// in flight is dropped: then nothing else holds the write half.
fn reset_write_half(write_fut: Option<WriteFuture>, write_half: Arc<Mutex<MyOwnedWriteHalf>>) {
    drop(write_fut);

    if let Ok(write_half) = Arc::try_unwrap(write_half) {
        write_half.into_inner().reset();
    }
}

/// Appends `payload` to the last batch while that stays within [`RAW_WRITE_BATCH`] - a backlog of
/// small frames costs about its bytes - and otherwise queues the payload's own `Vec` as a batch,
/// moved, without a copy.
fn push_coalesced(queue: &mut VecDeque<Vec<u8>>, payload: Vec<u8>) {
    match queue.back_mut() {
        Some(back) if back.len() + payload.len() <= RAW_WRITE_BATCH => {
            back.extend_from_slice(&payload)
        }
        _ => queue.push_back(payload),
    }
}

#[cfg(test)]
pub(crate) fn push_coalesced_for_tests(queue: &mut VecDeque<Vec<u8>>, payload: Vec<u8>) {
    push_coalesced(queue, payload)
}

fn write_batch(write_half: Arc<Mutex<MyOwnedWriteHalf>>, batch: Vec<u8>) -> WriteFuture {
    Box::pin(async move { write_half.lock().await.write_to_socket(&batch).await })
}

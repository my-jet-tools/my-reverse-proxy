use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use tokio::sync::{mpsc, Notify};

use super::ResponseSlot;

/// The ordered queue of response slots from the reader to the writer, counting the responses
/// which are not written out yet.
///
/// The count is what the request-head deadline (`header_read_timeout`) starts from: the reader
/// waits for the next request right after it dispatched one, and a client does not send it
/// before it has the answer. While an answer is still going out - a slow upstream, a long
/// download, a long poll - the wait is not the client's, and is not timed as such.
pub struct ResponseQueue {
    sender: mpsc::Sender<ResponseSlot>,
    in_flight: Arc<InFlightResponses>,
}

impl ResponseQueue {
    pub fn new(capacity: usize) -> (Self, mpsc::Receiver<ResponseSlot>, Arc<InFlightResponses>) {
        let (sender, receiver) = mpsc::channel(capacity);
        let in_flight = Arc::new(InFlightResponses::new());

        let queue = Self {
            sender,
            in_flight: in_flight.clone(),
        };

        (queue, receiver, in_flight)
    }

    /// `Err` when the writer is gone: the connection is finished.
    pub async fn send(&self, slot: ResponseSlot) -> Result<(), ()> {
        self.in_flight.started();
        self.sender.send(slot).await.map_err(|_| ())
    }

    pub fn in_flight(&self) -> &InFlightResponses {
        &self.in_flight
    }
}

/// Responses queued or being written. The writer reports each one it wrote out to the end;
/// one it could not is the end of the connection, so it is never reported.
pub struct InFlightResponses {
    count: AtomicUsize,
    idle: Notify,
}

impl InFlightResponses {
    fn new() -> Self {
        Self {
            count: AtomicUsize::new(0),
            idle: Notify::new(),
        }
    }

    fn started(&self) {
        self.count.fetch_add(1, Ordering::AcqRel);
    }

    pub fn finished(&self) {
        if self.count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.idle.notify_one();
        }
    }

    pub fn is_idle(&self) -> bool {
        self.count.load(Ordering::Acquire) == 0
    }

    /// Resolves after the last response was written out - or spuriously, for one that was
    /// finished before anybody waited: check [`Self::is_idle`] again.
    pub async fn wait_idle(&self) {
        self.idle.notified().await;
    }
}

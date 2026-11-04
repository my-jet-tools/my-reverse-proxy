use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use tokio::sync::Notify;

/// The deadline for the first request of a connection served by hyper (`http2` and `https2`
/// endpoints).
///
/// hyper times the head of an http/1.1 request (`header_read_timeout`, with a timer), but not
/// what comes before it: the auto builder of an `https2` endpoint first reads the opening bytes
/// to tell h2 from http/1.1, and an h2 connection waits for the client preface and its first
/// HEADERS - all with no limit, so a client which connects and sends nothing would hold the
/// connection for as long as TCP does. Until a request reaches the service, the connection has
/// `header_read_timeout`; after that hyper's own timeouts and the h2 PINGs take over.
pub struct FirstRequestDeadline {
    arrived: AtomicBool,
    notify: Notify,
}

impl FirstRequestDeadline {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            arrived: AtomicBool::new(false),
            notify: Notify::new(),
        })
    }

    /// Called by the service for every request.
    pub fn request_arrived(&self) {
        if !self.arrived.swap(true, Ordering::AcqRel) {
            // Kept as a permit when nobody waits yet.
            self.notify.notify_one();
        }
    }

    async fn wait(&self) {
        if self.arrived.load(Ordering::Acquire) {
            return;
        }

        self.notify.notified().await;
    }

    /// Serves `connection` to its end - or drops it, which closes it, when no request reached
    /// the service within `timeout`. `None` in that case.
    pub async fn serve<TConnection: Future>(
        &self,
        connection: TConnection,
        timeout: Duration,
    ) -> Option<TConnection::Output> {
        tokio::pin!(connection);

        tokio::select! {
            output = &mut connection => return Some(output),
            arrived = tokio::time::timeout(timeout, self.wait()) => {
                if arrived.is_err() {
                    return None;
                }
            }
        }

        Some(connection.await)
    }
}

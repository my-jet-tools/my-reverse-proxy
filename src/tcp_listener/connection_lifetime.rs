use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicU32, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use tokio::sync::Notify;

/// What becomes of a connection served by hyper (`http2` and `https2` endpoints) past its first
/// request - nginx's `keepalive_timeout` and `keepalive_requests`:
/// - an h2 connection with no request on it for `h2_idle_timeout` is closed with a GOAWAY. A
///   client which answers the PINGs would otherwise hold it as long as it likes;
/// - after `max_requests_per_connection` requests the connection is closed the same way - an h2
///   one with a GOAWAY, an http/1.1 one once the answer to the last request is out - and the
///   client opens another.
///
/// The requests on their way are served to their end either way. An http/1.1 connection which
/// waits for its next request is closed by hyper itself, at `header_read_timeout`.
pub struct ConnectionLifetime {
    /// Requests whose answers are not out yet.
    active: AtomicUsize,
    /// Requests the connection got.
    requests: AtomicU32,
    /// A request came, or its answer is out.
    changed: Notify,
}

impl ConnectionLifetime {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            active: AtomicUsize::new(0),
            requests: AtomicU32::new(0),
            changed: Notify::new(),
        })
    }

    /// A request came: it is on the connection until the guard is dropped - with its answer.
    pub fn request_started(self: &Arc<Self>) -> ActiveRequest {
        self.requests.fetch_add(1, Ordering::AcqRel);
        self.active.fetch_add(1, Ordering::AcqRel);
        self.changed.notify_waiters();

        ActiveRequest {
            lifetime: self.clone(),
        }
    }

    /// Serves `connection` to its end. Once it was idle for `idle_timeout`, or got
    /// `max_requests`, `graceful_shutdown` is called on it - it finishes what it serves and
    /// closes - and it is served to that end.
    pub async fn serve<C, F>(
        &self,
        connection: C,
        graceful_shutdown: F,
        idle_timeout: Duration,
        max_requests: u32,
    ) -> C::Output
    where
        C: Future,
        F: FnOnce(Pin<&mut C>),
    {
        tokio::pin!(connection);

        tokio::select! {
            output = &mut connection => return output,
            _ = self.time_to_close(idle_timeout, max_requests) => {}
        }

        graceful_shutdown(connection.as_mut());

        connection.await
    }

    async fn time_to_close(&self, idle_timeout: Duration, max_requests: u32) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            // Registered before the counters are read: a change between the read and the wait
            // is not missed.
            changed.as_mut().enable();

            if self.requests.load(Ordering::Acquire) >= max_requests {
                return;
            }

            if self.active.load(Ordering::Acquire) == 0 {
                if tokio::time::timeout(idle_timeout, changed).await.is_err() {
                    return;
                }
            } else {
                changed.await;
            }
        }
    }
}

/// A request on its connection: see [`ConnectionLifetime::request_started`].
pub struct ActiveRequest {
    lifetime: Arc<ConnectionLifetime>,
}

impl Drop for ActiveRequest {
    fn drop(&mut self) {
        self.lifetime.active.fetch_sub(1, Ordering::AcqRel);
        self.lifetime.changed.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::AtomicBool,
        task::{Context, Poll},
    };

    use super::*;

    /// A connection which ends only after it was told to shut down - as hyper's does once the
    /// requests on it are served.
    struct Connection {
        shutdown: Arc<AtomicBool>,
    }

    impl Future for Connection {
        type Output = &'static str;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.shutdown.load(Ordering::Acquire) {
                return Poll::Ready("shut down");
            }

            // Looked at again soon: the test has no other way to wake it.
            let waker = cx.waker().clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(10)).await;
                waker.wake();
            });

            Poll::Pending
        }
    }

    fn connection() -> (Connection, Arc<AtomicBool>) {
        let shutdown = Arc::new(AtomicBool::new(false));
        (
            Connection {
                shutdown: shutdown.clone(),
            },
            shutdown,
        )
    }

    fn shut_down(connection: Pin<&mut Connection>) {
        connection.shutdown.store(true, Ordering::Release);
    }

    #[tokio::test]
    async fn an_idle_connection_is_shut_down_after_the_idle_timeout() {
        let lifetime = ConnectionLifetime::new();
        let (connection, shutdown) = connection();

        let started = tokio::time::Instant::now();
        let output = tokio::time::timeout(
            Duration::from_secs(5),
            lifetime.serve(connection, shut_down, Duration::from_millis(300), 1000),
        )
        .await
        .expect("an idle connection is still served");

        assert_eq!(output, "shut down");
        assert!(shutdown.load(Ordering::Acquire));
        assert!(started.elapsed() >= Duration::from_millis(300));
    }

    #[tokio::test]
    async fn a_connection_with_a_request_on_it_is_not_idle() {
        let lifetime = ConnectionLifetime::new();
        let (connection, shutdown) = connection();

        let request = lifetime.request_started();
        let serving = tokio::spawn({
            let lifetime = lifetime.clone();
            async move {
                lifetime
                    .serve(connection, shut_down, Duration::from_millis(200), 1000)
                    .await
            }
        });

        // Five idle timeouts with the request on the way: still served.
        tokio::time::sleep(Duration::from_millis(1000)).await;
        assert!(!shutdown.load(Ordering::Acquire));

        // Its answer is out: the idle time starts.
        drop(request);
        let started = tokio::time::Instant::now();
        let output = tokio::time::timeout(Duration::from_secs(5), serving)
            .await
            .expect("an idle connection is still served")
            .unwrap();
        assert_eq!(output, "shut down");
        assert!(started.elapsed() >= Duration::from_millis(150));
    }

    #[tokio::test]
    async fn after_the_most_requests_the_connection_is_shut_down() {
        let lifetime = ConnectionLifetime::new();
        let (connection, shutdown) = connection();

        let serving = tokio::spawn({
            let lifetime = lifetime.clone();
            async move {
                lifetime
                    .serve(connection, shut_down, Duration::from_secs(1000), 3)
                    .await
            }
        });

        for _ in 0..2 {
            drop(lifetime.request_started());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!shutdown.load(Ordering::Acquire), "two of three");

        // The third one is still served: the shutdown lets it finish.
        let _third = lifetime.request_started();
        let output = tokio::time::timeout(Duration::from_secs(5), serving)
            .await
            .expect("a connection past its most requests is still served")
            .unwrap();
        assert_eq!(output, "shut down");
    }
}

use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::body::{Body, Frame, SizeHint};
use tokio::sync::Notify;

use crate::{access_log::AccessRecord, configurations::HttpEndpointInfo};

use super::{ActiveRequest, ConnectionCut};

/// Who takes the blame when an answer is not taken: written to the log of the endpoint.
#[derive(Clone)]
pub struct SendTimeout {
    /// What the connection is cut with.
    pub cut: Arc<ConnectionCut>,
    /// The endpoint's `write_timeout`.
    pub timeout: Duration,
    pub endpoint: Option<Arc<HttpEndpointInfo>>,
    pub ip: Option<String>,
}

/// The body of an answer of a connection served by hyper (`http2` and `https2` endpoints), as it
/// goes out - nginx's `send_timeout`.
///
/// hyper asks the body for its next frame only once it can send it on: an h2 stream whose window
/// the client keeps shut, or an http/1.1 client which reads nothing, is never asked for one again.
/// Such a client would hold the answer - and the upstream connection it is read from - for as
/// long as it likes. So once a frame was handed to hyper with more to come, hyper has to come
/// back for the next one within `write_timeout`; if it does not, the connection is cut. A body
/// which waits for its upstream is not timed: the client is not to blame for that.
///
/// The request is on its connection (see [`ActiveRequest`]) until the body is dropped.
pub struct WatchedResponseBody {
    inner: BoxBody<Bytes, String>,
    _request: ActiveRequest,
    send_timeout: SendTimeout,
    /// Started with the first frame which has more after it: an answer of one frame is out as
    /// soon as hyper has it.
    watch: Option<Arc<SendWatch>>,
    /// The line of the access log, written when the body is dropped: with the status, the bytes
    /// of the body which went out, and whether all of it did.
    access: Option<AccessRecord>,
    status: u16,
    body_bytes: u64,
    whole: bool,
}

impl WatchedResponseBody {
    pub fn new(
        inner: BoxBody<Bytes, String>,
        request: ActiveRequest,
        send_timeout: SendTimeout,
        access: Option<AccessRecord>,
        status: u16,
    ) -> Self {
        Self {
            inner,
            _request: request,
            send_timeout,
            watch: None,
            access,
            status,
            body_bytes: 0,
            whole: false,
        }
    }
}

impl Body for WatchedResponseBody {
    type Data = Bytes;
    type Error = String;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();

        // hyper came back for more.
        if let Some(watch) = this.watch.as_ref() {
            watch.taken();
        }

        let frame = Pin::new(&mut this.inner).poll_frame(cx);

        if let Poll::Ready(Some(Ok(frame))) = &frame {
            if let Some(data) = frame.data_ref() {
                this.body_bytes += data.len() as u64;
            }
        }

        match &frame {
            Poll::Ready(None) => this.whole = true,
            Poll::Ready(Some(Ok(_))) if this.inner.is_end_stream() => this.whole = true,
            _ => {}
        }

        match &frame {
            Poll::Ready(Some(Ok(_))) if !this.inner.is_end_stream() => {
                let send_timeout = &this.send_timeout;
                this.watch
                    .get_or_insert_with(|| SendWatch::start(send_timeout))
                    .handed_over();
            }
            Poll::Ready(_) => {
                if let Some(watch) = this.watch.take() {
                    watch.finish();
                }
            }
            Poll::Pending => {}
        }

        frame
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for WatchedResponseBody {
    fn drop(&mut self) {
        if let Some(watch) = self.watch.take() {
            watch.finish();
        }

        if let Some(access) = self.access.take() {
            let whole = self.whole || self.inner.is_end_stream();
            access.answered(self.status, self.body_bytes, whole);
        }
    }
}

/// The task which cuts the connection of an answer hyper stopped asking for.
struct SendWatch {
    started: tokio::time::Instant,
    /// When a frame was handed to hyper, which has not come back for the next one since: in
    /// milliseconds from `started`, plus one. 0: hyper came back.
    handed_over_at: AtomicU64,
    finished: AtomicBool,
    finished_notify: Notify,
}

impl SendWatch {
    fn start(send_timeout: &SendTimeout) -> Arc<Self> {
        let watch = Arc::new(Self {
            started: tokio::time::Instant::now(),
            handed_over_at: AtomicU64::new(0),
            finished: AtomicBool::new(false),
            finished_notify: Notify::new(),
        });

        let task_watch = watch.clone();
        let send_timeout = send_timeout.clone();
        crate::app::spawn_named("response_send_watch", async move {
            task_watch.run(send_timeout).await;
        });

        watch
    }

    fn now(&self) -> u64 {
        self.started.elapsed().as_millis() as u64 + 1
    }

    fn handed_over(&self) {
        self.handed_over_at.store(self.now(), Ordering::Release);
    }

    fn taken(&self) {
        self.handed_over_at.store(0, Ordering::Release);
    }

    fn finish(&self) {
        self.finished.store(true, Ordering::Release);
        self.finished_notify.notify_waiters();
    }

    async fn run(&self, send_timeout: SendTimeout) {
        loop {
            let finished = self.finished_notify.notified();
            tokio::pin!(finished);
            finished.as_mut().enable();

            if self.finished.load(Ordering::Acquire) {
                return;
            }

            let wait = match self.handed_over_at.load(Ordering::Acquire) {
                0 => send_timeout.timeout,
                handed_over_at => {
                    let held = Duration::from_millis(self.now().saturating_sub(handed_over_at));

                    if held >= send_timeout.timeout {
                        if let Some(endpoint) = send_timeout.endpoint.as_ref() {
                            crate::app::APP_CTX.proxy_logs.write(
                                endpoint.host_endpoint.as_str(),
                                None,
                                send_timeout.ip.clone(),
                                format!(
                                    "The client took nothing of an answer for {:?} \
                                     (write_timeout): the connection is cut",
                                    send_timeout.timeout
                                ),
                            );
                        }

                        send_timeout.cut.cut_now().await;
                        return;
                    }

                    send_timeout.timeout - held
                }
            };

            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = finished => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt;

    use super::*;
    use crate::tcp_listener::ConnectionLifetime;

    type Frames = futures::stream::Iter<std::vec::IntoIter<Result<Frame<Bytes>, String>>>;

    fn body_of(frames: usize) -> http_body_util::StreamBody<Frames> {
        let frames: Vec<_> = (0..frames)
            .map(|_| Ok(Frame::data(Bytes::from_static(b"0123456789"))))
            .collect();

        http_body_util::StreamBody::new(futures::stream::iter(frames))
    }

    fn watched(
        inner: BoxBody<Bytes, String>,
        timeout: Duration,
    ) -> (WatchedResponseBody, Arc<ConnectionCut>) {
        let lifetime = ConnectionLifetime::new();
        let cut = ConnectionCut::new();

        let body = WatchedResponseBody::new(
            inner,
            lifetime.request_started(),
            SendTimeout {
                cut: cut.clone(),
                timeout,
                endpoint: None,
                ip: None,
            },
            None,
            200,
        );

        (body, cut)
    }

    #[tokio::test]
    async fn an_answer_the_client_stops_taking_cuts_the_connection() {
        let (mut body, cut) = watched(body_of(3).boxed(), Duration::from_millis(500));

        // hyper takes the first frame, and never comes back for the second one.
        body.frame().await.unwrap().unwrap();

        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(!cut.is_cut());

        tokio::time::sleep(Duration::from_millis(1250)).await;
        assert!(cut.is_cut());
    }

    #[tokio::test]
    async fn an_answer_taken_to_its_end_cuts_nothing() {
        let (mut body, cut) = watched(body_of(5).boxed(), Duration::from_millis(500));

        while let Some(frame) = body.frame().await {
            frame.unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        drop(body);

        tokio::time::sleep(Duration::from_millis(1000)).await;
        assert!(!cut.is_cut());
    }

    #[tokio::test]
    async fn an_answer_waiting_for_its_upstream_is_not_timed() {
        // One frame, then the upstream is silent - an SSE stream between its events.
        let first: Result<Frame<Bytes>, String> = Ok(Frame::data(Bytes::from_static(b"event")));
        let inner = http_body_util::StreamBody::new(futures::StreamExt::chain(
            futures::stream::iter(vec![first]),
            futures::stream::pending(),
        ));
        let (mut body, cut) = watched(inner.boxed(), Duration::from_millis(300));

        body.frame().await.unwrap().unwrap();

        // hyper is back for more at once, and waits with it for the upstream.
        let waiting = tokio::spawn(async move {
            let _ = body.frame().await;
        });

        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(!cut.is_cut());
        waiting.abort();
    }

    #[tokio::test]
    async fn an_answer_of_one_frame_starts_no_watch() {
        let (mut body, cut) = watched(
            http_body_util::Full::new(Bytes::from_static(b"page"))
                .map_err(|never| match never {})
                .boxed(),
            Duration::from_millis(300),
        );

        body.frame().await.unwrap().unwrap();
        assert!(body.watch.is_none());

        tokio::time::sleep(Duration::from_millis(800)).await;
        assert!(!cut.is_cut());
    }
}

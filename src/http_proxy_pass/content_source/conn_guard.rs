use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::body::{Body, Frame, SizeHint};
use my_http_client::{http1::MyHttpClient, MyHttpClientConnector};

use crate::{http_client_pool::HttpClientPoolItem, upstream_h1_pool::H1ClientHandle};

/// What a response body holds on to while it is read: the upstream connection behind it.
pub trait ConnGuard: Send + Sync {
    /// The body is dropped before its end - the client went away mid-response, the normal end of
    /// an SSE session. The connection is still in the middle of that response, so it must not
    /// take another request: it would queue behind a body which may never end.
    fn body_abandoned(&self) {}
}

/// A response body that carries a guard whose `Drop` runs only after
/// the body is fully consumed/dropped.
///
/// Used to tie an upstream H1 connection handle (a pool rent, or a dedicated
/// client `Arc`) to the lifetime of the response body. Without this, the proxy
/// dropped the handle as soon as the response *headers* arrived — releasing the
/// pool entry / disposing the client while an (often infinite) SSE body was
/// still streaming. See `attach_conn_guard`.
pub struct GuardedBody {
    inner: BoxBody<Bytes, String>,
    guard: Box<dyn ConnGuard>,
    /// The body was read to its end.
    finished: bool,
}

impl Body for GuardedBody {
    type Data = Bytes;
    type Error = String;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // GuardedBody is Unpin (all its fields are), so get_mut is safe.
        let this = self.get_mut();
        let frame = Pin::new(&mut this.inner).poll_frame(cx);

        if let Poll::Ready(None) = frame {
            this.finished = true;
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

impl Drop for GuardedBody {
    fn drop(&mut self) {
        // hyper stops polling a body which reports its end, so that counts as read to the end too.
        if !self.finished && !self.inner.is_end_stream() {
            self.guard.body_abandoned();
        }
    }
}

/// Wraps `resp`'s body so `guard` is dropped only when the body is. `guard` is
/// type-erased so any owning handle/client can be attached (H1 pool handle,
/// dedicated `MyHttpClient`, gateway or ssh pool client, …).
pub fn attach_conn_guard(
    resp: my_http_client::HyperResponse,
    guard: Box<dyn ConnGuard>,
) -> my_http_client::HyperResponse {
    let (parts, inner) = resp.into_parts();
    let guarded = GuardedBody {
        inner,
        guard,
        finished: false,
    }
    .boxed();
    http::Response::from_parts(parts, guarded)
}

/// A gateway or ssh pool client goes back to the pool when dropped - unless its connection is
/// still in the middle of a response nobody reads.
impl<TStream, TConnector> ConnGuard for HttpClientPoolItem<TStream, TConnector>
where
    TStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + 'static,
    TConnector: MyHttpClientConnector<TStream> + Send + Sync + 'static,
{
    fn body_abandoned(&self) {
        self.discard();
    }
}

/// An h1 pool entry goes back in service when its rent is released - unless its connection is
/// still in the middle of a response nobody reads: then the entry is connected anew first.
impl<TStream, TConnector> ConnGuard for H1ClientHandle<TStream, TConnector>
where
    TStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
    TConnector: MyHttpClientConnector<TStream> + Send + Sync + 'static,
{
    fn body_abandoned(&self) {
        self.abandon();
    }
}

/// A client of its own for one request: never reused, so an abandoned body changes nothing.
impl<TStream, TConnector> ConnGuard for MyHttpClient<TStream, TConnector>
where
    TStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + 'static,
    TConnector: MyHttpClientConnector<TStream> + Send + Sync + 'static,
{
}

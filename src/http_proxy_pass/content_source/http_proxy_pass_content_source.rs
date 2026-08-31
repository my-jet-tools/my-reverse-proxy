use bytes::Bytes;
use http_body_util::Full;

use crate::{
    http_content_source::local_path::*, http_content_source::static_content::*,
    http_content_source::*, http_proxy_pass::ProxyPassError,
};

use super::*;

pub enum HttpProxyPassContentSource {
    UnixHttp1(UnixHttp1ContentSource),
    Http1(Http1ContentSource),
    Https1(Https1ContentSource),
    Http2(Http2ContentSource),
    UnixHttp2(UnixHttp2ContentSource),
    Https2(Https2ContentSource),
    //Http1OverGateway(Http1OverGatewayContentSource),
    //Http2OverGateway(Http2OverGatewayContentSource),
    Http1OverSsh(Http1OverSshContentSource),
    Http2OverSsh(Http2OverSshContentSource),
    LocalPath(LocalPathContentSrc),
    PathOverSsh(PathOverSshContentSource),
    PathOverGateway(PathOverGatewayContentSource),
    Static(StaticContentSrc),
    Drop,
    DynamicProxy(DynamicProxyContentSource),
}

impl HttpProxyPassContentSource {
    /// Whether this upstream can take the request body as a stream of frames
    /// instead of one buffer. h2 only: it is the h2 client that has a streamed
    /// send, and h2 needs no chunked framing to carry a body whose length is not
    /// known up front.
    pub fn can_stream_request_body(&self) -> bool {
        matches!(
            self,
            Self::Http2(_) | Self::Https2(_) | Self::UnixHttp2(_) | Self::Http2OverSsh(_)
        )
    }

    /// Send a request whose body is forwarded frame by frame. Only reached for a
    /// source that answered `true` to [`Self::can_stream_request_body`] — the
    /// request builder asks before it decides not to collect the body.
    pub async fn send_streamed_request(
        &self,
        req: hyper::Request<crate::my_http2_client::HyperRequestBody>,
        content_size: Option<usize>,
    ) -> Result<HttpResponse, ProxyPassError> {
        match self {
            Self::Http2(model) => model.execute_streamed(req, content_size).await,
            Self::Https2(model) => model.execute_streamed(req, content_size).await,
            Self::UnixHttp2(model) => model.execute_streamed(req, content_size).await,
            Self::Http2OverSsh(model) => model.execute_streamed(req, content_size).await,
            _ => Err(ProxyPassError::UpstreamUnavailable),
        }
    }

    pub async fn send_request(
        &self,
        req: hyper::Request<Full<Bytes>>,
    ) -> Result<HttpResponse, ProxyPassError> {
        match self {
            Self::Http1(model) => model.execute(req).await,
            Self::UnixHttp2(model) => model.execute(req).await,
            Self::UnixHttp1(model) => model.execute(req).await,
            Self::Https1(model) => model.execute(req).await,
            Self::Http2(model) => model.execute(req).await,
            Self::Https2(model) => model.execute(req).await,
            Self::Http1OverSsh(model) => model.execute(req).await,
            Self::Http2OverSsh(model) => model.execute(req).await,
            Self::LocalPath(model) => model.execute(req).await,
            Self::PathOverSsh(model) => model.execute(req).await,
            //Self::Http1OverGateway(model) => model.execute(req).await,
            //Self::Http2OverGateway(model) => model.execute(req).await,
            Self::PathOverGateway(model) => model.execute(req).await,
            Self::Static(model) => model.execute(req).await,
            Self::Drop => {
                println!(
                    "DROP location hit: {} {} (Host: {:?}) -> connection dropped",
                    req.method(),
                    req.uri(),
                    req.headers()
                        .get(hyper::header::HOST)
                        .and_then(|v| v.to_str().ok())
                );
                Err(ProxyPassError::DropConnection)
            }
            Self::DynamicProxy(model) => model.execute(req).await,
        }
    }
}

#![allow(unused)]

use std::future::Future;

use futures::future::IntoFuture;
use hyper::header::PRAGMA;

use crate::http_client_connectors::HttpClientError;

#[derive(Debug)]
pub enum ProxyPassError {
    HttpClientError(HttpClientError),
    HyperError(hyper::Error),
    IoError(tokio::io::Error),
    SshSessionError(my_ssh::SshSessionError),
    WebSocketProtocolError(hyper_tungstenite::tungstenite::error::ProtocolError),
    MyHttpClientError(my_http_client::MyHttpClientError),
    NoLocationFound,
    ConnectionIsDisposed,
    Unauthorized,
    UserIsForbidden,
    IpRestricted(String),
    Disconnected,
    Timeout,
    /// The client went silent in the middle of a request body the proxy waits for whole -
    /// longer than the endpoint's `read_timeout`. Answered `408`.
    ClientBodyTimeout,
    /// A request body the proxy has to hold whole is larger than `max_buffered_request_body` - it
    /// says so, or it came so. Answered `413`.
    ClientBodyTooLarge,
    /// The request bodies held whole already take what `max_buffered_request_bodies_total` lets
    /// them all take: this one is not held on top of them. Answered `503`.
    BufferedBodiesFull,
    /// The client is over a `rate_limit`: answered `429`, with a `Retry-After` of so many
    /// seconds.
    TooManyRequests(u64),
    Disposed,
    GatewayError,
    NoWebSocketUpgrade,
    UpstreamUnavailable,
    NoHostHeader,
    DropConnection,
    ProxyToHeaderMissing,
    ProxyToHeaderInvalid,
    ProxyToHostNotAllowed,
}

impl ProxyPassError {
    pub fn is_disposed(&self) -> bool {
        matches!(self, ProxyPassError::ConnectionIsDisposed)
    }

    pub fn is_hyper_canceled(&self) -> bool {
        match self {
            ProxyPassError::HyperError(err) => err.is_canceled(),
            _ => false,
        }
    }
}

impl From<HttpClientError> for ProxyPassError {
    fn from(src: HttpClientError) -> Self {
        Self::HttpClientError(src)
    }
}

impl From<hyper::Error> for ProxyPassError {
    fn from(src: hyper::Error) -> Self {
        Self::HyperError(src)
    }
}

impl From<std::io::Error> for ProxyPassError {
    fn from(src: std::io::Error) -> Self {
        Self::IoError(src)
    }
}

impl From<my_ssh::SshSessionError> for ProxyPassError {
    fn from(src: my_ssh::SshSessionError) -> Self {
        Self::SshSessionError(src)
    }
}

impl From<hyper_tungstenite::tungstenite::error::ProtocolError> for ProxyPassError {
    fn from(src: hyper_tungstenite::tungstenite::error::ProtocolError) -> Self {
        Self::WebSocketProtocolError(src)
    }
}

impl From<my_http_client::MyHttpClientError> for ProxyPassError {
    fn from(src: my_http_client::MyHttpClientError) -> Self {
        Self::MyHttpClientError(src)
    }
}

#[derive(Debug)]
pub enum ExecuteWithTimeoutError {
    ReconnectAndRetry,
    ProxyPassError(ProxyPassError),
}

impl From<ProxyPassError> for ExecuteWithTimeoutError {
    fn from(src: ProxyPassError) -> Self {
        Self::ProxyPassError(src)
    }
}

impl From<hyper::Error> for ExecuteWithTimeoutError {
    fn from(src: hyper::Error) -> Self {
        Self::ProxyPassError(src.into())
    }
}

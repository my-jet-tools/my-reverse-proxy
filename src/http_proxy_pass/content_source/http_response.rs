use std::sync::Arc;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use my_http_client::MyHttpClientDisconnect;
use my_ssh::SshAsyncChannel;

pub enum HttpResponse {
    Response(my_http_client::HyperResponse),
    WebSocketUpgrade {
        /// Boxed: an upgrade is rare, while `HttpResponse` is returned for every proxied
        /// request and should not carry the size of the biggest upstream stream.
        stream: Box<WebSocketUpgradeStream>,
        response: hyper::Response<BoxBody<Bytes, String>>,
        disconnection: Arc<dyn MyHttpClientDisconnect + Send + Sync + 'static>,
        /// Bytes the upstream client already pulled off the socket together with
        /// the `101` line. In ~96% of connections the server's first frame (the
        /// one written from its on-connected callback) lands in that same
        /// `read()`, so it is gone from the socket and has to be handed to the
        /// websocket decoder explicitly. Empty when there was no such tail.
        leftover: Vec<u8>,
    },
}

pub enum WebSocketUpgradeStream {
    TcpStream(tokio::net::TcpStream),
    UnixStream(tokio::net::UnixStream),
    TlsStream(Box<my_tls::tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
    SshChannel(SshAsyncChannel),
    H2Upgraded(hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>),
    GatewayStream(crate::tcp_gateway::forwarded_connection::TcpGatewayProxyForwardStream),
    // Hyper(HyperWebsocket),
}

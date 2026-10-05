use std::sync::Arc;

use my_http_client::http1::*;
use rust_extensions::remote_endpoint::RemoteEndpointOwned;

use crate::{
    http_client_connectors::HttpOverGatewayConnector, http_proxy_pass::ProxyPassError,
    tcp_gateway::CONNECT_ACK_MARGIN,
};

use super::*;

/// An http/1.1 upstream reached through a gateway, for the hyper based (http2) endpoints.
pub struct Http1OverGatewayContentSource {
    pub gateway_id: Arc<String>,
    pub remote_endpoint: Arc<RemoteEndpointOwned>,
    pub request_timeout: std::time::Duration,
    pub connect_timeout: std::time::Duration,
}

impl Http1OverGatewayContentSource {
    pub async fn execute(
        &self,
        req: http::Request<http_body_util::Full<bytes::Bytes>>,
    ) -> Result<HttpResponse, ProxyPassError> {
        let pool_key = pool_key(
            &self.gateway_id,
            &self.remote_endpoint,
            self.connect_timeout,
        );

        let mut http_client = crate::app::APP_CTX.http_over_gateway_clients_pool.get(
            pool_key.into(),
            client_connect_timeout(self.connect_timeout),
            Some(crate::consts::DEFAULT_READ_TIMEOUT),
            || HttpOverGatewayConnector {
                gateway_id: self.gateway_id.clone(),
                remote_endpoint: self.remote_endpoint.clone(),
                connect_timeout: self.connect_timeout,
            },
        );

        let req = MyHttpRequest::from_hyper_request(req).await;

        match http_client.do_request(&req, self.request_timeout).await? {
            // The client stays out of the pool until the body is read to its end: a chunked or
            // streaming body is still being read on its connection when the head arrives.
            MyHttpResponse::Response(response) => Ok(HttpResponse::Response(attach_conn_guard(
                response,
                Box::new(http_client),
            ))),
            MyHttpResponse::WebSocketUpgrade {
                stream,
                response,
                disconnection,
                leftover,
            } => {
                http_client.upgraded_to_websocket();
                Ok(HttpResponse::WebSocketUpgrade {
                    stream: Box::new(WebSocketUpgradeStream::GatewayStream(stream)),
                    response,
                    disconnection,
                    leftover,
                })
            }
        }
    }
}

/// Upstreams with the same host behind different gateways are different upstreams. A pool client
/// keeps the connect timeout it was created with - it reconnects with it and sends it in
/// `CONNECT` - so locations with different connect timeouts get clients of their own.
pub fn pool_key(
    gateway_id: &str,
    remote_endpoint: &RemoteEndpointOwned,
    connect_timeout: std::time::Duration,
) -> String {
    format!(
        "gateway:{}->{}#connect={}ms",
        gateway_id,
        remote_endpoint.as_str(),
        connect_timeout.as_millis()
    )
}

/// The connect timeout of a pool client. The peer is given `connect_timeout` for its own connect
/// (it travels in `CONNECT`), and the answer still has to come back: the client waits for both,
/// like the h1 pipeline does.
pub fn client_connect_timeout(connect_timeout: std::time::Duration) -> std::time::Duration {
    connect_timeout + CONNECT_ACK_MARGIN
}

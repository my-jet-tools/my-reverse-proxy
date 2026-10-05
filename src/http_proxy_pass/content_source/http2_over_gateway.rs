use std::sync::Arc;

use rust_extensions::remote_endpoint::RemoteEndpointOwned;

use crate::{http_client_connectors::HttpOverGatewayConnector, http_proxy_pass::ProxyPassError};

use super::*;

/// A cleartext http2 (h2c) upstream reached through a gateway, for the hyper based (http2)
/// endpoints.
pub struct Http2OverGatewayContentSource {
    pub gateway_id: Arc<String>,
    pub remote_endpoint: Arc<RemoteEndpointOwned>,
    pub request_timeout: std::time::Duration,
    pub connect_timeout: std::time::Duration,
}

impl Http2OverGatewayContentSource {
    /// Goes through the shared h2 dispatcher, which also carries a WebSocket opened with an
    /// RFC 8441 extended CONNECT.
    pub async fn execute(
        &self,
        req: http::Request<http_body_util::Full<bytes::Bytes>>,
    ) -> Result<HttpResponse, ProxyPassError> {
        execute_h2(&self.get_client(), &req, self.request_timeout).await
    }

    /// Same upstream, with the client's request body forwarded as a stream of
    /// frames instead of being collected first.
    pub async fn execute_streamed(
        &self,
        req: hyper::Request<crate::my_http2_client::HyperRequestBody>,
        content_size: Option<usize>,
    ) -> Result<HttpResponse, ProxyPassError> {
        let response = self
            .get_client()
            .do_streamed_request(req, content_size, self.request_timeout)
            .await?;

        Ok(HttpResponse::Response(response))
    }

    fn get_client(
        &self,
    ) -> crate::http2_client_pool::Http2ClientPoolItem<
        crate::tcp_gateway::forwarded_connection::TcpGatewayProxyForwardStream,
        HttpOverGatewayConnector,
    > {
        crate::app::APP_CTX.http2_over_gateway_clients_pool.get(
            super::http1_over_gateway::pool_key(
                &self.gateway_id,
                &self.remote_endpoint,
                self.connect_timeout,
            )
            .into(),
            // The h2 handshake makes one more round trip through the gateway.
            super::http1_over_gateway::client_connect_timeout(self.connect_timeout)
                + crate::tcp_gateway::CONNECT_ACK_MARGIN,
            || {
                (
                    HttpOverGatewayConnector {
                        gateway_id: self.gateway_id.clone(),
                        remote_endpoint: self.remote_endpoint.clone(),
                        connect_timeout: self.connect_timeout,
                    },
                    crate::app::APP_CTX.prometheus.clone(),
                )
            },
        )
    }
}

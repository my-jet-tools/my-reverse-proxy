use std::sync::Arc;

use my_http_client::{MyHttpClientConnector, MyHttpClientError};
use rust_extensions::remote_endpoint::{RemoteEndpoint, RemoteEndpointOwned};
use tokio::io::{ReadHalf, WriteHalf};

use crate::tcp_gateway::forwarded_connection::TcpGatewayProxyForwardStream;

/// Opens a plain TCP connection to `remote_endpoint` through gateway `gateway_id`, for the
/// hyper based clients of the http2 endpoints.
pub struct HttpOverGatewayConnector {
    pub gateway_id: Arc<String>,
    pub remote_endpoint: Arc<RemoteEndpointOwned>,
    pub connect_timeout: std::time::Duration,
}

#[async_trait::async_trait]
impl MyHttpClientConnector<TcpGatewayProxyForwardStream> for HttpOverGatewayConnector {
    async fn connect(&self) -> Result<TcpGatewayProxyForwardStream, MyHttpClientError> {
        let Some((gateway, connection_id)) =
            crate::app::APP_CTX.get_gateway_by_id_with_next_connection_id(self.gateway_id.as_str())
        else {
            return Err(MyHttpClientError::CanNotConnectToRemoteHost(format!(
                "Gateway {} is not found",
                self.gateway_id
            )));
        };

        gateway
            .connect_to_forward_proxy_connection(
                self.remote_endpoint.clone(),
                self.connect_timeout,
                connection_id,
            )
            .await
            .map_err(MyHttpClientError::CanNotConnectToRemoteHost)
    }

    fn get_remote_endpoint<'s>(&'s self) -> RemoteEndpoint<'s> {
        self.remote_endpoint.to_ref()
    }

    fn is_debug(&self) -> bool {
        false
    }

    fn reunite(
        read: ReadHalf<TcpGatewayProxyForwardStream>,
        write: WriteHalf<TcpGatewayProxyForwardStream>,
    ) -> TcpGatewayProxyForwardStream {
        read.unsplit(write)
    }
}

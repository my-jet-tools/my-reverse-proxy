use std::sync::Arc;

use my_http_client::{MyHttpClientConnector, MyHttpClientError};
use rust_extensions::remote_endpoint::{RemoteEndpoint, RemoteEndpointOwned};
use tokio::{
    io::{ReadHalf, WriteHalf},
    net::TcpStream,
};

pub struct HttpConnector {
    pub remote_endpoint: Arc<RemoteEndpointOwned>,
    pub debug: bool,
}

#[async_trait::async_trait]
impl MyHttpClientConnector<TcpStream> for HttpConnector {
    fn get_remote_endpoint<'s>(&'s self) -> RemoteEndpoint<'s> {
        self.remote_endpoint.to_ref()
    }

    fn is_debug(&self) -> bool {
        self.debug
    }

    async fn connect(&self) -> Result<TcpStream, MyHttpClientError> {
        let host_port = self.remote_endpoint.get_host_port();

        match crate::tcp_utils::connect_tcp(host_port.as_str()).await {
            Ok(tcp_stream) => Ok(tcp_stream),
            Err(err) => Err(
                my_http_client::MyHttpClientError::CanNotConnectToRemoteHost(format!(
                    "{}. Err:{}",
                    self.remote_endpoint.as_str(),
                    err
                )),
            ),
        }
    }

    fn reunite(read: ReadHalf<TcpStream>, write: WriteHalf<TcpStream>) -> TcpStream {
        read.unsplit(write)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use my_http_client::MyHttpClientConnector;
    use rust_extensions::remote_endpoint::RemoteEndpointOwned;

    /// The connection of the http/1.1 and h2 upstream pools relays a request as it comes: it
    /// does not hold a small write back until the one before it is acknowledged.
    #[tokio::test]
    async fn the_connection_to_an_upstream_sends_without_delay() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let connector = super::HttpConnector {
            remote_endpoint: Arc::new(
                RemoteEndpointOwned::try_parse(format!("http://127.0.0.1:{port}")).unwrap(),
            ),
            debug: false,
        };

        let stream = connector.connect().await.unwrap();

        assert!(stream.nodelay().unwrap());
    }
}

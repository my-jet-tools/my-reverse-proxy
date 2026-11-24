use std::sync::Arc;

use crate::{
    configurations::{HttpEndpointInfo, HttpListenPortConfiguration},
    network_stream::NetworkStream,
    tcp_listener::https::ClientCertificateData,
    types::*,
};

use super::ReadAhead;

#[derive(Clone)]
pub struct HttpConnectionInfo {
    pub cn_user_name: Option<Arc<ClientCertificateData>>,
    /// The client of the request being served: the peer of the connection - or, on a request
    /// through Cloudflare to a `cloudflare: true` endpoint, the address of its `CF-Connecting-IP`.
    /// Set for every request ([`Self::set_request_client`]): Cloudflare sends the requests of
    /// all its visitors through the connections it keeps.
    pub connection_ip: ConnectionIp,
    /// The Cloudflare server the request being served came through, when `connection_ip` is of
    /// its `CF-Connecting-IP`.
    pub cloudflare_edge: Option<std::net::IpAddr>,
    /// The peer of the connection - what it was accepted from.
    pub peer_ip: ConnectionIp,
    pub endpoint_info: Option<Arc<HttpEndpointInfo>>,
    pub listen_config: Arc<HttpListenPortConfiguration>,
    /// `AppConfiguration::generation` at the moment `listen_config` was taken.
    config_generation: u64,
    /// The requests read off the connection so far: see `max_requests_per_connection`.
    pub requests: u32,
    /// The line of the access log of the request being served, until its answer takes it
    /// (`ResponseSlot::access`). `None` while the log is off.
    pub access: Option<crate::access_log::AccessRecord>,
}

impl HttpConnectionInfo {
    fn new(
        connection_ip: ConnectionIp,
        cn_user_name: Option<Arc<ClientCertificateData>>,
        endpoint_info: Option<Arc<HttpEndpointInfo>>,
        listen_config: Arc<HttpListenPortConfiguration>,
    ) -> Self {
        Self {
            connection_ip,
            cloudflare_edge: None,
            peer_ip: connection_ip,
            cn_user_name,
            endpoint_info,
            listen_config,
            config_generation: crate::app::APP_CTX.current_configuration.generation(),
            requests: 0,
            access: None,
        }
    }

    pub fn request_client(&self) -> crate::cloudflare::RequestClient {
        crate::cloudflare::RequestClient {
            ip: self.connection_ip,
            cloudflare_edge: self.cloudflare_edge,
        }
    }

    pub fn set_request_client(&mut self, client: crate::cloudflare::RequestClient) {
        self.connection_ip = client.ip;
        self.cloudflare_edge = client.cloudflare_edge;
    }

    /// A keep-alive connection keeps serving the port configuration it was
    /// accepted with. After a settings reload this swaps in the live one, so a
    /// changed location (`api_keys_auth`, upstream, headers) applies to the next
    /// request on an already-open connection as well. Returns true when the
    /// configuration was replaced — the caller must re-resolve the endpoint.
    pub async fn pick_up_reload(&mut self) -> bool {
        let (generation, replaced) = crate::app::APP_CTX
            .current_configuration
            .pick_up_reload(
                &self.listen_config.listen_host,
                &self.listen_config,
                self.config_generation,
            )
            .await;

        self.config_generation = generation;

        match replaced {
            Some(listen_config) => {
                self.listen_config = listen_config;
                true
            }
            None => false,
        }
    }
}

pub async fn kick_h1_reverse_proxy_server(
    connection_ip: ConnectionIp,
    endpoint_info: Arc<HttpEndpointInfo>,
    server_stream: my_tls::tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    cn_user_name: Option<Arc<ClientCertificateData>>,
    listen_config: Arc<HttpListenPortConfiguration>,
) {
    let http_connection_info = HttpConnectionInfo::new(
        connection_ip,
        cn_user_name,
        Some(endpoint_info),
        listen_config,
    );
    super::serve_reverse_proxy_pipelined(server_stream, http_connection_info, None).await;
}

/// A connection of an `http` / `http2` endpoint - a tcp port or a unix socket - whose client
/// speaks http/1.1, served to its end on the task it is on. `read_ahead`: what was read of it to
/// tell that (`tcp_listener::plain_http`).
pub async fn serve_h1_plain_connection<TStream: NetworkStream + Send + Sync + 'static>(
    stream: TStream,
    connection_ip: ConnectionIp,
    listen_config: Arc<HttpListenPortConfiguration>,
    read_ahead: ReadAhead,
) {
    let http_connection_info = HttpConnectionInfo::new(connection_ip, None, None, listen_config);

    super::serve_reverse_proxy_pipelined(stream, http_connection_info, Some(read_ahead)).await;
}

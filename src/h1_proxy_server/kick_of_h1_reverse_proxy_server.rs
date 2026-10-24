use std::sync::Arc;

use crate::{
    configurations::{HttpEndpointInfo, HttpListenPortConfiguration},
    tcp_listener::https::ClientCertificateData,
    types::*,
};

#[derive(Clone)]
pub struct HttpConnectionInfo {
    pub cn_user_name: Option<Arc<ClientCertificateData>>,
    pub connection_ip: ConnectionIp,
    pub endpoint_info: Option<Arc<HttpEndpointInfo>>,
    pub listen_config: Arc<HttpListenPortConfiguration>,
    /// `AppConfiguration::generation` at the moment `listen_config` was taken.
    config_generation: u64,
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
            cn_user_name,
            endpoint_info,
            listen_config,
            config_generation: crate::app::APP_CTX.current_configuration.generation(),
        }
    }

    /// A keep-alive connection keeps serving the port configuration it was
    /// accepted with. After a settings reload this swaps in the live one, so a
    /// changed location (`auth_header`, upstream, headers) applies to the next
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
    super::serve_reverse_proxy_pipelined(server_stream, http_connection_info).await;
}

pub fn kick_h1_tcp_reverse_proxy_server_from_http(
    accepted_connection: tokio::net::TcpStream,
    connection_ip: impl Into<ConnectionIp>,
    listen_config: Arc<HttpListenPortConfiguration>,
) {
    let http_connection_info =
        HttpConnectionInfo::new(connection_ip.into(), None, None, listen_config);

    crate::app::spawn_named(
        "h1_tcp_server_connection",
        super::serve_reverse_proxy_pipelined(accepted_connection, http_connection_info),
    );
}

#[cfg(unix)]
pub fn kick_h1_unix_reverse_proxy_server_from_http(
    accepted_connection: tokio::net::UnixStream,
    listen_config: Arc<HttpListenPortConfiguration>,
) {
    let http_connection_info =
        HttpConnectionInfo::new(ConnectionIp::UnixSocket, None, None, listen_config);
    crate::app::spawn_named(
        "h1_unix_server_connection",
        super::serve_reverse_proxy_pipelined(accepted_connection, http_connection_info),
    );
}

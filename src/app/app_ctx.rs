use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicI64, Ordering},
        Arc,
    },
};

use super::*;
use encryption::aes::AesKey;
use my_ssh::SshAsyncChannel;
use my_tls::tokio_rustls::client::TlsStream;
use my_tls::tokio_rustls::rustls::sign::CertifiedKey;
use rust_extensions::AppStates;
use tokio::{net::TcpStream, sync::Mutex};

use crate::{
    configurations::*,
    http2_client_pool::Http2ClientPool,
    http_client_connectors::*,
    http_client_pool::HttpClientPool,
    settings::ConnectionsSettingsModel,
    settings_compiled::SettingsCompiled,
    ssl::CertificatesCache,
    tcp_gateway::{
        client::{TcpGatewayClient, TcpGatewayClientParams},
        forwarded_connection::TcpGatewayProxyForwardStream,
        server::{GatewayServerKeys, TcpGatewayServer},
        TcpGatewayConnection,
    },
    upstream_h1_pool::H1PoolRegistry,
    upstream_h2_pool::H2PoolRegistry,
};

use super::{ActiveListenPorts, CertPassKeys, Metrics, Prometheus};

pub const APP_NAME: &str = env!("CARGO_PKG_NAME");
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

pub static APP_CTX: std::sync::LazyLock<AppContext> = std::sync::LazyLock::new(|| {
    // Tests start from empty settings rather than the `~/.my-reverse-proxy` of
    // whoever runs them, and build the endpoints they need themselves.
    #[cfg(test)]
    let settings_model = SettingsCompiled::default();
    #[cfg(not(test))]
    let settings_model = SettingsCompiled::load_settings_block().unwrap();
    AppContext::new(settings_model)
});

pub struct AppContext {
    pub http_over_ssh_clients_pool: HttpClientPool<SshAsyncChannel, HttpOverSshConnector>,

    pub http2_over_ssh_clients_pool: Http2ClientPool<SshAsyncChannel, HttpOverSshConnector>,

    pub http_over_gateway_clients_pool:
        HttpClientPool<TcpGatewayProxyForwardStream, HttpOverGatewayConnector>,

    pub http2_over_gateway_clients_pool:
        Http2ClientPool<TcpGatewayProxyForwardStream, HttpOverGatewayConnector>,

    pub h2_tcp_pools: H2PoolRegistry<TcpStream, HttpConnector>,
    pub h2_tls_pools: H2PoolRegistry<TlsStream<TcpStream>, HttpTlsConnector>,
    #[cfg(unix)]
    pub h2_uds_pools: H2PoolRegistry<tokio::net::UnixStream, UnixSocketHttpConnector>,

    pub h1_tcp_pools: H1PoolRegistry<TcpStream, HttpConnector>,
    pub h1_tls_pools: H1PoolRegistry<TlsStream<TcpStream>, HttpTlsConnector>,
    #[cfg(unix)]
    pub h1_uds_pools: H1PoolRegistry<tokio::net::UnixStream, UnixSocketHttpConnector>,

    id: AtomicI64,
    pub connection_settings: ConnectionsSettingsModel,
    pub default_h2_livness_url: Option<String>,
    pub pool_supervisor_interval: std::time::Duration,

    /// Snapshot of the last compiled settings that were actually applied to the
    /// running proxy (set at the end of `load_everything_from_settings`). Lets us
    /// expose the applied configuration without recompiling the files from disk.
    pub applied_settings: arc_swap::ArcSwapOption<SettingsCompiled>,

    /// Held while settings are put into the live configuration - by a reload of the settings
    /// files, of one of their ports, or by a read of the urls of `real_time_configurations`. Each
    /// of them reads what the other one applied, so one is never in the middle of the other.
    pub settings_apply_lock: Mutex<()>,

    /// What each url of `real_time_configurations` answered last.
    pub real_time_configurations: RealTimeConfigurations,

    /// The keys requests to a location guarded by `api_keys_auth` are checked against.
    pub api_keys: crate::api_keys::ApiKeysStore,

    pub token_secret_key: AesKey,
    pub current_configuration: AppConfiguration,
    pub states: Arc<AppStates>,

    pub show_error_description: AtomicBool,
    pub prometheus: Arc<Prometheus>,
    pub metrics: Metrics,
    pub proxy_logs: ProxyLogs,
    pub debug_flags: DebugFlags,
    /// `global_settings.debug_ip`. Filled by `load_everything_from_settings`, so
    /// it follows every settings reload.
    pub debug_ip: DebugIpList,
    pub active_listen_ports: Mutex<ActiveListenPorts>,

    pub ssh_config_list: SshConfigList,

    pub allowed_users_list: AllowedUsersList,

    pub ssl_certificates_cache: CertificatesCache,

    pub ssh_cert_pass_keys: CertPassKeys,

    /// The gateway server of the settings, or the one of the secure store.
    pub gateway_server: GatewayServerSlot,
    /// The gateway clients of the settings, and those of the connections of the secure store.
    pub gateway_clients: GatewayClients,
    /// The address the control port listens on (`global_settings.http_control_port` /
    /// `http_control_ip`, `127.0.0.1:8000` by default). Bound once, at startup.
    pub http_control_addr: SocketAddr,
    /// `global_settings.control_unix_socket`: the control port is served on this unix socket too.
    /// Bound once, at startup.
    pub http_control_unix_socket: Option<String>,
    /// `header_read_timeout` of `global_settings`, for the control port: my-http-server times the
    /// head of an http/1.1 request with it (it is no endpoint, so only the global level applies).
    pub http_control_header_read_timeout: std::time::Duration,

    pub ssh_sessions_pool: SshSessionsPool,

    pub self_signed_cert: Arc<CertifiedKey>,

    /// The session cache and the ticket keys every https endpoint without a client certificate
    /// resumes TLS sessions from. Made once: a config built per connection would start empty.
    pub tls_session_resumption: crate::tcp_listener::https::TlsSessionResumption,

    pub rps: Arc<RpsAccumulator>,

    pub ip_blocklist: IpBlocklist,

    /// The client connections held at once: `max_connections`, `max_connections_per_ip`.
    pub connection_limits: ConnectionLimits,

    /// `access_log`: a line for every request answered. Started by the settings load.
    pub access_log: crate::access_log::AccessLog,

    pub traffic: TrafficAccumulator,

    pub resolved_domain_ips: ResolvedDomainIps,

    /// The networks Cloudflare connects to origins from: who a `cloudflare: true` endpoint takes
    /// connections from. See [`crate::cloudflare`].
    pub cloudflare_ip_ranges: crate::cloudflare::CloudflareIpRanges,

    /// Every connection a `cloudflare: true` endpoint closed, and every Cloudflare server which
    /// reached an endpoint without the flag - written to `$HOME/logs`.
    pub cloudflare_deviations: crate::cloudflare::DeviationJournal,

    /// Whether `POST /api/initialize` has opened the secure store, and the network keys the data
    /// read from services is decrypted with. See [`crate::secure`].
    pub secure: crate::secure::SecureState,

    /// While it is open, the MCP tools which change the proxy work - for the address it was
    /// opened from.
    pub mcp_admin_mode: McpAdminMode,

    /// Where the requests of each MCP session come from.
    pub mcp_session_callers: McpSessionCallers,
}

impl AppContext {
    pub fn new(settings_model: SettingsCompiled) -> Self {
        let http_control_addr = settings_model.get_http_control_addr().unwrap();
        let http_control_unix_socket = settings_model.get_control_unix_socket().unwrap();
        let http_control_header_read_timeout = settings_model
            .get_global_timeouts()
            .resolve()
            .client
            .header_read_timeout;
        let connection_settings = settings_model.get_connections_settings();
        let default_h2_livness_url = settings_model.get_default_h2_livness_url();
        let pool_supervisor_interval = settings_model.get_pool_supervisor_interval();

        let token_secret_key = if let Some(session_key) = settings_model.get_session_key() {
            AesKey::new(get_token_secret_key_from_settings(session_key.as_bytes()).as_slice())
        } else {
            AesKey::new(generate_random_token_secret_key().as_slice())
        };

        // Before the gateway server and clients: the server lets in the keys the store
        // authorizes, and a client which names a private key of the store takes it from here at
        // every connect.
        let secure = crate::secure::SecureState::new();

        let gateway_server = if let Some(gateway_server_settings) =
            settings_model.get_gateway_server()
        {
            let authorized_keys = gateway_server_settings.load_authorized_keys().unwrap();
            let allowed_ip = gateway_server_settings.get_allowed_ip_list().unwrap();
            // A port which can not be bound ends the startup, as the keys above do: a
            // proxy with no gateway listener must not come up.
            Some(
                TcpGatewayServer::new(
                    format!("0.0.0.0:{}", gateway_server_settings.port,),
                    GatewayServerKeys::new(authorized_keys, secure.gateway_authorized_keys.clone()),
                    allowed_ip,
                    gateway_server_settings.is_debug(),
                )
                .unwrap(),
            )
        } else {
            None
        };

        let mut gateway_clients = HashMap::new();

        let ssh_registry = &settings_model.ssh;
        for (id, client_settings) in settings_model.gateway_clients.iter() {
            let signing_key = client_settings
                .get_signing_key(id.as_str(), ssh_registry, &secure.private_keys)
                .unwrap();
            let client = TcpGatewayClient::new(TcpGatewayClientParams {
                id: id.to_string(),
                remote_endpoint: client_settings.remote_host.to_string(),
                signing_key,
                compression: client_settings.get_compression(id.as_str()).unwrap(),
                allow_incoming_forward_connections: client_settings
                    .get_allow_incoming_forward_connections(),
                connect_timeout: client_settings.get_connect_timeout(),
                debug: client_settings.is_debug(),
                sync_ssl_certificates: client_settings.get_sync_ssl_certificates(),
            });

            gateway_clients.insert(id.clone(), client);
        }

        let ip_blocklist = IpBlocklist::new();
        ip_blocklist.set_white_list(settings_model.get_ip_blocklist_white_list());

        Self {
            id: AtomicI64::new(0),
            connection_settings,
            default_h2_livness_url,
            pool_supervisor_interval,
            applied_settings: arc_swap::ArcSwapOption::empty(),
            settings_apply_lock: Mutex::new(()),
            real_time_configurations: RealTimeConfigurations::new(),
            api_keys: crate::api_keys::ApiKeysStore::new(),
            // saved_client_certs: SavedClientCert::new(),
            token_secret_key,
            current_configuration: AppConfiguration::new(),
            states: Arc::new(AppStates::create_initialized()),
            prometheus: Arc::new(Prometheus::new()),
            ssl_certificates_cache: CertificatesCache::new(),
            //local_port_allocator: LocalPortAllocator::new(),
            //ssh_to_http_port_forward_pool: SshToHttpPortForwardPool::new(),
            show_error_description: AtomicBool::new(
                settings_model.get_show_error_description_on_error_page(),
            ),
            metrics: Metrics::new(),
            proxy_logs: ProxyLogs::new(),
            debug_flags: DebugFlags::new(),
            debug_ip: DebugIpList::new(),
            active_listen_ports: Mutex::new(ActiveListenPorts::new()),
            ssh_config_list: SshConfigList::new(),
            allowed_users_list: AllowedUsersList::new(),
            ssh_cert_pass_keys: CertPassKeys::new(),
            http_over_ssh_clients_pool: HttpClientPool::new(),

            http2_over_ssh_clients_pool: Http2ClientPool::new(),
            http_over_gateway_clients_pool: HttpClientPool::new(),
            http2_over_gateway_clients_pool: Http2ClientPool::new(),
            h2_tcp_pools: H2PoolRegistry::new(),
            h2_tls_pools: H2PoolRegistry::new(),
            #[cfg(unix)]
            h2_uds_pools: H2PoolRegistry::new(),
            h1_tcp_pools: H1PoolRegistry::new(),
            h1_tls_pools: H1PoolRegistry::new(),
            #[cfg(unix)]
            h1_uds_pools: H1PoolRegistry::new(),
            gateway_server: GatewayServerSlot::new(gateway_server),
            gateway_clients: GatewayClients::new(gateway_clients),
            http_control_addr,
            http_control_unix_socket,
            http_control_header_read_timeout,
            ssh_sessions_pool: SshSessionsPool::new(),
            self_signed_cert: Arc::new(
                crate::self_signed_cert::generate(
                    crate::self_signed_cert::SELF_SIGNED_CERT_NAME.to_string(),
                )
                .unwrap(),
            ),
            tls_session_resumption: crate::tcp_listener::https::TlsSessionResumption::new(),
            rps: Arc::new(RpsAccumulator::new()),
            ip_blocklist,
            connection_limits: ConnectionLimits::new(
                settings_model.get_connection_limits().unwrap(),
            ),
            access_log: crate::access_log::AccessLog::new(),
            traffic: TrafficAccumulator::new(),
            resolved_domain_ips: ResolvedDomainIps::new(),
            cloudflare_ip_ranges: crate::cloudflare::CloudflareIpRanges::new(),
            cloudflare_deviations: crate::cloudflare::DeviationJournal::new(),
            secure,
            mcp_admin_mode: McpAdminMode::new(),
            mcp_session_callers: McpSessionCallers::new(),
        }
    }

    pub fn get_next_id(&self) -> i64 {
        self.id.fetch_add(1, Ordering::SeqCst)
    }

    pub fn get_gateway_by_id_with_next_connection_id(
        &self,
        gateway_id: &str,
    ) -> Option<(Arc<TcpGatewayConnection>, u32)> {
        if let Some(server_gateway) = self.gateway_server.get() {
            if let Some(result) = server_gateway.get_gateway_connection(gateway_id) {
                return Some((result, server_gateway.get_next_connection_id()));
            }
        }

        let gateway_client = self.gateway_clients.get(gateway_id)?;

        let result = gateway_client.get_gateway_connection(gateway_id)?;

        Some((result, gateway_client.get_next_connection_id()))
    }

    pub fn get_gateway_by_id(&self, gateway_id: &str) -> Option<Arc<TcpGatewayConnection>> {
        if let Some(server_gateway) = self.gateway_server.get() {
            if let Some(result) = server_gateway.get_gateway_connection(gateway_id) {
                return Some(result);
            }
        }

        let gateway_client = self.gateway_clients.get(gateway_id)?;

        gateway_client.get_gateway_connection(gateway_id)
    }
}

fn generate_random_token_secret_key() -> Vec<u8> {
    let mut result = Vec::with_capacity(48);

    let mut key = vec![];

    while result.len() < 48 {
        if key.is_empty() {
            key = uuid::Uuid::new_v4().as_bytes().to_vec();
        }

        result.push(key.pop().unwrap());
    }

    result
}

fn get_token_secret_key_from_settings(session_key: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(48);

    let mut key = vec![];

    while result.len() < 48 {
        if key.is_empty() {
            key = session_key.to_vec();
        }

        result.push(key.pop().unwrap());
    }

    result
}

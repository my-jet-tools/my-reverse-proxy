use std::{
    collections::HashMap,
    net::IpAddr,
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
        server::TcpGatewayServer,
        TcpGatewayConnection,
    },
    upstream_h1_pool::H1PoolRegistry,
    upstream_h2_pool::H2PoolRegistry,
};

use super::{ActiveListenPorts, CertPassKeys, Metrics, Prometheus};

pub const APP_NAME: &str = env!("CARGO_PKG_NAME");
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

// Tests start from empty settings rather than the `~/.my-reverse-proxy` of
// whoever runs them, and build the endpoints they need themselves.
#[cfg(test)]
pub static APP_CTX: std::sync::LazyLock<AppContext> =
    std::sync::LazyLock::new(|| AppContext::new(SettingsCompiled::default()).unwrap());

// The proxy has built it from the settings file in `build_app_ctx`.
#[cfg(not(test))]
pub static APP_CTX: std::sync::LazyLock<AppContext> = std::sync::LazyLock::new(|| {
    BUILT_APP_CTX
        .lock()
        .unwrap()
        .take()
        .expect("APP_CTX is used before build_app_ctx has built it")
});

static BUILT_APP_CTX: std::sync::Mutex<Option<AppContext>> = std::sync::Mutex::new(None);

/// Builds `APP_CTX` from the settings file, before anything uses it. A settings error - a value
/// which does not parse, a key file which is not there, a gateway port which is taken - comes
/// back as an error for the startup to report, where in the initializer of `APP_CTX` it could
/// only panic, and a panic aborts an installed Windows service.
///
/// The lock is held while the context is built: `AppContext::new` spawns the gateway loops, and
/// one which touches `APP_CTX` before the context is in place waits for it here.
pub fn build_app_ctx() -> Result<(), String> {
    let settings_model = SettingsCompiled::load_settings_block()?;

    let mut built = BUILT_APP_CTX.lock().unwrap();
    *built = Some(AppContext::new(settings_model)?);
    drop(built);

    std::sync::LazyLock::force(&APP_CTX);

    Ok(())
}

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

    pub gateway_server: Option<TcpGatewayServer>,
    pub gateway_clients: HashMap<String, TcpGatewayClient>,
    pub http_control_port: Option<u16>,
    pub http_control_ip: Option<IpAddr>,

    pub ssh_sessions_pool: SshSessionsPool,

    pub self_signed_cert: Arc<CertifiedKey>,

    pub rps: Arc<RpsAccumulator>,

    pub ip_blocklist: IpBlocklist,

    pub traffic: TrafficAccumulator,

    pub resolved_domain_ips: ResolvedDomainIps,
}

impl AppContext {
    pub fn new(settings_model: SettingsCompiled) -> Result<Self, String> {
        let http_control_port = settings_model.get_http_control_port();
        let http_control_ip = settings_model.get_http_control_ip()?;
        let connection_settings = settings_model.get_connections_settings();
        let default_h2_livness_url = settings_model.get_default_h2_livness_url();
        let pool_supervisor_interval = settings_model.get_pool_supervisor_interval();

        let token_secret_key = if let Some(session_key) = settings_model.get_session_key() {
            AesKey::new(get_token_secret_key_from_settings(session_key.as_bytes()).as_slice())
        } else {
            AesKey::new(generate_random_token_secret_key().as_slice())
        };

        let gateway_server =
            if let Some(gateway_server_settings) = settings_model.get_gateway_server() {
                let authorized_keys = gateway_server_settings.load_authorized_keys()?;
                let allowed_ip = gateway_server_settings.get_allowed_ip_list()?;
                // A port which can not be bound ends the startup, as the keys above do: a
                // proxy with no gateway listener must not come up.
                Some(TcpGatewayServer::new(
                    format!("0.0.0.0:{}", gateway_server_settings.port,),
                    authorized_keys,
                    allowed_ip,
                    gateway_server_settings.is_debug(),
                )?)
            } else {
                None
            };

        let mut gateway_clients = HashMap::new();

        let ssh_registry = &settings_model.ssh;
        for (id, client_settings) in settings_model.gateway_clients.iter() {
            let signing_key = client_settings.load_signing_key(id.as_str(), ssh_registry)?;
            let client = TcpGatewayClient::new(TcpGatewayClientParams {
                id: id.to_string(),
                remote_endpoint: client_settings.remote_host.to_string(),
                signing_key,
                compression: client_settings.get_compression(id.as_str())?,
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

        Ok(Self {
            id: AtomicI64::new(0),
            connection_settings,
            default_h2_livness_url,
            pool_supervisor_interval,
            applied_settings: arc_swap::ArcSwapOption::empty(),
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
            gateway_server,
            gateway_clients,
            http_control_port,
            http_control_ip,
            ssh_sessions_pool: SshSessionsPool::new(),
            self_signed_cert: Arc::new(crate::self_signed_cert::generate(
                crate::self_signed_cert::SELF_SIGNED_CERT_NAME.to_string(),
            )?),
            rps: Arc::new(RpsAccumulator::new()),
            ip_blocklist,
            traffic: TrafficAccumulator::new(),
            resolved_domain_ips: ResolvedDomainIps::new(),
        })
    }

    pub fn get_next_id(&self) -> i64 {
        self.id.fetch_add(1, Ordering::SeqCst)
    }

    pub fn get_gateway_by_id_with_next_connection_id(
        &self,
        gateway_id: &str,
    ) -> Option<(Arc<TcpGatewayConnection>, u32)> {
        if let Some(server_gateway) = self.gateway_server.as_ref() {
            if let Some(result) = server_gateway.get_gateway_connection(gateway_id) {
                return Some((result, server_gateway.get_next_connection_id()));
            }
        }

        let gateway_client = self.gateway_clients.get(gateway_id)?;

        let result = gateway_client.get_gateway_connection(gateway_id)?;

        Some((result, gateway_client.get_next_connection_id()))
    }

    pub fn get_gateway_by_id(&self, gateway_id: &str) -> Option<Arc<TcpGatewayConnection>> {
        if let Some(server_gateway) = self.gateway_server.as_ref() {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A setting which does not hold is returned, for the startup to report - not a panic, which
    /// would abort an installed Windows service.
    #[test]
    fn a_settings_error_is_returned() {
        let settings = SettingsCompiled {
            global_settings: Some(serde_yaml::from_str("http_control_ip: not-an-ip").unwrap()),
            ..Default::default()
        };
        let Err(err) = AppContext::new(settings) else {
            panic!("a context was built with http_control_ip: not-an-ip");
        };
        assert!(err.contains("not-an-ip"), "{err}");

        let settings = SettingsCompiled {
            gateway_server: Some(
                serde_yaml::from_str("port: 1\nauthorized_keys: [/no/such/key.pub]").unwrap(),
            ),
            ..Default::default()
        };
        let Err(err) = AppContext::new(settings) else {
            panic!("a context was built with an authorized key which is not there");
        };
        assert!(err.contains("/no/such/key.pub"), "{err}");
    }
}

use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use super::*;

#[derive(Clone)]
pub enum ListenConfiguration {
    Http(Arc<HttpListenPortConfiguration>),
    Tcp(Arc<TcpEndpointHostConfig>),
    Mcp(Arc<HttpListenPortConfiguration>),
}

impl ListenConfiguration {
    pub fn get_white_list_id(&self) -> Option<&str> {
        match self {
            ListenConfiguration::Http(_) => None,
            ListenConfiguration::Tcp(config) => config.ip_white_list_id.as_deref(),
            ListenConfiguration::Mcp(_) => None,
        }
    }
}

pub struct AppConfigurationInner {
    pub listen_tcp_endpoints: HashMap<u16, ListenConfiguration>,
    pub listen_unix_socket_endpoints: HashMap<Arc<String>, ListenConfiguration>,
    pub google_auth_credentials: GoogleAuthCredentialsList,
    pub oauth_credentials: OAuthCredentialsList,
    pub white_list_ip_list: WhiteListedIpListConfigurations,
    pub error_configurations: BTreeMap<String, String>,
}

impl AppConfigurationInner {
    pub fn new() -> Self {
        Self {
            listen_tcp_endpoints: HashMap::new(),
            listen_unix_socket_endpoints: HashMap::new(),
            google_auth_credentials: GoogleAuthCredentialsList::new(),
            oauth_credentials: OAuthCredentialsList::new(),
            white_list_ip_list: WhiteListedIpListConfigurations::new(),
            error_configurations: BTreeMap::new(),
        }
    }

    /// The HTTP port configuration currently applied for a listener, TCP or
    /// unix. `None` for a port that is not configured or is a raw TCP forward.
    pub fn get_http_listen_config(
        &self,
        listen_host: &crate::types::ListenHost,
    ) -> Option<Arc<HttpListenPortConfiguration>> {
        let listen_config = match listen_host {
            crate::types::ListenHost::Tcp(socket_addr) => {
                self.listen_tcp_endpoints.get(&socket_addr.port())
            }
            crate::types::ListenHost::Unix(socket) => self.listen_unix_socket_endpoints.get(socket),
        };

        match listen_config? {
            ListenConfiguration::Http(config) | ListenConfiguration::Mcp(config) => {
                Some(config.clone())
            }
            ListenConfiguration::Tcp(_) => None,
        }
    }
}

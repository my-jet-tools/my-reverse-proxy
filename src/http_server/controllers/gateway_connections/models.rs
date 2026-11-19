use serde::Serialize;

use crate::secure::StoredGatewayConnection;

/// A connection to a gateway as the API tells of it: the fields named as in `gateway_clients` of
/// the settings, and whether its gateway connection is up.
#[derive(Serialize)]
pub struct GatewayConnectionHttpModel {
    pub id: String,
    pub remote_host: String,
    pub private_key: String,
    pub compress: u32,
    /// Milliseconds; `null` - the default of 5 seconds.
    pub connect_timeout: Option<u64>,
    pub allow_incoming_forward_connections: bool,
    pub sync_ssl_certificates: Vec<String>,
    pub debug: bool,
    pub connected: bool,
}

impl GatewayConnectionHttpModel {
    pub fn new(connection: StoredGatewayConnection, connected: bool) -> Self {
        Self {
            id: connection.id,
            remote_host: connection.remote_host,
            private_key: connection.private_key,
            compress: connection.compress,
            connect_timeout: match connection.connect_timeout_ms {
                0 => None,
                milliseconds => Some(milliseconds),
            },
            allow_incoming_forward_connections: connection.allow_incoming_forward_connections,
            sync_ssl_certificates: connection.sync_ssl_certificates,
            debug: connection.debug,
            connected,
        }
    }
}

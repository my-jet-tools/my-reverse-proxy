use mcp_server_middleware::*;
use rust_extensions::date_time::DateTimeAsMicroseconds;
use serde::*;

use crate::secure::StoredGatewayConnection;

/// `Ok` while the admin mode of MCP is open for where the session of `ctx` comes from; what a tool
/// which changes the proxy answers otherwise.
pub fn admin_mode_is_open_for(ctx: &ToolCallContext) -> Result<(), String> {
    let session = crate::app::APP_CTX.mcp_session_callers.get(&ctx.session_id);

    crate::app::APP_CTX
        .mcp_admin_mode
        .check_for(session, DateTimeAsMicroseconds::now())
}

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct PublicKeyMcpModel {
    #[property(description = "Id of the key in the secure store.")]
    pub id: String,

    #[property(
        description = "The public key in OpenSSH form, `ssh-ed25519 AAAA...`: a line of an authorized_keys file, or what set_gateway_authorized_key of the proxy whose gateway server is to let it in takes."
    )]
    pub public_key: String,
}

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct AuthorizedKeyMcpModel {
    #[property(
        description = "The gateway name a client which signs with the key comes in under: the id of its connection or gateway_clients entry."
    )]
    pub id: String,

    #[property(description = "The public key in OpenSSH form, `ssh-ed25519 AAAA...`.")]
    pub public_key: String,

    #[property(
        description = "The addresses the key is let in from: addresses, from-to ranges, subnets, `*` for any."
    )]
    pub ip_white_list: Vec<String>,
}

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct GatewayConnectionMcpModel {
    #[property(
        description = "The gateway id: what routes name as `gateway:<id>->host:port`, and the name the client gives the gateway server in its handshake."
    )]
    pub id: String,

    #[property(description = "host:port of the gateway server.")]
    pub remote_host: String,

    #[property(
        description = "Id of the private key of the secure store the handshake is signed with."
    )]
    pub private_key: String,

    #[property(description = "The compression level of the gateway connection: 0 - off.")]
    pub compress: u32,

    #[property(
        description = "The connect timeout in milliseconds; null - the default of 5 seconds."
    )]
    pub connect_timeout: Option<u64>,

    #[property(
        description = "Whether the gateway server may open connections through this gateway connection towards this side."
    )]
    pub allow_incoming_forward_connections: bool,

    #[property(description = "Ids of the TLS certificates synced from the gateway server.")]
    pub sync_ssl_certificates: Vec<String>,

    #[property(description = "Whether the client logs in debug mode.")]
    pub debug: bool,

    #[property(description = "Whether the gateway connection is up now.")]
    pub connected: bool,
}

impl GatewayConnectionMcpModel {
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

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct DeletedMcpModel {
    #[property(description = "The id the call named.")]
    pub id: String,

    #[property(description = "False when there was nothing with this id.")]
    pub deleted: bool,
}

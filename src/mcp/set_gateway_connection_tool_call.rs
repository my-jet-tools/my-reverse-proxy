use mcp_server_middleware::*;
use serde::*;

use super::{admin_mode_is_open, GatewayConnectionMcpModel};

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct SetGatewayConnectionInputData {
    #[property(
        description = "The gateway id, up to 64 letters, digits, '-', '_' and '.': routes name it as `gateway:<id>->host:port`, and the gateway server knows the connection by it. A connection with this id is replaced; the id of a gateway client of the settings is refused."
    )]
    pub id: String,

    #[property(description = "host:port of the gateway server.")]
    pub remote_host: String,

    #[property(
        description = "Id of the private key of the secure store to sign the handshake with: generate_private_key makes one. It has to be in the store."
    )]
    pub private_key: String,

    #[property(
        description = "Compression level of the gateway connection: 0 or left out - off, from 1 on - a row of the table in docs/gateway-compression.md."
    )]
    pub compress: Option<u64>,

    #[property(description = "Connect timeout in milliseconds; left out - 5 seconds.")]
    pub connect_timeout: Option<u64>,

    #[property(
        description = "Whether the gateway server may open connections through this gateway connection towards this side; left out - false."
    )]
    pub allow_incoming_forward_connections: Option<bool>,

    #[property(description = "Ids of the TLS certificates to sync from the gateway server.")]
    pub sync_ssl_certificates: Option<Vec<String>>,

    #[property(description = "Debug logging of the client; left out - false.")]
    pub debug: Option<bool>,
}

pub struct SetGatewayConnectionHandler;

impl ToolDefinition for SetGatewayConnectionHandler {
    const FUNC_NAME: &'static str = "set_gateway_connection";
    const DESCRIPTION: &'static str = "ADMIN MODE. Sets a connection of this proxy to a gateway server - an entry like those of gateway_clients of the settings, with the handshake signed by a private key of the secure store - and starts its client at once; it is kept in the secure store and started after every initialize. Setting an existing id replaces the connection: its client is restarted, and what went through the old gateway connection is closed. The gateway server has to let the key in: get_public_key gives the public key for it. Returns the connection as kept; get_gateway_connections then tells whether it connected. Refused while admin mode is closed (see get_mcp_admin_mode): then ask the operator to open it, do not retry.";
}

#[async_trait::async_trait]
impl McpToolCall<SetGatewayConnectionInputData, GatewayConnectionMcpModel>
    for SetGatewayConnectionHandler
{
    async fn execute_tool_call(
        &self,
        model: SetGatewayConnectionInputData,
    ) -> Result<GatewayConnectionMcpModel, String> {
        admin_mode_is_open()?;

        let connection =
            crate::scripts::set_gateway_connection(crate::secure::GatewayConnectionInput {
                id: model.id,
                remote_host: model.remote_host,
                private_key: model.private_key,
                compress: model.compress,
                connect_timeout: model.connect_timeout,
                allow_incoming_forward_connections: model.allow_incoming_forward_connections,
                sync_ssl_certificates: model.sync_ssl_certificates,
                debug: model.debug,
            })
            .await
            .map_err(|err| err.message())?;

        println!(
            "Secure store: gateway connection '{}' to '{}' is set over MCP",
            connection.id, connection.remote_host
        );

        Ok(GatewayConnectionMcpModel::new(connection, false))
    }
}

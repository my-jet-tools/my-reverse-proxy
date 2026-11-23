use mcp_server_middleware::*;
use serde::*;

use super::{admin_mode_is_open_for, AuthorizedKeyMcpModel};

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct SetGatewayAuthorizedKeyInputData {
    #[property(
        description = "The gateway name the connecting proxy comes in under - the id of its connection (set_gateway_connection there) or of its gateway_clients entry: letters, digits, '-', '_' and '.'. A handshake under another name is refused. A key with this id is replaced."
    )]
    pub id: String,

    #[property(
        description = "The Ed25519 public key in OpenSSH form, `ssh-ed25519 AAAA...` - what get_public_key or generate_private_key of the connecting proxy give."
    )]
    pub public_key: String,

    #[property(
        description = "The addresses the connecting proxy connects from, at least one: IPv4 addresses, from-to ranges, subnets (10.0.0.0/24), or `*` for any. A handshake from another address is refused."
    )]
    pub ip_white_list: Vec<String>,
}

pub struct SetGatewayAuthorizedKeyHandler;

impl ToolDefinition for SetGatewayAuthorizedKeyHandler {
    const FUNC_NAME: &'static str = "set_gateway_authorized_key";
    const DESCRIPTION: &'static str = "ADMIN MODE. Lets a public key in through the gateway server of this proxy: a gateway client which signs its handshake with the private half connects from its next handshake on - under the gateway name `id` only, and from the addresses of `ip_white_list` only - besides the keys of the authorized_keys files. Kept in the secure store under `id`; what the id had is replaced. Only a public key is given here: the private one stays on the connecting proxy. Refused while admin mode is closed (see get_mcp_admin_mode): then ask the operator to open it, do not retry.";
}

#[async_trait::async_trait]
impl McpToolCallEx<SetGatewayAuthorizedKeyInputData, AuthorizedKeyMcpModel>
    for SetGatewayAuthorizedKeyHandler
{
    async fn execute_tool_call(
        &self,
        model: SetGatewayAuthorizedKeyInputData,
        ctx: &ToolCallContext,
    ) -> Result<AuthorizedKeyMcpModel, String> {
        admin_mode_is_open_for(ctx)?;

        let id = crate::secure::check_gateway_connection_id(&model.id)?;
        let public = crate::secure::parse_openssh_ed25519_public(&model.public_key)?;
        let ip_white_list = crate::secure::check_key_ip_white_list(&model.ip_white_list)?;

        crate::app::APP_CTX
            .secure
            .set_gateway_authorized_key(id, public, ip_white_list.clone())
            .await
            .map_err(|err| err.message())?;

        println!(
            "Secure store: the gateway server lets '{id}' in from {ip_white_list:?} - set over MCP"
        );

        Ok(AuthorizedKeyMcpModel {
            id: id.to_string(),
            public_key: crate::secure::openssh_verifying_key(&public),
            ip_white_list,
        })
    }
}

use mcp_server_middleware::*;
use serde::*;

use super::{admin_mode_is_open, PublicKeyMcpModel};

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct SetGatewayAuthorizedKeyInputData {
    #[property(
        description = "Id to keep the key under, up to 64 characters - say, the proxy which connects with it. A key with this id is replaced."
    )]
    pub id: String,

    #[property(
        description = "The Ed25519 public key in OpenSSH form, `ssh-ed25519 AAAA...` - what get_public_key or generate_private_key of the connecting proxy give."
    )]
    pub public_key: String,
}

pub struct SetGatewayAuthorizedKeyHandler;

impl ToolDefinition for SetGatewayAuthorizedKeyHandler {
    const FUNC_NAME: &'static str = "set_gateway_authorized_key";
    const DESCRIPTION: &'static str = "ADMIN MODE. Lets a public key in through the gateway server of this proxy: a gateway client which signs its handshake with the private half connects from its next handshake on - besides the keys of the authorized_keys files. Kept in the secure store under `id`; a key with this id is replaced. Only a public key is given here: the private one stays on the connecting proxy. Refused while admin mode is closed (see get_mcp_admin_mode): then ask the operator to open it, do not retry.";
}

#[async_trait::async_trait]
impl McpToolCall<SetGatewayAuthorizedKeyInputData, PublicKeyMcpModel>
    for SetGatewayAuthorizedKeyHandler
{
    async fn execute_tool_call(
        &self,
        model: SetGatewayAuthorizedKeyInputData,
    ) -> Result<PublicKeyMcpModel, String> {
        admin_mode_is_open()?;

        let id = crate::secure::check_private_key_id(&model.id)?;
        let public = crate::secure::parse_openssh_ed25519_public(&model.public_key)?;

        crate::app::APP_CTX
            .secure
            .set_gateway_authorized_key(id, public)
            .await
            .map_err(|err| err.message())?;

        println!("Secure store: the gateway server lets key '{id}' in - set over MCP");

        Ok(PublicKeyMcpModel {
            id: id.to_string(),
            public_key: crate::secure::openssh_verifying_key(&public),
        })
    }
}

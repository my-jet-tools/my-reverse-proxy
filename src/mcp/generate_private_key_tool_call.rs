use mcp_server_middleware::*;
use serde::*;

use super::{admin_mode_is_open, PublicKeyMcpModel};

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct GeneratePrivateKeyInputData {
    #[property(
        description = "Id to keep the new key under in the secure store, up to 64 characters - what a gateway connection names as its private_key. An id which has a key already is refused."
    )]
    pub id: String,
}

pub struct GeneratePrivateKeyHandler;

impl ToolDefinition for GeneratePrivateKeyHandler {
    const FUNC_NAME: &'static str = "generate_private_key";
    const DESCRIPTION: &'static str = "ADMIN MODE. Generates a new Ed25519 private key and keeps it in the secure store under `id`; returns its PUBLIC key only - a private key never leaves the proxy through MCP. Use it for a connection of this proxy to a gateway: (1) generate the key here, (2) let its public key in on the proxy which runs the gateway server - set_gateway_authorized_key there, or a line of its authorized_keys file, (3) set_gateway_connection here with private_key = this id. An id which has a key already is refused. Refused while admin mode is closed (see get_mcp_admin_mode): then ask the operator to open it, do not retry.";
}

#[async_trait::async_trait]
impl McpToolCall<GeneratePrivateKeyInputData, PublicKeyMcpModel> for GeneratePrivateKeyHandler {
    async fn execute_tool_call(
        &self,
        model: GeneratePrivateKeyInputData,
    ) -> Result<PublicKeyMcpModel, String> {
        admin_mode_is_open()?;

        let id = crate::secure::check_private_key_id(&model.id)?;

        let public = crate::app::APP_CTX
            .secure
            .generate_private_key(id)
            .await
            .map_err(|err| err.message())?;

        println!("Secure store: private key '{id}' is generated over MCP");

        Ok(PublicKeyMcpModel {
            id: id.to_string(),
            public_key: crate::secure::openssh_verifying_key(&public),
        })
    }
}

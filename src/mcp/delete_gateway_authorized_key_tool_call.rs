use mcp_server_middleware::*;
use serde::*;

use super::{admin_mode_is_open_for, DeletedMcpModel};

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct DeleteGatewayAuthorizedKeyInputData {
    #[property(
        description = "Id of the key to stop letting in (see get_gateway_authorized_keys)."
    )]
    pub id: String,
}

pub struct DeleteGatewayAuthorizedKeyHandler;

impl ToolDefinition for DeleteGatewayAuthorizedKeyHandler {
    const FUNC_NAME: &'static str = "delete_gateway_authorized_key";
    const DESCRIPTION: &'static str = "ADMIN MODE. Stops letting a key of the secure store in through the gateway server: a gateway connection it let in stays up until it breaks, and its next handshake is refused. Keys of the authorized_keys files are not touched. Refused while admin mode is closed (see get_mcp_admin_mode): then ask the operator to open it, do not retry.";
}

#[async_trait::async_trait]
impl McpToolCallEx<DeleteGatewayAuthorizedKeyInputData, DeletedMcpModel>
    for DeleteGatewayAuthorizedKeyHandler
{
    async fn execute_tool_call(
        &self,
        model: DeleteGatewayAuthorizedKeyInputData,
        ctx: &ToolCallContext,
    ) -> Result<DeletedMcpModel, String> {
        admin_mode_is_open_for(ctx)?;

        let id = model.id.trim().to_string();

        let deleted = crate::app::APP_CTX
            .secure
            .delete_gateway_authorized_key(&id)
            .await
            .map_err(|err| err.message())?;

        if deleted {
            println!(
                "Secure store: the gateway server no longer lets key '{id}' in - removed over MCP"
            );
        }

        Ok(DeletedMcpModel { id, deleted })
    }
}

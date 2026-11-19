use mcp_server_middleware::*;
use serde::*;

use super::{admin_mode_is_open, DeletedMcpModel};

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct DeleteGatewayConnectionInputData {
    #[property(description = "Id of the connection to remove (see get_gateway_connections).")]
    pub id: String,
}

pub struct DeleteGatewayConnectionHandler;

impl ToolDefinition for DeleteGatewayConnectionHandler {
    const FUNC_NAME: &'static str = "delete_gateway_connection";
    const DESCRIPTION: &'static str = "ADMIN MODE. Removes a connection to a gateway from the secure store and stops its client: the gateway connection, and every route through it, is closed now. The private key it used stays. Gateway clients of the settings files are not touched. Refused while admin mode is closed (see get_mcp_admin_mode): then ask the operator to open it, do not retry.";
}

#[async_trait::async_trait]
impl McpToolCall<DeleteGatewayConnectionInputData, DeletedMcpModel>
    for DeleteGatewayConnectionHandler
{
    async fn execute_tool_call(
        &self,
        model: DeleteGatewayConnectionInputData,
    ) -> Result<DeletedMcpModel, String> {
        admin_mode_is_open()?;

        let id = model.id.trim().to_string();

        let deleted = crate::scripts::delete_gateway_connection(&id)
            .await
            .map_err(|err| err.message())?;

        if deleted {
            println!("Secure store: gateway connection '{id}' is removed over MCP");
        }

        Ok(DeletedMcpModel { id, deleted })
    }
}

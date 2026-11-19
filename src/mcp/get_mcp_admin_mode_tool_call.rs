use mcp_server_middleware::*;
use rust_extensions::date_time::DateTimeAsMicroseconds;
use serde::*;

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct GetMcpAdminModeInputData {}

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct GetMcpAdminModeResponse {
    #[property(
        description = "Whether admin mode is open: the tools which change the secure store work."
    )]
    pub open: bool,

    #[property(description = "Seconds it stays open for; 0 when it is closed.")]
    pub seconds_left: i64,
}

pub struct GetMcpAdminModeHandler;

impl ToolDefinition for GetMcpAdminModeHandler {
    const FUNC_NAME: &'static str = "get_mcp_admin_mode";
    const DESCRIPTION: &'static str = "Whether MCP admin mode is open, and for how many seconds more. Admin mode is what the tools which change the secure store need: generate_private_key, set_gateway_connection, delete_gateway_connection, set_gateway_authorized_key, delete_gateway_authorized_key. Only the operator opens it, for some minutes, with an encrypted call of the control port (POST /api/mcp/v1/admin-mode); no tool opens it. Call this before planning a series of changes; when it is closed, ask the operator to open it. Reading is never gated.";
}

#[async_trait::async_trait]
impl McpToolCall<GetMcpAdminModeInputData, GetMcpAdminModeResponse> for GetMcpAdminModeHandler {
    async fn execute_tool_call(
        &self,
        _model: GetMcpAdminModeInputData,
    ) -> Result<GetMcpAdminModeResponse, String> {
        let seconds_left = crate::app::APP_CTX
            .mcp_admin_mode
            .seconds_left(DateTimeAsMicroseconds::now());

        Ok(GetMcpAdminModeResponse {
            open: seconds_left > 0,
            seconds_left,
        })
    }
}

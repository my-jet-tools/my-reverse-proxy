use mcp_server_middleware::*;
use rust_extensions::date_time::DateTimeAsMicroseconds;
use serde::*;

use crate::app::McpSessionCaller;

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct GetMcpAdminModeInputData {}

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct GetMcpAdminModeResponse {
    #[property(description = "Whether admin mode is open.")]
    pub open: bool,

    #[property(description = "Seconds it stays open for; 0 when it is closed.")]
    pub seconds_left: i64,

    #[property(
        description = "The address it is open for - the one the operator opened it from - or `this host` for the unix socket and the loopback with no address in X-Forwarded-For; null when it is closed."
    )]
    pub ip: Option<String>,

    #[property(
        description = "The country of that address, ISO 3166 code of two letters; `-` when the country database has none (a private address, this host). Null when it is closed."
    )]
    pub country: Option<String>,

    #[property(
        description = "Where this MCP session comes from; null when it is not known (a new session) or it has come from more than one address."
    )]
    pub session_ip: Option<String>,

    #[property(
        description = "Whether the tools which need admin mode work for this session: it is open, and this session comes from the address it is open for."
    )]
    pub open_for_this_session: bool,
}

pub struct GetMcpAdminModeHandler;

impl ToolDefinition for GetMcpAdminModeHandler {
    const FUNC_NAME: &'static str = "get_mcp_admin_mode";
    const DESCRIPTION: &'static str = "Whether MCP admin mode is open, for how many seconds more, and for which address and country. Admin mode is what the tools which change the proxy need: reload_settings, generate_private_key, set_gateway_connection, delete_gateway_connection, set_gateway_authorized_key, delete_gateway_authorized_key. It works only for the MCP sessions which come from the address the operator opened it from - with an encrypted call of the control port (POST /api/mcp/v1/admin-mode); no tool opens it, and a session from another address is refused. Call this before planning a series of changes: when it is closed, or not open for this session, ask the operator to open it. Reading is never gated.";
}

#[async_trait::async_trait]
impl McpToolCallEx<GetMcpAdminModeInputData, GetMcpAdminModeResponse> for GetMcpAdminModeHandler {
    async fn execute_tool_call(
        &self,
        _model: GetMcpAdminModeInputData,
        ctx: &ToolCallContext,
    ) -> Result<GetMcpAdminModeResponse, String> {
        let now = DateTimeAsMicroseconds::now();
        let state = crate::app::APP_CTX.mcp_admin_mode.state(now);
        let session = crate::app::APP_CTX.mcp_session_callers.get(&ctx.session_id);

        let session_ip = match session {
            McpSessionCaller::From(caller) => Some(caller),
            McpSessionCaller::Unknown | McpSessionCaller::Mixed => None,
        };

        Ok(GetMcpAdminModeResponse {
            open: state.is_some(),
            seconds_left: state.map(|itm| itm.seconds_left).unwrap_or(0),
            ip: state.map(|itm| itm.opened_from.to_string()),
            country: state.map(|itm| itm.opened_from.country()),
            session_ip: session_ip.map(|itm| itm.to_string()),
            open_for_this_session: crate::app::APP_CTX
                .mcp_admin_mode
                .check_for(session, now)
                .is_ok(),
        })
    }
}

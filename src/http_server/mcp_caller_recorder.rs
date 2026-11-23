use my_http_server::{
    HttpContext, HttpFailResult, HttpOkResult, HttpRequestHeaders, HttpServerMiddleware,
};
use rust_extensions::date_time::DateTimeAsMicroseconds;

/// In front of MCP: writes down where every request of an MCP session comes from - the tools run
/// apart from the requests which call them, and the ones which need admin mode check the session
/// against the address it was opened from. It answers nothing itself.
pub struct McpCallerRecorder;

#[async_trait::async_trait]
impl HttpServerMiddleware for McpCallerRecorder {
    async fn handle_request(
        &self,
        ctx: &mut HttpContext,
    ) -> Option<Result<HttpOkResult, HttpFailResult>> {
        let path = ctx.request.get_path();
        let path = path.as_str();

        if path != "/mcp" && !path.starts_with("/mcp/") {
            return None;
        }

        let session_id = ctx
            .request
            .get_headers()
            .try_get_case_insensitive("mcp-session-id")
            .and_then(|value| value.as_str().ok())?;

        crate::app::APP_CTX.mcp_session_callers.note(
            session_id.trim(),
            crate::app::CallerIp::of_request(&ctx.request),
            DateTimeAsMicroseconds::now(),
        );

        None
    }
}

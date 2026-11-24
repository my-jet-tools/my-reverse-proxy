use my_http_server::{macros::http_route, HttpContext, HttpFailResult, HttpOkResult, HttpOutput};
use rust_extensions::date_time::DateTimeAsMicroseconds;
use serde::Serialize;

use super::{key_of_encrypted_request, EncryptedJsonHttpInput};

#[http_route(
    method: "POST",
    route: "/api/mcp/v1/admin-mode/get",
    summary: "The address the admin commands of MCP are taken from",
    description: "Encrypted with a network key (Content-Encoding: aes128gcm), and answered encrypted with the same key. The body is any JSON - `{}` - since an empty body carries no encryption; it changes nothing. The answer is `{\"open\", \"seconds_left\", \"ip\", \"country\", \"your_ip\", \"your_country\", \"open_for_you\"}`: whether admin mode is open, for how many seconds more, the address the admin commands of MCP are taken from - the one it was opened from - and its country; the address this call comes from, as the proxy sees it, and its country; and whether MCP sessions from that address may give the admin commands now. `this host` is the unix socket and the bare loopback; a country is `-` when the country database has none for the address.",
    controller: "Mcp",
    input_data: EncryptedJsonHttpInput,
    result:[
        {status_code: 200, description: "The state of admin mode, encrypted"},
        {status_code: 400, description: "The body opens with no key"},
        {status_code: 415, description: "The body did not come encrypted - or the proxy has no network keys yet"},
    ]
)]
pub struct GetMcpAdminModeAction;

async fn handle_request(
    _action: &GetMcpAdminModeAction,
    _input_data: EncryptedJsonHttpInput,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = key_of_encrypted_request(ctx)?;

    let state = crate::app::APP_CTX
        .mcp_admin_mode
        .state(DateTimeAsMicroseconds::now());

    let you = crate::app::CallerIp::of_request(&ctx.request);

    HttpOutput::as_json(McpAdminModeStateHttpModel {
        open: state.is_some(),
        seconds_left: state.map(|itm| itm.seconds_left).unwrap_or(0),
        ip: state.map(|itm| itm.opened_from.to_string()),
        country: state.map(|itm| itm.opened_from.country()),
        your_ip: you.to_string(),
        your_country: you.country(),
        open_for_you: state.is_some_and(|itm| itm.opened_from == you),
    })
    .encode(&key)
    .into_ok_result(false)
}

#[derive(Serialize)]
struct McpAdminModeStateHttpModel {
    open: bool,
    seconds_left: i64,
    /// The address the admin commands of MCP are taken from; `None` while it is closed.
    ip: Option<String>,
    country: Option<String>,
    /// The address this call comes from, as the proxy sees it.
    your_ip: String,
    your_country: String,
    /// MCP sessions from `your_ip` may give the admin commands now.
    open_for_you: bool,
}

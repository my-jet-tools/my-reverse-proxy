use my_http_server::{macros::http_route, HttpContext, HttpFailResult, HttpOkResult, HttpOutput};
use rust_extensions::date_time::DateTimeAsMicroseconds;
use serde::{Deserialize, Serialize};

use crate::consts::{DEFAULT_MCP_ADMIN_MODE_MINUTES, MAX_MCP_ADMIN_MODE_MINUTES};

use super::{key_of_encrypted_request, parse_call, EncryptedJsonHttpInput};

#[http_route(
    method: "POST",
    route: "/api/mcp/v1/admin-mode",
    summary: "Open or close the admin mode of MCP",
    description: "Encrypted with a network key (Content-Encoding: aes128gcm), and answered encrypted with the same key - no MCP tool opens the admin mode. Body: JSON `{\"minutes\": 10}`: it is open for that many minutes from now, 60 at most, in place of the time and the address it had; 0 closes it, from any address; `{}` opens it for 10. It is open for the address this call comes from - the first entry of its `X-Forwarded-For` when it is an address (the caller holds a network key: the address it gives is taken, over the unix socket as over TCP), the peer address otherwise, `this host` for the unix socket and the loopback with no address in the header: while it is open, the MCP tools which change the proxy work for the MCP sessions from that address, and are refused for any other - reload_settings, generate_private_key, set_gateway_connection, delete_gateway_connection, set_gateway_authorized_key, delete_gateway_authorized_key. It is closed when the proxy starts. The answer is `{\"open\", \"seconds_left\", \"ip\", \"country\"}`.",
    controller: "Mcp",
    input_data: EncryptedJsonHttpInput,
    result:[
        {status_code: 200, description: "`{\"open\", \"seconds_left\", \"ip\", \"country\"}`, encrypted"},
        {status_code: 400, description: "The body opens with no key, is not the JSON above, or asks for more than 60 minutes"},
        {status_code: 415, description: "The body did not come encrypted - or the proxy has no network keys yet"},
    ]
)]
pub struct SetMcpAdminModeAction;

async fn handle_request(
    _action: &SetMcpAdminModeAction,
    input_data: EncryptedJsonHttpInput,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = key_of_encrypted_request(ctx)?;

    let call: SetMcpAdminModeCall = parse_call(&input_data.body, "{\"minutes\": 10}")?;

    let minutes = call.minutes.unwrap_or(DEFAULT_MCP_ADMIN_MODE_MINUTES);

    if minutes > MAX_MCP_ADMIN_MODE_MINUTES {
        return Err(HttpFailResult::as_validation_error(format!(
            "minutes is {minutes}: the admin mode of MCP is opened for {MAX_MCP_ADMIN_MODE_MINUTES} minutes at most"
        )));
    }

    let now = DateTimeAsMicroseconds::now();
    let admin_mode = &crate::app::APP_CTX.mcp_admin_mode;

    // Open for where this call comes from; closed by a call from anywhere.
    let caller = crate::app::CallerIp::of_encrypted_request(&ctx.request);

    admin_mode.open_for(minutes, now, caller);

    if minutes == 0 {
        println!(
            "MCP admin mode is closed over the encrypted API, from {caller} ({})",
            caller.country()
        );
    } else {
        println!(
            "MCP admin mode is open for {minutes} minutes for {caller} ({}) - opened over the encrypted API",
            caller.country()
        );
    }

    let state = admin_mode.state(now);

    HttpOutput::as_json(McpAdminModeHttpModel {
        open: state.is_some(),
        seconds_left: state.map(|itm| itm.seconds_left).unwrap_or(0),
        ip: state.map(|itm| itm.opened_from.to_string()),
        country: state.map(|itm| itm.opened_from.country()),
    })
    .encode(&key)
    .into_ok_result(false)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetMcpAdminModeCall {
    minutes: Option<u64>,
}

#[derive(Serialize)]
struct McpAdminModeHttpModel {
    open: bool,
    seconds_left: i64,
    /// The address it is open for: where the call which opened it came from.
    ip: Option<String>,
    country: Option<String>,
}

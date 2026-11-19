use my_http_server::{macros::http_route, HttpContext, HttpFailResult, HttpOkResult, HttpOutput};
use rust_extensions::date_time::DateTimeAsMicroseconds;
use serde::{Deserialize, Serialize};

use crate::consts::{DEFAULT_MCP_ADMIN_MODE_MINUTES, MAX_MCP_ADMIN_MODE_MINUTES};

use super::{key_of_encrypted_request, parse_call, EncryptedJsonHttpInput};

#[http_route(
    method: "POST",
    route: "/api/mcp/v1/admin-mode",
    summary: "Open or close the admin mode of MCP",
    description: "Encrypted with a network key (Content-Encoding: aes128gcm), and answered encrypted with the same key - no MCP tool opens the admin mode. Body: JSON `{\"minutes\": 10}`: it is open for that many minutes from now, 60 at most, in place of the time it had left; 0 closes it; `{}` opens it for 10. While it is open, the MCP tools which change the secure store work: generate_private_key, set_gateway_connection, delete_gateway_connection, set_gateway_authorized_key, delete_gateway_authorized_key. It is closed when the proxy starts. The answer is `{\"open\", \"seconds_left\"}`.",
    controller: "Mcp",
    input_data: EncryptedJsonHttpInput,
    result:[
        {status_code: 200, description: "`{\"open\", \"seconds_left\"}`, encrypted"},
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

    admin_mode.open_for(minutes, now);

    if minutes == 0 {
        println!("MCP admin mode is closed over the encrypted API");
    } else {
        println!("MCP admin mode is open for {minutes} minutes - opened over the encrypted API");
    }

    let seconds_left = admin_mode.seconds_left(now);

    HttpOutput::as_json(McpAdminModeHttpModel {
        open: seconds_left > 0,
        seconds_left,
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
}

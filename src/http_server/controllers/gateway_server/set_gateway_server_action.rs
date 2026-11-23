use my_http_server::{macros::http_route, HttpContext, HttpFailResult, HttpOkResult, HttpOutput};
use serde::Serialize;

use crate::secure::StoredGatewayServer;

use super::{key_of_encrypted_request, parse_call, store_refusal, EncryptedJsonHttpInput};

#[http_route(
    method: "POST",
    route: "/api/gateway-server/v1/set",
    summary: "Run the gateway server",
    description: "Encrypted with a network key (Content-Encoding: aes128gcm), and answered encrypted with the same key. Body: JSON `{\"port\": 30000, \"allowed_ip\": [\"10.0.0.0/24\"], \"debug\": false}` - what `gateway_server` of the settings says, with no `authorized_keys` files: the server lets in the keys the secure store authorizes (`/api/gateway-authorized-keys/v1/...`), each under its gateway name and from its ip_white_list. `allowed_ip` may be left out: before the handshake, it lets anybody connect then. The server listens at `0.0.0.0:<port>` at once, in place of the one set before, whose clients are disconnected: on another port the new one listens first, and a port which can not be had leaves the one before as it is; on the same port the one before stops first. It is kept in the secure store, to run after every initialize. Refused while the settings have a gateway server. The answer is the server as kept.",
    controller: "GatewayServer",
    input_data: EncryptedJsonHttpInput,
    result:[
        {status_code: 200, description: "Runs and is kept: `{\"port\", \"allowed_ip\", \"debug\"}`, encrypted"},
        {status_code: 400, description: "The body opens with no key, is not the JSON above, the port is not one, or an allowed_ip entry is not one"},
        {status_code: 409, description: "The port can not be listened at - the server set before runs on - or the settings have a gateway server"},
        {status_code: 415, description: "The body did not come encrypted - or the proxy has no network keys yet"},
        {status_code: 503, description: "The proxy is not initialized"},
        {status_code: 500, description: "The secure store can not be written"},
    ]
)]
pub struct SetGatewayServerAction;

async fn handle_request(
    _action: &SetGatewayServerAction,
    input_data: EncryptedJsonHttpInput,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = key_of_encrypted_request(ctx)?;

    let input: crate::secure::GatewayServerInput = parse_call(
        &input_data.body,
        "{\"port\": 30000, \"allowed_ip\": [...], \"debug\": false}",
    )?;

    let server = crate::scripts::set_gateway_server(input)
        .await
        .map_err(store_refusal)?;

    println!(
        "Secure store: the gateway server at port {} is set over the encrypted API",
        server.port
    );

    HttpOutput::as_json(GatewayServerHttpModel::from(server))
        .encode(&key)
        .into_ok_result(false)
}

/// The gateway server as the store keeps it.
#[derive(Serialize)]
pub struct GatewayServerHttpModel {
    pub port: u32,
    pub allowed_ip: Vec<String>,
    pub debug: bool,
}

impl From<StoredGatewayServer> for GatewayServerHttpModel {
    fn from(server: StoredGatewayServer) -> Self {
        Self {
            port: server.port,
            allowed_ip: server.allowed_ip,
            debug: server.debug,
        }
    }
}

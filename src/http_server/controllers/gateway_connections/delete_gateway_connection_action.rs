use my_http_server::{macros::http_route, HttpContext, HttpFailResult, HttpOkResult, HttpOutput};
use serde::{Deserialize, Serialize};

use super::{key_of_encrypted_request, parse_call, store_refusal, EncryptedJsonHttpInput};

#[http_route(
    method: "POST",
    route: "/api/gateway-connections/v1/delete",
    summary: "Remove a connection to a gateway",
    description: "Encrypted with a network key (Content-Encoding: aes128gcm), and answered encrypted with the same key. Body: JSON `{\"id\": \"london\"}`. The connection is removed from the secure store and its client is stopped: the gateway connection, and everything tunnelled through it, are closed now. The answer is `{\"id\", \"deleted\"}`: `false` when there was no such connection.",
    controller: "GatewayConnections",
    input_data: EncryptedJsonHttpInput,
    result:[
        {status_code: 200, description: "`{\"id\", \"deleted\"}`, encrypted"},
        {status_code: 400, description: "The body opens with no key, or is not the JSON above"},
        {status_code: 415, description: "The body did not come encrypted - or the proxy has no network keys yet"},
        {status_code: 503, description: "The proxy is not initialized"},
        {status_code: 500, description: "The secure store can not be written"},
    ]
)]
pub struct DeleteGatewayConnectionAction;

async fn handle_request(
    _action: &DeleteGatewayConnectionAction,
    input_data: EncryptedJsonHttpInput,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = key_of_encrypted_request(ctx)?;

    let call: DeleteGatewayConnectionCall = parse_call(&input_data.body, "{\"id\": \"...\"}")?;

    let deleted = crate::scripts::delete_gateway_connection(&call.id)
        .await
        .map_err(store_refusal)?;

    if deleted {
        println!(
            "Secure store: gateway connection '{}' is removed over the encrypted API",
            call.id.trim()
        );
    }

    HttpOutput::as_json(DeletedGatewayConnectionHttpModel {
        id: call.id.trim().to_string(),
        deleted,
    })
    .encode(&key)
    .into_ok_result(false)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteGatewayConnectionCall {
    id: String,
}

#[derive(Serialize)]
struct DeletedGatewayConnectionHttpModel {
    id: String,
    deleted: bool,
}

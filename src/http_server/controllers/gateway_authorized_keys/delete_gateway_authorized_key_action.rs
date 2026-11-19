use my_http_server::{macros::http_route, HttpContext, HttpFailResult, HttpOkResult, HttpOutput};
use serde::{Deserialize, Serialize};

use super::{key_of_encrypted_request, parse_call, store_refusal, EncryptedJsonHttpInput};

#[http_route(
    method: "POST",
    route: "/api/gateway-authorized-keys/v1/delete",
    summary: "Stop letting a key in through the gateway server",
    description: "Encrypted with a network key (Content-Encoding: aes128gcm), and answered encrypted with the same key. Body: JSON `{\"id\": \"paris\"}`. The key is removed from the secure store: a gateway connection it let in stays up, and its next handshake is refused. The answer is `{\"id\", \"deleted\"}`: `false` when there was no such key.",
    controller: "GatewayAuthorizedKeys",
    input_data: EncryptedJsonHttpInput,
    result:[
        {status_code: 200, description: "`{\"id\", \"deleted\"}`, encrypted"},
        {status_code: 400, description: "The body opens with no key, or is not the JSON above"},
        {status_code: 415, description: "The body did not come encrypted - or the proxy has no network keys yet"},
        {status_code: 503, description: "The proxy is not initialized"},
        {status_code: 500, description: "The secure store can not be written"},
    ]
)]
pub struct DeleteGatewayAuthorizedKeyAction;

async fn handle_request(
    _action: &DeleteGatewayAuthorizedKeyAction,
    input_data: EncryptedJsonHttpInput,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = key_of_encrypted_request(ctx)?;

    let call: DeleteGatewayAuthorizedKeyCall = parse_call(&input_data.body, "{\"id\": \"...\"}")?;

    let id = call.id.trim();

    let deleted = crate::app::APP_CTX
        .secure
        .delete_gateway_authorized_key(id)
        .await
        .map_err(store_refusal)?;

    if deleted {
        println!(
            "Secure store: the gateway server no longer lets key '{id}' in - removed over the encrypted API"
        );
    }

    HttpOutput::as_json(DeletedGatewayAuthorizedKeyHttpModel {
        id: id.to_string(),
        deleted,
    })
    .encode(&key)
    .into_ok_result(false)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteGatewayAuthorizedKeyCall {
    id: String,
}

#[derive(Serialize)]
struct DeletedGatewayAuthorizedKeyHttpModel {
    id: String,
    deleted: bool,
}

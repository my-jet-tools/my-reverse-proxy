use my_http_server::{macros::http_route, HttpContext, HttpFailResult, HttpOkResult, HttpOutput};
use serde::{Deserialize, Serialize};

use super::{key_of_encrypted_request, parse_call, store_refusal, EncryptedJsonHttpInput};

#[http_route(
    method: "POST",
    route: "/api/private-keys/v1/delete",
    summary: "Remove a private key from the secure store",
    description: "Encrypted with a network key (Content-Encoding: aes128gcm), and answered encrypted with the same key. Body: JSON `{\"id\": \"london\"}`. A gateway client with `private_key: <id>` keeps the connection it has, and does not connect again until a key is installed under the id. The answer is `{\"id\", \"deleted\"}`: `false` when there was no such key.",
    controller: "PrivateKeys",
    input_data: EncryptedJsonHttpInput,
    result:[
        {status_code: 200, description: "`{\"id\", \"deleted\"}`, encrypted"},
        {status_code: 400, description: "The body opens with no key, or is not the JSON above"},
        {status_code: 415, description: "The body did not come encrypted - or the proxy has no network keys yet"},
        {status_code: 503, description: "The proxy is not initialized"},
        {status_code: 500, description: "The secure store can not be written"},
    ]
)]
pub struct DeletePrivateKeyAction;

async fn handle_request(
    _action: &DeletePrivateKeyAction,
    input_data: EncryptedJsonHttpInput,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = key_of_encrypted_request(ctx)?;

    let call: DeletePrivateKeyCall = parse_call(&input_data.body, "{\"id\": \"...\"}")?;

    let id = crate::secure::check_private_key_id(&call.id)
        .map_err(HttpFailResult::as_validation_error)?;

    let deleted = crate::app::APP_CTX
        .secure
        .delete_private_key(id)
        .await
        .map_err(store_refusal)?;

    HttpOutput::as_json(DeletedHttpModel {
        id: id.to_string(),
        deleted,
    })
    .encode(&key)
    .into_ok_result(false)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeletePrivateKeyCall {
    id: String,
}

#[derive(Serialize)]
struct DeletedHttpModel {
    id: String,
    deleted: bool,
}

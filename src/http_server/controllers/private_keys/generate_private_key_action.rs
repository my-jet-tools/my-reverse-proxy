use my_http_server::{macros::http_route, HttpContext, HttpFailResult, HttpOkResult, HttpOutput};
use serde::Deserialize;

use super::{
    key_of_encrypted_request, parse_call, store_refusal, EncryptedJsonHttpInput,
    PrivateKeyHttpModel,
};

#[http_route(
    method: "POST",
    route: "/api/private-keys/v1/generate",
    summary: "Generate a private key in the secure store",
    description: "Encrypted with a network key (Content-Encoding: aes128gcm), and answered encrypted with the same key. Body: JSON `{\"id\": \"london\"}`. A new Ed25519 key is kept in the secure store under `id`; an id which has a key is refused - delete it first. The answer is `{\"id\", \"public_key\"}`: the line for `authorized_keys` of a gateway server, or for `/api/gateway-authorized-keys/v1/set` of a proxy whose gateway server is to let it in. `/api/private-keys/v1/download` gives the key itself.",
    controller: "PrivateKeys",
    input_data: EncryptedJsonHttpInput,
    result:[
        {status_code: 200, description: "Generated: `{\"id\", \"public_key\"}`, encrypted"},
        {status_code: 400, description: "The body opens with no key, is not the JSON above, or the id is empty or too long"},
        {status_code: 409, description: "The id has a key already"},
        {status_code: 415, description: "The body did not come encrypted - or the proxy has no network keys yet"},
        {status_code: 503, description: "The proxy is not initialized"},
        {status_code: 500, description: "The secure store can not be written"},
    ]
)]
pub struct GeneratePrivateKeyAction;

async fn handle_request(
    _action: &GeneratePrivateKeyAction,
    input_data: EncryptedJsonHttpInput,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = key_of_encrypted_request(ctx)?;

    let call: GeneratePrivateKeyCall = parse_call(&input_data.body, "{\"id\": \"...\"}")?;

    let id = crate::secure::check_private_key_id(&call.id)
        .map_err(HttpFailResult::as_validation_error)?;

    let public = crate::app::APP_CTX
        .secure
        .generate_private_key(id)
        .await
        .map_err(store_refusal)?;

    println!("Secure store: private key '{id}' is generated over the encrypted API");

    HttpOutput::as_json(PrivateKeyHttpModel {
        id: id.to_string(),
        public_key: crate::secure::openssh_verifying_key(&public),
    })
    .encode(&key)
    .into_ok_result(false)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GeneratePrivateKeyCall {
    id: String,
}

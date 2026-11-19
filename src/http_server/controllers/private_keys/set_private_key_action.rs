use my_http_server::{macros::http_route, HttpContext, HttpFailResult, HttpOkResult, HttpOutput};
use serde::{Deserialize, Serialize};

use super::{key_of_encrypted_request, parse_call, store_refusal, EncryptedJsonHttpInput};

#[http_route(
    method: "POST",
    route: "/api/private-keys/v1/set",
    summary: "Install a private key in the secure store",
    description: "Encrypted with a network key (Content-Encoding: aes128gcm), and answered encrypted with the same key. Body: JSON `{\"id\": \"london\", \"private_key\": \"<OpenSSH private key>\", \"passphrase\": \"...\"}` - an Ed25519 key in OpenSSH form, what `gateway_keygen` writes; `passphrase` only for a key encrypted with one. It is kept in the secure store under `id`, in place of the key the id had, and a gateway client with `private_key: <id>` signs its next connect with it. The answer is `{\"id\", \"public_key\"}`: the line for `authorized_keys` of the gateway server.",
    controller: "PrivateKeys",
    input_data: EncryptedJsonHttpInput,
    result:[
        {status_code: 200, description: "Installed: `{\"id\", \"public_key\"}`, encrypted"},
        {status_code: 400, description: "The body opens with no key, is not the JSON above, the id is empty or too long, or the key is not an OpenSSH Ed25519 key (or its passphrase does not open it)"},
        {status_code: 415, description: "The body did not come encrypted - or the proxy has no network keys yet"},
        {status_code: 503, description: "The proxy is not initialized"},
        {status_code: 500, description: "The secure store can not be written"},
    ]
)]
pub struct SetPrivateKeyAction;

async fn handle_request(
    _action: &SetPrivateKeyAction,
    input_data: EncryptedJsonHttpInput,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = key_of_encrypted_request(ctx)?;

    let call: SetPrivateKeyCall = parse_call(
        &input_data.body,
        "{\"id\": \"...\", \"private_key\": \"...\", \"passphrase\": \"...\"}",
    )?;

    let id = crate::secure::check_private_key_id(&call.id)
        .map_err(HttpFailResult::as_validation_error)?;

    let signing_key =
        crate::secure::parse_openssh_ed25519(&call.private_key, call.passphrase.as_deref())
            .map_err(HttpFailResult::as_validation_error)?;

    let public_key = crate::secure::openssh_public_key(&signing_key);

    crate::app::APP_CTX
        .secure
        .set_private_key(id, signing_key)
        .await
        .map_err(store_refusal)?;

    HttpOutput::as_json(PrivateKeyHttpModel {
        id: id.to_string(),
        public_key,
    })
    .encode(&key)
    .into_ok_result(false)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetPrivateKeyCall {
    id: String,
    private_key: String,
    passphrase: Option<String>,
}

/// A private key as the API tells of it: its id and its public half - never the key.
#[derive(Serialize)]
pub struct PrivateKeyHttpModel {
    pub id: String,
    pub public_key: String,
}

use my_http_server::{macros::http_route, HttpContext, HttpFailResult, HttpOkResult, HttpOutput};
use serde::{Deserialize, Serialize};

use super::{key_of_encrypted_request, parse_call, EncryptedJsonHttpInput};

#[http_route(
    method: "POST",
    route: "/api/private-keys/v1/download",
    summary: "The private key itself, to connect to the gateway with it",
    description: "Encrypted with a network key (Content-Encoding: aes128gcm), and answered encrypted with the same key - the only way a private key leaves the secure store; MCP never gives one. Body: JSON `{\"id\": \"london\"}`. The answer is `{\"id\", \"private_key\", \"public_key\"}`: `private_key` is the key in OpenSSH form, what `gateway_keygen` writes and `/api/private-keys/v1/set` of another proxy installs - which then connects with it to the gateway server which lets `public_key` in.",
    controller: "PrivateKeys",
    input_data: EncryptedJsonHttpInput,
    result:[
        {status_code: 200, description: "`{\"id\", \"private_key\", \"public_key\"}`, encrypted"},
        {status_code: 400, description: "The body opens with no key, or is not the JSON above"},
        {status_code: 404, description: "The secure store has no key with this id"},
        {status_code: 415, description: "The body did not come encrypted - or the proxy has no network keys yet"},
        {status_code: 503, description: "The proxy is not initialized"},
    ]
)]
pub struct DownloadPrivateKeyAction;

async fn handle_request(
    _action: &DownloadPrivateKeyAction,
    input_data: EncryptedJsonHttpInput,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = key_of_encrypted_request(ctx)?;

    let call: DownloadPrivateKeyCall = parse_call(&input_data.body, "{\"id\": \"...\"}")?;

    let id = call.id.trim();

    if !crate::app::APP_CTX.secure.is_initialized() {
        return Err(super::store_refusal(
            crate::secure::SecureStoreError::NotInitialized,
        ));
    }

    let Some(signing_key) = crate::app::APP_CTX.secure.private_keys.get(id) else {
        return Err(HttpFailResult::as_not_found(
            format!("The secure store has no private key '{id}'"),
            false,
        ));
    };

    println!("Secure store: private key '{id}' is given over the encrypted API");

    let private_key = crate::secure::openssh_private_key(&signing_key, &format!("gateway-{id}"));

    HttpOutput::as_json(DownloadedPrivateKeyHttpModel {
        id: id.to_string(),
        private_key: private_key.to_string(),
        public_key: crate::secure::openssh_public_key(&signing_key),
    })
    .encode(&key)
    .into_ok_result(false)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DownloadPrivateKeyCall {
    id: String,
}

#[derive(Serialize)]
struct DownloadedPrivateKeyHttpModel {
    id: String,
    private_key: String,
    public_key: String,
}

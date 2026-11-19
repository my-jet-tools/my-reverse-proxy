use my_http_server::{macros::http_route, HttpContext, HttpFailResult, HttpOkResult, HttpOutput};
use serde::Serialize;

use super::{key_of_encrypted_request, EncryptedJsonHttpInput, PrivateKeyHttpModel};

#[http_route(
    method: "POST",
    route: "/api/private-keys/v1/list",
    summary: "The private keys of the secure store",
    description: "Encrypted with a network key (Content-Encoding: aes128gcm), and answered encrypted with the same key. The body is any JSON - `{}` - since an empty body carries no encryption. The answer is `{\"private_keys\": [{\"id\", \"public_key\"}]}`, by the ids in order: the public halves, never the keys.",
    controller: "PrivateKeys",
    input_data: EncryptedJsonHttpInput,
    result:[
        {status_code: 200, description: "`{\"private_keys\": [...]}`, encrypted"},
        {status_code: 400, description: "The body opens with no key"},
        {status_code: 415, description: "The body did not come encrypted - or the proxy has no network keys yet"},
    ]
)]
pub struct ListPrivateKeysAction;

async fn handle_request(
    _action: &ListPrivateKeysAction,
    _input_data: EncryptedJsonHttpInput,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = key_of_encrypted_request(ctx)?;

    let private_keys = crate::app::APP_CTX
        .secure
        .private_keys
        .list()
        .into_iter()
        .map(|(id, signing_key)| PrivateKeyHttpModel {
            public_key: crate::secure::openssh_public_key(&signing_key),
            id,
        })
        .collect();

    HttpOutput::as_json(PrivateKeysHttpModel { private_keys })
        .encode(&key)
        .into_ok_result(false)
}

#[derive(Serialize)]
struct PrivateKeysHttpModel {
    private_keys: Vec<PrivateKeyHttpModel>,
}

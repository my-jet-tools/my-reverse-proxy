use my_http_server::{macros::http_route, HttpContext, HttpFailResult, HttpOkResult, HttpOutput};
use serde::Serialize;

use super::{key_of_encrypted_request, EncryptedJsonHttpInput, GatewayAuthorizedKeyHttpModel};

#[http_route(
    method: "POST",
    route: "/api/gateway-authorized-keys/v1/list",
    summary: "The keys of the secure store the gateway server lets in",
    description: "Encrypted with a network key (Content-Encoding: aes128gcm), and answered encrypted with the same key. The body is any JSON - `{}` - since an empty body carries no encryption. The answer is `{\"authorized_keys\": [{\"id\", \"public_key\", \"ip_white_list\"}]}`, by the ids in order: the gateway name each key comes in under, the key, and the addresses it comes from. The keys of the `authorized_keys` files are not here.",
    controller: "GatewayAuthorizedKeys",
    input_data: EncryptedJsonHttpInput,
    result:[
        {status_code: 200, description: "`{\"authorized_keys\": [...]}`, encrypted"},
        {status_code: 400, description: "The body opens with no key"},
        {status_code: 415, description: "The body did not come encrypted - or the proxy has no network keys yet"},
    ]
)]
pub struct ListGatewayAuthorizedKeysAction;

async fn handle_request(
    _action: &ListGatewayAuthorizedKeysAction,
    _input_data: EncryptedJsonHttpInput,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = key_of_encrypted_request(ctx)?;

    let authorized_keys = crate::app::APP_CTX
        .secure
        .gateway_authorized_keys
        .list()
        .iter()
        .map(|itm| GatewayAuthorizedKeyHttpModel {
            id: itm.id.clone(),
            public_key: crate::secure::openssh_verifying_key(&itm.key),
            ip_white_list: itm.ip_white_list.clone(),
        })
        .collect();

    HttpOutput::as_json(GatewayAuthorizedKeysHttpModel { authorized_keys })
        .encode(&key)
        .into_ok_result(false)
}

#[derive(Serialize)]
struct GatewayAuthorizedKeysHttpModel {
    authorized_keys: Vec<GatewayAuthorizedKeyHttpModel>,
}

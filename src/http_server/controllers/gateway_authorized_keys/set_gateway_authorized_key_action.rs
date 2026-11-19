use my_http_server::{macros::http_route, HttpContext, HttpFailResult, HttpOkResult, HttpOutput};
use serde::{Deserialize, Serialize};

use super::{key_of_encrypted_request, parse_call, store_refusal, EncryptedJsonHttpInput};

#[http_route(
    method: "POST",
    route: "/api/gateway-authorized-keys/v1/set",
    summary: "Let a key in through the gateway server",
    description: "Encrypted with a network key (Content-Encoding: aes128gcm), and answered encrypted with the same key. Body: JSON `{\"id\": \"paris\", \"public_key\": \"ssh-ed25519 AAAA...\"}` - an Ed25519 public key in OpenSSH form: what `/api/private-keys/v1/generate`, the MCP tool `get_public_key` or the `.pub` file of `gateway_keygen` give. It is kept in the secure store under `id` - in place of the key the id had - and the gateway server lets a client which signs with its private half in from the next handshake on, besides the keys of its `authorized_keys` files. The answer is `{\"id\", \"public_key\"}`.",
    controller: "GatewayAuthorizedKeys",
    input_data: EncryptedJsonHttpInput,
    result:[
        {status_code: 200, description: "Set: `{\"id\", \"public_key\"}`, encrypted"},
        {status_code: 400, description: "The body opens with no key, is not the JSON above, the id is empty or too long, or the key is not an OpenSSH Ed25519 public key"},
        {status_code: 415, description: "The body did not come encrypted - or the proxy has no network keys yet"},
        {status_code: 503, description: "The proxy is not initialized"},
        {status_code: 500, description: "The secure store can not be written"},
    ]
)]
pub struct SetGatewayAuthorizedKeyAction;

async fn handle_request(
    _action: &SetGatewayAuthorizedKeyAction,
    input_data: EncryptedJsonHttpInput,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = key_of_encrypted_request(ctx)?;

    let call: SetGatewayAuthorizedKeyCall = parse_call(
        &input_data.body,
        "{\"id\": \"...\", \"public_key\": \"ssh-ed25519 ...\"}",
    )?;

    let id = crate::secure::check_private_key_id(&call.id)
        .map_err(HttpFailResult::as_validation_error)?;

    let public = crate::secure::parse_openssh_ed25519_public(&call.public_key)
        .map_err(HttpFailResult::as_validation_error)?;

    crate::app::APP_CTX
        .secure
        .set_gateway_authorized_key(id, public)
        .await
        .map_err(store_refusal)?;

    println!("Secure store: the gateway server lets key '{id}' in - set over the encrypted API");

    HttpOutput::as_json(GatewayAuthorizedKeyHttpModel {
        id: id.to_string(),
        public_key: crate::secure::openssh_verifying_key(&public),
    })
    .encode(&key)
    .into_ok_result(false)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetGatewayAuthorizedKeyCall {
    id: String,
    public_key: String,
}

/// A key the gateway server lets in: its id and the key.
#[derive(Serialize)]
pub struct GatewayAuthorizedKeyHttpModel {
    pub id: String,
    pub public_key: String,
}

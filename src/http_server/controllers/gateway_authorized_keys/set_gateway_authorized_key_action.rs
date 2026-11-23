use my_http_server::{macros::http_route, HttpContext, HttpFailResult, HttpOkResult, HttpOutput};
use serde::{Deserialize, Serialize};

use super::{key_of_encrypted_request, parse_call, store_refusal, EncryptedJsonHttpInput};

#[http_route(
    method: "POST",
    route: "/api/gateway-authorized-keys/v1/set",
    summary: "Let a key in through the gateway server",
    description: "Encrypted with a network key (Content-Encoding: aes128gcm), and answered encrypted with the same key. Body: JSON `{\"id\": \"london\", \"public_key\": \"ssh-ed25519 AAAA...\", \"ip_white_list\": [\"10.0.0.5\", \"10.1.0.0/24\"]}`. `id` is the gateway name the client comes in under - the id of its `gateway_clients` entry or of its connection - letters, digits, `-`, `_` and `.`; `public_key` an Ed25519 public key in OpenSSH form, what `/api/private-keys/v1/generate`, the MCP tool `get_public_key` or the `.pub` file of `gateway_keygen` give; `ip_white_list` the addresses it connects from - entries of `ip_white_lists`: addresses, `from-to` ranges, subnets, `*` for any - at least one. The gateway server lets a client which signs with the key in from the next handshake on - under that name only, and from those addresses only - besides the keys of its `authorized_keys` files. Kept in the secure store under `id`, in place of what the id had. The answer is `{\"id\", \"public_key\", \"ip_white_list\"}`.",
    controller: "GatewayAuthorizedKeys",
    input_data: EncryptedJsonHttpInput,
    result:[
        {status_code: 200, description: "Set: `{\"id\", \"public_key\", \"ip_white_list\"}`, encrypted"},
        {status_code: 400, description: "The body opens with no key, is not the JSON above, the id is not a gateway name, the key is not an OpenSSH Ed25519 public key, or ip_white_list is empty or has an entry which is not one"},
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
        "{\"id\": \"<gateway name>\", \"public_key\": \"ssh-ed25519 ...\", \"ip_white_list\": [\"...\"]}",
    )?;

    let id = crate::secure::check_gateway_connection_id(&call.id)
        .map_err(HttpFailResult::as_validation_error)?;

    let public = crate::secure::parse_openssh_ed25519_public(&call.public_key)
        .map_err(HttpFailResult::as_validation_error)?;

    let ip_white_list = crate::secure::check_key_ip_white_list(&call.ip_white_list)
        .map_err(HttpFailResult::as_validation_error)?;

    crate::app::APP_CTX
        .secure
        .set_gateway_authorized_key(id, public, ip_white_list.clone())
        .await
        .map_err(store_refusal)?;

    println!(
        "Secure store: the gateway server lets '{id}' in from {ip_white_list:?} - set over the encrypted API"
    );

    HttpOutput::as_json(GatewayAuthorizedKeyHttpModel {
        id: id.to_string(),
        public_key: crate::secure::openssh_verifying_key(&public),
        ip_white_list,
    })
    .encode(&key)
    .into_ok_result(false)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetGatewayAuthorizedKeyCall {
    id: String,
    public_key: String,
    ip_white_list: Vec<String>,
}

/// A key the gateway server lets in: the gateway name it comes in under, the key, and where from.
#[derive(Serialize)]
pub struct GatewayAuthorizedKeyHttpModel {
    pub id: String,
    pub public_key: String,
    pub ip_white_list: Vec<String>,
}

use my_http_server::{macros::http_route, HttpContext, HttpFailResult, HttpOkResult, HttpOutput};
use serde::Serialize;

use super::{key_of_encrypted_request, store_refusal, EncryptedJsonHttpInput};

#[http_route(
    method: "POST",
    route: "/api/gateway-server/v1/delete",
    summary: "Stop the gateway server",
    description: "Encrypted with a network key (Content-Encoding: aes128gcm), and answered encrypted with the same key. The body is any JSON - `{}` - since an empty body carries no encryption. The gateway server of the secure store is removed from it and stopped: its port is closed, and the connections of its clients, with everything tunnelled through them. A gateway server of the settings is not touched. The answer is `{\"deleted\"}`: `false` when the store had none.",
    controller: "GatewayServer",
    input_data: EncryptedJsonHttpInput,
    result:[
        {status_code: 200, description: "`{\"deleted\"}`, encrypted"},
        {status_code: 400, description: "The body opens with no key"},
        {status_code: 415, description: "The body did not come encrypted - or the proxy has no network keys yet"},
        {status_code: 503, description: "The proxy is not initialized"},
        {status_code: 500, description: "The secure store can not be written"},
    ]
)]
pub struct DeleteGatewayServerAction;

async fn handle_request(
    _action: &DeleteGatewayServerAction,
    _input_data: EncryptedJsonHttpInput,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = key_of_encrypted_request(ctx)?;

    let deleted = crate::scripts::delete_gateway_server()
        .await
        .map_err(store_refusal)?;

    if deleted {
        println!("Secure store: the gateway server is removed and stopped over the encrypted API");
    }

    HttpOutput::as_json(DeletedGatewayServerHttpModel { deleted })
        .encode(&key)
        .into_ok_result(false)
}

#[derive(Serialize)]
struct DeletedGatewayServerHttpModel {
    deleted: bool,
}

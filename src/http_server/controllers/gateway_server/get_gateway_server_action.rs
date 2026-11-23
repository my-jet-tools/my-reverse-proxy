use my_http_server::{macros::http_route, HttpContext, HttpFailResult, HttpOkResult, HttpOutput};
use serde::Serialize;

use super::{key_of_encrypted_request, EncryptedJsonHttpInput, GatewayServerHttpModel};

#[http_route(
    method: "POST",
    route: "/api/gateway-server/v1/get",
    summary: "The gateway server: the one the secure store keeps, and the one which runs",
    description: "Encrypted with a network key (Content-Encoding: aes128gcm), and answered encrypted with the same key. The body is any JSON - `{}` - since an empty body carries no encryption. The answer is `{\"secure_store\": {\"port\", \"allowed_ip\", \"debug\"} | null, \"running\": {\"source\": \"secure_store\" | \"settings\", \"listen\", \"clients\"} | null}`: what the store keeps, and the server which runs now with the gateway names of the clients connected to it. A server the store keeps and which does not run - its port could not be had at initialize - is in the first and not in the second.",
    controller: "GatewayServer",
    input_data: EncryptedJsonHttpInput,
    result:[
        {status_code: 200, description: "`{\"secure_store\", \"running\"}`, encrypted"},
        {status_code: 400, description: "The body opens with no key"},
        {status_code: 415, description: "The body did not come encrypted - or the proxy has no network keys yet"},
    ]
)]
pub struct GetGatewayServerAction;

async fn handle_request(
    _action: &GetGatewayServerAction,
    _input_data: EncryptedJsonHttpInput,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = key_of_encrypted_request(ctx)?;

    let secure_store = crate::app::APP_CTX
        .secure
        .gateway_server()
        .map(GatewayServerHttpModel::from);

    let running =
        crate::scripts::running_gateway_server()
            .await
            .map(|itm| RunningGatewayServerHttpModel {
                source: if itm.from_secure_store {
                    "secure_store"
                } else {
                    "settings"
                },
                listen: itm.listen,
                clients: itm.clients,
            });

    HttpOutput::as_json(GatewayServerStateHttpModel {
        secure_store,
        running,
    })
    .encode(&key)
    .into_ok_result(false)
}

#[derive(Serialize)]
struct GatewayServerStateHttpModel {
    secure_store: Option<GatewayServerHttpModel>,
    running: Option<RunningGatewayServerHttpModel>,
}

#[derive(Serialize)]
struct RunningGatewayServerHttpModel {
    source: &'static str,
    listen: String,
    clients: Vec<String>,
}

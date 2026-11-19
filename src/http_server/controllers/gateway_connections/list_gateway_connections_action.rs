use my_http_server::{macros::http_route, HttpContext, HttpFailResult, HttpOkResult, HttpOutput};
use serde::Serialize;

use super::{key_of_encrypted_request, EncryptedJsonHttpInput, GatewayConnectionHttpModel};

#[http_route(
    method: "POST",
    route: "/api/gateway-connections/v1/list",
    summary: "The connections to gateways of the secure store",
    description: "Encrypted with a network key (Content-Encoding: aes128gcm), and answered encrypted with the same key. The body is any JSON - `{}` - since an empty body carries no encryption. The answer is `{\"gateway_connections\": [...]}`, by the ids in order: each as `/api/gateway-connections/v1/set` keeps it, with `connected` - whether its gateway connection is up now. The gateway clients of the settings are not here.",
    controller: "GatewayConnections",
    input_data: EncryptedJsonHttpInput,
    result:[
        {status_code: 200, description: "`{\"gateway_connections\": [...]}`, encrypted"},
        {status_code: 400, description: "The body opens with no key"},
        {status_code: 415, description: "The body did not come encrypted - or the proxy has no network keys yet"},
    ]
)]
pub struct ListGatewayConnectionsAction;

async fn handle_request(
    _action: &ListGatewayConnectionsAction,
    _input_data: EncryptedJsonHttpInput,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = key_of_encrypted_request(ctx)?;

    let gateway_connections = crate::scripts::list_gateway_connections()
        .into_iter()
        .map(|itm| GatewayConnectionHttpModel::new(itm.connection, itm.connected))
        .collect();

    HttpOutput::as_json(GatewayConnectionsHttpModel {
        gateway_connections,
    })
    .encode(&key)
    .into_ok_result(false)
}

#[derive(Serialize)]
struct GatewayConnectionsHttpModel {
    gateway_connections: Vec<GatewayConnectionHttpModel>,
}

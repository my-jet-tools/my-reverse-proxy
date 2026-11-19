use my_http_server::{macros::http_route, HttpContext, HttpFailResult, HttpOkResult, HttpOutput};

use super::{
    key_of_encrypted_request, parse_call, store_refusal, EncryptedJsonHttpInput,
    GatewayConnectionHttpModel,
};

#[http_route(
    method: "POST",
    route: "/api/gateway-connections/v1/set",
    summary: "Set a connection to a gateway",
    description: "Encrypted with a network key (Content-Encoding: aes128gcm), and answered encrypted with the same key. Body: JSON `{\"id\": \"london\", \"remote_host\": \"gateway.example.com:9000\", \"private_key\": \"to-london\", \"compress\": 1, \"connect_timeout\": 5000, \"allow_incoming_forward_connections\": false, \"sync_ssl_certificates\": [], \"debug\": false}` - the fields of an entry of `gateway_clients` of the settings; all but `id`, `remote_host` and `private_key` may be left out. `private_key` is the id of a private key of the secure store, which has to be there. The connection is kept in the secure store under `id` - in place of the one there was - and its client is started at once, and after every initialize from then on: routes name it as `gateway:<id>->...`. The id of a gateway client of the settings is refused. The answer is the connection as kept.",
    controller: "GatewayConnections",
    input_data: EncryptedJsonHttpInput,
    result:[
        {status_code: 200, description: "Set and started: the connection, encrypted"},
        {status_code: 400, description: "The body opens with no key, is not the JSON above, a field can not work, or the private key is not in the secure store"},
        {status_code: 409, description: "The settings have a gateway client with this id"},
        {status_code: 415, description: "The body did not come encrypted - or the proxy has no network keys yet"},
        {status_code: 503, description: "The proxy is not initialized"},
        {status_code: 500, description: "The secure store can not be written"},
    ]
)]
pub struct SetGatewayConnectionAction;

async fn handle_request(
    _action: &SetGatewayConnectionAction,
    input_data: EncryptedJsonHttpInput,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = key_of_encrypted_request(ctx)?;

    let input: crate::secure::GatewayConnectionInput = parse_call(
        &input_data.body,
        "{\"id\": \"...\", \"remote_host\": \"host:port\", \"private_key\": \"...\", ...}",
    )?;

    let connection = crate::scripts::set_gateway_connection(input)
        .await
        .map_err(store_refusal)?;

    println!(
        "Secure store: gateway connection '{}' to '{}' is set over the encrypted API",
        connection.id, connection.remote_host
    );

    HttpOutput::as_json(GatewayConnectionHttpModel::new(connection, false))
        .encode(&key)
        .into_ok_result(false)
}

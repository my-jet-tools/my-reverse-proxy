use mcp_server_middleware::*;
use serde::*;

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct GetClientCaEndpointsStatusInputData {}

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct ClientCaEndpointStatusEntry {
    #[property(
        description = "Endpoint host as configured, e.g. `example.com:443` or a unix socket path."
    )]
    pub endpoint_host: String,

    #[property(
        description = "Id of the client certificate ca this endpoint verifies client certificates against. Use this as `ca_id` when uploading it via init_client_certificate_ca."
    )]
    pub ca_id: String,

    #[property(
        description = "False when the ca is declared by the endpoint but not loaded — every TLS handshake to this endpoint is cut right now."
    )]
    pub loaded: bool,

    #[property(description = "Common Name of the loaded ca. Empty when the ca is not loaded.")]
    pub cn: String,

    #[property(
        description = "RFC3339 expiry of the loaded ca. Empty when the ca is not loaded. The ca's OWN expiry is not enforced (an expired ca keeps verifying clients); the validity dates of the CLIENT certificates are enforced, unless this entry declares unlimited_expiration."
    )]
    pub expires: String,

    #[property(
        description = "How many revoked serials the loaded ca carries (from its CRL). 0 when the ca is not loaded or has no revocation list."
    )]
    pub crl_records: i64,

    #[property(
        description = "The loaded ca is past its expiry. It still verifies clients (validity dates are not checked during verification), but it is almost certainly not what the operator intends."
    )]
    pub expired: bool,

    #[property(
        description = "The ca entry declares `unlimited_expiration: true` - client certificates verified against it are accepted however old they are. Deliberate, but worth reporting when an endpoint's access is being reviewed."
    )]
    pub unlimited_expiration: bool,
}

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct GetClientCaEndpointsStatusResponse {
    #[property(
        description = "One entry per https/mcp endpoint that requires a client certificate (mTLS)."
    )]
    pub endpoints: Vec<ClientCaEndpointStatusEntry>,

    #[property(description = "Total number of endpoints reported.")]
    pub total: i64,

    #[property(
        description = "How many endpoints require a ca that is not loaded and therefore cut every connection."
    )]
    pub needs_attention: i64,
}

pub struct GetClientCaEndpointsStatusHandler;

impl ToolDefinition for GetClientCaEndpointsStatusHandler {
    const FUNC_NAME: &'static str = "get_client_ca_endpoints_status";
    const DESCRIPTION: &'static str = "List every https/mcp endpoint that requires a client certificate (mTLS) and report whether the ca it verifies against is loaded. A ca that is declared in configuration but never resolved (no `client_certificate_ca` entry, unreachable source, broken PEM) leaves the endpoint listening while every TLS handshake is cut — nothing is ever served without client-certificate verification. To fix such an endpoint, upload the ca with init_client_certificate_ca — it is used immediately, no reload required.";
}

#[async_trait::async_trait]
impl McpToolCall<GetClientCaEndpointsStatusInputData, GetClientCaEndpointsStatusResponse>
    for GetClientCaEndpointsStatusHandler
{
    async fn execute_tool_call(
        &self,
        _model: GetClientCaEndpointsStatusInputData,
    ) -> Result<GetClientCaEndpointsStatusResponse, String> {
        let statuses = crate::scripts::get_client_ca_endpoints_status().await;

        let mut needs_attention = 0i64;
        let mut endpoints = Vec::with_capacity(statuses.len());

        for status in statuses {
            if !status.loaded {
                needs_attention += 1;
            }

            endpoints.push(ClientCaEndpointStatusEntry {
                endpoint_host: status.endpoint_host,
                ca_id: status.ca_id,
                loaded: status.loaded,
                cn: status.cn.unwrap_or_default(),
                expires: status.expires.map(|e| e.to_rfc3339()).unwrap_or_default(),
                crl_records: status.crl_records.unwrap_or(0) as i64,
                expired: status.expired,
                unlimited_expiration: status.unlimited_expiration,
            });
        }

        let total = endpoints.len() as i64;

        Ok(GetClientCaEndpointsStatusResponse {
            endpoints,
            total,
            needs_attention,
        })
    }
}

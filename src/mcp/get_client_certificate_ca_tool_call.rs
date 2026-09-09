use mcp_server_middleware::*;
use serde::*;

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct GetClientCertificateCaInputData {
    #[property(
        description = "Id of the client certificate ca to read (see the `ca_id` field of get_client_ca_endpoints_status)."
    )]
    pub ca_id: String,
}

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct GetClientCertificateCaResponse {
    #[property(
        description = "True when a ca is loaded under this id. When false, all other fields are empty and every TLS handshake to the endpoints requiring it is currently cut."
    )]
    pub found: bool,

    #[property(description = "Id of the client certificate ca.")]
    pub ca_id: String,

    #[property(description = "Common Name of the ca.")]
    pub cn: String,

    #[property(description = "RFC3339 expiry of the ca.")]
    pub expires: String,

    #[property(
        description = "The ca is past its expiry. It still verifies clients - the ca's OWN validity is not enforced (unlike the client certificates', which is) - but it is almost certainly not what the operator intends."
    )]
    pub expired: bool,

    #[property(
        description = "Whether the certificate declares BasicConstraints CA:TRUE. False means a self-signed leaf is acting as the trust anchor."
    )]
    pub is_ca: bool,

    #[property(
        description = "Where the ca came from: `local_source` (resolved from the configured file source) or `manually_provided` (uploaded at runtime)."
    )]
    pub origin: String,

    #[property(
        description = "How many revoked serials its revocation list carries. 0 means no client certificate can be revoked."
    )]
    pub crl_records: i64,

    #[property(
        description = "The ca entry declares `unlimited_expiration: true`, so client certificates verified against it are accepted regardless of their validity dates."
    )]
    pub unlimited_expiration: bool,
}

pub struct GetClientCertificateCaHandler;

impl ToolDefinition for GetClientCertificateCaHandler {
    const FUNC_NAME: &'static str = "get_client_certificate_ca";
    const DESCRIPTION: &'static str = "Return metadata about the client certificate ca (mTLS trust anchor) currently loaded for a given id: its CN, expiry, whether it is a real CA certificate, where it came from and how many serials its revocation list carries. Metadata only — the raw CA PEM material is never exposed. Use it to see what an endpoint trusts, and to check what you would be replacing before calling init_client_certificate_ca.";
}

#[async_trait::async_trait]
impl McpToolCall<GetClientCertificateCaInputData, GetClientCertificateCaResponse>
    for GetClientCertificateCaHandler
{
    async fn execute_tool_call(
        &self,
        model: GetClientCertificateCaInputData,
    ) -> Result<GetClientCertificateCaResponse, String> {
        match crate::scripts::get_client_ca_details(&model.ca_id).await {
            Some(details) => Ok(GetClientCertificateCaResponse {
                found: true,
                ca_id: details.id,
                cn: details.cn,
                expires: details.expires.to_rfc3339(),
                expired: details.expired,
                is_ca: details.is_ca,
                origin: details.origin,
                crl_records: details.crl_records as i64,
                unlimited_expiration: details.unlimited_expiration,
            }),
            None => Ok(GetClientCertificateCaResponse {
                found: false,
                ca_id: model.ca_id.trim().to_string(),
                cn: String::new(),
                expires: String::new(),
                expired: false,
                is_ca: false,
                origin: String::new(),
                crl_records: 0,
                unlimited_expiration: false,
            }),
        }
    }
}

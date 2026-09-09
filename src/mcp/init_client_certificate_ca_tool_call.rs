use mcp_server_middleware::*;
use serde::*;

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct InitClientCertificateCaInputData {
    #[property(
        description = "Id of the client certificate ca to install, exactly as referenced by an endpoint (see the `ca_id` field of get_client_ca_endpoints_status)."
    )]
    pub ca_id: String,

    #[property(
        description = "The CA certificate in PEM format - EXACTLY ONE -----BEGIN CERTIFICATE----- block. Client certificates presented to the endpoint must be signed directly by it, so for a root -> issuing-ca -> client chain pass the issuing ca. A PEM with several certificates is refused: only one is ever used as the trust anchor."
    )]
    pub ca: String,

    #[property(
        description = "Optional certificate revocation list in PEM format (-----BEGIN X509 CRL-----). When omitted, the 'revocation_list' configured for this ca id is loaded from its source (and the upload is REFUSED if it can not be read), else the list of the ca being replaced is kept. Never pass an empty string to clear it - there is no way to remove revocations through this tool."
    )]
    pub crl: Option<String>,

    #[property(
        description = "Set only when the operator explicitly asked to rotate to a DIFFERENT certification authority. Without it, replacing a loaded ca with an unrelated one is refused, because it changes which clients the endpoint trusts. Never set it on your own initiative to get past that refusal."
    )]
    pub replace_different_ca: Option<bool>,
}

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct InitClientCertificateCaResponse {
    #[property(description = "Id of the client certificate ca that was installed.")]
    pub ca_id: String,

    #[property(description = "Common Name of the installed ca.")]
    pub cn: String,

    #[property(description = "RFC3339 expiry of the installed ca.")]
    pub expires: String,

    #[property(
        description = "The installed ca is already past its expiry. It still verifies clients here (validity dates are not checked during verification), but it is almost certainly the wrong file."
    )]
    pub expired: bool,

    #[property(
        description = "Whether the uploaded certificate declares BasicConstraints CA:TRUE. False means a self-signed leaf was installed as the trust anchor — accepted, but usually a mistake."
    )]
    pub is_ca: bool,

    #[property(description = "Endpoints that require this ca and are now able to verify clients.")]
    pub endpoints: Vec<String>,

    #[property(description = "Revoked serials the ca is loaded with after the upload.")]
    pub crl_records: i64,

    #[property(
        description = "Where those serials came from: 'uploaded', 'configured_revocation_list' (loaded from the source declared in the configuration, and kept refreshed by the timer), 'kept_from_previous' (the list of the ca that was replaced), or 'none' (nothing can be revoked)."
    )]
    pub crl_source: String,

    #[property(
        description = "True when the upload replaced a ca of a different authority - the set of clients the endpoint trusts has changed."
    )]
    pub replaced_different_authority: bool,
}

pub struct InitClientCertificateCaHandler;

impl ToolDefinition for InitClientCertificateCaHandler {
    const FUNC_NAME: &'static str = "init_client_certificate_ca";
    const DESCRIPTION: &'static str = "Upload (or replace) the client certificate ca (mTLS trust anchor) of a running endpoint by id. WORKFLOW: first call get_client_ca_endpoints_status to find the endpoint whose ca is not loaded and note its `ca_id`, then pass the CA certificate PEM here. SAFETY: before storing, this validates that (1) the PEM contains exactly one readable x509 certificate, (2) at least one endpoint requires `ca_id`, and (3) if a ca is already loaded under that id, the uploaded one is the SAME authority - replacing it with an unrelated ca is refused unless `replace_different_ca` is set. This ca decides WHICH CLIENTS ARE TRUSTED by that endpoint: installing an unrelated ca lets its certificate holders in, so upload only material the operator handed you for this endpoint, and never set `replace_different_ca` to get past a refusal on your own initiative. Revocation is fail-closed: with no `crl` passed, the `revocation_list` configured for this ca id is loaded and the upload is REFUSED if it can not be read, so a manual upload never quietly disables revocation. On success the ca is used on the next TLS handshake with no reload - connections already established keep the ca they handshook with, so replacing a compromised ca does not by itself drop the clients already connected under it.";
}

#[async_trait::async_trait]
impl McpToolCall<InitClientCertificateCaInputData, InitClientCertificateCaResponse>
    for InitClientCertificateCaHandler
{
    async fn execute_tool_call(
        &self,
        model: InitClientCertificateCaInputData,
    ) -> Result<InitClientCertificateCaResponse, String> {
        let crl = model
            .crl
            .map(|crl| crl.trim().to_string())
            .filter(|crl| !crl.is_empty())
            .map(|crl| crl.into_bytes());

        let result = crate::scripts::init_client_ca_manually(
            &model.ca_id,
            model.ca.into_bytes(),
            crl,
            model.replace_different_ca.unwrap_or(false),
        )
        .await?;

        Ok(InitClientCertificateCaResponse {
            ca_id: result.ca_id,
            cn: result.cn,
            expires: result.expires.to_rfc3339(),
            expired: result.expired,
            is_ca: result.is_ca,
            endpoints: result.endpoints,
            crl_records: result.crl_records as i64,
            crl_source: result.crl_source.to_string(),
            replaced_different_authority: result.replaced_different_authority,
        })
    }
}

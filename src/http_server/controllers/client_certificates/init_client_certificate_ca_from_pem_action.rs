use my_http_server::{
    macros::{http_route, MyHttpInput, MyHttpObjectStructure},
    HttpContext, HttpFailResult, HttpOkResult, HttpOutput,
};
use serde::Serialize;

use crate::http_server::controllers::decode_base64_pem;

#[http_route(
    method: "POST",
    route: "/api/ClientCertificates/InitFromPem",
    summary: "Init (upload) a client certificate ca passing PEM in a json body",
    description: "Same as /api/ClientCertificates/Init but the CA (and the optional revocation list) travel in a json body as base64 of their PEM text - this is what the admin ui uses when the operator pastes the CA into the 'Client cert CA not loaded' dialog. Base64 keeps the multi-line PEM intact through json (a `#[http_body]` String comes back with its json escapes unresolved, so raw PEM in a json field would arrive corrupted). Send the base64 as a SINGLE line - `base64 < ca.crt` and `openssl base64` wrap at 76 characters and the wrapping newlines survive as literal backslash-n. Validation before anything is stored: the PEM must contain exactly ONE certificate (only one is ever used as the trust anchor - upload the ca that directly issues the client certificates), at least one endpoint must require this ca id, and if a ca is already loaded under this id the uploaded one must be the same authority unless replace_different_ca is set. Revocation list, in order: the uploaded one, else the 'revocation_list' configured for this ca id (loaded here - the upload is REFUSED if it can not be read, rather than installing a ca without the revocations it is configured to enforce), else the list of the ca being replaced, else none. The ca is used from the next TLS handshake - no reload required; connections already established keep the ca they handshook with.",
    controller: "ClientCertificates",
    input_data: InitClientCertificateCaFromPemHttpInput,
    result:[
        {status_code: 200, description: "CA validated and installed", model:"InitClientCertificateCaResultHttpModel"},
        {status_code: 400, description: "Validation error (bad base64, bad PEM, bad CRL, or no endpoint requires this ca id)"},
    ]
)]
pub struct InitClientCertificateCaFromPemAction;

async fn handle_request(
    _action: &InitClientCertificateCaFromPemAction,
    input_data: InitClientCertificateCaFromPemHttpInput,
    _ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let ca_pem = decode_base64_pem(&input_data.ca, "ca")?;

    let crl_pem = match input_data.crl.as_deref() {
        // An empty/whitespace-only field means "no CRL sent" - the ui always posts the field.
        Some(crl) if !crl.trim().is_empty() => Some(decode_base64_pem(crl, "crl")?),
        _ => None,
    };

    let result = crate::scripts::init_client_ca_manually(
        &input_data.ca_id,
        ca_pem,
        crl_pem,
        input_data.replace_different_ca.unwrap_or(false),
    )
    .await
    .map_err(HttpFailResult::as_validation_error)?;

    HttpOutput::as_json(InitClientCertificateCaResultHttpModel::new(result)).into_ok_result(true)
}

#[derive(MyHttpInput)]
pub struct InitClientCertificateCaFromPemHttpInput {
    #[http_body(
        name = "ca_id",
        description = "Id of the client certificate ca as referenced by the endpoint in configuration"
    )]
    pub ca_id: String,

    #[http_body(
        name = "ca",
        description = "The CA certificate: base64 of the PEM text"
    )]
    pub ca: String,

    #[http_body(
        name = "crl",
        description = "Optional certificate revocation list: base64 of the PEM text. When omitted the configured 'revocation_list' is loaded, or the list of the CA being replaced is kept"
    )]
    pub crl: Option<String>,

    #[http_body(
        name = "replace_different_ca",
        description = "Allow replacing a loaded CA with a DIFFERENT authority (a deliberate rotation). Without it such an upload is refused, because it changes which clients the endpoint trusts"
    )]
    pub replace_different_ca: Option<bool>,
}

// `MyHttpObjectStructure` does not tolerate doc comments on the fields - the field meaning is
// described in the action `description` above instead.
#[derive(Debug, Serialize, MyHttpObjectStructure)]
pub struct InitClientCertificateCaResultHttpModel {
    pub ca_id: String,
    pub cn: String,
    pub expires: String,
    pub expired: bool,
    pub is_ca: bool,
    pub endpoints: Vec<String>,
    pub crl_records: usize,
    // Where those revoked serials came from: uploaded / configured_revocation_list /
    // kept_from_previous / none.
    pub crl_source: String,
    pub replaced_different_authority: bool,
    // `unlimited_expiration:` on the ca entry - the validity dates of client certificates
    // verified against this ca are not enforced.
    pub unlimited_expiration: bool,
}

impl InitClientCertificateCaResultHttpModel {
    pub fn new(src: crate::scripts::InitClientCaResult) -> Self {
        Self {
            ca_id: src.ca_id,
            cn: src.cn,
            expires: src.expires.to_rfc3339(),
            expired: src.expired,
            is_ca: src.is_ca,
            endpoints: src.endpoints,
            crl_records: src.crl_records,
            crl_source: src.crl_source.to_string(),
            replaced_different_authority: src.replaced_different_authority,
            unlimited_expiration: src.unlimited_expiration,
        }
    }
}

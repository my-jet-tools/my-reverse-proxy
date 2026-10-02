use my_http_server::{
    macros::{http_route, MyHttpInput},
    HttpContext, HttpFailResult, HttpOkResult, HttpOutput,
};

use super::InitClientCertificateCaResultHttpModel;

#[http_route(
    method: "POST",
    route: "/api/ClientCertificates/Init",
    summary: "Init (upload) a client certificate ca at runtime",
    description: "Initializes/replaces the client certificate CA (mTLS trust anchor) of a running endpoint. Send the CA - and optionally its revocation list - as PEM text in multipart/form-data fields (in Swagger just paste them; with curl use `-F 'ca=<ca.crt'`, which sends the file content as a form field). Validation before anything is stored: the PEM must contain exactly ONE certificate (only one is ever used as the trust anchor - upload the ca that directly issues the client certificates), at least one endpoint must require this ca id, and if a ca is already loaded under this id the uploaded one must be the same authority unless replace_different_ca is set. Revocation list, in order: the uploaded one, else the 'revocation_list' configured for this ca id (loaded here - the upload is REFUSED if it can not be read), else the list of the ca being replaced, else none. Used from the next TLS handshake - no reload required; connections already established keep the ca they handshook with. The same thing over a json body is /api/ClientCertificates/InitFromPem, which is what the admin ui uses.",
    controller: "ClientCertificates",
    input_data: InitClientCertificateCaHttpInput,
    result:[
        {status_code: 200, description: "CA validated and installed", model:"InitClientCertificateCaResultHttpModel"},
        {status_code: 400, description: "Validation error (bad PEM, bad CRL, or no endpoint requires this ca id)"},
    ]
)]
pub struct InitClientCertificateCaAction;

async fn handle_request(
    _action: &InitClientCertificateCaAction,
    input_data: InitClientCertificateCaHttpInput,
    _ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let crl = input_data
        .crl
        .as_deref()
        .map(|crl| crl.trim())
        .filter(|crl| !crl.is_empty())
        .map(|crl| crl.as_bytes().to_vec());

    let result = crate::scripts::init_client_ca_manually(
        &input_data.ca_id,
        input_data.ca.trim().as_bytes().to_vec(),
        crl,
        input_data.replace_different_ca.unwrap_or(false),
    )
    .await
    .map_err(HttpFailResult::as_validation_error)?;

    HttpOutput::as_json(InitClientCertificateCaResultHttpModel::new(result)).into_ok_result(true)
}

// PEM is text, so the parts are read as `String` - same as the ssl certificate upload: since
// my-http-server 0.9.0 the input derives come from my-http-utils, which implements neither
// `DataTypeProvider` nor the client writer for `FileContent`.
#[derive(MyHttpInput)]
pub struct InitClientCertificateCaHttpInput {
    #[http_form_data(
        name = "ca_id",
        description = "Id of the client certificate ca as referenced by the endpoint in configuration"
    )]
    pub ca_id: String,

    #[http_form_data(name = "ca", description = "The CA certificate in PEM format")]
    pub ca: String,

    #[http_form_data(
        name = "crl",
        description = "Optional certificate revocation list in PEM format. When omitted the configured 'revocation_list' is loaded, or the list of the CA being replaced is kept"
    )]
    pub crl: Option<String>,

    #[http_form_data(
        name = "replace_different_ca",
        description = "Allow replacing a loaded CA with a DIFFERENT authority (a deliberate rotation). Without it such an upload is refused, because it changes which clients the endpoint trusts"
    )]
    pub replace_different_ca: Option<bool>,
}

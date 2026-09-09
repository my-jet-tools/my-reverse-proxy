use crate::models::{InitClientCaRequestModel, InitClientCaResultModel};

const INIT_FROM_PEM_PATH: &str = "/api/ClientCertificates/InitFromPem";

/// Uploads the client-certificate CA (and optionally its revocation list) for `ca_id`. The
/// pasted PEM text is sent base64-encoded so its line breaks survive the json body untouched.
/// An empty `crl` means "keep whatever revocation list the CA being replaced had" — the proxy
/// never drops it silently.
pub async fn init_client_certificate_ca(
    ca_id: &str,
    ca: &str,
    crl: &str,
) -> Result<InitClientCaResultModel, String> {
    let request = InitClientCaRequestModel {
        ca_id: ca_id.to_string(),
        ca: super::to_base64(ca),
        crl: if crl.is_empty() {
            None
        } else {
            Some(super::to_base64(crl))
        },
    };

    super::post_json(INIT_FROM_PEM_PATH, &request).await
}

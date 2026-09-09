use crate::models::{InitSslCertificateRequestModel, InitSslCertificateResultModel};

const INIT_FROM_PEM_PATH: &str = "/api/SslCertificates/InitFromPem";

/// Uploads PEM material for `cert_id`. The pasted PEM text is sent base64-encoded so its line
/// breaks survive the json body untouched. The proxy validates the key/certificate pair and the
/// SNI before installing it, so a rejection here is a real validation failure and its text is
/// meant to be shown to the operator as-is.
pub async fn init_ssl_certificate(
    cert_id: &str,
    certificate: &str,
    private_key: &str,
) -> Result<InitSslCertificateResultModel, String> {
    let request = InitSslCertificateRequestModel {
        cert_id: cert_id.to_string(),
        cert: super::to_base64(certificate),
        private_key: super::to_base64(private_key),
    };

    super::post_json(INIT_FROM_PEM_PATH, &request).await
}

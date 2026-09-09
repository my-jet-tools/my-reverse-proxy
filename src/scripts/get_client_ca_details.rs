use rust_extensions::date_time::DateTimeAsMicroseconds;

use crate::configurations::SslCertificateIdRef;

pub struct ClientCaDetails {
    pub id: String,
    pub cn: String,
    pub expires: DateTimeAsMicroseconds,
    /// Whether the certificate declares BasicConstraints CA:TRUE.
    pub is_ca: bool,
    /// The ca is past its `not_after`.
    pub expired: bool,
    /// Where the CA came from: `local_source` or `manually_provided`.
    pub origin: String,
    /// Amount of revoked serials the CA is loaded with.
    pub crl_records: usize,
}

/// Returns metadata about the client-certificate CA currently loaded under the given id, or
/// `None` when nothing is loaded under it. The CA PEM material itself is never returned.
pub async fn get_client_ca_details(ca_id: &str) -> Option<ClientCaDetails> {
    let ca_id = ca_id.trim();

    let ca = crate::app::APP_CTX
        .ssl_certificates_cache
        .read(|c| c.client_ca.get(SslCertificateIdRef::new(ca_id)))
        .await?;

    let info = ca.get_ca_info();

    Some(ClientCaDetails {
        id: ca_id.to_string(),
        cn: info.cn,
        expires: info.expires,
        is_ca: info.is_ca,
        expired: info.expires.unix_microseconds <= DateTimeAsMicroseconds::now().unix_microseconds,
        origin: ca.origin_as_str().to_string(),
        crl_records: ca.crl_list.len(),
    })
}

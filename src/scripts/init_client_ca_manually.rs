use std::sync::Arc;

use my_ssh::ssh_settings::OverSshConnectionSettings;
use my_tls::crl::CrlRecord;
use rust_extensions::date_time::DateTimeAsMicroseconds;

use crate::{configurations::SslCertificateIdRef, tcp_listener::https::ClientCertificateCa};

/// Where the revocation list the CA ends up with came from.
pub mod crl_source {
    /// The operator uploaded a CRL together with the CA.
    pub const UPLOADED: &str = "uploaded";
    /// No CRL was uploaded, so the `revocation_list:` configured for this ca id was loaded from
    /// its source. The CA keeps that source, so the refresh timer keeps the list up to date.
    pub const CONFIGURED_SOURCE: &str = "configured_revocation_list";
    /// No CRL was uploaded and none is configured, so the revocation list of the CA being
    /// replaced was carried over.
    pub const KEPT_FROM_PREVIOUS: &str = "kept_from_previous";
    /// The CA has no revocation list at all — no client certificate can be revoked.
    pub const NONE: &str = "none";
}

pub struct InitClientCaResult {
    pub ca_id: String,
    pub cn: String,
    pub expires: DateTimeAsMicroseconds,
    /// The uploaded CA is already past its `not_after`. Reported, not refused — client
    /// certificate verification here never looks at validity dates.
    pub expired: bool,
    /// Whether the uploaded certificate declares BasicConstraints CA:TRUE. Reported, not
    /// enforced — a self-signed leaf used as the trust anchor is a working setup here.
    pub is_ca: bool,
    /// Endpoints that require this CA — verified to be non-empty before anything is stored.
    pub endpoints: Vec<String>,
    /// Revoked serials the CA is loaded with after the upload.
    pub crl_records: usize,
    /// One of [`crl_source`] — where those serials came from.
    pub crl_source: &'static str,
    /// The upload replaced a CA of a DIFFERENT authority (only possible with
    /// `replace_different_ca`), i.e. the set of clients this endpoint trusts has changed.
    pub replaced_different_authority: bool,
}

/// Uploads (or replaces) a client-certificate CA in the running cache by id.
///
/// Safety checks performed before anything is stored:
/// 1. The PEM must parse into EXACTLY ONE readable x509 certificate. Only one certificate is
///    ever used as the trust anchor (see [`ClientCertificateCa::verify_cert`]), so a bundle is
///    refused rather than silently reduced to its first block.
/// 2. At least one https/mcp endpoint must require `ca_id` — we refuse to store a CA that no
///    endpoint verifies against (guards against typos / orphan uploads).
/// 3. If a CA is already loaded under `ca_id`, the uploaded certificate must be the SAME
///    authority (same subject + public key), unless `replace_different_ca` is set. Replacing the
///    anchor with an unrelated CA changes which clients the endpoint trusts, so it has to be
///    asked for explicitly rather than being the default outcome of a typo — or of an agent
///    driving the MCP tool.
/// 4. The revocation list is resolved fail-closed, in this order: the uploaded CRL, else the
///    `revocation_list:` configured for this ca id (loaded here; if it can not be read the whole
///    upload is refused — installing a CA whose configured revocations are missing would serve
///    revoked clients), else the list of the CA being replaced, else none.
///
/// The stored CA has no `ca_file_source`, so it is never re-read from a file. It is used from the
/// next TLS handshake — connections already established keep the CA they handshook with. To hand
/// management back to a configured source, use RefreshCaCertificate.
pub async fn init_client_ca_manually(
    ca_id: &str,
    ca_pem: Vec<u8>,
    crl_pem: Option<Vec<u8>>,
    replace_different_ca: bool,
) -> Result<InitClientCaResult, String> {
    let ca_id = ca_id.trim();

    if ca_id.is_empty() {
        return Err("ca_id must not be empty".to_string());
    }

    let client_ca_id = SslCertificateIdRef::new(ca_id);

    // (1) Parse the PEM material. Rejects malformed / empty content instead of storing a CA that
    // would fail every handshake, and rejects a bundle whose extra certificates would be dropped.
    let certs = crate::ssl::certificates::load_certs(ca_pem)?;

    if certs.len() > 1 {
        return Err(format!(
            "The uploaded PEM contains {} certificates. Only one certificate is used as the trust anchor, so upload exactly the CA that DIRECTLY issues the client certificates (for a root -> issuing-ca -> client chain that is the issuing ca).",
            certs.len()
        ));
    }

    let uploaded_ca = ClientCertificateCa::new(certs, None, vec![], None)?;

    // (2) The CA must actually be required by an endpoint.
    let endpoints: Vec<String> = crate::scripts::get_client_ca_endpoints_status()
        .await
        .into_iter()
        .filter(|endpoint| endpoint.ca_id == ca_id)
        .map(|endpoint| endpoint.endpoint_host)
        .collect();

    if endpoints.is_empty() {
        return Err(format!(
            "No https endpoint requires client certificate ca '{}'. Refusing to upload a CA that verifies no endpoint.",
            ca_id
        ));
    }

    // (4) Everything that needs I/O is resolved before the cache is touched: the uploaded CRL, or
    // the one the configuration declares for this ca id.
    let explicit_crl: Option<(Vec<CrlRecord>, Option<OverSshConnectionSettings>, &'static str)> =
        match crl_pem {
            Some(crl_pem) => Some((
                crate::scripts::parse_crl_pem(crl_pem.as_slice())?,
                // The pasted list is the operator's explicit intent: it is not tied to a source,
                // so the refresh timer will not overwrite it.
                None,
                crl_source::UPLOADED,
            )),
            None => load_configured_revocation_list(ca_id).await?,
        };

    let info = uploaded_ca.get_ca_info();
    let now = DateTimeAsMicroseconds::now();

    // (3) + the store itself happen under ONE write lock: the authority check, the carry-over of
    // the previous revocation list and the insert must not interleave with another upload or with
    // the CRL refresh timer.
    let mut outcome: Result<(usize, &'static str, bool), String> = Ok((0, crl_source::NONE, false));

    crate::app::APP_CTX
        .ssl_certificates_cache
        .write(|config| {
            let existing = config.client_ca.get(client_ca_id);

            let mut replaced_different_authority = false;

            if let Some(existing) = existing.as_ref() {
                if !uploaded_ca.is_same_authority_as(existing) {
                    if !replace_different_ca {
                        outcome = Err(format!(
                            "Client certificate ca '{}' is currently loaded with a DIFFERENT authority (loaded: '{}', uploaded: '{}'). Installing it would change which clients the endpoint(s) [{}] trust. Repeat the upload with replace_different_ca=true if that is what you intend.",
                            ca_id,
                            existing.get_cn(),
                            info.cn,
                            endpoints.join(", ")
                        ));
                        return;
                    }

                    replaced_different_authority = true;
                }
            }

            let (crl_list, crl_file_source, source) = match explicit_crl.clone() {
                Some((crl_list, crl_file_source, source)) => (crl_list, crl_file_source, source),
                None => match existing.as_ref() {
                    // Carry the revocation list of the CA being replaced: dropping it would
                    // silently un-revoke every certificate it lists. Its source is NOT carried —
                    // it belongs to the replaced CA, and the timer would keep writing that file's
                    // content onto this one.
                    Some(existing) if !existing.crl_list.is_empty() => (
                        existing.crl_list.clone(),
                        None,
                        crl_source::KEPT_FROM_PREVIOUS,
                    ),
                    _ => (vec![], None, crl_source::NONE),
                },
            };

            let crl_records = crl_list.len();

            config.client_ca.insert(
                client_ca_id,
                Arc::new(uploaded_ca.with_crl(crl_list, crl_file_source)),
            );

            outcome = Ok((crl_records, source, replaced_different_authority));
        })
        .await;

    let (crl_records, crl_source, replaced_different_authority) = outcome?;

    println!(
        "Client certificate ca '{}' has been set manually (cn: {}, expires: {}, revoked serials: {} [{}]).",
        ca_id,
        info.cn,
        info.expires.to_rfc3339(),
        crl_records,
        crl_source
    );

    Ok(InitClientCaResult {
        ca_id: ca_id.to_string(),
        cn: info.cn,
        expires: info.expires,
        expired: info.expires.unix_microseconds <= now.unix_microseconds,
        is_ca: info.is_ca,
        endpoints,
        crl_records,
        crl_source,
        replaced_different_authority,
    })
}

/// The `revocation_list:` configured for this ca id, loaded from its source.
///
/// This is what keeps a manual upload from disabling revocation: the CA is typically uploaded
/// precisely because `refresh_ca_from_sources` could not complete — and it fails as a whole, so a
/// configured revocation list is not in the cache either. Returning `Err` here refuses the upload:
/// an endpoint that cuts every connection is a better outcome than one that serves clients whose
/// certificates the configuration says are revoked.
async fn load_configured_revocation_list(
    ca_id: &str,
) -> Result<Option<(Vec<CrlRecord>, Option<OverSshConnectionSettings>, &'static str)>, String> {
    let settings = crate::app::APP_CTX.applied_settings.load_full();

    let Some(settings) = settings else {
        return Ok(None);
    };

    let Some(configured) = settings
        .client_certificate_ca
        .iter()
        .find(|itm| itm.id == ca_id)
    else {
        return Ok(None);
    };

    let Some(revocation_list) = configured
        .revocation_list
        .as_deref()
        .map(|itm| itm.trim())
        .filter(|itm| !itm.is_empty())
    else {
        return Ok(None);
    };

    let crl_file_src = OverSshConnectionSettings::try_parse(revocation_list).ok_or(format!(
        "Client certificate ca '{}' declares an invalid revocation list source '{}'. Fix it in the configuration, or upload the revocation list together with the ca.",
        ca_id, revocation_list
    ))?;

    let crl = crate::scripts::load_file(&crl_file_src, crate::consts::DEFAULT_HTTP_CONNECT_TIMEOUT)
        .await
        .map_err(|err| {
            format!(
                "Client certificate ca '{}' declares 'revocation_list: {}' which can not be read: {}. Refusing to install a ca without the revocations it is configured to enforce - fix the source, or upload the revocation list together with the ca.",
                ca_id, revocation_list, err
            )
        })?;

    let crl = crate::scripts::parse_crl_pem(crl.as_slice()).map_err(|err| {
        format!(
            "Client certificate ca '{}' declares 'revocation_list: {}' which does not parse: {}. Fix the source, or upload the revocation list together with the ca.",
            ca_id, revocation_list, err
        )
    })?;

    Ok(Some((
        crl,
        // The source is kept, so the refresh timer keeps this list up to date even though the ca
        // itself was provided by hand.
        Some(crl_file_src),
        crl_source::CONFIGURED_SOURCE,
    )))
}

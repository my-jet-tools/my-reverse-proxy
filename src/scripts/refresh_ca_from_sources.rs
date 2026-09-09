use std::sync::Arc;

use my_ssh::ssh_settings::OverSshConnectionSettings;

use crate::{
    configurations::SslCertificateIdRef, settings::ClientCertificateCaSettings,
    settings_compiled::SettingsCompiled, tcp_listener::https::ClientCertificateCa,
};

pub async fn refresh_ca_from_sources<'s>(
    settings_model: &SettingsCompiled,
    ca_id: SslCertificateIdRef<'s>,
) -> Result<(), String> {
    let mut found_certificate = None;

    for client_certificate in settings_model.client_certificate_ca.iter() {
        if client_certificate.id == ca_id.as_str() {
            found_certificate = Some(client_certificate);
            break;
        }
    }

    if found_certificate.is_none() {
        return Err(format!(
            "Client certificate with id '{}' is not found",
            ca_id.as_str(),
        ));
    }

    let client_certificate: &ClientCertificateCaSettings = found_certificate.unwrap();

    // A "manual" ca has no source configured — it is uploaded at runtime from the admin ui or
    // POST /api/ClientCertificates/Init(FromPem). Nothing to resolve here, so the endpoint is
    // allowed to start with the ca absent from the cache (every TLS handshake to it is cut until
    // the ca is pushed).
    let ca_source = match client_certificate.get_source()? {
        Some(ca_source) => ca_source,
        None => return Ok(()),
    };

    let ca_file_src = OverSshConnectionSettings::try_parse(ca_source).ok_or(format!(
        "Invalid Client Certificate file source {}",
        ca_source
    ))?;

    let ca = super::load_file(&ca_file_src, crate::consts::DEFAULT_HTTP_CONNECT_TIMEOUT).await?;

    let crl = if let Some(crl_file_path) = client_certificate.revocation_list.as_ref() {
        let crl_file_src =
            OverSshConnectionSettings::try_parse(crl_file_path.as_str()).ok_or(format!(
                "Invalid Client Certificate CRL file source {}",
                crl_file_path.as_str()
            ))?;

        let crl =
            super::load_file(&crl_file_src, crate::consts::DEFAULT_HTTP_CONNECT_TIMEOUT).await?;

        let crl = super::parse_crl_pem(crl.as_slice())?;

        Some((crl, Some(crl_file_src)))
    } else {
        None
    };

    let client_cert = ClientCertificateCa::from_bytes(ca.as_slice(), Some(ca_file_src), crl)?;

    let client_cert = Arc::new(client_cert);

    crate::app::APP_CTX
        .ssl_certificates_cache
        .write(move |config| {
            config.client_ca.insert(ca_id, client_cert);
        })
        .await;

    Ok(())
}

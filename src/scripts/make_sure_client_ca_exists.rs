use crate::{
    configurations::{SslCertificateId, SslCertificateIdRef},
    settings::*,
    settings_compiled::SettingsCompiled,
};

pub async fn make_sure_client_ca_exists<'s>(
    settings_model: &'s SettingsCompiled,
    host_settings: &'s HostSettings,
) -> Result<Option<SslCertificateId>, String> {
    let client_ca_id = super::get_from_host_or_templates(
        settings_model,
        host_settings,
        |host_settings| host_settings.endpoint.client_certificate_ca.as_ref(),
        |templates| templates.client_certificate_ca.as_ref(),
    )?;

    if client_ca_id.is_none() {
        return Ok(None);
    }

    let client_ca_id = client_ca_id.unwrap();

    let client_ca_id = SslCertificateIdRef::new(client_ca_id);

    let client_ca_is_loaded = crate::app::APP_CTX
        .ssl_certificates_cache
        .read(|config| config.client_ca.has_certificate(client_ca_id))
        .await;

    if client_ca_is_loaded {
        return Ok(Some(client_ca_id.into()));
    }

    // The CA is not loaded yet. Try to resolve it from the configured source, but do NOT fail
    // the whole endpoint if that fails (no `client_certificate_ca` entry in settings, source
    // unreachable, broken PEM). The endpoint must stay usable so the CA can arrive in the
    // background — an upload from the admin ui or /api/ClientCertificates/Init(FromPem).
    // Until it does, `tls_acceptor::create_config` finds no CA for this endpoint and cuts every
    // connection (`CertificateUnavailable`), so nothing is served without client-certificate
    // verification — the endpoint just does not complete a handshake.
    if let Err(err) = super::refresh_ca_from_sources(settings_model, client_ca_id).await {
        println!(
            "Endpoint keeps listening without client certificate ca '{}' (connections are cut until it arrives): {}",
            client_ca_id.as_str(),
            err
        );
    }

    Ok(Some(client_ca_id.into()))
}

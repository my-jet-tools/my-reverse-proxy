use crate::{
    configurations::{SslCertificateId, SslCertificateIdRef},
    settings::*,
    settings_compiled::SettingsCompiled,
};

/// What an endpoint requires of its client certificate ca, resolved from the configuration.
pub struct ClientCaRequirement {
    pub id: SslCertificateId,
    /// From `unlimited_expiration:` on the ca entry - carried on the endpoint (not on the cached
    /// ca) so that changing it in the settings takes effect on the next reload, without having to
    /// re-resolve or re-upload the certificate.
    pub unlimited_expiration: bool,
}

pub async fn make_sure_client_ca_exists<'s>(
    settings_model: &'s SettingsCompiled,
    host_settings: &'s HostSettings,
) -> Result<Option<ClientCaRequirement>, String> {
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

    // The ca has to be DECLARED in the `client_certificate_ca` section: that entry is where its
    // revocation list, its `unlimited_expiration` and (optionally) its file source live. An
    // endpoint naming an id that exists nowhere is a typo, not a certificate waiting to be
    // uploaded - refusing it here puts the host in the errors map instead of leaving an endpoint
    // that can never be completed.
    let configured = settings_model
        .client_certificate_ca
        .iter()
        .find(|itm| itm.id.as_str() == client_ca_id.as_str());

    let Some(configured) = configured else {
        return Err(format!(
            "Endpoint requires client certificate ca '{}', which is not declared in the 'client_certificate_ca' section. Declare it there - with 'ca:' to load the certificate from a file source, or without it to upload the certificate from the admin ui.",
            client_ca_id
        ));
    };

    let requirement = ClientCaRequirement {
        id: SslCertificateIdRef::new(client_ca_id).into(),
        unlimited_expiration: configured.get_unlimited_expiration(),
    };

    let client_ca_id = SslCertificateIdRef::new(client_ca_id);

    let client_ca_is_loaded = crate::app::APP_CTX
        .ssl_certificates_cache
        .read(|config| config.client_ca.has_certificate(client_ca_id))
        .await;

    if client_ca_is_loaded {
        return Ok(Some(requirement));
    }

    // The ca is declared but its material is not here yet. Unlike the declaration itself, that is
    // NOT fatal: the endpoint keeps listening so the certificate can arrive in the background - an
    // upload from the admin ui or /api/ClientCertificates/Init(FromPem). Until it does,
    // `tls_acceptor::create_config` finds no ca for this endpoint and cuts every connection
    // (`CertificateUnavailable`), so nothing is served without client-certificate verification.
    if let Err(err) = super::refresh_ca_from_sources(settings_model, client_ca_id).await {
        println!(
            "Endpoint keeps listening without client certificate ca '{}' (connections are cut until it arrives): {}",
            client_ca_id.as_str(),
            err
        );
    }

    Ok(Some(requirement))
}

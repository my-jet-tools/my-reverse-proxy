use crate::{configurations::SslCertificateIdRef, settings_compiled::SettingsCompiled};

pub async fn refresh_ca_from_settings(cert_id: &str) -> Result<(), String> {
    let settings_model = SettingsCompiled::load_settings().await?;

    // `refresh_ca_from_sources` treats a source-less entry as "manual" and returns Ok without
    // touching the cache - which is right on the startup path but would answer this explicitly
    // requested refresh with a success that did nothing.
    if let Some(configured) = settings_model
        .client_certificate_ca
        .iter()
        .find(|itm| itm.id == cert_id)
    {
        if configured.get_source()?.is_none() {
            return Err(format!(
                "Client certificate ca '{}' has no 'ca' source configured - it is provided by hand (admin ui / POST /api/ClientCertificates/Init), so there is nothing to refresh from. Add a 'ca:' source to the configuration to hand it back to source management.",
                cert_id
            ));
        }
    }

    let client_ca_id = SslCertificateIdRef::new(cert_id);
    crate::scripts::refresh_ca_from_sources(&settings_model, client_ca_id).await?;

    Ok(())
}

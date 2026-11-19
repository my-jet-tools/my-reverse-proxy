use crate::{app::APP_CTX, configurations::SslCertificateIdRef};

/// Right after `POST /api/initialize`: the connections to gateways of the store are started, and
/// what could not be read without the network keys is read again now that they are here. The
/// urls of `real_time_configurations` are asked at once, and every certificate and CA of the
/// settings which has a source and is not loaded is loaded from it - a source which answers
/// encrypted opens now. The hourly timer of the certificates renews only what is loaded, so
/// nothing else would try them again.
pub async fn after_initialize() {
    crate::scripts::apply_gateway_connections_of_store();

    APP_CTX.real_time_configurations.request_refresh();

    let Some(settings) = APP_CTX.applied_settings.load_full() else {
        return;
    };

    for ssl_certificate in settings.ssl_certificates.iter() {
        if !matches!(ssl_certificate.get_sources(), Ok(Some(_))) {
            continue;
        }

        let id = SslCertificateIdRef::new(ssl_certificate.id.as_str());

        let is_loaded = APP_CTX
            .ssl_certificates_cache
            .read(|config| config.ssl_certs.has_certificate(id))
            .await;

        if is_loaded {
            continue;
        }

        match crate::scripts::refresh_ssl_certs_from_sources(&settings, id).await {
            Ok(()) => println!(
                "Initialized: TLS certificate '{}' is loaded from its source",
                id.as_str()
            ),
            Err(err) => println!(
                "Initialized: TLS certificate '{}' still can not be loaded: {err}",
                id.as_str()
            ),
        }
    }

    for client_ca in settings.client_certificate_ca.iter() {
        if !matches!(client_ca.get_source(), Ok(Some(_))) {
            continue;
        }

        let id = SslCertificateIdRef::new(client_ca.id.as_str());

        let is_loaded = APP_CTX
            .ssl_certificates_cache
            .read(|config| config.client_ca.has_certificate(id))
            .await;

        if is_loaded {
            continue;
        }

        match crate::scripts::refresh_ca_from_sources(&settings, id).await {
            Ok(()) => println!(
                "Initialized: client certificate ca '{}' is loaded from its source",
                id.as_str()
            ),
            Err(err) => println!(
                "Initialized: client certificate ca '{}' still can not be loaded: {err}",
                id.as_str()
            ),
        }
    }
}

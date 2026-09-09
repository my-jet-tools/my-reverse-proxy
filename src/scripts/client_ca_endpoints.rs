use rust_extensions::date_time::DateTimeAsMicroseconds;

use crate::configurations::{ListenConfiguration, SslCertificateIdRef};

pub struct ClientCaEndpointStatus {
    /// Full endpoint host as configured, e.g. `example.com:443` or a unix socket path.
    pub endpoint_host: String,
    /// `client_certificate_ca` id the endpoint requires client certificates to be signed by.
    pub ca_id: String,
    /// `false` when the CA is declared by the endpoint but is not in the running cache — every
    /// TLS handshake to this endpoint is cut until it arrives.
    pub loaded: bool,
    pub cn: Option<String>,
    pub expires: Option<DateTimeAsMicroseconds>,
    /// The loaded ca is past its `not_after`. Client certificate verification here does not look
    /// at validity dates, so such a ca keeps working - it is reported so the operator can see it.
    pub expired: bool,
    /// How many revoked serials the loaded CA carries (from its CRL).
    pub crl_records: Option<usize>,
    /// `unlimited_expiration:` on the ca entry - client certificates verified against it are
    /// accepted regardless of their validity dates.
    pub unlimited_expiration: bool,
}

/// Enumerates every https/mcp endpoint that requires a client certificate and reports whether
/// the CA it verifies against is currently loaded.
pub async fn get_client_ca_endpoints_status() -> Vec<ClientCaEndpointStatus> {
    // (endpoint_host, ca_id, unlimited_expiration). The flag is read from the compiled endpoint,
    // not from `applied_settings`: that snapshot is only refreshed by a FULL reload, so after a
    // ReloadEndpoint it would report something the handshake no longer does.
    let endpoints: Vec<(String, String, bool)> = crate::app::APP_CTX
        .current_configuration
        .get(|cfg| {
            let mut out = Vec::new();
            for listen in cfg.listen_tcp_endpoints.values() {
                collect_endpoints(listen, &mut out);
            }
            for listen in cfg.listen_unix_socket_endpoints.values() {
                collect_endpoints(listen, &mut out);
            }
            out
        })
        .await;

    let now = DateTimeAsMicroseconds::now();

    let mut result = Vec::with_capacity(endpoints.len());

    for (endpoint_host, ca_id, unlimited_expiration) in endpoints {
        let ca = crate::app::APP_CTX
            .ssl_certificates_cache
            .read(|c| c.client_ca.get(SslCertificateIdRef::new(ca_id.as_str())))
            .await;

        let (loaded, cn, expires, expired, crl_records) = match ca {
            None => (false, None, None, false, None),
            Some(ca) => {
                let info = ca.get_ca_info();
                (
                    true,
                    Some(info.cn),
                    Some(info.expires),
                    info.expires.unix_microseconds <= now.unix_microseconds,
                    Some(ca.crl_list.len()),
                )
            }
        };

        result.push(ClientCaEndpointStatus {
            endpoint_host,
            ca_id,
            loaded,
            cn,
            expires,
            expired,
            crl_records,
            unlimited_expiration,
        });
    }

    result
}

fn collect_endpoints(listen: &ListenConfiguration, out: &mut Vec<(String, String, bool)>) {
    let http = match listen {
        ListenConfiguration::Http(http) | ListenConfiguration::Mcp(http) => http,
        ListenConfiguration::Tcp(_) => return,
    };

    for endpoint in http.endpoints.iter() {
        let Some(ca_id) = endpoint.client_certificate_id.as_ref() else {
            continue;
        };

        out.push((
            endpoint.as_str().to_string(),
            ca_id.as_str().to_string(),
            endpoint.client_certificate_unlimited_expiration,
        ));
    }
}

use std::sync::Arc;

use crate::{http_proxy_pass::HttpProxyPassIdentity, settings::HttpEndpointModifyHeadersSettings};

use super::*;

pub enum AuthorizationRequired<'s> {
    GoogleAuth(&'s str),
    ClientCertificate,
}

pub struct HttpEndpointInfo {
    pub host_endpoint: EndpointHttpHostString,
    pub debug: bool,
    pub inject_country: bool,
    pub listen_endpoint_type: ListenHttpEndpointType,
    pub g_auth: Option<String>,
    /// Name of the `oauth:` block gating this endpoint, when it has one. The
    /// endpoint then also answers the OAuth server's own paths itself.
    pub oauth: Option<String>,
    pub ssl_certificate_id: Option<SslCertificateId>,
    pub client_certificate_id: Option<SslCertificateId>,
    /// `unlimited_expiration:` of the client certificate ca this endpoint requires. Kept on the
    /// endpoint rather than on the cached ca, so a change in the settings applies on the next
    /// reload without re-resolving or re-uploading the certificate.
    pub client_certificate_unlimited_expiration: bool,
    pub locations: Vec<Arc<ProxyPassLocationConfig>>,
    pub allowed_user_list_id: Option<String>,
    pub modify_request_headers: ModifyHeadersConfig,
    pub modify_response_headers: ModifyHeadersConfig,
    pub whitelisted_ip_list_id: Option<String>,
    pub keep_alive: bool,
    pub track_metrics_by_all_domains: bool,
    pub hsts: bool,
    pub mcp_settings: McpEndpointSettings,
    /// Endpoint-scoped transport read/write idle timeouts (resolved cascade,
    /// global → endpoint). Used by every byte pump of this endpoint.
    pub timeouts: crate::types::HttpTimeouts,
    /// `Some`: the endpoint was given an access setting it can not apply, and serves nobody.
    pub not_served_reason: Option<NotServedReason>,
}

/// Everything an endpoint is compiled from.
///
/// A struct rather than a positional argument list: seven of these are
/// `Option<String>` and two more are `Option<SslCertificateId>`, so transposing
/// a pair — `g_auth` for `oauth`, the server certificate for the client CA —
/// compiles cleanly and quietly mis-secures the endpoint.
pub struct HttpEndpointInfoParams {
    pub host_endpoint: EndpointHttpHostString,
    pub listen_endpoint_type: ListenHttpEndpointType,
    pub debug: bool,
    pub inject_country: bool,
    pub g_auth: Option<String>,
    pub oauth: Option<String>,
    pub ssl_certificate_id: Option<SslCertificateId>,
    pub client_certificate_id: Option<SslCertificateId>,
    pub client_certificate_unlimited_expiration: bool,
    pub whitelisted_ip_list_id: Option<String>,
    pub locations: Vec<Arc<ProxyPassLocationConfig>>,
    pub allowed_user_list_id: Option<String>,
    pub modify_headers_settings: HttpEndpointModifyHeadersSettings,
    pub keep_alive: bool,
    pub track_metrics_by_all_domains: bool,
    pub hsts: bool,
    pub mcp_settings: McpEndpointSettings,
    pub timeouts: crate::types::HttpTimeouts,
    pub not_served_reason: Option<NotServedReason>,
}

impl HttpEndpointInfo {
    pub fn new(params: HttpEndpointInfoParams) -> Self {
        let HttpEndpointInfoParams {
            host_endpoint,
            listen_endpoint_type,
            debug,
            inject_country,
            g_auth,
            oauth,
            ssl_certificate_id,
            client_certificate_id,
            client_certificate_unlimited_expiration,
            whitelisted_ip_list_id,
            locations,
            allowed_user_list_id,
            mut modify_headers_settings,
            keep_alive,
            track_metrics_by_all_domains,
            hsts,
            mcp_settings,
            timeouts,
            not_served_reason,
        } = params;

        if debug {
            println!("Endpoint {} is in debug mode", host_endpoint.as_str());
        }

        let mut modify_request_headers =
            ModifyHeadersConfig::new_request(&mut modify_headers_settings);

        // The access token on an oauth-gated endpoint is one this proxy minted
        // for itself. Stripping it here — at the endpoint level, so it holds for
        // every location of the endpoint — keeps it out of the upstream, which
        // the MCP authorization spec requires.
        if oauth.is_some() {
            modify_request_headers.add_to_remove("authorization");
        }

        Self {
            host_endpoint,
            debug,
            inject_country,
            listen_endpoint_type,
            g_auth,
            oauth,
            client_certificate_id,
            client_certificate_unlimited_expiration,
            locations,
            allowed_user_list_id,
            modify_request_headers,
            modify_response_headers: ModifyHeadersConfig::new_response(
                &mut modify_headers_settings,
            ),
            ssl_certificate_id,
            whitelisted_ip_list_id,
            keep_alive,
            track_metrics_by_all_domains,
            hsts,
            mcp_settings,
            timeouts,
            not_served_reason,
        }
    }

    /// Returns `Some(domain)` if this request should emit per-domain metrics,
    /// `None` otherwise. `request_host` is the value parsed from the inbound
    /// `Host:` header (or h2 `:authority`), already stripped of port.
    pub fn tracked_domain<'a>(&'a self, request_host: Option<&'a str>) -> Option<&'a str> {
        if self.track_metrics_by_all_domains {
            request_host
        } else {
            self.host_endpoint.get_server_name()
        }
    }

    pub fn is_my_endpoint(&self, server_name: &str) -> bool {
        self.host_endpoint.is_my_server_name(server_name)
    }

    pub fn as_str(&self) -> &str {
        self.host_endpoint.as_str()
    }

    /// `path`: the request target as received - with its query string, if it has one.
    pub fn find_location(&self, path: &str) -> Option<&Arc<ProxyPassLocationConfig>> {
        self.locations
            .iter()
            .find(|location| crate::types::is_path_of_location(path, &location.path))
    }

    /// Guards against HTTP/2 connection coalescing (and any cross-SNI
    /// `Host`/`:authority` reuse): mTLS is enforced only during the TLS
    /// handshake, which is bound to the SNI that opened the connection.
    /// `connection_cert_ca` is the `client_certificate_id` that verified the
    /// connection's client certificate (None — no certificate presented).
    /// Returns `false` when this endpoint requires a client certificate but the
    /// connection has none, OR has one verified by a DIFFERENT CA — presence
    /// alone is not enough: a certificate trusted by another vhost's CA says
    /// nothing about this endpoint's mTLS requirement. The caller answers 421
    /// so the client re-opens a dedicated connection and performs mTLS here.
    pub fn connection_satisfies_client_cert(
        &self,
        connection_cert: Option<&crate::tcp_listener::https::ClientCertificateData>,
    ) -> bool {
        client_cert_satisfies(
            self.client_certificate_id.as_ref().map(|itm| itm.as_str()),
            self.client_certificate_unlimited_expiration,
            connection_cert,
        )
    }

    /// Whether the connection's client-certificate identity (CN) is meaningful
    /// for THIS endpoint: only when the endpoint itself requires a client
    /// certificate from the same CA that verified it. A certificate presented
    /// for another vhost's handshake must not become an identity here — it
    /// would leak into `allowed_users` checks and `${CLIENT_CERT_CN}` headers
    /// for a vhost whose CA never saw that certificate. This also keeps a
    /// coalesced request's outcome identical to a dedicated-connection one
    /// (where a no-mTLS endpoint never asks for a certificate at all).
    pub fn client_cert_identity_applies(
        &self,
        connection_cert: &crate::tcp_listener::https::ClientCertificateData,
    ) -> bool {
        self.connection_satisfies_client_cert(Some(connection_cert))
            && self.client_certificate_id.is_some()
    }

    pub fn must_be_authorized<'s>(&'s self) -> Option<AuthorizationRequired<'s>> {
        if let Some(g_auth) = self.g_auth.as_deref() {
            return Some(AuthorizationRequired::GoogleAuth(g_auth));
        }

        if self.ssl_certificate_id.is_some() {
            return Some(AuthorizationRequired::ClientCertificate);
        }

        None
    }

    pub async fn user_is_allowed(&self, identity: &Option<HttpProxyPassIdentity>) -> bool {
        let Some(allowed_user_list_id) = self.allowed_user_list_id.as_ref() else {
            return true;
        };

        let Some(identity) = identity else {
            return false;
        };

        crate::app::APP_CTX
            .allowed_users_list
            .is_allowed(allowed_user_list_id, identity.as_str())
            .await
    }
}

/// Whether a connection's client certificate satisfies an endpoint's mTLS requirement.
///
/// `required_ca` is the endpoint's `client_certificate_ca` (None - the endpoint requires none),
/// `endpoint_unlimited_expiration` its `unlimited_expiration` flag, and `connection_cert` what the
/// TLS handshake of the connection actually verified.
fn client_cert_satisfies(
    required_ca: Option<&str>,
    endpoint_unlimited_expiration: bool,
    connection_cert: Option<&crate::tcp_listener::https::ClientCertificateData>,
) -> bool {
    let Some(required_ca) = required_ca else {
        return true;
    };

    let Some(connection_cert) = connection_cert else {
        return false;
    };

    if connection_cert.ca_id != required_ca {
        return false;
    }

    // The certificate may have been accepted past its expiry because the endpoint that opened the
    // connection declares `unlimited_expiration`. That exception belongs to the endpoint that opted
    // into it: one that enforces expiry must not inherit it over a coalesced or reused connection -
    // and the two can differ while a targeted reload has applied a settings change to only one.
    if connection_cert.accepted_outside_validity && !endpoint_unlimited_expiration {
        return false;
    }

    true
}

#[cfg(test)]
mod client_cert_guard_tests {
    use super::client_cert_satisfies;
    use crate::tcp_listener::https::ClientCertificateData;

    fn cert(ca_id: &str, accepted_outside_validity: bool) -> ClientCertificateData {
        ClientCertificateData {
            cn: "client".to_string(),
            ca_id: ca_id.to_string(),
            accepted_outside_validity,
        }
    }

    #[test]
    fn endpoint_without_mtls_accepts_anything() {
        assert!(client_cert_satisfies(None, false, None));
        assert!(client_cert_satisfies(
            None,
            false,
            Some(&cert("other", true))
        ));
    }

    #[test]
    fn a_certificate_is_required_and_must_come_from_this_ca() {
        assert!(client_cert_satisfies(
            Some("partner"),
            false,
            Some(&cert("partner", false))
        ));
        assert!(!client_cert_satisfies(Some("partner"), false, None));
        assert!(!client_cert_satisfies(
            Some("partner"),
            false,
            Some(&cert("other", false))
        ));
    }

    #[test]
    fn an_expired_certificate_does_not_travel_to_an_endpoint_that_enforces_expiry() {
        // Accepted at an endpoint declaring unlimited_expiration, then reused (h2 coalescing or a
        // keep-alive request for another Host) for an endpoint that does not declare it.
        assert!(client_cert_satisfies(
            Some("partner"),
            true,
            Some(&cert("partner", true))
        ));
        assert!(!client_cert_satisfies(
            Some("partner"),
            false,
            Some(&cert("partner", true))
        ));
    }
}

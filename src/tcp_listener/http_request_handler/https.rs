use std::sync::Arc;

use bytes::Bytes;
use http::StatusCode;
use http_body_util::combinators::BoxBody;

use crate::{
    configurations::HttpListenPortConfiguration,
    http_proxy_pass::{HttpListenPortInfo, HttpProxyPass},
    tcp_listener::{https::ClientCertificateData, ConnectionCut},
    types::ConnectionIp,
};

use super::{
    utils::{create_bad_request_response, create_err_response, BadRequestReason, RejectedRequest},
    LiveEndpointCache,
};

pub struct HttpsRequestsHandler {
    endpoints: LiveEndpointCache,
    /// The peer of the connection.
    connection_ip: ConnectionIp,
    client_certificate: Option<Arc<ClientCertificateData>>,
    /// What a request cuts the connection with: see [`ConnectionCut`].
    pub cut: Arc<ConnectionCut>,
}

impl HttpsRequestsHandler {
    pub fn new(
        connection_ip: ConnectionIp,
        listen_port_config: Arc<HttpListenPortConfiguration>,
        client_certificate: Option<Arc<ClientCertificateData>>,
    ) -> Self {
        Self {
            endpoints: LiveEndpointCache::new(listen_port_config),
            connection_ip,
            client_certificate,
            cut: ConnectionCut::new(),
        }
    }

    async fn get_http_proxy_pass(
        &self,
        req: &hyper::Request<hyper::body::Incoming>,
    ) -> Result<Arc<HttpProxyPass>, RejectedRequest> {
        // Picks up a `reload_settings` that happened while this connection was
        // open, and drops the cached per-Host proxy passes if it replaced this
        // port's configuration. Every mTLS / IP / auth check below therefore
        // runs against the configuration that is live NOW, not the one this
        // connection was accepted with.
        let listen_port_config = self.endpoints.load_current().await;

        let host: String = if let Some(host) = req.uri().host() {
            host.to_string()
        } else if let Some(host) = req
            .headers()
            .get(hyper::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(':').next().unwrap_or(v).trim())
            .filter(|v| !v.is_empty())
        {
            // Origin-form HTTP/1.1 request (e.g. an http/1.1 client reaching this
            // h2-typed endpoint via ALPN fallback): the authority is only in the
            // `Host` header, not the request URI.
            host.to_string()
        } else {
            crate::app::APP_CTX.proxy_logs.write_port(
                listen_port_config.listen_host.get_log_key().as_str(),
                self.connection_ip.get_ip_log(),
                format!(
                    "Rejected request: can not detect host. Uri:{}. Headers: {:?}",
                    req.uri(),
                    crate::types::HeaderList::new(
                        req.headers(),
                        &listen_port_config.required_headers()
                    )
                ),
            );
            return Err(create_bad_request_response(
                &self.connection_ip,
                req,
                &listen_port_config,
                BadRequestReason::HostNotDetected,
            ));
        };

        let host_key = host.to_ascii_lowercase();

        // A request of a `drop` location: as if nothing were here - before every check below,
        // and before `cloudflare` and `request_with_header_only` of `handle_request`.
        if let Some(existing) = self.endpoints.get(&host_key) {
            if let Some(dropped) =
                super::utils::drop_if_a_drop_location(&existing.endpoint_info, req, &self.cut).await
            {
                return Err(dropped);
            }

            return Ok(existing);
        }

        let http_endpoint_info = listen_port_config.get_http_endpoint_info(Some(host.as_str()));
        let Some(http_endpoint_info) = http_endpoint_info else {
            crate::app::APP_CTX.proxy_logs.write_port(
                listen_port_config.listen_host.get_log_key().as_str(),
                self.connection_ip.get_ip_log(),
                format!(
                    "Rejected request: no endpoint configured for host [{}]",
                    host
                ),
            );
            return Err(create_bad_request_response(
                &self.connection_ip,
                req,
                &listen_port_config,
                BadRequestReason::NoConfigurationForHost(host.as_str()),
            ));
        };

        if let Some(dropped) =
            super::utils::drop_if_a_drop_location(&http_endpoint_info, req, &self.cut).await
        {
            return Err(dropped);
        }

        // mTLS is enforced only during the TLS handshake, which is bound to the
        // SNI used to open this connection. A browser may coalesce HTTP/2
        // requests for several hosts onto one connection (RFC 7540 §9.1.1), and a
        // hostile client can simply send a different `:authority`. If the
        // resolved endpoint requires a client certificate but this connection
        // presented none — or one verified by a different CA — refuse with 421
        // Misdirected Request so the client re-opens a dedicated connection
        // (with the right SNI) and performs mTLS against this endpoint's CA.
        if !http_endpoint_info.connection_satisfies_client_cert(self.client_certificate.as_deref())
        {
            crate::app::APP_CTX.proxy_logs.write_port(
                listen_port_config.listen_host.get_log_key().as_str(),
                self.connection_ip.get_ip_log(),
                format!(
                    "Rejected request for host [{}]: endpoint requires a client certificate but the TLS connection presented none or one from a different CA (HTTP/2 coalescing or SNI mismatch)",
                    host
                ),
            );
            let content = crate::error_templates::generate_layout_body(
                421,
                "Misdirected Request",
                Some("A client certificate is required for this host".into()),
            );
            return Err(create_err_response(
                StatusCode::MISDIRECTED_REQUEST,
                content,
            ));
        }

        // Enforce the *request-host* endpoint's IP and country allow-lists per
        // request. The connection-level check in handle_connection only sees the
        // SNI endpoint; a coalesced / cross-`Host` request (RFC 7540 §9.1.1) must
        // still satisfy the allow-lists of the vhost it actually targets. Skipped
        // when the client IP is unknown (unix socket), matching the
        // location-level check in HttpProxyPass::send_payload. The client of a
        // `cloudflare: true` endpoint is not the peer: its requests are checked
        // one by one, by `send_payload`.
        let refusal = if http_endpoint_info.cloudflare {
            None
        } else {
            http_endpoint_info
                .address_refusal(&self.connection_ip)
                .await
        };
        if let Some(refusal) = refusal {
            crate::app::APP_CTX.proxy_logs.write_port(
                listen_port_config.listen_host.get_log_key().as_str(),
                self.connection_ip.get_ip_log(),
                format!("Rejected request for host [{host}]: {refusal}"),
            );
            let content =
                crate::error_templates::generate_layout_body(401, "Restricted by IP", None);
            return Err(create_err_response(StatusCode::UNAUTHORIZED, content));
        }

        if crate::app::APP_CTX
            .debug_flags
            .is_endpoint_debug(http_endpoint_info.host_endpoint.as_str())
        {
            crate::app::APP_CTX.proxy_logs.write(
                http_endpoint_info.host_endpoint.as_str(),
                None,
                self.connection_ip.get_ip_log(),
                format!("Detected. [{}]{:?}", req.method(), req.uri()),
            );
        }

        let listening_port_info = HttpListenPortInfo {
            endpoint_type: http_endpoint_info.listen_endpoint_type,
            listen_host: listen_port_config.listen_host.clone(),
        };

        // The connection's client-cert identity is scoped to endpoints that
        // require the same CA that verified it. On a coalesced / cross-`Host`
        // request to an endpoint with no (or another) mTLS requirement the
        // identity must stay empty — same as on a dedicated connection, where
        // such an endpoint would never have asked for a certificate.
        let client_certificate = self
            .client_certificate
            .as_ref()
            .filter(|cert| http_endpoint_info.client_cert_identity_applies(cert))
            .cloned();

        let http_proxy_pass =
            HttpProxyPass::new(http_endpoint_info, listening_port_info, client_certificate).await;

        Ok(self
            .endpoints
            .insert_or_get_existing(host_key, Arc::new(http_proxy_pass)))
    }

    pub async fn handle_request(
        &self,
        req: hyper::Request<hyper::body::Incoming>,
    ) -> hyper::Result<hyper::Response<BoxBody<Bytes, String>>> {
        let proxy_pass = match self.get_http_proxy_pass(&req).await {
            Ok(proxy_pass) => proxy_pass,
            Err(rejected) => return Ok(*rejected),
        };

        // Who the request is of. A `cloudflare: true` endpoint reached otherwise than through
        // Cloudflare, or a request without the headers of `request_with_header_only`, cuts the
        // connection without a word - every request of it with it.
        let Some(client) =
            super::utils::client_of_request(&proxy_pass.endpoint_info, self.connection_ip, &req)
        else {
            self.cut.cut_now().await;
            return Ok(super::utils::answer_of_a_cut_connection());
        };

        super::handle_requests::handle_requests(req, &proxy_pass, client, &self.cut).await
    }

    pub async fn dispose(&self) {
        self.endpoints.dispose().await;
    }
}

pub async fn handle_request(
    request_handler: Arc<HttpsRequestsHandler>,
    req: hyper::Request<hyper::body::Incoming>,
) -> hyper::Result<hyper::Response<BoxBody<Bytes, String>>> {
    request_handler.handle_request(req).await
}

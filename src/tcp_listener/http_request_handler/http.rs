use std::sync::Arc;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;

use crate::{
    configurations::HttpListenPortConfiguration,
    http_proxy_pass::*,
    tcp_listener::{ConnectionCut, ConnectionLifetime, SendTimeout, WatchedResponseBody},
    types::ConnectionIp,
};

use super::{
    utils::{create_bad_request_response, BadRequestReason, RejectedRequest},
    LiveEndpointCache,
};

pub struct HttpRequestHandler {
    endpoints: LiveEndpointCache,
    /// The peer of the connection.
    connection_ip: ConnectionIp,
    /// What a request cuts the connection with: see [`ConnectionCut`].
    pub cut: Arc<ConnectionCut>,
    /// The requests of the connection, and when it is closed for them: see
    /// [`ConnectionLifetime`].
    pub lifetime: Arc<ConnectionLifetime>,
}

impl HttpRequestHandler {
    pub fn new(
        connection_ip: ConnectionIp,
        listen_port_config: Arc<HttpListenPortConfiguration>,
    ) -> Self {
        Self {
            endpoints: LiveEndpointCache::new(listen_port_config),
            connection_ip,
            cut: ConnectionCut::new(),
            lifetime: ConnectionLifetime::new(),
        }
    }

    async fn get_http_proxy_pass(
        &self,
        req: &hyper::Request<hyper::body::Incoming>,
    ) -> Result<Arc<HttpProxyPass>, RejectedRequest> {
        // Picks up a `reload_settings` that happened while this connection was
        // open, and drops the cached per-Host proxy passes if it replaced this
        // port's configuration.
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
            // Origin-form HTTP/1.1 request: the authority is only in the `Host`
            // header, not the request URI.
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
        if http_endpoint_info.is_none() {
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
        }

        let http_endpoint_info = http_endpoint_info.unwrap();

        if let Some(dropped) =
            super::utils::drop_if_a_drop_location(&http_endpoint_info, req, &self.cut).await
        {
            return Err(dropped);
        }

        // A Cloudflare server reaching an endpoint without `cloudflare: true` is noted - once for
        // the host of the connection: there was no TLS handshake to note it at.
        if !http_endpoint_info.cloudflare {
            crate::cloudflare::connection_may_go_on(
                http_endpoint_info.as_str(),
                false,
                &self.connection_ip,
                Some(host.as_bytes()),
            );
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

        let http_proxy_pass =
            HttpProxyPass::new(http_endpoint_info, listening_port_info, None).await;

        Ok(self
            .endpoints
            .insert_or_get_existing(host_key, Arc::new(http_proxy_pass)))
    }

    pub async fn handle_request(
        &self,
        req: hyper::Request<hyper::body::Incoming>,
    ) -> hyper::Result<hyper::Response<BoxBody<Bytes, String>>> {
        let request = self.lifetime.request_started();
        let mut access =
            crate::access_log::record_of_hyper_request(&req, self.connection_ip.get_ip_log());

        let proxy_pass = match self.get_http_proxy_pass(&req).await {
            Ok(proxy_pass) => proxy_pass,
            Err(rejected) => return Ok(self.watched(*rejected, request, None, access)),
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

        // Behind Cloudflare the client is the one of `CF-Connecting-IP`.
        if let Some(access) = access.as_mut() {
            access.set_client(client.ip.get_ip_log());
        }

        let response =
            super::handle_requests::handle_requests(req, &proxy_pass, client, &self.cut).await?;

        Ok(self.watched(response, request, Some(&proxy_pass), access))
    }

    /// `response` as it goes out: on the connection until it is out, and not held longer than
    /// the endpoint's `write_timeout` by a client which takes nothing of it. See
    /// [`WatchedResponseBody`].
    fn watched(
        &self,
        response: hyper::Response<BoxBody<Bytes, String>>,
        request: crate::tcp_listener::ActiveRequest,
        proxy_pass: Option<&HttpProxyPass>,
        access: Option<crate::access_log::AccessRecord>,
    ) -> hyper::Response<BoxBody<Bytes, String>> {
        use http_body_util::BodyExt;

        let send_timeout = SendTimeout {
            cut: self.cut.clone(),
            timeout: proxy_pass
                .map(|proxy_pass| proxy_pass.endpoint_info.timeouts.write_timeout)
                .unwrap_or(crate::consts::DEFAULT_WRITE_TIMEOUT),
            endpoint: proxy_pass.map(|proxy_pass| proxy_pass.endpoint_info.clone()),
            ip: self.connection_ip.get_ip_log(),
        };

        let status = response.status().as_u16();

        response.map(|body| {
            WatchedResponseBody::new(body, request, send_timeout, access, status).boxed()
        })
    }

    pub async fn dispose(&self) {
        self.endpoints.dispose().await;
    }
}

pub async fn handle_request(
    request_handler: Arc<HttpRequestHandler>,
    req: hyper::Request<hyper::body::Incoming>,
) -> hyper::Result<hyper::Response<BoxBody<Bytes, String>>> {
    request_handler.handle_request(req).await
}

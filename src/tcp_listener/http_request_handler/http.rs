use std::sync::Arc;

use bytes::Bytes;
use http::StatusCode;
use http_body_util::{combinators::BoxBody, BodyExt, Full};

use crate::{configurations::HttpListenPortConfiguration, http_proxy_pass::*, types::ConnectionIp};

use super::LiveEndpointCache;

pub struct HttpRequestHandler {
    endpoints: LiveEndpointCache,
    connection_ip: ConnectionIp,
}

impl HttpRequestHandler {
    pub fn new(
        connection_ip: ConnectionIp,
        listen_port_config: Arc<HttpListenPortConfiguration>,
    ) -> Self {
        Self {
            endpoints: LiveEndpointCache::new(listen_port_config),
            connection_ip,
        }
    }

    async fn get_http_proxy_pass(
        &self,
        req: &hyper::Request<hyper::body::Incoming>,
    ) -> Result<Arc<HttpProxyPass>, hyper::Result<hyper::Response<BoxBody<Bytes, String>>>> {
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
                    req.headers()
                ),
            );
            return Err(create_err_response(
                StatusCode::BAD_REQUEST,
                "Unknown host".to_string().into_bytes(),
            ));
        };

        let host_key = host.to_ascii_lowercase();

        if let Some(existing) = self.endpoints.get(&host_key) {
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
            let content =
                crate::error_templates::generate_layout(400, "No configuration found", None);
            return Err(create_err_response(StatusCode::BAD_REQUEST, content));
        }

        let http_endpoint_info = http_endpoint_info.unwrap();

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

        let http_proxy_pass = HttpProxyPass::new(
            self.connection_ip,
            http_endpoint_info,
            listening_port_info,
            None,
        )
        .await;

        Ok(self
            .endpoints
            .insert_or_get_existing(host_key, Arc::new(http_proxy_pass)))
    }

    pub async fn handle_request(
        &self,
        req: hyper::Request<hyper::body::Incoming>,
    ) -> hyper::Result<hyper::Response<BoxBody<Bytes, String>>> {
        match self.get_http_proxy_pass(&req).await {
            Ok(proxy_pass) => {
                super::handle_requests::handle_requests(req, &proxy_pass, self.connection_ip).await
            }
            Err(err) => err,
        }
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

fn create_err_response(
    status_code: StatusCode,
    content: impl Into<Bytes>,
) -> hyper::Result<hyper::Response<BoxBody<Bytes, String>>> {
    let result = hyper::Response::builder()
        .status(status_code)
        .body(
            Full::new(content.into())
                .map_err(|e| crate::to_hyper_error(e))
                .boxed(),
        )
        .unwrap();

    Ok(result)
}

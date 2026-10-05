use std::sync::Arc;

use my_ssh::{ssh_settings::OverSshConnectionSettings, SshSession};

use crate::{http_client_connectors::HttpOverSshConnector, http_proxy_pass::ProxyPassError};

use super::*;

pub struct Http2OverSshContentSource {
    pub over_ssh: OverSshConnectionSettings,
    pub ssh_session: Arc<SshSession>,
    pub debug: bool,
    pub request_timeout: std::time::Duration,
    pub connect_timeout: std::time::Duration,
}

impl Http2OverSshContentSource {
    pub async fn execute(
        &self,
        req: http::Request<http_body_util::Full<bytes::Bytes>>,
    ) -> Result<HttpResponse, ProxyPassError> {
        let http_client = crate::app::APP_CTX.http2_over_ssh_clients_pool.get(
            self.over_ssh.to_string().into(),
            self.connect_timeout,
            || {
                (
                    HttpOverSshConnector {
                        remote_endpoint: self.over_ssh.get_remote_endpoint().to_owned(),
                        debug: self.debug,
                        ssh_session: self.ssh_session.clone(),
                        connect_timeout: self.connect_timeout,
                    },
                    crate::app::APP_CTX.prometheus.clone(),
                )
            },
        );

        // The shared h2 dispatcher also carries a WebSocket opened with an RFC 8441 extended
        // CONNECT.
        execute_h2(&http_client, &req, self.request_timeout).await
    }

    /// Same upstream, with the client's request body forwarded as a stream of
    /// frames instead of being collected first.
    pub async fn execute_streamed(
        &self,
        req: hyper::Request<crate::my_http2_client::HyperRequestBody>,
        content_size: Option<usize>,
    ) -> Result<HttpResponse, ProxyPassError> {
        let http_client = crate::app::APP_CTX.http2_over_ssh_clients_pool.get(
            self.over_ssh.to_string().into(),
            self.connect_timeout,
            || {
                (
                    HttpOverSshConnector {
                        remote_endpoint: self.over_ssh.get_remote_endpoint().to_owned(),
                        debug: self.debug,
                        ssh_session: self.ssh_session.clone(),
                        connect_timeout: self.connect_timeout,
                    },
                    crate::app::APP_CTX.prometheus.clone(),
                )
            },
        );

        let response = http_client
            .do_streamed_request(req, content_size, self.request_timeout)
            .await?;
        Ok(HttpResponse::Response(response))
    }
}

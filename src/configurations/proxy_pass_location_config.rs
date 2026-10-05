use std::time::Duration;

use my_ssh::ssh_settings::OverSshConnectionSettings;

use crate::{
    app::APP_CTX, http_content_source::local_path::LocalPathContentSrc, http_content_source::*,
    http_proxy_pass::content_source::*, settings::LocationSettings,
};

use super::*;

pub struct ProxyPassLocationConfig {
    pub path: String,
    pub id: i64,
    /// Logical identity of the (listen → upstream) pair, formatted as
    /// `"{listen_host}|{path}->{scheme}://{host}:{port}"`. On config apply
    /// we scan existing pools for a matching `id_string` and reuse the
    /// pool's `location_id` instead of allocating a fresh one — this keeps
    /// upstream pools warm across reloads.
    pub id_string: String,
    pub modify_request_headers: ModifyHeadersConfig,
    pub modify_response_headers: ModifyHeadersConfig,
    pub ip_white_list_id: Option<String>,
    pub domain_name: Option<String>,
    pub proxy_pass_to: ProxyPassToConfig,
    pub compress: bool,
    pub auth_header: Option<String>,
}

/// Byte-for-byte comparison of the configured `auth_header` value against the
/// request's `Authorization` value after stripping surrounding SP / HTAB. No
/// scheme parsing on purpose: `Bearer x` and `bearer x` are different values.
/// An absent header and a wrong value are indistinguishable to the caller.
pub fn auth_header_matches(expected: &str, actual: Option<&[u8]>) -> bool {
    match actual {
        Some(actual) => trim_ascii_blanks(actual) == expected.as_bytes(),
        None => false,
    }
}

fn trim_ascii_blanks(input: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = input.len();
    while start < end && (input[start] == b' ' || input[start] == b'\t') {
        start += 1;
    }
    while end > start && (input[end - 1] == b' ' || input[end - 1] == b'\t') {
        end -= 1;
    }
    &input[start..end]
}

impl ProxyPassLocationConfig {
    pub fn new(
        path: String,
        location_settings: &LocationSettings,
        proxy_pass_to: ProxyPassToConfig,
        listen_host: &str,
    ) -> Self {
        let mut modify_request_headers = ModifyHeadersConfig::default();
        let mut modify_response_headers = ModifyHeadersConfig::default();

        if let Some(mut modify_headers) = location_settings.modify_http_headers.clone() {
            modify_request_headers.populate_request(&mut modify_headers);
            modify_response_headers.populate_response(&mut modify_headers);
        }

        let id_string = build_location_id_string(listen_host, &path, &proxy_pass_to);
        let id = crate::scripts::find_location_id_by_id_string(&id_string)
            .unwrap_or_else(|| APP_CTX.get_next_id());

        Self {
            path,
            id,
            id_string,
            modify_request_headers,
            modify_response_headers,
            ip_white_list_id: location_settings.whitelisted_ip.clone(),
            proxy_pass_to,
            domain_name: location_settings.domain_name.clone(),
            compress: location_settings.get_compress(),
            auth_header: location_settings.auth_header.clone(),
        }
    }
    pub fn get_proxy_pass_to_as_string(&self) -> String {
        self.proxy_pass_to.to_string()
    }

    /// The per-location `auth_header` gate. `actual` is the request's raw
    /// `Authorization` value (`None` when the header is absent). Shared by the
    /// h1 byte pipeline and the hyper (h2 endpoint) path so both enforce the
    /// same rule.
    pub fn auth_header_accepts(&self, actual: Option<&[u8]>) -> bool {
        match self.auth_header.as_deref() {
            Some(expected) => auth_header_matches(expected, actual),
            None => true,
        }
    }

    pub async fn create_data_source(
        &self,
        debug: bool,
        timeout: Duration,
    ) -> HttpProxyPassContentSource {
        let is_mcp = self.proxy_pass_to.is_mcp();

        let result = match &self.proxy_pass_to {
            ProxyPassToConfig::Static(config) => HttpProxyPassContentSource::Static(
                crate::http_content_source::static_content::StaticContentSrc::new(config.clone()),
            ),
            ProxyPassToConfig::Http1(proxy_pass) | ProxyPassToConfig::McpHttp1(proxy_pass) => {
                match &proxy_pass.remote_host {
                    MyReverseProxyRemoteEndpoint::Gateway { id, remote_host } => {
                        HttpProxyPassContentSource::Http1OverGateway(
                            Http1OverGatewayContentSource {
                                gateway_id: id.clone(),
                                remote_endpoint: remote_host.clone(),
                                request_timeout: proxy_pass.request_timeout,
                                connect_timeout: proxy_pass.connect_timeout,
                            },
                        )
                    }
                    MyReverseProxyRemoteEndpoint::OverSsh {
                        ssh_credentials,
                        remote_host,
                    } => {
                        let ssh_session = crate::scripts::ssh::get_ssh_session(ssh_credentials)
                            .await
                            .unwrap();

                        let model = Http1OverSshContentSource {
                            over_ssh: OverSshConnectionSettings {
                                ssh_credentials: ssh_credentials.clone().into(),
                                remote_resource_string: remote_host.as_str().to_string(),
                            },
                            ssh_session,
                            debug,
                            request_timeout: proxy_pass.request_timeout,
                            connect_timeout: proxy_pass.connect_timeout,
                        };

                        HttpProxyPassContentSource::Http1OverSsh(model)
                    }
                    MyReverseProxyRemoteEndpoint::Direct { remote_host } => {
                        let remote_endpoint_scheme = remote_host.get_scheme();

                        if remote_endpoint_scheme.is_none() {
                            panic!(
                                "Scheme is not set for remote resource {}",
                                remote_host.as_str()
                            );
                        }

                        match remote_endpoint_scheme.as_ref().unwrap() {
                            rust_extensions::remote_endpoint::Scheme::Http => {
                                let (pool_desc, pool_params, factory) = make_tcp_h1_pool_factory(
                                    remote_host,
                                    debug,
                                    proxy_pass,
                                    self.id,
                                    self.id_string.clone(),
                                    is_mcp,
                                );
                                return HttpProxyPassContentSource::Http1(Http1ContentSource {
                                    pool_desc,
                                    pool_params,
                                    factory,
                                    request_timeout: proxy_pass.request_timeout,
                                    is_mcp,
                                });
                            }
                            rust_extensions::remote_endpoint::Scheme::Https => {
                                let (pool_desc, pool_params, factory) = make_tls_h1_pool_factory(
                                    remote_host,
                                    debug,
                                    self.domain_name.clone(),
                                    proxy_pass,
                                    self.id,
                                    self.id_string.clone(),
                                    is_mcp,
                                );
                                return HttpProxyPassContentSource::Https1(Https1ContentSource {
                                    pool_desc,
                                    pool_params,
                                    factory,
                                    request_timeout: proxy_pass.request_timeout,
                                });
                            }
                            rust_extensions::remote_endpoint::Scheme::Ws => {
                                let (pool_desc, pool_params, factory) = make_tcp_h1_pool_factory(
                                    remote_host,
                                    debug,
                                    proxy_pass,
                                    self.id,
                                    self.id_string.clone(),
                                    is_mcp,
                                );
                                return HttpProxyPassContentSource::Http1(Http1ContentSource {
                                    pool_desc,
                                    pool_params,
                                    factory,
                                    request_timeout: proxy_pass.request_timeout,
                                    is_mcp,
                                });
                            }
                            rust_extensions::remote_endpoint::Scheme::Wss => {
                                let (pool_desc, pool_params, factory) = make_tls_h1_pool_factory(
                                    remote_host,
                                    debug,
                                    self.domain_name.clone(),
                                    proxy_pass,
                                    self.id,
                                    self.id_string.clone(),
                                    is_mcp,
                                );
                                return HttpProxyPassContentSource::Https1(Https1ContentSource {
                                    pool_desc,
                                    pool_params,
                                    factory,
                                    request_timeout: proxy_pass.request_timeout,
                                });
                            }
                            rust_extensions::remote_endpoint::Scheme::UnixSocket => {
                                let (pool_desc, pool_params, factory) = make_uds_h1_pool_factory(
                                    remote_host,
                                    debug,
                                    proxy_pass,
                                    self.id,
                                    self.id_string.clone(),
                                    is_mcp,
                                );
                                return HttpProxyPassContentSource::UnixHttp1(
                                    UnixHttp1ContentSource {
                                        pool_desc,
                                        pool_params,
                                        factory,
                                        request_timeout: proxy_pass.request_timeout,
                                    },
                                );
                            }
                        }
                    }
                }
            }

            ProxyPassToConfig::Http2(proxy_pass) | ProxyPassToConfig::McpHttp2(proxy_pass) => {
                match &proxy_pass.remote_host {
                    MyReverseProxyRemoteEndpoint::Gateway { id, remote_host } => {
                        HttpProxyPassContentSource::Http2OverGateway(
                            Http2OverGatewayContentSource {
                                gateway_id: id.clone(),
                                remote_endpoint: remote_host.clone(),
                                request_timeout: proxy_pass.request_timeout,
                                connect_timeout: proxy_pass.connect_timeout,
                            },
                        )
                    }
                    MyReverseProxyRemoteEndpoint::OverSsh {
                        ssh_credentials,
                        remote_host,
                    } => {
                        let ssh_session = crate::scripts::ssh::get_ssh_session(ssh_credentials)
                            .await
                            .unwrap();

                        let model = Http2OverSshContentSource {
                            over_ssh: OverSshConnectionSettings {
                                ssh_credentials: ssh_credentials.clone().into(),
                                remote_resource_string: remote_host.as_str().to_string(),
                            },
                            ssh_session: ssh_session.clone(),
                            debug,
                            request_timeout: proxy_pass.request_timeout,
                            connect_timeout: proxy_pass.connect_timeout,
                        };

                        return HttpProxyPassContentSource::Http2OverSsh(model);
                    }
                    MyReverseProxyRemoteEndpoint::Direct { remote_host } => {
                        let remote_endpoint_scheme = remote_host.get_scheme();

                        if remote_endpoint_scheme.is_none() {
                            panic!(
                                "Scheme is not set for remote resource {}",
                                remote_host.as_str()
                            );
                        }

                        match remote_endpoint_scheme.as_ref().unwrap() {
                            rust_extensions::remote_endpoint::Scheme::Http => {
                                let (pool_desc, pool_params, factory) = make_tcp_h2_pool_factory(
                                    remote_host,
                                    debug,
                                    proxy_pass,
                                    self.id,
                                    self.id_string.clone(),
                                );
                                return HttpProxyPassContentSource::Http2(Http2ContentSource {
                                    pool_desc,
                                    pool_params,
                                    factory,
                                    request_timeout: proxy_pass.request_timeout,
                                });
                            }
                            rust_extensions::remote_endpoint::Scheme::Https => {
                                let (pool_desc, pool_params, factory) = make_tls_h2_pool_factory(
                                    remote_host,
                                    debug,
                                    self.domain_name.clone(),
                                    proxy_pass,
                                    self.id,
                                    self.id_string.clone(),
                                );
                                return HttpProxyPassContentSource::Https2(Https2ContentSource {
                                    pool_desc,
                                    pool_params,
                                    factory,
                                    request_timeout: proxy_pass.request_timeout,
                                });
                            }
                            rust_extensions::remote_endpoint::Scheme::Ws => {
                                let (pool_desc, pool_params, factory) = make_tcp_h1_pool_factory(
                                    remote_host,
                                    debug,
                                    proxy_pass,
                                    self.id,
                                    self.id_string.clone(),
                                    is_mcp,
                                );
                                return HttpProxyPassContentSource::Http1(Http1ContentSource {
                                    pool_desc,
                                    pool_params,
                                    factory,
                                    request_timeout: proxy_pass.request_timeout,
                                    is_mcp,
                                });
                            }
                            rust_extensions::remote_endpoint::Scheme::Wss => {
                                let (pool_desc, pool_params, factory) = make_tls_h1_pool_factory(
                                    remote_host,
                                    debug,
                                    self.domain_name.clone(),
                                    proxy_pass,
                                    self.id,
                                    self.id_string.clone(),
                                    is_mcp,
                                );
                                return HttpProxyPassContentSource::Https1(Https1ContentSource {
                                    pool_desc,
                                    pool_params,
                                    factory,
                                    request_timeout: proxy_pass.request_timeout,
                                });
                            }
                            rust_extensions::remote_endpoint::Scheme::UnixSocket => {
                                let (pool_desc, pool_params, factory) = make_uds_h2_pool_factory(
                                    remote_host,
                                    debug,
                                    proxy_pass,
                                    self.id,
                                    self.id_string.clone(),
                                );
                                return HttpProxyPassContentSource::UnixHttp2(
                                    UnixHttp2ContentSource {
                                        pool_desc,
                                        pool_params,
                                        factory,
                                        request_timeout: proxy_pass.request_timeout,
                                    },
                                );
                            }
                        }
                    }
                }
            }
            ProxyPassToConfig::FilesPath(model) => match &model.files_path {
                MyReverseProxyRemoteEndpoint::Gateway { id, remote_host } => {
                    let model = PathOverGatewayContentSource {
                        gateway_id: id.clone(),
                        path: remote_host.clone(),
                        default_file: model.default_file.clone(),
                    };
                    HttpProxyPassContentSource::PathOverGateway(model)
                }
                MyReverseProxyRemoteEndpoint::OverSsh {
                    ssh_credentials,
                    remote_host,
                } => {
                    let ssh_session = crate::scripts::ssh::get_ssh_session(ssh_credentials)
                        .await
                        .unwrap();
                    let src = PathOverSshContentSource::new(
                        ssh_session,
                        remote_host.as_str().to_string(),
                        model.default_file.clone(),
                        timeout,
                    );

                    HttpProxyPassContentSource::PathOverSsh(src)
                }
                MyReverseProxyRemoteEndpoint::Direct { remote_host } => {
                    let local_file_path = LocalFilePath::new(remote_host.as_str().to_string());
                    HttpProxyPassContentSource::LocalPath(LocalPathContentSrc::new(
                        &local_file_path,
                        model.default_file.clone(),
                    ))
                }
            },
            ProxyPassToConfig::UnixHttp1(proxy_pass) => match &proxy_pass.remote_host {
                // The gateway peer connects to a socket path itself: through a gateway a unix
                // socket upstream is an ordinary one.
                MyReverseProxyRemoteEndpoint::Gateway { id, remote_host } => {
                    HttpProxyPassContentSource::Http1OverGateway(Http1OverGatewayContentSource {
                        gateway_id: id.clone(),
                        remote_endpoint: remote_host.clone(),
                        request_timeout: proxy_pass.request_timeout,
                        connect_timeout: proxy_pass.connect_timeout,
                    })
                }
                MyReverseProxyRemoteEndpoint::OverSsh {
                    ssh_credentials,
                    remote_host,
                } => {
                    panic!(
                        "Unix+Http is not supported  over ssh. host_port: {}:{}. Remote_host: {}",
                        ssh_credentials.get_host_port().0,
                        ssh_credentials.get_host_port().1,
                        remote_host.as_str()
                    );
                }
                MyReverseProxyRemoteEndpoint::Direct { remote_host } => {
                    let (pool_desc, pool_params, factory) = make_uds_h1_pool_factory(
                        remote_host,
                        debug,
                        proxy_pass,
                        self.id,
                        self.id_string.clone(),
                        is_mcp,
                    );
                    return HttpProxyPassContentSource::UnixHttp1(UnixHttp1ContentSource {
                        pool_desc,
                        pool_params,
                        factory,
                        request_timeout: proxy_pass.request_timeout,
                    });
                }
            },
            ProxyPassToConfig::UnixHttp2(proxy_pass) => match &proxy_pass.remote_host {
                // As for unix+http: the gateway peer connects to the socket path itself.
                MyReverseProxyRemoteEndpoint::Gateway { id, remote_host } => {
                    HttpProxyPassContentSource::Http2OverGateway(Http2OverGatewayContentSource {
                        gateway_id: id.clone(),
                        remote_endpoint: remote_host.clone(),
                        request_timeout: proxy_pass.request_timeout,
                        connect_timeout: proxy_pass.connect_timeout,
                    })
                }
                MyReverseProxyRemoteEndpoint::OverSsh {
                    ssh_credentials,
                    remote_host,
                } => {
                    panic!(
                        "Unix+Http2 is not supported  over ssh. HostPort: {}. RemoteHost: {}",
                        ssh_credentials.get_host_port_as_string(),
                        remote_host.as_str()
                    );
                }
                MyReverseProxyRemoteEndpoint::Direct { remote_host } => {
                    let (pool_desc, pool_params, factory) = make_uds_h2_pool_factory(
                        remote_host,
                        debug,
                        proxy_pass,
                        self.id,
                        self.id_string.clone(),
                    );
                    return HttpProxyPassContentSource::UnixHttp2(UnixHttp2ContentSource {
                        pool_desc,
                        pool_params,
                        factory,
                        request_timeout: proxy_pass.request_timeout,
                    });
                }
            },
            ProxyPassToConfig::Drop => HttpProxyPassContentSource::Drop,
            ProxyPassToConfig::DynamicProxy(config) => {
                HttpProxyPassContentSource::DynamicProxy(DynamicProxyContentSource {
                    request_timeout: config.request_timeout,
                    connect_timeout: config.connect_timeout,
                    allowed_hosts: config.allowed_hosts.clone().map(std::sync::Arc::new),
                    debug,
                })
            }
        };

        result
    }

    pub fn is_remote_content_http1(&self) -> Option<bool> {
        match &self.proxy_pass_to {
            ProxyPassToConfig::Http1(_) => Some(true),
            ProxyPassToConfig::McpHttp1(_) => Some(true),
            ProxyPassToConfig::UnixHttp1(_) => Some(true),
            ProxyPassToConfig::Http2(_) => Some(false),
            ProxyPassToConfig::McpHttp2(_) => Some(false),
            ProxyPassToConfig::UnixHttp2(_) => Some(false),
            ProxyPassToConfig::DynamicProxy(_) => Some(true),
            _ => None,
        }
    }
}

fn build_location_id_string(
    listen_host: &str,
    path: &str,
    proxy_pass_to: &ProxyPassToConfig,
) -> String {
    format!(
        "{}|{}->{}|{}",
        listen_host,
        path,
        proxy_pass_to.get_type_as_str(),
        proxy_pass_to,
    )
}

fn h1_tcp_pool_name(host: &str, port: u16, location_id: i64) -> String {
    format!("h1://{}:{}#{}", host, port, location_id)
}

fn h1_tls_pool_name(host: &str, port: u16, location_id: i64) -> String {
    format!("h1s://{}:{}#{}", host, port, location_id)
}

fn h1_uds_pool_name(socket_path: &str, location_id: i64) -> String {
    format!("uds-h1://{}#{}", socket_path, location_id)
}

fn h2_tcp_pool_name(host: &str, port: u16, location_id: i64) -> String {
    format!("h2://{}:{}#{}", host, port, location_id)
}

fn h2_tls_pool_name(host: &str, port: u16, location_id: i64) -> String {
    format!("h2s://{}:{}#{}", host, port, location_id)
}

fn h2_uds_pool_name(socket_path: &str, location_id: i64) -> String {
    format!("uds-h2://{}#{}", socket_path, location_id)
}

fn h1_pool_params(
    proxy_pass: &ProxyPassToModel,
    is_mcp: bool,
) -> crate::upstream_h1_pool::PoolParams {
    let mut params = crate::upstream_h1_pool::PoolParams {
        connect_timeout: proxy_pass.connect_timeout,
        pool_size: proxy_pass.pool_tuning.pool_size,
        ping_timeout: proxy_pass.pool_tuning.ping_timeout,
        hot_window: proxy_pass.pool_tuning.hot_window,
        // Same global liveness path as the h2 pools; without it, a dead idle h1
        // connection is only discovered by the first real request after the idle.
        health_check_path: APP_CTX.default_h2_livness_url.clone(),
        ..Default::default()
    };
    if is_mcp {
        // MCP SSE bodies can idle far longer than the default read timeout
        // without any keepalive — don't tear down a healthy idle stream.
        params.read_stream_timeout = crate::consts::DEFAULT_MCP_READ_TIMEOUT;
    }
    params
}

fn h2_pool_params(proxy_pass: &ProxyPassToModel) -> crate::upstream_h2_pool::PoolParams {
    crate::upstream_h2_pool::PoolParams {
        connect_timeout: proxy_pass.connect_timeout,
        pool_size: proxy_pass.pool_tuning.pool_size,
        ping_timeout: proxy_pass.pool_tuning.ping_timeout,
        hot_window: proxy_pass.pool_tuning.hot_window,
        health_check_path: APP_CTX.default_h2_livness_url.clone(),
        ..Default::default()
    }
}

pub(crate) fn make_tcp_h1_pool_factory(
    remote_host: &std::sync::Arc<rust_extensions::remote_endpoint::RemoteEndpointOwned>,
    debug: bool,
    proxy_pass: &ProxyPassToModel,
    location_id: i64,
    id_string: String,
    is_mcp: bool,
) -> (
    crate::upstream_h1_pool::PoolDesc,
    crate::upstream_h1_pool::PoolParams,
    crate::upstream_h1_pool::ConnectorFactory<crate::http_client_connectors::HttpConnector>,
) {
    let port = remote_host.get_port().unwrap_or(80);
    let desc = crate::upstream_h1_pool::PoolDesc {
        location_id,
        name: h1_tcp_pool_name(remote_host.get_host(), port, location_id),
        authority: format!("{}:{}", remote_host.get_host(), port),
        id_string,
    };
    let endpoint_arc = remote_host.clone();
    let params = h1_pool_params(proxy_pass, is_mcp);
    let factory: crate::upstream_h1_pool::ConnectorFactory<
        crate::http_client_connectors::HttpConnector,
    > = std::sync::Arc::new(move || {
        let metrics: std::sync::Arc<
            dyn my_http_client::http1::MyHttpClientMetrics + Send + Sync + 'static,
        > = APP_CTX.prometheus.clone();
        (
            crate::http_client_connectors::HttpConnector {
                remote_endpoint: endpoint_arc.clone(),
                debug,
            },
            metrics,
        )
    });
    (desc, params, factory)
}

pub(crate) fn make_tls_h1_pool_factory(
    remote_host: &std::sync::Arc<rust_extensions::remote_endpoint::RemoteEndpointOwned>,
    debug: bool,
    domain_name: Option<String>,
    proxy_pass: &ProxyPassToModel,
    location_id: i64,
    id_string: String,
    is_mcp: bool,
) -> (
    crate::upstream_h1_pool::PoolDesc,
    crate::upstream_h1_pool::PoolParams,
    crate::upstream_h1_pool::ConnectorFactory<crate::http_client_connectors::HttpTlsConnector>,
) {
    let port = remote_host.get_port().unwrap_or(443);
    let desc = crate::upstream_h1_pool::PoolDesc {
        location_id,
        name: h1_tls_pool_name(remote_host.get_host(), port, location_id),
        authority: format!("{}:{}", remote_host.get_host(), port),
        id_string,
    };
    let endpoint_arc = remote_host.clone();
    let params = h1_pool_params(proxy_pass, is_mcp);
    let factory: crate::upstream_h1_pool::ConnectorFactory<
        crate::http_client_connectors::HttpTlsConnector,
    > = std::sync::Arc::new(move || {
        let metrics: std::sync::Arc<
            dyn my_http_client::http1::MyHttpClientMetrics + Send + Sync + 'static,
        > = APP_CTX.prometheus.clone();
        (
            crate::http_client_connectors::HttpTlsConnector {
                remote_endpoint: endpoint_arc.clone(),
                domain_name: domain_name.clone(),
                debug,
            },
            metrics,
        )
    });
    (desc, params, factory)
}

pub(crate) fn make_uds_h1_pool_factory(
    remote_host: &std::sync::Arc<rust_extensions::remote_endpoint::RemoteEndpointOwned>,
    debug: bool,
    proxy_pass: &ProxyPassToModel,
    location_id: i64,
    id_string: String,
    is_mcp: bool,
) -> (
    crate::upstream_h1_pool::PoolDesc,
    crate::upstream_h1_pool::PoolParams,
    crate::upstream_h1_pool::ConnectorFactory<
        crate::http_client_connectors::UnixSocketHttpConnector,
    >,
) {
    let desc = crate::upstream_h1_pool::PoolDesc {
        location_id,
        name: h1_uds_pool_name(remote_host.get_host_port().as_str(), location_id),
        // Unix socket has no host:port; the ping's Host header only needs to
        // be syntactically valid (same placeholder the h2 uds pool uses).
        authority: "localhost".to_string(),
        id_string,
    };
    let endpoint_arc = remote_host.clone();
    let params = h1_pool_params(proxy_pass, is_mcp);
    let factory: crate::upstream_h1_pool::ConnectorFactory<
        crate::http_client_connectors::UnixSocketHttpConnector,
    > = std::sync::Arc::new(move || {
        let metrics: std::sync::Arc<
            dyn my_http_client::http1::MyHttpClientMetrics + Send + Sync + 'static,
        > = APP_CTX.prometheus.clone();
        (
            crate::http_client_connectors::UnixSocketHttpConnector {
                remote_endpoint: endpoint_arc.clone(),
                debug,
            },
            metrics,
        )
    });
    (desc, params, factory)
}

pub(crate) fn make_tcp_h2_pool_factory(
    remote_host: &std::sync::Arc<rust_extensions::remote_endpoint::RemoteEndpointOwned>,
    debug: bool,
    proxy_pass: &ProxyPassToModel,
    location_id: i64,
    id_string: String,
) -> (
    crate::upstream_h2_pool::PoolDesc,
    crate::upstream_h2_pool::PoolParams,
    crate::upstream_h2_pool::ConnectorFactory<crate::http_client_connectors::HttpConnector>,
) {
    let port = remote_host.get_port().unwrap_or(80);
    let host = remote_host.get_host();
    let desc = crate::upstream_h2_pool::PoolDesc {
        location_id,
        name: h2_tcp_pool_name(host, port, location_id),
        authority: format!("{}:{}", host, port),
        id_string,
    };
    let endpoint_arc = remote_host.clone();
    let params = h2_pool_params(proxy_pass);
    let factory: crate::upstream_h2_pool::ConnectorFactory<
        crate::http_client_connectors::HttpConnector,
    > = std::sync::Arc::new(move || {
        let metrics: std::sync::Arc<
            dyn my_http_client::hyper::MyHttpHyperClientMetrics + Send + Sync + 'static,
        > = APP_CTX.prometheus.clone();
        (
            crate::http_client_connectors::HttpConnector {
                remote_endpoint: endpoint_arc.clone(),
                debug,
            },
            metrics,
        )
    });
    (desc, params, factory)
}

pub(crate) fn make_tls_h2_pool_factory(
    remote_host: &std::sync::Arc<rust_extensions::remote_endpoint::RemoteEndpointOwned>,
    debug: bool,
    domain_name: Option<String>,
    proxy_pass: &ProxyPassToModel,
    location_id: i64,
    id_string: String,
) -> (
    crate::upstream_h2_pool::PoolDesc,
    crate::upstream_h2_pool::PoolParams,
    crate::upstream_h2_pool::ConnectorFactory<crate::http_client_connectors::HttpTlsConnector>,
) {
    let port = remote_host.get_port().unwrap_or(443);
    let host = remote_host.get_host();
    let desc = crate::upstream_h2_pool::PoolDesc {
        location_id,
        name: h2_tls_pool_name(host, port, location_id),
        authority: format!("{}:{}", host, port),
        id_string,
    };
    let endpoint_arc = remote_host.clone();
    let params = h2_pool_params(proxy_pass);
    let factory: crate::upstream_h2_pool::ConnectorFactory<
        crate::http_client_connectors::HttpTlsConnector,
    > = std::sync::Arc::new(move || {
        let metrics: std::sync::Arc<
            dyn my_http_client::hyper::MyHttpHyperClientMetrics + Send + Sync + 'static,
        > = APP_CTX.prometheus.clone();
        (
            crate::http_client_connectors::HttpTlsConnector {
                remote_endpoint: endpoint_arc.clone(),
                domain_name: domain_name.clone(),
                debug,
            },
            metrics,
        )
    });
    (desc, params, factory)
}

pub(crate) fn make_uds_h2_pool_factory(
    remote_host: &std::sync::Arc<rust_extensions::remote_endpoint::RemoteEndpointOwned>,
    debug: bool,
    proxy_pass: &ProxyPassToModel,
    location_id: i64,
    id_string: String,
) -> (
    crate::upstream_h2_pool::PoolDesc,
    crate::upstream_h2_pool::PoolParams,
    crate::upstream_h2_pool::ConnectorFactory<
        crate::http_client_connectors::UnixSocketHttpConnector,
    >,
) {
    let desc = crate::upstream_h2_pool::PoolDesc {
        location_id,
        name: h2_uds_pool_name(remote_host.get_host_port().as_str(), location_id),
        authority: "localhost".to_string(),
        id_string,
    };
    let endpoint_arc = remote_host.clone();
    let params = h2_pool_params(proxy_pass);
    let factory: crate::upstream_h2_pool::ConnectorFactory<
        crate::http_client_connectors::UnixSocketHttpConnector,
    > = std::sync::Arc::new(move || {
        let metrics: std::sync::Arc<
            dyn my_http_client::hyper::MyHttpHyperClientMetrics + Send + Sync + 'static,
        > = APP_CTX.prometheus.clone();
        (
            crate::http_client_connectors::UnixSocketHttpConnector {
                remote_endpoint: endpoint_arc.clone(),
                debug,
            },
            metrics,
        )
    });
    (desc, params, factory)
}

#[cfg(test)]
mod auth_header_tests {
    use super::auth_header_matches;

    #[test]
    fn exact_value_matches() {
        assert!(auth_header_matches("Bearer abc", Some(b"Bearer abc")));
    }

    #[test]
    fn surrounding_blanks_are_ignored() {
        assert!(auth_header_matches("Bearer abc", Some(b"  Bearer abc\t")));
    }

    #[test]
    fn absent_header_is_refused() {
        assert!(!auth_header_matches("Bearer abc", None));
    }

    #[test]
    fn wrong_value_is_refused() {
        assert!(!auth_header_matches("Bearer abc", Some(b"Bearer abd")));
        assert!(!auth_header_matches(
            "Bearer abc",
            Some(b"Bearer abc extra")
        ));
        assert!(!auth_header_matches("Bearer abc", Some(b"")));
    }

    #[test]
    fn scheme_is_case_sensitive() {
        assert!(!auth_header_matches("Bearer abc", Some(b"bearer abc")));
    }
}

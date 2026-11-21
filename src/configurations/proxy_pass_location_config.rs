use std::time::Duration;

use my_ssh::ssh_settings::OverSshConnectionSettings;

use crate::{
    app::APP_CTX, http_content_source::*, http_proxy_pass::content_source::*,
    settings::LocationSettings,
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
    /// The location's own `whitelisted_country`: see [`Self::ip_is_allowed`].
    pub whitelisted_country: Option<std::sync::Arc<crate::types::CountryWhiteList>>,
    pub domain_name: Option<String>,
    pub proxy_pass_to: ProxyPassToConfig,
    pub compress: bool,
    /// The id of the set of `api_keys:` a request to this location has to carry a key of in
    /// `X-Api-Key`: the location's own `api_keys_auth`, or else the one of its endpoint (or of the
    /// endpoint's template). `None`: the location is open - `none` was written, or nothing.
    pub api_keys_auth: Option<String>,
    /// `strip_path` of the settings: the upstream gets the request target without the part of
    /// the path which picked this location (`crate::types::strip_location_path`).
    pub strip_path: bool,
    /// `rate_limit` of the location: on top of the one of its endpoint.
    pub rate_limit: Option<std::sync::Arc<crate::types::RateLimiter>>,
    /// The upstream of an h2 location as the h1 pipeline sends to it - built at the first
    /// request and kept for as long as these settings are. See [`Self::h2_upstream`].
    h2_upstream: tokio::sync::OnceCell<std::sync::Arc<HttpProxyPassContentSource>>,
}

impl ProxyPassLocationConfig {
    /// `endpoint_api_keys_auth`: `api_keys_auth` of the endpoint the location is of - or of its
    /// template. `whitelisted_country`: the list the location's `whitelisted_country` names.
    pub fn new(
        path: String,
        location_settings: &LocationSettings,
        proxy_pass_to: ProxyPassToConfig,
        listen_host: &str,
        endpoint_api_keys_auth: Option<&str>,
        whitelisted_country: Option<std::sync::Arc<crate::types::CountryWhiteList>>,
        rate_limit: Option<std::sync::Arc<crate::types::RateLimiter>>,
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
            whitelisted_country,
            proxy_pass_to,
            domain_name: location_settings.domain_name.clone(),
            compress: location_settings.get_compress(),
            api_keys_auth: crate::api_keys::resolve_api_keys_auth(
                location_settings.api_keys_auth.as_deref(),
                endpoint_api_keys_auth,
            ),
            strip_path: location_settings.get_strip_path(),
            rate_limit,
            h2_upstream: tokio::sync::OnceCell::new(),
        }
    }

    /// The upstream of an `http2`, `mcp-h2` or `unix+http2` location for the h1 pipeline. The
    /// hyper path builds one for every connection; the pipeline takes this one for every
    /// request, so it is built once per location and settings: a reload makes new locations,
    /// and with them new upstreams. The connections themselves are in the pools of `APP_CTX`.
    /// `debug` is the endpoint's: a location belongs to one endpoint.
    pub async fn h2_upstream(&self, debug: bool) -> std::sync::Arc<HttpProxyPassContentSource> {
        self.h2_upstream
            .get_or_init(|| async {
                std::sync::Arc::new(
                    self.create_data_source(debug, crate::consts::DEFAULT_HTTP_CONNECT_TIMEOUT)
                        .await,
                )
            })
            .await
            .clone()
    }
    pub fn get_proxy_pass_to_as_string(&self) -> String {
        self.proxy_pass_to.to_string()
    }

    /// The `api_keys_auth` gate of the location. `values`: every `X-Api-Key` header of the
    /// request. Shared by the h1 byte pipeline and the hyper path, so both apply the same rule.
    /// A request it refuses is counted against its source by the IP block-list - the caller
    /// does that, it has the address.
    pub fn api_keys_auth_accepts<'a>(&self, values: impl Iterator<Item = &'a [u8]>) -> bool {
        match self.api_keys_auth.as_deref() {
            Some(id) => crate::api_keys::request_has_api_key(&APP_CTX.api_keys, id, values),
            None => true,
        }
    }

    /// The location's own `whitelisted_ip` and `whitelisted_country` - on top of the endpoint's.
    /// Shared by the h1 byte pipeline and the hyper path so both enforce the same rule. A
    /// connection without an address (a unix socket) is not restricted - the same exemption the
    /// endpoint's lists have. See [`client_address_refusal`].
    pub async fn ip_is_allowed(&self, connection_ip: &crate::types::ConnectionIp) -> bool {
        client_address_refusal(
            self.ip_white_list_id.as_deref(),
            self.whitelisted_country.as_deref(),
            connection_ip,
        )
        .await
        .is_none()
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
                            #[cfg(unix)]
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
                            // Not reached: compiling the settings refuses a unix socket upstream on
                            // this platform.
                            #[cfg(not(unix))]
                            rust_extensions::remote_endpoint::Scheme::UnixSocket => {
                                return unix_socket_not_supported();
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
                            #[cfg(unix)]
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
                            // Not reached: compiling the settings refuses a unix socket upstream on
                            // this platform.
                            #[cfg(not(unix))]
                            rust_extensions::remote_endpoint::Scheme::UnixSocket => {
                                return unix_socket_not_supported();
                            }
                        }
                    }
                }
            }
            ProxyPassToConfig::FilesPath(model) => {
                HttpProxyPassContentSource::Files(FilesContentSource::new(model, timeout))
            }
            #[cfg(unix)]
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
            #[cfg(unix)]
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
            #[cfg(unix)]
            ProxyPassToConfig::UnixHttp1(_) => Some(true),
            ProxyPassToConfig::Http2(_) => Some(false),
            ProxyPassToConfig::McpHttp2(_) => Some(false),
            #[cfg(unix)]
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

#[cfg(unix)]
fn h1_uds_pool_name(socket_path: &str, location_id: i64) -> String {
    format!("uds-h1://{}#{}", socket_path, location_id)
}

fn h2_tcp_pool_name(host: &str, port: u16, location_id: i64) -> String {
    format!("h2://{}:{}#{}", host, port, location_id)
}

fn h2_tls_pool_name(host: &str, port: u16, location_id: i64) -> String {
    format!("h2s://{}:{}#{}", host, port, location_id)
}

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
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

/// What a unix socket upstream is served by on a platform without unix sockets: a 502 which
/// says why.
#[cfg(not(unix))]
fn unix_socket_not_supported() -> HttpProxyPassContentSource {
    HttpProxyPassContentSource::Static(
        crate::http_content_source::static_content::StaticContentSrc::new(std::sync::Arc::new(
            StaticContentConfig {
                status_code: 502,
                content_type: Some("text/plain".to_string()),
                body: crate::consts::UNIX_SOCKETS_NOT_SUPPORTED
                    .as_bytes()
                    .to_vec(),
            },
        )),
    )
}

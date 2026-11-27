use my_ssh::ssh_settings::OverSshConnectionSettings;

use crate::{configurations::*, settings::*, settings_compiled::SettingsCompiled};

/// `endpoint_api_keys_auth`: `api_keys_auth` of the endpoint the location is of - or of its
/// template: the location is guarded by it unless it names a set of its own, or `none`.
pub async fn compile_location_proxy_pass_to(
    settings_model: &SettingsCompiled,
    location_settings: &LocationSettings,
    listen_host: &str,
    resolved: &ResolvedTimeouts,
    endpoint_api_keys_auth: Option<&str>,
) -> Result<ProxyPassLocationConfig, String> {
    let path = location_settings.path.as_deref().unwrap_or("/").to_string();

    let location_type = match location_settings.get_location_type()? {
        Some(location_type) => location_type,
        None => LocationType::detect_from_location_settings(location_settings)?,
    };

    // Every network location type compiles the same model out of
    // `proxy_pass_to` and differs only in which variant wraps it — the variant
    // is the only decision, so the parsing lives in one helper.
    let proxy_pass_to = match location_type {
        #[cfg(unix)]
        LocationType::UnixSocketHttp => ProxyPassToConfig::UnixHttp1(
            compile_model(
                location_settings,
                settings_model,
                resolved,
                "unix+http",
                listen_host,
                &path,
            )
            .await?,
        ),

        #[cfg(unix)]
        LocationType::UnixSocketHttp2 => ProxyPassToConfig::UnixHttp2(
            compile_model(
                location_settings,
                settings_model,
                resolved,
                "unix+http2",
                listen_host,
                &path,
            )
            .await?,
        ),

        #[cfg(not(unix))]
        LocationType::UnixSocketHttp | LocationType::UnixSocketHttp2 => {
            return Err(unix_socket_upstream_is_refused(
                listen_host,
                &path,
                location_settings,
            ));
        }

        LocationType::Http | LocationType::Https1 => ProxyPassToConfig::Http1(
            compile_model(
                location_settings,
                settings_model,
                resolved,
                "http",
                listen_host,
                &path,
            )
            .await?,
        ),

        LocationType::Mcp => ProxyPassToConfig::McpHttp1(
            compile_model(
                location_settings,
                settings_model,
                resolved,
                crate::consts::location_type::MCP,
                listen_host,
                &path,
            )
            .await?,
        ),

        LocationType::McpH2 => ProxyPassToConfig::McpHttp2(
            compile_model(
                location_settings,
                settings_model,
                resolved,
                crate::consts::location_type::MCP_H2,
                listen_host,
                &path,
            )
            .await?,
        ),

        LocationType::Http2 | LocationType::Https2 => ProxyPassToConfig::Http2(
            compile_model(
                location_settings,
                settings_model,
                resolved,
                "http2",
                listen_host,
                &path,
            )
            .await?,
        ),

        LocationType::Files => {
            if location_settings.proxy_pass_to.is_none() {
                return Err("proxy_pass_to is required for files location type".to_string());
            }

            let proxy_pass_to = location_settings.proxy_pass_to.clone().unwrap();

            // A location is read as a folder when `proxy_pass_to` is not an url: so is a socket
            // file without its type. With a path after it, it is plainly not a folder.
            if let Ok((_, Some(_))) = split_unix_socket_path(proxy_pass_to.as_str()) {
                return Err(format!(
                    "Endpoint '{listen_host}', location '{path}': proxy_pass_to '{proxy_pass_to}' \
                     is a unix socket and the path of its requests, not a folder: give the \
                     location its type - mcp, mcp-h2, unix+http or unix+http2"
                ));
            }

            let files_path =
                MyReverseProxyRemoteEndpoint::try_parse(proxy_pass_to.as_str(), settings_model)
                    .await?;

            let model = ProxyPassFilesPathModel {
                files_path,
                default_file: location_settings.default_file.clone(),
            };

            ProxyPassToConfig::FilesPath(model)
        }
        LocationType::StaticContent => {
            let body = location_settings.body.clone().unwrap_or_default();

            let body = get_static_content_body(body).await?;
            let model: StaticContentConfig = StaticContentConfig {
                status_code: location_settings.status_code.unwrap_or(200),
                content_type: location_settings.content_type.clone(),
                body,
            };

            ProxyPassToConfig::Static(model.into())
        }
        LocationType::Drop => ProxyPassToConfig::Drop,
        LocationType::DynamicProxy => ProxyPassToConfig::DynamicProxy(
            DynamicProxyConfig {
                request_timeout: resolved.request_timeout,
                connect_timeout: resolved.connect_timeout,
                allowed_hosts: location_settings.allowed_hosts.clone(),
            }
            .into(),
        ),
    };

    // A unix socket upstream of a location of another type: a `unix+http://`, `http+unix://` or
    // `unix://` URL, or a socket path behind a gateway.
    #[cfg(not(unix))]
    if let ProxyPassToConfig::Http1(model)
    | ProxyPassToConfig::Http2(model)
    | ProxyPassToConfig::McpHttp1(model)
    | ProxyPassToConfig::McpHttp2(model) = &proxy_pass_to
    {
        if model.remote_host.is_unix_socket() {
            return Err(unix_socket_upstream_is_refused(
                listen_host,
                &path,
                location_settings,
            ));
        }
    }

    let whitelisted_country =
        super::get_location_whitelisted_country(settings_model, location_settings)?;

    let rate_limit = match location_settings.rate_limit.as_deref() {
        Some(rate) => Some(std::sync::Arc::new(
            crate::types::RateLimiter::parse(rate, location_settings.rate_limit_burst)
                .map_err(|err| format!("Endpoint '{listen_host}', location '{path}': {err}"))?,
        )),
        None => None,
    };

    let result = ProxyPassLocationConfig::new(
        path,
        location_settings,
        proxy_pass_to,
        listen_host,
        endpoint_api_keys_auth,
        whitelisted_country,
        rate_limit,
    );

    Ok(result)
}

/// A unix socket upstream - direct, or the target of a gateway - is refused on a platform without
/// unix sockets: refused when its location compiles, only its endpoint fails to load, and says why.
#[cfg(not(unix))]
fn unix_socket_upstream_is_refused(
    listen_host: &str,
    path: &str,
    location_settings: &LocationSettings,
) -> String {
    format!(
        "Endpoint '{}', location '{}': proxy_pass_to '{}' is a unix socket: {}",
        listen_host,
        path,
        location_settings
            .proxy_pass_to
            .as_deref()
            .unwrap_or_default(),
        crate::consts::UNIX_SOCKETS_NOT_SUPPORTED
    )
}

/// Parses `proxy_pass_to` into the upstream model shared by every network
/// location type. `location_type_name` only names the type in the error, `listen_host` and
/// `path` the location.
async fn compile_model(
    location_settings: &LocationSettings,
    settings_model: &SettingsCompiled,
    resolved: &ResolvedTimeouts,
    location_type_name: &str,
    listen_host: &str,
    path: &str,
) -> Result<ProxyPassToModel, String> {
    let Some(proxy_pass_to) = location_settings.proxy_pass_to.as_ref() else {
        return Err(format!(
            "proxy_pass_to is required for {} location type",
            location_type_name
        ));
    };

    let (remote_host, socket_path_and_query) = split_socket_path(proxy_pass_to).map_err(|err| {
        format!("Endpoint '{listen_host}', location '{path}': proxy_pass_to {err}")
    })?;

    Ok(ProxyPassToModel {
        remote_host: MyReverseProxyRemoteEndpoint::try_parse(remote_host, settings_model).await?,
        socket_path_and_query: socket_path_and_query.map(str::to_string),
        server_name: location_settings.domain_name.clone(),
        request_timeout: resolved.request_timeout,
        connect_timeout: resolved.connect_timeout,
        pool_tuning: PoolTuning::from_resolved(resolved),
    })
}

/// `proxy_pass_to` without the path written after the socket file of a unix socket of this host,
/// and that path: see [`split_unix_socket_path`]. A socket behind `ssh:...->` or `gateway:...->`
/// is not a file of this host, and a path after it is refused rather than taken for a part of the
/// socket file.
fn split_socket_path(proxy_pass_to: &str) -> Result<(&str, Option<&str>), String> {
    // Where `MyReverseProxyRemoteEndpoint::try_parse` splits a source behind ssh or a gateway.
    if let Some((_, target)) = proxy_pass_to.split_once("->") {
        if split_unix_socket_path(target)?.1.is_some() {
            return Err(format!(
                "'{proxy_pass_to}': a path after the socket file is read for a unix socket of \
                 this host only - not behind ssh: or gateway:"
            ));
        }

        return Ok((proxy_pass_to, None));
    }

    split_unix_socket_path(proxy_pass_to)
}

async fn get_static_content_body(body: String) -> Result<Vec<u8>, String> {
    if body.is_empty() {
        return Ok(Vec::new());
    }
    match get_fist_char(body.as_str()) {
        Some(c) => {
            if c == '<' {
                return Ok(body.into_bytes());
            }

            if c == '{' {
                return Ok(body.into_bytes());
            }

            match OverSshConnectionSettings::try_parse(body.as_str()) {
                Some(data_source) => {
                    super::load_file(&data_source, crate::consts::DEFAULT_HTTP_CONNECT_TIMEOUT)
                        .await
                }
                None => Ok(body.into_bytes()),
            }
        }
        None => Ok(body.into_bytes()),
    }
}

fn get_fist_char(body: &str) -> Option<char> {
    for c in body.chars() {
        if c.is_whitespace() {
            continue;
        }

        return Some(c);
    }

    None
}

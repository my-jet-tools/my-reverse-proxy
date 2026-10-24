use std::sync::Arc;

use crate::{
    configurations::{
        EndpointHttpHostString, HttpEndpointInfo, HttpEndpointInfoParams, ListenHttpEndpointType,
        NotServedReason, ProxyPassLocationConfig,
    },
    settings::HostSettings,
    settings_compiled::SettingsCompiled,
};

pub async fn compile_http_configuration(
    settings_model: &SettingsCompiled,
    host_endpoint: EndpointHttpHostString,
    host_settings: &HostSettings,
    http_type: ListenHttpEndpointType,
) -> Result<HttpEndpointInfo, String> {
    let mut locations = Vec::with_capacity(host_settings.locations.len());

    let endpoint_whitelisted_ip =
        super::get_endpoint_white_listed_ip(settings_model, host_settings).await?;

    let allowed_user_list =
        crate::scripts::get_endpoint_users_list(settings_model, host_settings).await?;

    let modify_endpoints_headers =
        crate::scripts::get_endpoint_modify_headers(settings_model, host_settings);

    let (g_auth, ssl_cert_id, client_cert_ca) = if http_type.is_https_or_mcp() {
        let ssl_cert_id = super::make_sure_ssl_cert_exists(settings_model, host_settings).await?;

        let client_cert_ca =
            super::make_sure_client_ca_exists(settings_model, host_settings).await?;

        let g_auth = super::get_google_auth_credentials(settings_model, host_settings).await?;

        (g_auth, Some(ssl_cert_id), client_cert_ca)
    } else {
        // A client certificate is presented during a TLS handshake, so on a plain-http endpoint
        // the setting can not be applied at all. Silently dropping it would leave an endpoint the
        // operator believes is mTLS-protected serving everyone - and with no "ca not loaded"
        // badge to hint at it, since the endpoint carries no ca id.
        let client_cert_ca = super::get_from_host_or_templates(
            settings_model,
            host_settings,
            |host_settings| host_settings.endpoint.client_certificate_ca.as_ref(),
            |templates| templates.client_certificate_ca.as_ref(),
        )?;

        if client_cert_ca.is_some() {
            return Err(format!(
                "Endpoint '{}' is 'type: {}', which has no TLS layer, so 'client_certificate_ca' \
             can not be applied to it - the endpoint would serve every client unverified. Use \
             'type: https' / 'type: https2' on the endpoint, or remove 'client_certificate_ca'",
                host_endpoint.as_str(),
                http_type.as_str()
            ));
        }

        (None, None, None::<super::ClientCaRequirement>)
    };

    let not_served_reason = access_settings_the_endpoint_can_not_apply(
        settings_model,
        &host_endpoint,
        host_settings,
        http_type,
        g_auth.is_some(),
        allowed_user_list.is_some(),
    )?;

    // Unlike google_auth this is resolved for plain-http endpoints too: an
    // endpoint behind a TLS-terminating proxy is still reached over https by the
    // client, and `public_url` is there to say so.
    let oauth = super::get_oauth_credentials(settings_model, host_settings).await?;

    // `type: mcp` is a raw byte bridge that never parses HTTP, so there is
    // nothing an authorization server could hook into. Refusing the config is
    // better than starting up and serving the MCP server unauthenticated.
    if oauth.is_some() && matches!(http_type, ListenHttpEndpointType::Mcp) {
        return Err(format!(
            "Endpoint '{}' is 'type: mcp', which is a raw TCP bridge with no HTTP layer, so \
             'oauth' can not be applied to it. Use 'type: https' on the endpoint with a location \
             of 'type: mcp' instead",
            host_endpoint.as_str()
        ));
    }

    // Timeout cascade: HardCode < Global < Endpoint < Location.
    // Build the global→endpoint layer once, then layer each location on top.
    let global_timeouts = settings_model.get_global_timeouts();
    let endpoint_timeouts = global_timeouts.overriden_by(&host_settings.endpoint.timeouts);

    // MCP timeouts are tunnel-scoped: resolved from the endpoint layer, with the
    // first location allowed to override (an mcp endpoint carries one location).
    let mut mcp_resolved = endpoint_timeouts.resolve();

    let listen_host = host_endpoint.as_str().to_string();
    for (location_index, location_settings) in host_settings.locations.iter().enumerate() {
        let resolved = endpoint_timeouts
            .overriden_by(&location_settings.timeouts)
            .resolve();

        if location_index == 0 {
            mcp_resolved = resolved;
        }

        // A list a location names is loaded the same way as one the endpoint
        // names - and has to be declared just the same. Nothing else loads it.
        if let Some(ip_list_id) = location_settings.whitelisted_ip.as_ref() {
            super::refresh_ip_list_from_settings(settings_model, ip_list_id).await?;
        }

        let proxy_pass_to = super::compile_location_proxy_pass_to(
            settings_model,
            location_settings,
            &listen_host,
            &resolved,
        )
        .await?;

        // MCP never goes through a gateway - not as an mcp location, not as a 'type: mcp'
        // endpoint: such a configuration is refused rather than half supported.
        let is_mcp = proxy_pass_to.proxy_pass_to.is_mcp()
            || matches!(http_type, ListenHttpEndpointType::Mcp);
        if is_mcp && proxy_pass_to.proxy_pass_to.remote_endpoint_kind() == Some("gateway") {
            return Err(format!(
                "Endpoint '{}', location '{}': MCP through a gateway is not supported. Point \
                 proxy_pass_to at the MCP server directly",
                listen_host, proxy_pass_to.path
            ));
        }

        // `mcp-h2` talks h2 to the upstream, and the h2 upstream pools are only
        // reachable from the hyper request path — which runs for `http2` /
        // `https2` endpoints. Under an http/1 endpoint the request goes through
        // the byte pipeline, which has no h2 upstream at all, so every request
        // to this location would fail. Say it at config time.
        if http_type.is_http1_or_mcp()
            && matches!(
                proxy_pass_to.proxy_pass_to,
                crate::configurations::ProxyPassToConfig::McpHttp2(_)
            )
        {
            return Err(format!(
                "Endpoint '{}' is 'type: {}' (http/1), but its location '{}' is 'type: {}', which \
                 requires an http/2 upstream. Use 'type: {}' here, or move the location to an \
                 endpoint of 'type: http2' / 'type: https2'",
                listen_host,
                http_type.as_str(),
                proxy_pass_to.path,
                crate::consts::location_type::MCP_H2,
                crate::consts::location_type::MCP,
            ));
        }

        // Where the request path is not what goes on, `strip_path` has nothing to cut. Refused
        // rather than ignored: the operator expects the upstream to see another path.
        if proxy_pass_to.strip_path {
            if let Some(reason) = strip_path_has_no_meaning(http_type, &proxy_pass_to) {
                return Err(format!(
                    "Endpoint '{}', location '{}': 'strip_path' has no meaning here - {}. Remove \
                     'strip_path'",
                    listen_host, proxy_pass_to.path, reason
                ));
            }
        }

        {
            locations.push(Arc::new(proxy_pass_to));
        }
    }

    let mcp_settings = crate::configurations::McpEndpointSettings::new(
        mcp_resolved.read_timeout,
        mcp_resolved.write_timeout,
        host_settings.endpoint.get_mcp_buffer_size(),
    );

    // Endpoint-scoped transport read/write timeouts (global → endpoint), applied
    // to every byte pump of this endpoint's connections.
    let endpoint_resolved = endpoint_timeouts.resolve();
    let http_timeouts = crate::types::HttpTimeouts {
        read_timeout: endpoint_resolved.read_timeout,
        write_timeout: endpoint_resolved.write_timeout,
    };

    let http_endpoint_info = HttpEndpointInfo::new(HttpEndpointInfoParams {
        host_endpoint,
        listen_endpoint_type: http_type,
        debug: host_settings.endpoint.get_debug(),
        inject_country: host_settings.endpoint.get_inject_country(),
        g_auth,
        oauth,
        ssl_certificate_id: ssl_cert_id,
        client_certificate_unlimited_expiration: client_cert_ca
            .as_ref()
            .map(|itm| itm.unlimited_expiration)
            .unwrap_or(false),
        client_certificate_id: client_cert_ca.map(|itm| itm.id),
        whitelisted_ip_list_id: endpoint_whitelisted_ip,
        locations,
        allowed_user_list_id: allowed_user_list,
        modify_headers_settings: modify_endpoints_headers,
        keep_alive: host_settings.endpoint.keep_alive.unwrap_or(true),
        track_metrics_by_all_domains: host_settings
            .endpoint
            .track_metrics_by_all_domains
            .unwrap_or(false),
        hsts: host_settings.endpoint.hsts.unwrap_or(false),
        mcp_settings,
        timeouts: http_timeouts,
        not_served_reason,
    });

    Ok(http_endpoint_info)
}

/// Why a location with `strip_path` can not have it, if it can not: the request path is not
/// what its upstream gets, or there is no upstream.
fn strip_path_has_no_meaning(
    http_type: ListenHttpEndpointType,
    location: &ProxyPassLocationConfig,
) -> Option<&'static str> {
    use crate::configurations::ProxyPassToConfig;

    if matches!(http_type, ListenHttpEndpointType::Mcp) {
        return Some(
            "the endpoint is 'type: mcp', a raw bridge with no HTTP layer, so there is no \
             request path to cut",
        );
    }

    let reason = match &location.proxy_pass_to {
        ProxyPassToConfig::McpHttp1(_) | ProxyPassToConfig::McpHttp2(_) => {
            "an mcp location sends every request to the path of its proxy_pass_to"
        }
        ProxyPassToConfig::Static(_) => "a static location answers by itself",
        ProxyPassToConfig::Drop => "a drop location closes the connection",
        _ => {
            // The cut is made in the path as it was received, where the decoded match of the
            // location path ends. When that is not text, the end can fall inside a letter.
            let decoded = crate::types::percent_decode_once(location.path.as_bytes());

            if std::str::from_utf8(&decoded).is_ok() {
                return None;
            }

            "the path of the location, percent-decoded, is not UTF-8 text, so the cut could \
             fall inside a letter"
        }
    };

    Some(reason)
}

/// The access settings of the endpoint which its type has no way to apply. The settings load
/// with them, and the endpoint serves nobody: see [`NotServedReason`].
///
/// - `type: mcp` is a TLS termination and a byte bridge to the first location. It parses no
///   HTTP, so it can check neither a header nor a session: `auth_header` of a location,
///   `google_auth` and `allowed_users`. (`whitelisted_ip` it can check, and does - by the
///   address of the connection.)
/// - `google_auth` is resolved for `https` and `https2` endpoints only: on `http` and `http2`
///   it is not there, and the endpoint would serve everybody.
fn access_settings_the_endpoint_can_not_apply(
    settings_model: &SettingsCompiled,
    host_endpoint: &EndpointHttpHostString,
    host_settings: &HostSettings,
    http_type: ListenHttpEndpointType,
    has_google_auth: bool,
    has_allowed_users: bool,
) -> Result<Option<NotServedReason>, String> {
    let result = match http_type {
        ListenHttpEndpointType::Mcp => {
            let mut settings = Vec::new();

            if host_settings
                .locations
                .iter()
                .any(|location| location.auth_header.is_some())
            {
                settings.push("auth_header");
            }

            if has_google_auth {
                settings.push("google_auth");
            }

            if has_allowed_users {
                settings.push("allowed_users");
            }

            NotServedReason::new(
                host_endpoint.as_str(),
                http_type.as_str(),
                &settings,
                "a raw bridge with no HTTP layer",
                "remove the setting, or use 'type: https' on the endpoint with a location of \
                 'type: mcp'",
            )
        }
        ListenHttpEndpointType::Http1 | ListenHttpEndpointType::Http2 => {
            let google_auth = super::get_from_host_or_templates(
                settings_model,
                host_settings,
                |host_settings| host_settings.endpoint.google_auth.as_ref(),
                |templates| templates.google_auth.as_ref(),
            )?;

            let settings: &[&str] = if google_auth.is_some() {
                &["google_auth"]
            } else {
                &[]
            };

            NotServedReason::new(
                host_endpoint.as_str(),
                http_type.as_str(),
                settings,
                "which has no TLS layer",
                "remove 'google_auth', or use 'type: https' / 'type: https2' on the endpoint",
            )
        }
        ListenHttpEndpointType::Https1 | ListenHttpEndpointType::Https2 => None,
    };

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn compile(endpoint_type: &str, location_type: &str) -> Result<(), String> {
        let host_settings: HostSettings = my_settings_reader::serde_yaml::from_str(&format!(
            "endpoint:\n  type: {endpoint_type}\nlocations:\n- path: /mcp\n  type: {location_type}\n  proxy_pass_to: 'gateway:gw->http://127.0.0.1:8000/mcp'\n"
        ))
        .unwrap();

        let listen_type = match endpoint_type {
            "http" => ListenHttpEndpointType::Http1,
            "http2" => ListenHttpEndpointType::Http2,
            "mcp" => ListenHttpEndpointType::Mcp,
            other => panic!("no endpoint type {other} in these tests"),
        };

        compile_http_configuration(
            &SettingsCompiled::default(),
            EndpointHttpHostString::new("localhost:8000".to_string()).unwrap(),
            &host_settings,
            listen_type,
        )
        .await
        .map(|_| ())
    }

    #[tokio::test]
    async fn mcp_through_a_gateway_is_refused() {
        for (endpoint_type, location_type) in
            [("http", "mcp"), ("http2", "mcp-h2"), ("mcp", "http")]
        {
            let err = compile(endpoint_type, location_type)
                .await
                .expect_err("MCP through a gateway is accepted");
            assert!(
                err.contains("MCP through a gateway is not supported"),
                "{endpoint_type}/{location_type}: {err}"
            );
        }

        // Anything else still goes through a gateway.
        compile("http", "http").await.unwrap();
        compile("http2", "http2").await.unwrap();
    }

    /// `locations`: the `locations:` list as a settings file writes it.
    async fn compile_locations(
        endpoint_type: &str,
        locations: &str,
    ) -> Result<HttpEndpointInfo, String> {
        let host_settings: HostSettings = my_settings_reader::serde_yaml::from_str(&format!(
            "endpoint:\n  type: {endpoint_type}\nlocations:\n{locations}"
        ))
        .unwrap();

        let listen_type = match endpoint_type {
            "http" => ListenHttpEndpointType::Http1,
            "http2" => ListenHttpEndpointType::Http2,
            "mcp" => ListenHttpEndpointType::Mcp,
            other => panic!("no endpoint type {other} in these tests"),
        };

        compile_http_configuration(
            &SettingsCompiled::default(),
            EndpointHttpHostString::new("localhost:8000".to_string()).unwrap(),
            &host_settings,
            listen_type,
        )
        .await
    }

    /// A location with `strip_path`, of the type and to the upstream given.
    fn stripped_location(location_type: &str, proxy_pass_to: &str) -> String {
        format!(
            "- path: /prefix/\n  type: {location_type}\n  proxy_pass_to: '{proxy_pass_to}'\n  strip_path: true\n"
        )
    }

    #[tokio::test]
    async fn strip_path_is_taken_by_a_location_which_sends_the_request_on() {
        let mut locations = Vec::new();

        for (location_type, proxy_pass_to) in [
            ("http", "http://127.0.0.1:8000"),
            ("http", "https://127.0.0.1:8000"),
            ("http2", "http://127.0.0.1:8000"),
            ("http", "gateway:gw->http://127.0.0.1:8000"),
            ("http2", "gateway:gw->http://127.0.0.1:8000"),
            ("http", "ssh:user@127.0.0.1:22->http://127.0.0.1:8000"),
            ("http2", "ssh:user@127.0.0.1:22->http://127.0.0.1:8000"),
        ] {
            locations.push(stripped_location(location_type, proxy_pass_to));
        }

        // A folder served under a prefix, and the upstream a client names.
        locations.push(
            "- path: /static/\n  proxy_pass_to: '/srv/www'\n  default_file: index.html\n  strip_path: true\n"
                .to_string(),
        );
        locations.push("- path: /dynamic/\n  type: dynamic\n  strip_path: true\n".to_string());

        #[cfg(unix)]
        {
            locations.push(stripped_location("unix+http", "/var/run/app.sock"));
            locations.push(stripped_location("unix+http2", "/var/run/app.sock"));
        }

        // Escapes in the path of the location are fine as long as it is text, decoded.
        locations.push(
            stripped_location("http", "http://127.0.0.1:8000").replace("/prefix/", "/caf%C3%A9/"),
        );

        for endpoint_type in ["http", "http2"] {
            for location in &locations {
                let endpoint_info = compile_locations(endpoint_type, location)
                    .await
                    .unwrap_or_else(|err| panic!("{endpoint_type}: {location}: {err}"));

                assert!(
                    endpoint_info.locations[0].strip_path,
                    "{endpoint_type}: {location}"
                );
            }
        }

        // Not set, it is off.
        let endpoint_info = compile_locations(
            "http",
            "- path: /prefix/\n  proxy_pass_to: 'http://127.0.0.1:8000'\n",
        )
        .await
        .unwrap();
        assert!(!endpoint_info.locations[0].strip_path);
    }

    #[tokio::test]
    async fn strip_path_is_refused_where_the_request_path_goes_nowhere() {
        for (endpoint_type, location) in [
            (
                "http",
                stripped_location("mcp", "http://127.0.0.1:8000/mcp"),
            ),
            (
                "http2",
                stripped_location("mcp-h2", "http://127.0.0.1:8000/mcp"),
            ),
            (
                "http",
                "- path: /prefix/\n  type: static\n  strip_path: true\n".to_string(),
            ),
            (
                "http2",
                "- path: /prefix/\n  type: static\n  strip_path: true\n".to_string(),
            ),
            (
                "http",
                "- path: /prefix/\n  type: drop\n  strip_path: true\n".to_string(),
            ),
            (
                "http2",
                "- path: /prefix/\n  type: drop\n  strip_path: true\n".to_string(),
            ),
            // A byte bridge: no request path at all.
            ("mcp", stripped_location("http", "http://127.0.0.1:8000")),
            // The second location of a `type: mcp` endpoint is looked at as well.
            (
                "mcp",
                format!(
                    "- path: /\n  type: http\n  proxy_pass_to: 'http://127.0.0.1:8000'\n{}",
                    stripped_location("http", "http://127.0.0.1:8000")
                ),
            ),
            // `%C3` alone is half a letter.
            (
                "http",
                stripped_location("http", "http://127.0.0.1:8000").replace("/prefix/", "/caf%C3"),
            ),
            (
                "http2",
                stripped_location("http", "http://127.0.0.1:8000").replace("/prefix/", "/%FF/"),
            ),
        ] {
            let Err(err) = compile_locations(endpoint_type, &location).await else {
                panic!("{endpoint_type}: {location}: strip_path is accepted");
            };

            assert!(
                err.contains("'strip_path' has no meaning here"),
                "{endpoint_type}: {location}: {err}"
            );
        }

        // Off, it is nothing to refuse.
        compile_locations(
            "http",
            "- path: /prefix/\n  type: static\n  strip_path: false\n",
        )
        .await
        .unwrap();
    }
}

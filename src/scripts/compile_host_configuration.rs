use std::sync::Arc;

use crate::{
    configurations::*,
    settings::{EndpointTypeSettings, HostSettings},
    settings_compiled::SettingsCompiled,
};

/// Compiles a single host into a `ListenConfiguration`. For HTTP endpoints multiple hosts can
/// share one port, so `existing` is the configuration already accumulated for that port (from the
/// live config on a per-port reload, or from the map being built during a full reload) and the new
/// endpoint is merged into it. `None` means this is the first host on the port.
pub async fn compile_host_configuration(
    settings_model: &SettingsCompiled,
    host_endpoint: EndpointHttpHostString,
    host_settings: &HostSettings,
    existing: Option<ListenConfiguration>,
) -> Result<ListenConfiguration, String> {
    // Refused here rather than when the settings are read: only this endpoint fails to load, the
    // others are served, and the error is reported with theirs.
    #[cfg(not(unix))]
    if host_endpoint.is_unix_socket() {
        return Err(format!(
            "Endpoint '{}' listens on a unix socket: {}",
            host_endpoint.as_str(),
            crate::consts::UNIX_SOCKETS_NOT_SUPPORTED
        ));
    }

    match host_settings.endpoint.get_endpoint_type()? {
        EndpointTypeSettings::Http1 => {
            let http_endpoint_info = crate::scripts::compile_http_configuration(
                settings_model,
                host_endpoint,
                host_settings,
                ListenHttpEndpointType::Http1,
            )
            .await?;

            let config = super::merge_http_into_existing(existing, http_endpoint_info)?;

            Ok(ListenConfiguration::Http(Arc::new(config)))
        }

        EndpointTypeSettings::Http2 => {
            let http_endpoint_info = crate::scripts::compile_http_configuration(
                settings_model,
                host_endpoint,
                host_settings,
                ListenHttpEndpointType::Http2,
            )
            .await?;

            let config = super::merge_http_into_existing(existing, http_endpoint_info)?;

            Ok(ListenConfiguration::Http(Arc::new(config)))
        }

        EndpointTypeSettings::Https1 => {
            let http_endpoint_info = crate::scripts::compile_http_configuration(
                settings_model,
                host_endpoint,
                host_settings,
                ListenHttpEndpointType::Https1,
            )
            .await?;

            println!(
                "Merging Https1 configuration {}",
                http_endpoint_info.as_str()
            );

            let config = super::merge_http_into_existing(existing, http_endpoint_info)?;

            Ok(ListenConfiguration::Http(Arc::new(config)))
        }

        EndpointTypeSettings::Https2 => {
            let http_endpoint_info = crate::scripts::compile_http_configuration(
                settings_model,
                host_endpoint,
                host_settings,
                ListenHttpEndpointType::Https2,
            )
            .await?;

            let config = super::merge_http_into_existing(existing, http_endpoint_info)?;

            Ok(ListenConfiguration::Http(config.into()))
        }
        EndpointTypeSettings::Tcp => {
            // A 'type: tcp' endpoint is a raw byte bridge - it never performs a TLS handshake of
            // its own, so a client certificate can not be requested or verified here. Refusing is
            // the same rule the http/http2 endpoints get in `compile_http_configuration`: an
            // endpoint the operator believes is mTLS-protected must never quietly serve everyone.
            if host_settings.endpoint.client_certificate_ca.is_some() {
                return Err(format!(
                    "Endpoint '{}' is 'type: tcp', a raw byte bridge with no TLS layer of its own, \
                     so 'client_certificate_ca' can not be applied to it - the endpoint would pass \
                     every client through unverified. Use 'type: https' / 'type: https2', or \
                     remove 'client_certificate_ca'",
                    host_endpoint.as_str()
                ));
            }

            let tcp_configuration =
                TcpEndpointHostConfig::new(settings_model, host_endpoint, host_settings).await?;

            Ok(ListenConfiguration::Tcp(tcp_configuration.into()))
        }

        EndpointTypeSettings::Mcp => {
            let http_endpoint_info = crate::scripts::compile_http_configuration(
                settings_model,
                host_endpoint,
                host_settings,
                ListenHttpEndpointType::Mcp,
            )
            .await?;

            println!("Merging MCP configuration {}", http_endpoint_info.as_str());
            let config = super::merge_http_into_existing(existing, http_endpoint_info)?;

            Ok(ListenConfiguration::Mcp(config.into()))
        }
    }
}

/// A settings file which names a unix socket on a platform without them: the endpoint is refused
/// with the reason, as any other endpoint which does not compile, and nothing panics.
#[cfg(all(test, not(unix)))]
mod tests {
    use super::*;
    use crate::consts::UNIX_SOCKETS_NOT_SUPPORTED;

    async fn compile(host: &str, yaml: &str) -> Result<(), String> {
        let host_settings: HostSettings = my_settings_reader::serde_yaml::from_str(yaml).unwrap();

        compile_host_configuration(
            &SettingsCompiled::default(),
            EndpointHttpHostString::new(host.to_string()).unwrap(),
            &host_settings,
            None,
        )
        .await
        .map(|_| ())
    }

    /// An `http2` endpoint with one location: `location` holds its lines after `- `.
    async fn compile_location(location: &str) -> Result<(), String> {
        compile(
            "localhost:8000",
            &format!("endpoint:\n  type: http2\nlocations:\n- {location}\n"),
        )
        .await
    }

    /// A `tcp` endpoint to `proxy_pass_to`.
    async fn compile_tcp(proxy_pass_to: &str) -> Result<(), String> {
        compile(
            "7000",
            &format!("endpoint:\n  type: tcp\nlocations:\n- proxy_pass_to: '{proxy_pass_to}'\n"),
        )
        .await
    }

    fn assert_refused(result: Result<(), String>, what: &str) {
        let err = result.expect_err(what);
        assert!(err.contains(UNIX_SOCKETS_NOT_SUPPORTED), "{what}: {err}");
    }

    #[tokio::test]
    async fn an_endpoint_on_a_unix_socket_is_refused() {
        for host in ["/var/run/proxy.sock", "~/proxy.sock"] {
            let result = compile(
                host,
                "endpoint:\n  type: http\nlocations:\n- proxy_pass_to: http://127.0.0.1:9000\n",
            )
            .await;

            assert_refused(result.clone(), host);
            assert!(result.unwrap_err().contains(host), "{host}");
        }
    }

    #[tokio::test]
    async fn a_unix_socket_upstream_is_refused() {
        for location in [
            // `type: unix+http` and `type: unix+http2`, written or read from `proxy_pass_to`.
            "type: unix+http\n  proxy_pass_to: /var/run/app.sock",
            "type: unix+http2\n  proxy_pass_to: /var/run/app.sock",
            "proxy_pass_to: 'unix+http:///var/run/app.sock'",
            // A unix socket URL under a location of another type.
            "proxy_pass_to: 'http+unix:///var/run/app.sock'",
            "type: http\n  proxy_pass_to: 'unix+http:///var/run/app.sock'",
            "type: http2\n  proxy_pass_to: 'unix:///var/run/app.sock'",
            "type: mcp\n  proxy_pass_to: 'unix+http:///var/run/app.sock'",
            "type: mcp-h2\n  proxy_pass_to: 'http+unix:///var/run/app.sock'",
        ] {
            assert_refused(compile_location(location).await, location);
        }
    }

    /// The far side of a gateway is the one which connects to the socket - refused all the same.
    #[tokio::test]
    async fn a_unix_socket_behind_a_gateway_is_refused() {
        for location in [
            "proxy_pass_to: 'gateway:gw->unix+http:///var/run/app.sock'",
            "type: unix+http2\n  proxy_pass_to: 'gateway:gw->/var/run/app.sock'",
            "type: http\n  proxy_pass_to: 'gateway:gw->unix+http:///var/run/app.sock'",
            "type: http2\n  proxy_pass_to: 'gateway:gw->/var/run/app.sock'",
        ] {
            assert_refused(compile_location(location).await, location);
        }
    }

    #[tokio::test]
    async fn a_tcp_endpoint_to_a_unix_socket_is_refused() {
        for proxy_pass_to in [
            "gateway:gw->/var/run/app.sock",
            "gateway:gw->unix:///var/run/app.sock",
            "unix:///var/run/app.sock",
        ] {
            assert_refused(compile_tcp(proxy_pass_to).await, proxy_pass_to);
        }
    }

    #[tokio::test]
    async fn an_upstream_which_is_not_a_unix_socket_compiles() {
        for location in [
            "proxy_pass_to: http://127.0.0.1:9000",
            "type: http2\n  proxy_pass_to: http://127.0.0.1:9000",
            "proxy_pass_to: 'gateway:gw->http://127.0.0.1:9000'",
        ] {
            compile_location(location)
                .await
                .unwrap_or_else(|err| panic!("{location}: {err}"));
        }

        compile_tcp("127.0.0.1:9000").await.unwrap();
        compile_tcp("gateway:gw->127.0.0.1:9000").await.unwrap();
    }
}

use std::sync::Arc;

use crate::{settings::HostSettings, settings_compiled::SettingsCompiled};

use super::*;

pub struct TcpEndpointHostConfig {
    pub host_endpoint: EndpointHttpHostString,
    pub remote_host: Arc<MyReverseProxyRemoteEndpoint>,
    pub debug: bool,
    pub ip_white_list_id: Option<String>,
    /// `whitelisted_ip` of the location - a tcp endpoint has one. A connection has to be in
    /// this list as well as in the list of the endpoint.
    pub location_ip_white_list_id: Option<String>,
    /// Transport read/write idle timeouts (resolved cascade: global → endpoint).
    pub timeouts: crate::types::HttpTimeouts,
    /// `Some`: the endpoint was given an access setting it can not apply, and serves nobody.
    pub not_served_reason: Option<NotServedReason>,
}

impl TcpEndpointHostConfig {
    pub async fn new(
        settings_model: &SettingsCompiled,
        host_endpoint: EndpointHttpHostString,
        host_settings: &HostSettings,
    ) -> Result<Self, String> {
        let Some(location_settings) = host_settings.locations.first() else {
            return Err(format!(
                "No location found for tcp host {}",
                host_endpoint.as_str()
            ));
        };

        let Some(remote_host) = location_settings.proxy_pass_to.as_ref() else {
            return Err("proxy_pass_to is required for tcp location type".to_string());
        };

        // Only the first location is served, and the setting is wrong on any of them: every
        // location is looked at.
        if let Some(location) = host_settings
            .locations
            .iter()
            .find(|location| location.get_strip_path())
        {
            return Err(format!(
                "Endpoint '{}' is 'type: tcp', a forward of bytes with no HTTP layer, so \
                 'strip_path' of its location '{}' has no meaning - there is no request path to \
                 cut. Remove 'strip_path'",
                host_endpoint.as_str(),
                location.path.as_deref().unwrap_or("/")
            ));
        }

        let ip_white_list_id =
            crate::scripts::get_endpoint_white_listed_ip(settings_model, host_settings).await?;

        // The list the location names is loaded the same way as the one of the endpoint, and
        // has to be declared just the same.
        let location_ip_white_list_id = match location_settings.whitelisted_ip.as_ref() {
            Some(ip_list_id) => {
                crate::scripts::refresh_ip_list_from_settings(settings_model, ip_list_id).await?;
                Some(ip_list_id.to_string())
            }
            None => None,
        };

        let not_served_reason = access_settings_a_tcp_endpoint_can_not_apply(
            settings_model,
            &host_endpoint,
            host_settings,
        )?;

        let remote_host =
            MyReverseProxyRemoteEndpoint::try_parse(remote_host.as_str(), settings_model).await?;

        // Through a gateway it is the far side which connects to the socket, and it is refused
        // all the same: a settings file which names a unix socket does not load here.
        #[cfg(not(unix))]
        if remote_host.is_unix_socket() {
            return Err(format!(
                "Endpoint '{}': proxy_pass_to '{}' is a unix socket: {}",
                host_endpoint.as_str(),
                location_settings
                    .proxy_pass_to
                    .as_deref()
                    .unwrap_or_default(),
                crate::consts::UNIX_SOCKETS_NOT_SUPPORTED
            ));
        }

        // Transport timeout cascade for this tcp endpoint: global → endpoint.
        let resolved = settings_model
            .get_global_timeouts()
            .overriden_by(&host_settings.endpoint.timeouts)
            .resolve();
        let timeouts = crate::types::HttpTimeouts {
            read_timeout: resolved.read_timeout,
            write_timeout: resolved.write_timeout,
        };

        let result = Self {
            host_endpoint,
            remote_host: remote_host.into(),
            debug: host_settings.endpoint.get_debug(),
            ip_white_list_id,
            location_ip_white_list_id,
            timeouts,
            not_served_reason,
        };

        Ok(result)
    }
}

/// A tcp endpoint forwards bytes: there is no request in which it could look for a header or
/// a session. `auth_header`, `google_auth` and `allowed_users` load, and the endpoint serves
/// nobody: see [`NotServedReason`]. Its `whitelisted_ip` - of the endpoint and of the location
/// - it checks by the address of the connection.
fn access_settings_a_tcp_endpoint_can_not_apply(
    settings_model: &SettingsCompiled,
    host_endpoint: &EndpointHttpHostString,
    host_settings: &HostSettings,
) -> Result<Option<NotServedReason>, String> {
    let mut settings = Vec::new();

    if host_settings
        .locations
        .iter()
        .any(|location| location.auth_header.is_some())
    {
        settings.push("auth_header");
    }

    let google_auth = crate::scripts::get_from_host_or_templates(
        settings_model,
        host_settings,
        |host_settings| host_settings.endpoint.google_auth.as_ref(),
        |templates| templates.google_auth.as_ref(),
    )?;

    if google_auth.is_some() {
        settings.push("google_auth");
    }

    if host_settings.endpoint.allowed_users.is_some() {
        settings.push("allowed_users");
    }

    Ok(NotServedReason::new(
        host_endpoint.as_str(),
        "tcp",
        &settings,
        "a forward of bytes with no HTTP layer",
        "remove the setting, or use an http type of endpoint",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `locations`: the `locations:` list as a settings file writes it.
    async fn compile(locations: &str) -> Result<TcpEndpointHostConfig, String> {
        let host_settings: HostSettings = my_settings_reader::serde_yaml::from_str(&format!(
            "endpoint:\n  type: tcp\nlocations:\n{locations}"
        ))
        .unwrap();

        TcpEndpointHostConfig::new(
            &SettingsCompiled::default(),
            EndpointHttpHostString::new("8000".to_string()).unwrap(),
            &host_settings,
        )
        .await
    }

    #[tokio::test]
    async fn strip_path_on_any_location_of_a_tcp_endpoint_is_refused() {
        for locations in [
            "- proxy_pass_to: 127.0.0.1:9000\n  strip_path: true\n",
            // Only the first location is served: the second one is looked at all the same.
            "- proxy_pass_to: 127.0.0.1:9000\n- path: /x/\n  proxy_pass_to: 127.0.0.1:9001\n  strip_path: true\n",
        ] {
            let Err(err) = compile(locations).await else {
                panic!("{locations}: strip_path is accepted");
            };

            assert!(
                err.contains("'type: tcp'") && err.contains("'strip_path'"),
                "{locations}: {err}"
            );
        }

        compile("- proxy_pass_to: 127.0.0.1:9000\n").await.unwrap();
        compile("- proxy_pass_to: 127.0.0.1:9000\n  strip_path: false\n")
            .await
            .unwrap();
    }
}

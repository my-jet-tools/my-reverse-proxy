use crate::{
    configurations::{EndpointHttpHostString, EndpointPort, ListenConfiguration},
    settings_compiled::SettingsCompiled,
};

pub async fn reload_tcp_port_configurations(port_to_refresh: u16) -> Result<String, String> {
    let _apply_lock = crate::app::APP_CTX.settings_apply_lock.lock().await;

    let settings_model = SettingsCompiled::load_settings().await?;

    let compiled = compile_port(&settings_model, |endpoint_host| {
        matches!(endpoint_host.get_port(), EndpointPort::Tcp(port) if port == port_to_refresh)
    })
    .await?;

    let had_config = compiled.configuration.is_some();

    crate::app::APP_CTX
        .current_configuration
        .write(move |config| {
            config
                .error_configurations
                .remove(&port_to_refresh.to_string());

            compiled.apply_dynamic_host_errors(&mut config.error_configurations);

            match compiled.configuration {
                Some(cfg) => {
                    config.listen_tcp_endpoints.insert(port_to_refresh, cfg);
                }
                None => {
                    config.listen_tcp_endpoints.remove(&port_to_refresh);
                }
            }
        })
        .await;

    crate::scripts::sync_endpoints().await;

    if had_config {
        Ok(format!("Updated TCP port {}", port_to_refresh))
    } else {
        Ok(format!("Removed TCP port {}", port_to_refresh))
    }
}

pub async fn reload_unix_configurations(host_to_refresh: &String) -> Result<String, String> {
    let _apply_lock = crate::app::APP_CTX.settings_apply_lock.lock().await;

    let settings_model = SettingsCompiled::load_settings().await?;

    let compiled = compile_port(&settings_model, |endpoint_host| {
        endpoint_host.is_unix_socket() && endpoint_host.as_str() == host_to_refresh.as_str()
    })
    .await?;

    let had_config = compiled.configuration.is_some();
    let unix_path = std::sync::Arc::new(host_to_refresh.clone());
    let host_to_refresh_clone = host_to_refresh.clone();

    crate::app::APP_CTX
        .current_configuration
        .write(move |config| {
            config
                .error_configurations
                .remove(host_to_refresh_clone.as_str());

            compiled.apply_dynamic_host_errors(&mut config.error_configurations);

            match compiled.configuration {
                Some(cfg) => {
                    config
                        .listen_unix_socket_endpoints
                        .insert(unix_path.clone(), cfg);
                }
                None => {
                    config.listen_unix_socket_endpoints.remove(&unix_path);
                }
            }
        })
        .await;

    crate::scripts::sync_endpoints().await;

    if had_config {
        Ok(format!("Updated Unix socket {}", host_to_refresh))
    } else {
        Ok(format!("Removed Unix socket {}", host_to_refresh))
    }
}

/// One port, compiled again from the settings.
struct CompiledPort {
    configuration: Option<ListenConfiguration>,
    /// The dynamic hosts of the port, the ones which are served as well.
    dynamic_host_ids: Vec<String>,
    /// The dynamic hosts of the port which are not served, and why.
    dynamic_host_errors: Vec<(String, String)>,
}

impl CompiledPort {
    /// The errors of the dynamic hosts of the port are the ones found now.
    fn apply_dynamic_host_errors(
        &self,
        error_configurations: &mut std::collections::BTreeMap<String, String>,
    ) {
        for host_id in &self.dynamic_host_ids {
            error_configurations.remove(host_id);
        }

        for (host_id, err) in &self.dynamic_host_errors {
            error_configurations.insert(host_id.clone(), err.clone());
        }
    }
}

/// The hosts of the settings on one port, compiled one next to the other: those of the files
/// first, then the dynamic ones. A host of the files which does not compile fails the reload,
/// as it always has; a dynamic one is left out with its error - what the url gives can not keep
/// the hosts of the files from being reloaded.
async fn compile_port(
    settings_model: &SettingsCompiled,
    is_on_port: impl Fn(&EndpointHttpHostString) -> bool,
) -> Result<CompiledPort, String> {
    let mut result = CompiledPort {
        configuration: None,
        dynamic_host_ids: Vec::new(),
        dynamic_host_errors: Vec::new(),
    };

    for (host_id, host_settings) in settings_model.hosts_in_apply_order() {
        let dynamic_host = settings_model.is_dynamic_host(host_id);

        let endpoint_host = match settings_model.get_endpoint_host_string(host_id) {
            Ok(endpoint_host) => endpoint_host,
            // Its port is not known: it is not on this one.
            Err(_) if dynamic_host => continue,
            Err(err) => return Err(err),
        };

        if !is_on_port(&endpoint_host) {
            continue;
        }

        if dynamic_host {
            result.dynamic_host_ids.push(host_id.clone());

            if let Some(existing) = result.configuration.as_ref() {
                if let Err(err) =
                    super::check_dynamic_host_fits(existing, &endpoint_host, host_settings)
                {
                    result.dynamic_host_errors.push((host_id.clone(), err));
                    continue;
                }
            }
        }

        let compiled = crate::scripts::compile_host_configuration(
            settings_model,
            endpoint_host,
            host_settings,
            result.configuration.clone(),
        )
        .await;

        match compiled {
            Ok(compiled) => result.configuration = Some(compiled),
            Err(err) if dynamic_host => result.dynamic_host_errors.push((host_id.clone(), err)),
            Err(err) => return Err(err),
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts(yaml: &str) -> std::collections::HashMap<String, crate::settings::HostSettings> {
        crate::settings::DynamicHostsModel::parse(yaml.as_bytes())
            .unwrap()
            .unwrap()
            .hosts
    }

    /// A reload of a port is never kept from the hosts of the files by what the url gives: a
    /// dynamic host which does not compile, or would take the port, is left out with its error.
    #[tokio::test]
    async fn a_dynamic_host_which_can_not_be_served_does_not_fail_the_reload_of_its_port() {
        let mut settings = SettingsCompiled {
            hosts: hosts(
                "hosts:\n  files.localhost:7100:\n    endpoint:\n      type: http\n    locations:\n    - proxy_pass_to: http://127.0.0.1:9000\n",
            ),
            ..Default::default()
        };
        settings.set_dynamic_hosts(&hosts(concat!(
            "hosts:\n",
            "  bad.localhost:7100:\n    endpoint:\n      type: no-such-type\n    locations:\n    - proxy_pass_to: http://127.0.0.1:9000\n",
            "  tcp.localhost:7100:\n    endpoint:\n      type: tcp\n    locations:\n    - proxy_pass_to: 127.0.0.1:9000\n",
            "  good.localhost:7100:\n    endpoint:\n      type: http\n    locations:\n    - proxy_pass_to: http://127.0.0.1:9001\n",
            "  other.localhost:7101:\n    endpoint:\n      type: http\n    locations:\n    - proxy_pass_to: http://127.0.0.1:9001\n",
        )));

        let compiled = compile_port(&settings, |endpoint_host| {
            matches!(endpoint_host.get_port(), EndpointPort::Tcp(7100))
        })
        .await
        .unwrap();

        let Some(ListenConfiguration::Http(configuration)) = compiled.configuration.as_ref() else {
            panic!("port 7100 is not an http port");
        };
        let mut served: Vec<_> = configuration
            .endpoints
            .iter()
            .map(|itm| (itm.as_str().to_string(), itm.dynamic_host))
            .collect();
        served.sort();
        assert_eq!(
            served,
            [
                ("files.localhost:7100".to_string(), false),
                ("good.localhost:7100".to_string(), true)
            ]
        );

        let mut refused: Vec<_> = compiled
            .dynamic_host_errors
            .iter()
            .map(|(host_id, _)| host_id.as_str())
            .collect();
        refused.sort();
        assert_eq!(refused, ["bad.localhost:7100", "tcp.localhost:7100"]);

        // The errors of the port's dynamic hosts are the ones found now.
        let mut error_configurations = std::collections::BTreeMap::new();
        error_configurations.insert("good.localhost:7100".to_string(), "before".to_string());
        error_configurations.insert("files.localhost:7100".to_string(), "kept".to_string());
        compiled.apply_dynamic_host_errors(&mut error_configurations);

        assert!(!error_configurations.contains_key("good.localhost:7100"));
        assert!(error_configurations.contains_key("bad.localhost:7100"));
        assert!(error_configurations.contains_key("tcp.localhost:7100"));
        assert_eq!(error_configurations["files.localhost:7100"], "kept");
    }

    /// A host of the files which does not compile fails the reload of its port, as before.
    #[tokio::test]
    async fn a_host_of_the_files_which_does_not_compile_fails_the_reload() {
        let settings = SettingsCompiled {
            hosts: hosts(
                "hosts:\n  files.localhost:7102:\n    endpoint:\n      type: no-such-type\n    locations:\n    - proxy_pass_to: http://127.0.0.1:9000\n",
            ),
            ..Default::default()
        };

        let result = compile_port(&settings, |endpoint_host| {
            matches!(endpoint_host.get_port(), EndpointPort::Tcp(7102))
        })
        .await;

        assert!(result.is_err());
    }
}

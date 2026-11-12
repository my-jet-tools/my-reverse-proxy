use std::{collections::BTreeSet, sync::Arc};

use crate::{app::APP_CTX, configurations::EndpointPort, settings_compiled::SettingsCompiled};

use super::put_together_port::*;

pub async fn reload_tcp_port_configurations(port_to_refresh: u16) -> Result<String, String> {
    if reload_port(EndpointPort::Tcp(port_to_refresh)).await? {
        Ok(format!("Updated TCP port {}", port_to_refresh))
    } else {
        Ok(format!("Removed TCP port {}", port_to_refresh))
    }
}

pub async fn reload_unix_configurations(host_to_refresh: &String) -> Result<String, String> {
    let port = EndpointPort::UnixSocket(Arc::new(host_to_refresh.clone()));

    if reload_port(port).await? {
        Ok(format!("Updated Unix socket {}", host_to_refresh))
    } else {
        Ok(format!("Removed Unix socket {}", host_to_refresh))
    }
}

/// Puts one port together anew from the settings files: the hosts of the files on it - the ones
/// it had and the ones it has now - are reloaded, with their names; the dynamic hosts and names
/// on it are put next to them. The settings applied are updated with what is reloaded, and the
/// hosts of `dynamic_hosts.url` are put next to them anew.
///
/// A host of the files which does not compile fails the reload, as it always has; a dynamic one
/// is left out with its error - what the url gives can not keep the hosts of the files from
/// being reloaded. Returns whether the port is served.
async fn reload_port(port: EndpointPort) -> Result<bool, String> {
    let _apply_lock = APP_CTX.settings_apply_lock.lock().await;

    let fresh = SettingsCompiled::load_settings().await?;
    let applied = APP_CTX.applied_settings.load_full();

    let is_on_port = |host_id: &str| port_of(host_id).as_ref() == Some(&port);

    let hosts_of_files_on_port = |settings: &SettingsCompiled| -> BTreeSet<String> {
        settings
            .hosts
            .keys()
            .filter(|host_id| !settings.is_dynamic_host(host_id) && is_on_port(host_id))
            .cloned()
            .collect()
    };

    let mut host_ids = hosts_of_files_on_port(&fresh);
    if let Some(applied) = applied.as_ref() {
        host_ids.extend(hosts_of_files_on_port(applied));
    }

    let (after, host_ids) =
        super::settings_with_reloaded_hosts(applied.as_deref(), &fresh, host_ids);

    let mut errors = FoundErrors::default();

    // Everything the port had and has is looked at anew.
    for settings in [Some(&after), applied.as_deref()].into_iter().flatten() {
        for host_id in settings.hosts.keys().filter(|host_id| is_on_port(host_id)) {
            errors.look_at_host(settings, host_id);
        }

        for (name, itm) in &settings.additional_hosts {
            if itm.dynamic && is_on_port(name) {
                errors.look_at_dynamic(name);
            }
        }
    }

    for host_id in &host_ids {
        errors.add_ignored_entries(&after, host_id);
    }

    let host_ids_here: Vec<&String> = after
        .hosts_in_apply_order()
        .into_iter()
        .map(|(host_id, _)| host_id)
        .filter(|host_id| is_on_port(host_id))
        .collect();

    let configuration = compile_port(&after, &host_ids_here, &mut errors).await?;

    let names: Vec<_> = after
        .additional_hosts_in_apply_order()
        .into_iter()
        .filter(|(name, _)| is_on_port(name))
        .collect();

    let configuration = put_names(configuration, &names, &mut errors);
    let served = configuration.is_some();

    publish_ports(
        vec![(port, configuration)],
        errors,
        after.get_static_host_ids_lowercase(),
    )
    .await;

    // The hosts of the url, against the hosts of the files as they are now.
    if let Some(applied) = applied.as_ref() {
        super::apply_dynamic_hosts_change(applied, &after).await;
    }

    APP_CTX.applied_settings.store(Some(Arc::new(after)));

    crate::scripts::sync_endpoints().await;

    Ok(served)
}

/// The hosts of one port, compiled one next to the other: those of the files first, then the
/// dynamic ones. A host of the files which does not compile fails the reload, as it always has;
/// a dynamic one is left out with its error.
async fn compile_port(
    settings_model: &SettingsCompiled,
    host_ids: &[&String],
    errors: &mut FoundErrors,
) -> Result<Option<crate::configurations::ListenConfiguration>, String> {
    put_hosts(settings_model, None, host_ids, true, errors).await
}

#[cfg(test)]
mod tests {
    use crate::configurations::{ListenConfiguration, ListenHttpEndpointType};

    use super::*;

    fn hosts(yaml: &str) -> std::collections::HashMap<String, crate::settings::HostSettings> {
        crate::settings::DynamicHostsModel::parse(yaml.as_bytes())
            .unwrap()
            .unwrap()
            .hosts
    }

    fn on_port(settings: &SettingsCompiled, port: u16) -> Vec<&String> {
        settings
            .hosts_in_apply_order()
            .into_iter()
            .map(|(host_id, _)| host_id)
            .filter(|host_id| port_of(host_id) == Some(EndpointPort::Tcp(port)))
            .collect()
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

        let mut errors = FoundErrors::default();
        let compiled = compile_port(&settings, &on_port(&settings, 7100), &mut errors)
            .await
            .unwrap();

        let Some(ListenConfiguration::Http(configuration)) = compiled.as_ref() else {
            panic!("port 7100 is not an http port");
        };
        assert!(matches!(
            configuration.listen_endpoint_type,
            ListenHttpEndpointType::Http1
        ));

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

        let mut refused: Vec<_> = errors
            .describe()
            .into_iter()
            .map(|itm| itm.split(':').next().unwrap().to_string())
            .collect();
        refused.sort();
        assert_eq!(refused, ["bad.localhost", "tcp.localhost"]);

        // The errors of the port's dynamic hosts are the ones found now.
        let mut error_configurations = std::collections::BTreeMap::new();
        error_configurations.insert("good.localhost:7100".to_string(), "before".to_string());
        error_configurations.insert("files.localhost:7100".to_string(), "kept".to_string());
        errors.look_at_dynamic("good.localhost:7100");
        errors.apply(
            &mut error_configurations,
            &settings.get_static_host_ids_lowercase(),
        );

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

        let result = compile_port(
            &settings,
            &on_port(&settings, 7102),
            &mut FoundErrors::default(),
        )
        .await;

        assert!(result.is_err());
    }
}

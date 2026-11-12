use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use crate::{
    configurations::{EndpointPort, ListenConfiguration},
    settings_compiled::SettingsCompiled,
};

use super::put_together_port::*;

pub async fn load_everything_from_settings() -> Result<(), String> {
    let apply_lock = crate::app::APP_CTX.settings_apply_lock.lock().await;

    let settings_model = SettingsCompiled::load_settings().await?;

    crate::scripts::update_ssh_config_list(&settings_model).await;

    crate::app::APP_CTX
        .debug_ip
        .set(settings_model.get_debug_ip());

    // Build the full new configuration into local maps first, then swap it into the live
    // configuration in a single write. This way endpoints that disappeared from the settings are
    // simply absent from the new maps (instead of lingering, as an in-place merge would leave them),
    // and `sync_endpoints` below tears down their listeners. The live config keeps serving the old
    // configuration untouched until the atomic swap, so there is no window of missing routes.
    let mut listen_tcp_endpoints: HashMap<u16, ListenConfiguration> = HashMap::new();
    let mut listen_unix_socket_endpoints: HashMap<Arc<String>, ListenConfiguration> =
        HashMap::new();

    let mut errors = FoundErrors::default();

    for (host_id, err) in &settings_model.dynamic_host_errors {
        errors.add_dynamic(host_id, err.clone());
    }

    for host_id in settings_model.additional_host_errors.keys() {
        errors.add_ignored_entries(&settings_model, host_id);
    }

    let hosts_by_port = hosts_by_port(&settings_model, |_| true, &mut errors);
    let mut names_by_port = names_by_port(&settings_model, |_, _| true);

    let mut ports: Vec<(EndpointPort, Vec<&String>)> = hosts_by_port.into_iter().collect();
    // A name whose port has no host: its host is not served there - it is told about.
    for port in names_by_port.keys() {
        if !ports.iter().any(|(itm, _)| itm == port) {
            ports.push((port.clone(), Vec::new()));
        }
    }

    for (port, host_ids) in ports {
        // Not strict: a host which does not compile is left out with its error, and the rest
        // are served.
        let configuration = put_hosts(&settings_model, None, &host_ids, false, &mut errors).await?;
        let names = names_by_port.remove(&port).unwrap_or_default();
        let configuration = put_names(configuration, &names, &mut errors);

        let Some(configuration) = configuration else {
            continue;
        };

        match port {
            EndpointPort::Tcp(port) => {
                listen_tcp_endpoints.insert(port, configuration);
            }
            EndpointPort::UnixSocket(unix_host) => {
                listen_unix_socket_endpoints.insert(unix_host, configuration);
            }
        }
    }

    errors.print();

    println!("Applying new configuration (atomic swap)");

    let static_host_ids = settings_model.get_static_host_ids_lowercase();

    crate::app::APP_CTX
        .current_configuration
        .write(move |config| {
            config.listen_tcp_endpoints = listen_tcp_endpoints;
            config.listen_unix_socket_endpoints = listen_unix_socket_endpoints;

            let mut error_configurations = BTreeMap::new();
            errors.apply(&mut error_configurations, &static_host_ids);
            config.error_configurations = error_configurations;
        })
        .await;

    println!("Kicking off tcp endpoints");

    crate::scripts::sync_endpoints().await;

    // Keep a copy of what we just applied so it can be read back (e.g. via MCP)
    // without recompiling the files — and compared against a fresh compile.
    crate::app::APP_CTX
        .applied_settings
        .store(Some(Arc::new(settings_model)));

    drop(apply_lock);

    // The settings may name another url, or one they did not name before: it is read now
    // rather than when the interval of the one before is out.
    crate::app::APP_CTX.dynamic_hosts.request_refresh();

    Ok(())
}

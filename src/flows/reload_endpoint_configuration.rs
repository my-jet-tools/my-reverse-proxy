use std::{collections::BTreeSet, sync::Arc};

use crate::{app::APP_CTX, configurations::EndpointPort, settings_compiled::SettingsCompiled};

use super::put_together_port::*;

/// Reloads one host from the settings files - whichever of its names is given: the host and the
/// names of its `additional_hosts` are one configuration. A name which moved to another host,
/// or became a host of its own, takes that host along.
///
/// The settings applied are updated with what is reloaded, and the hosts of `dynamic_hosts.url`
/// are put next to them anew: a later read of the url is checked against the hosts as they are
/// served, not as the last full reload left them.
///
/// A host of the files which does not compile fails the reload, and nothing is changed.
pub async fn reload_endpoint_configuration(host_id_to_refresh: &str) -> Result<String, String> {
    let _apply_lock = APP_CTX.settings_apply_lock.lock().await;

    let fresh = SettingsCompiled::load_settings().await?;
    let applied = APP_CTX.applied_settings.load_full();

    // The host it names now, and the one it named before.
    let mut host_ids = BTreeSet::new();
    host_ids.extend(fresh.get_main_host_id(host_id_to_refresh));
    if let Some(applied) = applied.as_ref() {
        host_ids.extend(applied.get_main_host_id(host_id_to_refresh));
    }

    if host_ids.is_empty() {
        return Err(format!(
            "Host configuration {} not found",
            host_id_to_refresh
        ));
    }

    let (after, host_ids) = settings_with_reloaded_hosts(applied.as_deref(), &fresh, host_ids);

    let not_served = apply_reloaded_hosts(applied.as_deref(), &after, &host_ids).await?;

    APP_CTX.applied_settings.store(Some(Arc::new(after)));

    crate::scripts::sync_endpoints().await;

    if not_served.is_empty() {
        Ok(format!(
            "Host configuration {} has been reloaded",
            host_id_to_refresh
        ))
    } else {
        Ok(format!(
            "Host configuration {} has been reloaded. Not served: {}",
            host_id_to_refresh,
            not_served.join("; ")
        ))
    }
}

/// Puts the hosts `host_ids` of `after` - the settings `applied` with them reloaded - into the
/// live configuration in place of what they served, with their names; then the hosts of
/// `dynamic_hosts.url` against them. Returns what is not served of theirs, as `id: error`.
///
/// A host of the files which does not compile fails it before anything is written: what is
/// served stays as it is.
pub async fn apply_reloaded_hosts(
    applied: Option<&SettingsCompiled>,
    after: &SettingsCompiled,
    host_ids: &BTreeSet<String>,
) -> Result<Vec<String>, String> {
    let mut errors = FoundErrors::default();

    let mut ports: Vec<EndpointPort> = Vec::new();
    for host_id in host_ids {
        if let Some(port) = port_of(host_id) {
            if !ports.contains(&port) {
                ports.push(port);
            }
        }

        errors.look_at_host(after, host_id);
        errors.add_ignored_entries(after, host_id);

        // Their names, before and now: one of the url is told about under its own id.
        for settings in [Some(after), applied].into_iter().flatten() {
            for (name, itm) in settings.get_additional_hosts_of(host_id) {
                if itm.dynamic {
                    errors.look_at_dynamic(name);
                }
            }
        }
    }

    let is_reloaded = |host_id: &str| host_ids.contains(host_id);

    let mut new_ports = Vec::with_capacity(ports.len());

    for port in ports {
        let live = get_live_configuration(&port).await;

        // The endpoints of the hosts reloaded go, and so do the ones of their names.
        let configuration = without_endpoints(
            live,
            |endpoint| {
                is_reloaded(endpoint.as_str())
                    || endpoint
                        .additional_host_of
                        .as_deref()
                        .is_some_and(is_reloaded)
            },
            |tcp| is_reloaded(tcp.host_endpoint.as_str()),
        );

        let host_ids_here: Vec<&String> = after
            .hosts_in_apply_order()
            .into_iter()
            .map(|(host_id, _)| host_id)
            .filter(|host_id| is_reloaded(host_id) && port_of(host_id).as_ref() == Some(&port))
            .collect();

        // Strict: a host of the files which does not compile fails the reload before anything
        // is written.
        let configuration =
            put_hosts(after, configuration, &host_ids_here, true, &mut errors).await?;

        let names: Vec<_> = after
            .additional_hosts_in_apply_order()
            .into_iter()
            .filter(|(name, itm)| {
                is_reloaded(&itm.host_id) && port_of(name).as_ref() == Some(&port)
            })
            .collect();

        let configuration = put_names(configuration, &names, &mut errors);

        new_ports.push((port, configuration));
    }

    let not_served = errors.describe();

    publish_ports(new_ports, errors, after.get_static_host_ids_lowercase()).await;

    // The hosts of the url, against the hosts of the files as they are now.
    if let Some(applied) = applied {
        super::apply_dynamic_hosts_change(applied, after).await;
    }

    Ok(not_served)
}

/// The settings applied - `None` before the first reload of the settings - with the hosts of
/// the files `host_ids`, and the ones they take along, as `fresh` has them; and the hosts of
/// `dynamic_hosts.url` put next to them anew. Also returns the hosts reloaded.
pub fn settings_with_reloaded_hosts(
    applied: Option<&SettingsCompiled>,
    fresh: &SettingsCompiled,
    host_ids: BTreeSet<String>,
) -> (SettingsCompiled, BTreeSet<String>) {
    let Some(applied) = applied else {
        return (fresh.clone(), host_ids);
    };

    let host_ids = applied.get_hosts_of_files_reloaded_with(fresh, host_ids);

    let answer = applied
        .dynamic_hosts
        .as_ref()
        .and_then(|dynamic_hosts| APP_CTX.dynamic_hosts.get_answer(&dynamic_hosts.url));

    let after = applied.with_hosts_of_files_from(fresh, &host_ids, answer.as_deref());

    (after, host_ids)
}

use std::{collections::HashSet, sync::Arc, time::Duration};

use flurl::FlUrl;

use crate::{
    app::APP_CTX,
    configurations::{EndpointHttpHostString, EndpointPort, ListenConfiguration},
    settings::{DynamicHostsModel, DynamicHostsSettings, EndpointTypeSettings, HostSettings},
    settings_compiled::{AdditionalHost, SettingsCompiled},
};

use super::put_together_port::*;

/// Reads `dynamic_hosts.url` and applies its hosts, if they are not the ones served already.
///
/// Returns how long to wait before the next read: `None` when the applied settings have no
/// `dynamic_hosts` - then the url is read again after a reload of the settings only.
///
/// A read which fails changes nothing: the hosts read before are served until a read succeeds.
/// Neither does a blank answer, which is not told about either: the url said nothing.
pub async fn refresh_dynamic_hosts() -> Option<Duration> {
    let applied = APP_CTX.applied_settings.load_full()?;

    let Some(settings) = applied.dynamic_hosts.clone() else {
        APP_CTX.dynamic_hosts.clear();
        return None;
    };

    match read_dynamic_hosts(&settings).await {
        Ok(answer) => {
            if APP_CTX.dynamic_hosts.clear_error() {
                println!("Dynamic hosts: {} is read again", settings.url);
            }

            let Some(answer) = answer else {
                return Some(settings.get_refresh_interval());
            };

            if !APP_CTX
                .dynamic_hosts
                .has_same_answer(settings.url.as_str(), &answer)
            {
                apply_dynamic_hosts(settings.url.as_str(), answer).await;
            }
        }
        Err(err) => {
            if APP_CTX.dynamic_hosts.set_error(err.clone()) {
                println!(
                    "Dynamic hosts: can not read {}: {}. The hosts read before are served.",
                    settings.url, err
                );
            }
        }
    }

    Some(settings.get_refresh_interval())
}

/// What `dynamic_hosts.url` answers with - `None` if it answers `2xx` with a blank body, which
/// says nothing. Any answer but `2xx` is a failure. Neither is ever no hosts: a url which is
/// restarted must not take every dynamic host away - no hosts are `hosts: {}`.
pub async fn read_dynamic_hosts(
    settings: &DynamicHostsSettings,
) -> Result<Option<DynamicHostsModel>, String> {
    let mut response = FlUrl::new(settings.url.as_str())
        .set_timeout(settings.get_request_timeout())
        .get()
        .await
        .map_err(|err| format!("the request failed: {err}"))?;

    let status_code = response.get_status_code();

    if !(200..300).contains(&status_code) {
        return Err(format!("answered with the status code {status_code}"));
    }

    let body = response
        .get_body()
        .map_err(|err| format!("the answer can not be read: {err}"))?
        .into_vec(crate::consts::MAX_DYNAMIC_HOSTS_RESPONSE_SIZE)
        .await
        .map_err(|err| format!("the answer can not be read: {err}"))?;

    DynamicHostsModel::parse(&body)
}

/// Serves the hosts of `answer`, read from `url`, in place of the dynamic hosts served before.
/// Nothing of the settings files is read again: the hosts of the files stay as the last reload
/// left them - and so does the configuration the additional hosts of the answer are served with.
async fn apply_dynamic_hosts(url: &str, answer: DynamicHostsModel) {
    let _apply_lock = APP_CTX.settings_apply_lock.lock().await;

    let Some(before) = APP_CTX.applied_settings.load_full() else {
        return;
    };

    // The settings were reloaded while the url was read, and name another url now: what was
    // read is not their hosts. The url they name is read next.
    if before.dynamic_hosts.as_ref().map(|itm| itm.url.as_str()) != Some(url) {
        return;
    }

    let mut after = before.as_ref().clone();
    after.set_dynamic_hosts_answer(&answer);

    println!(
        "Dynamic hosts: {} hosts and {} names are read from {}",
        after.dynamic_host_ids.len(),
        after
            .additional_hosts
            .values()
            .filter(|itm| itm.dynamic)
            .count(),
        url
    );

    APP_CTX
        .dynamic_hosts
        .set_answer(url.to_string(), Arc::new(answer));

    let listeners_changed = apply_dynamic_hosts_change(&before, &after).await;

    APP_CTX.applied_settings.store(Some(Arc::new(after)));

    if listeners_changed {
        crate::scripts::sync_endpoints().await;
    }
}

/// Puts the dynamic hosts of `after` into the live configuration in place of the ones of
/// `before`, and the names of the url in place of its names before.
///
/// Only the ports a dynamic host or a name came to, left, or changed on are touched. Each of
/// them keeps what it serves of the settings files - hosts and names, as the last reload put
/// them there - and every dynamic host which did not change: its very endpoint, and with it its
/// upstream connections. A dynamic host which changed is compiled anew; the names of the url are
/// put next to the endpoints of their hosts anew - nothing is compiled for them. A read which
/// changes only names changes only names. The ports are replaced in one write: a connection sees
/// either all of the change or none of it, and picks it up with the next request it reads
/// (`AppConfiguration::pick_up_reload`).
///
/// A dynamic host never takes the place of a host of the settings files: one which would is
/// refused, and so is one which does not compile; the others are served.
///
/// Returns `true` if a port is served now which was not before, or the other way round: its
/// listener is to be started or stopped.
pub async fn apply_dynamic_hosts_change(
    before: &SettingsCompiled,
    after: &SettingsCompiled,
) -> bool {
    // The dynamic hosts which are not what they were: come, gone, or with other settings.
    let mut changed_hosts: HashSet<&str> = HashSet::new();

    for host_id in &before.dynamic_host_ids {
        let same = after.dynamic_host_ids.contains(host_id)
            && crate::app::same_host(&before.hosts[host_id], &after.hosts[host_id]);

        if !same {
            changed_hosts.insert(host_id);
        }
    }

    for host_id in &after.dynamic_host_ids {
        if !before.dynamic_host_ids.contains(host_id) {
            changed_hosts.insert(host_id);
        }
    }

    // The names of the url which are not what they were - and the ones of a host which changed:
    // they are put next to its new endpoint.
    let mut changed_names: HashSet<&str> = HashSet::new();

    for (settings, other) in [(before, after), (after, before)] {
        for (name, itm) in settings
            .additional_hosts
            .iter()
            .filter(|(_, itm)| itm.dynamic)
        {
            if other.additional_hosts.get(name) != Some(itm)
                || changed_hosts.contains(itm.host_id.as_str())
            {
                changed_names.insert(name);
            }
        }
    }

    let mut errors = FoundErrors::default();

    let mut ports: Vec<EndpointPort> = Vec::new();
    for host_id in changed_hosts.iter().chain(changed_names.iter()) {
        errors.look_at_dynamic(host_id);

        // One whose id names no port is told about with the hosts of `after` below.
        if let Some(port) = port_of(host_id) {
            if !ports.contains(&port) {
                ports.push(port);
            }
        }
    }

    // The refusals of the read before are looked at anew: the ones of this read take their place.
    for host_id in before.dynamic_host_errors.keys() {
        errors.look_at_dynamic(host_id);
    }

    for (host_id, err) in &after.dynamic_host_errors {
        errors.add_dynamic(host_id, err.clone());
    }

    let is_dynamic_name = |_: &str, itm: &AdditionalHost| itm.dynamic;

    let hosts_by_port_after =
        hosts_by_port(after, |host_id| after.is_dynamic_host(host_id), &mut errors);
    let names_by_port_after = names_by_port(after, is_dynamic_name);

    // What the ports had of the url, the errors of which are looked at anew.
    let mut ignored = FoundErrors::default();
    let hosts_by_port_before = hosts_by_port(
        before,
        |host_id| before.is_dynamic_host(host_id),
        &mut ignored,
    );
    let names_by_port_before = names_by_port(before, is_dynamic_name);

    let mut new_ports: Vec<(EndpointPort, Option<ListenConfiguration>)> =
        Vec::with_capacity(ports.len());

    let mut listeners_changed = false;

    for port in ports {
        for host_id in hosts_by_port_before.get(&port).into_iter().flatten() {
            errors.look_at_dynamic(host_id);
        }
        for (name, _) in names_by_port_before.get(&port).into_iter().flatten() {
            errors.look_at_dynamic(name);
        }

        let live = get_live_configuration(&port).await;
        let was_served = live.is_some();

        let is_kept = |host_id: &str| {
            !changed_hosts.contains(host_id) && after.dynamic_host_ids.contains(host_id)
        };

        // What stays: what the port serves of the settings files, and each dynamic host which did
        // not change. The names of the url go: they are put anew below.
        let configuration = without_endpoints(
            live,
            |endpoint| {
                endpoint.dynamic_host
                    && (endpoint.additional_host_of.is_some() || !is_kept(endpoint.as_str()))
            },
            |tcp| tcp.dynamic_host && !is_kept(tcp.host_endpoint.as_str()),
        );

        let host_ids: Vec<&String> = hosts_by_port_after
            .get(&port)
            .into_iter()
            .flatten()
            .copied()
            .filter(|host_id| {
                errors.look_at_dynamic(host_id);
                // One which did not change and is served is kept as it is; one which was
                // refused is tried again.
                !is_kept(host_id) || !serves_host(&configuration, host_id)
            })
            .collect();

        let configuration =
            match put_hosts(after, configuration, &host_ids, false, &mut errors).await {
                Ok(configuration) => configuration,
                // Not strict: a dynamic host is left out with its error, it fails nothing.
                Err(err) => {
                    println!("Dynamic hosts: port {port:?} can not be put together: {err}");
                    continue;
                }
            };

        let names = names_by_port_after.get(&port).cloned().unwrap_or_default();
        for (name, _) in &names {
            errors.look_at_dynamic(name);
        }
        let configuration = put_names(configuration, &names, &mut errors);

        listeners_changed |= was_served != configuration.is_some();
        new_ports.push((port, configuration));
    }

    publish_ports(new_ports, errors, after.get_static_host_ids_lowercase()).await;

    listeners_changed
}

/// Refuses a dynamic host which would take the place of what the port serves already, rather
/// than be next to it. `existing` is what the port has without this host: an endpoint with its
/// id which is dynamic is the host itself, served before, and is replaced.
///
/// Every way a dynamic host is put on a port goes through here - a read of the url, a reload of
/// the settings, of a port, of one endpoint: a tcp endpoint replaces whatever its port had.
pub fn check_dynamic_host_fits(
    existing: &ListenConfiguration,
    host_endpoint: &EndpointHttpHostString,
    host_settings: &HostSettings,
) -> Result<(), String> {
    let is_itself = |other: &EndpointHttpHostString| {
        other.as_str().eq_ignore_ascii_case(host_endpoint.as_str())
    };

    match existing {
        ListenConfiguration::Http(config) | ListenConfiguration::Mcp(config) => {
            if let Some(served) = config
                .endpoints
                .iter()
                .find(|itm| !itm.dynamic_host && is_itself(&itm.host_endpoint))
            {
                return Err(format!(
                    "Dynamic host is refused: {} is served by a host of the settings files",
                    served.host_endpoint.as_str()
                ));
            }

            let is_tcp = matches!(
                host_settings.endpoint.get_endpoint_type(),
                Ok(EndpointTypeSettings::Tcp)
            );

            if is_tcp
                && config
                    .endpoints
                    .iter()
                    .any(|itm| !is_itself(&itm.host_endpoint))
            {
                return Err(format!(
                    "Dynamic host is refused: a tcp endpoint takes the port for itself, and the port of {} serves other hosts",
                    host_endpoint.as_str()
                ));
            }

            Ok(())
        }
        ListenConfiguration::Tcp(config) => {
            if config.dynamic_host && is_itself(&config.host_endpoint) {
                return Ok(());
            }

            Err(format!(
                "Dynamic host is refused: the port is served by the tcp endpoint {}",
                config.host_endpoint.as_str()
            ))
        }
    }
}

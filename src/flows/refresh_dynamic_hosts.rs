use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use flurl::FlUrl;

use crate::{
    app::APP_CTX,
    configurations::{
        EndpointHttpHostString, EndpointPort, HttpListenPortConfiguration, ListenConfiguration,
    },
    settings::{DynamicHostsModel, DynamicHostsSettings, EndpointTypeSettings, HostSettings},
    settings_compiled::SettingsCompiled,
};

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
        "Dynamic hosts: {} hosts are read from {}",
        after.dynamic_host_ids.len(),
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
/// `before`.
///
/// Only the ports a dynamic host came to, left, or changed on are touched. Each of them is put
/// together from what it serves now with the dynamic hosts taken away - the hosts of the
/// settings files, as the last reload compiled them - and the dynamic hosts of `after` on it.
/// The ports are replaced in one write: a connection sees either all of the change or none of
/// it, and picks it up with the next request it reads (`AppConfiguration::pick_up_reload`).
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
    let mut changed_ids: Vec<&String> = Vec::new();

    for host_id in &before.dynamic_host_ids {
        let same = after.dynamic_host_ids.contains(host_id)
            && crate::app::same_host(&before.hosts[host_id], &after.hosts[host_id]);

        if !same {
            changed_ids.push(host_id);
        }
    }

    for host_id in &after.dynamic_host_ids {
        if !before.dynamic_host_ids.contains(host_id) {
            changed_ids.push(host_id);
        }
    }

    let mut errors: BTreeMap<String, String> = BTreeMap::new();

    let mut ports: Vec<EndpointPort> = Vec::new();
    for host_id in &changed_ids {
        match EndpointHttpHostString::new(host_id.to_string()) {
            Ok(host_endpoint) => {
                let port = host_endpoint.get_port();
                if !ports.contains(&port) {
                    ports.push(port);
                }
            }
            Err(err) => {
                if after.dynamic_host_ids.contains(*host_id) {
                    errors.insert(host_id.to_string(), err);
                }
            }
        }
    }

    // Every dynamic host on the ports which are put together again is compiled again: its
    // error, if it has one, is found anew.
    let mut ids_looked_at: HashSet<String> = changed_ids.iter().map(|id| id.to_string()).collect();
    ids_looked_at.extend(before.dynamic_host_errors.keys().cloned());

    let mut new_ports: Vec<(EndpointPort, Option<ListenConfiguration>)> =
        Vec::with_capacity(ports.len());

    let mut before_by_port = dynamic_hosts_by_port(before);
    let mut after_by_port = dynamic_hosts_by_port(after);

    let mut listeners_changed = false;

    for port in ports {
        let live = get_live_configuration(&port).await;
        let was_served = live.is_some();
        let mut configuration = without_dynamic_hosts(live);

        ids_looked_at.extend(before_by_port.remove(&port).unwrap_or_default());

        for host_id in after_by_port.remove(&port).unwrap_or_default() {
            ids_looked_at.insert(host_id.clone());

            let host_settings = &after.hosts[&host_id];
            let host_endpoint = match EndpointHttpHostString::new(host_id.clone()) {
                Ok(host_endpoint) => host_endpoint,
                Err(err) => {
                    errors.insert(host_id, err);
                    continue;
                }
            };

            if let Some(existing) = configuration.as_ref() {
                if let Err(err) = check_dynamic_host_fits(existing, &host_endpoint, host_settings) {
                    errors.insert(host_id, err);
                    continue;
                }
            }

            match crate::scripts::compile_host_configuration(
                after,
                host_endpoint,
                host_settings,
                configuration.clone(),
            )
            .await
            {
                Ok(compiled) => configuration = Some(compiled),
                Err(err) => {
                    errors.insert(host_id, err);
                }
            }
        }

        listeners_changed |= was_served != configuration.is_some();
        new_ports.push((port, configuration));
    }

    for (host_id, err) in after.dynamic_host_errors.iter() {
        errors.insert(host_id.clone(), err.clone());
    }

    for (host_id, err) in errors.iter() {
        println!("Dynamic host {host_id} is not served. Err is: {err}");
    }

    let static_host_ids = after.get_static_host_ids_lowercase();
    let is_static_host =
        move |host_id: &str| static_host_ids.contains(&host_id.to_ascii_lowercase());

    APP_CTX
        .current_configuration
        .write(move |config| {
            // An error under the id of a host of the settings files is that host's own: it is
            // the reload of the files which finds it again.
            for host_id in ids_looked_at {
                if !is_static_host(&host_id) {
                    config.error_configurations.remove(&host_id);
                }
            }

            for (port, configuration) in new_ports {
                match (port, configuration) {
                    (EndpointPort::Tcp(port), Some(configuration)) => {
                        config.listen_tcp_endpoints.insert(port, configuration);
                    }
                    (EndpointPort::Tcp(port), None) => {
                        config.listen_tcp_endpoints.remove(&port);
                    }
                    (EndpointPort::UnixSocket(path), Some(configuration)) => {
                        config
                            .listen_unix_socket_endpoints
                            .insert(path, configuration);
                    }
                    (EndpointPort::UnixSocket(path), None) => {
                        config.listen_unix_socket_endpoints.remove(&path);
                    }
                }
            }

            for (host_id, err) in errors {
                if !is_static_host(&host_id) {
                    config.error_configurations.insert(host_id, err);
                }
            }
        })
        .await;

    listeners_changed
}

async fn get_live_configuration(port: &EndpointPort) -> Option<ListenConfiguration> {
    APP_CTX
        .current_configuration
        .get(|config| match port {
            EndpointPort::Tcp(port) => config.listen_tcp_endpoints.get(port).cloned(),
            EndpointPort::UnixSocket(path) => {
                config.listen_unix_socket_endpoints.get(path).cloned()
            }
        })
        .await
}

/// The dynamic hosts of `settings` by the port they are on, each port's in the order of their
/// ids: two hosts which can not both be served are decided the same way at every read.
fn dynamic_hosts_by_port(settings: &SettingsCompiled) -> HashMap<EndpointPort, Vec<String>> {
    let mut result: HashMap<EndpointPort, Vec<String>> = HashMap::new();

    for host_id in &settings.dynamic_host_ids {
        if let Ok(host_endpoint) = EndpointHttpHostString::new(host_id.to_string()) {
            result
                .entry(host_endpoint.get_port())
                .or_default()
                .push(host_id.clone());
        }
    }

    for host_ids in result.values_mut() {
        host_ids.sort();
    }

    result
}

/// What a port serves with its dynamic hosts taken away: `None` if it served nothing else.
/// A port with no dynamic host keeps its very configuration.
fn without_dynamic_hosts(
    configuration: Option<ListenConfiguration>,
) -> Option<ListenConfiguration> {
    match configuration? {
        ListenConfiguration::Http(config) => {
            without_dynamic_http_hosts(config).map(ListenConfiguration::Http)
        }
        ListenConfiguration::Mcp(config) => {
            without_dynamic_http_hosts(config).map(ListenConfiguration::Mcp)
        }
        ListenConfiguration::Tcp(config) => {
            if config.dynamic_host {
                None
            } else {
                Some(ListenConfiguration::Tcp(config))
            }
        }
    }
}

fn without_dynamic_http_hosts(
    config: Arc<HttpListenPortConfiguration>,
) -> Option<Arc<HttpListenPortConfiguration>> {
    if !config.endpoints.iter().any(|itm| itm.dynamic_host) {
        return Some(config);
    }

    let endpoints: Vec<_> = config
        .endpoints
        .iter()
        .filter(|itm| !itm.dynamic_host)
        .cloned()
        .collect();

    // A port is of the type of its first endpoint: when it was a dynamic one, the port is of
    // the type of the endpoint which is first now.
    let listen_endpoint_type = endpoints.first()?.listen_endpoint_type;

    Some(Arc::new(HttpListenPortConfiguration {
        endpoints,
        listen_endpoint_type,
        listen_host: config.listen_host.clone(),
    }))
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

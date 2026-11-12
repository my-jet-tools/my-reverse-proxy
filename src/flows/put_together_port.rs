//! Putting a port together: the hosts compiled onto it one next to the other, then the names of
//! their `additional_hosts` next to their endpoints. Every way the live configuration is changed
//! goes through here - a reload of the settings, of one endpoint, of one port, and a read of
//! `dynamic_hosts.url` - so a name is served the same way whichever of them put it there.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::{
    app::APP_CTX,
    configurations::*,
    settings_compiled::{AdditionalHost, SettingsCompiled},
};

/// The errors a change of the live configuration finds, and the ids whose errors it looks at
/// anew: what those had in the configuration errors is taken away, and what is found put in.
#[derive(Default)]
pub struct FoundErrors {
    /// Of the hosts of the settings files - and of the entries of their `additional_hosts`,
    /// which are told about under the host whose list has them.
    of_files: BTreeMap<String, String>,
    /// Of the hosts and the names of `dynamic_hosts.url`. One under the id of a host or a name of
    /// the settings files is not put into the configuration errors: it is not that host's error
    /// - `dynamic_hosts.refused_hosts` lists it.
    dynamic: BTreeMap<String, String>,
    ids_of_files: BTreeSet<String>,
    dynamic_ids: BTreeSet<String>,
}

impl FoundErrors {
    pub fn add_of_files(&mut self, host_id: &str, err: impl Into<String>) {
        self.ids_of_files.insert(host_id.to_string());
        append(&mut self.of_files, host_id.to_string(), err.into());
    }

    pub fn add_dynamic(&mut self, host_id: &str, err: impl Into<String>) {
        self.dynamic_ids.insert(host_id.to_string());
        append(&mut self.dynamic, host_id.to_string(), err.into());
    }

    /// The error a host of the settings files had is taken away: the host is put together anew.
    pub fn look_at_host_of_files(&mut self, host_id: &str) {
        self.ids_of_files.insert(host_id.to_string());
    }

    /// The error a host or a name of the url had is taken away: it is put together anew.
    pub fn look_at_dynamic(&mut self, host_id: &str) {
        self.dynamic_ids.insert(host_id.to_string());
    }

    /// Looks at `host_id` anew as a host of the files or of the url, as `settings` have it.
    pub fn look_at_host(&mut self, settings: &SettingsCompiled, host_id: &str) {
        if settings.is_dynamic_host(host_id) {
            self.look_at_dynamic(host_id);
        } else {
            self.look_at_host_of_files(host_id);
        }
    }

    /// The entries of `additional_hosts` of the host `host_id` the settings files ignore.
    pub fn add_ignored_entries(&mut self, settings: &SettingsCompiled, host_id: &str) {
        for err in settings
            .additional_host_errors
            .get(host_id)
            .into_iter()
            .flatten()
        {
            self.add_of_files(host_id, err.clone());
        }
    }

    pub fn print(&self) {
        for (host_id, err) in self.of_files.iter().chain(self.dynamic.iter()) {
            println!("Host {host_id} is not served as configured. Err is: {err}");
        }
    }

    /// What was found, as `id: error`.
    pub fn describe(&self) -> Vec<String> {
        self.of_files
            .iter()
            .chain(self.dynamic.iter())
            .map(|(host_id, err)| format!("{host_id}: {err}"))
            .collect()
    }

    /// Puts what was found into `error_configurations`, in place of what the ids looked at had
    /// there. `static_host_ids`: the ids of the hosts and the names of the settings files, in
    /// lower case.
    pub fn apply(
        self,
        error_configurations: &mut BTreeMap<String, String>,
        static_host_ids: &HashSet<String>,
    ) {
        let is_static = |host_id: &str| static_host_ids.contains(&host_id.to_ascii_lowercase());

        for host_id in &self.ids_of_files {
            error_configurations.remove(host_id);
        }

        for host_id in &self.dynamic_ids {
            if !is_static(host_id) {
                error_configurations.remove(host_id);
            }
        }

        for (host_id, err) in self.of_files {
            append(error_configurations, host_id, err);
        }

        for (host_id, err) in self.dynamic {
            if !is_static(&host_id) {
                append(error_configurations, host_id, err);
            }
        }
    }
}

fn append(errors: &mut BTreeMap<String, String>, host_id: String, err: String) {
    match errors.get_mut(&host_id) {
        Some(existing) => {
            existing.push_str("; ");
            existing.push_str(&err);
        }
        None => {
            errors.insert(host_id, err);
        }
    }
}

/// The port of a host id - `None` for what is not one.
pub fn port_of(host_id: &str) -> Option<EndpointPort> {
    EndpointHttpHostString::new(host_id.to_string())
        .ok()
        .map(|host_endpoint| host_endpoint.get_port())
}

/// The hosts of `settings` which `pick` picks, by their ports - each port's in the order they
/// are put on it: those of the files first, then the dynamic ones by their ids. A host whose id
/// names no port is told about in `errors`.
pub fn hosts_by_port<'s>(
    settings: &'s SettingsCompiled,
    pick: impl Fn(&str) -> bool,
    errors: &mut FoundErrors,
) -> HashMap<EndpointPort, Vec<&'s String>> {
    let mut result: HashMap<EndpointPort, Vec<&String>> = HashMap::new();

    for (host_id, _) in settings.hosts_in_apply_order() {
        if !pick(host_id) {
            continue;
        }

        match EndpointHttpHostString::new(host_id.clone()) {
            Ok(host_endpoint) => result
                .entry(host_endpoint.get_port())
                .or_default()
                .push(host_id),
            Err(err) if settings.is_dynamic_host(host_id) => errors.add_dynamic(host_id, err),
            Err(err) => errors.add_of_files(host_id, err),
        }
    }

    result
}

/// The names of `additional_hosts` of `settings` which `pick` picks, by their ports - each
/// port's in the order they are put on it: those of the files first, then the ones of the url.
pub fn names_by_port(
    settings: &SettingsCompiled,
    pick: impl Fn(&str, &AdditionalHost) -> bool,
) -> HashMap<EndpointPort, Vec<(&String, &AdditionalHost)>> {
    let mut result: HashMap<EndpointPort, Vec<(&String, &AdditionalHost)>> = HashMap::new();

    for (name, itm) in settings.additional_hosts_in_apply_order() {
        if !pick(name, itm) {
            continue;
        }

        if let Some(port) = port_of(name) {
            result.entry(port).or_default().push((name, itm));
        }
    }

    result
}

pub async fn get_live_configuration(port: &EndpointPort) -> Option<ListenConfiguration> {
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

/// Puts the configurations of `ports` into the live configuration, and the errors found into
/// its configuration errors - in one write: a connection sees either all of the change or none
/// of it, and picks it up with the next request it reads (`AppConfiguration::pick_up_reload`).
pub async fn publish_ports(
    ports: Vec<(EndpointPort, Option<ListenConfiguration>)>,
    errors: FoundErrors,
    static_host_ids: HashSet<String>,
) {
    errors.print();

    APP_CTX
        .current_configuration
        .write(move |config| {
            for (port, configuration) in ports {
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

            errors.apply(&mut config.error_configurations, &static_host_ids);
        })
        .await;
}

/// What a port serves with the endpoints `remove` picks taken away - `None` if nothing is left.
/// The very same configuration if it picks none.
pub fn without_endpoints(
    configuration: Option<ListenConfiguration>,
    remove: impl Fn(&HttpEndpointInfo) -> bool,
    remove_tcp: impl Fn(&TcpEndpointHostConfig) -> bool,
) -> Option<ListenConfiguration> {
    match configuration? {
        ListenConfiguration::Http(config) => {
            HttpListenPortConfiguration::without_endpoints(&config, remove)
                .map(ListenConfiguration::Http)
        }
        ListenConfiguration::Mcp(config) => {
            HttpListenPortConfiguration::without_endpoints(&config, remove)
                .map(ListenConfiguration::Mcp)
        }
        ListenConfiguration::Tcp(config) => {
            if remove_tcp(&config) {
                None
            } else {
                Some(ListenConfiguration::Tcp(config))
            }
        }
    }
}

/// Whether the port serves the host `host_id` itself - not a name of it.
pub fn serves_host(configuration: &Option<ListenConfiguration>, host_id: &str) -> bool {
    match configuration {
        Some(ListenConfiguration::Http(config)) | Some(ListenConfiguration::Mcp(config)) => config
            .endpoints
            .iter()
            .any(|itm| itm.additional_host_of.is_none() && itm.as_str() == host_id),
        Some(ListenConfiguration::Tcp(config)) => config.host_endpoint.as_str() == host_id,
        None => false,
    }
}

/// Compiles the hosts `host_ids` of `settings` onto a port which serves `configuration`, one
/// next to the other, in their order.
///
/// A dynamic host which would take the place of what the port serves, or does not compile, is
/// left out with its error: what the url gives never keeps the hosts of the files out. A host of
/// the files which does not compile is left out with its error too - unless `strict`: then it
/// fails the whole port, and the caller changes nothing.
pub async fn put_hosts(
    settings: &SettingsCompiled,
    mut configuration: Option<ListenConfiguration>,
    host_ids: &[&String],
    strict: bool,
    errors: &mut FoundErrors,
) -> Result<Option<ListenConfiguration>, String> {
    for host_id in host_ids {
        let host_settings = &settings.hosts[*host_id];
        let dynamic = settings.is_dynamic_host(host_id);

        let host_endpoint = match settings.get_endpoint_host_string(host_id) {
            Ok(host_endpoint) => host_endpoint,
            Err(err) if dynamic => {
                errors.add_dynamic(host_id, err);
                continue;
            }
            Err(err) if strict => return Err(err),
            Err(err) => {
                errors.add_of_files(host_id, err);
                continue;
            }
        };

        if dynamic {
            if let Some(existing) = configuration.as_ref() {
                if let Err(err) =
                    super::check_dynamic_host_fits(existing, &host_endpoint, host_settings)
                {
                    errors.add_dynamic(host_id, err);
                    continue;
                }
            }
        }

        match crate::scripts::compile_host_configuration(
            settings,
            host_endpoint,
            host_settings,
            configuration.clone(),
        )
        .await
        {
            Ok(compiled) => configuration = Some(compiled),
            Err(err) if dynamic => errors.add_dynamic(host_id, err),
            Err(err) if strict => return Err(err),
            Err(err) => errors.add_of_files(host_id, err),
        }
    }

    Ok(configuration)
}

/// Puts each of `names` - names of `additional_hosts` on the port of `configuration` - next to
/// the endpoint of its host: an endpoint of its own, which is the host's endpoint under the name.
/// A name which can not be served is told about in `errors`: one of the url under its id, one of
/// the files under its host - which is not told about twice when it is the host which is not
/// served.
pub fn put_names(
    configuration: Option<ListenConfiguration>,
    names: &[(&String, &AdditionalHost)],
    errors: &mut FoundErrors,
) -> Option<ListenConfiguration> {
    if names.is_empty() {
        return configuration;
    }

    let names: Vec<AdditionalHostName> = names
        .iter()
        .map(|(name, itm)| AdditionalHostName {
            host_id: name.as_str(),
            additional_host_of: itm.host_id.as_str(),
            dynamic_host: itm.dynamic,
        })
        .collect();

    let (configuration, refused) = match configuration {
        Some(ListenConfiguration::Http(config)) => {
            let (config, refused) =
                HttpListenPortConfiguration::with_additional_hosts(&config, &names);
            (Some(ListenConfiguration::Http(config)), refused)
        }
        Some(ListenConfiguration::Mcp(config)) => {
            let (config, refused) =
                HttpListenPortConfiguration::with_additional_hosts(&config, &names);
            (Some(ListenConfiguration::Mcp(config)), refused)
        }
        Some(ListenConfiguration::Tcp(config)) => {
            let refused = names
                .into_iter()
                .map(|name| {
                    let refusal = AdditionalHostRefusal::Other(format!(
                        "the port is served by the tcp endpoint {}",
                        config.host_endpoint.as_str()
                    ));
                    (name, refusal)
                })
                .collect();
            (Some(ListenConfiguration::Tcp(config)), refused)
        }
        None => {
            let refused = names
                .into_iter()
                .map(|name| (name, AdditionalHostRefusal::HostNotServed))
                .collect();
            (None, refused)
        }
    };

    for (name, refusal) in refused {
        if name.dynamic_host {
            errors.add_dynamic(
                name.host_id,
                format!(
                    "Dynamic host is not served: {}",
                    refusal.describe(name.additional_host_of)
                ),
            );
        } else if !matches!(refusal, AdditionalHostRefusal::HostNotServed) {
            errors.add_of_files(
                name.additional_host_of,
                format!(
                    "additional_hosts: '{}' is not served: {}",
                    name.host_id,
                    refusal.describe(name.additional_host_of)
                ),
            );
        }
    }

    configuration
}

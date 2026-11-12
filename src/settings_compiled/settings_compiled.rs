use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    net::IpAddr,
};

use rust_extensions::duration_utils::DurationExtensions;

use crate::{configurations::EndpointHttpHostString, settings::*};

use super::{AdditionalHost, VariablesCompiled};

#[derive(Debug, Default, Clone)]

pub struct SettingsCompiled {
    pub ssh: HashMap<String, SshConfigSettings>,
    /// The hosts of the settings files, and the dynamic ones next to them: those are named in
    /// `dynamic_host_ids`. The names of their `additional_hosts` are not hosts of their own: they
    /// are in `additional_hosts`, and the settings here have no `additional_hosts` left.
    pub hosts: HashMap<String, HostSettings>,
    /// Each name of `additional_hosts` - of a host of the settings files, of a host of the url, or
    /// of `additional_hosts:` of the url - with the host it is a name of. A request for a name is
    /// served by the configuration of that host, under the name.
    pub additional_hosts: BTreeMap<String, AdditionalHost>,
    /// The entries of `additional_hosts` of the settings files which are ignored - by the host
    /// whose list has them - each with why. The ones of the url are in `dynamic_host_errors`.
    pub additional_host_errors: BTreeMap<String, Vec<String>>,
    /// `dynamic_hosts:` of the settings - the url more hosts are read from.
    pub dynamic_hosts: Option<DynamicHostsSettings>,
    /// The ids of `hosts` which came from `dynamic_hosts.url`.
    pub dynamic_host_ids: HashSet<String>,
    /// The hosts and the names of `dynamic_hosts.url` which are not taken, and why: a variable
    /// which is not there, an id the settings files have already, a name which is not a domain
    /// name.
    pub dynamic_host_errors: BTreeMap<String, String>,
    /// The variables the settings were compiled with - the dynamic hosts are compiled with them
    /// as well, when they come.
    pub variables: VariablesCompiled,
    pub ssl_certificates: Vec<SslCertificatesSettingsModel>,
    pub client_certificate_ca: Vec<ClientCertificateCaSettings>,
    pub global_settings: Option<GlobalSettings>,
    pub g_auth: HashMap<String, GoogleAuthSettings>,
    pub oauth: HashMap<String, OAuthSettings>,
    pub endpoint_templates: HashMap<String, EndpointTemplateSettings>,
    pub allowed_users: HashMap<String, Vec<String>>,
    pub ip_white_lists: HashMap<String, Vec<String>>,
    pub gateway_server: Option<GatewayServerSettings>,
    pub gateway_clients: HashMap<String, GatewayClientSettings>,
}

impl SettingsCompiled {
    pub fn get_endpoint_host_string(
        &self,
        host_id: &str,
    ) -> Result<EndpointHttpHostString, String> {
        EndpointHttpHostString::new(host_id.to_string())
    }

    /// Whether the host came from `dynamic_hosts.url` rather than from a settings file.
    pub fn is_dynamic_host(&self, host_id: &str) -> bool {
        self.dynamic_host_ids.contains(host_id)
    }

    /// The host `host_id` is a name of - `None` for a host written as a key.
    pub fn get_additional_host_of(&self, host_id: &str) -> Option<&String> {
        self.additional_hosts.get(host_id).map(|itm| &itm.host_id)
    }

    /// The host whose configuration serves `host_id` - letter case aside: the host itself, or the
    /// host it is a name of. `None` if the settings have neither.
    pub fn get_main_host_id(&self, host_id: &str) -> Option<String> {
        if let Some(found) = self
            .hosts
            .keys()
            .find(|existing| existing.eq_ignore_ascii_case(host_id))
        {
            return Some(found.clone());
        }

        self.additional_hosts
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(host_id))
            .map(|(_, itm)| itm.host_id.clone())
    }

    /// The names of `additional_hosts` of the host `host_id`, by their ids.
    pub fn get_additional_hosts_of<'s>(
        &'s self,
        host_id: &'s str,
    ) -> impl Iterator<Item = (&'s String, &'s AdditionalHost)> + 's {
        self.additional_hosts
            .iter()
            .filter(move |(_, itm)| itm.host_id == host_id)
    }

    /// The host which serves `host_id` - letter case aside - and its names: the host first, then
    /// its names by their ids. Empty if the settings have no such host.
    pub fn get_host_group(&self, host_id: &str) -> Vec<String> {
        let Some(main_host_id) = self.get_main_host_id(host_id) else {
            return Vec::new();
        };

        let mut result = Vec::new();

        if self.hosts.contains_key(&main_host_id) {
            result.push(main_host_id.clone());
        }

        result.extend(
            self.get_additional_hosts_of(&main_host_id)
                .map(|(name, _)| name.clone()),
        );

        result
    }

    /// The names of `additional_hosts` in the order they are put on their ports: those of the
    /// settings files first, then the ones of the url - each by their ids.
    pub fn additional_hosts_in_apply_order(&self) -> Vec<(&String, &AdditionalHost)> {
        let mut result: Vec<_> = self
            .additional_hosts
            .iter()
            .filter(|(_, itm)| !itm.dynamic)
            .collect();

        result.extend(self.additional_hosts.iter().filter(|(_, itm)| itm.dynamic));

        result
    }

    /// Takes the `additional_hosts` of the hosts of the settings files out of their settings into
    /// `additional_hosts`. An entry which can not be served is ignored, with why under the host
    /// whose list has it, and the rest are taken: an entry with a variable which is not there,
    /// which is not a domain name, names another port, is the id of a host, or is in the list
    /// twice. A name in the lists of two hosts is ignored by both: which of them it would be
    /// served by is not to depend on the order the files are read in - nothing here does.
    pub(crate) fn resolve_additional_hosts_of_files(&mut self) {
        let mut host_ids: Vec<String> = self.hosts.keys().cloned().collect();
        host_ids.sort();

        let host_ids_lowercase: HashSet<String> = host_ids
            .iter()
            .map(|host_id| host_id.to_ascii_lowercase())
            .collect();

        // Each name, by its id in lower case: the hosts which have it, with the id as written.
        let mut names: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();

        for host_id in host_ids {
            let Some(entries) = self
                .hosts
                .get_mut(&host_id)
                .and_then(|host_settings| host_settings.additional_hosts.take())
            else {
                continue;
            };

            let host_settings = &self.hosts[&host_id];
            let mut own = HashSet::new();
            let mut errors = Vec::new();

            for entry in entries {
                let ignored =
                    |err: &str| format!("additional_hosts: '{}' is ignored: {err}", entry.trim());

                let compiled_entry = match self.variables.apply_variables(entry.clone()) {
                    Ok(compiled_entry) => compiled_entry,
                    Err(err) => {
                        errors.push(ignored(&err));
                        continue;
                    }
                };

                let name =
                    match super::get_additional_host_id(&host_id, host_settings, &compiled_entry) {
                        Ok(name) => name,
                        Err(err) => {
                            errors.push(ignored(&err));
                            continue;
                        }
                    };

                let lowercase = name.to_ascii_lowercase();

                if host_ids_lowercase.contains(&lowercase) {
                    errors.push(ignored("the settings have a host with this id"));
                    continue;
                }

                if !own.insert(lowercase.clone()) {
                    errors.push(ignored("it is in the list twice"));
                    continue;
                }

                names
                    .entry(lowercase)
                    .or_default()
                    .push((host_id.clone(), name));
            }

            if !errors.is_empty() {
                self.additional_host_errors
                    .entry(host_id)
                    .or_default()
                    .extend(errors);
            }
        }

        for (_, hosts) in names {
            if let [(host_id, name)] = hosts.as_slice() {
                self.additional_hosts.insert(
                    name.clone(),
                    AdditionalHost {
                        host_id: host_id.clone(),
                        dynamic: false,
                    },
                );
                continue;
            }

            let all: Vec<String> = hosts
                .iter()
                .map(|(host_id, _)| format!("'{host_id}'"))
                .collect();

            for (host_id, name) in &hosts {
                self.additional_host_errors
                    .entry(host_id.clone())
                    .or_default()
                    .push(format!(
                        "additional_hosts: '{name}' is ignored: it is in additional_hosts of {} - a name is served by one host only",
                        all.join(" and ")
                    ));
            }
        }
    }

    /// Puts what `dynamic_hosts.url` answered with next to the hosts of the settings files, in
    /// place of what it answered before: the hosts of its `hosts`, each with the names of its own
    /// `additional_hosts`, then the names of its `additional_hosts:` - names of a host the
    /// settings files have, or its `hosts` have.
    ///
    /// A host or a name of the settings files is never replaced: a dynamic one with its id -
    /// letter case aside - is refused. Neither does one which can not be taken keep the others
    /// out: it is put into `dynamic_host_errors`, and the rest are taken. Each name is taken on
    /// its own: a wrong entry of a long list does not take the list down.
    pub fn set_dynamic_hosts_answer(&mut self, answer: &DynamicHostsModel) {
        self.clear_dynamic_hosts();

        let mut taken_ids: HashSet<String> = self
            .hosts
            .keys()
            .chain(self.additional_hosts.keys())
            .map(|host_id| host_id.to_ascii_lowercase())
            .collect();

        // In the order of the ids, so two which can not both be taken are decided the same way
        // at every read.
        let mut host_ids: Vec<&String> = answer.hosts.keys().collect();
        host_ids.sort();

        for host_id in host_ids {
            let entries = answer.hosts[host_id]
                .additional_hosts
                .clone()
                .unwrap_or_default();

            let compiled = super::compile_host(
                host_id.clone(),
                answer.hosts[host_id].clone(),
                &self.variables,
            );

            let (main_host_id, mut host_settings) = match compiled {
                Ok(compiled) => compiled,
                Err(err) => {
                    self.add_dynamic_host_error(host_id.clone(), format!("Dynamic host: {err}"));

                    for entry in &entries {
                        self.add_dynamic_host_error(
                            entry.trim().to_string(),
                            format!("Dynamic host is refused: it is in additional_hosts of '{host_id}', which is refused"),
                        );
                    }
                    continue;
                }
            };

            host_settings.additional_hosts = None;

            if !taken_ids.insert(main_host_id.to_ascii_lowercase()) {
                let err = self.get_refusal_of_taken_id(&main_host_id);
                self.add_dynamic_host_error(main_host_id.clone(), err.to_string());

                // They are not served with a configuration which is not served.
                for entry in &entries {
                    let key = self.get_entry_key(&main_host_id, &host_settings, entry);
                    self.add_dynamic_host_error(
                        key,
                        format!("Dynamic host is refused: it is in additional_hosts of '{main_host_id}', which is refused"),
                    );
                }
                continue;
            }

            self.dynamic_host_ids.insert(main_host_id.clone());
            self.hosts
                .insert(main_host_id.clone(), host_settings.clone());

            for entry in &entries {
                self.take_dynamic_name(&mut taken_ids, &main_host_id, &host_settings, entry);
            }
        }

        let mut keys: Vec<&String> = answer.additional_hosts.keys().collect();
        keys.sort();

        for key in keys {
            let entries = &answer.additional_hosts[key];

            let key = match self.variables.apply_variables(key.clone()) {
                Ok(key) => key,
                Err(err) => {
                    for entry in entries {
                        self.add_dynamic_host_error(
                            entry.trim().to_string(),
                            format!("Dynamic host: {err}"),
                        );
                    }
                    continue;
                }
            };

            // The host whose configuration they are served with - the one `key` is a name of,
            // if it is a name itself.
            let Some(main_host_id) = self.get_main_host_id(&key) else {
                for entry in entries {
                    self.add_dynamic_host_error(
                        entry.trim().to_string(),
                        format!(
                            "Dynamic host is refused: it is in additional_hosts of '{key}', which neither the settings files nor the hosts of the url have"
                        ),
                    );
                }
                continue;
            };

            let host_settings = self.hosts[&main_host_id].clone();

            for entry in entries {
                self.take_dynamic_name(&mut taken_ids, &main_host_id, &host_settings, entry);
            }
        }
    }

    /// The hosts of `hosts`, read from `dynamic_hosts.url` with nothing else.
    #[cfg(test)]
    pub fn set_dynamic_hosts(&mut self, hosts: &HashMap<String, HostSettings>) {
        self.set_dynamic_hosts_answer(&DynamicHostsModel {
            hosts: hosts.clone(),
            additional_hosts: HashMap::new(),
        });
    }

    /// Takes away what the url answered with: its hosts, its names, and their errors.
    fn clear_dynamic_hosts(&mut self) {
        for host_id in self.dynamic_host_ids.drain() {
            self.hosts.remove(&host_id);
        }

        self.additional_hosts.retain(|_, itm| !itm.dynamic);
        self.dynamic_host_errors.clear();
    }

    /// Takes `entry` - an entry of `additional_hosts` of `main_host_id`, given by the url - as a
    /// name of that host, unless it is not one, or is taken already: then it is refused.
    fn take_dynamic_name(
        &mut self,
        taken_ids: &mut HashSet<String>,
        main_host_id: &str,
        host_settings: &HostSettings,
        entry: &str,
    ) {
        let compiled_entry = match self.variables.apply_variables(entry.to_string()) {
            Ok(compiled_entry) => compiled_entry,
            Err(err) => {
                self.add_dynamic_host_error(
                    entry.trim().to_string(),
                    format!("Dynamic host: {err}"),
                );
                return;
            }
        };

        let name = match super::get_additional_host_id(main_host_id, host_settings, &compiled_entry)
        {
            Ok(name) => name,
            Err(err) => {
                self.add_dynamic_host_error(
                    compiled_entry.trim().to_string(),
                    format!(
                        "Dynamic host is refused: '{}' of additional_hosts of '{main_host_id}': {err}",
                        compiled_entry.trim()
                    ),
                );
                return;
            }
        };

        if !taken_ids.insert(name.to_ascii_lowercase()) {
            let err = self.get_refusal_of_taken_id(&name);
            self.add_dynamic_host_error(
                name,
                format!("{err} (it is in additional_hosts of '{main_host_id}')"),
            );
            return;
        }

        self.additional_hosts.insert(
            name,
            AdditionalHost {
                host_id: main_host_id.to_string(),
                dynamic: true,
            },
        );
    }

    fn get_refusal_of_taken_id(&self, host_id: &str) -> &'static str {
        if self.is_static_host(host_id) {
            "Dynamic host is refused: the settings files have a host with this id"
        } else {
            "Dynamic host is refused: the url gives another host with this id"
        }
    }

    /// What an entry of `additional_hosts` of `host_id` is told about under: the name it is, or
    /// the entry as it is written if it is not one.
    fn get_entry_key(&self, host_id: &str, host_settings: &HostSettings, entry: &str) -> String {
        self.variables
            .apply_variables(entry.to_string())
            .ok()
            .and_then(|entry| super::get_additional_host_id(host_id, host_settings, &entry).ok())
            .unwrap_or_else(|| entry.trim().to_string())
    }

    /// Two reasons under one key - two hosts listing the same wrong entry - are both told.
    fn add_dynamic_host_error(&mut self, key: String, err: String) {
        match self.dynamic_host_errors.get_mut(&key) {
            Some(existing) => {
                existing.push_str("; ");
                existing.push_str(&err);
            }
            None => {
                self.dynamic_host_errors.insert(key, err);
            }
        }
    }

    /// The hosts in the order they are put on their ports: those of the settings files first,
    /// then the dynamic ones by their ids. A dynamic host is checked against what its port has
    /// already, and a host of the files is never put after one.
    pub fn hosts_in_apply_order(&self) -> Vec<(&String, &HostSettings)> {
        let mut static_hosts = Vec::with_capacity(self.hosts.len());
        let mut dynamic_hosts = Vec::with_capacity(self.dynamic_host_ids.len());

        for (host_id, host_settings) in &self.hosts {
            if self.dynamic_host_ids.contains(host_id) {
                dynamic_hosts.push((host_id, host_settings));
            } else {
                static_hosts.push((host_id, host_settings));
            }
        }

        dynamic_hosts.sort_by(|a, b| a.0.cmp(b.0));
        static_hosts.extend(dynamic_hosts);
        static_hosts
    }

    /// A host or a name of the settings files - letter case aside.
    pub fn is_static_host(&self, host_id: &str) -> bool {
        self.hosts.keys().any(|existing| {
            existing.eq_ignore_ascii_case(host_id) && !self.dynamic_host_ids.contains(existing)
        }) || self
            .additional_hosts
            .iter()
            .any(|(name, itm)| !itm.dynamic && name.eq_ignore_ascii_case(host_id))
    }

    /// The ids of the hosts and of the names of the settings files, in lower case.
    pub fn get_static_host_ids_lowercase(&self) -> HashSet<String> {
        self.hosts
            .keys()
            .filter(|host_id| !self.dynamic_host_ids.contains(*host_id))
            .chain(
                self.additional_hosts
                    .iter()
                    .filter(|(_, itm)| !itm.dynamic)
                    .map(|(name, _)| name),
            )
            .map(|host_id| host_id.to_ascii_lowercase())
            .collect()
    }

    /// The host of the settings files `host_id` is a name of - letter case aside.
    fn get_static_name_owner(&self, host_id: &str) -> Option<&String> {
        self.additional_hosts
            .iter()
            .find(|(name, itm)| !itm.dynamic && name.eq_ignore_ascii_case(host_id))
            .map(|(_, itm)| &itm.host_id)
    }

    /// The host of the settings files with the id `host_id` - letter case aside.
    fn get_static_host_id(&self, host_id: &str) -> Option<&String> {
        self.hosts.keys().find(|existing| {
            existing.eq_ignore_ascii_case(host_id) && !self.dynamic_host_ids.contains(*existing)
        })
    }

    /// The hosts of the settings files to be reloaded together with `host_ids`, so that these
    /// settings - the ones applied - and `fresh` - the settings files as they are now - agree on
    /// every name of the hosts reloaded: a name which moved to another host, or became a host of
    /// its own, or the other way round, takes that other host along.
    pub fn get_hosts_of_files_reloaded_with(
        &self,
        fresh: &SettingsCompiled,
        host_ids: BTreeSet<String>,
    ) -> BTreeSet<String> {
        let mut result = host_ids;

        loop {
            let mut more = Vec::new();

            for host_id in &result {
                for (now, other) in [(fresh, self), (self, fresh)] {
                    let names = now
                        .get_additional_hosts_of(host_id)
                        .filter(|(_, itm)| !itm.dynamic)
                        .map(|(name, _)| name.as_str());

                    for id in std::iter::once(host_id.as_str()).chain(names) {
                        for found in [
                            other.get_static_name_owner(id),
                            other.get_static_host_id(id),
                        ]
                        .into_iter()
                        .flatten()
                        {
                            if !result.contains(found) {
                                more.push(found.clone());
                            }
                        }
                    }
                }
            }

            if more.is_empty() {
                return result;
            }

            result.extend(more);
        }
    }

    /// These settings with the hosts of the settings files `host_ids` - and their names, and the
    /// errors of their lists - as `fresh` has them: one which `fresh` does not have is gone. What
    /// `answer` - the answer of `dynamic_hosts.url` - gives is put next to them anew: a dynamic
    /// host is taken or refused against the hosts of the files as they are now.
    pub fn with_hosts_of_files_from(
        &self,
        fresh: &SettingsCompiled,
        host_ids: &BTreeSet<String>,
        answer: Option<&DynamicHostsModel>,
    ) -> SettingsCompiled {
        let mut result = self.clone();
        result.clear_dynamic_hosts();

        // All of them first: a name can move from one of them to another.
        for host_id in host_ids {
            result.hosts.remove(host_id);
            result
                .additional_hosts
                .retain(|_, itm| itm.host_id != *host_id);
            result.additional_host_errors.remove(host_id);
        }

        for host_id in host_ids {
            if fresh.is_dynamic_host(host_id) {
                continue;
            }

            let Some(host_settings) = fresh.hosts.get(host_id) else {
                continue;
            };

            result.hosts.insert(host_id.clone(), host_settings.clone());

            for (name, itm) in fresh.get_additional_hosts_of(host_id) {
                if !itm.dynamic {
                    result.additional_hosts.insert(name.clone(), itm.clone());
                }
            }

            if let Some(errors) = fresh.additional_host_errors.get(host_id) {
                result
                    .additional_host_errors
                    .insert(host_id.clone(), errors.clone());
            }
        }

        if let Some(answer) = answer {
            result.set_dynamic_hosts_answer(answer);
        }

        result
    }

    pub fn get_http_control_port(&self) -> Option<u16> {
        if let Some(global_settings) = self.global_settings.as_ref() {
            return global_settings.http_control_port;
        }

        None
    }

    /// `global_settings.http_control_ip` - checked when the settings are loaded.
    pub fn get_http_control_ip(&self) -> Result<Option<IpAddr>, String> {
        match self.global_settings.as_ref() {
            Some(global_settings) => global_settings.get_http_control_ip(),
            None => Ok(None),
        }
    }

    pub fn get_connections_settings(&self) -> ConnectionsSettingsModel {
        let result = if let Some(global_settings) = self.global_settings.as_ref() {
            match global_settings.connection_settings.as_ref() {
                Some(connection_settings) => ConnectionsSettingsModel::new(connection_settings),
                None => ConnectionsSettingsModel::default(),
            }
        } else {
            ConnectionsSettingsModel::default()
        };

        println!(
            "Each connection is going to use buffer: {}",
            crate::format_mem(result.buffer_size)
        );

        println!(
            "Timeout to connect to remote endpoint is: {}",
            result.remote_connect_timeout.format_to_string()
        );

        result
    }

    pub fn get_session_key(&self) -> Option<String> {
        if let Some(global_settings) = self.global_settings.as_ref() {
            if let Some(connection_settings) = global_settings.connection_settings.as_ref() {
                return connection_settings.session_key.clone();
            }
        }

        None
    }

    pub fn get_gateway_server(&self) -> Option<&GatewayServerSettings> {
        self.gateway_server.as_ref()
    }

    pub fn get_default_h2_livness_url(&self) -> Option<String> {
        self.global_settings
            .as_ref()
            .and_then(|g| g.default_h2_livness_url.clone())
    }

    /// The lowest (global) level of the timeout cascade. Empty if no
    /// `global_settings` block is present.
    pub fn get_global_timeouts(&self) -> crate::settings::TimeoutsSettings {
        self.global_settings
            .as_ref()
            .map(|g| g.timeouts)
            .unwrap_or_default()
    }

    pub fn get_pool_supervisor_interval(&self) -> std::time::Duration {
        let value = self
            .global_settings
            .as_ref()
            .and_then(|g| g.pool_supervisor_interval);

        match value {
            Some(value) => std::time::Duration::from_millis(value),
            None => crate::consts::DEFAULT_POOL_SUPERVISOR_INTERVAL,
        }
    }

    pub fn get_show_error_description_on_error_page(&self) -> bool {
        if let Some(global_settings) = self.global_settings.as_ref() {
            if let Some(show_error_description_on_error_page) =
                global_settings.show_error_description_on_error_page
            {
                return show_error_description_on_error_page;
            }
        }

        false
    }

    /// Source IPs that are shown the diagnostic page on a refused request
    /// (`global_settings.debug_ip`). The entries were validated when the
    /// settings were compiled.
    pub fn get_debug_ip(&self) -> Vec<std::net::IpAddr> {
        self.global_settings
            .as_ref()
            .and_then(|g| g.get_debug_ip().ok())
            .unwrap_or_default()
    }

    /// Global IP block-list allow-list (fail2ban exemptions), if configured.
    pub fn get_ip_blocklist_white_list(&self) -> Option<Vec<String>> {
        self.global_settings
            .as_ref()?
            .ip_blocklist_white_list
            .clone()
    }
}

#[cfg(test)]
mod dynamic_hosts_tests {
    use std::collections::HashMap;

    use super::*;

    fn hosts(yaml: &str) -> HashMap<String, HostSettings> {
        DynamicHostsModel::parse(yaml.as_bytes())
            .unwrap()
            .unwrap()
            .hosts
    }

    fn answer(yaml: &str) -> DynamicHostsModel {
        DynamicHostsModel::parse(yaml.as_bytes()).unwrap().unwrap()
    }

    fn host(host_id: &str, proxy_pass_to: &str) -> String {
        format!(
            "  '{host_id}':\n    endpoint:\n      type: http\n    locations:\n    - proxy_pass_to: '{proxy_pass_to}'\n"
        )
    }

    fn host_with_names(
        host_id: &str,
        endpoint_type: &str,
        names: &[&str],
        proxy_pass_to: &str,
    ) -> String {
        let names: String = names.iter().map(|itm| format!("    - '{itm}'\n")).collect();

        format!(
            "  '{host_id}':\n    additional_hosts:\n{names}    endpoint:\n      type: {endpoint_type}\n    locations:\n    - proxy_pass_to: '{proxy_pass_to}'\n"
        )
    }

    fn settings_with_static_host() -> SettingsCompiled {
        SettingsCompiled {
            hosts: hosts(&format!(
                "hosts:\n{}",
                host("static.example.com:8000", "http://127.0.0.1:9000")
            )),
            ..Default::default()
        }
    }

    fn sorted<'s>(ids: impl Iterator<Item = &'s String>) -> Vec<&'s str> {
        let mut result: Vec<&str> = ids.map(|itm| itm.as_str()).collect();
        result.sort();
        result
    }

    fn name_of<'s>(settings: &'s SettingsCompiled, name: &str) -> Option<(&'s str, bool)> {
        settings
            .additional_hosts
            .get(name)
            .map(|itm| (itm.host_id.as_str(), itm.dynamic))
    }

    #[test]
    fn the_dynamic_hosts_are_next_to_the_hosts_of_the_files() {
        let mut settings = settings_with_static_host();

        settings.set_dynamic_hosts(&hosts(&format!(
            "hosts:\n{}{}",
            host("a.example.com:8000", "http://127.0.0.1:9001"),
            host("b.example.com:8001", "http://127.0.0.1:9002"),
        )));

        assert_eq!(
            sorted(settings.hosts.keys()),
            [
                "a.example.com:8000",
                "b.example.com:8001",
                "static.example.com:8000"
            ]
        );

        assert!(settings.is_dynamic_host("a.example.com:8000"));
        assert!(settings.is_dynamic_host("b.example.com:8001"));
        assert!(!settings.is_dynamic_host("static.example.com:8000"));
        assert!(settings.is_static_host("STATIC.example.com:8000"));
        assert!(!settings.is_static_host("a.example.com:8000"));
        assert!(settings.dynamic_host_errors.is_empty());
    }

    /// The hosts of a read replace the ones of the read before: a host the url does not give
    /// any more is gone, and the hosts of the files stay.
    #[test]
    fn a_read_replaces_the_dynamic_hosts_of_the_read_before() {
        let mut settings = settings_with_static_host();

        settings.set_dynamic_hosts(&hosts(&format!(
            "hosts:\n{}",
            host("a.example.com:8000", "http://127.0.0.1:9001")
        )));
        settings.set_dynamic_hosts(&hosts(&format!(
            "hosts:\n{}",
            host("b.example.com:8000", "http://127.0.0.1:9002")
        )));

        assert!(!settings.hosts.contains_key("a.example.com:8000"));
        assert!(settings.hosts.contains_key("b.example.com:8000"));
        assert!(settings.hosts.contains_key("static.example.com:8000"));
        assert_eq!(settings.dynamic_host_ids.len(), 1);

        settings.set_dynamic_hosts(&HashMap::new());

        assert_eq!(settings.hosts.len(), 1);
        assert!(settings.hosts.contains_key("static.example.com:8000"));
        assert!(settings.dynamic_host_ids.is_empty());
    }

    /// The url can not take a host of the files over - not even written in other letters.
    #[test]
    fn a_host_of_the_files_is_never_replaced() {
        let mut settings = settings_with_static_host();

        settings.set_dynamic_hosts(&hosts(&format!(
            "hosts:\n{}{}",
            host("Static.Example.com:8000", "http://10.0.0.66:80"),
            host("a.example.com:8000", "http://127.0.0.1:9001"),
        )));

        assert_eq!(
            settings.hosts["static.example.com:8000"].locations[0]
                .proxy_pass_to
                .as_deref(),
            Some("http://127.0.0.1:9000")
        );
        assert!(!settings.hosts.contains_key("Static.Example.com:8000"));
        assert!(settings.dynamic_host_errors["Static.Example.com:8000"]
            .contains("the settings files have a host with this id"));

        // The others are taken.
        assert!(settings.is_dynamic_host("a.example.com:8000"));
    }

    #[test]
    fn two_dynamic_hosts_with_one_id_are_decided_the_same_way_every_time() {
        for _ in 0..10 {
            let mut settings = SettingsCompiled::default();

            settings.set_dynamic_hosts(&hosts(&format!(
                "hosts:\n{}{}",
                host("a.example.com:8000", "http://127.0.0.1:9001"),
                host("A.example.com:8000", "http://127.0.0.1:9002"),
            )));

            // `A` is before `a`.
            assert!(settings.is_dynamic_host("A.example.com:8000"));
            assert!(!settings.hosts.contains_key("a.example.com:8000"));
            assert!(settings.dynamic_host_errors["a.example.com:8000"]
                .contains("another host with this id"));
        }
    }

    /// The variables of the settings are put into the dynamic hosts as into the hosts of the
    /// files; a host with one which is not there is refused, and the others are taken.
    #[test]
    fn the_variables_of_the_settings_are_put_into_the_dynamic_hosts() {
        let mut settings_model = crate::settings::SettingsModel::parse_for_tests(
            "variables:\n  upstream: 127.0.0.1:9005\n",
        );
        let mut settings = SettingsCompiled::default();
        settings.variables.merge(&mut settings_model);

        settings.set_dynamic_hosts(&hosts(&format!(
            "hosts:\n{}{}",
            host("a.example.com:8000", "http://${upstream}"),
            host("b.example.com:8000", "http://${not_there}"),
        )));

        assert_eq!(
            settings.hosts["a.example.com:8000"].locations[0]
                .proxy_pass_to
                .as_deref(),
            Some("http://127.0.0.1:9005")
        );
        assert!(!settings.hosts.contains_key("b.example.com:8000"));
        assert!(settings.dynamic_host_errors["b.example.com:8000"].contains("not_there"));
    }

    /// The `additional_hosts` of a dynamic host are names of it - not hosts of their own. One the
    /// files have already is refused, and so is one on another port, each on its own; the rest
    /// are taken.
    #[test]
    fn the_additional_hosts_of_a_dynamic_host_are_names_of_it() {
        let mut settings = settings_with_static_host();

        settings.set_dynamic_hosts(&hosts(&format!(
            "hosts:\n{}",
            host_with_names(
                "a.example.com:8000",
                "http",
                &[
                    "b.example.com",
                    "STATIC.example.com",
                    "c.example.com:8001",
                    "d.example.com:8000"
                ],
                "http://127.0.0.1:9001"
            ),
        )));

        assert_eq!(
            sorted(settings.hosts.keys()),
            ["a.example.com:8000", "static.example.com:8000"]
        );
        assert!(settings.hosts["a.example.com:8000"]
            .additional_hosts
            .is_none());

        assert_eq!(
            name_of(&settings, "b.example.com:8000"),
            Some(("a.example.com:8000", true))
        );
        assert_eq!(
            name_of(&settings, "d.example.com:8000"),
            Some(("a.example.com:8000", true))
        );
        assert_eq!(settings.additional_hosts.len(), 2);

        let errors = &settings.dynamic_host_errors;
        assert!(errors["STATIC.example.com:8000"].contains("the settings files have a host"));
        assert!(errors["c.example.com:8001"].contains("on port 8001"));
        assert_eq!(errors.len(), 2, "{errors:?}");

        // Whichever of them is named, the group is the same.
        for host_id in ["a.example.com:8000", "B.example.com:8000"] {
            assert_eq!(
                settings.get_host_group(host_id),
                [
                    "a.example.com:8000",
                    "b.example.com:8000",
                    "d.example.com:8000"
                ],
                "{host_id}"
            );
        }
        assert_eq!(
            settings.get_host_group("static.example.com:8000"),
            ["static.example.com:8000"]
        );
        assert!(settings
            .get_host_group("nobody.example.com:8000")
            .is_empty());

        // The next read has no names: they go.
        settings.set_dynamic_hosts(&hosts(&format!(
            "hosts:\n{}",
            host("a.example.com:8000", "http://127.0.0.1:9001")
        )));

        assert!(settings.additional_hosts.is_empty());
        assert!(settings.dynamic_host_errors.is_empty());
    }

    /// A dynamic host which is refused takes its names with it: they are not served with a
    /// configuration which is not served. One which can not have names is served without them.
    #[test]
    fn a_refused_dynamic_host_takes_its_names_with_it() {
        let mut settings = settings_with_static_host();

        settings.set_dynamic_hosts(&hosts(&format!(
            "hosts:\n{}{}{}",
            host_with_names(
                "static.example.com:8000",
                "http",
                &["d.example.com"],
                "http://127.0.0.1:9001"
            ),
            host_with_names(
                "e.example.com:5432",
                "tcp",
                &["f.example.com"],
                "127.0.0.1:9002"
            ),
            host("g.example.com:8000", "http://127.0.0.1:9003"),
        )));

        assert_eq!(
            sorted(settings.hosts.keys()),
            [
                "e.example.com:5432",
                "g.example.com:8000",
                "static.example.com:8000"
            ]
        );

        let errors = &settings.dynamic_host_errors;
        assert!(errors["static.example.com:8000"]
            .contains("the settings files have a host with this id"));
        assert!(errors["d.example.com:8000"].contains("which is refused"));
        assert!(errors["f.example.com"].contains("type: tcp"));
        assert_eq!(errors.len(), 3, "{errors:?}");
        assert!(settings.additional_hosts.is_empty());
    }

    /// One entry with a variable which is not there is refused on its own: the host and the
    /// rest of its names are served.
    #[test]
    fn a_name_with_a_variable_which_is_not_there_is_refused_alone() {
        let mut settings = SettingsCompiled::default();

        settings.set_dynamic_hosts(&hosts(&format!(
            "hosts:\n{}",
            host_with_names(
                "a.example.com:8000",
                "http",
                &["b.example.com", "${not_there}.example.com"],
                "http://127.0.0.1:9001"
            ),
        )));

        assert!(settings.is_dynamic_host("a.example.com:8000"));
        assert_eq!(
            name_of(&settings, "b.example.com:8000"),
            Some(("a.example.com:8000", true))
        );
        assert!(settings.dynamic_host_errors["${not_there}.example.com"].contains("not_there"));
    }

    /// The url may give no configuration of its own - only names for a host which has one: in
    /// the settings files, or in the `hosts` the url gives. Each of them is taken on its own.
    #[test]
    fn the_additional_hosts_of_the_answer_are_names_of_their_host() {
        let mut settings = settings_with_static_host();
        settings.additional_hosts.insert(
            "www.static.example.com:8000".to_string(),
            AdditionalHost {
                host_id: "static.example.com:8000".to_string(),
                dynamic: false,
            },
        );

        settings.set_dynamic_hosts_answer(&answer(&format!(
            "hosts:\n{}additional_hosts:\n  STATIC.example.com:8000:\n  - t1.example.com\n  - T1.example.com\n  - not a name\n  - static.example.com\n  - www.static.example.com\n  - t2.example.com:8001\n  a.example.com:8000:\n  - a2.example.com\n  www.static.example.com:8000:\n  - t3.example.com\n  missing.example.com:8000:\n  - x.example.com\n",
            host("a.example.com:8000", "http://127.0.0.1:9001"),
        )));

        assert_eq!(
            sorted(settings.hosts.keys()),
            ["a.example.com:8000", "static.example.com:8000"]
        );

        for (name, of, dynamic) in [
            ("t1.example.com:8000", "static.example.com:8000", true),
            ("t3.example.com:8000", "static.example.com:8000", true),
            ("a2.example.com:8000", "a.example.com:8000", true),
            (
                "www.static.example.com:8000",
                "static.example.com:8000",
                false,
            ),
        ] {
            assert_eq!(name_of(&settings, name), Some((of, dynamic)), "{name}");
        }
        assert_eq!(settings.additional_hosts.len(), 4);

        assert_eq!(
            settings.get_host_group("t1.example.com:8000"),
            [
                "static.example.com:8000",
                "t1.example.com:8000",
                "t3.example.com:8000",
                "www.static.example.com:8000"
            ]
        );

        let errors = &settings.dynamic_host_errors;
        assert!(errors["T1.example.com:8000"].contains("the url gives another host"));
        assert!(errors["not a name"].contains("not a domain name"));
        assert!(errors["static.example.com:8000"].contains("the settings files have a host"));
        assert!(errors["www.static.example.com:8000"].contains("the settings files have a host"));
        assert!(errors["t2.example.com:8001"].contains("on port 8001"));
        assert!(errors["x.example.com"].contains("neither the settings files nor"));
        assert_eq!(errors.len(), 6, "{errors:?}");

        // The answer without them: they go, and the host of the files keeps its own name.
        settings.set_dynamic_hosts_answer(&DynamicHostsModel::default());

        assert_eq!(sorted(settings.hosts.keys()), ["static.example.com:8000"]);
        assert_eq!(
            sorted(settings.additional_hosts.keys()),
            ["www.static.example.com:8000"]
        );
        assert!(settings.dynamic_host_errors.is_empty());
    }

    fn files(hosts_yaml: &str, names: &[(&str, &str)]) -> SettingsCompiled {
        let mut result = SettingsCompiled {
            hosts: hosts(&format!("hosts:\n{hosts_yaml}")),
            ..Default::default()
        };

        for (name, host_id) in names {
            result.additional_hosts.insert(
                name.to_string(),
                AdditionalHost {
                    host_id: host_id.to_string(),
                    dynamic: false,
                },
            );
        }

        result
    }

    /// A name which moved from one host to another takes the other host along into the reload -
    /// and so does a name which became a host of its own.
    #[test]
    fn a_reload_takes_along_the_hosts_a_name_moved_between() {
        let applied = files(
            &format!(
                "{}{}{}",
                host("a.localhost:8000", "http://127.0.0.1:9001"),
                host("b.localhost:8000", "http://127.0.0.1:9002"),
                host("c.localhost:8000", "http://127.0.0.1:9003"),
            ),
            &[
                ("n.localhost:8000", "a.localhost:8000"),
                ("m.localhost:8000", "c.localhost:8000"),
            ],
        );

        let fresh = files(
            &format!(
                "{}{}{}{}",
                host("a.localhost:8000", "http://127.0.0.1:9001"),
                host("b.localhost:8000", "http://127.0.0.1:9002"),
                host("c.localhost:8000", "http://127.0.0.1:9003"),
                host("m.localhost:8000", "http://127.0.0.1:9004"),
            ),
            &[("n.localhost:8000", "b.localhost:8000")],
        );

        let reloaded_with = |host_id: &str| -> Vec<String> {
            applied
                .get_hosts_of_files_reloaded_with(&fresh, BTreeSet::from([host_id.to_string()]))
                .into_iter()
                .collect()
        };

        assert_eq!(
            reloaded_with("a.localhost:8000"),
            ["a.localhost:8000", "b.localhost:8000"]
        );
        assert_eq!(
            reloaded_with("b.localhost:8000"),
            ["a.localhost:8000", "b.localhost:8000"]
        );
        assert_eq!(
            reloaded_with("c.localhost:8000"),
            ["c.localhost:8000", "m.localhost:8000"]
        );

        let patched = applied.with_hosts_of_files_from(
            &fresh,
            &BTreeSet::from([
                "a.localhost:8000".to_string(),
                "b.localhost:8000".to_string(),
            ]),
            None,
        );

        assert_eq!(
            name_of(&patched, "n.localhost:8000"),
            Some(("b.localhost:8000", false))
        );
        // A host which is not reloaded keeps what it had.
        assert_eq!(
            name_of(&patched, "m.localhost:8000"),
            Some(("c.localhost:8000", false))
        );
        assert!(!patched.hosts.contains_key("m.localhost:8000"));
    }

    /// The hosts of the url are put next to the reloaded hosts of the files anew: a dynamic host
    /// refused for the id of a host of the files is taken once that host is gone from them.
    #[test]
    fn a_reload_puts_the_dynamic_hosts_anew() {
        let applied_files = files(&host("a.localhost:8000", "http://127.0.0.1:9001"), &[]);
        let answer = answer(&format!(
            "hosts:\n{}",
            host("a.localhost:8000", "http://127.0.0.1:9100")
        ));

        let mut applied = applied_files.clone();
        applied.set_dynamic_hosts_answer(&answer);
        assert!(!applied.is_dynamic_host("a.localhost:8000"));

        let fresh = SettingsCompiled::default();
        let patched = applied.with_hosts_of_files_from(
            &fresh,
            &BTreeSet::from(["a.localhost:8000".to_string()]),
            Some(&answer),
        );

        assert!(patched.is_dynamic_host("a.localhost:8000"));
        assert_eq!(
            patched.hosts["a.localhost:8000"].locations[0]
                .proxy_pass_to
                .as_deref(),
            Some("http://127.0.0.1:9100")
        );
        assert!(patched.dynamic_host_errors.is_empty());
    }
}

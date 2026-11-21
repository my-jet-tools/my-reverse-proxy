use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
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
    /// Each name of `additional_hosts` - of a host of the settings files, of a host of a url, or
    /// of `additional_hosts:` of a url - with the host it is a name of. A request for a name is
    /// served by the configuration of that host, under the name.
    pub additional_hosts: BTreeMap<String, AdditionalHost>,
    /// The entries of `additional_hosts` of the settings files which are ignored - by the host
    /// whose list has them - each with why. The ones of the urls are in `dynamic_host_errors`.
    pub additional_host_errors: BTreeMap<String, Vec<String>>,
    /// `real_time_configurations:` of the settings - the urls more hosts and keys are read from.
    pub real_time_configurations: Option<RealTimeConfigurationsSettings>,
    /// The ids of `hosts` which came from the urls of `real_time_configurations`.
    pub dynamic_host_ids: HashSet<String>,
    /// The hosts and the names of the urls which are not taken, and why: a variable which is not
    /// there, an id the settings files have already, a name which is not a domain name.
    pub dynamic_host_errors: BTreeMap<String, String>,
    /// The sets of `api_keys:` of the settings files, by their ids - each put together from every
    /// file which declares keys under its id.
    pub api_keys: HashMap<String, Vec<crate::types::ProtectedString>>,
    /// The keys the urls of `real_time_configurations` gave, by the ids of their sets. A request
    /// is checked against these together with `api_keys`: see [`Self::get_api_keys`].
    pub dynamic_api_keys: HashMap<String, Vec<crate::types::ProtectedString>>,
    /// The ip lists the urls of `real_time_configurations` gave, by their ids. A list is the
    /// entries of the settings files together with these: see [`Self::get_ip_white_list`].
    pub dynamic_ip_white_lists: HashMap<String, Vec<String>>,
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
    /// `country_white_lists` of the settings files: the countries of each list as written.
    pub country_white_lists: HashMap<String, Vec<String>>,
    pub gateway_server: Option<GatewayServerSettings>,
    pub gateway_clients: HashMap<String, GatewayClientSettings>,
}

/// The lists of `from` added to the ones of `into` with the same ids, each entry once.
fn merge_ip_white_lists(
    into: &mut HashMap<String, Vec<String>>,
    from: &HashMap<String, Vec<String>>,
) {
    for (id, entries) in from {
        let list = into.entry(id.clone()).or_default();

        for entry in entries {
            if !list.contains(entry) {
                list.push(entry.clone());
            }
        }
    }
}

/// Who has an id already, while the answers of the urls are put next to the hosts of the files.
#[derive(Clone, Copy)]
enum TakenBy {
    Files,
    /// The url at this place of `real_time_configurations.urls`.
    Url(usize),
}

impl TakenBy {
    /// Taken by a url lower in the list than the one at `source`: that one writes over it.
    fn is_url_below(&self, source: usize) -> bool {
        matches!(self, Self::Url(other) if *other > source)
    }
}

impl SettingsCompiled {
    pub fn get_endpoint_host_string(
        &self,
        host_id: &str,
    ) -> Result<EndpointHttpHostString, String> {
        EndpointHttpHostString::new(host_id.to_string())
    }

    /// Whether the host came from a url of `real_time_configurations` rather than from a settings
    /// file.
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

    /// Puts what the urls of `real_time_configurations` answered with - `answers`, in the order of
    /// the urls - next to the hosts of the settings files, in place of what they answered before:
    /// the hosts of their `hosts`, each with the names of its own `additional_hosts`, then the
    /// names of their `additional_hosts:` - names of a host the settings files have, or a url
    /// gives; and their keys, with the keys of the files.
    ///
    /// A host or a name of the settings files is never replaced: a dynamic one with its id -
    /// letter case aside - is refused. A host or a name two urls give is taken from the one lower
    /// in the list, and the other is left out without a word: the urls are gone through from the
    /// top, and the one below writes over the one above. Neither does one which can not be taken
    /// keep the others out: it is put into `dynamic_host_errors`, and the rest are taken. Each
    /// name is taken on its own: a wrong entry of a long list does not take the list down.
    pub fn set_real_time_answers(&mut self, answers: &[Arc<RealTimeConfigurationModel>]) {
        self.clear_dynamic_hosts();

        let mut taken: HashMap<String, TakenBy> = self
            .hosts
            .keys()
            .chain(self.additional_hosts.keys())
            .map(|host_id| (host_id.to_ascii_lowercase(), TakenBy::Files))
            .collect();

        // The names of each url, taken once the hosts of every url are there: a url can give
        // names of a host another url gives.
        let mut names_of_hosts: Vec<Vec<(String, HostSettings, Vec<String>)>> =
            vec![Vec::new(); answers.len()];

        // From the url lower in the list up: whatever a url gives first is what one below it
        // left free.
        for (source, answer) in answers.iter().enumerate().rev() {
            // In the order of the ids, so two which can not both be taken are decided the same
            // way at every read.
            let mut host_ids: Vec<&String> = answer.hosts.keys().collect();
            host_ids.sort();

            for host_id in host_ids {
                let entries = answer.hosts[host_id]
                    .additional_hosts
                    .clone()
                    .unwrap_or_default();

                // A url below gives a host with this id: it writes over this one - its names
                // included - and nothing is told.
                if let Ok(id) = self.variables.apply_variables(host_id.clone()) {
                    if taken
                        .get(&id.to_ascii_lowercase())
                        .is_some_and(|taken_by| taken_by.is_url_below(source))
                    {
                        continue;
                    }
                }

                let compiled = super::compile_host(
                    host_id.clone(),
                    answer.hosts[host_id].clone(),
                    &self.variables,
                );

                let (main_host_id, mut host_settings) = match compiled {
                    Ok(compiled) => compiled,
                    Err(err) => {
                        self.add_dynamic_host_error(
                            host_id.clone(),
                            format!("Dynamic host: {err}"),
                        );

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

                if taken.contains_key(&main_host_id.to_ascii_lowercase()) {
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

                taken.insert(main_host_id.to_ascii_lowercase(), TakenBy::Url(source));

                self.dynamic_host_ids.insert(main_host_id.clone());
                self.hosts
                    .insert(main_host_id.clone(), host_settings.clone());

                names_of_hosts[source].push((main_host_id, host_settings, entries));
            }
        }

        for source in (0..answers.len()).rev() {
            for (main_host_id, host_settings, entries) in
                std::mem::take(&mut names_of_hosts[source])
            {
                for entry in &entries {
                    self.take_dynamic_name(
                        &mut taken,
                        source,
                        &main_host_id,
                        &host_settings,
                        entry,
                    );
                }
            }

            let answer = &answers[source];

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

                // The host whose configuration they are served with - the one `key` is a name
                // of, if it is a name itself.
                let Some(main_host_id) = self.get_main_host_id(&key) else {
                    for entry in entries {
                        self.add_dynamic_host_error(
                            entry.trim().to_string(),
                            format!(
                                "Dynamic host is refused: it is in additional_hosts of '{key}', which neither the settings files nor the hosts of the urls have"
                            ),
                        );
                    }
                    continue;
                };

                let host_settings = self.hosts[&main_host_id].clone();

                for entry in entries {
                    self.take_dynamic_name(
                        &mut taken,
                        source,
                        &main_host_id,
                        &host_settings,
                        entry,
                    );
                }
            }
        }

        for answer in answers {
            crate::api_keys::merge_api_keys(&mut self.dynamic_api_keys, &answer.api_keys);
            merge_ip_white_lists(&mut self.dynamic_ip_white_lists, &answer.ip_white_lists);
        }
    }

    /// What one url answered with, and nothing of any other url.
    #[cfg(test)]
    pub fn set_dynamic_hosts_answer(&mut self, answer: &RealTimeConfigurationModel) {
        self.set_real_time_answers(&[Arc::new(answer.clone())]);
    }

    /// The hosts of `hosts`, read from a url with nothing else.
    #[cfg(test)]
    pub fn set_dynamic_hosts(&mut self, hosts: &HashMap<String, HostSettings>) {
        self.set_dynamic_hosts_answer(&RealTimeConfigurationModel {
            hosts: hosts.clone(),
            ..Default::default()
        });
    }

    /// Takes away what the urls answered with: their hosts, their names, their errors, their
    /// keys.
    fn clear_dynamic_hosts(&mut self) {
        for host_id in self.dynamic_host_ids.drain() {
            self.hosts.remove(&host_id);
        }

        self.additional_hosts.retain(|_, itm| !itm.dynamic);
        self.dynamic_host_errors.clear();
        self.dynamic_api_keys.clear();
        self.dynamic_ip_white_lists.clear();
    }

    /// The ip list `id`: the entries the settings files declare, with the ones the urls gave under
    /// the same id. `None` if neither declares it - then nobody is let in by it.
    pub fn get_ip_white_list(&self, id: &str) -> Option<Vec<String>> {
        let from_files = self.ip_white_lists.get(id);
        let from_urls = self.dynamic_ip_white_lists.get(id);

        if from_files.is_none() && from_urls.is_none() {
            return None;
        }

        let mut result = from_files.cloned().unwrap_or_default();

        for entry in from_urls.into_iter().flatten() {
            if !result.contains(entry) {
                result.push(entry.clone());
            }
        }

        Some(result)
    }

    /// Every set of keys requests are checked against: the keys the settings files declare, with
    /// the ones the urls gave under the same ids.
    pub fn get_api_keys(&self) -> HashMap<String, Vec<crate::types::ProtectedString>> {
        let mut result = self.api_keys.clone();
        crate::api_keys::merge_api_keys(&mut result, &self.dynamic_api_keys);
        result
    }

    /// Takes `entry` - an entry of `additional_hosts` of `main_host_id`, given by the url at
    /// `source` - as a name of that host, unless it is not one, or is taken already: then it is
    /// refused - or left out without a word, if a url below has it.
    fn take_dynamic_name(
        &mut self,
        taken: &mut HashMap<String, TakenBy>,
        source: usize,
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

        match taken.get(&name.to_ascii_lowercase()) {
            None => {}
            Some(taken_by) if taken_by.is_url_below(source) => return,
            Some(_) => {
                let err = self.get_refusal_of_taken_id(&name);
                self.add_dynamic_host_error(
                    name,
                    format!("{err} (it is in additional_hosts of '{main_host_id}')"),
                );
                return;
            }
        }

        taken.insert(name.to_ascii_lowercase(), TakenBy::Url(source));

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
    /// `answers` - the answers of the urls of `real_time_configurations` - give is put next to
    /// them anew: a dynamic host is taken or refused against the hosts of the files as they are
    /// now.
    pub fn with_hosts_of_files_from(
        &self,
        fresh: &SettingsCompiled,
        host_ids: &BTreeSet<String>,
        answers: &[Arc<RealTimeConfigurationModel>],
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

        if !answers.is_empty() {
            result.set_real_time_answers(answers);
        }

        result
    }

    /// The address the control port listens on: `global_settings.http_control_port` and
    /// `http_control_ip`, `127.0.0.1:8000` when they say nothing - checked when the settings are
    /// loaded.
    pub fn get_http_control_addr(&self) -> Result<SocketAddr, String> {
        match self.global_settings.as_ref() {
            Some(global_settings) => global_settings.get_http_control_addr(),
            None => Ok(crate::settings::default_http_control_addr()),
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

    /// The limits of the request bodies an endpoint holds in memory: `endpoint_max_body` - its own
    /// `max_buffered_request_body` - else the one of `global_settings`, and the total of
    /// `global_settings`.
    pub fn get_buffered_body_limits(
        &self,
        endpoint_max_body: Option<&str>,
    ) -> Result<crate::types::BufferedBodyLimits, String> {
        let global = self.global_settings.as_ref();

        crate::types::BufferedBodyLimits::resolve(
            global.and_then(|g| g.max_buffered_request_body.as_deref()),
            global.and_then(|g| g.max_buffered_request_bodies_total.as_deref()),
            endpoint_max_body,
        )
    }

    /// `max_request_body` of an endpoint whose own is `endpoint_max_request_body`: else the one
    /// of `global_settings`.
    pub fn get_max_request_body(
        &self,
        endpoint_max_request_body: Option<&str>,
    ) -> Result<Option<usize>, String> {
        crate::types::resolve_max_request_body(
            self.global_settings
                .as_ref()
                .and_then(|g| g.max_request_body.as_deref()),
            endpoint_max_request_body,
        )
    }

    /// `access_log` of `global_settings`: `None` - no access log.
    pub fn get_access_log(&self) -> Result<Option<crate::access_log::AccessLogSettings>, String> {
        match self.global_settings.as_ref() {
            Some(global_settings) => global_settings.get_access_log(),
            None => Ok(None),
        }
    }

    /// `max_connections` and `max_connections_per_ip`, out of `global_settings`.
    pub fn get_connection_limits(&self) -> Result<crate::app::ConnectionLimitsSettings, String> {
        match self.global_settings.as_ref() {
            Some(global_settings) => global_settings.get_connection_limits(),
            None => Ok(crate::app::ConnectionLimitsSettings::default()),
        }
    }

    /// The limits of a client connection, out of `global_settings`.
    pub fn get_connection_settings(&self) -> Result<crate::types::ConnectionSettings, String> {
        match self.global_settings.as_ref() {
            Some(global_settings) => global_settings.get_connection_settings(),
            None => Ok(crate::types::ConnectionSettings::default()),
        }
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

    /// `global_settings.control_unix_socket`: the unix socket the control port is served on too.
    pub fn get_control_unix_socket(&self) -> Result<Option<String>, String> {
        match self.global_settings.as_ref() {
            Some(global_settings) => global_settings.get_control_unix_socket(),
            None => Ok(None),
        }
    }

    /// `global_settings.secure_store_file`, or `~/.my-reverse-proxy-secure`.
    pub fn get_secure_store_file(&self) -> String {
        self.global_settings
            .as_ref()
            .and_then(|itm| itm.secure_store_file.clone())
            .filter(|itm| !itm.trim().is_empty())
            .unwrap_or_else(|| crate::consts::DEFAULT_SECURE_STORE_FILE.to_string())
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

    /// A list is the entries of the files with the ones of every url under its id, each once.
    #[test]
    fn an_ip_list_is_put_together_from_the_files_and_the_urls() {
        let mut settings = SettingsCompiled::default();
        settings
            .ip_white_lists
            .insert("office".to_string(), vec!["10.0.0.1".to_string()]);

        let first = answer(
            "ip_white_lists:\n  office:\n  - 10.0.0.2\n  - 10.0.0.1\n  vpn:\n  - 10.8.0.1\n",
        );
        let second = answer("ip_white_lists:\n  office:\n  - 10.0.0.3\n");

        settings.set_real_time_answers(&[Arc::new(first), Arc::new(second)]);

        assert_eq!(
            settings.get_ip_white_list("office").unwrap(),
            ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        );
        assert_eq!(settings.get_ip_white_list("vpn").unwrap(), ["10.8.0.1"]);
        assert_eq!(settings.get_ip_white_list("nobody"), None);

        // The urls give nothing any more: what the files declare stays, the rest goes.
        settings.set_real_time_answers(&[]);

        assert_eq!(settings.get_ip_white_list("office").unwrap(), ["10.0.0.1"]);
        assert_eq!(settings.get_ip_white_list("vpn"), None);
    }

    fn hosts(yaml: &str) -> HashMap<String, HostSettings> {
        RealTimeConfigurationModel::parse(yaml.as_bytes())
            .unwrap()
            .unwrap()
            .hosts
    }

    fn answer(yaml: &str) -> RealTimeConfigurationModel {
        RealTimeConfigurationModel::parse(yaml.as_bytes())
            .unwrap()
            .unwrap()
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
        settings.set_dynamic_hosts_answer(&RealTimeConfigurationModel::default());

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
            &[],
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
            &[Arc::new(answer.clone())],
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

    fn answers(yamls: &[String]) -> Vec<Arc<RealTimeConfigurationModel>> {
        yamls.iter().map(|yaml| Arc::new(answer(yaml))).collect()
    }

    fn upstream_of<'s>(settings: &'s SettingsCompiled, host_id: &str) -> Option<&'s str> {
        settings.hosts.get(host_id)?.locations[0]
            .proxy_pass_to
            .as_deref()
    }

    /// The urls are gone through from the top, and the one lower in the list writes over the one
    /// above: nothing is told about the host which is written over.
    #[test]
    fn a_host_two_urls_give_is_taken_from_the_lower_one() {
        let mut settings = settings_with_static_host();

        settings.set_real_time_answers(&answers(&[
            format!(
                "hosts:\n{}{}",
                host("a.example.com:8000", "http://127.0.0.1:9001"),
                host("only-upper.example.com:8000", "http://127.0.0.1:9002"),
            ),
            format!(
                "hosts:\n{}{}",
                host("A.example.com:8000", "http://127.0.0.1:9101"),
                host("only-lower.example.com:8000", "http://127.0.0.1:9102"),
            ),
        ]));

        assert_eq!(
            upstream_of(&settings, "A.example.com:8000"),
            Some("http://127.0.0.1:9101")
        );
        assert!(!settings.hosts.contains_key("a.example.com:8000"));
        assert_eq!(
            upstream_of(&settings, "only-upper.example.com:8000"),
            Some("http://127.0.0.1:9002")
        );
        assert_eq!(
            upstream_of(&settings, "only-lower.example.com:8000"),
            Some("http://127.0.0.1:9102")
        );
        assert!(
            settings.dynamic_host_errors.is_empty(),
            "{:?}",
            settings.dynamic_host_errors
        );
    }

    /// The names of a host written over go with it: the host is served as the url below gives
    /// it, names included.
    #[test]
    fn the_names_of_a_host_written_over_go_with_it() {
        let mut settings = settings_with_static_host();

        settings.set_real_time_answers(&answers(&[
            format!(
                "hosts:\n{}",
                host_with_names(
                    "a.example.com:8000",
                    "http",
                    &["upper-name.example.com"],
                    "http://127.0.0.1:9001"
                ),
            ),
            format!(
                "hosts:\n{}",
                host_with_names(
                    "a.example.com:8000",
                    "http",
                    &["lower-name.example.com"],
                    "http://127.0.0.1:9101"
                ),
            ),
        ]));

        assert_eq!(
            name_of(&settings, "lower-name.example.com:8000"),
            Some(("a.example.com:8000", true))
        );
        assert_eq!(name_of(&settings, "upper-name.example.com:8000"), None);
        assert!(
            settings.dynamic_host_errors.is_empty(),
            "{:?}",
            settings.dynamic_host_errors
        );
    }

    #[test]
    fn a_name_two_urls_give_is_taken_from_the_lower_one() {
        let mut settings = settings_with_static_host();

        settings.set_real_time_answers(&answers(&[
            format!(
                "hosts:\n{}{}additional_hosts:\n  a.example.com:8000:\n  - tenant.example.com\n",
                host("a.example.com:8000", "http://127.0.0.1:9001"),
                host("b.example.com:8000", "http://127.0.0.1:9002"),
            ),
            "additional_hosts:\n  b.example.com:8000:\n  - tenant.example.com\n".to_string(),
        ]));

        assert_eq!(
            name_of(&settings, "tenant.example.com:8000"),
            Some(("b.example.com:8000", true))
        );
        assert!(
            settings.dynamic_host_errors.is_empty(),
            "{:?}",
            settings.dynamic_host_errors
        );
    }

    /// One url gives the configuration, another the names it is served under.
    #[test]
    fn a_url_may_give_names_of_a_host_another_url_gives() {
        let mut settings = settings_with_static_host();

        for order in [[0, 1], [1, 0]] {
            let given = [
                format!(
                    "hosts:\n{}",
                    host("a.example.com:8000", "http://127.0.0.1:9001")
                ),
                "additional_hosts:\n  a.example.com:8000:\n  - tenant.example.com\n".to_string(),
            ];

            settings.set_real_time_answers(&answers(&[
                given[order[0]].clone(),
                given[order[1]].clone(),
            ]));

            assert_eq!(
                name_of(&settings, "tenant.example.com:8000"),
                Some(("a.example.com:8000", true)),
                "{order:?}"
            );
            assert!(
                settings.dynamic_host_errors.is_empty(),
                "{:?}",
                settings.dynamic_host_errors
            );
        }
    }

    /// Whatever the place of the url in the list.
    #[test]
    fn no_url_replaces_a_host_of_the_files() {
        let mut settings = settings_with_static_host();
        let static_host_id = settings.hosts.keys().next().unwrap().clone();

        settings.set_real_time_answers(&answers(&[
            format!(
                "hosts:\n{}",
                host("a.example.com:8000", "http://127.0.0.1:9001")
            ),
            format!("hosts:\n{}", host(&static_host_id, "http://127.0.0.1:9101")),
        ]));

        assert!(!settings.is_dynamic_host(&static_host_id));
        assert!(settings.dynamic_host_errors[&static_host_id]
            .contains("the settings files have a host with this id"));
    }

    /// The keys of one id - from the files and from every url - make one set; another read of the
    /// urls replaces what they gave before, and the keys of the files stay.
    #[test]
    fn the_keys_of_the_urls_are_put_together_with_the_keys_of_the_files() {
        let mut settings = settings_with_static_host();
        settings
            .api_keys
            .insert("mcp_clients".to_string(), vec!["file-key".into()]);

        settings.set_real_time_answers(&answers(&[
            "api_keys:\n  mcp_clients:\n  - upper-key\n  admins:\n  - admin-key\n".to_string(),
            "api_keys:\n  mcp_clients:\n  - lower-key\n  - upper-key\n".to_string(),
        ]));

        let api_keys = settings.get_api_keys();
        let mut clients = api_keys["mcp_clients"].clone();
        clients.sort();
        assert_eq!(clients, ["file-key", "lower-key", "upper-key"]);
        assert_eq!(api_keys["admins"], ["admin-key"]);

        settings.set_real_time_answers(&answers(&["hosts: {}\n".to_string()]));

        let api_keys = settings.get_api_keys();
        assert_eq!(api_keys["mcp_clients"], ["file-key"]);
        assert!(!api_keys.contains_key("admins"));
    }
}

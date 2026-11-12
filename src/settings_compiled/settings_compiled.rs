use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::IpAddr,
};

use rust_extensions::duration_utils::DurationExtensions;

use crate::{configurations::EndpointHttpHostString, settings::*};

use super::VariablesCompiled;

#[derive(Debug, Default, Clone)]

pub struct SettingsCompiled {
    pub ssh: HashMap<String, SshConfigSettings>,
    /// The hosts of the settings files, and the dynamic ones next to them: those are named in
    /// `dynamic_host_ids`. The `additional_hosts` of a host are hosts of their own here, with a
    /// copy of its settings - named in `additional_host_of`.
    pub hosts: HashMap<String, HostSettings>,
    /// The hosts of `hosts` which are in `additional_hosts` of another host, and that host.
    pub additional_host_of: HashMap<String, String>,
    /// `dynamic_hosts:` of the settings - the url more hosts are read from.
    pub dynamic_hosts: Option<DynamicHostsSettings>,
    /// The ids of `hosts` which came from `dynamic_hosts.url`.
    pub dynamic_host_ids: HashSet<String>,
    /// The hosts of `dynamic_hosts.url` which are not in `hosts`, and why: a variable which is
    /// not there, an id the settings files have a host of their own for.
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

    /// The host whose `additional_hosts` this host is in - `None` for a host written as a key.
    pub fn get_additional_host_of(&self, host_id: &str) -> Option<&String> {
        self.additional_host_of.get(host_id)
    }

    /// The hosts served with the configuration of `host_id` - letter case aside: the host its
    /// configuration is written under first, then its `additional_hosts`, by their ids. Empty if
    /// the settings have no such host.
    pub fn get_host_group(&self, host_id: &str) -> Vec<String> {
        let Some(host_id) = self
            .hosts
            .keys()
            .find(|existing| existing.eq_ignore_ascii_case(host_id))
        else {
            return Vec::new();
        };

        let main_host_id = self
            .additional_host_of
            .get(host_id)
            .unwrap_or(host_id)
            .clone();

        let mut additional_hosts: Vec<String> = self
            .additional_host_of
            .iter()
            .filter(|(_, of)| **of == main_host_id)
            .map(|(additional_host_id, _)| additional_host_id.clone())
            .collect();
        additional_hosts.sort();

        let mut result = Vec::with_capacity(additional_hosts.len() + 1);
        if self.hosts.contains_key(&main_host_id) {
            result.push(main_host_id);
        }
        result.extend(additional_hosts);
        result
    }

    /// Puts a host of the settings files into `hosts`.
    ///
    /// A host of `additional_hosts` is in no other place of the files - letter case aside: two
    /// configurations for one host would be served depending on the order the files are read in.
    /// A host written as a key again replaces the one before, as it always has - and the
    /// additional hosts of that one go with it.
    pub(crate) fn insert_host_of_files(
        &mut self,
        expanded: super::ExpandedHost,
    ) -> Result<(), String> {
        let super::ExpandedHost {
            host_id,
            host_settings,
            additional_host_of,
        } = expanded;

        let same_host = self
            .hosts
            .keys()
            .find(|existing| existing.eq_ignore_ascii_case(&host_id))
            .cloned();

        if let Some(same_host) = same_host {
            let in_additional_hosts_of = additional_host_of
                .as_ref()
                .or_else(|| self.additional_host_of.get(&same_host));

            if let Some(main_host_id) = in_additional_hosts_of {
                return Err(format!(
                    "Host '{host_id}' is declared more than once: it is in additional_hosts of '{main_host_id}', and the settings have another host with this id"
                ));
            }

            if same_host == host_id {
                let replaced_additional_hosts: Vec<String> = self
                    .additional_host_of
                    .iter()
                    .filter(|(_, of)| **of == host_id)
                    .map(|(additional_host_id, _)| additional_host_id.clone())
                    .collect();

                for additional_host_id in replaced_additional_hosts {
                    self.additional_host_of.remove(&additional_host_id);
                    self.hosts.remove(&additional_host_id);
                }
            }
        }

        if let Some(main_host_id) = additional_host_of {
            self.additional_host_of
                .insert(host_id.clone(), main_host_id);
        }

        self.hosts.insert(host_id, host_settings);

        Ok(())
    }

    /// Puts what `dynamic_hosts.url` answered with next to the hosts of the settings files, in
    /// place of the dynamic hosts there were before: the hosts of its `hosts`, each with its own
    /// `additional_hosts`, then the hosts of its `additional_hosts` - served with the
    /// configuration of a host the settings files have, or its `hosts` have.
    ///
    /// A host of the settings files is never replaced: a dynamic host with its id - letter case
    /// aside - is refused. Neither does one dynamic host which can not be served keep the others
    /// out: it is put into `dynamic_host_errors`, and the rest are taken. Each additional host is
    /// one on its own as well: a wrong entry of a long list does not take the list down.
    pub fn set_dynamic_hosts_answer(&mut self, answer: &DynamicHostsModel) {
        for host_id in self.dynamic_host_ids.drain() {
            self.hosts.remove(&host_id);
            self.additional_host_of.remove(&host_id);
        }
        self.dynamic_host_errors.clear();

        let mut taken_ids: HashSet<String> = self
            .hosts
            .keys()
            .map(|host_id| host_id.to_ascii_lowercase())
            .collect();

        // In the order of the ids, so two hosts which can not both be taken are decided the
        // same way at every read.
        let mut host_ids: Vec<&String> = answer.hosts.keys().collect();
        host_ids.sort();

        for host_id in host_ids {
            let compiled = super::compile_host(
                host_id.clone(),
                answer.hosts[host_id].clone(),
                &self.variables,
            );

            let (main_host_id, mut host_settings) = match compiled {
                Ok(compiled) => compiled,
                Err(err) => {
                    self.dynamic_host_errors
                        .insert(host_id.clone(), format!("Dynamic host: {err}"));
                    continue;
                }
            };

            let additional_hosts = host_settings.additional_hosts.take().unwrap_or_default();

            let taken = self.take_dynamic_host(
                &mut taken_ids,
                main_host_id.clone(),
                host_settings.clone(),
                None,
            );

            if taken {
                self.take_dynamic_additional_hosts(
                    &mut taken_ids,
                    &main_host_id,
                    &host_settings,
                    &additional_hosts,
                );
                continue;
            }

            // They are not served with a configuration which is not served.
            for additional_host in &additional_hosts {
                self.dynamic_host_errors.insert(
                    get_additional_host_error_key(&main_host_id, &host_settings, additional_host),
                    format!(
                        "Dynamic host is refused: it is in additional_hosts of '{main_host_id}', which is refused"
                    ),
                );
            }
        }

        let mut main_host_ids: Vec<&String> = answer.additional_hosts.keys().collect();
        main_host_ids.sort();

        for main_host_id in main_host_ids {
            let additional_hosts = &answer.additional_hosts[main_host_id];

            let main_host_id = match self.variables.apply_variables(main_host_id.clone()) {
                Ok(main_host_id) => main_host_id,
                Err(err) => {
                    for additional_host in additional_hosts {
                        self.dynamic_host_errors.insert(
                            additional_host.trim().to_string(),
                            format!("Dynamic host: {err}"),
                        );
                    }
                    continue;
                }
            };

            // The host whose configuration they are served with - the one it is written under,
            // if it is an additional host itself.
            let configuration_host_id = self
                .hosts
                .keys()
                .find(|existing| existing.eq_ignore_ascii_case(&main_host_id))
                .map(|found| self.additional_host_of.get(found).unwrap_or(found).clone());

            let Some(configuration_host_id) = configuration_host_id else {
                for additional_host in additional_hosts {
                    self.dynamic_host_errors.insert(
                        additional_host.trim().to_string(),
                        format!(
                            "Dynamic host is refused: it is in additional_hosts of '{main_host_id}', which neither the settings files nor the hosts of the url have"
                        ),
                    );
                }
                continue;
            };

            let host_settings = self.hosts[&configuration_host_id].clone();

            let mut compiled_additional_hosts = Vec::with_capacity(additional_hosts.len());
            for additional_host in additional_hosts {
                match self.variables.apply_variables(additional_host.clone()) {
                    Ok(additional_host) => compiled_additional_hosts.push(additional_host),
                    Err(err) => {
                        self.dynamic_host_errors.insert(
                            additional_host.trim().to_string(),
                            format!("Dynamic host: {err}"),
                        );
                    }
                }
            }

            self.take_dynamic_additional_hosts(
                &mut taken_ids,
                &configuration_host_id,
                &host_settings,
                &compiled_additional_hosts,
            );
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

    /// Takes the dynamic host `host_id`, unless a host with its id - letter case aside - is
    /// there already: then it is refused, and `false` is returned.
    fn take_dynamic_host(
        &mut self,
        taken_ids: &mut HashSet<String>,
        host_id: String,
        host_settings: HostSettings,
        additional_host_of: Option<&str>,
    ) -> bool {
        if !taken_ids.insert(host_id.to_ascii_lowercase()) {
            let err = if self.is_static_host(&host_id) {
                "Dynamic host is refused: the settings files have a host with this id"
            } else {
                "Dynamic host is refused: the url gives another host with this id"
            };

            let err = match additional_host_of {
                Some(main_host_id) => {
                    format!("{err} (it is in additional_hosts of '{main_host_id}')")
                }
                None => err.to_string(),
            };

            self.dynamic_host_errors.insert(host_id, err);
            return false;
        }

        if let Some(main_host_id) = additional_host_of {
            self.additional_host_of
                .insert(host_id.clone(), main_host_id.to_string());
        }

        self.dynamic_host_ids.insert(host_id.clone());
        self.hosts.insert(host_id, host_settings);

        true
    }

    /// Takes each of `additional_hosts` as a dynamic host with `host_settings` - the
    /// configuration of `main_host_id` - on its own: one which can not be is refused, and the
    /// others are taken.
    fn take_dynamic_additional_hosts(
        &mut self,
        taken_ids: &mut HashSet<String>,
        main_host_id: &str,
        host_settings: &HostSettings,
        additional_hosts: &[String],
    ) {
        for additional_host in additional_hosts {
            match super::get_additional_host_id(main_host_id, host_settings, additional_host) {
                Ok(additional_host_id) => {
                    self.take_dynamic_host(
                        taken_ids,
                        additional_host_id,
                        host_settings.clone(),
                        Some(main_host_id),
                    );
                }
                Err(err) => {
                    self.dynamic_host_errors.insert(
                        additional_host.trim().to_string(),
                        format!("Dynamic host: {err}"),
                    );
                }
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

    /// A host of the settings files - letter case aside.
    pub fn is_static_host(&self, host_id: &str) -> bool {
        self.hosts.keys().any(|existing| {
            existing.eq_ignore_ascii_case(host_id) && !self.dynamic_host_ids.contains(existing)
        })
    }

    /// The ids of the hosts of the settings files, in lower case.
    pub fn get_static_host_ids_lowercase(&self) -> HashSet<String> {
        self.hosts
            .keys()
            .filter(|host_id| !self.dynamic_host_ids.contains(*host_id))
            .map(|host_id| host_id.to_ascii_lowercase())
            .collect()
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

/// What the error of an entry of `additional_hosts` of `main_host_id` is put under: its host id,
/// or the entry as it is written if it is not one.
fn get_additional_host_error_key(
    main_host_id: &str,
    host_settings: &HostSettings,
    additional_host: &str,
) -> String {
    super::get_additional_host_id(main_host_id, host_settings, additional_host)
        .unwrap_or_else(|_| additional_host.trim().to_string())
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

    fn host(host_id: &str, proxy_pass_to: &str) -> String {
        format!(
            "  '{host_id}':\n    endpoint:\n      type: http\n    locations:\n    - proxy_pass_to: '{proxy_pass_to}'\n"
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

    #[test]
    fn the_dynamic_hosts_are_next_to_the_hosts_of_the_files() {
        let mut settings = settings_with_static_host();

        settings.set_dynamic_hosts(&hosts(&format!(
            "hosts:\n{}{}",
            host("a.example.com:8000", "http://127.0.0.1:9001"),
            host("b.example.com:8001", "http://127.0.0.1:9002"),
        )));

        let mut host_ids: Vec<_> = settings.hosts.keys().cloned().collect();
        host_ids.sort();
        assert_eq!(
            host_ids,
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

    fn host_with_additional_hosts(
        host_id: &str,
        endpoint_type: &str,
        additional_hosts: &[&str],
        proxy_pass_to: &str,
    ) -> String {
        let additional_hosts: String = additional_hosts
            .iter()
            .map(|itm| format!("    - '{itm}'\n"))
            .collect();

        format!(
            "  '{host_id}':\n    additional_hosts:\n{additional_hosts}    endpoint:\n      type: {endpoint_type}\n    locations:\n    - proxy_pass_to: '{proxy_pass_to}'\n"
        )
    }

    /// The `additional_hosts` of a dynamic host are dynamic hosts with its configuration. One the
    /// files have already is refused, on its own; the rest are served.
    #[test]
    fn the_additional_hosts_of_a_dynamic_host_are_dynamic_hosts() {
        let mut settings = settings_with_static_host();

        settings.set_dynamic_hosts(&hosts(&format!(
            "hosts:\n{}",
            host_with_additional_hosts(
                "a.example.com:8000",
                "http",
                &["b.example.com", "STATIC.example.com", "c.example.com:8001"],
                "http://127.0.0.1:9001"
            ),
        )));

        for host_id in [
            "a.example.com:8000",
            "b.example.com:8000",
            "c.example.com:8001",
        ] {
            assert!(settings.is_dynamic_host(host_id), "{host_id}");
            assert_eq!(
                settings.hosts[host_id].locations[0]
                    .proxy_pass_to
                    .as_deref(),
                Some("http://127.0.0.1:9001"),
                "{host_id}"
            );
            assert!(settings.hosts[host_id].additional_hosts.is_none());
        }

        assert_eq!(settings.get_additional_host_of("a.example.com:8000"), None);
        assert_eq!(
            settings
                .get_additional_host_of("b.example.com:8000")
                .map(|itm| itm.as_str()),
            Some("a.example.com:8000")
        );

        // The host of the files keeps its own configuration.
        assert_eq!(
            settings.hosts["static.example.com:8000"].locations[0]
                .proxy_pass_to
                .as_deref(),
            Some("http://127.0.0.1:9000")
        );
        assert!(settings.dynamic_host_errors["STATIC.example.com:8000"]
            .contains("additional_hosts of 'a.example.com:8000'"));
        assert_eq!(settings.dynamic_host_errors.len(), 1);

        // Whichever of them is named, the group is the same.
        for host_id in ["a.example.com:8000", "C.example.com:8001"] {
            assert_eq!(
                settings.get_host_group(host_id),
                [
                    "a.example.com:8000",
                    "b.example.com:8000",
                    "c.example.com:8001"
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

        // The next read has no additional hosts: they go.
        settings.set_dynamic_hosts(&hosts(&format!(
            "hosts:\n{}",
            host("a.example.com:8000", "http://127.0.0.1:9001")
        )));

        assert!(!settings.hosts.contains_key("b.example.com:8000"));
        assert!(!settings.hosts.contains_key("c.example.com:8001"));
        assert!(settings.additional_host_of.is_empty());
        assert!(settings.dynamic_host_errors.is_empty());
    }

    /// A dynamic host which is refused takes its additional hosts with it: they are not served
    /// with a configuration which is not served. One which can not have additional hosts is
    /// served without them.
    #[test]
    fn a_refused_dynamic_host_takes_its_additional_hosts_with_it() {
        let mut settings = settings_with_static_host();

        settings.set_dynamic_hosts(&hosts(&format!(
            "hosts:\n{}{}{}",
            host_with_additional_hosts(
                "static.example.com:8000",
                "http",
                &["d.example.com"],
                "http://127.0.0.1:9001"
            ),
            host_with_additional_hosts(
                "e.example.com:5432",
                "tcp",
                &["f.example.com"],
                "127.0.0.1:9002"
            ),
            host("g.example.com:8000", "http://127.0.0.1:9003"),
        )));

        let mut host_ids: Vec<_> = settings.hosts.keys().cloned().collect();
        host_ids.sort();
        assert_eq!(
            host_ids,
            [
                "e.example.com:5432",
                "g.example.com:8000",
                "static.example.com:8000"
            ]
        );

        assert!(settings.dynamic_host_errors["static.example.com:8000"]
            .contains("the settings files have a host with this id"));
        assert!(settings.dynamic_host_errors["d.example.com:8000"].contains("which is refused"));
        assert!(settings.dynamic_host_errors["f.example.com"].contains("type: tcp"));
        assert_eq!(settings.dynamic_host_errors.len(), 3);
        assert!(settings.additional_host_of.is_empty());
    }

    /// The url may give no configuration of its own - only more hosts for a host which has one:
    /// in the settings files, or in the `hosts` the url gives. Each of them is taken on its own.
    #[test]
    fn the_additional_hosts_of_the_answer_are_served_with_the_configuration_of_their_host() {
        let mut settings = settings_with_static_host();

        let answer = DynamicHostsModel::parse(
            format!(
                "hosts:\n{}additional_hosts:\n  STATIC.example.com:8000:\n  - t1.example.com\n  - T1.example.com\n  - not a name\n  - static.example.com\n  - t2.example.com:8001\n  a.example.com:8000:\n  - a2.example.com\n  missing.example.com:8000:\n  - x.example.com\n",
                host("a.example.com:8000", "http://127.0.0.1:9001"),
            )
            .as_bytes(),
        )
        .unwrap()
        .unwrap();

        settings.set_dynamic_hosts_answer(&answer);

        let mut host_ids: Vec<_> = settings.hosts.keys().cloned().collect();
        host_ids.sort();
        assert_eq!(
            host_ids,
            [
                "a.example.com:8000",
                "a2.example.com:8000",
                "static.example.com:8000",
                "t1.example.com:8000",
                "t2.example.com:8001"
            ]
        );

        for (host_id, of, proxy_pass_to) in [
            (
                "t1.example.com:8000",
                "static.example.com:8000",
                "http://127.0.0.1:9000",
            ),
            (
                "t2.example.com:8001",
                "static.example.com:8000",
                "http://127.0.0.1:9000",
            ),
            (
                "a2.example.com:8000",
                "a.example.com:8000",
                "http://127.0.0.1:9001",
            ),
        ] {
            assert!(settings.is_dynamic_host(host_id), "{host_id}");
            assert_eq!(
                settings
                    .get_additional_host_of(host_id)
                    .map(|itm| itm.as_str()),
                Some(of),
                "{host_id}"
            );
            assert_eq!(
                settings.hosts[host_id].locations[0]
                    .proxy_pass_to
                    .as_deref(),
                Some(proxy_pass_to),
                "{host_id}"
            );
        }

        assert!(!settings.is_dynamic_host("static.example.com:8000"));
        assert_eq!(
            settings.get_host_group("t2.example.com:8001"),
            [
                "static.example.com:8000",
                "t1.example.com:8000",
                "t2.example.com:8001"
            ]
        );

        let errors = &settings.dynamic_host_errors;
        assert!(errors["T1.example.com:8000"].contains("the url gives another host"));
        assert!(errors["not a name"].contains("neither a domain name"));
        assert!(errors["static.example.com:8000"].contains("the settings files have a host"));
        assert!(errors["x.example.com"].contains("neither the settings files nor"));
        assert_eq!(errors.len(), 4, "{errors:?}");

        // The answer without them: they go, and the host of the files stays as it is.
        settings.set_dynamic_hosts_answer(&DynamicHostsModel::default());

        assert_eq!(
            settings.hosts.keys().collect::<Vec<_>>(),
            ["static.example.com:8000"]
        );
        assert!(settings.additional_host_of.is_empty());
        assert!(settings.dynamic_host_errors.is_empty());
    }
}

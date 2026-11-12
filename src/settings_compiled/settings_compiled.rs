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
    /// `dynamic_host_ids`.
    pub hosts: HashMap<String, HostSettings>,
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

    /// Puts the hosts read from `dynamic_hosts.url` next to the hosts of the settings files,
    /// in place of the dynamic hosts there were before.
    ///
    /// A host of the settings files is never replaced: a dynamic host with its id - letter case
    /// aside - is refused. Neither does one dynamic host which can not be compiled keep the
    /// others out: it is put into `dynamic_host_errors`, and the rest are taken.
    pub fn set_dynamic_hosts(&mut self, hosts: &HashMap<String, HostSettings>) {
        for host_id in self.dynamic_host_ids.drain() {
            self.hosts.remove(&host_id);
        }
        self.dynamic_host_errors.clear();

        let mut taken_ids: HashSet<String> = self
            .hosts
            .keys()
            .map(|host_id| host_id.to_ascii_lowercase())
            .collect();

        // In the order of the ids, so two hosts which can not both be taken are decided the
        // same way at every read.
        let mut host_ids: Vec<&String> = hosts.keys().collect();
        host_ids.sort();

        for host_id in host_ids {
            let compiled =
                super::compile_host(host_id.clone(), hosts[host_id].clone(), &self.variables);

            let (compiled_id, host_settings) = match compiled {
                Ok(compiled) => compiled,
                Err(err) => {
                    self.dynamic_host_errors
                        .insert(host_id.clone(), format!("Dynamic host: {err}"));
                    continue;
                }
            };

            if !taken_ids.insert(compiled_id.to_ascii_lowercase()) {
                let err = if self.is_static_host(&compiled_id) {
                    "Dynamic host is refused: the settings files have a host with this id"
                } else {
                    "Dynamic host is refused: the url gives another host with this id"
                };
                self.dynamic_host_errors
                    .insert(compiled_id, err.to_string());
                continue;
            }

            self.dynamic_host_ids.insert(compiled_id.clone());
            self.hosts.insert(compiled_id, host_settings);
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
}

use std::{collections::HashMap, time::Duration};

use serde::*;

use super::HostSettings;

/// The shortest `refresh_interval` taken: a smaller one - a zero above all - would ask the urls
/// without a pause.
pub const MIN_REAL_TIME_CONFIGURATIONS_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

/// `real_time_configurations:` - the urls the proxy reads more hosts and api keys from, and how
/// often it reads them. One interval and one timeout for all of them.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct RealTimeConfigurationsSettings {
    /// Each answers with a [`RealTimeConfigurationModel`]. A host which two of them give is
    /// served as the one lower in the list gives it.
    pub urls: Vec<String>,
    /// Milliseconds between two reads of the urls. Absent:
    /// [`DEFAULT_REAL_TIME_CONFIGURATIONS_REFRESH_INTERVAL`].
    ///
    /// [`DEFAULT_REAL_TIME_CONFIGURATIONS_REFRESH_INTERVAL`]: crate::consts::DEFAULT_REAL_TIME_CONFIGURATIONS_REFRESH_INTERVAL
    pub refresh_interval: Option<u64>,
    /// Milliseconds a read of a url may take - the request and its whole answer. Absent:
    /// [`DEFAULT_REAL_TIME_CONFIGURATIONS_REQUEST_TIMEOUT`].
    ///
    /// [`DEFAULT_REAL_TIME_CONFIGURATIONS_REQUEST_TIMEOUT`]: crate::consts::DEFAULT_REAL_TIME_CONFIGURATIONS_REQUEST_TIMEOUT
    pub request_timeout: Option<u64>,
}

impl RealTimeConfigurationsSettings {
    /// Refuses the settings which can not work: no urls, a url which is empty or in the list
    /// twice, an interval which would ask the urls without a pause.
    pub fn check(&self) -> Result<(), String> {
        if self.urls.is_empty() {
            return Err("real_time_configurations.urls is empty".to_string());
        }

        for (index, url) in self.urls.iter().enumerate() {
            if url.trim().is_empty() {
                return Err(format!(
                    "real_time_configurations.urls: url #{} is empty",
                    index + 1
                ));
            }

            if self.urls[..index].contains(url) {
                return Err(format!(
                    "real_time_configurations.urls: {url} is in the list twice"
                ));
            }
        }

        if let Some(refresh_interval) = self.refresh_interval {
            if Duration::from_millis(refresh_interval)
                < MIN_REAL_TIME_CONFIGURATIONS_REFRESH_INTERVAL
            {
                return Err(format!(
                    "real_time_configurations.refresh_interval is {refresh_interval}ms: it is in milliseconds, and can not be less than {}",
                    MIN_REAL_TIME_CONFIGURATIONS_REFRESH_INTERVAL.as_millis()
                ));
            }
        }

        if self.request_timeout == Some(0) {
            return Err("real_time_configurations.request_timeout can not be 0".to_string());
        }

        Ok(())
    }

    pub fn get_refresh_interval(&self) -> Duration {
        match self.refresh_interval {
            Some(value) => Duration::from_millis(value),
            None => crate::consts::DEFAULT_REAL_TIME_CONFIGURATIONS_REFRESH_INTERVAL,
        }
    }

    pub fn get_request_timeout(&self) -> Duration {
        match self.request_timeout {
            Some(value) => Duration::from_millis(value),
            None => crate::consts::DEFAULT_REAL_TIME_CONFIGURATIONS_REQUEST_TIMEOUT,
        }
    }
}

/// What a url of `real_time_configurations` answers with, in YAML - read by the same parser as
/// the settings files: the `hosts:` of a settings file, `additional_hosts:` for hosts which have
/// their configuration already, `api_keys:` and `ip_white_lists:`. Any of them may be left out. Nothing else of a
/// settings file is read from there - another key is an error rather than quietly left out.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct RealTimeConfigurationModel {
    #[serde(default, deserialize_with = "super::null_as_default")]
    pub hosts: HashMap<String, HostSettings>,
    /// A host of the settings files - or of `hosts` above, or a name of one - and more names of
    /// it, as if they were in its `additional_hosts`.
    #[serde(default, deserialize_with = "super::null_as_default")]
    pub additional_hosts: HashMap<String, Vec<String>>,
    /// Keys by the ids of their sets, put together with the keys the settings files and the other
    /// urls declare under the same ids. Taken as they are written: no variable is put into them.
    #[serde(default, deserialize_with = "super::null_as_default")]
    pub api_keys: HashMap<String, Vec<crate::types::ProtectedString>>,
    /// IP lists by their ids - what `whitelisted_ip` of an endpoint or a location names - put
    /// together with the lists the settings files and the other urls declare under the same ids.
    /// ip-whitelister's `GET /api/export` answers with this. Each entry is an IPv4 address, a
    /// `from-to` range of them, or `*`: one which is none of them refuses the whole answer.
    #[serde(default, deserialize_with = "super::null_as_default")]
    pub ip_white_lists: HashMap<String, Vec<String>>,
}

impl RealTimeConfigurationModel {
    /// `None` for a blank answer - empty, or nothing but spaces and line breaks: the url said
    /// nothing, so what it gave before stays, and it is not a failure either. That there are no
    /// hosts is said with `hosts: {}`.
    ///
    /// A set of keys which can not work - one under the id `none`, an empty key - refuses the
    /// whole answer: what the url gave before stays.
    pub fn parse(content: &[u8]) -> Result<Option<Self>, String> {
        if super::SettingsModel::is_blank_content(content) {
            return Ok(None);
        }

        let mut model: Self = my_settings_reader::serde_yaml::from_slice(content)
            .map_err(|err| format!("the answer is not a real-time configuration: {err}"))?;

        let mut api_keys = HashMap::with_capacity(model.api_keys.len());

        for (id, keys) in std::mem::take(&mut model.api_keys) {
            let keys = crate::api_keys::check_api_keys(&id, keys)
                .map_err(|err| format!("the answer is refused: {err}"))?;
            api_keys.insert(id, keys);
        }

        model.api_keys = api_keys;

        for (id, entries) in model.ip_white_lists.iter() {
            for entry in entries {
                crate::types::check_ip_white_list_entry(entry).map_err(|err| {
                    format!("the answer is refused: ip_white_lists '{id}': {err}")
                })?;
            }
        }

        Ok(Some(model))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(yaml: &str) -> RealTimeConfigurationsSettings {
        my_settings_reader::serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn only_the_urls_are_required() {
        let settings = settings("urls:\n- http://127.0.0.1:5000/hosts");

        settings.check().unwrap();
        assert_eq!(settings.urls, ["http://127.0.0.1:5000/hosts"]);
        assert_eq!(
            settings.get_refresh_interval(),
            crate::consts::DEFAULT_REAL_TIME_CONFIGURATIONS_REFRESH_INTERVAL
        );
        assert_eq!(
            settings.get_request_timeout(),
            crate::consts::DEFAULT_REAL_TIME_CONFIGURATIONS_REQUEST_TIMEOUT
        );
    }

    #[test]
    fn the_intervals_are_milliseconds_and_one_for_all_the_urls() {
        let settings = settings(
            "urls:\n- http://127.0.0.1/a\n- http://127.0.0.1/b\nrefresh_interval: 30000\nrequest_timeout: 2500",
        );

        settings.check().unwrap();
        assert_eq!(settings.get_refresh_interval(), Duration::from_secs(30));
        assert_eq!(settings.get_request_timeout(), Duration::from_millis(2500));
    }

    /// `refresh_interval: 30` meant as seconds would ask the urls 33 times a second.
    #[test]
    fn settings_which_can_not_work_are_refused() {
        for yaml in [
            "urls: []",
            "urls:\n- ''",
            "urls:\n- '  '",
            "urls:\n- http://127.0.0.1/a\n- http://127.0.0.1/a",
            "urls:\n- http://127.0.0.1/hosts\nrefresh_interval: 0",
            "urls:\n- http://127.0.0.1/hosts\nrefresh_interval: 30",
            "urls:\n- http://127.0.0.1/hosts\nrequest_timeout: 0",
        ] {
            assert!(settings(yaml).check().is_err(), "{yaml}");
        }
    }

    /// `url:` of the `dynamic_hosts` it took the place of, or a key written wrong, is not left
    /// out without a word.
    #[test]
    fn a_key_which_is_not_there_is_an_error() {
        for yaml in [
            "url: http://127.0.0.1/hosts",
            "urls:\n- http://127.0.0.1/hosts\nrefresh_intreval: 5000",
        ] {
            assert!(
                my_settings_reader::serde_yaml::from_str::<RealTimeConfigurationsSettings>(yaml)
                    .is_err(),
                "{yaml}"
            );
        }
    }

    #[test]
    fn a_blank_answer_says_nothing() {
        for content in ["", " ", "\n", "\r\n  \n"] {
            let model = RealTimeConfigurationModel::parse(content.as_bytes())
                .unwrap_or_else(|err| panic!("{content:?}: {err}"));
            assert!(model.is_none(), "{content:?}");
        }
    }

    #[test]
    fn hosts_with_nothing_in_them_are_no_hosts() {
        for content in [
            "hosts:\n",
            "hosts: {}\n",
            "{}",
            r#"{"hosts":{}}"#,
            r#"{"hosts":null}"#,
        ] {
            let model = RealTimeConfigurationModel::parse(content.as_bytes())
                .unwrap_or_else(|err| panic!("{content:?}: {err}"))
                .unwrap_or_else(|| panic!("{content:?} is taken for a blank answer"));
            assert!(model.hosts.is_empty(), "{content:?}");
            assert!(model.api_keys.is_empty(), "{content:?}");
        }
    }

    #[test]
    fn the_hosts_are_read_in_yaml_and_in_json() {
        let yaml = "hosts:\n  a.example.com:8000:\n    endpoint:\n      type: http\n    locations:\n    - proxy_pass_to: http://127.0.0.1:9000\n";
        let json = r#"{"hosts":{"a.example.com:8000":{"endpoint":{"type":"http"},"locations":[{"proxy_pass_to":"http://127.0.0.1:9000"}]}}}"#;

        for content in [yaml, json] {
            let model = RealTimeConfigurationModel::parse(content.as_bytes())
                .unwrap()
                .unwrap();
            let host = model.hosts.get("a.example.com:8000").unwrap();
            assert_eq!(host.endpoint.endpoint_type, "http");
            assert_eq!(
                host.locations[0].proxy_pass_to.as_deref(),
                Some("http://127.0.0.1:9000")
            );
        }
    }

    /// More hosts for a configuration of the settings files, and nothing else: the url need
    /// not give a configuration of its own.
    #[test]
    fn the_answer_may_be_additional_hosts_only() {
        let yaml = "additional_hosts:\n  example.com:443:\n  - tenant1.example.com\n  - tenant2.example.com:8443\n  other.example.com:443: []\n";

        let model = RealTimeConfigurationModel::parse(yaml.as_bytes())
            .unwrap()
            .unwrap();

        assert!(model.hosts.is_empty());
        assert_eq!(
            model.additional_hosts["example.com:443"],
            ["tenant1.example.com", "tenant2.example.com:8443"]
        );
        assert!(model.additional_hosts["other.example.com:443"].is_empty());

        let model = RealTimeConfigurationModel::parse(b"additional_hosts:\n")
            .unwrap()
            .unwrap();
        assert!(model.additional_hosts.is_empty());
    }

    /// ip-whitelister's `GET /api/export`: ip lists and nothing else.
    #[test]
    fn the_answer_may_be_ip_white_lists_only() {
        let yaml = "ip_white_lists:\n  office:\n  - 198.51.100.4\n  - 10.0.1.1-10.0.1.9\n  - '*'\n  empty: []\n";

        let model = RealTimeConfigurationModel::parse(yaml.as_bytes())
            .unwrap()
            .unwrap();

        assert!(model.hosts.is_empty());
        assert_eq!(
            model.ip_white_lists["office"],
            ["198.51.100.4", "10.0.1.1-10.0.1.9", "*"]
        );
        assert!(model.ip_white_lists["empty"].is_empty());
    }

    /// An entry `WhiteListedIpList` can not read would panic the proxy: it refuses the answer.
    #[test]
    fn an_ip_list_with_an_entry_which_is_not_an_address_refuses_the_answer() {
        for content in [
            "ip_white_lists:\n  office:\n  - 10.0.0.1/24\n",
            "ip_white_lists:\n  office:\n  - 2001:db8::1\n",
            "ip_white_lists:\n  office:\n  - 10.0.0.300\n",
            "ip_white_lists:\n  office:\n  - 10.0.0.1-\n",
            "ip_white_lists:\n  office:\n  - office.example.com\n",
            "ip_white_lists:\n  office:\n  - ''\n",
            "ip_white_lists:\n  office: 10.0.0.1\n",
        ] {
            let result = RealTimeConfigurationModel::parse(content.as_bytes());
            assert!(result.is_err(), "{content:?}");
        }
    }

    /// Keys only: a url which hands out keys for the hosts of the settings files.
    #[test]
    fn the_answer_may_be_api_keys_only() {
        let yaml = "api_keys:\n  mcp_clients:\n  - tenant7-key\n  - ' spaced-key '\n  admins: []\n";

        let model = RealTimeConfigurationModel::parse(yaml.as_bytes())
            .unwrap()
            .unwrap();

        assert!(model.hosts.is_empty());
        assert_eq!(model.api_keys["mcp_clients"], ["tenant7-key", "spaced-key"]);
        assert!(model.api_keys["admins"].is_empty());
    }

    #[test]
    fn a_set_of_keys_which_can_not_work_refuses_the_answer() {
        for content in [
            "api_keys:\n  none:\n  - key\n",
            "api_keys:\n  NONE: []\n",
            "api_keys:\n  clients:\n  - ''\n",
            "api_keys:\n  clients:\n  - ${MCP_KEY}\n",
            "hosts: {}\napi_keys:\n  clients:\n  - ${lower_case}\n",
        ] {
            assert!(
                RealTimeConfigurationModel::parse(content.as_bytes()).is_err(),
                "{content:?}"
            );
        }
    }

    /// The url gives hosts and keys and nothing else: a certificate or a variable there would be
    /// read by nobody.
    #[test]
    fn anything_else_is_an_error() {
        for content in [
            "variables:\n  ENV: dev\n",
            "hosts: {}\nssl_certificates: []\n",
            "not the hosts",
            "hosts: 5\n",
            "api_keys: 5\n",
            "api_keys:\n  clients: key\n",
        ] {
            assert!(
                RealTimeConfigurationModel::parse(content.as_bytes()).is_err(),
                "{content:?}"
            );
        }
    }
}

use std::{collections::HashMap, time::Duration};

use serde::*;

use super::HostSettings;

/// The shortest `refresh_interval` taken: a smaller one - a zero above all - would ask the url
/// for the hosts without a pause.
pub const MIN_DYNAMIC_HOSTS_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

/// `dynamic_hosts:` - the url the proxy reads more hosts from, and how often it does.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DynamicHostsSettings {
    /// Answers with the hosts: see [`DynamicHostsModel`].
    pub url: String,
    /// Milliseconds between two reads of the url. Absent: [`DEFAULT_DYNAMIC_HOSTS_REFRESH_INTERVAL`].
    ///
    /// [`DEFAULT_DYNAMIC_HOSTS_REFRESH_INTERVAL`]: crate::consts::DEFAULT_DYNAMIC_HOSTS_REFRESH_INTERVAL
    pub refresh_interval: Option<u64>,
    /// Milliseconds a read of the url may take - the request and its whole answer. Absent:
    /// [`DEFAULT_DYNAMIC_HOSTS_REQUEST_TIMEOUT`].
    ///
    /// [`DEFAULT_DYNAMIC_HOSTS_REQUEST_TIMEOUT`]: crate::consts::DEFAULT_DYNAMIC_HOSTS_REQUEST_TIMEOUT
    pub request_timeout: Option<u64>,
}

impl DynamicHostsSettings {
    /// Refuses the settings which can not work: no url, or an interval which would ask the url
    /// without a pause.
    pub fn check(&self) -> Result<(), String> {
        if self.url.trim().is_empty() {
            return Err("dynamic_hosts.url is empty".to_string());
        }

        if let Some(refresh_interval) = self.refresh_interval {
            if Duration::from_millis(refresh_interval) < MIN_DYNAMIC_HOSTS_REFRESH_INTERVAL {
                return Err(format!(
                    "dynamic_hosts.refresh_interval is {refresh_interval}ms: it is in milliseconds, and can not be less than {}",
                    MIN_DYNAMIC_HOSTS_REFRESH_INTERVAL.as_millis()
                ));
            }
        }

        if self.request_timeout == Some(0) {
            return Err("dynamic_hosts.request_timeout can not be 0".to_string());
        }

        Ok(())
    }

    pub fn get_refresh_interval(&self) -> Duration {
        match self.refresh_interval {
            Some(value) => Duration::from_millis(value),
            None => crate::consts::DEFAULT_DYNAMIC_HOSTS_REFRESH_INTERVAL,
        }
    }

    pub fn get_request_timeout(&self) -> Duration {
        match self.request_timeout {
            Some(value) => Duration::from_millis(value),
            None => crate::consts::DEFAULT_DYNAMIC_HOSTS_REQUEST_TIMEOUT,
        }
    }
}

/// What `dynamic_hosts.url` answers with, in YAML - read by the same parser as the settings
/// files: the `hosts:` of a settings file, and `additional_hosts:` for hosts which have their
/// configuration already. Either may be left out. Nothing else of a settings file is read from
/// there - another key is an error rather than quietly left out.
#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct DynamicHostsModel {
    #[serde(default, deserialize_with = "super::null_as_default")]
    pub hosts: HashMap<String, HostSettings>,
    /// A host of the settings files - or of `hosts` above, or a name of one - and more names of
    /// it, as if they were in its `additional_hosts`.
    #[serde(default, deserialize_with = "super::null_as_default")]
    pub additional_hosts: HashMap<String, Vec<String>>,
}

impl DynamicHostsModel {
    /// `None` for a blank answer - empty, or nothing but spaces and line breaks: the url said
    /// nothing, so the hosts read before stay, and it is not a failure either. That there are no
    /// hosts is said with `hosts: {}`.
    pub fn parse(content: &[u8]) -> Result<Option<Self>, String> {
        if super::SettingsModel::is_blank_content(content) {
            return Ok(None);
        }

        my_settings_reader::serde_yaml::from_slice(content)
            .map(Some)
            .map_err(|err| format!("the answer is not the hosts of a settings file: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(yaml: &str) -> DynamicHostsSettings {
        my_settings_reader::serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn only_the_url_is_required() {
        let settings = settings("url: http://127.0.0.1:5000/hosts");

        settings.check().unwrap();
        assert_eq!(
            settings.get_refresh_interval(),
            crate::consts::DEFAULT_DYNAMIC_HOSTS_REFRESH_INTERVAL
        );
        assert_eq!(
            settings.get_request_timeout(),
            crate::consts::DEFAULT_DYNAMIC_HOSTS_REQUEST_TIMEOUT
        );
    }

    #[test]
    fn the_intervals_are_milliseconds() {
        let settings =
            settings("url: http://127.0.0.1/hosts\nrefresh_interval: 30000\nrequest_timeout: 2500");

        settings.check().unwrap();
        assert_eq!(settings.get_refresh_interval(), Duration::from_secs(30));
        assert_eq!(settings.get_request_timeout(), Duration::from_millis(2500));
    }

    /// `refresh_interval: 30` meant as seconds would ask the url 33 times a second.
    #[test]
    fn settings_which_can_not_work_are_refused() {
        for yaml in [
            "url: ''",
            "url: '  '",
            "url: http://127.0.0.1/hosts\nrefresh_interval: 0",
            "url: http://127.0.0.1/hosts\nrefresh_interval: 30",
            "url: http://127.0.0.1/hosts\nrequest_timeout: 0",
        ] {
            assert!(settings(yaml).check().is_err(), "{yaml}");
        }
    }

    #[test]
    fn a_blank_answer_says_nothing() {
        for content in ["", " ", "\n", "\r\n  \n"] {
            let model = DynamicHostsModel::parse(content.as_bytes())
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
            let model = DynamicHostsModel::parse(content.as_bytes())
                .unwrap_or_else(|err| panic!("{content:?}: {err}"))
                .unwrap_or_else(|| panic!("{content:?} is taken for a blank answer"));
            assert!(model.hosts.is_empty(), "{content:?}");
        }
    }

    #[test]
    fn the_hosts_are_read_in_yaml_and_in_json() {
        let yaml = "hosts:\n  a.example.com:8000:\n    endpoint:\n      type: http\n    locations:\n    - proxy_pass_to: http://127.0.0.1:9000\n";
        let json = r#"{"hosts":{"a.example.com:8000":{"endpoint":{"type":"http"},"locations":[{"proxy_pass_to":"http://127.0.0.1:9000"}]}}}"#;

        for content in [yaml, json] {
            let model = DynamicHostsModel::parse(content.as_bytes())
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

        let model = DynamicHostsModel::parse(yaml.as_bytes()).unwrap().unwrap();

        assert!(model.hosts.is_empty());
        assert_eq!(
            model.additional_hosts["example.com:443"],
            ["tenant1.example.com", "tenant2.example.com:8443"]
        );
        assert!(model.additional_hosts["other.example.com:443"].is_empty());

        let model = DynamicHostsModel::parse(b"additional_hosts:\n")
            .unwrap()
            .unwrap();
        assert!(model.additional_hosts.is_empty());
    }

    /// The url gives hosts and nothing else: a certificate or a variable there would be read by
    /// nobody.
    #[test]
    fn anything_but_hosts_is_an_error() {
        for content in [
            "variables:\n  ENV: dev\n",
            "hosts: {}\nssl_certificates: []\n",
            "not the hosts",
            "hosts: 5\n",
        ] {
            assert!(
                DynamicHostsModel::parse(content.as_bytes()).is_err(),
                "{content:?}"
            );
        }
    }
}

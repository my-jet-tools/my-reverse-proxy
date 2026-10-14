use std::collections::HashMap;

use super::*;
use serde::*;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SettingsModel {
    /// Not required in any file: the hosts may all be in the files the main one includes, and a
    /// file may hold nothing but certificates or variables. `hosts:` with nothing under it is no
    /// hosts as well.
    #[serde(default, deserialize_with = "null_as_default")]
    pub hosts: HashMap<String, HostSettings>,
    pub include: Option<Vec<String>>,
    pub dynamic_configurations_file: Option<String>,
    pub variables: Option<HashMap<String, String>>,
    pub ssl_certificates: Option<Vec<SslCertificatesSettingsModel>>,
    pub client_certificate_ca: Option<Vec<ClientCertificateCaSettings>>,
    pub global_settings: Option<GlobalSettings>,
    pub g_auth: Option<HashMap<String, GoogleAuthSettings>>,
    pub oauth: Option<HashMap<String, OAuthSettings>>,
    pub ssh: Option<HashMap<String, SshConfigSettings>>,
    pub endpoint_templates: Option<HashMap<String, EndpointTemplateSettings>>,
    pub allowed_users: Option<HashMap<String, Vec<String>>>,
    pub ip_white_lists: Option<HashMap<String, Vec<String>>>,
    pub gateway_server: Option<GatewayServerSettings>,
    pub gateway_clients: Option<HashMap<String, GatewayClientSettings>>,
}

impl SettingsModel {
    pub async fn load_async(file_name: Option<&str>) -> Result<Self, String> {
        let file_name = resolve_file_name(file_name);
        let file_content = read_file_async(file_name.as_str()).await?;
        Self::from_yaml(file_name.as_str(), &file_content)
    }

    pub fn load(file_name: Option<&str>) -> Result<Self, String> {
        let file_name = resolve_file_name(file_name);
        let file_content = read_file(file_name.as_str())?;
        Self::from_yaml(file_name.as_str(), &file_content)
    }

    /// Loads the dynamic settings file. A blank file (empty, or nothing but spaces
    /// and line breaks) is not parsed at all and yields `None` — it holds no data.
    pub async fn load_dynamic_async(file_name: &str) -> Result<Option<Self>, String> {
        let file_name = resolve_file_name(Some(file_name));
        let file_content = read_file_async(file_name.as_str()).await?;
        Self::from_dynamic_yaml(file_name.as_str(), &file_content)
    }

    pub fn load_dynamic(file_name: &str) -> Result<Option<Self>, String> {
        let file_name = resolve_file_name(Some(file_name));
        let file_content = read_file(file_name.as_str())?;
        Self::from_dynamic_yaml(file_name.as_str(), &file_content)
    }

    /// True if the content is empty or consists only of whitespace (spaces, tabs, line breaks).
    pub fn is_blank_content(content: &[u8]) -> bool {
        content.iter().all(|b| b.is_ascii_whitespace())
    }

    fn from_dynamic_yaml(file_name: &str, content: &[u8]) -> Result<Option<Self>, String> {
        if Self::is_blank_content(content) {
            return Ok(None);
        }

        Self::from_yaml(file_name, content).map(Some)
    }

    fn from_yaml(file_name: &str, content: &[u8]) -> Result<Self, String> {
        match my_settings_reader::serde_yaml::from_slice(content) {
            Ok(result) => Ok(result),
            Err(err) => Err(format!(
                "Invalid yaml format of file: {}. Err: {}",
                file_name, err
            )),
        }
    }
}

/// A key which is there with nothing under it - `hosts:` - is read as if it were not there.
fn null_as_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn resolve_file_name(file_name: Option<&str>) -> String {
    if let Some(file_name) = file_name {
        rust_extensions::file_utils::format_path(file_name).to_string()
    } else {
        format!("{}/{}", std::env::var("HOME").unwrap(), ".my-reverse-proxy")
    }
}

async fn read_file_async(file_name: &str) -> Result<Vec<u8>, String> {
    tokio::fs::read(file_name)
        .await
        .map_err(|_| format!("Can not read settings from file: {}", file_name))
}

fn read_file(file_name: &str) -> Result<Vec<u8>, String> {
    std::fs::read(file_name).map_err(|_| format!("Can not read settings from file: {}", file_name))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    use super::SettingsModel;

    #[test]
    fn test() {
        let mut hosts = HashMap::new();

        hosts.insert(
            "localhost:9000".to_string(),
            HostSettings {
                endpoint: EndpointSettings {
                    endpoint_type: "http1".to_owned(),
                    ssl_certificate: None,
                    client_certificate_ca: None,
                    modify_http_headers: None,
                    debug: None,
                    inject_country: None,
                    google_auth: None,
                    oauth: None,
                    whitelisted_ip: None,
                    template_id: None,
                    allowed_users: None,
                    keep_alive: None,
                    track_metrics_by_all_domains: None,
                    hsts: None,
                    mcp_buffer_size: None,
                    timeouts: TimeoutsSettings::default(),
                },
                locations: vec![LocationSettings {
                    path: Some("/".to_owned()),
                    proxy_pass_to: "https://www.google.com".to_owned().into(),
                    location_type: Some("http".to_owned()),
                    modify_http_headers: None,
                    default_file: None,
                    status_code: None,
                    body: None,
                    content_type: None,
                    whitelisted_ip: None,
                    domain_name: None,
                    compress: None,
                    trace_payload: None,
                    auth_header: None,
                    allowed_hosts: None,
                    timeouts: TimeoutsSettings::default(),
                }],
            },
        );

        let mut ssh_configs = HashMap::new();

        ssh_configs.insert(
            "root@10.0.0.1".to_string(),
            SshConfigSettings {
                password: "my_password".to_string().into(),
                private_key_file: None,
                passphrase: None,
            },
        );

        ssh_configs.insert(
            "root@10.0.0.2".to_string(),
            SshConfigSettings {
                password: None,
                private_key_file: Some("~/certs/private_key.ssh".to_string()),
                passphrase: Some("my_pass_phrase".to_string()),
            },
        );

        let mut gateway_clients = HashMap::new();

        gateway_clients.insert(
            "client_id".to_string(),
            GatewayClientSettings {
                remote_host: "127.0.0.1:3000".to_string(),
                ssh_credentials: String::new(),
                debug: None,
                compress: None,
                allow_incoming_forward_connections: None,
                connect_timeout: None,
                sync_ssl_certificates: None,
            },
        );

        let model = SettingsModel {
            hosts,
            global_settings: None,
            include: None,
            dynamic_configurations_file: None,
            variables: None,
            ssl_certificates: None,
            client_certificate_ca: None,
            ssh: Some(ssh_configs),
            g_auth: None,
            oauth: None,
            endpoint_templates: None,
            allowed_users: None,
            ip_white_lists: None,
            gateway_server: None,
            gateway_clients: Some(gateway_clients),
        };

        let json = serde_yaml::to_string(&model).unwrap();

        println!("{}", json);
    }

    #[test]
    fn blank_dynamic_content_is_not_parsed() {
        for content in ["", " ", "\n", "\r\n", "  \n\t\r\n \n"] {
            let result = SettingsModel::from_dynamic_yaml("dynamic", content.as_bytes());
            assert!(result.unwrap().is_none(), "content: {:?}", content);
        }
    }

    #[test]
    fn non_blank_dynamic_content_is_parsed() {
        let result = SettingsModel::from_dynamic_yaml("dynamic", b"\n\nhosts: {}\n\n");
        assert!(result.unwrap().unwrap().hosts.is_empty());

        let result = SettingsModel::from_dynamic_yaml("dynamic", b"\n  not a settings file\n");
        assert!(result.is_err());
    }

    /// The hosts may all be in the included files: a file without them - or with `hosts:` and
    /// nothing under it - is read, and has no hosts.
    #[test]
    fn hosts_are_not_required() {
        for content in [
            "include:\n- ~/hosts.yaml\n",
            "hosts:\ninclude:\n- ~/hosts.yaml\n",
            "hosts: {}\n",
            "variables:\n  ENV: dev\n",
        ] {
            let model = SettingsModel::from_yaml("settings", content.as_bytes())
                .unwrap_or_else(|err| panic!("{content:?}: {err}"));
            assert!(model.hosts.is_empty(), "{content:?}");
        }

        let model = SettingsModel::from_yaml(
            "settings",
            b"include:\n- ~/hosts.yaml\nhosts:\n  localhost:8000:\n    endpoint:\n      type: http\n    locations:\n    - proxy_pass_to: http://127.0.0.1:9000\n",
        )
        .unwrap();
        assert_eq!(model.hosts.len(), 1);
        assert_eq!(model.include.unwrap(), vec!["~/hosts.yaml".to_string()]);

        // Hosts which are not a map are still an error.
        assert!(SettingsModel::from_yaml("settings", b"hosts: 5\n").is_err());
    }

    #[test]
    fn blank_dynamic_file_is_loaded_as_no_data() {
        let file_name = std::env::temp_dir().join(format!(
            "my-reverse-proxy-blank-dynamic-{}.yaml",
            std::process::id()
        ));
        std::fs::write(&file_name, " \n\n  \r\n").unwrap();

        let result = SettingsModel::load_dynamic(file_name.to_str().unwrap());

        std::fs::remove_file(&file_name).unwrap();
        assert!(result.unwrap().is_none());
    }
}

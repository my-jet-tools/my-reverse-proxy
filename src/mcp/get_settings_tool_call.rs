use mcp_server_middleware::*;
use serde::*;

use crate::app::APP_CTX;
use crate::settings_compiled::SettingsCompiled;

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct ConfigurationErrorEntry {
    #[property(description = "Host id whose configuration failed to apply")]
    pub host_id: String,

    #[property(description = "Error message recorded for the host")]
    pub error: String,
}

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct GetSettingsInputData {}

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct LocationSettingsSummary {
    #[property(description = "Location path prefix (e.g. '/')")]
    pub path: String,

    #[property(description = "Upstream / target (proxy_pass_to as written in YAML)")]
    pub proxy_pass_to: String,

    #[property(
        description = "Explicit location type from YAML (http/http2/https/static/drop/...), or empty if auto-detected from proxy_pass_to"
    )]
    pub location_type: String,

    #[property(description = "Whitelisted IP list id for this location, if any")]
    pub whitelisted_ip: String,

    #[property(
        description = "whitelisted_country of this location: the id of a list of country_white_lists a client has to come from, on top of the endpoint's lists. Empty if not set"
    )]
    pub whitelisted_country: String,

    #[property(
        description = "True if strip_path is set on this location: the location path is cut off the request path before it goes upstream"
    )]
    pub strip_path: bool,

    #[property(
        description = "api_keys_auth of the location as written: the id of the set of api_keys a request has to carry a key of in X-Api-Key, in place of the endpoint's; 'none' opens the location although its endpoint is guarded; empty if not set (the endpoint's applies)"
    )]
    pub api_keys_auth: String,
}

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct HostSettingsSummary {
    #[property(
        description = "Host id as written in YAML (e.g. 'mydomain.com:443' or 'unix:/var/run/x.sock')"
    )]
    pub host_id: String,

    #[property(description = "Endpoint type: http / http2 / https / https2 / tcp / mcp")]
    pub endpoint_type: String,

    #[property(description = "True if debug logging is enabled on this endpoint")]
    pub debug: bool,

    #[property(description = "ssl_certificate id referenced by this host, if any")]
    pub ssl_certificate: String,

    #[property(description = "client_certificate_ca id referenced by this host, if any")]
    pub client_certificate_ca: String,

    #[property(description = "google_auth id referenced by this host, if any")]
    pub google_auth: String,

    #[property(description = "Endpoint template id, if any")]
    pub template_id: String,

    #[property(description = "Allowed users list id, if any")]
    pub allowed_users: String,

    #[property(description = "Whitelisted IP list id, if any")]
    pub whitelisted_ip: String,

    #[property(
        description = "whitelisted_country of the endpoint as written: the id of a list of country_white_lists a client has to come from (with whitelisted_ip, it has to pass both). Empty if not set; endpoint_templates may still give one"
    )]
    pub whitelisted_country: String,

    #[property(description = "True if HSTS is enabled on this endpoint")]
    pub hsts: bool,

    #[property(
        description = "api_keys_auth of the endpoint as written: the id of the set of api_keys every location of it takes requests with a key of in X-Api-Key (a location may name its own set, or 'none'). Empty if not set; endpoint_templates may still give one"
    )]
    pub api_keys_auth: String,

    #[property(
        description = "True if the host was read from a url of real_time_configurations rather than from a settings file"
    )]
    pub dynamic: bool,

    #[property(
        description = "The host whose additional_hosts this host is in, and whose configuration it is served with. Empty for a host written as a key of hosts"
    )]
    pub additional_host_of: String,

    #[property(description = "Locations under this host")]
    pub locations: Vec<LocationSettingsSummary>,
}

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct GlobalSettingsSummary {
    #[property(
        description = "The address the control port listens on as these settings give it (ip:port): global_settings.http_control_port - a port, or the whole address like 0.0.0.0:8000 - and http_control_ip; 127.0.0.1:8000 if they say nothing. The control port binds it at startup: a change takes effect after a restart. Empty if these settings give no valid address"
    )]
    pub http_control_addr: String,

    #[property(description = "default_h2_livness_url from global_settings, if configured")]
    pub default_h2_livness_url: String,

    #[property(
        description = "show_error_description_on_error_page flag: when on, a 4xx/5xx page of the proxy shows the error behind it - to the global_settings.debug_ip sources only, everybody else gets the title alone"
    )]
    pub show_error_description_on_error_page: bool,
}

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct GatewayServerSummary {
    #[property(description = "Gateway server port")]
    pub port: i64,

    #[property(description = "True if debug logging is enabled on the gateway server")]
    pub debug: bool,

    #[property(description = "Count of authorized_keys paths configured")]
    pub authorized_keys_count: i64,
}

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct RealTimeUrlSummary {
    #[property(description = "A url of real_time_configurations.urls, the variables put in")]
    pub url: String,

    #[property(
        description = "True once the url has answered: what it gave is served. False until its first successful read"
    )]
    pub answered: bool,

    #[property(
        description = "Why the last read of the url failed, empty if it succeeded. What the last read which succeeded gave is served meanwhile"
    )]
    pub last_read_error: String,
}

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct RealTimeConfigurationsSummary {
    #[property(
        description = "real_time_configurations.urls in their order: a host two urls give is served as the one lower in the list gives it"
    )]
    pub urls: Vec<RealTimeUrlSummary>,

    #[property(description = "Milliseconds between two reads of the urls")]
    pub refresh_interval: i64,

    #[property(description = "Milliseconds a read of a url may take")]
    pub request_timeout: i64,

    #[property(
        description = "Hosts and names of the urls which are not among the hosts, and why: a variable which is not there, an id a settings file has a host of its own for. Errors of compiling a dynamic host are in current_configuration_errors"
    )]
    pub refused_hosts: Vec<ConfigurationErrorEntry>,
}

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct ApiKeysSummary {
    #[property(description = "Id of a set of api_keys")]
    pub id: String,

    #[property(
        description = "How many keys a request is checked against under this id: the keys of the settings files and the ones the urls of real_time_configurations gave, each counted once. The keys themselves are never shown"
    )]
    pub keys: i64,

    #[property(description = "How many of them the settings files declare")]
    pub keys_in_files: i64,

    #[property(description = "How many keys the urls of real_time_configurations gave")]
    pub keys_from_urls: i64,

    #[property(
        description = "True if an api_keys_auth of an endpoint, a location or an endpoint template names the id. Used with keys=0: every request to what it guards is refused with 401"
    )]
    pub used: bool,
}

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct CountryWhiteListSummary {
    #[property(description = "Id of a list of country_white_lists")]
    pub id: String,

    #[property(
        description = "The countries of the list as ISO 3166 codes of two letters, sorted - what a client's country (by its IP) is compared with. [\"*\"]: every client is let in. Empty: nobody is let in (or the list does not compile - see error)"
    )]
    pub countries: Vec<String>,

    #[property(
        description = "Why the list does not compile (a code which is not a country); empty if it does. A host naming such a list does not load"
    )]
    pub error: String,
}

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct GetSettingsResponse {
    #[property(description = "Resolved path to the settings file that was read")]
    pub settings_file: String,

    #[property(description = "Global settings block")]
    pub global: GlobalSettingsSummary,

    #[property(
        description = "All hosts defined in the settings file (and any included files), and the ones read from the urls of real_time_configurations (dynamic=true)"
    )]
    pub hosts: Vec<HostSettingsSummary>,

    #[property(description = "real_time_configurations block, if configured")]
    pub real_time_configurations: Option<RealTimeConfigurationsSummary>,

    #[property(
        description = "The sets of api_keys: every id the settings files or the urls declare keys under, and every id an api_keys_auth names - with how many keys it has. The keys themselves are never shown"
    )]
    pub api_keys: Vec<ApiKeysSummary>,

    #[property(description = "SSH config ids defined in settings")]
    pub ssh_ids: Vec<String>,

    #[property(description = "SSL certificate ids defined in settings")]
    pub ssl_certificate_ids: Vec<String>,

    #[property(description = "Client certificate CA ids defined in settings")]
    pub client_certificate_ca_ids: Vec<String>,

    #[property(description = "Google auth ids defined in settings")]
    pub g_auth_ids: Vec<String>,

    #[property(description = "Endpoint template ids defined in settings")]
    pub endpoint_template_ids: Vec<String>,

    #[property(description = "Allowed-users list ids defined in settings")]
    pub allowed_users_list_ids: Vec<String>,

    #[property(description = "IP white list ids defined in settings")]
    pub ip_white_list_ids: Vec<String>,

    #[property(description = "Country white lists defined in settings, sorted by id")]
    pub country_white_lists: Vec<CountryWhiteListSummary>,

    #[property(description = "Gateway server block, if configured")]
    pub gateway_server: Option<GatewayServerSummary>,

    #[property(description = "Gateway client ids defined in settings")]
    pub gateway_client_ids: Vec<String>,

    #[property(
        description = "Errors recorded by the running configuration for endpoints that failed to apply. These are NOT settings-file errors — they come from the in-memory current_configuration state."
    )]
    pub current_configuration_errors: Vec<ConfigurationErrorEntry>,
}

pub struct GetSettingsHandler;

impl ToolDefinition for GetSettingsHandler {
    const FUNC_NAME: &'static str = "get_settings";
    const DESCRIPTION: &'static str = "Read and parse the settings YAML (~/.my-reverse-proxy, plus any `include:` files) and return a structured overview: hosts with their endpoint type and locations, global settings, ids of SSH/SSL/CA/g_auth/templates/users/ip-lists/gateway-clients, and any errors recorded for endpoints in the currently-running configuration. Use this to see what settings the file currently declares — call reload_settings afterwards to apply changes.";
}

#[async_trait::async_trait]
impl McpToolCall<GetSettingsInputData, GetSettingsResponse> for GetSettingsHandler {
    async fn execute_tool_call(
        &self,
        _model: GetSettingsInputData,
    ) -> Result<GetSettingsResponse, String> {
        // `get_settings` shows what the files declare right now: recompile from disk.
        let settings = SettingsCompiled::load_settings().await?;
        let current_configuration_errors = load_current_configuration_errors().await;

        Ok(build_settings_summary(
            &settings,
            crate::settings::settings_file_path()?,
            current_configuration_errors,
        ))
    }
}

/// Builds the structured overview shared by `get_settings` (compiled-from-files) and
/// `get_applied_settings` (last-applied snapshot). Keeping it in one place means both
/// tools return the exact same shape, so the two can be diffed field-by-field.
pub fn build_settings_summary(
    settings: &SettingsCompiled,
    settings_file: String,
    current_configuration_errors: Vec<ConfigurationErrorEntry>,
) -> GetSettingsResponse {
    let global = GlobalSettingsSummary {
        http_control_addr: settings
            .get_http_control_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_default(),
        default_h2_livness_url: settings.get_default_h2_livness_url().unwrap_or_default(),
        show_error_description_on_error_page: settings.get_show_error_description_on_error_page(),
    };

    let summarize = |host_id: &String,
                     host: &crate::settings::HostSettings,
                     dynamic: bool,
                     additional_host_of: String| {
        let locations = host
            .locations
            .iter()
            .map(|loc| LocationSettingsSummary {
                path: loc.path.clone().unwrap_or_default(),
                proxy_pass_to: loc.proxy_pass_to.clone().unwrap_or_default(),
                location_type: loc.location_type.clone().unwrap_or_default(),
                whitelisted_ip: loc.whitelisted_ip.clone().unwrap_or_default(),
                whitelisted_country: loc.whitelisted_country.clone().unwrap_or_default(),
                strip_path: loc.get_strip_path(),
                api_keys_auth: loc.api_keys_auth.clone().unwrap_or_default(),
            })
            .collect();

        HostSettingsSummary {
            host_id: host_id.clone(),
            endpoint_type: host.endpoint.endpoint_type.clone(),
            debug: host.endpoint.debug.unwrap_or(false),
            ssl_certificate: host.endpoint.ssl_certificate.clone().unwrap_or_default(),
            client_certificate_ca: host
                .endpoint
                .client_certificate_ca
                .clone()
                .unwrap_or_default(),
            google_auth: host.endpoint.google_auth.clone().unwrap_or_default(),
            template_id: host.endpoint.template_id.clone().unwrap_or_default(),
            allowed_users: host.endpoint.allowed_users.clone().unwrap_or_default(),
            whitelisted_ip: host.endpoint.whitelisted_ip.clone().unwrap_or_default(),
            whitelisted_country: host
                .endpoint
                .whitelisted_country
                .clone()
                .unwrap_or_default(),
            hsts: host.endpoint.hsts.unwrap_or(false),
            api_keys_auth: host.endpoint.api_keys_auth.clone().unwrap_or_default(),
            dynamic,
            additional_host_of,
            locations,
        }
    };

    let mut hosts: Vec<HostSettingsSummary> = settings
        .hosts
        .iter()
        .map(|(host_id, host)| {
            summarize(
                host_id,
                host,
                settings.is_dynamic_host(host_id),
                String::new(),
            )
        })
        .collect();

    // Each name of `additional_hosts` is listed as a host, with the configuration of the host it
    // is a name of.
    for (name, itm) in &settings.additional_hosts {
        if let Some(host) = settings.hosts.get(&itm.host_id) {
            hosts.push(summarize(name, host, itm.dynamic, itm.host_id.clone()));
        }
    }

    hosts.sort_by(|a, b| a.host_id.cmp(&b.host_id));

    let gateway_server = settings
        .gateway_server
        .as_ref()
        .map(|g| GatewayServerSummary {
            port: g.port as i64,
            debug: g.is_debug(),
            authorized_keys_count: g.authorized_keys.len() as i64,
        });

    let real_time_configurations =
        settings
            .real_time_configurations
            .as_ref()
            .map(|real_time_configurations| RealTimeConfigurationsSummary {
                urls: real_time_configurations
                    .urls
                    .iter()
                    .map(|url| RealTimeUrlSummary {
                        url: url.clone(),
                        answered: !APP_CTX
                            .real_time_configurations
                            .get_answers(std::slice::from_ref(url))
                            .is_empty(),
                        last_read_error: APP_CTX
                            .real_time_configurations
                            .get_last_error(url)
                            .unwrap_or_default(),
                    })
                    .collect(),
                refresh_interval: real_time_configurations.get_refresh_interval().as_millis()
                    as i64,
                request_timeout: real_time_configurations.get_request_timeout().as_millis() as i64,
                refused_hosts: settings
                    .dynamic_host_errors
                    .iter()
                    .map(|(host_id, error)| ConfigurationErrorEntry {
                        host_id: host_id.clone(),
                        error: error.clone(),
                    })
                    .collect(),
            });

    GetSettingsResponse {
        settings_file,
        global,
        hosts,
        real_time_configurations,
        api_keys: summarize_api_keys(settings),
        ssh_ids: sorted_keys(settings.ssh.keys()),
        ssl_certificate_ids: settings
            .ssl_certificates
            .iter()
            .map(|c| c.id.clone())
            .collect(),
        client_certificate_ca_ids: settings
            .client_certificate_ca
            .iter()
            .map(|c| c.id.clone())
            .collect(),
        g_auth_ids: sorted_keys(settings.g_auth.keys()),
        endpoint_template_ids: sorted_keys(settings.endpoint_templates.keys()),
        allowed_users_list_ids: sorted_keys(settings.allowed_users.keys()),
        ip_white_list_ids: sorted_keys(settings.ip_white_lists.keys()),
        country_white_lists: summarize_country_white_lists(settings),
        gateway_server,
        gateway_client_ids: sorted_keys(settings.gateway_clients.keys()),
        current_configuration_errors,
    }
}

/// Every set of keys - declared, or named by an `api_keys_auth` - with how many keys it has. The
/// keys are secrets: they are counted, never shown.
fn summarize_api_keys(settings: &SettingsCompiled) -> Vec<ApiKeysSummary> {
    let mut used: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();

    for host in settings.hosts.values() {
        used.extend(host.endpoint.api_keys_auth.as_deref());

        for location in &host.locations {
            used.extend(location.api_keys_auth.as_deref());
        }
    }

    for template in settings.endpoint_templates.values() {
        used.extend(template.api_keys_auth.as_deref());
    }

    used.retain(|id| !crate::api_keys::is_no_api_keys(id));

    let all = settings.get_api_keys();

    let mut ids: std::collections::BTreeSet<&str> = used.clone();
    ids.extend(all.keys().map(|id| id.as_str()));

    ids.into_iter()
        .map(|id| ApiKeysSummary {
            id: id.to_string(),
            keys: all.get(id).map(|keys| keys.len()).unwrap_or(0) as i64,
            keys_in_files: settings
                .api_keys
                .get(id)
                .map(|keys| keys.len())
                .unwrap_or(0) as i64,
            keys_from_urls: settings
                .dynamic_api_keys
                .get(id)
                .map(|keys| keys.len())
                .unwrap_or(0) as i64,
            used: used.contains(id),
        })
        .collect()
}

/// Snapshot of the running configuration's per-host error map.
pub async fn load_current_configuration_errors() -> Vec<ConfigurationErrorEntry> {
    APP_CTX
        .current_configuration
        .get(|cfg| {
            cfg.error_configurations
                .iter()
                .map(|(host_id, error)| ConfigurationErrorEntry {
                    host_id: host_id.clone(),
                    error: error.clone(),
                })
                .collect::<Vec<_>>()
        })
        .await
}

/// Every list of `country_white_lists`, as it compiles - or why it does not.
fn summarize_country_white_lists(settings: &SettingsCompiled) -> Vec<CountryWhiteListSummary> {
    sorted_keys(settings.country_white_lists.keys())
        .into_iter()
        .map(|id| {
            let compiled =
                crate::types::CountryWhiteList::new(&id, &settings.country_white_lists[&id]);

            match compiled {
                Ok(list) => CountryWhiteListSummary {
                    countries: list.countries().into_iter().map(String::from).collect(),
                    error: String::new(),
                    id,
                },
                Err(error) => CountryWhiteListSummary {
                    countries: Vec::new(),
                    error,
                    id,
                },
            }
        })
        .collect()
}

fn sorted_keys<'a, I: IntoIterator<Item = &'a String>>(keys: I) -> Vec<String> {
    let mut out: Vec<String> = keys.into_iter().cloned().collect();
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::settings::HostSettings;

    #[test]
    fn the_summary_shows_strip_path_of_each_location() {
        let hosts: HashMap<String, HostSettings> = serde_yaml::from_str(
            [
                "'localhost:8000':",
                "  endpoint:",
                "    type: http",
                "  locations:",
                "  - path: /stripped/",
                "    proxy_pass_to: http://127.0.0.1:9000",
                "    strip_path: true",
                "  - path: /kept/",
                "    proxy_pass_to: http://127.0.0.1:9001",
                "    strip_path: false",
                "  - path: /",
                "    proxy_pass_to: http://127.0.0.1:9002",
            ]
            .join("\n")
            .as_str(),
        )
        .unwrap();

        let settings = SettingsCompiled {
            hosts,
            ..Default::default()
        };

        let summary = build_settings_summary(&settings, String::new(), vec![]);

        let locations: Vec<_> = summary.hosts[0]
            .locations
            .iter()
            .map(|location| (location.path.as_str(), location.strip_path))
            .collect();

        // Not set, it is off.
        assert_eq!(
            locations,
            [("/stripped/", true), ("/kept/", false), ("/", false)]
        );
    }
    /// The lists show the countries as they are compared - codes of two letters - and a list
    /// which does not compile says why, before a host naming it fails to load.
    #[test]
    fn the_summary_shows_the_country_lists_and_who_names_them() {
        let hosts: HashMap<String, HostSettings> = serde_yaml::from_str(
            [
                "'localhost:8000':",
                "  endpoint:",
                "    type: http",
                "    whitelisted_country: europe",
                "  locations:",
                "  - path: /admin",
                "    proxy_pass_to: http://127.0.0.1:9000",
                "    whitelisted_country: only_ua",
            ]
            .join("\n")
            .as_str(),
        )
        .unwrap();

        let country_white_lists = HashMap::from([
            (
                "europe".to_string(),
                vec!["pol".to_string(), "DE".to_string()],
            ),
            ("only_ua".to_string(), vec!["UA".to_string()]),
            ("typo".to_string(), vec!["XX".to_string()]),
        ]);

        let settings = SettingsCompiled {
            hosts,
            country_white_lists,
            ..Default::default()
        };

        let summary = build_settings_summary(&settings, String::new(), vec![]);

        assert_eq!(summary.hosts[0].whitelisted_country, "europe");
        assert_eq!(summary.hosts[0].locations[0].whitelisted_country, "only_ua");

        let lists: Vec<_> = summary
            .country_white_lists
            .iter()
            .map(|list| {
                (
                    list.id.as_str(),
                    list.countries.join(","),
                    list.error.is_empty(),
                )
            })
            .collect();

        assert_eq!(
            lists,
            [
                ("europe", "DE,PL".to_string(), true),
                ("only_ua", "UA".to_string(), true),
                ("typo", String::new(), false),
            ]
        );
        assert!(
            summary.country_white_lists[2]
                .error
                .contains("'XX' is not a country code"),
            "{}",
            summary.country_white_lists[2].error
        );
    }

    /// A set named by an `api_keys_auth` and declared nowhere is listed with no keys: every
    /// request to what it guards is refused. No key is ever in the summary.
    #[test]
    fn the_summary_counts_the_keys_and_never_shows_one() {
        let hosts: HashMap<String, HostSettings> = serde_yaml::from_str(
            [
                "'localhost:8000':",
                "  endpoint:",
                "    type: http",
                "    api_keys_auth: mcp_clients",
                "  locations:",
                "  - path: /admin",
                "    proxy_pass_to: http://127.0.0.1:9000",
                "    api_keys_auth: admins",
                "  - path: /health",
                "    proxy_pass_to: http://127.0.0.1:9000",
                "    api_keys_auth: none",
            ]
            .join("\n")
            .as_str(),
        )
        .unwrap();

        let settings = SettingsCompiled {
            hosts,
            api_keys: HashMap::from([(
                "mcp_clients".to_string(),
                vec!["file-key-1".to_string(), "file-key-2".to_string()],
            )]),
            dynamic_api_keys: HashMap::from([
                (
                    "mcp_clients".to_string(),
                    vec!["file-key-1".to_string(), "url-key".to_string()],
                ),
                ("not_used".to_string(), vec!["url-key-2".to_string()]),
            ]),
            ..Default::default()
        };

        let summary = build_settings_summary(&settings, String::new(), vec![]);

        let api_keys: Vec<_> = summary
            .api_keys
            .iter()
            .map(|itm| {
                (
                    itm.id.as_str(),
                    itm.keys,
                    itm.keys_in_files,
                    itm.keys_from_urls,
                    itm.used,
                )
            })
            .collect();

        assert_eq!(
            api_keys,
            [
                ("admins", 0, 0, 0, true),
                ("mcp_clients", 3, 2, 2, true),
                ("not_used", 1, 0, 1, false),
            ]
        );

        assert_eq!(summary.hosts[0].api_keys_auth, "mcp_clients");
        assert_eq!(summary.hosts[0].locations[1].api_keys_auth, "none");

        let json = serde_json::to_string(&summary).unwrap();
        for key in ["file-key-1", "file-key-2", "url-key"] {
            assert!(!json.contains(key), "{json}");
        }
    }
}

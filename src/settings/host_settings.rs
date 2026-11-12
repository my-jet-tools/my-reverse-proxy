use serde::*;

use super::*;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HostSettings {
    /// More names of this host: a request for one is served by this configuration, under the
    /// name. A name is on the port of this host - `www.example.com`, or `www.example.com:443`
    /// for `example.com:443`; one on another port is ignored with an error. See
    /// `settings_compiled::get_additional_host_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_hosts: Option<Vec<String>>,
    pub endpoint: EndpointSettings,
    pub locations: Vec<LocationSettings>,
}

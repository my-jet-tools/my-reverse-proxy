use serde::*;

use super::*;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HostSettings {
    /// More hosts served with this same configuration: a domain name is served on the port of
    /// this host, a `domain:port` on that port. See `settings_compiled::expand_additional_hosts`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_hosts: Option<Vec<String>>,
    pub endpoint: EndpointSettings,
    pub locations: Vec<LocationSettings>,
}

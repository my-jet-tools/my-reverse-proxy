use std::net::IpAddr;

use serde::*;

use super::{ConnectionsSettings, ModifyHttpHeadersSettings, TimeoutsSettings};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GlobalSettings {
    pub connection_settings: Option<ConnectionsSettings>,
    pub all_http_endpoints: Option<AllHttpEndpointsGlobalSettings>,
    pub show_error_description_on_error_page: Option<bool>,
    pub http_control_port: Option<u16>,
    /// The address the control port listens on - an IPv4 or IPv6 one. Absent = `0.0.0.0`, every
    /// IPv4 address of the host. Nothing served there asks who is calling, so `127.0.0.1` keeps
    /// it to the host itself.
    pub http_control_ip: Option<String>,
    pub default_h2_livness_url: Option<String>,
    /// Global allow-list for the automatic IP block-list (fail2ban): source IPs
    /// (single addresses or `from-to` ranges) whose failed connections are never
    /// counted and which are never treated as blocked. Empty/absent = no
    /// exemptions.
    #[serde(default)]
    pub ip_blocklist_white_list: Option<Vec<String>>,
    /// Source IPs that are shown a detailed diagnostic page when their request
    /// is refused before an endpoint is resolved (unknown / undetectable host).
    /// Everybody else gets a bare `400 Bad Request`. A single address or a
    /// list of them, IPv4 or IPv6, exact addresses only. Empty/absent = nobody.
    #[serde(default)]
    pub debug_ip: Option<DebugIpSettings>,
    /// How often the (single, global) supervisor sweeps every H1/H2 upstream
    /// pool, in milliseconds. Defaults to 10000 (10s). Global-only — a single
    /// timer drives every pool, so it is not part of the cascade.
    pub pool_supervisor_interval: Option<u64>,
    /// Lowest level of the timeout cascade — overridden by the endpoint, then
    /// the location.
    #[serde(flatten)]
    pub timeouts: TimeoutsSettings,
}

impl GlobalSettings {
    /// Parsed `debug_ip`. Errors on an entry that is not an IP address, so a
    /// typo fails the settings load instead of silently matching nobody.
    pub fn get_debug_ip(&self) -> Result<Vec<IpAddr>, String> {
        let items: &[String] = match self.debug_ip.as_ref() {
            Some(DebugIpSettings::Single(ip)) => std::slice::from_ref(ip),
            Some(DebugIpSettings::List(list)) => list,
            None => &[],
        };

        let mut result = Vec::with_capacity(items.len());
        for itm in items {
            let itm = itm.trim();
            if itm.is_empty() {
                continue;
            }

            match itm.parse::<IpAddr>() {
                Ok(ip) => result.push(ip),
                Err(_) => {
                    return Err(format!(
                        "global_settings.debug_ip: '{}' is not a valid ip address",
                        itm
                    ));
                }
            }
        }

        Ok(result)
    }

    /// Parsed `http_control_ip`. Errors on a value that is not an IP address: the control port
    /// does not fall back to listening on every address because of a typo.
    pub fn get_http_control_ip(&self) -> Result<Option<IpAddr>, String> {
        let Some(ip) = self.http_control_ip.as_ref() else {
            return Ok(None);
        };

        match ip.trim().parse::<IpAddr>() {
            Ok(ip) => Ok(Some(ip)),
            Err(_) => Err(format!(
                "global_settings.http_control_ip: '{}' is not a valid ip address",
                ip
            )),
        }
    }
}

/// `debug_ip:` takes either one address or a list of them.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum DebugIpSettings {
    Single(String),
    List(Vec<String>),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AllHttpEndpointsGlobalSettings {
    pub modify_http_headers: Option<ModifyHttpHeadersSettings>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> GlobalSettings {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn debug_ip_is_absent_by_default() {
        let settings = parse("http_control_port: 9000");

        assert!(settings.get_debug_ip().unwrap().is_empty());
    }

    #[test]
    fn debug_ip_accepts_a_single_address() {
        let settings = parse("debug_ip: 10.0.0.5");

        assert_eq!(
            settings.get_debug_ip().unwrap(),
            vec!["10.0.0.5".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn debug_ip_accepts_a_list() {
        let settings = parse("debug_ip:\n- 10.0.0.5\n- \"::1\"\n- \"\"");

        assert_eq!(
            settings.get_debug_ip().unwrap(),
            vec![
                "10.0.0.5".parse::<IpAddr>().unwrap(),
                "::1".parse::<IpAddr>().unwrap()
            ]
        );
    }

    #[test]
    fn debug_ip_refuses_what_is_not_an_address() {
        let settings = parse("debug_ip: 10.0.0.5-10.0.0.9");

        let err = settings.get_debug_ip().unwrap_err();

        assert!(err.contains("10.0.0.5-10.0.0.9"), "{err}");
    }

    #[test]
    fn http_control_ip_is_absent_by_default() {
        let settings = parse("http_control_port: 9000");

        assert_eq!(settings.get_http_control_ip().unwrap(), None);
    }

    #[test]
    fn http_control_ip_accepts_ipv4_and_ipv6() {
        let settings = parse("http_control_ip: 127.0.0.1");
        assert_eq!(
            settings.get_http_control_ip().unwrap(),
            Some("127.0.0.1".parse::<IpAddr>().unwrap())
        );

        let settings = parse("http_control_ip: \"::1\"");
        assert_eq!(
            settings.get_http_control_ip().unwrap(),
            Some("::1".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn http_control_ip_refuses_what_is_not_an_address() {
        for value in ["localhost", "127.0.0.1:9000", "10.0.0.300", "\"\""] {
            let settings = parse(&format!("http_control_ip: {value}"));

            let err = settings.get_http_control_ip().unwrap_err();

            assert!(err.contains("global_settings.http_control_ip"), "{err}");
        }
    }
}

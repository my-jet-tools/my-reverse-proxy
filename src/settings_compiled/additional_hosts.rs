use std::collections::HashSet;

use crate::{
    configurations::{EndpointHttpHostString, EndpointPort},
    settings::{EndpointTypeSettings, HostSettings},
};

/// One host of the settings, once its `additional_hosts` are put out as hosts of their own.
#[derive(Debug)]
pub struct ExpandedHost {
    pub host_id: String,
    pub host_settings: HostSettings,
    /// The host whose `additional_hosts` this one is in - `None` for that host itself.
    pub additional_host_of: Option<String>,
}

/// A host and the ones of its `additional_hosts`: one configuration, served under each of these
/// hosts - every one of them is a host of its own, with a copy of the same settings, from here on.
///
/// An entry of `additional_hosts` is a domain name, served on the port of the host
/// (`www.example.com` under `example.com:443` is `www.example.com:443`), or a domain name and a
/// port of its own (`www.example.com:8443`). The host is first, its additional hosts follow in
/// the order they are written in. None of them keeps `additional_hosts`.
///
/// Fails if the host has no domain name to stand next to (a port alone, a unix socket), is
/// `type: tcp` - which takes its whole port - or an entry is not a domain name, or is there twice.
pub fn expand_additional_hosts(
    host_id: String,
    mut host_settings: HostSettings,
) -> Result<Vec<ExpandedHost>, String> {
    let additional_hosts = host_settings.additional_hosts.take().unwrap_or_default();

    if additional_hosts.is_empty() {
        return Ok(vec![ExpandedHost {
            host_id,
            host_settings,
            additional_host_of: None,
        }]);
    }

    let mut taken = HashSet::new();
    taken.insert(host_id.to_ascii_lowercase());

    let mut result = Vec::with_capacity(additional_hosts.len() + 1);

    for additional_host in additional_hosts {
        let additional_host_id =
            get_additional_host_id(&host_id, &host_settings, &additional_host)?;

        if !taken.insert(additional_host_id.to_ascii_lowercase()) {
            return Err(format!(
                "Host '{host_id}': '{}' of additional_hosts is there twice, or is the host itself",
                additional_host.trim()
            ));
        }

        result.push(ExpandedHost {
            host_id: additional_host_id,
            host_settings: host_settings.clone(),
            additional_host_of: Some(host_id.clone()),
        });
    }

    result.insert(
        0,
        ExpandedHost {
            host_id,
            host_settings,
            additional_host_of: None,
        },
    );

    Ok(result)
}

/// The host id of `additional_host`, an entry of `additional_hosts` of `host_id`: a domain name
/// gets the port of `host_id`, a domain name and a port is the host id as it is.
///
/// Fails if `host_id` can not have additional hosts - it has no domain name to stand next to
/// (a port alone, a unix socket), or is `type: tcp`, which takes its whole port - or the entry is
/// not a domain name.
pub fn get_additional_host_id(
    host_id: &str,
    host_settings: &HostSettings,
    additional_host: &str,
) -> Result<String, String> {
    let port = get_port_of_named_host(host_id).ok_or_else(|| {
        format!(
            "Host '{host_id}': additional_hosts needs a host with a domain name and a port, like 'example.com:443'"
        )
    })?;

    if let Ok(EndpointTypeSettings::Tcp) = host_settings.endpoint.get_endpoint_type() {
        return Err(format!(
            "Host '{host_id}': additional_hosts can not be used with type: tcp - a tcp endpoint takes its whole port"
        ));
    }

    let additional_host = additional_host.trim();

    let additional_host_id = if additional_host.contains(':') {
        additional_host.to_string()
    } else {
        format!("{additional_host}:{port}")
    };

    if get_port_of_named_host(&additional_host_id).is_none() {
        return Err(format!(
            "Host '{host_id}': '{additional_host}' of additional_hosts is neither a domain name nor a domain name and a port"
        ));
    }

    Ok(additional_host_id)
}

/// The tcp port of a `domain:port` host id - `None` for a port alone, a unix socket, or what is
/// not a host id.
fn get_port_of_named_host(host_id: &str) -> Option<u16> {
    let host_endpoint = EndpointHttpHostString::new(host_id.to_string()).ok()?;

    let server_name = host_endpoint.get_server_name()?;

    // A name of digits only is a port written without its colon, not a domain name.
    if server_name.is_empty()
        || server_name.chars().all(|c| c.is_ascii_digit())
        || server_name
            .chars()
            .any(|c| c.is_whitespace() || c == '/' || c == ':')
    {
        return None;
    }

    match host_endpoint.get_port() {
        EndpointPort::Tcp(port) => Some(port),
        EndpointPort::UnixSocket(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(yaml: &str) -> HostSettings {
        crate::settings::DynamicHostsModel::parse(format!("hosts:\n  'host':\n{yaml}").as_bytes())
            .unwrap()
            .unwrap()
            .hosts
            .remove("host")
            .unwrap()
    }

    const HTTP: &str = "    endpoint:\n      type: http\n    locations:\n    - proxy_pass_to: http://127.0.0.1:9000\n";

    fn with_additional_hosts(endpoint_type: &str, additional_hosts: &[&str]) -> HostSettings {
        let mut host_settings =
            host(&HTTP.replace("type: http", &format!("type: {endpoint_type}")));
        host_settings.additional_hosts =
            Some(additional_hosts.iter().map(|itm| itm.to_string()).collect());
        host_settings
    }

    fn ids(expanded: &[ExpandedHost]) -> Vec<(&str, Option<&str>)> {
        expanded
            .iter()
            .map(|itm| (itm.host_id.as_str(), itm.additional_host_of.as_deref()))
            .collect()
    }

    #[test]
    fn additional_hosts_are_read_from_the_settings() {
        let host_settings = host(&format!(
            "    additional_hosts:\n    - www.example.com\n    - api.example.com:8443\n{HTTP}"
        ));

        assert_eq!(
            host_settings.additional_hosts.as_deref(),
            Some(
                &[
                    "www.example.com".to_string(),
                    "api.example.com:8443".to_string()
                ][..]
            )
        );
    }

    #[test]
    fn a_host_without_additional_hosts_is_itself_only() {
        for host_settings in [host(HTTP), with_additional_hosts("http", &[])] {
            let expanded =
                expand_additional_hosts("example.com:443".to_string(), host_settings).unwrap();

            assert_eq!(ids(&expanded), [("example.com:443", None)]);
        }

        // Neither a port alone nor a unix socket needs a domain name without additional_hosts.
        for host_id in ["8000", "/var/run/proxy.sock"] {
            assert_eq!(
                expand_additional_hosts(host_id.to_string(), host(HTTP))
                    .unwrap()
                    .len(),
                1
            );
        }
    }

    #[test]
    fn every_additional_host_is_a_host_with_the_same_settings() {
        let expanded = expand_additional_hosts(
            "example.com:443".to_string(),
            with_additional_hosts(
                "https2",
                &["www.example.com", " api.example.com ", "example.com:8443"],
            ),
        )
        .unwrap();

        assert_eq!(
            ids(&expanded),
            [
                ("example.com:443", None),
                ("www.example.com:443", Some("example.com:443")),
                ("api.example.com:443", Some("example.com:443")),
                ("example.com:8443", Some("example.com:443")),
            ]
        );

        for itm in &expanded {
            assert!(
                itm.host_settings.additional_hosts.is_none(),
                "{}",
                itm.host_id
            );
            assert_eq!(itm.host_settings.endpoint.endpoint_type, "https2");
            assert_eq!(
                itm.host_settings.locations[0].proxy_pass_to.as_deref(),
                Some("http://127.0.0.1:9000")
            );
        }
    }

    #[test]
    fn additional_hosts_are_refused_where_they_can_not_be_served() {
        for (host_id, endpoint_type, additional_hosts, expected) in [
            ("8000", "http", &["www.example.com"][..], "needs a host"),
            (
                "/var/run/proxy.sock",
                "http",
                &["www.example.com"],
                "needs a host",
            ),
            ("example.com:5432", "tcp", &["www.example.com"], "type: tcp"),
            ("example.com:443", "http", &[""], "neither"),
            ("example.com:443", "http", &[":443"], "neither"),
            ("example.com:443", "http", &["8443"], "neither"),
            (
                "example.com:443",
                "http",
                &["www.example.com:http"],
                "neither",
            ),
            (
                "example.com:443",
                "http",
                &["/var/run/other.sock"],
                "neither",
            ),
            ("example.com:443", "http", &["www example.com"], "neither"),
            ("example.com:443", "http", &["a:b:443"], "neither"),
            (
                "example.com:443",
                "http",
                &["www.example.com", "WWW.example.com"],
                "twice",
            ),
            ("example.com:443", "http", &["example.com"], "twice"),
            ("example.com:443", "http", &["Example.com:443"], "twice"),
        ] {
            let err = expand_additional_hosts(
                host_id.to_string(),
                with_additional_hosts(endpoint_type, additional_hosts),
            )
            .unwrap_err();

            assert!(
                err.contains(expected),
                "{host_id} {additional_hosts:?}: {err}"
            );
        }
    }
}

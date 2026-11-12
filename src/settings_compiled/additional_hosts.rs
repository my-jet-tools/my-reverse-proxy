use crate::{
    configurations::{EndpointHttpHostString, EndpointPort},
    settings::{EndpointTypeSettings, HostSettings},
};

/// A name of `additional_hosts`, and the host it is a name of. A request for the name is served
/// by that host's configuration - under the name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdditionalHost {
    /// The host whose configuration the name is served with: a key of `hosts`.
    pub host_id: String,
    /// The name came from `dynamic_hosts.url`. Its host may be one of the settings files.
    pub dynamic: bool,
}

/// The id of `entry`, an entry of `additional_hosts` of `host_id`: the name on the port of the
/// host - `www.example.com` of `example.com:443` is `www.example.com:443`. A name is served on
/// the port of its host only: `www.example.com:443` is taken as it is, `www.example.com:8443`
/// is refused.
///
/// Fails - with why, to be told about with the entry - if the host can not have names (it has
/// no domain name to stand next to: a port alone, a unix socket; or it is `type: tcp`, which
/// takes its whole port), or the entry is not a domain name, or names another port.
pub fn get_additional_host_id(
    host_id: &str,
    host_settings: &HostSettings,
    entry: &str,
) -> Result<String, String> {
    let port = get_port_of_named_host(host_id).ok_or_else(|| {
        format!("additional_hosts needs a host with a domain name and a port, like 'example.com:443' - '{host_id}' is not one")
    })?;

    if let Ok(EndpointTypeSettings::Tcp) = host_settings.endpoint.get_endpoint_type() {
        return Err(
            "additional_hosts can not be used with type: tcp - a tcp endpoint takes its whole port"
                .to_string(),
        );
    }

    let entry = entry.trim();

    let (name, entry_port) = match entry.split_once(':') {
        Some((name, entry_port)) => (name, Some(entry_port)),
        None => (entry, None),
    };

    if !is_domain_name(name) {
        return Err("it is not a domain name".to_string());
    }

    if let Some(entry_port) = entry_port {
        match entry_port.parse::<u16>() {
            Ok(entry_port) if entry_port == port => {}
            Ok(entry_port) => {
                return Err(format!(
                    "it is on port {entry_port}, and a name is served on the port of its host - {port}"
                ));
            }
            Err(_) => return Err("it is not a domain name".to_string()),
        }
    }

    Ok(format!("{name}:{port}"))
}

/// A name a `Host` header or an SNI can carry: letters, digits, `-`, `_` and dots. Not digits
/// alone - that is a port written without its colon - and no `*`: a name is matched as it is.
fn is_domain_name(name: &str) -> bool {
    !name.is_empty()
        && !name.chars().all(|c| c.is_ascii_digit())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
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

    fn host(endpoint_type: &str) -> HostSettings {
        crate::settings::DynamicHostsModel::parse(
            format!(
                "hosts:\n  'host':\n    endpoint:\n      type: {endpoint_type}\n    locations:\n    - proxy_pass_to: http://127.0.0.1:9000\n"
            )
            .as_bytes(),
        )
        .unwrap()
        .unwrap()
        .hosts
        .remove("host")
        .unwrap()
    }

    #[test]
    fn additional_hosts_are_read_from_the_settings() {
        let host_settings = crate::settings::DynamicHostsModel::parse(
            b"hosts:\n  'host':\n    additional_hosts:\n    - www.example.com\n    - api.example.com:443\n    endpoint:\n      type: http\n    locations:\n    - proxy_pass_to: http://127.0.0.1:9000\n",
        )
        .unwrap()
        .unwrap()
        .hosts
        .remove("host")
        .unwrap();

        assert_eq!(
            host_settings.additional_hosts.as_deref(),
            Some(
                &[
                    "www.example.com".to_string(),
                    "api.example.com:443".to_string()
                ][..]
            )
        );
    }

    /// A name is on the port of its host: written with it or without it.
    #[test]
    fn a_name_is_on_the_port_of_its_host() {
        for (entry, expected) in [
            ("www.example.com", "www.example.com:443"),
            (" api.example.com ", "api.example.com:443"),
            ("Api.Example.com:443", "Api.Example.com:443"),
            ("api.example.com:0443", "api.example.com:443"),
            ("10.0.0.5", "10.0.0.5:443"),
            ("tenant_1.example.com", "tenant_1.example.com:443"),
        ] {
            assert_eq!(
                get_additional_host_id("example.com:443", &host("https2"), entry).as_deref(),
                Ok(expected),
                "{entry}"
            );
        }
    }

    #[test]
    fn a_name_which_can_not_be_served_is_refused() {
        for (host_id, endpoint_type, entry, expected) in [
            ("8000", "http", "www.example.com", "needs a host"),
            (
                "/var/run/proxy.sock",
                "http",
                "www.example.com",
                "needs a host",
            ),
            ("example.com:5432", "tcp", "www.example.com", "type: tcp"),
            (
                "example.com:443",
                "http",
                "www.example.com:8443",
                "on port 8443",
            ),
            ("example.com:443", "http", "", "not a domain name"),
            ("example.com:443", "http", ":443", "not a domain name"),
            ("example.com:443", "http", "8443", "not a domain name"),
            (
                "example.com:443",
                "http",
                "*.example.com",
                "not a domain name",
            ),
            (
                "example.com:443",
                "http",
                "www.example.com:http",
                "not a domain name",
            ),
            (
                "example.com:443",
                "http",
                "/var/run/other.sock",
                "not a domain name",
            ),
            (
                "example.com:443",
                "http",
                "www example.com",
                "not a domain name",
            ),
            ("example.com:443", "http", "a:b:443", "not a domain name"),
        ] {
            let err = get_additional_host_id(host_id, &host(endpoint_type), entry).unwrap_err();

            assert!(err.contains(expected), "{host_id} {entry:?}: {err}");
        }
    }
}

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use serde::*;

use super::{ConnectionsSettings, ModifyHttpHeadersSettings, TimeoutsSettings};

/// The port of the control port when `http_control_port` is not given.
pub const DEFAULT_HTTP_CONTROL_PORT: u16 = 8000;

/// The address the control port listens on when the settings name none. Nothing served there
/// asks who is calling, so it is the host itself unless the settings open it up.
pub const DEFAULT_HTTP_CONTROL_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// The control port when the settings say nothing of it: `127.0.0.1:8000`.
pub fn default_http_control_addr() -> SocketAddr {
    SocketAddr::new(DEFAULT_HTTP_CONTROL_IP, DEFAULT_HTTP_CONTROL_PORT)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GlobalSettings {
    pub connection_settings: Option<ConnectionsSettings>,
    pub all_http_endpoints: Option<AllHttpEndpointsGlobalSettings>,
    /// A 4xx/5xx page of the proxy shows the error behind it - to the `debug_ip` sources only:
    /// the error tells of upstreams, files and hosts inside. Everybody else gets the title alone.
    pub show_error_description_on_error_page: Option<bool>,
    /// The control port: a port - `9000`, served on `127.0.0.1` - or the whole address it listens
    /// on - `0.0.0.0:9000`, `"[::]:9000"`. Absent = `127.0.0.1:8000`.
    pub http_control_port: Option<HttpControlPortSettings>,
    /// The address the control port listens on - an IPv4 or IPv6 one - when `http_control_port`
    /// is a bare port. The other way of saying `http_control_port: 0.0.0.0:9000`; the two may not
    /// both name one.
    pub http_control_ip: Option<String>,
    /// The control port on a unix socket too: the path of the socket, `~` expanded. The same admin
    /// ui, `/api`, `/swagger` and `/mcp` as on `http_control_port`. `control-unix-socket` is read
    /// as well. Bound at startup.
    #[serde(alias = "control-unix-socket")]
    pub control_unix_socket: Option<String>,
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
    /// The file of the secure store: what `POST /api/initialize` opens with the files key, or
    /// creates. It has to be on a volume the proxy can write to. Absent:
    /// `~/.my-reverse-proxy-secure`.
    pub secure_store_file: Option<String>,
    /// `max_buffered_request_body` of every endpoint which names none: the most of one request
    /// body the proxy holds in memory. Absent: `100Mb`. See [`crate::types::BufferedBodyLimits`].
    pub max_buffered_request_body: Option<String>,
    /// The most all the request bodies held in memory at once may take, the endpoints together.
    /// A body which would go over it is answered `503`. Absent: `512Mb`.
    pub max_buffered_request_bodies_total: Option<String>,
    /// After so many requests a client connection is closed - an h2 one with a GOAWAY. Absent:
    /// 1000. See [`crate::types::ConnectionSettings`].
    pub max_requests_per_connection: Option<u32>,
    /// The most the head of an http/1.1 request may take. Absent: `64Kb`.
    pub max_request_head_size: Option<String>,
    /// The requests an h2 client may have open at once on one connection. Absent: 128.
    pub h2_max_concurrent_streams: Option<u32>,
    /// The most the decoded headers of an h2 request may take. Absent: `16Kb`.
    pub h2_max_header_list_size: Option<String>,
    /// `max_request_body` of every endpoint which names none: the most any request body may take.
    /// Absent: no limit but the ones of the bodies held in memory.
    pub max_request_body: Option<String>,
    /// A line for every request the http/https endpoints answer goes to this file, `~` expanded -
    /// nginx's `access_log`. Absent: no access log. See [`crate::access_log`].
    pub access_log: Option<String>,
    /// The access log is turned over past this size. Absent: `100Mb`.
    pub access_log_max_size: Option<String>,
    /// The turned-over files of the access log which are kept. Absent: 5.
    pub access_log_files: Option<u32>,
    /// `tls_min_version` of every endpoint which names none: `1.2` or `1.3`. Absent: `1.2`.
    #[serde(default, deserialize_with = "crate::types::number_or_text")]
    pub tls_min_version: Option<String>,
    /// The client connections every port of `hosts` holds at once. A connection over it is
    /// closed as it is accepted. Absent: half the open files limit of the process. See
    /// [`crate::app::ConnectionLimits`].
    pub max_connections: Option<usize>,
    /// ... of them from one address - Cloudflare and `ip_blocklist_white_list` aside. Absent:
    /// 1000.
    pub max_connections_per_ip: Option<usize>,
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

    /// The limits of the request bodies held in memory, for an endpoint which names no
    /// `max_buffered_request_body` of its own. Errors on a value which is not a size, so a typo
    /// fails the settings load.
    pub fn get_buffered_body_limits(&self) -> Result<crate::types::BufferedBodyLimits, String> {
        crate::types::BufferedBodyLimits::resolve(
            self.max_buffered_request_body.as_deref(),
            self.max_buffered_request_bodies_total.as_deref(),
            None,
        )
    }

    /// The limits of a client connection. Errors on a value out of its range, so a typo fails
    /// the settings load.
    pub fn get_connection_settings(&self) -> Result<crate::types::ConnectionSettings, String> {
        crate::types::ConnectionSettings::resolve(
            self.max_requests_per_connection,
            self.max_request_head_size.as_deref(),
            self.h2_max_concurrent_streams,
            self.h2_max_header_list_size.as_deref(),
        )
    }

    /// `max_request_body`, for an endpoint which names none. Errors on a value which is not a
    /// size, and on `0`.
    pub fn get_max_request_body(&self) -> Result<Option<usize>, String> {
        crate::types::resolve_max_request_body(self.max_request_body.as_deref(), None)
    }

    /// `access_log`, `access_log_max_size` and `access_log_files`: `None` - no access log.
    pub fn get_access_log(&self) -> Result<Option<crate::access_log::AccessLogSettings>, String> {
        crate::access_log::AccessLogSettings::resolve(
            self.access_log.as_deref(),
            self.access_log_max_size.as_deref(),
            self.access_log_files,
        )
    }

    /// `tls_min_version`, for an endpoint which names none.
    pub fn get_tls_min_version(&self) -> Result<crate::types::TlsMinVersion, String> {
        crate::types::TlsMinVersion::resolve(self.tls_min_version.as_deref(), None)
    }

    /// `max_connections` and `max_connections_per_ip`. Errors on `0`.
    pub fn get_connection_limits(&self) -> Result<crate::app::ConnectionLimitsSettings, String> {
        crate::app::ConnectionLimitsSettings::resolve(
            self.max_connections,
            self.max_connections_per_ip,
        )
    }

    /// `control_unix_socket` with `~` expanded - `None` when it is not given. An error on a
    /// platform without unix sockets: the control port does not quietly go without the socket.
    pub fn get_control_unix_socket(&self) -> Result<Option<String>, String> {
        let Some(path) = self
            .control_unix_socket
            .as_deref()
            .map(str::trim)
            .filter(|path| !path.is_empty())
        else {
            return Ok(None);
        };

        if !cfg!(unix) {
            return Err(format!(
                "global_settings.control_unix_socket: '{path}' - unix sockets are not supported on this platform"
            ));
        }

        super::expand_home(path).map(Some)
    }

    /// The address the control port listens on, out of `http_control_port` and `http_control_ip`.
    ///
    /// Errors on a value which is neither a port nor an address, and on an address given twice:
    /// the control port does not end up on another address than the one meant because of a typo.
    pub fn get_http_control_addr(&self) -> Result<SocketAddr, String> {
        let ip = self.get_http_control_ip()?;

        let port = match self.http_control_port.as_ref() {
            None => DEFAULT_HTTP_CONTROL_PORT,
            Some(HttpControlPortSettings::Port(port)) => *port,
            Some(HttpControlPortSettings::Address(value)) => {
                let value = value.trim();

                if let Ok(port) = value.parse::<u16>() {
                    port
                } else if let Ok(addr) = value.parse::<SocketAddr>() {
                    if let Some(ip) = ip {
                        return Err(format!(
                            "global_settings: the address of the control port is given twice - \
                             http_control_port: '{value}' and http_control_ip: '{ip}'. Keep one of them"
                        ));
                    }

                    return Ok(addr);
                } else {
                    return Err(format!(
                        "global_settings.http_control_port: '{value}' is neither a port (9000) \
                         nor an address with a port (0.0.0.0:9000, \"[::]:9000\")"
                    ));
                }
            }
        };

        Ok(SocketAddr::new(ip.unwrap_or(DEFAULT_HTTP_CONTROL_IP), port))
    }

    /// Parsed `http_control_ip`. Errors on a value that is not an IP address: the control port
    /// does not fall back to the default address because of a typo.
    fn get_http_control_ip(&self) -> Result<Option<IpAddr>, String> {
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

/// `http_control_port:` takes either a port or the whole address: `9000`, `0.0.0.0:9000`.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum HttpControlPortSettings {
    Port(u16),
    Address(String),
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
    fn the_control_unix_socket_is_a_path_with_home_expanded() {
        assert_eq!(
            parse("http_control_port: 9000").get_control_unix_socket(),
            Ok(None)
        );
        assert_eq!(
            parse("control_unix_socket: ''").get_control_unix_socket(),
            Ok(None)
        );

        let settings = parse("control_unix_socket: /var/run/my-reverse-proxy-control.sock");
        assert_eq!(
            settings.get_control_unix_socket(),
            Ok(Some("/var/run/my-reverse-proxy-control.sock".to_string()))
        );

        // Written the way the other settings of the services are written, too.
        let settings = parse("control-unix-socket: ~/sockets/control.sock");
        assert_eq!(
            settings.get_control_unix_socket(),
            Ok(Some(format!(
                "{}/sockets/control.sock",
                crate::settings::home_dir().unwrap()
            )))
        );
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

            let err = settings.get_http_control_addr().unwrap_err();

            assert!(err.contains("global_settings.http_control_ip"), "{err}");
        }
    }

    fn addr(value: &str) -> SocketAddr {
        value.parse().unwrap()
    }

    /// Nothing served on the control port asks who is calling: unless the settings open it up,
    /// it is the host's own.
    #[test]
    fn the_control_port_is_the_hosts_own_by_default() {
        let settings = parse("show_error_description_on_error_page: false");
        assert_eq!(
            settings.get_http_control_addr().unwrap(),
            addr("127.0.0.1:8000")
        );
        assert_eq!(default_http_control_addr(), addr("127.0.0.1:8000"));

        let settings = parse("http_control_port: 9000");
        assert_eq!(
            settings.get_http_control_addr().unwrap(),
            addr("127.0.0.1:9000")
        );

        // A port written in quotes is a port all the same.
        let settings = parse("http_control_port: \"9000\"");
        assert_eq!(
            settings.get_http_control_addr().unwrap(),
            addr("127.0.0.1:9000")
        );
    }

    #[test]
    fn http_control_port_takes_the_whole_address() {
        let settings = parse("http_control_port: 0.0.0.0:8000");
        assert_eq!(
            settings.get_http_control_addr().unwrap(),
            addr("0.0.0.0:8000")
        );

        let settings = parse("http_control_port: 10.0.0.5:9000");
        assert_eq!(
            settings.get_http_control_addr().unwrap(),
            addr("10.0.0.5:9000")
        );

        // `[` opens a list in yaml: an IPv6 address goes in quotes.
        let settings = parse("http_control_port: \"[::]:9000\"");
        assert_eq!(settings.get_http_control_addr().unwrap(), addr("[::]:9000"));
    }

    #[test]
    fn http_control_ip_gives_the_address_of_a_bare_port() {
        let settings = parse("http_control_port: 9000\nhttp_control_ip: 0.0.0.0");
        assert_eq!(
            settings.get_http_control_addr().unwrap(),
            addr("0.0.0.0:9000")
        );

        let settings = parse("http_control_ip: \"::1\"");
        assert_eq!(
            settings.get_http_control_addr().unwrap(),
            addr("[::1]:8000")
        );
    }

    #[test]
    fn the_address_may_not_be_given_twice() {
        let settings = parse("http_control_port: 0.0.0.0:9000\nhttp_control_ip: 127.0.0.1");

        let err = settings.get_http_control_addr().unwrap_err();

        assert!(err.contains("given twice"), "{err}");
        assert!(err.contains("0.0.0.0:9000"), "{err}");
        assert!(err.contains("127.0.0.1"), "{err}");
    }

    #[test]
    fn http_control_port_refuses_what_is_neither_a_port_nor_an_address() {
        for value in [
            "localhost:9000",
            "0.0.0.0",
            // A trailing `:` is yaml of its own: in quotes.
            "\"0.0.0.0:\"",
            "0.0.0.0:70000",
            "\"::1:9000\"",
            "\"\"",
        ] {
            let settings = parse(&format!("http_control_port: {value}"));

            let err = settings.get_http_control_addr().unwrap_err();

            assert!(
                err.contains("global_settings.http_control_port"),
                "{value}: {err}"
            );
        }

        // Out of the range of a port: not a value of the setting at all.
        assert!(serde_yaml::from_str::<GlobalSettings>("http_control_port: 70000").is_err());
    }
}

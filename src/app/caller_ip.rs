use std::net::IpAddr;

use my_http_server::{HttpRequest, HttpRequestHeaders, SocketAddress};

/// Where a call of the control port comes from: an address, or this host itself - its unix socket,
/// or its loopback with no proxy in between.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerIp {
    Ip(IpAddr),
    ThisHost,
}

impl CallerIp {
    /// The caller of a request which came from `peer` - `None`: the unix socket - with the
    /// `X-Forwarded-For` it came with. A request the proxy relays to the control port comes from
    /// its loopback, with the header the proxy writes: the address of its client, the last entry
    /// of the header. The header of a request from anywhere else is not believed - it is the
    /// client's own word.
    pub fn of(peer: Option<IpAddr>, x_forwarded_for: Option<&str>) -> Self {
        let Some(peer) = peer.map(|ip| ip.to_canonical()) else {
            return Self::ThisHost;
        };

        if !peer.is_loopback() {
            return Self::Ip(peer);
        }

        let relayed_for = x_forwarded_for
            .and_then(|value| value.rsplit(',').next())
            .and_then(|last| last.trim().parse::<IpAddr>().ok());

        match relayed_for {
            Some(client) => Self::Ip(client.to_canonical()),
            None => Self::ThisHost,
        }
    }

    pub fn of_request(request: &HttpRequest) -> Self {
        let peer = match &request.addr {
            SocketAddress::Tcp(addr) => Some(addr.ip()),
            SocketAddress::Unix(_) => None,
        };

        let x_forwarded_for = request
            .get_headers()
            .try_get_case_insensitive("x-forwarded-for")
            .and_then(|value| value.as_str().ok());

        Self::of(peer, x_forwarded_for)
    }

    /// The country of the address, the ISO 3166 code of two letters - `-` for one the country
    /// database has no country for (a private one, say), and for this host.
    pub fn country(&self) -> String {
        match self {
            Self::Ip(ip) => crate::ip_db::lookup_country(*ip)
                .map(|code| String::from_utf8_lossy(&code).into_owned())
                .unwrap_or_else(|| "-".to_string()),
            Self::ThisHost => "-".to_string(),
        }
    }
}

impl std::fmt::Display for CallerIp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::ThisHost => f.write_str("this host"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn a_direct_caller_is_its_address_whatever_header_it_sends() {
        assert_eq!(
            CallerIp::of(Some(ip("203.0.113.7")), None),
            CallerIp::Ip(ip("203.0.113.7"))
        );

        // Its own word: not believed.
        assert_eq!(
            CallerIp::of(Some(ip("203.0.113.7")), Some("198.51.100.1")),
            CallerIp::Ip(ip("203.0.113.7"))
        );

        // An IPv4 client of a dual-stack listener is the IPv4 address it is.
        assert_eq!(
            CallerIp::of(Some(ip("::ffff:203.0.113.7")), None),
            CallerIp::Ip(ip("203.0.113.7"))
        );
    }

    #[test]
    fn a_call_the_proxy_relays_comes_from_the_address_it_writes() {
        assert_eq!(
            CallerIp::of(Some(ip("127.0.0.1")), Some("203.0.113.7")),
            CallerIp::Ip(ip("203.0.113.7"))
        );

        // Behind another proxy: the last entry is what the nearest one saw.
        assert_eq!(
            CallerIp::of(Some(ip("127.0.0.1")), Some("198.51.100.1, 203.0.113.7")),
            CallerIp::Ip(ip("203.0.113.7"))
        );
    }

    #[test]
    fn the_unix_socket_and_the_bare_loopback_are_this_host() {
        assert_eq!(CallerIp::of(None, Some("203.0.113.7")), CallerIp::ThisHost);
        assert_eq!(
            CallerIp::of(Some(ip("127.0.0.1")), None),
            CallerIp::ThisHost
        );
        assert_eq!(
            CallerIp::of(Some(ip("::1")), Some("not an address")),
            CallerIp::ThisHost
        );

        assert_eq!(CallerIp::ThisHost.country(), "-");
        assert_eq!(CallerIp::ThisHost.to_string(), "this host");
    }
}

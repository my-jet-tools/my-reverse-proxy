use std::net::IpAddr;

use my_http_server::{HttpRequest, HttpRequestHeaders, SocketAddress};

/// Where a call of the control port comes from: an address, or this host itself - its unix socket,
/// or its loopback, with no client address written in `X-Forwarded-For`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerIp {
    Ip(IpAddr),
    ThisHost,
}

impl CallerIp {
    /// The caller of a request which came from `peer` - `None`: the unix socket - with the
    /// `X-Forwarded-For` it came with.
    ///
    /// - From the network: its peer address. The header is the client's own word, and not
    ///   believed.
    /// - From this host - the loopback or the unix socket, one as the other: the first entry of
    ///   the header when it is an address. The proxy relays a request here after its own rules,
    ///   and writes the header itself - `<client>`, or `<client>, <Cloudflare server>` for one
    ///   which came through Cloudflare (`RequestClient::x_forwarded_for`): the client first. A
    ///   process of this host which writes it is trusted as the loopback is. With no address in
    ///   the header it is this host.
    pub fn of(peer: Option<IpAddr>, x_forwarded_for: Option<&str>) -> Self {
        if let Some(peer) = peer.map(|ip| ip.to_canonical()) {
            if !peer.is_loopback() {
                return Self::Ip(peer);
            }
        }

        match first_address(x_forwarded_for) {
            Some(client) => Self::Ip(client),
            None => Self::ThisHost,
        }
    }

    /// The caller of a request of the encrypted channel - its sender holds a network key, so the
    /// address it gives in `X-Forwarded-For` is taken from any peer: the first entry, the client.
    /// Without an address in the header, as [`Self::of`].
    pub fn of_encrypted(peer: Option<IpAddr>, x_forwarded_for: Option<&str>) -> Self {
        match first_address(x_forwarded_for) {
            Some(client) => Self::Ip(client),
            None => Self::of(peer, x_forwarded_for),
        }
    }

    /// [`Self::of_encrypted`] of `request`.
    pub fn of_encrypted_request(request: &HttpRequest) -> Self {
        let (peer, x_forwarded_for) = peer_and_x_forwarded_for(request);
        Self::of_encrypted(peer, x_forwarded_for)
    }

    pub fn of_request(request: &HttpRequest) -> Self {
        let (peer, x_forwarded_for) = peer_and_x_forwarded_for(request);
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

/// The first entry of `X-Forwarded-For`, when it is an address.
fn first_address(x_forwarded_for: Option<&str>) -> Option<IpAddr> {
    x_forwarded_for?
        .split(',')
        .next()?
        .trim()
        .parse::<IpAddr>()
        .ok()
        .map(|ip| ip.to_canonical())
}

/// The address `request` came from - `None`: the unix socket - and its `X-Forwarded-For`.
fn peer_and_x_forwarded_for(request: &HttpRequest) -> (Option<IpAddr>, Option<&str>) {
    let peer = match &request.addr {
        SocketAddress::Tcp(addr) => Some(addr.ip()),
        SocketAddress::Unix(_) => None,
    };

    let x_forwarded_for = request
        .get_headers()
        .try_get_case_insensitive("x-forwarded-for")
        .and_then(|value| value.as_str().ok());

    (peer, x_forwarded_for)
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

    /// The unix socket and the loopback: this host, one as the other.
    const THIS_HOST: [Option<&str>; 3] = [None, Some("127.0.0.1"), Some("::1")];

    fn peer(text: Option<&str>) -> Option<IpAddr> {
        text.map(ip)
    }

    #[test]
    fn a_caller_from_the_network_is_its_address_whatever_header_it_sends() {
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

    /// The proxy relays to the control port over the loopback or the unix socket alike, and
    /// writes the client first - a Cloudflare server after it for a request which came through
    /// Cloudflare.
    #[test]
    fn a_call_from_this_host_comes_from_the_client_in_the_header() {
        for from in THIS_HOST {
            assert_eq!(
                CallerIp::of(peer(from), Some("203.0.113.7")),
                CallerIp::Ip(ip("203.0.113.7")),
                "{from:?}"
            );
            assert_eq!(
                CallerIp::of(peer(from), Some("203.0.113.7, 172.68.1.1")),
                CallerIp::Ip(ip("203.0.113.7")),
                "{from:?}"
            );
            assert_eq!(
                CallerIp::of(peer(from), Some(" ::ffff:203.0.113.7 ")),
                CallerIp::Ip(ip("203.0.113.7")),
                "{from:?}"
            );
        }
    }

    /// The unix socket and the loopback with no address in the header are this host.
    #[test]
    fn the_unix_socket_and_the_loopback_with_no_address_in_the_header_are_this_host() {
        for from in THIS_HOST {
            for header in [
                None,
                Some(""),
                Some("not an address"),
                Some("unknown, 10.0.0.1"),
            ] {
                assert_eq!(
                    CallerIp::of(peer(from), header),
                    CallerIp::ThisHost,
                    "{from:?} {header:?}"
                );
            }
        }

        assert_eq!(CallerIp::ThisHost.country(), "-");
        assert_eq!(CallerIp::ThisHost.to_string(), "this host");
    }

    /// A client of the public port of the proxy which itself is on this host - an ssh tunnel to it,
    /// say - is the address the proxy writes for it: `127.0.0.1`, not `this host`.
    #[test]
    fn a_loopback_client_the_proxy_relays_is_its_address() {
        assert_eq!(
            CallerIp::of(None, Some("127.0.0.1")),
            CallerIp::Ip(ip("127.0.0.1"))
        );
        assert_eq!(CallerIp::Ip(ip("127.0.0.1")).to_string(), "127.0.0.1");
    }

    /// A call of the encrypted channel: the address its sender gives is taken from any peer.
    #[test]
    fn an_encrypted_call_comes_from_the_address_it_gives() {
        for from in [Some("10.0.0.9"), Some("127.0.0.1"), None] {
            assert_eq!(
                CallerIp::of_encrypted(peer(from), Some("203.0.113.7")),
                CallerIp::Ip(ip("203.0.113.7")),
                "{from:?}"
            );
            assert_eq!(
                CallerIp::of_encrypted(peer(from), Some("203.0.113.7, 10.0.0.1")),
                CallerIp::Ip(ip("203.0.113.7")),
                "{from:?}"
            );
        }

        // No address in the header: as any call.
        assert_eq!(
            CallerIp::of_encrypted(Some(ip("10.0.0.9")), None),
            CallerIp::Ip(ip("10.0.0.9"))
        );
        assert_eq!(CallerIp::of_encrypted(None, None), CallerIp::ThisHost);
        assert_eq!(
            CallerIp::of_encrypted(None, Some("not an address")),
            CallerIp::ThisHost
        );
    }
}

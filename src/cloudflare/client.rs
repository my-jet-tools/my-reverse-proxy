use std::net::{IpAddr, SocketAddr};

use crate::types::ConnectionIp;

use super::CloudflareIpRanges;

/// The header Cloudflare puts the address of its visitor in. Cloudflare always writes it itself,
/// whatever the visitor sent under the name - so it is the client's address exactly when the
/// request came from Cloudflare.
pub const CF_CONNECTING_IP: &str = "cf-connecting-ip";

/// What is wrong with a connection, or with one of its requests, on its way to an endpoint.
///
/// All but [`Deviation::CloudflarePeerWithoutFlag`] are of a `cloudflare: true` endpoint and close
/// the connection without a word: a browser can not end up in any of them, only a request made to
/// get around Cloudflare can - or a zone of Cloudflare told to take the header away.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Deviation {
    /// The networks of Cloudflare are not read yet, so nobody can be told to be Cloudflare.
    RangesNotLoaded,
    /// The connection is not from Cloudflare.
    NotCloudflarePeer,
    /// From Cloudflare, with no `CF-Connecting-IP`: only a rule of a zone takes it away.
    MissingCfConnectingIp,
    /// From Cloudflare, with more than one `CF-Connecting-IP`.
    SeveralCfConnectingIp,
    /// From Cloudflare, with a `CF-Connecting-IP` which is not an address - as it came, made
    /// safe to write down (see [`printable`]).
    InvalidCfConnectingIp(String),
    /// A Cloudflare server reached an endpoint without `cloudflare: true`: the hostname is likely
    /// proxied by Cloudflare while the flag is forgotten. Served - the upstream is told the
    /// address of the Cloudflare server, which nobody can fake - and only noted.
    CloudflarePeerWithoutFlag,
}

impl Deviation {
    /// The reason, as the journal writes it.
    pub fn as_code(&self) -> &'static str {
        match self {
            Self::RangesNotLoaded => "cloudflare_ranges_not_loaded",
            Self::NotCloudflarePeer => "not_cloudflare_peer",
            Self::MissingCfConnectingIp => "no_cf_connecting_ip",
            Self::SeveralCfConnectingIp => "several_cf_connecting_ip",
            Self::InvalidCfConnectingIp(_) => "bad_cf_connecting_ip",
            Self::CloudflarePeerWithoutFlag => "cloudflare_peer_without_flag",
        }
    }

    pub fn closes_connection(&self) -> bool {
        !matches!(self, Self::CloudflarePeerWithoutFlag)
    }
}

/// Who a request is of.
#[derive(Debug, Clone, Copy)]
pub struct RequestClient {
    /// The client: the peer of the connection - or, on a request through Cloudflare to a
    /// `cloudflare: true` endpoint, the address of its `CF-Connecting-IP`. The allow-lists, the
    /// country, the logs and `${ENDPOINT_IP}` are of it.
    pub ip: ConnectionIp,
    /// The Cloudflare server the request came through - the peer of the connection - when `ip`
    /// is of `CF-Connecting-IP`.
    pub cloudflare_edge: Option<IpAddr>,
}

impl RequestClient {
    pub fn direct(peer: ConnectionIp) -> Self {
        Self {
            ip: peer,
            cloudflare_edge: None,
        }
    }

    pub fn is_via_cloudflare(&self) -> bool {
        self.cloudflare_edge.is_some()
    }

    /// The `X-Forwarded-For` the upstream gets - the proxy's own, never what the client sent:
    /// the client first, then the Cloudflare server it came through. So the first address is the
    /// client on every endpoint, and that is the one an upstream takes.
    ///
    /// `None` for a unix socket: there is no address to write, and the header goes on as the
    /// local process which connected wrote it.
    pub fn x_forwarded_for(&self) -> Option<String> {
        let client = self.ip.get_ip_addr()?;

        match self.cloudflare_edge {
            Some(edge) => Some(format!("{client}, {edge}")),
            None => Some(client.to_string()),
        }
    }

    /// Whether a request header named `name`, as the client sent it, is taken away: one which
    /// tells who the client is, and is not the proxy's to pass on.
    ///
    /// - `X-Forwarded-For`, `X-Real-IP` and `True-Client-IP` always: the first is written anew,
    ///   and nobody the proxy trusts writes the other two.
    /// - What Cloudflare writes - `CF-Connecting-IP`, `CF-Connecting-IPv6`, `CF-IPCountry` -
    ///   unless the request came through Cloudflare to a `cloudflare: true` endpoint: on any other
    ///   it is the client's own word.
    ///
    /// Nothing is taken away on a unix socket: a local process is not the internet, and it gets
    /// no address of the proxy's in their place.
    pub fn takes_away_header(&self, name: &[u8]) -> bool {
        if self.ip.get_ip_addr().is_none() {
            return false;
        }

        const ALWAYS: [&str; 3] = ["x-forwarded-for", "x-real-ip", "true-client-ip"];
        const WRITTEN_BY_CLOUDFLARE: [&str; 3] =
            [CF_CONNECTING_IP, "cf-connecting-ipv6", "cf-ipcountry"];

        if ALWAYS.iter().any(|header| header_name_is(name, header)) {
            return true;
        }

        !self.is_via_cloudflare()
            && WRITTEN_BY_CLOUDFLARE
                .iter()
                .any(|header| header_name_is(name, header))
    }
}

/// What a connection from `peer` to an endpoint is up to, as soon as it is known which endpoint:
/// `None` - nothing. See [`Deviation::closes_connection`].
pub fn peer_deviation(
    endpoint_is_cloudflare: bool,
    peer: &ConnectionIp,
    ranges: &CloudflareIpRanges,
) -> Option<Deviation> {
    let peer_is_cloudflare = peer.get_ip_addr().map(|ip| ranges.contains(ip));

    if endpoint_is_cloudflare {
        return match peer_is_cloudflare {
            Some(Some(true)) => None,
            Some(None) => Some(Deviation::RangesNotLoaded),
            // A unix socket is no Cloudflare server either.
            Some(Some(false)) | None => Some(Deviation::NotCloudflarePeer),
        };
    }

    match peer_is_cloudflare {
        Some(Some(true)) => Some(Deviation::CloudflarePeerWithoutFlag),
        _ => None,
    }
}

/// Who a request on a connection from `peer` is of. Of a `cloudflare: true` endpoint: the address
/// of its one `CF-Connecting-IP` (`cf_connecting_ip` - every value it came with), when the
/// connection is from Cloudflare; anything else is a deviation which closes the connection. Of any
/// other endpoint: the peer.
///
/// Asked for every request, not for the connection: Cloudflare sends the requests of all its
/// visitors through the connections it keeps to the origin.
pub fn request_client<'h>(
    endpoint_is_cloudflare: bool,
    peer: ConnectionIp,
    cf_connecting_ip: impl Iterator<Item = &'h [u8]>,
    ranges: &CloudflareIpRanges,
) -> Result<RequestClient, Deviation> {
    if !endpoint_is_cloudflare {
        return Ok(RequestClient::direct(peer));
    }

    if let Some(deviation) = peer_deviation(true, &peer, ranges) {
        return Err(deviation);
    }

    // `peer_deviation` let it through: an address of Cloudflare.
    let Some(edge) = peer.get_ip_addr() else {
        return Err(Deviation::NotCloudflarePeer);
    };

    let mut values = cf_connecting_ip;

    let Some(value) = values.next() else {
        return Err(Deviation::MissingCfConnectingIp);
    };

    if values.next().is_some() {
        return Err(Deviation::SeveralCfConnectingIp);
    }

    let client = std::str::from_utf8(value.trim_ascii())
        .ok()
        .and_then(|value| value.parse::<IpAddr>().ok())
        .ok_or_else(|| Deviation::InvalidCfConnectingIp(printable(value)))?;

    Ok(RequestClient {
        // Nothing reads the port of a client: the address is all there is of it.
        ip: ConnectionIp::Tcp(SocketAddr::new(client.to_canonical(), 0)),
        cloudflare_edge: Some(edge.to_canonical()),
    })
}

/// Whether an upstream could read a header named `name` as `header` (written in lowercase). Not
/// only the name in any case: also with whitespace around it (`X-Forwarded-For :`, which HTTP/1.1
/// forbids and a lenient server trims) and with `_` for `-` (`X_Forwarded_For`, which CGI-style
/// servers - PHP, WSGI, Rack - read as the very same `HTTP_X_FORWARDED_FOR`).
pub fn header_name_is(name: &[u8], header: &str) -> bool {
    let name = name.trim_ascii();

    name.len() == header.len()
        && name
            .iter()
            .zip(header.as_bytes())
            .all(|(&byte, &expected)| {
                let byte = match byte {
                    b'_' => b'-',
                    byte => byte.to_ascii_lowercase(),
                };
                byte == expected
            })
}

/// The most of a value from a client a line of the journal takes.
const MAX_PRINTABLE_LEN: usize = 64;

/// `value`, which came from a client, the way it can be written in a line of text: at most
/// [`MAX_PRINTABLE_LEN`] bytes of it, and every byte which is not printable ASCII - a line feed
/// would start a line of its own -, a `"` and a `\` written as `\xNN`.
pub fn printable(value: &[u8]) -> String {
    let mut result = String::with_capacity(value.len().min(MAX_PRINTABLE_LEN) + 3);

    for &byte in value.iter().take(MAX_PRINTABLE_LEN) {
        if (0x20..0x7f).contains(&byte) && byte != b'"' && byte != b'\\' {
            result.push(byte as char);
        } else {
            result.push_str(&format!("\\x{byte:02x}"));
        }
    }

    if value.len() > MAX_PRINTABLE_LEN {
        result.push_str("...");
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloudflare::IpCidr;

    fn ranges() -> CloudflareIpRanges {
        let ranges = CloudflareIpRanges::new();
        ranges.replace(vec![
            IpCidr::parse("172.64.0.0/13").unwrap(),
            IpCidr::parse("2400:cb00::/32").unwrap(),
        ]);
        ranges
    }

    fn peer(src: &str) -> ConnectionIp {
        ConnectionIp::Tcp(src.parse().unwrap())
    }

    const CLOUDFLARE: &str = "172.68.1.2:443";
    const STRANGER: &str = "203.0.113.7:5000";

    fn client_of(
        endpoint_is_cloudflare: bool,
        from: &str,
        values: &[&[u8]],
    ) -> Result<RequestClient, Deviation> {
        request_client(
            endpoint_is_cloudflare,
            peer(from),
            values.iter().copied(),
            &ranges(),
        )
    }

    #[test]
    fn through_cloudflare_the_client_is_of_cf_connecting_ip() {
        let client = client_of(true, CLOUDFLARE, &[b" 198.51.100.4 "]).unwrap();

        assert_eq!(
            client.ip.get_ip_addr(),
            Some("198.51.100.4".parse().unwrap())
        );
        assert_eq!(client.cloudflare_edge, Some("172.68.1.2".parse().unwrap()));
        assert_eq!(
            client.x_forwarded_for().as_deref(),
            Some("198.51.100.4, 172.68.1.2")
        );
    }

    #[test]
    fn an_ipv6_client_and_an_ipv6_edge_are_read_as_well() {
        let client = client_of(true, "[2400:cb00::7]:443", &[b"2001:db8::1"]).unwrap();

        assert_eq!(
            client.x_forwarded_for().as_deref(),
            Some("2001:db8::1, 2400:cb00::7")
        );
    }

    #[test]
    fn an_edge_on_a_dual_stack_socket_is_its_ipv4_address() {
        let client = client_of(true, "[::ffff:172.68.1.2]:443", &[b"198.51.100.4"]).unwrap();

        assert_eq!(
            client.x_forwarded_for().as_deref(),
            Some("198.51.100.4, 172.68.1.2")
        );
    }

    #[test]
    fn a_stranger_on_a_cloudflare_endpoint_is_refused_whatever_it_sends() {
        assert_eq!(
            client_of(true, STRANGER, &[b"198.51.100.4"]).unwrap_err(),
            Deviation::NotCloudflarePeer
        );

        #[cfg(unix)]
        assert_eq!(
            request_client(
                true,
                ConnectionIp::UnixSocket,
                [b"198.51.100.4".as_slice()].into_iter(),
                &ranges()
            )
            .unwrap_err(),
            Deviation::NotCloudflarePeer
        );
    }

    #[test]
    fn before_the_networks_are_read_nobody_passes_for_cloudflare() {
        let err = request_client(
            true,
            peer(CLOUDFLARE),
            [b"198.51.100.4".as_slice()].into_iter(),
            &CloudflareIpRanges::new(),
        )
        .unwrap_err();

        assert_eq!(err, Deviation::RangesNotLoaded);
        assert!(err.closes_connection());
    }

    #[test]
    fn cloudflare_without_a_single_valid_cf_connecting_ip_is_refused() {
        assert_eq!(
            client_of(true, CLOUDFLARE, &[]).unwrap_err(),
            Deviation::MissingCfConnectingIp
        );
        assert_eq!(
            client_of(true, CLOUDFLARE, &[b"198.51.100.4", b"198.51.100.5"]).unwrap_err(),
            Deviation::SeveralCfConnectingIp
        );
        assert_eq!(
            client_of(true, CLOUDFLARE, &[b"198.51.100.4, 8.8.8.8"]).unwrap_err(),
            Deviation::InvalidCfConnectingIp("198.51.100.4, 8.8.8.8".to_string())
        );
        assert_eq!(
            client_of(true, CLOUDFLARE, &[b"evil\r\nX: 1"]).unwrap_err(),
            Deviation::InvalidCfConnectingIp("evil\\x0d\\x0aX: 1".to_string())
        );
    }

    #[test]
    fn every_deviation_of_a_cloudflare_endpoint_closes_the_connection() {
        for deviation in [
            Deviation::RangesNotLoaded,
            Deviation::NotCloudflarePeer,
            Deviation::MissingCfConnectingIp,
            Deviation::SeveralCfConnectingIp,
            Deviation::InvalidCfConnectingIp(String::new()),
        ] {
            assert!(deviation.closes_connection(), "{deviation:?}");
        }

        assert!(!Deviation::CloudflarePeerWithoutFlag.closes_connection());
    }

    #[test]
    fn without_the_flag_the_client_is_the_peer_whatever_it_sends() {
        for from in [CLOUDFLARE, STRANGER] {
            let client = client_of(false, from, &[b"198.51.100.4"]).unwrap();

            assert_eq!(client.ip.get_ip_addr(), peer(from).get_ip_addr());
            assert!(!client.is_via_cloudflare());
            assert_eq!(
                client.x_forwarded_for(),
                peer(from).get_ip_addr().map(|ip| ip.to_string())
            );
        }
    }

    #[test]
    fn cloudflare_reaching_an_endpoint_without_the_flag_is_noted_not_refused() {
        let ranges = ranges();

        let deviation = peer_deviation(false, &peer(CLOUDFLARE), &ranges).unwrap();
        assert_eq!(deviation, Deviation::CloudflarePeerWithoutFlag);
        assert!(!deviation.closes_connection());

        assert_eq!(peer_deviation(false, &peer(STRANGER), &ranges), None);
        assert_eq!(
            peer_deviation(false, &peer(CLOUDFLARE), &CloudflareIpRanges::new()),
            None
        );
    }

    #[test]
    fn the_peer_check_of_a_cloudflare_endpoint() {
        let ranges = ranges();

        assert_eq!(peer_deviation(true, &peer(CLOUDFLARE), &ranges), None);
        assert_eq!(
            peer_deviation(true, &peer(STRANGER), &ranges),
            Some(Deviation::NotCloudflarePeer)
        );
        assert_eq!(
            peer_deviation(true, &peer(CLOUDFLARE), &CloudflareIpRanges::new()),
            Some(Deviation::RangesNotLoaded)
        );
    }

    #[test]
    fn what_tells_who_the_client_is_is_taken_away_unless_cloudflare_wrote_it() {
        let direct = RequestClient::direct(peer(STRANGER));
        let via_cloudflare = client_of(true, CLOUDFLARE, &[b"198.51.100.4"]).unwrap();

        for name in [
            "X-Forwarded-For",
            "x_forwarded_for",
            " X-Real-IP ",
            "True-Client-IP",
        ] {
            assert!(direct.takes_away_header(name.as_bytes()), "{name}");
            assert!(via_cloudflare.takes_away_header(name.as_bytes()), "{name}");
        }

        for name in [
            "CF-Connecting-IP",
            "cf_connecting_ip",
            "CF-Connecting-IPv6",
            "CF-IPCountry",
        ] {
            assert!(direct.takes_away_header(name.as_bytes()), "{name}");
            assert!(!via_cloudflare.takes_away_header(name.as_bytes()), "{name}");
        }

        for name in ["Host", "X-Forwarded-Proto", "X-Forwarded-Host", "CF-Ray"] {
            assert!(!direct.takes_away_header(name.as_bytes()), "{name}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn nothing_is_taken_away_on_a_unix_socket() {
        let local = RequestClient::direct(ConnectionIp::UnixSocket);

        assert!(!local.takes_away_header(b"X-Forwarded-For"));
        assert!(!local.takes_away_header(b"CF-Connecting-IP"));
        assert_eq!(local.x_forwarded_for(), None);
    }

    #[test]
    fn a_value_from_a_client_is_written_as_printable_text() {
        assert_eq!(printable(b"1.2.3.4"), "1.2.3.4");
        assert_eq!(printable(b"a\"b\\c\x00\xff"), "a\\x22b\\x5cc\\x00\\xff");
        assert_eq!(printable(&[b'a'; 100]), format!("{}...", "a".repeat(64)));
    }
}

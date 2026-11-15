use std::{net::IpAddr, sync::Arc};

use arc_swap::ArcSwapOption;
use serde::Deserialize;

use super::IpCidr;

/// Where Cloudflare publishes the networks its servers connect to origins from. Read over https
/// with the certificate checked: whoever could hand the proxy a list of their own would be taken
/// for Cloudflare on every `cloudflare: true` endpoint.
pub const CLOUDFLARE_IPS_URL: &str = "https://api.cloudflare.com/client/v4/ips";

/// The most the answer is read of. The real one is about a kilobyte.
pub const MAX_CLOUDFLARE_IPS_RESPONSE_SIZE: usize = 64 * 1024;

/// More networks than this is not the list Cloudflare publishes (it has a couple of dozen).
const MAX_NETWORKS: usize = 1000;

/// A network wider than this is not one of Cloudflare's: a list with `0.0.0.0/0` in it would
/// let everybody pass for Cloudflare. Its widest networks are an IPv4 `/13` and an IPv6 `/29`.
const MIN_IPV4_PREFIX: u8 = 8;
const MIN_IPV6_PREFIX: u8 = 16;

/// The networks of Cloudflare, as last read from [`CLOUDFLARE_IPS_URL`]. Empty until the first
/// read succeeds - and then no address is taken for Cloudflare: a `cloudflare: true` endpoint
/// serves nobody until it is known who Cloudflare is. A failed read never takes away a list
/// which was read before.
pub struct CloudflareIpRanges {
    networks: ArcSwapOption<Vec<IpCidr>>,
}

impl CloudflareIpRanges {
    pub fn new() -> Self {
        Self {
            networks: ArcSwapOption::empty(),
        }
    }

    pub fn replace(&self, networks: Vec<IpCidr>) {
        self.networks.store(Some(Arc::new(networks)));
    }

    pub fn is_loaded(&self) -> bool {
        self.networks.load().is_some()
    }

    /// `None`: the list is not read yet, so nobody can be told to be Cloudflare.
    pub fn contains(&self, ip: IpAddr) -> Option<bool> {
        let networks = self.networks.load();
        let networks = networks.as_ref()?;
        Some(networks.iter().any(|network| network.contains(ip)))
    }
}

#[derive(Deserialize)]
struct ApiResponse {
    success: bool,
    result: Option<ApiResult>,
}

#[derive(Deserialize)]
struct ApiResult {
    ipv4_cidrs: Vec<String>,
    ipv6_cidrs: Vec<String>,
}

/// The networks in an answer of [`CLOUDFLARE_IPS_URL`]. Anything which does not look like the
/// list Cloudflare publishes is an error, and the list read before stays: an answer which says
/// it failed, one with no IPv4 or no IPv6 network, a network which is not one, or one too wide.
pub fn parse_cloudflare_ips_response(body: &[u8]) -> Result<Vec<IpCidr>, String> {
    let response: ApiResponse = serde_json::from_slice(body)
        .map_err(|err| format!("the answer is not the json of the list: {err}"))?;

    if !response.success {
        return Err("the answer says it failed (\"success\": false)".to_string());
    }

    let Some(result) = response.result else {
        return Err("the answer has no \"result\"".to_string());
    };

    if result.ipv4_cidrs.is_empty() || result.ipv6_cidrs.is_empty() {
        return Err(format!(
            "the answer lists {} IPv4 and {} IPv6 networks - Cloudflare has both",
            result.ipv4_cidrs.len(),
            result.ipv6_cidrs.len()
        ));
    }

    let count = result.ipv4_cidrs.len() + result.ipv6_cidrs.len();
    if count > MAX_NETWORKS {
        return Err(format!(
            "the answer lists {count} networks, more than {MAX_NETWORKS}"
        ));
    }

    let mut networks = Vec::with_capacity(count);

    for (src, must_be_v4) in result
        .ipv4_cidrs
        .iter()
        .map(|src| (src, true))
        .chain(result.ipv6_cidrs.iter().map(|src| (src, false)))
    {
        let network = IpCidr::parse(src)?;

        if network.is_v4() != must_be_v4 {
            return Err(format!(
                "'{src}' is listed among the {} networks",
                if must_be_v4 { "IPv4" } else { "IPv6" }
            ));
        }

        let min_prefix = if network.is_v4() {
            MIN_IPV4_PREFIX
        } else {
            MIN_IPV6_PREFIX
        };

        if network.prefix() < min_prefix {
            return Err(format!(
                "'{src}' is too wide a network to be Cloudflare's (the prefix is at least \
                 {min_prefix})"
            ));
        }

        networks.push(network);
    }

    Ok(networks)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_ANSWER: &str = r#"{"result":{"ipv4_cidrs":["173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20","197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13","104.24.0.0/14","172.64.0.0/13","131.0.72.0/22"],"ipv6_cidrs":["2400:cb00::/32","2606:4700::/32","2803:f800::/32","2405:b500::/32","2405:8100::/32","2a06:98c0::/29","2c0f:f248::/32"],"etag":"38f79d050aa027e3be3865e495dcc9bc"},"success":true,"errors":[],"messages":[]}"#;

    fn ip(src: &str) -> IpAddr {
        src.parse().unwrap()
    }

    #[test]
    fn the_list_cloudflare_publishes_is_read() {
        let networks = parse_cloudflare_ips_response(REAL_ANSWER.as_bytes()).unwrap();

        assert_eq!(networks.len(), 22);

        let ranges = CloudflareIpRanges::new();
        ranges.replace(networks);

        assert_eq!(ranges.contains(ip("172.68.1.2")), Some(true));
        assert_eq!(ranges.contains(ip("2a06:98c0::1")), Some(true));
        assert_eq!(ranges.contains(ip("203.0.113.7")), Some(false));
    }

    #[test]
    fn nobody_is_cloudflare_until_the_list_is_read() {
        let ranges = CloudflareIpRanges::new();

        assert!(!ranges.is_loaded());
        assert_eq!(ranges.contains(ip("172.68.1.2")), None);
    }

    #[test]
    fn an_answer_unlike_the_list_is_refused() {
        let refused = [
            ("not json", "not json".to_string()),
            (
                "failed",
                REAL_ANSWER.replace("\"success\":true", "\"success\":false"),
            ),
            (
                "no ipv6",
                r#"{"result":{"ipv4_cidrs":["173.245.48.0/20"],"ipv6_cidrs":[]},"success":true}"#
                    .to_string(),
            ),
            (
                "no ipv4",
                r#"{"result":{"ipv4_cidrs":[],"ipv6_cidrs":["2400:cb00::/32"]},"success":true}"#
                    .to_string(),
            ),
            ("no result", r#"{"success":true}"#.to_string()),
            (
                "everybody",
                REAL_ANSWER.replace("\"173.245.48.0/20\"", "\"0.0.0.0/0\""),
            ),
            (
                "too wide v6",
                REAL_ANSWER.replace("\"2400:cb00::/32\"", "\"2400::/8\""),
            ),
            (
                "not a network",
                REAL_ANSWER.replace("\"173.245.48.0/20\"", "\"173.245.48.0\""),
            ),
            (
                "v6 among v4",
                REAL_ANSWER.replace("\"173.245.48.0/20\"", "\"2400:cb00::/32\""),
            ),
        ];

        for (case, body) in refused {
            assert!(
                parse_cloudflare_ips_response(body.as_bytes()).is_err(),
                "{case}: the answer is taken for the list"
            );
        }
    }
}

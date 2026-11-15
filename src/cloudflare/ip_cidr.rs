use std::net::IpAddr;

/// One network of addresses - `173.245.48.0/20`, `2400:cb00::/32` - as Cloudflare lists its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpCidr {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl IpCidr {
    /// `address/prefix`. The bits of the address past the prefix must be zero: a network written
    /// with them is not what Cloudflare publishes, and taking it as its network would be a guess.
    pub fn parse(src: &str) -> Result<Self, String> {
        let src = src.trim();

        let Some((address, prefix)) = src.split_once('/') else {
            return Err(format!("'{src}' is not a network: no '/prefix'"));
        };

        let address: IpAddr = address
            .parse()
            .map_err(|_| format!("'{src}' is not a network: '{address}' is not an address"))?;

        let prefix: u8 = prefix
            .parse()
            .map_err(|_| format!("'{src}' is not a network: '{prefix}' is not a prefix"))?;

        let result = match address {
            IpAddr::V4(address) => {
                if prefix > 32 {
                    return Err(format!("'{src}': an IPv4 prefix is at most 32"));
                }
                Self::V4 {
                    network: u32::from(address),
                    prefix,
                }
            }
            IpAddr::V6(address) => {
                if prefix > 128 {
                    return Err(format!("'{src}': an IPv6 prefix is at most 128"));
                }
                Self::V6 {
                    network: u128::from(address),
                    prefix,
                }
            }
        };

        if !result.host_bits_are_zero() {
            return Err(format!("'{src}': the address has bits set past the prefix"));
        }

        Ok(result)
    }

    pub fn prefix(&self) -> u8 {
        match self {
            Self::V4 { prefix, .. } | Self::V6 { prefix, .. } => *prefix,
        }
    }

    pub fn is_v4(&self) -> bool {
        matches!(self, Self::V4 { .. })
    }

    /// An IPv4 address which came as IPv6 (`::ffff:1.2.3.4`, as a dual-stack socket reports it)
    /// is the IPv4 address it carries.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip.to_canonical()) {
            (Self::V4 { network, prefix }, IpAddr::V4(ip)) => {
                (u32::from(ip) & mask_v4(*prefix)) == *network
            }
            (Self::V6 { network, prefix }, IpAddr::V6(ip)) => {
                (u128::from(ip) & mask_v6(*prefix)) == *network
            }
            _ => false,
        }
    }

    fn host_bits_are_zero(&self) -> bool {
        match self {
            Self::V4 { network, prefix } => network & !mask_v4(*prefix) == 0,
            Self::V6 { network, prefix } => network & !mask_v6(*prefix) == 0,
        }
    }
}

impl std::fmt::Display for IpCidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V4 { network, prefix } => {
                write!(f, "{}/{}", std::net::Ipv4Addr::from(*network), prefix)
            }
            Self::V6 { network, prefix } => {
                write!(f, "{}/{}", std::net::Ipv6Addr::from(*network), prefix)
            }
        }
    }
}

fn mask_v4(prefix: u8) -> u32 {
    match prefix {
        0 => 0,
        prefix => u32::MAX << (32 - prefix),
    }
}

fn mask_v6(prefix: u8) -> u128 {
    match prefix {
        0 => 0,
        prefix => u128::MAX << (128 - prefix),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(src: &str) -> IpAddr {
        src.parse().unwrap()
    }

    #[test]
    fn an_ipv4_network_holds_its_addresses_and_no_others() {
        let cidr = IpCidr::parse("173.245.48.0/20").unwrap();

        assert!(cidr.contains(ip("173.245.48.0")));
        assert!(cidr.contains(ip("173.245.63.255")));
        assert!(!cidr.contains(ip("173.245.64.0")));
        assert!(!cidr.contains(ip("173.245.47.255")));
    }

    #[test]
    fn an_ipv6_network_holds_its_addresses_and_no_others() {
        let cidr = IpCidr::parse("2400:cb00::/32").unwrap();

        assert!(cidr.contains(ip("2400:cb00::1")));
        assert!(cidr.contains(ip("2400:cb00:ffff:ffff:ffff:ffff:ffff:ffff")));
        assert!(!cidr.contains(ip("2400:cb01::")));
    }

    #[test]
    fn an_ipv4_address_carried_in_ipv6_is_the_ipv4_address() {
        let cidr = IpCidr::parse("104.16.0.0/13").unwrap();

        assert!(cidr.contains(ip("::ffff:104.16.1.1")));
        assert!(!cidr.contains(ip("::ffff:10.0.0.1")));
    }

    #[test]
    fn a_family_never_matches_the_other_one() {
        assert!(!IpCidr::parse("0.0.0.0/0")
            .unwrap()
            .contains(ip("2400:cb00::1")));
        assert!(!IpCidr::parse("::/0").unwrap().contains(ip("1.1.1.1")));
    }

    #[test]
    fn a_host_and_the_whole_space_are_networks_too() {
        let host = IpCidr::parse("10.0.0.1/32").unwrap();
        assert!(host.contains(ip("10.0.0.1")));
        assert!(!host.contains(ip("10.0.0.2")));

        assert!(IpCidr::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
    }

    #[test]
    fn what_is_not_a_network_is_refused() {
        for src in [
            "173.245.48.0",
            "173.245.48.0/33",
            "2400:cb00::/129",
            "173.245.48.1/20",
            "abc/20",
            "173.245.48.0/x",
            "",
        ] {
            assert!(
                IpCidr::parse(src).is_err(),
                "'{src}' is taken for a network"
            );
        }
    }

    #[test]
    fn a_network_is_written_back_as_it_was_read() {
        for src in ["173.245.48.0/20", "2400:cb00::/32"] {
            assert_eq!(IpCidr::parse(src).unwrap().to_string(), src);
        }
    }
}

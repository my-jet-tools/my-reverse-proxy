use std::net::{IpAddr, Ipv4Addr};

/// An address as the number the entries of an ip list are compared with - `None` for one which is
/// not IPv4: the lists hold IPv4 addresses only, and an IPv6 client is in none of them. An IPv4
/// address behind a dual-stack socket (`::ffff:10.0.0.5`) is the IPv4 address it carries.
pub trait IntoIp {
    fn get_ip_value(&self) -> Option<u32>;
}

impl IntoIp for &'_ str {
    fn get_ip_value(&self) -> Option<u32> {
        self.trim().parse::<IpAddr>().ok()?.get_ip_value()
    }
}

impl IntoIp for &[u8; 4] {
    fn get_ip_value(&self) -> Option<u32> {
        Some(u32::from_be_bytes(**self))
    }
}

impl IntoIp for IpAddr {
    fn get_ip_value(&self) -> Option<u32> {
        match self {
            IpAddr::V4(ip) => ip.get_ip_value(),
            IpAddr::V6(ip) => ip.to_ipv4_mapped()?.get_ip_value(),
        }
    }
}

impl IntoIp for Ipv4Addr {
    fn get_ip_value(&self) -> Option<u32> {
        Some(u32::from(*self))
    }
}

pub enum WhitelistedIp {
    SingleIp(u32),
    Range { ip_from: u32, ip_to: u32 },
}

impl WhitelistedIp {
    /// Whether `other_ip` is this entry, or in it. An address which is not IPv4 is in no entry.
    pub fn is_my_ip(&self, other_ip: &impl IntoIp) -> bool {
        let Some(value) = other_ip.get_ip_value() else {
            return false;
        };

        match self {
            WhitelistedIp::SingleIp(ip) => *ip == value,
            WhitelistedIp::Range { ip_from, ip_to } => *ip_from <= value && value <= *ip_to,
        }
    }

    /// An entry of an ip list - `None` for `*`, which lets every address in:
    ///
    /// - an IPv4 address: `10.0.0.5`;
    /// - a range of them, both ends in it: `10.0.0.5-10.0.0.9`;
    /// - a subnet: `10.0.0.0/24`, a prefix of 0 to 32 bits. The address is put to the start of
    ///   its subnet, so `10.0.0.5/24` is `10.0.0.0/24`.
    pub fn parse(entry: &str) -> Result<Option<Self>, String> {
        let entry = entry.trim();

        if entry == super::WHITE_LIST_EVERYBODY {
            return Ok(None);
        }

        let not_an_entry = || {
            format!(
                "'{entry}' is neither an IPv4 address, nor a from-to range of them, nor a subnet (10.0.0.0/24), nor *"
            )
        };

        let address = |text: &str| text.trim().parse::<Ipv4Addr>().map(u32::from).ok();

        if let Some((address_text, prefix)) = entry.split_once('/') {
            let network = address(address_text).ok_or_else(not_an_entry)?;

            let prefix: u32 = prefix
                .trim()
                .parse()
                .ok()
                .filter(|prefix| *prefix <= 32)
                .ok_or_else(not_an_entry)?;

            let mask = match prefix {
                0 => 0,
                prefix => u32::MAX << (32 - prefix),
            };

            let ip_from = network & mask;
            let ip_to = ip_from | !mask;

            return Ok(Some(Self::Range { ip_from, ip_to }));
        }

        if let Some((from, to)) = entry.split_once('-') {
            let ip_from = address(from).ok_or_else(not_an_entry)?;
            let ip_to = address(to).ok_or_else(not_an_entry)?;

            return Ok(Some(Self::Range { ip_from, ip_to }));
        }

        let ip = address(entry).ok_or_else(not_an_entry)?;

        Ok(Some(Self::SingleIp(ip)))
    }
}

impl std::fmt::Display for WhitelistedIp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WhitelistedIp::SingleIp(ip) => write!(f, "{}", to_ip(*ip)),
            WhitelistedIp::Range { ip_from, ip_to } => {
                write!(f, "{}-{}", to_ip(*ip_from), to_ip(*ip_to))
            }
        }
    }
}

fn to_ip(ip: u32) -> Ipv4Addr {
    let v = ip.to_be_bytes();
    Ipv4Addr::new(v[0], v[1], v[2], v[3])
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_parse_ip() {
        let ip1: [u8; 4] = [192, 168, 1, 1];

        let left = (&ip1).get_ip_value();

        let right = "192.168.1.1".get_ip_value();

        assert_eq!(left, right);
        assert!(left.is_some());
    }

    #[test]
    fn test_convert_both_sides() {
        let ip = Ipv4Addr::new(192, 168, 1, 5);

        let as_u32 = ip.get_ip_value().unwrap();

        let back_to_ip = to_ip(as_u32);

        assert_eq!(ip, back_to_ip);
    }

    /// An IPv6 client is in no list - and does not panic the connection it came on. One behind a
    /// dual-stack socket is the IPv4 address it carries.
    #[test]
    fn an_ipv6_address_is_no_number_and_a_mapped_one_is_its_ipv4() {
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(v6.get_ip_value(), None);

        let mapped: IpAddr = "::ffff:10.0.0.5".parse().unwrap();
        assert_eq!(
            mapped.get_ip_value(),
            Ipv4Addr::new(10, 0, 0, 5).get_ip_value()
        );

        assert_eq!("not an address".get_ip_value(), None);
        assert_eq!("10.0.0.0/24".get_ip_value(), None);
    }

    #[test]
    fn a_subnet_is_the_range_of_its_addresses() {
        let range = |entry: &str| match WhitelistedIp::parse(entry).unwrap().unwrap() {
            WhitelistedIp::Range { ip_from, ip_to } => (to_ip(ip_from), to_ip(ip_to)),
            WhitelistedIp::SingleIp(_) => panic!("{entry} is not a range"),
        };

        assert_eq!(
            range("10.0.0.0/24"),
            (Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255))
        );
        assert_eq!(
            range(" 10.0.0.5/24 "),
            (Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255))
        );
        assert_eq!(
            range("10.1.0.0/16"),
            (Ipv4Addr::new(10, 1, 0, 0), Ipv4Addr::new(10, 1, 255, 255))
        );
        assert_eq!(
            range("192.168.1.7/32"),
            (Ipv4Addr::new(192, 168, 1, 7), Ipv4Addr::new(192, 168, 1, 7))
        );
        assert_eq!(
            range("0.0.0.0/0"),
            (Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(255, 255, 255, 255))
        );
        assert_eq!(
            range("10.0.0.1-10.0.0.9"),
            (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 9))
        );

        assert!(matches!(
            WhitelistedIp::parse("10.0.0.5"),
            Ok(Some(WhitelistedIp::SingleIp(_)))
        ));
        assert!(matches!(WhitelistedIp::parse(" * "), Ok(None)));
    }

    #[test]
    fn what_is_not_an_entry_is_an_error_not_a_panic() {
        for entry in [
            "",
            "10.0.0.0/33",
            "10.0.0.0/",
            "/24",
            "10.0.0.0/a",
            "10.0.0.0/24/1",
            "10.0.0.300",
            "10.0.0.1-",
            "-10.0.0.1",
            "2001:db8::/32",
            "::1",
            "office.example.com",
        ] {
            let err = WhitelistedIp::parse(entry)
                .err()
                .unwrap_or_else(|| panic!("{entry:?}"));
            assert!(err.contains("subnet (10.0.0.0/24)"), "{err}");
        }
    }
}

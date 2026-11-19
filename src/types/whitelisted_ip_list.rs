use super::{IntoIp, WhitelistedIp};

#[cfg(test)]
use std::net::IpAddr;

/// A list of `ip_white_lists`. `*` among the entries lets every address in; a list with no entry
/// lets nobody in - as does a list an endpoint names and the settings do not declare (it is not
/// in the live configuration: [`crate::configurations::WhiteListedIpListConfigurations`]).
pub struct WhiteListedIpList {
    /// `*` is one of the entries.
    everybody: bool,
    items: Vec<WhitelistedIp>,
}

/// The entry which lets every address in.
pub const WHITE_LIST_EVERYBODY: &str = "*";

/// Whether `entry` can be an entry of an ip list: an IPv4 address, a `from-to` range of them, a
/// subnet (`10.0.0.0/24`), or `*` - see [`WhitelistedIp::parse`]. Every list is checked with this
/// when it comes - from the settings files, from a url - so a wrong entry is an error with a word
/// on it, not an address left out without one.
pub fn check_ip_white_list_entry(entry: &str) -> Result<(), String> {
    WhitelistedIp::parse(entry).map(|_| ())
}

impl WhiteListedIpList {
    /// The list of `src`. An entry which is not one - every list is checked with
    /// [`check_ip_white_list_entry`] when it comes, so it is never met here - is left out: it lets
    /// nobody in, rather than taking the proxy down.
    pub fn new(src: &[String]) -> Self {
        let mut everybody = false;
        let mut items = Vec::new();

        for itm in src {
            match WhitelistedIp::parse(itm) {
                Ok(Some(item)) => items.push(item),
                Ok(None) => everybody = true,
                Err(err) => println!("An ip list entry is left out: {err}"),
            }
        }

        Self { everybody, items }
    }

    pub fn is_whitelisted(&self, ip: &impl IntoIp) -> bool {
        // Before the address is read: `*` lets an IPv6 address in too, which no entry can.
        if self.everybody {
            return true;
        }

        for itm in &self.items {
            if itm.is_my_ip(ip) {
                return true;
            }
        }

        false
    }

    pub fn to_list_of_string(&self) -> Vec<String> {
        let mut result = Vec::with_capacity(self.items.len() + 1);
        if self.everybody {
            result.push(WHITE_LIST_EVERYBODY.to_string());
        }
        for itm in &self.items {
            result.push(itm.to_string());
        }
        result
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_range() {
        let list = vec!["127.0.0.5-127.0.0.10".to_string()];

        let list = super::WhiteListedIpList::new(list.as_slice());

        assert!(list.is_whitelisted(&"127.0.0.5"));

        assert!(list.is_whitelisted(&"127.0.0.10"));

        assert!(!list.is_whitelisted(&"127.0.0.4"));
    }

    #[test]
    fn a_subnet_lets_its_addresses_in() {
        let list = super::WhiteListedIpList::new(&[
            "10.0.0.0/24".to_string(),
            "192.168.1.7/32".to_string(),
        ]);

        assert!(list.is_whitelisted(&"10.0.0.0"));
        assert!(list.is_whitelisted(&"10.0.0.255"));
        assert!(!list.is_whitelisted(&"10.0.1.0"));
        assert!(list.is_whitelisted(&"192.168.1.7"));
        assert!(!list.is_whitelisted(&"192.168.1.8"));

        // A client behind a dual-stack socket, and an IPv6 one: no panic.
        assert!(list.is_whitelisted(&"::ffff:10.0.0.9".parse::<super::IpAddr>().unwrap()));
        assert!(!list.is_whitelisted(&"2001:db8::1".parse::<super::IpAddr>().unwrap()));
    }

    /// A wrong entry never takes the proxy down: it is left out.
    #[test]
    fn a_wrong_entry_is_left_out_not_a_panic() {
        let list = super::WhiteListedIpList::new(&[
            "10.0.0.0/33".to_string(),
            "garbage".to_string(),
            "10.0.0.5".to_string(),
        ]);

        assert!(list.is_whitelisted(&"10.0.0.5"));
        assert!(!list.is_whitelisted(&"10.0.0.6"));

        assert!(super::check_ip_white_list_entry("10.0.0.0/24").is_ok());
        assert!(super::check_ip_white_list_entry("10.0.0.0/33").is_err());
    }

    #[test]
    fn an_empty_list_lets_nobody_in() {
        let list = super::WhiteListedIpList::new(&[]);

        assert!(!list.is_whitelisted(&"127.0.0.1"));
        assert!(!list.is_whitelisted(&"10.0.0.5"));
    }

    #[test]
    fn a_star_among_the_entries_lets_everybody_in() {
        let list = super::WhiteListedIpList::new(&["10.0.0.5".to_string(), " * ".to_string()]);

        assert!(list.is_whitelisted(&"10.0.0.5"));
        assert!(list.is_whitelisted(&"8.8.8.8"));
        // An IPv6 address is not compared with the entries at all.
        assert!(list.is_whitelisted(&"2001:4860:4860::8888".parse::<std::net::IpAddr>().unwrap()));

        assert_eq!(list.to_list_of_string(), ["*", "10.0.0.5"]);
    }
}

use super::{IntoIp, WhitelistedIp};

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

/// Whether `entry` can be an entry of an ip list: an IPv4 address, a `from-to` range of them, or
/// `*`. [`WhiteListedIpList::new`] panics on anything else, so a list from outside the settings
/// files is checked with this first.
pub fn check_ip_white_list_entry(entry: &str) -> Result<(), String> {
    let entry = entry.trim();

    if entry == WHITE_LIST_EVERYBODY {
        return Ok(());
    }

    let is_valid = match entry.split_once('-') {
        Some((from, to)) => {
            from.trim().parse::<std::net::Ipv4Addr>().is_ok()
                && to.trim().parse::<std::net::Ipv4Addr>().is_ok()
                && from.trim() == from
                && to.trim() == to
        }
        None => entry.parse::<std::net::Ipv4Addr>().is_ok(),
    };

    if is_valid {
        Ok(())
    } else {
        Err(format!(
            "'{entry}' is neither an IPv4 address, nor a from-to range of them, nor *"
        ))
    }
}

impl WhiteListedIpList {
    pub fn new(src: &[String]) -> Self {
        let mut everybody = false;
        let mut items = Vec::new();
        for itm in src {
            let itm = itm.trim();

            if itm == WHITE_LIST_EVERYBODY {
                everybody = true;
                continue;
            }

            let mut parts = itm.split("-");

            let left = parts.next().unwrap();

            if let Some(right) = parts.next() {
                let ip_from = left.get_ip_value();
                let ip_to = right.get_ip_value();

                items.push(WhitelistedIp::Range { ip_from, ip_to });
            } else {
                items.push(WhitelistedIp::SingleIp(left.get_ip_value()));
            }
        }

        Self { everybody, items }
    }

    pub fn is_whitelisted(&self, ip: &impl IntoIp) -> bool {
        // Before the address is read: an IPv6 one can not be compared with the entries.
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

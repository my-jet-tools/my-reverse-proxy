use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::types::ConnectionIp;

/// Source IPs from `global_settings.debug_ip`: a request from one of them that
/// is refused before an endpoint is resolved gets a detailed diagnostic page
/// instead of a bare `400 Bad Request`.
///
/// Replaced on every settings (re)load and read only on the rejection path, so
/// an `ArcSwap` over a short list is enough.
pub struct DebugIpList {
    items: ArcSwap<Vec<IpAddr>>,
}

impl DebugIpList {
    pub fn new() -> Self {
        Self {
            items: ArcSwap::from_pointee(Vec::new()),
        }
    }

    pub fn set(&self, items: Vec<IpAddr>) {
        // Canonical form on both sides, so `1.2.3.4` in the settings matches a
        // client that arrives as the IPv4-mapped `::ffff:1.2.3.4`.
        let items = items.into_iter().map(|ip| ip.to_canonical()).collect();
        self.items.store(Arc::new(items));
    }

    /// Always `false` for a unix socket connection — it has no source IP.
    pub fn is_debug_ip(&self, connection_ip: &ConnectionIp) -> bool {
        let Some(ip) = connection_ip.get_ip_addr() else {
            return false;
        };

        self.items.load().contains(&ip.to_canonical())
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    fn tcp(addr: &str) -> ConnectionIp {
        ConnectionIp::Tcp(addr.parse::<SocketAddr>().unwrap())
    }

    #[test]
    fn nobody_is_a_debug_ip_until_configured() {
        let list = DebugIpList::new();

        assert!(!list.is_debug_ip(&tcp("10.0.0.5:5000")));
        assert!(!list.is_debug_ip(&ConnectionIp::UnixSocket));
    }

    #[test]
    fn matches_only_the_configured_addresses() {
        let list = DebugIpList::new();
        list.set(vec!["10.0.0.5".parse().unwrap(), "::1".parse().unwrap()]);

        assert!(list.is_debug_ip(&tcp("10.0.0.5:5000")));
        assert!(list.is_debug_ip(&tcp("[::1]:5000")));
        assert!(list.is_debug_ip(&tcp("[::ffff:10.0.0.5]:5000")));
        assert!(!list.is_debug_ip(&tcp("10.0.0.6:5000")));
        assert!(!list.is_debug_ip(&ConnectionIp::UnixSocket));
    }

    #[test]
    fn a_reload_replaces_the_list() {
        let list = DebugIpList::new();
        list.set(vec!["10.0.0.5".parse().unwrap()]);
        list.set(vec![]);

        assert!(!list.is_debug_ip(&tcp("10.0.0.5:5000")));
    }
}

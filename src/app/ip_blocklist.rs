use std::net::IpAddr;
use std::sync::Arc;

use ahash::AHashMap;
use arc_swap::ArcSwapOption;
use parking_lot::Mutex;
use rust_extensions::date_time::DateTimeAsMicroseconds;

use crate::types::WhiteListedIpList;

const WINDOW_SECS: i64 = 15;
/// Unambiguous abuse (e.g. non-TLS bytes on a TLS port) — block quickly.
const HARD_FAIL_THRESHOLD: u16 = 5;
/// Noisier, possibly-benign failures on a real endpoint — must pile up.
/// 30 over the 15s window ≈ 2 requests/sec sustained.
const SOFT_FAIL_THRESHOLD: u16 = 30;
const BLOCK_SECS: i64 = 5 * 60;

/// How strong a signal a failed attempt is. Hard failures are unambiguous abuse
/// we want blocked fast; soft failures are noisy and must accumulate.
#[derive(Clone, Copy, Debug)]
pub enum FailureSeverity {
    Hard,
    Soft,
}

#[derive(Clone, Copy)]
struct IpEntry {
    hard_count: u16,
    soft_count: u16,
    window_start: DateTimeAsMicroseconds,
    blocked_until: Option<DateTimeAsMicroseconds>,
}

pub struct IpBlocklist {
    map: Mutex<AHashMap<IpAddr, IpEntry>>,
    /// Global allow-list: IPs that are never auto-blocked and whose failures are
    /// never counted. `None` when not configured. Behind ArcSwap so it stays
    /// cheap to read on the hot accept path.
    white_list: ArcSwapOption<WhiteListedIpList>,
}

impl IpBlocklist {
    pub fn new() -> Self {
        Self {
            map: Mutex::new(AHashMap::new()),
            white_list: ArcSwapOption::empty(),
        }
    }

    /// Replace the global allow-list. `None` or an empty list disables it — an
    /// empty `WhiteListedIpList` would otherwise match every IP and silently
    /// switch the whole block-list off.
    pub fn set_white_list(&self, src: Option<Vec<String>>) {
        match src {
            Some(src) if !src.is_empty() => {
                self.white_list
                    .store(Some(Arc::new(WhiteListedIpList::new(&src))));
            }
            _ => self.white_list.store(None),
        }
    }

    pub fn is_white_listed(&self, ip: &IpAddr) -> bool {
        match self.white_list.load_full() {
            Some(white_list) => white_list.is_whitelisted(ip),
            None => false,
        }
    }

    /// Never counted and never blocked: an address of the global allow-list, and a server of
    /// Cloudflare - it brings the requests of many clients at once, and blocking it would turn
    /// away every one of them. The client of a request through Cloudflare to a
    /// `cloudflare: true` endpoint is counted by its own address.
    fn is_exempt(&self, ip: &IpAddr) -> bool {
        self.is_white_listed(ip)
            || crate::app::APP_CTX.cloudflare_ip_ranges.contains(*ip) == Some(true)
    }

    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        if self.is_exempt(ip) {
            return false;
        }
        let map = self.map.lock();
        let Some(entry) = map.get(ip) else {
            return false;
        };
        let Some(blocked_until) = entry.blocked_until else {
            return false;
        };
        blocked_until > DateTimeAsMicroseconds::now()
    }

    /// A connection of `ip` got through to an endpoint: the noisy failures it had are forgiven -
    /// not the hard ones. Getting through takes nothing but a TLS handshake and a `Host`, so an
    /// address which tries one wrong api key or client secret after another, each on a connection
    /// of its own, would have its count taken back before every try, and never be blocked. A hard
    /// failure goes when its window is out.
    pub fn register_success(&self, ip: &IpAddr) {
        let mut map = self.map.lock();

        let Some(entry) = map.get_mut(ip) else {
            return;
        };

        if entry.hard_count == 0 && entry.blocked_until.is_none() {
            map.remove(ip);
        } else {
            entry.soft_count = 0;
        }
    }

    pub fn unblock(&self, ip: &IpAddr) -> bool {
        let mut map = self.map.lock();
        map.remove(ip).is_some()
    }

    pub fn register_failure(&self, ip: IpAddr, severity: FailureSeverity) {
        if self.is_exempt(&ip) {
            return;
        }

        let now = DateTimeAsMicroseconds::now();

        let (newly_blocked, hard_count, soft_count) = {
            let mut map = self.map.lock();
            let entry = map.entry(ip).or_insert(IpEntry {
                hard_count: 0,
                soft_count: 0,
                window_start: now,
                blocked_until: None,
            });

            if now.duration_since(entry.window_start).get_full_seconds() > WINDOW_SECS {
                entry.hard_count = 0;
                entry.soft_count = 0;
                entry.window_start = now;
            }

            let was_blocked = match entry.blocked_until {
                Some(until) => until > now,
                None => false,
            };

            match severity {
                FailureSeverity::Hard => entry.hard_count = entry.hard_count.saturating_add(1),
                FailureSeverity::Soft => entry.soft_count = entry.soft_count.saturating_add(1),
            }

            if entry.hard_count >= HARD_FAIL_THRESHOLD || entry.soft_count >= SOFT_FAIL_THRESHOLD {
                let mut blocked_until = now;
                blocked_until.add_seconds(BLOCK_SECS);
                entry.blocked_until = Some(blocked_until);
            }

            let blocked_now = match entry.blocked_until {
                Some(until) => until > now,
                None => false,
            };

            (
                blocked_now && !was_blocked,
                entry.hard_count,
                entry.soft_count,
            )
        };

        // One line per new block (not per failure), with the offending IP.
        if newly_blocked {
            crate::app::APP_CTX.proxy_logs.write_port(
                "ip-blocklist",
                Some(ip.to_string()),
                format!(
                    "Blocked IP {ip} for {BLOCK_SECS}s ({hard_count} hard / {soft_count} soft failures within {WINDOW_SECS}s)"
                ),
            );
        }
    }

    pub fn cleanup(&self) -> usize {
        let now = DateTimeAsMicroseconds::now();
        let mut map = self.map.lock();
        map.retain(|_, entry| {
            if let Some(blocked_until) = entry.blocked_until {
                if blocked_until > now {
                    return true;
                }
            }
            now.duration_since(entry.window_start).get_full_seconds() <= WINDOW_SECS
        });
        map.values()
            .filter(|entry| match entry.blocked_until {
                Some(until) => until > now,
                None => false,
            })
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 99, 0, last])
    }

    #[test]
    fn five_hard_failures_block_the_address() {
        let blocklist = IpBlocklist::new();

        for _ in 0..HARD_FAIL_THRESHOLD - 1 {
            blocklist.register_failure(ip(1), FailureSeverity::Hard);
        }
        assert!(!blocklist.is_blocked(&ip(1)));

        blocklist.register_failure(ip(1), FailureSeverity::Hard);
        assert!(blocklist.is_blocked(&ip(1)));
        assert!(!blocklist.is_blocked(&ip(2)));
    }

    /// One wrong key after another, each on a connection of its own which gets through to the
    /// endpoint first: the hard failures add up all the same.
    #[test]
    fn a_connection_which_gets_through_does_not_forgive_hard_failures() {
        let blocklist = IpBlocklist::new();

        for _ in 0..HARD_FAIL_THRESHOLD {
            blocklist.register_success(&ip(3));
            blocklist.register_failure(ip(3), FailureSeverity::Hard);
        }

        assert!(blocklist.is_blocked(&ip(3)));
    }

    #[test]
    fn a_connection_which_gets_through_forgives_soft_failures() {
        let blocklist = IpBlocklist::new();

        for _ in 0..SOFT_FAIL_THRESHOLD * 2 {
            blocklist.register_failure(ip(4), FailureSeverity::Soft);
            blocklist.register_success(&ip(4));
        }
        assert!(!blocklist.is_blocked(&ip(4)));

        // With a hard failure counted, the soft ones are still forgiven - and the hard one stays.
        blocklist.register_failure(ip(5), FailureSeverity::Hard);
        for _ in 0..SOFT_FAIL_THRESHOLD * 2 {
            blocklist.register_failure(ip(5), FailureSeverity::Soft);
            blocklist.register_success(&ip(5));
        }
        assert!(!blocklist.is_blocked(&ip(5)));

        for _ in 0..HARD_FAIL_THRESHOLD - 1 {
            blocklist.register_failure(ip(5), FailureSeverity::Hard);
        }
        assert!(blocklist.is_blocked(&ip(5)));
    }

    #[test]
    fn a_white_listed_address_is_never_counted() {
        let blocklist = IpBlocklist::new();
        blocklist.set_white_list(Some(vec!["10.99.0.6".to_string()]));

        for _ in 0..HARD_FAIL_THRESHOLD * 2 {
            blocklist.register_failure(ip(6), FailureSeverity::Hard);
        }

        assert!(!blocklist.is_blocked(&ip(6)));
    }
}

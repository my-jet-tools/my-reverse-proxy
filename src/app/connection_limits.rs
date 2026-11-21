use std::{
    net::IpAddr,
    sync::atomic::{AtomicUsize, Ordering},
};

use ahash::AHashMap;
use parking_lot::Mutex;

/// `max_connections` and `max_connections_per_ip` of `global_settings`, resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionLimitsSettings {
    /// The client connections every port of `hosts` holds at once, together. nginx:
    /// `worker_connections`.
    pub max_connections: usize,
    /// ... of them from one address. nginx: `limit_conn`.
    pub max_connections_per_ip: usize,
}

impl ConnectionLimitsSettings {
    /// The limits out of `global_settings`, each a default where it is not given:
    /// `max_connections` half the files the process may open - a proxied connection holds one to
    /// its upstream as well - and `max_connections_per_ip` 1000. Errors on `0`.
    pub fn resolve(
        max_connections: Option<usize>,
        max_connections_per_ip: Option<usize>,
    ) -> Result<Self, String> {
        let max_connections = match max_connections {
            Some(0) => {
                return Err(
                    "global_settings.max_connections: 0 would take no connection".to_string(),
                )
            }
            Some(max_connections) => max_connections,
            None => default_max_connections(),
        };

        let max_connections_per_ip = match max_connections_per_ip {
            Some(0) => {
                return Err(
                    "global_settings.max_connections_per_ip: 0 would take no connection"
                        .to_string(),
                )
            }
            Some(max_connections_per_ip) => max_connections_per_ip,
            None => crate::consts::DEFAULT_MAX_CONNECTIONS_PER_IP,
        };

        Ok(Self {
            max_connections,
            max_connections_per_ip,
        })
    }
}

impl Default for ConnectionLimitsSettings {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            max_connections_per_ip: crate::consts::DEFAULT_MAX_CONNECTIONS_PER_IP,
        }
    }
}

/// Half the files the process may open: the soft `RLIMIT_NOFILE`.
#[cfg(unix)]
fn default_max_connections() -> usize {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };

    // SAFETY: `getrlimit` writes the limit into the struct it is given, which lives on this stack
    // frame for the whole call.
    let read = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };

    if read != 0 {
        return crate::consts::DEFAULT_MAX_CONNECTIONS_WITHOUT_RLIMIT;
    }

    usize::try_from(limit.rlim_cur / 2)
        .unwrap_or(usize::MAX)
        .max(crate::consts::MIN_DEFAULT_MAX_CONNECTIONS)
}

#[cfg(not(unix))]
fn default_max_connections() -> usize {
    crate::consts::DEFAULT_MAX_CONNECTIONS_WITHOUT_RLIMIT
}

/// Why a connection was not taken.
#[derive(Debug, PartialEq, Eq)]
pub enum ConnectionRefusal {
    /// `max_connections` are held already.
    Total(usize),
    /// `max_connections_per_ip` are held from this address already.
    PerIp(usize),
}

impl std::fmt::Display for ConnectionRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Total(max) => write!(f, "{max} connections are held already (max_connections)"),
            Self::PerIp(max) => write!(
                f,
                "{max} connections from this address are held already (max_connections_per_ip)"
            ),
        }
    }
}

/// The client connections the listeners of `hosts` hold: in all, and from each address. A
/// connection over the limit is closed as it is accepted - before a byte of it is read - so a
/// flood of connections can not take the files of the process, which every other connection and
/// every upstream needs.
pub struct ConnectionLimits {
    max_connections: AtomicUsize,
    max_connections_per_ip: AtomicUsize,
    held: AtomicUsize,
    held_per_ip: Mutex<AHashMap<IpAddr, usize>>,
}

impl ConnectionLimits {
    pub fn new(settings: ConnectionLimitsSettings) -> Self {
        Self {
            max_connections: AtomicUsize::new(settings.max_connections),
            max_connections_per_ip: AtomicUsize::new(settings.max_connections_per_ip),
            held: AtomicUsize::new(0),
            held_per_ip: Mutex::new(AHashMap::new()),
        }
    }

    /// New limits, from a reload of the settings. The connections held already stay.
    pub fn set(&self, settings: ConnectionLimitsSettings) {
        self.max_connections
            .store(settings.max_connections, Ordering::Release);
        self.max_connections_per_ip
            .store(settings.max_connections_per_ip, Ordering::Release);
    }

    /// A slot for a connection from `ip`, held until it is dropped - with the connection.
    /// `exempt`: the address is not limited on its own - Cloudflare, which brings the
    /// connections of all its visitors, or an address of `ip_blocklist_white_list`.
    pub fn take(
        &'static self,
        ip: IpAddr,
        exempt: bool,
    ) -> Result<ConnectionSlot, ConnectionRefusal> {
        let max_connections = self.max_connections.load(Ordering::Acquire);
        let mut held = self.held.load(Ordering::Acquire);

        loop {
            if held >= max_connections {
                return Err(ConnectionRefusal::Total(max_connections));
            }

            match self.held.compare_exchange_weak(
                held,
                held + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => held = actual,
            }
        }

        if exempt {
            return Ok(ConnectionSlot {
                limits: Some(self),
                ip: None,
            });
        }

        let max_connections_per_ip = self.max_connections_per_ip.load(Ordering::Acquire);
        let mut held_per_ip = self.held_per_ip.lock();
        let held_from_ip = held_per_ip.entry(ip).or_insert(0);

        if *held_from_ip >= max_connections_per_ip {
            drop(held_per_ip);
            self.held.fetch_sub(1, Ordering::AcqRel);
            return Err(ConnectionRefusal::PerIp(max_connections_per_ip));
        }

        *held_from_ip += 1;

        Ok(ConnectionSlot {
            limits: Some(self),
            ip: Some(ip),
        })
    }

    #[cfg(test)]
    pub fn held(&self) -> usize {
        self.held.load(Ordering::Acquire)
    }
}

/// A connection's place among the ones held: given back when this is dropped.
pub struct ConnectionSlot {
    limits: Option<&'static ConnectionLimits>,
    /// The address it is counted for - `None`: not counted for one.
    ip: Option<IpAddr>,
}

impl ConnectionSlot {
    /// For a connection no limit is kept for: one of a unix socket, from the host itself.
    #[cfg(any(unix, test))]
    pub fn unlimited() -> Self {
        Self {
            limits: None,
            ip: None,
        }
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        let Some(limits) = self.limits else {
            return;
        };

        limits.held.fetch_sub(1, Ordering::AcqRel);

        if let Some(ip) = self.ip {
            let mut held_per_ip = limits.held_per_ip.lock();

            if let Some(held_from_ip) = held_per_ip.get_mut(&ip) {
                *held_from_ip -= 1;

                if *held_from_ip == 0 {
                    held_per_ip.remove(&ip);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(max_connections: usize, max_connections_per_ip: usize) -> &'static ConnectionLimits {
        Box::leak(Box::new(ConnectionLimits::new(ConnectionLimitsSettings {
            max_connections,
            max_connections_per_ip,
        })))
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    #[test]
    fn an_address_gets_no_more_than_its_limit_and_the_slots_come_back() {
        let limits = limits(100, 2);

        let first = limits.take(ip(1), false).unwrap();
        let _second = limits.take(ip(1), false).unwrap();
        assert_eq!(
            limits.take(ip(1), false).err(),
            Some(ConnectionRefusal::PerIp(2))
        );

        // Another address is not held back by it.
        let _other = limits.take(ip(2), false).unwrap();

        drop(first);
        let _again = limits.take(ip(1), false).unwrap();
        assert_eq!(limits.held(), 3);
    }

    #[test]
    fn no_more_than_the_total_is_taken() {
        let limits = limits(2, 100);

        let _first = limits.take(ip(1), false).unwrap();
        let _second = limits.take(ip(2), true).unwrap();
        assert_eq!(
            limits.take(ip(3), false).err(),
            Some(ConnectionRefusal::Total(2))
        );
        assert_eq!(limits.held(), 2);
    }

    #[test]
    fn an_exempt_address_is_held_to_the_total_only() {
        let limits = limits(100, 1);

        let slots: Vec<_> = (0..10).map(|_| limits.take(ip(1), true).unwrap()).collect();
        assert_eq!(limits.held(), 10);

        drop(slots);
        assert_eq!(limits.held(), 0);
        assert!(limits.held_per_ip.lock().is_empty());
    }

    #[test]
    fn new_limits_apply_to_the_next_connection() {
        let limits = limits(100, 1);

        let _first = limits.take(ip(1), false).unwrap();
        assert!(limits.take(ip(1), false).is_err());

        limits.set(ConnectionLimitsSettings {
            max_connections: 100,
            max_connections_per_ip: 2,
        });
        assert!(limits.take(ip(1), false).is_ok());
    }

    #[test]
    fn settings_default_and_refuse_zero() {
        let settings = ConnectionLimitsSettings::resolve(None, None).unwrap();
        assert_eq!(settings.max_connections_per_ip, 1000);
        assert!(settings.max_connections >= crate::consts::MIN_DEFAULT_MAX_CONNECTIONS);

        let settings = ConnectionLimitsSettings::resolve(Some(500), Some(20)).unwrap();
        assert_eq!(settings.max_connections, 500);
        assert_eq!(settings.max_connections_per_ip, 20);

        assert!(ConnectionLimitsSettings::resolve(Some(0), None).is_err());
        assert!(ConnectionLimitsSettings::resolve(None, Some(0)).is_err());
    }
}

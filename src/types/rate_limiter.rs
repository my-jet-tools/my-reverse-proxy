use std::{
    net::IpAddr,
    time::{Duration, Instant},
};

use ahash::AHashMap;
use parking_lot::Mutex;

/// Once there are so many clients in the table, the ones which are back to a full bucket - which
/// did nothing for long enough - are forgotten.
const FORGET_IDLE_CLIENTS_AT: usize = 10_000;

/// `rate_limit` of an endpoint or a location: how many requests one client may make - nginx's
/// `limit_req`. `10/s`, `600/m`, `100/h`: so many requests a second, a minute or an hour, and
/// `rate_limit_burst` of them at once (absent: as many as the period allows). A request over it is
/// answered `429 Too Many Requests` with a `Retry-After`.
///
/// A client is its address - behind Cloudflare the one of `CF-Connecting-IP` - and an IPv6 one
/// its /64 network: what one subscriber gets, and could otherwise walk through for a new limit
/// with every request.
pub struct RateLimiter {
    /// Requests a client is given back per second.
    per_second: f64,
    /// Requests a client may make at once: the size of its bucket.
    burst: f64,
    clients: Mutex<AHashMap<ClientKey, Bucket>>,
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
enum ClientKey {
    V4([u8; 4]),
    /// The /64 network.
    V6([u8; 8]),
}

impl ClientKey {
    fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => Self::V4(ip.octets()),
            IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
                Some(ip) => Self::V4(ip.octets()),
                None => {
                    let octets = ip.octets();
                    let mut network = [0u8; 8];
                    network.copy_from_slice(&octets[..8]);
                    Self::V6(network)
                }
            },
        }
    }
}

struct Bucket {
    tokens: f64,
    filled_at: Instant,
}

impl Bucket {
    fn tokens_at(&self, now: Instant, per_second: f64, burst: f64) -> f64 {
        let refilled = now.duration_since(self.filled_at).as_secs_f64() * per_second;
        (self.tokens + refilled).min(burst)
    }
}

impl RateLimiter {
    /// `rate`: `<requests>/s`, `/m` or `/h`. `burst`: the requests at once - absent, the number
    /// of `rate`. Errors on anything else, and on `0`.
    pub fn parse(rate: &str, burst: Option<u32>) -> Result<Self, String> {
        let invalid = || {
            format!("rate_limit: '{rate}' is not a rate - it is written as 10/s, 600/m or 100/h")
        };

        let (requests, period) = rate.trim().split_once('/').ok_or_else(invalid)?;
        let requests: u32 = requests.trim().parse().map_err(|_| invalid())?;

        let period_seconds = match period.trim() {
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            _ => return Err(invalid()),
        };

        if requests == 0 {
            return Err(format!("rate_limit: '{rate}' would let no request in"));
        }

        let burst = burst.unwrap_or(requests);

        if burst == 0 {
            return Err("rate_limit_burst: 0 would let no request in".to_string());
        }

        Ok(Self {
            per_second: requests as f64 / period_seconds,
            burst: burst as f64,
            clients: Mutex::new(AHashMap::new()),
        })
    }

    /// A request of the client at `ip`. `Err`: it is over the limit, and the next one may come
    /// in so long.
    pub fn take(&self, ip: IpAddr) -> Result<(), Duration> {
        self.take_at(ip, Instant::now())
    }

    fn take_at(&self, ip: IpAddr, now: Instant) -> Result<(), Duration> {
        let mut clients = self.clients.lock();

        if clients.len() >= FORGET_IDLE_CLIENTS_AT {
            let (per_second, burst) = (self.per_second, self.burst);
            clients.retain(|_, bucket| bucket.tokens_at(now, per_second, burst) < burst);
        }

        let bucket = clients.entry(ClientKey::of(ip)).or_insert(Bucket {
            tokens: self.burst,
            filled_at: now,
        });

        bucket.tokens = bucket.tokens_at(now, self.per_second, self.burst);
        bucket.filled_at = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return Ok(());
        }

        Err(Duration::from_secs_f64(
            (1.0 - bucket.tokens) / self.per_second,
        ))
    }
}

/// `Retry-After`: whole seconds, at least one.
pub fn retry_after_seconds(wait: Duration) -> u64 {
    wait.as_secs_f64().ceil().max(1.0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn a_rate_is_requests_a_second_a_minute_or_an_hour() {
        assert_eq!(RateLimiter::parse("10/s", None).unwrap().per_second, 10.0);
        assert_eq!(
            RateLimiter::parse(" 600 / m ", None).unwrap().per_second,
            10.0
        );
        assert_eq!(RateLimiter::parse("3600/h", None).unwrap().per_second, 1.0);
        assert_eq!(RateLimiter::parse("5/m", None).unwrap().burst, 5.0);
        assert_eq!(RateLimiter::parse("5/m", Some(2)).unwrap().burst, 2.0);

        for wrong in ["10", "10/d", "ten/s", "/s", "0/s", "-1/s"] {
            assert!(RateLimiter::parse(wrong, None).is_err(), "{wrong}");
        }
        assert!(RateLimiter::parse("10/s", Some(0)).is_err());
    }

    #[test]
    fn a_client_gets_its_burst_and_then_the_rate() {
        let limiter = RateLimiter::parse("2/s", Some(3)).unwrap();
        let start = Instant::now();

        for _ in 0..3 {
            assert!(limiter.take_at(ip("10.0.0.1"), start).is_ok());
        }

        let wait = limiter.take_at(ip("10.0.0.1"), start).unwrap_err();
        assert_eq!(wait, Duration::from_millis(500));
        assert_eq!(retry_after_seconds(wait), 1);

        // Another client has a bucket of its own.
        assert!(limiter.take_at(ip("10.0.0.2"), start).is_ok());

        // Half a second gives one request back.
        let later = start + Duration::from_millis(500);
        assert!(limiter.take_at(ip("10.0.0.1"), later).is_ok());
        assert!(limiter.take_at(ip("10.0.0.1"), later).is_err());
    }

    #[test]
    fn an_ipv6_client_is_its_64_network() {
        let limiter = RateLimiter::parse("1/m", None).unwrap();
        let now = Instant::now();

        assert!(limiter.take_at(ip("2001:db8:1:2::1"), now).is_ok());
        assert!(limiter.take_at(ip("2001:db8:1:2::ffff"), now).is_err());
        assert!(limiter.take_at(ip("2001:db8:1:3::1"), now).is_ok());

        // An IPv4 address mapped into IPv6 is the IPv4 one.
        assert!(limiter.take_at(ip("192.0.2.7"), now).is_ok());
        assert!(limiter.take_at(ip("::ffff:192.0.2.7"), now).is_err());
    }

    #[test]
    fn idle_clients_are_forgotten_when_the_table_is_full() {
        let limiter = RateLimiter::parse("1/s", None).unwrap();
        let start = Instant::now();

        for n in 0..FORGET_IDLE_CLIENTS_AT as u32 {
            let ip = IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0000 + n));
            limiter.take_at(ip, start).unwrap();
        }

        // A second later all of them have their request back: the next client finds them gone.
        limiter
            .take_at(ip("192.0.2.1"), start + Duration::from_secs(1))
            .unwrap();
        assert_eq!(limiter.clients.lock().len(), 1);
    }
}

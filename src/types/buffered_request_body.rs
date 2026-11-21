//! Request bodies the proxy holds whole in memory before it sends them on - to an upstream which
//! takes a body in one piece (every upstream but h2), a body to compress, a websocket handshake.
//! See `collect_client_body` of the request builder.
//!
//! A held body is limited twice: by `max_buffered_request_body` - a larger one is answered `413` -
//! and, all of them together, by `max_buffered_request_bodies_total` - over it a body is answered
//! `503`. The first alone is no limit on the memory: an h2 connection carries 200 requests at once,
//! and the connections are not counted.

use std::sync::atomic::{AtomicUsize, Ordering};

/// The limits of the bodies of an endpoint, resolved: `global_settings`, then the endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferedBodyLimits {
    /// `max_buffered_request_body`: the most one body may take. Never more than `max_total`.
    pub max_body: usize,
    /// `max_buffered_request_bodies_total`: the most all bodies held at once may take. A setting
    /// of `global_settings` only; every endpoint carries it, as it carries the global timeouts.
    pub max_total: usize,
}

impl Default for BufferedBodyLimits {
    fn default() -> Self {
        Self {
            max_body: crate::consts::DEFAULT_MAX_BUFFERED_REQUEST_BODY,
            max_total: crate::consts::DEFAULT_MAX_BUFFERED_REQUEST_BODIES_TOTAL,
        }
    }
}

impl BufferedBodyLimits {
    /// The limits of an endpoint: `max_buffered_request_body` of the endpoint, else of
    /// `global_settings`; `max_buffered_request_bodies_total` of `global_settings`. Each is a raw
    /// byte count or a number with `Kb`, `Mb` or `Gb`.
    ///
    /// Errors on a value which is not a size, on `0`, and on a body given more than all bodies
    /// together - a typo fails the settings load instead of turning into a limit nobody meant. A
    /// total below the default of one body takes the default down with it: that one was not given.
    pub fn resolve(
        global_max_body: Option<&str>,
        global_max_total: Option<&str>,
        endpoint_max_body: Option<&str>,
    ) -> Result<Self, String> {
        let max_total = match global_max_total {
            Some(value) => parse_limit("global_settings.max_buffered_request_bodies_total", value)?,
            None => crate::consts::DEFAULT_MAX_BUFFERED_REQUEST_BODIES_TOTAL,
        };

        let given_max_body = match (endpoint_max_body, global_max_body) {
            (Some(value), _) => Some(("max_buffered_request_body", value)),
            (None, Some(value)) => Some(("global_settings.max_buffered_request_body", value)),
            (None, None) => None,
        };

        let max_body = match given_max_body {
            Some((setting, value)) => {
                let max_body = parse_limit(setting, value)?;

                if max_body > max_total {
                    return Err(format!(
                        "{setting}: '{value}' is more than all request bodies held at once may \
                         take - global_settings.max_buffered_request_bodies_total is {max_total} \
                         bytes. Raise that one too"
                    ));
                }

                max_body
            }
            None => crate::consts::DEFAULT_MAX_BUFFERED_REQUEST_BODY.min(max_total),
        };

        Ok(Self {
            max_body,
            max_total,
        })
    }
}

/// `max_request_body` of an endpoint - else of `global_settings`: the most any request body may
/// take, streamed or held. `None`: no limit but the ones of the bodies held in memory.
pub fn resolve_max_request_body(
    global: Option<&str>,
    endpoint: Option<&str>,
) -> Result<Option<usize>, String> {
    match (endpoint, global) {
        (Some(value), _) => parse_limit("max_request_body", value).map(Some),
        (None, Some(value)) => parse_limit("global_settings.max_request_body", value).map(Some),
        (None, None) => Ok(None),
    }
}

fn parse_limit(setting: &str, value: &str) -> Result<usize, String> {
    let size = crate::settings::parse_buffer_size(value.trim())
        .map_err(|err| format!("{setting}: {err}"))?;

    if size == 0 {
        return Err(format!(
            "{setting}: '{value}' would refuse every request body. Give the most a body may take"
        ));
    }

    Ok(size)
}

/// The bytes of the request bodies held right now, the endpoints together.
pub struct BufferedBodies {
    held: AtomicUsize,
}

/// The bodies of the process: one count for every endpoint.
pub static BUFFERED_REQUEST_BODIES: BufferedBodies = BufferedBodies::new();

impl BufferedBodies {
    pub const fn new() -> Self {
        Self {
            held: AtomicUsize::new(0),
        }
    }

    #[cfg(test)]
    pub fn held(&self) -> usize {
        self.held.load(Ordering::Acquire)
    }

    /// The share of one body - nothing of it is held yet.
    pub fn share(&'static self) -> BufferedBodyShare {
        BufferedBodyShare {
            bodies: self,
            bytes: 0,
        }
    }
}

/// What one body takes of its [`BufferedBodies`]: given back when this is dropped.
pub struct BufferedBodyShare {
    bodies: &'static BufferedBodies,
    bytes: usize,
}

impl BufferedBodyShare {
    /// `len` bytes more of the body, if all bodies held stay within `max_total` with them.
    /// `false`: they would not, and nothing is taken.
    pub fn take(&mut self, len: usize, max_total: usize) -> bool {
        let mut held = self.bodies.held.load(Ordering::Acquire);

        loop {
            let Some(next) = held.checked_add(len) else {
                return false;
            };

            if next > max_total {
                return false;
            }

            match self.bodies.held.compare_exchange_weak(
                held,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.bytes += len;
                    return true;
                }
                Err(actual) => held = actual,
            }
        }
    }

    #[cfg(test)]
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

impl Drop for BufferedBodyShare {
    fn drop(&mut self) {
        if self.bytes > 0 {
            self.bodies.held.fetch_sub(self.bytes, Ordering::AcqRel);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MB: usize = 1024 * 1024;

    #[test]
    fn nothing_given_is_the_defaults() {
        assert_eq!(
            BufferedBodyLimits::resolve(None, None, None),
            Ok(BufferedBodyLimits::default())
        );
        assert_eq!(BufferedBodyLimits::default().max_body, 100 * MB);
        assert_eq!(BufferedBodyLimits::default().max_total, 512 * MB);
    }

    #[test]
    fn the_endpoint_wins_over_global_settings() {
        let limits = BufferedBodyLimits::resolve(Some("10Mb"), Some("1Gb"), Some("200Mb")).unwrap();
        assert_eq!(limits.max_body, 200 * MB);
        assert_eq!(limits.max_total, 1024 * MB);

        let limits = BufferedBodyLimits::resolve(Some("10Mb"), None, None).unwrap();
        assert_eq!(limits.max_body, 10 * MB);
        assert_eq!(limits.max_total, 512 * MB);

        let limits = BufferedBodyLimits::resolve(None, None, Some("1048576")).unwrap();
        assert_eq!(limits.max_body, MB);
    }

    #[test]
    fn a_body_may_not_be_given_more_than_all_bodies() {
        let err = BufferedBodyLimits::resolve(None, Some("50Mb"), Some("60Mb")).unwrap_err();
        assert!(
            err.starts_with("max_buffered_request_body: '60Mb'"),
            "{err}"
        );

        let err = BufferedBodyLimits::resolve(Some("1Gb"), None, None).unwrap_err();
        assert!(
            err.starts_with("global_settings.max_buffered_request_body: '1Gb'"),
            "{err}"
        );

        // The default of one body is not a value anybody gave: a smaller total takes it down.
        let limits = BufferedBodyLimits::resolve(None, Some("50Mb"), None).unwrap();
        assert_eq!(limits.max_body, 50 * MB);
        assert_eq!(limits.max_total, 50 * MB);
    }

    #[test]
    fn a_value_which_is_not_a_size_or_is_zero_fails_the_load() {
        let err = BufferedBodyLimits::resolve(None, None, Some("10 MB")).unwrap_err();
        assert!(err.starts_with("max_buffered_request_body: "), "{err}");

        let err = BufferedBodyLimits::resolve(None, Some("lots"), None).unwrap_err();
        assert!(
            err.starts_with("global_settings.max_buffered_request_bodies_total: "),
            "{err}"
        );

        let err = BufferedBodyLimits::resolve(Some("0"), None, None).unwrap_err();
        assert!(err.contains("would refuse every request body"), "{err}");
    }

    #[test]
    fn a_share_takes_within_the_total_and_gives_back_when_dropped() {
        static BODIES: BufferedBodies = BufferedBodies::new();

        let mut first = BODIES.share();
        assert!(first.take(600, 1000));
        assert!(first.take(300, 1000));
        assert_eq!(first.bytes(), 900);

        let mut second = BODIES.share();
        assert!(!second.take(200, 1000), "over the total");
        assert_eq!(second.bytes(), 0, "a refused take takes nothing");
        assert!(second.take(100, 1000), "exactly the total");
        assert_eq!(BODIES.held(), 1000);

        drop(first);
        assert_eq!(BODIES.held(), 100);

        drop(second);
        assert_eq!(BODIES.held(), 0);
    }

    #[test]
    fn a_take_which_would_overflow_is_refused() {
        static BODIES: BufferedBodies = BufferedBodies::new();

        let mut share = BODIES.share();
        assert!(share.take(10, usize::MAX));
        assert!(!share.take(usize::MAX, usize::MAX));
        assert_eq!(BODIES.held(), 10);
    }
}

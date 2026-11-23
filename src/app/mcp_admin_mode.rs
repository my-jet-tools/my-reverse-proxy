use std::sync::atomic::{AtomicI64, Ordering};

use rust_extensions::date_time::DateTimeAsMicroseconds;

/// What a tool which changes something answers while the admin mode is closed.
pub const MCP_ADMIN_MODE_IS_CLOSED: &str = "MCP admin mode is closed: this tool changes the proxy, and works only while the operator has opened admin mode - with an encrypted call of the control port, POST /api/mcp/v1/admin-mode. No MCP tool opens it: ask the operator to open it, and do not retry until then.";

/// The admin mode of MCP: while it is open, the tools which change the proxy work - they reload
/// the settings, generate private keys, set the connections to gateways and the keys the gateway
/// server lets in. It is opened for some minutes by an encrypted call of the control port,
/// `POST /api/mcp/v1/admin-mode`, and closes by itself; no MCP tool opens it. It is closed when
/// the proxy starts.
pub struct McpAdminMode {
    /// Unix microseconds it is open until; 0 - closed.
    open_until: AtomicI64,
}

impl McpAdminMode {
    pub fn new() -> Self {
        Self {
            open_until: AtomicI64::new(0),
        }
    }

    /// Opens it for `minutes` from `now` - in place of the time it had left - or closes it with 0.
    pub fn open_for(&self, minutes: u64, now: DateTimeAsMicroseconds) {
        let until = match minutes {
            0 => 0,
            minutes => now.unix_microseconds + minutes as i64 * 60 * 1_000_000,
        };

        self.open_until.store(until, Ordering::SeqCst);
    }

    /// The seconds it stays open for from `now`, a part of one counted as one: 0 when it is closed.
    pub fn seconds_left(&self, now: DateTimeAsMicroseconds) -> i64 {
        let until = self.open_until.load(Ordering::SeqCst);

        if until <= now.unix_microseconds {
            return 0;
        }

        (until - now.unix_microseconds + 999_999) / 1_000_000
    }

    /// `Ok` while it is open; what the tool answers when it is closed.
    pub fn check(&self, now: DateTimeAsMicroseconds) -> Result<(), String> {
        if self.seconds_left(now) > 0 {
            Ok(())
        } else {
            Err(MCP_ADMIN_MODE_IS_CLOSED.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: i64) -> DateTimeAsMicroseconds {
        DateTimeAsMicroseconds::new(1_700_000_000_000_000 + seconds * 1_000_000)
    }

    #[test]
    fn it_is_closed_until_it_is_opened() {
        let mode = McpAdminMode::new();

        assert_eq!(mode.seconds_left(at(0)), 0);
        assert!(mode.check(at(0)).is_err());
    }

    #[test]
    fn it_closes_by_itself_when_its_minutes_are_over() {
        let mode = McpAdminMode::new();
        mode.open_for(10, at(0));

        assert_eq!(mode.seconds_left(at(0)), 600);
        assert_eq!(mode.seconds_left(at(599)), 1);
        assert!(mode.check(at(599)).is_ok());

        assert_eq!(mode.seconds_left(at(600)), 0);
        assert!(mode.check(at(600)).is_err());
    }

    #[test]
    fn opening_it_again_sets_its_time_and_zero_closes_it() {
        let mode = McpAdminMode::new();
        mode.open_for(60, at(0));
        mode.open_for(1, at(10));

        assert_eq!(mode.seconds_left(at(10)), 60);

        mode.open_for(0, at(20));
        assert!(mode.check(at(20)).is_err());
    }
}

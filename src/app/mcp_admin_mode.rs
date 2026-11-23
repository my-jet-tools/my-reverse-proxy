use rust_extensions::date_time::DateTimeAsMicroseconds;

use super::{CallerIp, McpSessionCaller};

/// What a tool which changes something answers while the admin mode is closed.
pub const MCP_ADMIN_MODE_IS_CLOSED: &str = "MCP admin mode is closed: this tool changes the proxy, and works only while the operator has opened admin mode - with an encrypted call of the control port, POST /api/mcp/v1/admin-mode, from the address this MCP client comes from. No MCP tool opens it: ask the operator to open it, and do not retry until then.";

/// The admin mode of MCP: while it is open, the tools which change the proxy work - they reload
/// the settings, generate private keys, set the connections to gateways and the keys the gateway
/// server lets in - for the MCP sessions which come from the address it was opened from, and for
/// no other. It is opened for some minutes by an encrypted call of the control port,
/// `POST /api/mcp/v1/admin-mode`, closed by such a call from any address, and closes by itself;
/// no MCP tool opens it. It is closed when the proxy starts.
pub struct McpAdminMode {
    window: parking_lot::Mutex<Option<AdminWindow>>,
}

#[derive(Clone, Copy)]
struct AdminWindow {
    /// Unix microseconds it is open until.
    until: i64,
    /// Where the call which opened it came from.
    opened_from: CallerIp,
}

/// The admin mode as it is now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpAdminModeState {
    pub seconds_left: i64,
    pub opened_from: CallerIp,
}

impl McpAdminMode {
    pub fn new() -> Self {
        Self {
            window: parking_lot::Mutex::new(None),
        }
    }

    /// Opens it for `minutes` from `now` for the MCP sessions which come from `opened_from` - in
    /// place of what it had - or closes it with 0, whoever asks.
    pub fn open_for(&self, minutes: u64, now: DateTimeAsMicroseconds, opened_from: CallerIp) {
        let window = match minutes {
            0 => None,
            minutes => Some(AdminWindow {
                until: now.unix_microseconds + minutes as i64 * 60 * 1_000_000,
                opened_from,
            }),
        };

        *self.window.lock() = window;
    }

    /// While it is open: for how long more, and for whom.
    pub fn state(&self, now: DateTimeAsMicroseconds) -> Option<McpAdminModeState> {
        let window = (*self.window.lock())?;

        if window.until <= now.unix_microseconds {
            return None;
        }

        Some(McpAdminModeState {
            // A part of a second counted as one.
            seconds_left: (window.until - now.unix_microseconds + 999_999) / 1_000_000,
            opened_from: window.opened_from,
        })
    }

    /// The seconds it stays open for from `now`: 0 when it is closed.
    #[cfg(test)]
    pub fn seconds_left(&self, now: DateTimeAsMicroseconds) -> i64 {
        self.state(now).map(|itm| itm.seconds_left).unwrap_or(0)
    }

    /// `Ok` while it is open for where `session` comes from; what the tool answers otherwise.
    pub fn check_for(
        &self,
        session: McpSessionCaller,
        now: DateTimeAsMicroseconds,
    ) -> Result<(), String> {
        let Some(state) = self.state(now) else {
            return Err(MCP_ADMIN_MODE_IS_CLOSED.to_string());
        };

        let opened_for = format!(
            "MCP admin mode is open for {} ({}) only",
            state.opened_from,
            state.opened_from.country()
        );

        match session {
            McpSessionCaller::From(caller) if caller == state.opened_from => Ok(()),
            McpSessionCaller::From(caller) => Err(format!(
                "{opened_for}, and this MCP session comes from {caller} ({}). The operator opens it from the address the MCP client comes from.",
                caller.country()
            )),
            McpSessionCaller::Mixed => Err(format!(
                "{opened_for}, and this MCP session has come from more than one address: start a new session."
            )),
            McpSessionCaller::Unknown => Err(format!(
                "{opened_for}, and where this MCP session comes from is not known: start a new session."
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: i64) -> DateTimeAsMicroseconds {
        DateTimeAsMicroseconds::new(1_700_000_000_000_000 + seconds * 1_000_000)
    }

    fn from(text: &str) -> CallerIp {
        CallerIp::Ip(text.parse().unwrap())
    }

    #[test]
    fn it_is_closed_until_it_is_opened() {
        let mode = McpAdminMode::new();

        assert_eq!(mode.seconds_left(at(0)), 0);
        assert!(mode
            .check_for(McpSessionCaller::From(CallerIp::ThisHost), at(0))
            .is_err());
    }

    #[test]
    fn it_closes_by_itself_when_its_minutes_are_over() {
        let mode = McpAdminMode::new();
        let operator = from("203.0.113.7");
        mode.open_for(10, at(0), operator);

        assert_eq!(mode.seconds_left(at(0)), 600);
        assert_eq!(mode.seconds_left(at(599)), 1);
        assert!(mode
            .check_for(McpSessionCaller::From(operator), at(599))
            .is_ok());

        assert_eq!(mode.seconds_left(at(600)), 0);
        assert!(mode
            .check_for(McpSessionCaller::From(operator), at(600))
            .is_err());
    }

    /// Open for the address it was opened from, and for no other.
    #[test]
    fn it_lets_in_only_the_sessions_of_the_address_it_was_opened_from() {
        let mode = McpAdminMode::new();
        let operator = from("203.0.113.7");
        mode.open_for(10, at(0), operator);

        assert!(mode
            .check_for(McpSessionCaller::From(operator), at(1))
            .is_ok());

        for session in [
            McpSessionCaller::From(from("198.51.100.1")),
            McpSessionCaller::From(CallerIp::ThisHost),
            McpSessionCaller::Mixed,
            McpSessionCaller::Unknown,
        ] {
            let err = mode.check_for(session, at(1)).unwrap_err();
            assert!(err.contains("open for 203.0.113.7"), "{session:?}: {err}");
        }

        assert_eq!(mode.state(at(1)).map(|itm| itm.opened_from), Some(operator));
    }

    /// Opening it again takes it to the new address; closing it is anybody's.
    #[test]
    fn opening_it_again_moves_it_and_zero_closes_it() {
        let mode = McpAdminMode::new();
        mode.open_for(60, at(0), from("203.0.113.7"));
        mode.open_for(1, at(10), from("198.51.100.1"));

        assert_eq!(mode.seconds_left(at(10)), 60);
        assert!(mode
            .check_for(McpSessionCaller::From(from("203.0.113.7")), at(10))
            .is_err());

        mode.open_for(0, at(20), CallerIp::ThisHost);
        assert!(mode.state(at(20)).is_none());
    }
}

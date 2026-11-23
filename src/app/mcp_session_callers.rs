use std::collections::HashMap;

use rust_extensions::date_time::DateTimeAsMicroseconds;

use super::CallerIp;

/// How many sessions are remembered before the ones not seen for [`FORGOTTEN_AFTER`] are let go.
const MAX_SESSIONS: usize = 1024;

/// A session not seen for this long is let go of when the list is full.
const FORGOTTEN_AFTER_MICROSECONDS: i64 = 2 * 60 * 60 * 1_000_000;

/// The longest session id remembered: a longer one is not one the MCP middleware gives.
const MAX_SESSION_ID_LEN: usize = 128;

/// Where the requests of each MCP session come from: a tool runs apart from the request which
/// called it, so a middleware in front of MCP writes down the caller of every request of a session,
/// and the tools which need admin mode look here.
pub struct McpSessionCallers {
    sessions: parking_lot::Mutex<HashMap<String, SessionCaller>>,
}

struct SessionCaller {
    caller: CallerIp,
    /// It has come from another address too.
    mixed: bool,
    seen: i64,
}

/// Where an MCP session comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpSessionCaller {
    /// No request of it has been written down.
    Unknown,
    /// Its requests have come from more than one address.
    Mixed,
    From(CallerIp),
}

impl McpSessionCallers {
    pub fn new() -> Self {
        Self {
            sessions: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// A request of the session `session_id` came from `caller`.
    pub fn note(&self, session_id: &str, caller: CallerIp, now: DateTimeAsMicroseconds) {
        if session_id.is_empty() || session_id.len() > MAX_SESSION_ID_LEN {
            return;
        }

        let mut sessions = self.sessions.lock();

        if let Some(itm) = sessions.get_mut(session_id) {
            if itm.caller != caller {
                itm.mixed = true;
            }
            itm.seen = now.unix_microseconds;
            return;
        }

        if sessions.len() >= MAX_SESSIONS {
            let forgotten_before = now.unix_microseconds - FORGOTTEN_AFTER_MICROSECONDS;
            sessions.retain(|_, itm| itm.seen >= forgotten_before);

            if sessions.len() >= MAX_SESSIONS {
                sessions.clear();
            }
        }

        sessions.insert(
            session_id.to_string(),
            SessionCaller {
                caller,
                mixed: false,
                seen: now.unix_microseconds,
            },
        );
    }

    pub fn get(&self, session_id: &str) -> McpSessionCaller {
        match self.sessions.lock().get(session_id) {
            None => McpSessionCaller::Unknown,
            Some(itm) if itm.mixed => McpSessionCaller::Mixed,
            Some(itm) => McpSessionCaller::From(itm.caller),
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
    fn a_session_is_where_its_requests_come_from() {
        let callers = McpSessionCallers::new();
        assert_eq!(callers.get("a"), McpSessionCaller::Unknown);

        callers.note("a", from("203.0.113.7"), at(0));
        callers.note("a", from("203.0.113.7"), at(1));
        assert_eq!(
            callers.get("a"),
            McpSessionCaller::From(from("203.0.113.7"))
        );

        // Once from another address: never one address again.
        callers.note("a", from("198.51.100.1"), at(2));
        callers.note("a", from("203.0.113.7"), at(3));
        assert_eq!(callers.get("a"), McpSessionCaller::Mixed);
    }

    #[test]
    fn a_full_list_lets_the_old_sessions_go() {
        let callers = McpSessionCallers::new();

        for itm in 0..MAX_SESSIONS {
            callers.note(&format!("old-{itm}"), CallerIp::ThisHost, at(0));
        }

        callers.note("new", CallerIp::ThisHost, at(3 * 60 * 60));

        assert_eq!(callers.get("old-0"), McpSessionCaller::Unknown);
        assert_eq!(
            callers.get("new"),
            McpSessionCaller::From(CallerIp::ThisHost)
        );

        callers.note(
            &"x".repeat(MAX_SESSION_ID_LEN + 1),
            CallerIp::ThisHost,
            at(0),
        );
        assert_eq!(
            callers.get(&"x".repeat(MAX_SESSION_ID_LEN + 1)),
            McpSessionCaller::Unknown
        );
    }
}

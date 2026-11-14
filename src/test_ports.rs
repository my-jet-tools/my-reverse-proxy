//! The ports the tests serve on, and publish configurations for.
//!
//! The tests of this binary share one live configuration - `APP_CTX.current_configuration` - and
//! what a test publishes there for a port stays after the test: nothing takes it away. A port the
//! system hands out again would meet that configuration in another test. Linux picks the port of
//! a `bind` to port 0 at random, so it hands a port out again soon after it is free; macOS counts
//! the ports up, so it does not within a run - which is why a run there never showed it.
//! [`free_port`] never hands out a port twice in a run.

use std::{collections::BTreeSet, sync::Mutex};

static HANDED_OUT: Mutex<BTreeSet<u16>> = Mutex::new(BTreeSet::new());

/// A port nothing listens on now, which no test of this run was handed before.
pub async fn free_port() -> u16 {
    loop {
        let port = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port();

        if HANDED_OUT.lock().unwrap().insert(port) {
            return port;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_port_is_handed_out_once() {
        let mut ports = BTreeSet::new();

        for _ in 0..200 {
            assert!(ports.insert(free_port().await));
        }
    }
}

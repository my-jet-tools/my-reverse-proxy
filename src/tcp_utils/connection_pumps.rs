use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use tokio_util::sync::{CancellationToken, DropGuard};

use crate::types::HttpTimeouts;

/// What the byte pumps of the two directions of one proxied connection share.
///
/// Timeouts: a write gives up after the write timeout. A read gives up only once the whole
/// connection has been idle for the read timeout - neither direction moving bytes: a one-way
/// stream - logs pushed upstream, a file downloaded by a client which sends nothing - keeps one
/// direction silent for good, and is still alive.
///
/// And whether a pump has finished: a pump lingering on its reader after its writer's connection
/// closed knows the other one is done with the tail.
///
/// And whether the connection failed: a pump which failed resets its writer's connection, and
/// the other pump then resets its own and stops - the ends get errors, not a stream which looks
/// whole.
pub struct ConnectionPumps {
    timeouts: HttpTimeouts,
    started: Instant,
    /// When bytes last moved, either way: milliseconds since `started`.
    last_moved: AtomicU64,
    a_pump_finished: CancellationToken,
    failed: CancellationToken,
}

impl ConnectionPumps {
    pub fn new(timeouts: HttpTimeouts) -> Self {
        Self {
            timeouts,
            started: Instant::now(),
            last_moved: AtomicU64::new(0),
            a_pump_finished: CancellationToken::new(),
            failed: CancellationToken::new(),
        }
    }

    pub fn read_timeout(&self) -> Duration {
        self.timeouts.read_timeout
    }

    pub fn write_timeout(&self) -> Duration {
        self.timeouts.write_timeout
    }

    /// Bytes moved, either way.
    pub fn bytes_moved(&self) {
        self.last_moved.fetch_max(self.now(), Ordering::Relaxed);
    }

    /// How long a read may still wait before the connection counts as idle; `None` once it does.
    pub fn read_time_left(&self) -> Option<Duration> {
        let last_moved = self.last_moved.load(Ordering::Relaxed);
        let idle_for = Duration::from_millis(self.now().saturating_sub(last_moved));

        self.timeouts
            .read_timeout
            .checked_sub(idle_for)
            .filter(|time_left| !time_left.is_zero())
    }

    /// Held by a pump while it runs: dropping it - however the pump ends - tells the other pump.
    pub fn running(&self) -> DropGuard {
        self.a_pump_finished.clone().drop_guard()
    }

    /// Resolves once a pump has finished - for a pump which is still running, the other one.
    pub async fn other_pump_finished(&self) {
        self.a_pump_finished.cancelled().await;
    }

    /// The connection failed: both ends are to be reset.
    pub fn fail(&self) {
        self.failed.cancel();
    }

    /// Resolves once the connection failed - see [`Self::fail`].
    pub async fn failed(&self) {
        self.failed.cancelled().await;
    }

    pub fn is_failed(&self) -> bool {
        self.failed.is_cancelled()
    }

    fn now(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }
}

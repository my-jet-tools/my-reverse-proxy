use rust_extensions::{MyTimerTick, RepeatTimerIteration};

use crate::app::APP_CTX;

pub struct TrafficTimer;

#[async_trait::async_trait]
impl MyTimerTick for TrafficTimer {
    async fn tick(&self) -> RepeatTimerIteration {
        let snapshot = APP_CTX.traffic.snapshot_and_reset();
        for (domain, stats) in snapshot {
            APP_CTX.prometheus.set_traffic(&domain, &stats);
        }

        RepeatTimerIteration::WithInterval
    }
}

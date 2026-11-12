use std::time::Duration;

use crate::app::APP_CTX;

/// Reads `dynamic_hosts.url` every `refresh_interval`, and right away when a reload of the
/// settings asks for it. Not a `MyTimer`: the interval is of the settings, which a reload can
/// change, and a reload can not wait for the tick of the interval before it.
pub async fn dynamic_hosts_timer() {
    // Nothing to wait for but a request until the settings are applied.
    let mut interval: Option<Duration> = None;

    loop {
        match interval {
            Some(interval) => {
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    _ = APP_CTX.dynamic_hosts.wait_for_refresh_request() => {}
                }
            }
            None => APP_CTX.dynamic_hosts.wait_for_refresh_request().await,
        }

        if APP_CTX.states.is_shutting_down() {
            return;
        }

        interval = crate::flows::refresh_dynamic_hosts().await;
    }
}

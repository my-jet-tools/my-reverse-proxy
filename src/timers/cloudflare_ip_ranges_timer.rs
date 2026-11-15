use std::time::Duration;

use rust_extensions::{MyTimerTick, RepeatTimerIteration};

/// Reads the networks of Cloudflare again - registered on the hourly timer.
pub struct CloudflareIpRangesTimer;

#[async_trait::async_trait]
impl MyTimerTick for CloudflareIpRangesTimer {
    async fn tick(&self) -> RepeatTimerIteration {
        if let Err(err) = crate::scripts::refresh_cloudflare_ip_ranges().await {
            println!("Cloudflare IP ranges: {err}. The networks read before stay");
        }

        RepeatTimerIteration::WithInterval
    }
}

const FIRST_RETRY: Duration = Duration::from_secs(5);
const MAX_RETRY: Duration = Duration::from_secs(300);

/// The first read of the networks of Cloudflare, right at startup. Until it succeeds every
/// `cloudflare: true` endpoint closes every connection, so a failed read is tried again soon -
/// sooner first, then up to every [`MAX_RETRY`] - until one succeeds; from then on the hourly
/// timer keeps them fresh.
pub async fn load_cloudflare_ip_ranges_on_start() {
    let mut retry_in = FIRST_RETRY;

    loop {
        match crate::scripts::refresh_cloudflare_ip_ranges().await {
            Ok(count) => {
                println!("Cloudflare IP ranges: {count} networks are read");
                return;
            }
            Err(err) => {
                println!(
                    "Cloudflare IP ranges: {err}. Tried again in {} s - until then every \
                     'cloudflare: true' endpoint closes every connection",
                    retry_in.as_secs()
                );
            }
        }

        if crate::app::APP_CTX.cloudflare_ip_ranges.is_loaded() {
            // The hourly timer got there first.
            return;
        }

        tokio::time::sleep(retry_in).await;
        retry_in = (retry_in * 2).min(MAX_RETRY);

        if crate::app::APP_CTX.states.is_shutting_down()
            || crate::app::APP_CTX.cloudflare_ip_ranges.is_loaded()
        {
            return;
        }
    }
}

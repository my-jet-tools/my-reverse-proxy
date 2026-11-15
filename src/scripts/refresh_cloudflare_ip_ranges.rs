use std::time::Duration;

use flurl::FlUrl;

use crate::cloudflare::{
    parse_cloudflare_ips_response, CLOUDFLARE_IPS_URL, MAX_CLOUDFLARE_IPS_RESPONSE_SIZE,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Reads the networks of Cloudflare and makes them the ones a `cloudflare: true` endpoint takes
/// connections from. On any failure the networks read before stay. Returns how many were read.
pub async fn refresh_cloudflare_ip_ranges() -> Result<usize, String> {
    let mut response = FlUrl::new(CLOUDFLARE_IPS_URL)
        .set_timeout(REQUEST_TIMEOUT)
        .get()
        .await
        .map_err(|err| format!("the request to {CLOUDFLARE_IPS_URL} failed: {err}"))?;

    let status_code = response.get_status_code();

    if status_code != 200 {
        return Err(format!(
            "{CLOUDFLARE_IPS_URL} answered with the status code {status_code}"
        ));
    }

    let body = response
        .get_body()
        .map_err(|err| format!("the answer of {CLOUDFLARE_IPS_URL} can not be read: {err}"))?
        .into_vec(MAX_CLOUDFLARE_IPS_RESPONSE_SIZE)
        .await
        .map_err(|err| format!("the answer of {CLOUDFLARE_IPS_URL} can not be read: {err}"))?;

    let networks = parse_cloudflare_ips_response(&body)
        .map_err(|err| format!("{CLOUDFLARE_IPS_URL}: {err}"))?;

    let count = networks.len();
    crate::app::APP_CTX.cloudflare_ip_ranges.replace(networks);

    Ok(count)
}

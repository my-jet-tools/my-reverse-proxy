mod client_certificates;
pub use client_certificates::*;
mod configuration;
pub use configuration::*;
mod logs;
pub use logs::*;
mod ssl_certificates;
pub use ssl_certificates::*;

/// reqwest's wasm backend rejects relative paths ("builder error" from `Url::parse`), so every
/// request is anchored against the page origin. The SPA is always served by the same http server
/// as the admin API, so the origin is the right base.
fn build_url(path_and_query: &str) -> Result<String, String> {
    let origin = web_sys::window()
        .ok_or_else(|| "no window in current context".to_string())?
        .location()
        .origin()
        .map_err(|e| format!("could not read window.location.origin: {e:?}"))?;
    Ok(format!("{origin}{path_and_query}"))
}

/// POSTs `request` as json to an admin-api path and decodes the json answer.
///
/// The proxy reports a refused upload as `text/plain` with a `Validation error: ` prefix — that
/// text is the operator-facing explanation of what was wrong with the pasted material, so it is
/// unwrapped and returned as-is instead of being flattened into a status code.
pub(crate) async fn post_json<TRequest: serde::Serialize, TResponse: serde::de::DeserializeOwned>(
    path: &str,
    request: &TRequest,
) -> Result<TResponse, String> {
    let url = build_url(path)?;

    let resp = reqwest::Client::new()
        .post(&url)
        .json(request)
        .send()
        .await
        .map_err(|e| format!("POST {url} failed: {e}"))?;

    let status = resp.status();

    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();

        let message = body
            .trim()
            .trim_start_matches("Validation error:")
            .trim()
            .to_string();

        return Err(if message.is_empty() {
            format!("POST {url} returned {status}")
        } else {
            message
        });
    }

    resp.json::<TResponse>()
        .await
        .map_err(|e| format!("decoding {url} response failed: {e}"))
}

/// PEM material travels through json base64-encoded so its line breaks survive untouched.
pub(crate) fn to_base64(pem: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(pem.as_bytes())
}

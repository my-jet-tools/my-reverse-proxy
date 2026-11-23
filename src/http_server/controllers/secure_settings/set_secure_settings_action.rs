use my_http_server::{macros::http_route, HttpContext, HttpFailResult, HttpOkResult, HttpOutput};
use serde::Serialize;

use super::{key_of_encrypted_request, store_refusal, EncryptedYamlHttpInput};

#[http_route(
    method: "POST",
    route: "/api/secure-settings/v1/set",
    summary: "Set the secure settings document",
    description: "Encrypted with a network key (Content-Encoding: aes128gcm), and answered encrypted with the same key. The body is the whole secure settings document: YAML of the schema of the settings file - `hosts:` with their endpoints and locations, `variables:`, `ip_white_lists:`, ... - which replaces the one there was; a blank one (a line break) removes it. It is merged with the settings files like the dynamic settings file, after it: a host it has replaces a host of the files with the same id. The settings are compiled with it first - a document which is not settings YAML, or with which they do not compile, is refused and nothing is kept - then it is kept in the secure store. Like the dynamic settings file, it is applied by a reload - the MCP tool reload_settings, in admin mode - and when the store opens at initialize. The answer is `{\"bytes_kept\"}`.",
    controller: "SecureSettings",
    input_data: EncryptedYamlHttpInput,
    result:[
        {status_code: 200, description: "Kept: `{\"bytes_kept\"}`, encrypted"},
        {status_code: 400, description: "The body opens with no key, is not UTF-8, is not settings YAML, or the settings do not compile with it"},
        {status_code: 415, description: "The body did not come encrypted - or the proxy has no network keys yet"},
        {status_code: 503, description: "The proxy is not initialized"},
        {status_code: 500, description: "The secure store can not be written"},
    ]
)]
pub struct SetSecureSettingsAction;

async fn handle_request(
    _action: &SetSecureSettingsAction,
    input_data: EncryptedYamlHttpInput,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = key_of_encrypted_request(ctx)?;

    let content = String::from_utf8(input_data.body).map_err(|_| {
        HttpFailResult::as_validation_error("The secure settings are not UTF-8 text".to_string())
    })?;

    let bytes_kept = content.len();

    crate::scripts::set_secure_settings(content)
        .await
        .map_err(store_refusal)?;

    println!(
        "Secure store: the secure settings are set over the encrypted API - a reload applies them"
    );

    HttpOutput::as_json(SecureSettingsKeptHttpModel { bytes_kept })
        .encode(&key)
        .into_ok_result(false)
}

#[derive(Serialize)]
struct SecureSettingsKeptHttpModel {
    bytes_kept: usize,
}

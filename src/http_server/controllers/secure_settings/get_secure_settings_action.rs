use my_http_server::{macros::http_route, HttpContext, HttpFailResult, HttpOkResult, HttpOutput};

use crate::{http_server::controllers::EncryptedJsonHttpInput, secure::SecureStoreError};

use super::{key_of_encrypted_request, store_refusal};

#[http_route(
    method: "POST",
    route: "/api/secure-settings/v1/get",
    summary: "The secure settings document",
    description: "Encrypted with a network key (Content-Encoding: aes128gcm), and answered encrypted with the same key. The body is any JSON - `{}` - since an empty body carries no encryption. The answer is the secure settings document as it was set, YAML text - nothing when there is none. Read it, change it, and give the whole of it back to `/api/secure-settings/v1/set`: that one replaces the document.",
    controller: "SecureSettings",
    input_data: EncryptedJsonHttpInput,
    result:[
        {status_code: 200, description: "The document, encrypted"},
        {status_code: 400, description: "The body opens with no key"},
        {status_code: 415, description: "The body did not come encrypted - or the proxy has no network keys yet"},
        {status_code: 503, description: "The proxy is not initialized"},
    ]
)]
pub struct GetSecureSettingsAction;

async fn handle_request(
    _action: &GetSecureSettingsAction,
    _input_data: EncryptedJsonHttpInput,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = key_of_encrypted_request(ctx)?;

    if !crate::app::APP_CTX.secure.is_initialized() {
        return Err(store_refusal(SecureStoreError::NotInitialized));
    }

    let content = crate::app::APP_CTX
        .secure
        .secure_settings()
        .unwrap_or_default();

    HttpOutput::as_text(content)
        .encode(&key)
        .into_ok_result(false)
}

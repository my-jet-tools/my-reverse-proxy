use crate::{app::APP_CTX, secure::SecureStoreError, settings_compiled::SettingsCompiled};

/// Keeps `content` as the secure settings document, as `set_dynamic_settings` writes the dynamic
/// settings file: a reload applies it. A document which is not settings YAML, or with which the
/// settings do not compile, is refused, and nothing is kept. A blank one removes the document.
pub async fn set_secure_settings(content: String) -> Result<(), SecureStoreError> {
    if !APP_CTX.secure.is_initialized() {
        return Err(SecureStoreError::NotInitialized);
    }

    // What the settings compile to with the document, before it is kept.
    SettingsCompiled::load_settings_with_secure(Some(content.as_str()))
        .await
        .map_err(SecureStoreError::Invalid)?;

    APP_CTX.secure.set_secure_settings(content).await
}

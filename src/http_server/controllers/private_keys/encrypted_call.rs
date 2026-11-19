use my_http_server::{macros::MyHttpInput, BodyEncryptionKey, HttpContext, HttpFailResult};

use crate::secure::SecureStoreError;

/// The body of a call of the encrypted API: my-http-server has decrypted it before the action
/// runs, and the action gets the JSON.
#[derive(MyHttpInput)]
pub struct EncryptedJsonHttpInput {
    #[http_body_raw(
        description = "JSON, encrypted with a network key (Content-Encoding: aes128gcm): FlUrl's encrypted(&key), or bin/encrypted_call"
    )]
    pub body: Vec<u8>,
}

/// The key the request came encrypted with - what the answer is encrypted with. Only an encrypted
/// request reads or changes the private keys: a plain one, or an empty one, which carries no
/// encryption, is refused with `415`.
pub fn key_of_encrypted_request(ctx: &HttpContext) -> Result<BodyEncryptionKey, HttpFailResult> {
    ctx.request
        .get_encryption_info()
        .map(|info| info.key.clone())
        .ok_or_else(|| {
            HttpFailResult::from((
                415u16,
                "The body has to come encrypted with a network key (Content-Encoding: aes128gcm): FlUrl's encrypted(&key), or bin/encrypted_call".to_string(),
            ))
        })
}

/// The JSON of a call, or why it is refused - without a word of what it holds: serde quotes a
/// value of the wrong type, and a value here may be a private key. Only a field missing or
/// unknown, which names nothing but the field, is told as serde tells it.
pub fn parse_call<T: serde::de::DeserializeOwned>(
    body: &[u8],
    expected: &str,
) -> Result<T, HttpFailResult> {
    serde_json::from_slice(body).map_err(|err| {
        let text = err.to_string();

        let reason = if text.starts_with("missing field") || text.starts_with("unknown field") {
            format!("The body is not {expected}: {text}")
        } else if err.classify() == serde_json::error::Category::Data {
            format!(
                "The body is not {expected}: a value is of another type, at line {} column {}",
                err.line(),
                err.column()
            )
        } else {
            format!(
                "The body is not JSON: at line {} column {}",
                err.line(),
                err.column()
            )
        };

        HttpFailResult::as_validation_error(reason)
    })
}

pub fn store_refusal(err: SecureStoreError) -> HttpFailResult {
    match err {
        SecureStoreError::NotInitialized => HttpFailResult::from((
            503u16,
            "The proxy is not initialized: POST /api/initialize first".to_string(),
        )),
        SecureStoreError::Failed(reason) => HttpFailResult::as_fatal_error(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct Call {
        id: String,
        private_key: String,
    }

    /// A private key put where another type is expected is not quoted back.
    #[test]
    fn a_refused_call_is_not_quoted() {
        let secret = "-----BEGIN OPENSSH PRIVATE KEY-----secret";

        for body in [
            format!(r#"{{"id": ["{secret}"], "private_key": "x"}}"#),
            format!(r#"{{"id": "x", "private_key": 5, "other": "{secret}"}}"#),
            format!(r#"{{"id": "x", "private_key": "{secret}""#),
        ] {
            let refused = parse_call::<Call>(body.as_bytes(), "{...}").unwrap_err();
            let text = format!("{:?}", refused.output);
            assert!(!text.contains("secret"), "{text}");
        }
    }
}

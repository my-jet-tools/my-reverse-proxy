use std::sync::Arc;

use ed25519_dalek::SigningKey;

/// Where a gateway client takes the key it signs its handshake with.
#[derive(Clone)]
pub enum GatewaySigningKey {
    /// The key itself: read at startup from the file of the `ssh:` entry `ssh_credentials` of the
    /// client names.
    Key(Arc<SigningKey>),
    /// A private key of the proxy's secure store, by its id - `private_key:` of the client. It is
    /// taken at every connect: a key installed, or replaced, over the encrypted API is used by the
    /// next connect, and while the store does not have it the client does not connect.
    Stored {
        id: String,
        keys: Arc<crate::secure::PrivateKeys>,
    },
}

impl GatewaySigningKey {
    /// The key to sign this connect's handshake with - `None` while the store does not have it.
    pub fn resolve(&self) -> Option<Arc<SigningKey>> {
        match self {
            Self::Key(key) => Some(key.clone()),
            Self::Stored { id, keys } => keys.get(id),
        }
    }

    /// What the log says the client waits for, when [`Self::resolve`] gives nothing.
    pub fn describe_missing(&self) -> String {
        match self {
            Self::Key(_) => "its private key".to_string(),
            Self::Stored { id, .. } => format!(
                "private key '{id}' of the secure store: POST /api/initialize, then install it with POST /api/private-keys/v1/set"
            ),
        }
    }
}

impl From<SigningKey> for GatewaySigningKey {
    fn from(key: SigningKey) -> Self {
        Self::Key(Arc::new(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client which names a key of the store connects once the store has it, and with the key
    /// the store has at that moment.
    #[tokio::test]
    async fn a_stored_key_is_taken_when_the_store_has_it() {
        let state = crate::secure::SecureState::new();

        let signing = GatewaySigningKey::Stored {
            id: "london".to_string(),
            keys: state.private_keys.clone(),
        };

        assert!(signing.resolve().is_none());
        assert!(signing.describe_missing().contains("private key 'london'"));

        let path = std::env::temp_dir()
            .join(format!(
                "my-reverse-proxy-gateway-key-{}",
                std::process::id()
            ))
            .to_str()
            .unwrap()
            .to_string();
        let _ = std::fs::remove_file(&path);

        let files_key =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [1u8; 32]);
        state.initialize(&path, &files_key, None).await.unwrap();

        state
            .set_private_key("london", SigningKey::from_bytes(&[7; 32]))
            .await
            .unwrap();
        assert_eq!(signing.resolve().unwrap().to_bytes(), [7; 32]);

        // Replaced: the next connect signs with the new one.
        state
            .set_private_key("london", SigningKey::from_bytes(&[8; 32]))
            .await
            .unwrap();
        assert_eq!(signing.resolve().unwrap().to_bytes(), [8; 32]);

        assert!(state.delete_private_key("london").await.unwrap());
        assert!(signing.resolve().is_none());

        std::fs::remove_file(&path).unwrap();
    }
}

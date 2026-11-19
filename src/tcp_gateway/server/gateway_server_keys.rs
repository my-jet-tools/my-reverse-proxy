use std::sync::Arc;

use ed25519_dalek::VerifyingKey;

use crate::secure::AuthorizedKeys;

/// Who the gateway server lets in: the keys of its `authorized_keys` files, read at startup, and
/// the keys the secure store authorizes - as the store has them when a handshake starts, so a key
/// set or removed over the encrypted API or MCP counts from the next handshake on.
pub struct GatewayServerKeys {
    files: Vec<VerifyingKey>,
    stored: Option<Arc<AuthorizedKeys>>,
}

impl GatewayServerKeys {
    pub fn new(files: Vec<VerifyingKey>, stored: Arc<AuthorizedKeys>) -> Self {
        Self {
            files,
            stored: Some(stored),
        }
    }

    /// The keys a handshake starting now is checked against.
    pub fn current(&self) -> Vec<VerifyingKey> {
        let mut result = self.files.clone();

        if let Some(stored) = self.stored.as_ref() {
            result.extend(stored.list().iter().map(|(_, key)| *key));
        }

        result
    }
}

/// The keys of the files alone.
impl From<Vec<VerifyingKey>> for GatewayServerKeys {
    fn from(files: Vec<VerifyingKey>) -> Self {
        Self {
            files,
            stored: None,
        }
    }
}

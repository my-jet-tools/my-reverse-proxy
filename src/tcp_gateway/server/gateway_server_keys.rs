use std::sync::Arc;

use ed25519_dalek::VerifyingKey;

use crate::secure::AuthorizedKeys;
use crate::tcp_gateway::handshake::{AuthorizedClientKey, ClientKeyBinding};

/// Who the gateway server lets in: the keys of its `authorized_keys` files, read at startup -
/// under any gateway name - and the keys the secure store authorizes, each under its own name and
/// from its white list only, as the store has them when a handshake starts: a key set or removed
/// over the encrypted API or MCP counts from the next handshake on.
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
    pub fn current(&self) -> Vec<AuthorizedClientKey> {
        let mut result: Vec<AuthorizedClientKey> = self
            .files
            .iter()
            .map(|key| AuthorizedClientKey::unbound(*key))
            .collect();

        if let Some(stored) = self.stored.as_ref() {
            result.extend(stored.list().iter().map(|itm| AuthorizedClientKey {
                key: itm.key,
                binding: Some(ClientKeyBinding {
                    gateway_name: itm.id.clone(),
                    ip_white_list: itm.allowed_ip.clone(),
                }),
            }));
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

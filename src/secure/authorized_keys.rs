use std::sync::Arc;

use arc_swap::ArcSwap;
use ed25519_dalek::VerifyingKey;

/// The public keys of the secure store the gateway server of this proxy lets in, besides those of
/// its `authorized_keys` files, by their ids. They are set over the encrypted API of the control
/// port (`/api/gateway-authorized-keys/v1/...`) or over MCP in its admin mode, kept in the store,
/// and here from initialize on: every handshake looks at them as they are then.
pub struct AuthorizedKeys {
    keys: ArcSwap<Vec<(String, VerifyingKey)>>,
}

impl AuthorizedKeys {
    pub fn new() -> Self {
        Self {
            keys: ArcSwap::from_pointee(Vec::new()),
        }
    }

    /// Every key, by its id in order.
    pub fn list(&self) -> Arc<Vec<(String, VerifyingKey)>> {
        self.keys.load_full()
    }

    pub(super) fn set_all(&self, mut keys: Vec<(String, VerifyingKey)>) {
        keys.sort_by(|a, b| a.0.cmp(&b.0));
        self.keys.store(Arc::new(keys));
    }
}

/// An OpenSSH public key of Ed25519: a line of an `authorized_keys` file,
/// `ssh-ed25519 AAAA... comment` - what `get_public_key`, `generate` and the `.pub` file of
/// `gateway_keygen` give.
pub fn parse_openssh_ed25519_public(text: &str) -> Result<VerifyingKey, String> {
    let public = ssh_key::PublicKey::from_openssh(text.trim())
        .map_err(|err| format!("public_key is not an OpenSSH public key: {err}"))?;

    let ed25519 = public
        .key_data()
        .ed25519()
        .ok_or_else(|| "public_key is not an Ed25519 key, which the gateway takes".to_string())?;

    VerifyingKey::from_bytes(&ed25519.0)
        .map_err(|err| format!("public_key is not a valid Ed25519 key: {err}"))
}

/// `key` as a line of an `authorized_keys` file: `ssh-ed25519 AAAA...`.
pub fn openssh_verifying_key(key: &VerifyingKey) -> String {
    let public = ssh_key::PublicKey::from(ssh_key::public::KeyData::Ed25519(
        ssh_key::public::Ed25519PublicKey(key.to_bytes()),
    ));

    public
        .to_openssh()
        .expect("an Ed25519 public key is always written in OpenSSH form")
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    #[test]
    fn a_public_key_line_reads_back_with_or_without_a_comment() {
        let key = SigningKey::from_bytes(&[5; 32]).verifying_key();
        let line = openssh_verifying_key(&key);

        assert_eq!(parse_openssh_ed25519_public(&line).unwrap(), key);
        assert_eq!(
            parse_openssh_ed25519_public(&format!("  {line} gateway-london\n")).unwrap(),
            key
        );
    }

    #[test]
    fn what_is_not_an_ed25519_public_key_is_refused() {
        for text in ["", "ssh-ed25519", "ssh-ed25519 AAAA", "not a key"] {
            let err = parse_openssh_ed25519_public(text).unwrap_err();
            assert!(err.contains("public_key"), "{err}");
        }
    }

    #[test]
    fn the_keys_are_given_by_their_ids_in_order() {
        let keys = AuthorizedKeys::new();
        assert!(keys.list().is_empty());

        keys.set_all(vec![
            (
                "paris".to_string(),
                SigningKey::from_bytes(&[1; 32]).verifying_key(),
            ),
            (
                "berlin".to_string(),
                SigningKey::from_bytes(&[2; 32]).verifying_key(),
            ),
        ]);

        let list = keys.list();
        let ids: Vec<&str> = list.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, ["berlin", "paris"]);
    }
}

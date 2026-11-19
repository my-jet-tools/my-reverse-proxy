use std::{collections::HashMap, sync::Arc};

use arc_swap::ArcSwap;
use ed25519_dalek::SigningKey;
use rand_core::RngCore;
use ssh_key::{private::Ed25519Keypair, PrivateKey};
use zeroize::Zeroizing;

/// The private keys of the secure store, by their ids: what a gateway client which names one with
/// `private_key:` signs its handshake with. They are installed or generated over the encrypted
/// API of the control port (`/api/private-keys/v1/...`) - generated over MCP too, in its admin
/// mode - kept in the store, and here from initialize on.
pub struct PrivateKeys {
    keys: ArcSwap<HashMap<String, Arc<SigningKey>>>,
}

impl PrivateKeys {
    pub fn new() -> Self {
        Self {
            keys: ArcSwap::from_pointee(HashMap::new()),
        }
    }

    pub fn get(&self, id: &str) -> Option<Arc<SigningKey>> {
        self.keys.load().get(id).cloned()
    }

    /// Every key, by its id in order.
    pub fn list(&self) -> Vec<(String, Arc<SigningKey>)> {
        let mut result: Vec<_> = self
            .keys
            .load()
            .iter()
            .map(|(id, key)| (id.clone(), key.clone()))
            .collect();
        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    }

    pub(super) fn set_all(&self, keys: HashMap<String, Arc<SigningKey>>) {
        self.keys.store(Arc::new(keys));
    }
}

/// The id of a private key: what `private_key:` of a gateway client names. Up to 64 characters,
/// with no control characters, and not empty; whitespace around it is not part of it.
pub fn check_private_key_id(id: &str) -> Result<&str, String> {
    let id = id.trim();

    if id.is_empty() {
        return Err("id is empty".to_string());
    }

    if id.chars().count() > 64 {
        return Err("id is longer than 64 characters".to_string());
    }

    if id.chars().any(char::is_control) {
        return Err("id has a control character in it".to_string());
    }

    Ok(id)
}

/// An OpenSSH private key of Ed25519 - what `gateway_keygen` writes. One encrypted with a
/// passphrase is opened with `passphrase`. The error never repeats the key.
pub fn parse_openssh_ed25519(text: &str, passphrase: Option<&str>) -> Result<SigningKey, String> {
    // The OpenSSH parser is strict about the end of the block: a trailing line break left by an
    // editor or a copy and paste fails it.
    let private = PrivateKey::from_openssh(text.trim())
        .map_err(|err| format!("private_key is not an OpenSSH private key: {err}"))?;

    let private = if private.is_encrypted() {
        let passphrase = passphrase
            .ok_or_else(|| "private_key is encrypted, and no passphrase is given".to_string())?;

        private
            .decrypt(passphrase.as_bytes())
            .map_err(|_| "passphrase does not open private_key".to_string())?
    } else {
        private
    };

    let keypair: &Ed25519Keypair = private
        .key_data()
        .ed25519()
        .ok_or_else(|| "private_key is not an Ed25519 key, which the gateway takes".to_string())?;

    Ok(SigningKey::from_bytes(&keypair.private.to_bytes()))
}

/// The public half of `key` as a line of an `authorized_keys` file of a gateway server:
/// `ssh-ed25519 AAAA...`.
pub fn openssh_public_key(key: &SigningKey) -> String {
    super::openssh_verifying_key(&key.verifying_key())
}

/// A new Ed25519 key, out of the random source of the operating system.
pub fn generate_signing_key() -> SigningKey {
    let mut seed = Zeroizing::new([0u8; 32]);
    rand_core::OsRng.fill_bytes(&mut *seed);
    SigningKey::from_bytes(&seed)
}

/// `key` as an OpenSSH private key: what `gateway_keygen` writes, and what
/// `POST /api/private-keys/v1/set` of another proxy installs. It is not encrypted with a
/// passphrase: it is only given in an answer encrypted with a network key.
pub fn openssh_private_key(key: &SigningKey, comment: &str) -> Zeroizing<String> {
    let private_bytes = Zeroizing::new(key.to_bytes());

    let keypair = Ed25519Keypair {
        public: ssh_key::public::Ed25519PublicKey(key.verifying_key().to_bytes()),
        private: ssh_key::private::Ed25519PrivateKey::from_bytes(&private_bytes),
    };

    PrivateKey::new(keypair.into(), comment)
        .expect("an Ed25519 key pair is always an OpenSSH private key")
        .to_openssh(ssh_key::LineEnding::LF)
        .expect("an Ed25519 private key is always written in OpenSSH form")
}

#[cfg(test)]
pub fn openssh_private_key_for_tests(seed: u8, passphrase: Option<&str>) -> String {
    let signing = SigningKey::from_bytes(&[seed; 32]);

    let Some(passphrase) = passphrase else {
        return openssh_private_key(&signing, "test").to_string();
    };

    PrivateKey::from_openssh(openssh_private_key(&signing, "test").as_str())
        .unwrap()
        .encrypt(&mut rand_core::OsRng, passphrase.as_bytes())
        .unwrap()
        .to_openssh(ssh_key::LineEnding::LF)
        .unwrap()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_openssh_ed25519_key_is_read_with_or_without_a_passphrase() {
        let expected = SigningKey::from_bytes(&[3; 32]);

        let plain = openssh_private_key_for_tests(3, None);
        let key = parse_openssh_ed25519(&format!("{plain}\n\n"), None).unwrap();
        assert_eq!(key.to_bytes(), expected.to_bytes());

        let encrypted = openssh_private_key_for_tests(3, Some("phrase"));
        let key = parse_openssh_ed25519(&encrypted, Some("phrase")).unwrap();
        assert_eq!(key.to_bytes(), expected.to_bytes());

        let err = parse_openssh_ed25519(&encrypted, None).unwrap_err();
        assert!(err.contains("no passphrase"), "{err}");

        let err = parse_openssh_ed25519(&encrypted, Some("wrong")).unwrap_err();
        assert!(err.contains("does not open"), "{err}");
    }

    #[test]
    fn what_is_not_an_openssh_key_is_refused_without_being_repeated() {
        for text in [
            "",
            "not a key",
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
        ] {
            let err = parse_openssh_ed25519(text, None).unwrap_err();
            assert!(err.contains("not an OpenSSH private key"), "{err}");
            assert!(text.is_empty() || !err.contains(text), "{err}");
        }
    }

    #[test]
    fn the_public_key_is_a_line_of_authorized_keys() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let line = openssh_public_key(&key);

        assert!(line.starts_with("ssh-ed25519 "), "{line}");

        // The gateway server reads its authorized_keys files the same way.
        let public = ssh_key::PublicKey::from_openssh(&line).unwrap();
        assert_eq!(
            public.key_data().ed25519().unwrap().0,
            key.verifying_key().to_bytes()
        );
    }

    /// What is given for download opens as the key it is, as `set` of another proxy reads it.
    #[test]
    fn a_key_given_as_openssh_text_reads_back_as_the_same_key() {
        let key = generate_signing_key();
        let text = openssh_private_key(&key, "my-reverse-proxy london");

        assert!(text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));

        let read = parse_openssh_ed25519(&text, None).unwrap();
        assert_eq!(read.to_bytes(), key.to_bytes());
    }

    #[test]
    fn every_generated_key_is_another() {
        assert_ne!(
            generate_signing_key().to_bytes(),
            generate_signing_key().to_bytes()
        );
    }

    #[test]
    fn an_id_is_short_and_printable() {
        assert_eq!(check_private_key_id(" london \n"), Ok("london"));
        assert!(check_private_key_id("").is_err());
        assert!(check_private_key_id("   ").is_err());
        assert!(check_private_key_id(&"a".repeat(65)).is_err());
        assert!(check_private_key_id("lon\u{0}don").is_err());
    }

    #[test]
    fn the_keys_are_given_by_their_ids() {
        let keys = PrivateKeys::new();
        assert!(keys.get("london").is_none());

        keys.set_all(HashMap::from([
            (
                "london".to_string(),
                Arc::new(SigningKey::from_bytes(&[1; 32])),
            ),
            (
                "berlin".to_string(),
                Arc::new(SigningKey::from_bytes(&[2; 32])),
            ),
        ]));

        assert_eq!(keys.get("london").unwrap().to_bytes(), [1; 32]);
        let ids: Vec<String> = keys.list().into_iter().map(|(id, _)| id).collect();
        assert_eq!(ids, ["berlin", "london"]);
    }
}

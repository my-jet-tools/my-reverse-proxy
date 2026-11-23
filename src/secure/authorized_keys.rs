use std::sync::Arc;

use arc_swap::ArcSwap;
use ed25519_dalek::VerifyingKey;

use crate::types::{check_ip_white_list_entry, WhiteListedIpList};

/// The public keys of the secure store the gateway server of this proxy lets in, besides those of
/// its `authorized_keys` files, by their ids. They are set over the encrypted API of the control
/// port (`/api/gateway-authorized-keys/v1/...`) or over MCP in its admin mode, kept in the store,
/// and here from initialize on: every handshake looks at them as they are then.
pub struct AuthorizedKeys {
    keys: ArcSwap<Vec<AuthorizedKey>>,
}

/// A key the gateway server lets in: under one gateway name, from the addresses of its white list.
#[derive(Clone)]
pub struct AuthorizedKey {
    /// The gateway name a client which signs with the key comes in under - the id of its
    /// `gateway_clients` entry or of its connection.
    pub id: String,
    pub key: VerifyingKey,
    /// As it was set: what the API gives back.
    pub ip_white_list: Vec<String>,
    /// The same, as a handshake checks it.
    pub allowed_ip: Arc<WhiteListedIpList>,
}

impl AuthorizedKey {
    pub fn new(id: String, key: VerifyingKey, ip_white_list: Vec<String>) -> Self {
        Self {
            allowed_ip: Arc::new(WhiteListedIpList::new(&ip_white_list)),
            id,
            key,
            ip_white_list,
        }
    }
}

impl AuthorizedKeys {
    pub fn new() -> Self {
        Self {
            keys: ArcSwap::from_pointee(Vec::new()),
        }
    }

    /// Every key, by its id in order.
    pub fn list(&self) -> Arc<Vec<AuthorizedKey>> {
        self.keys.load_full()
    }

    pub(super) fn set_all(&self, mut keys: Vec<AuthorizedKey>) {
        keys.sort_by(|a, b| a.id.cmp(&b.id));
        self.keys.store(Arc::new(keys));
    }
}

/// The white list of an authorized key: at least one entry, each one of `ip_white_lists` - an IPv4
/// address, a `from-to` range, a subnet (`10.0.0.0/24`) or `*` for every address. Whitespace
/// around an entry is not part of it.
pub fn check_key_ip_white_list(list: &[String]) -> Result<Vec<String>, String> {
    if list.is_empty() {
        return Err(
            "ip_white_list is empty: name the addresses the key connects from, or `*` for any"
                .to_string(),
        );
    }

    list.iter()
        .map(|entry| {
            let entry = entry.trim();
            check_ip_white_list_entry(entry).map_err(|err| format!("ip_white_list: {err}"))?;
            Ok(entry.to_string())
        })
        .collect()
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
            AuthorizedKey::new(
                "paris".to_string(),
                SigningKey::from_bytes(&[1; 32]).verifying_key(),
                vec!["10.0.0.1".to_string()],
            ),
            AuthorizedKey::new(
                "berlin".to_string(),
                SigningKey::from_bytes(&[2; 32]).verifying_key(),
                vec!["*".to_string()],
            ),
        ]);

        let list = keys.list();
        let ids: Vec<&str> = list.iter().map(|itm| itm.id.as_str()).collect();
        assert_eq!(ids, ["berlin", "paris"]);
        assert!(list[1].allowed_ip.is_whitelisted(&"10.0.0.1"));
        assert!(!list[1].allowed_ip.is_whitelisted(&"10.0.0.2"));
    }

    #[test]
    fn a_white_list_has_entries_and_every_one_of_them_works() {
        assert_eq!(
            check_key_ip_white_list(&[
                " 10.0.0.1 ".to_string(),
                "10.0.1.0/24".to_string(),
                "10.0.2.1-10.0.2.9".to_string(),
                "*".to_string(),
            ]),
            Ok(vec![
                "10.0.0.1".to_string(),
                "10.0.1.0/24".to_string(),
                "10.0.2.1-10.0.2.9".to_string(),
                "*".to_string(),
            ])
        );

        let err = check_key_ip_white_list(&[]).unwrap_err();
        assert!(err.contains("empty"), "{err}");

        for entry in ["", "10.0.0", "office", "10.0.0.0/33"] {
            let err = check_key_ip_white_list(&[entry.to_string()]).unwrap_err();
            assert!(err.starts_with("ip_white_list"), "{entry}: {err}");
        }
    }
}

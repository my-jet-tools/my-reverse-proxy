use std::sync::Arc;

use base64::Engine;
use my_http_server::{BodyEncryptionKey, BodyEncryptionKeys, AES128GCM_CONTENT_ENCODING};
use zeroize::Zeroizing;

/// A files key or a network key: 32 random bytes.
pub const SECURE_KEY_LEN: usize = 32;

pub type SecureKey = Zeroizing<[u8; SECURE_KEY_LEN]>;

/// `text` as a key: 32 bytes in standard base64. Whitespace around it is not part of it - a key
/// pasted from a password manager often ends with a line break.
pub fn parse_secure_key(text: &str, name: &str) -> Result<SecureKey, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .map(Zeroizing::new)
        .map_err(|_| not_a_key(name))?;

    if bytes.len() != SECURE_KEY_LEN {
        return Err(not_a_key(name));
    }

    let mut key = Zeroizing::new([0u8; SECURE_KEY_LEN]);
    key.copy_from_slice(&bytes);

    Ok(key)
}

fn not_a_key(name: &str) -> String {
    format!("{name} is not base64 of 32 bytes: make one with `openssl rand -base64 32`")
}

/// Whether two keys are the same key, compared without stopping at the first difference.
pub fn same_secure_key(a: &[u8; SECURE_KEY_LEN], b: &[u8; SECURE_KEY_LEN]) -> bool {
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (left, right)| acc | (left ^ right))
        == 0
}

/// The network keys: what every packet of the standard is encrypted with - the data the proxy reads
/// from services, and the operator's calls to the control port. Several at once - one per service,
/// an old one and a new one while a key is rotated - and each is tried until one opens the body.
/// They come with `POST /api/initialize` and live in the secure store.
///
/// One list of my-http-server for everything: the control port's servers (its TCP address and its
/// unix socket) decrypt requests with it and refuse replays against the salts it keeps, and the
/// proxy decrypts what it reads with it. The encryption itself is my-http-utils' - RFC 8188,
/// `Content-Encoding: aes128gcm`, see docs/encrypted-service-data.md.
pub struct NetworkKeys {
    keys: Arc<BodyEncryptionKeys>,
}

impl NetworkKeys {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(BodyEncryptionKeys::new(Vec::new())),
        }
    }

    /// The list the control port's servers decrypt requests with. Both get this one: a body
    /// accepted on one of them is refused as a replay on the other.
    pub fn body_encryption_keys(&self) -> Arc<BodyEncryptionKeys> {
        self.keys.clone()
    }

    /// Replaces the keys. The id of each is its place in the list: `0` is the current key.
    pub fn set(&self, keys: Vec<SecureKey>) {
        let keys = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                BodyEncryptionKey::from_bytes(index.to_string(), &key[..])
                    .expect("a network key is 32 bytes")
            })
            .collect();

        self.keys.set(keys);
    }

    pub fn count(&self) -> usize {
        self.keys.len()
    }

    /// The body decrypted with the first key which opens it.
    pub fn try_open(&self, body: &[u8]) -> Option<Vec<u8>> {
        self.keys.decrypt(body).ok()
    }

    /// What a source gave, the way the proxy reads it: decrypted if one of the keys opens it, as
    /// it is otherwise.
    ///
    /// docs/encrypted-service-data.md puts it the other way round: parse it as it is, and
    /// decrypt it if that fails. The outcome is the same - AES-GCM never opens data which was not
    /// encrypted with the key, so a plain body is always read as it is - and this way it is done
    /// in one place for every source, rather than once in the parser of each.
    pub fn open_if_encrypted(&self, body: Vec<u8>) -> Vec<u8> {
        match self.try_open(&body) {
            Some(plain) => plain,
            None => body,
        }
    }

    /// An answer which says it is encrypted (`Content-Encoding: aes128gcm`): one of the keys has
    /// to open it, and the error tells which way it did not.
    pub fn open_marked(&self, body: &[u8]) -> Result<Vec<u8>, String> {
        let count = self.count();

        if count == 0 {
            return Err(format!(
                "the answer is encrypted (Content-Encoding: {AES128GCM_CONTENT_ENCODING}) and the \
                 proxy has no network keys: POST /api/initialize with network_keys"
            ));
        }

        self.try_open(body).ok_or_else(|| {
            format!(
                "the answer is encrypted (Content-Encoding: {AES128GCM_CONTENT_ENCODING}) and none \
                 of the {count} network keys opens it"
            )
        })
    }

    /// What was read with `content_encoding` (the header of an HTTP answer, `None` for a file):
    /// see [`Self::open_marked`] and [`Self::open_if_encrypted`].
    pub fn read(&self, body: Vec<u8>, content_encoding: Option<&str>) -> Result<Vec<u8>, String> {
        let is_marked = content_encoding.is_some_and(|value| {
            value
                .trim()
                .eq_ignore_ascii_case(AES128GCM_CONTENT_ENCODING)
        });

        if is_marked {
            self.open_marked(&body)
        } else {
            Ok(self.open_if_encrypted(body))
        }
    }
}

/// The network key of the tests. The proxy's keys are shared by the tests which run at the same
/// time, so every test which sets them sets this one: anything encrypted with another key is one
/// the proxy can not open.
#[cfg(test)]
pub const TEST_NETWORK_KEY: [u8; SECURE_KEY_LEN] = [0x5a; SECURE_KEY_LEN];

/// The proxy's network keys are [`TEST_NETWORK_KEY`] alone.
#[cfg(test)]
pub fn use_test_network_key() {
    crate::app::APP_CTX
        .secure
        .network_keys
        .set(vec![Zeroizing::new(TEST_NETWORK_KEY)]);
}

/// `plain` encrypted with `key`, the way a service of the standard encrypts its answer.
#[cfg(test)]
pub fn encrypt_for_tests(key: &[u8; SECURE_KEY_LEN], plain: &[u8]) -> Vec<u8> {
    my_http_server::HttpBodyEncryptionKey::from_bytes(key)
        .unwrap()
        .encrypt(plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> SecureKey {
        Zeroizing::new([byte; SECURE_KEY_LEN])
    }

    fn base64_of(key: &SecureKey) -> String {
        base64::engine::general_purpose::STANDARD.encode(&key[..])
    }

    #[test]
    fn a_key_is_base64_of_32_bytes() {
        let parsed = parse_secure_key(&format!("  {}\n", base64_of(&key(9))), "key").unwrap();
        assert!(same_secure_key(&parsed, &key(9)));

        for text in ["", "not base64!", "AAAA", &base64_of(&key(1))[..20]] {
            let err = parse_secure_key(text, "network_keys[0]").unwrap_err();
            assert!(err.contains("network_keys[0]"), "{err}");
            assert!(err.contains("openssl rand -base64 32"), "{err}");
        }

        // 31 and 33 bytes are not a key either.
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 31]);
        let long = base64::engine::general_purpose::STANDARD.encode([0u8; 33]);
        assert!(parse_secure_key(&short, "key").is_err());
        assert!(parse_secure_key(&long, "key").is_err());
    }

    /// A body encrypted the way the services encrypt their answers, kept as a fixed vector:
    /// whatever version of my-http-utils the proxy is built with, it opens what the services
    /// write.
    #[test]
    fn the_vector_of_the_standard_opens() {
        let keys = NetworkKeys::new();
        keys.set(vec![Zeroizing::new(core::array::from_fn(|index| {
            index as u8
        }))]);

        let body = base64::engine::general_purpose::STANDARD
            .decode("oKGio6SlpqeoqaqrrK2urwAAEAAAd4lQdR25LBqmiaRlRbryiJTYDikv7OAMtydV1zSRPu4Fy70/BNOmc0q8RjUIqwznMD1/D9zqlMc=")
            .unwrap();

        assert_eq!(
            keys.try_open(&body).unwrap(),
            b"ip_white_lists:\n  office:\n  - 10.0.0.1\n"
        );
    }

    #[test]
    fn every_key_is_tried_until_one_opens_the_body() {
        let keys = NetworkKeys::new();
        let body = encrypt_for_tests(&key(2), b"hosts: {}\n");

        assert_eq!(keys.try_open(&body), None);

        keys.set(vec![key(1), key(2), key(3)]);
        assert_eq!(keys.try_open(&body).unwrap(), b"hosts: {}\n");
        assert_eq!(keys.count(), 3);

        // The id of a key is its place in the list: `0` is the current one.
        assert!(keys.body_encryption_keys().get_by_id("0").is_some());
        assert!(keys.body_encryption_keys().get_by_id("2").is_some());
        assert!(keys.body_encryption_keys().get_by_id("3").is_none());

        keys.set(vec![key(1), key(3)]);
        assert_eq!(keys.try_open(&body), None);
    }

    #[test]
    fn plain_data_is_read_as_it_is() {
        let keys = NetworkKeys::new();
        keys.set(vec![key(1)]);

        let plain = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".to_vec();
        assert_eq!(keys.open_if_encrypted(plain.clone()), plain);
        assert_eq!(keys.read(plain.clone(), None).unwrap(), plain);
        assert_eq!(keys.read(plain.clone(), Some("gzip")).unwrap(), plain);

        let body = encrypt_for_tests(&key(1), b"data");
        assert_eq!(keys.open_if_encrypted(body.clone()), b"data");
        assert_eq!(keys.read(body, None).unwrap(), b"data");
    }

    /// An answer which says it is encrypted is never read as plain data.
    #[test]
    fn a_marked_answer_has_to_open() {
        let keys = NetworkKeys::new();
        let body = encrypt_for_tests(&key(5), b"data");

        let err = keys.read(body.clone(), Some("aes128gcm")).unwrap_err();
        assert!(err.contains("no network keys"), "{err}");
        assert!(err.contains("/api/initialize"), "{err}");

        keys.set(vec![key(1), key(2)]);
        let err = keys.read(body.clone(), Some(" AES128GCM ")).unwrap_err();
        assert!(err.contains("none of the 2 network keys"), "{err}");

        keys.set(vec![key(1), key(5)]);
        assert_eq!(keys.read(body, Some("aes128gcm")).unwrap(), b"data");

        let err = keys.read(b"plain".to_vec(), Some("aes128gcm")).unwrap_err();
        assert!(err.contains("none of the 2"), "{err}");
    }
}

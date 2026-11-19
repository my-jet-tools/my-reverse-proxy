use std::io::Write;

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::SECURE_KEY_LEN;

/// The first bytes of the file: it is a secure store of my-reverse-proxy.
const MAGIC: &[u8; 4] = b"MRPS";

/// How the rest of the file is laid out.
const VERSION: u8 = 1;

/// The store is encrypted with a key derived from the files key, not with the files key itself.
const STORE_KEY_INFO: &[u8] = b"my-reverse-proxy/secure-store/v1";

const HEADER_LEN: usize = MAGIC.len() + 1;

/// What the secure store holds. Protobuf, encrypted with the files key.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SecureStoreModel {
    /// The network keys, 32 bytes each, the current one first.
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub network_keys: Vec<Vec<u8>>,
    /// The private keys installed over the encrypted API, by their ids in order.
    #[prost(message, repeated, tag = "2")]
    pub private_keys: Vec<StoredPrivateKey>,
}

/// A private key of the store: what a gateway client names with `private_key:`.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StoredPrivateKey {
    #[prost(string, tag = "1")]
    pub id: String,
    /// The 32 bytes of the Ed25519 private key.
    #[prost(bytes = "vec", tag = "2")]
    pub ed25519: Vec<u8>,
}

/// What reading the store with a files key found.
pub enum SecureStoreLookup {
    /// There is no file: the store is created by the first initialize.
    Missing,
    Opened(SecureStoreModel),
    /// The file is a store, and this key does not open it - or it is damaged, which AES-GCM can
    /// not tell from another key.
    WrongKey,
}

/// The store at `path`, opened with `files_key`. An error is a file which can not be read, or
/// which is not a store of my-reverse-proxy at all.
pub fn read_secure_store(
    path: &str,
    files_key: &[u8; SECURE_KEY_LEN],
) -> Result<SecureStoreLookup, String> {
    let content = match std::fs::read(path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(SecureStoreLookup::Missing)
        }
        Err(err) => return Err(format!("the secure store {path} can not be read: {err}")),
    };

    if content.len() < HEADER_LEN + NONCE_LEN || &content[..MAGIC.len()] != MAGIC {
        return Err(format!(
            "{path} is not a secure store of my-reverse-proxy: it does not start the way one does"
        ));
    }

    if content[MAGIC.len()] != VERSION {
        return Err(format!(
            "the secure store {path} is of version {}, and this build reads version {VERSION}",
            content[MAGIC.len()]
        ));
    }

    let nonce: [u8; NONCE_LEN] = content[HEADER_LEN..HEADER_LEN + NONCE_LEN]
        .try_into()
        .expect("the length is checked above");

    let mut sealed = Zeroizing::new(content[HEADER_LEN + NONCE_LEN..].to_vec());

    let Ok(plain) = store_cipher(files_key).open_in_place(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(&content[..HEADER_LEN]),
        &mut sealed,
    ) else {
        return Ok(SecureStoreLookup::WrongKey);
    };

    let model: SecureStoreModel = prost::Message::decode(&plain[..]).map_err(|err| {
        format!("the secure store {path} opens, and what is in it can not be read: {err}")
    })?;

    Ok(SecureStoreLookup::Opened(model))
}

/// Writes `model` to `path`, encrypted with `files_key`: into a file next to it first, which then
/// takes its place, so a store is never half written. The file is the owner's only (`0600`).
pub fn write_secure_store(
    path: &str,
    files_key: &[u8; SECURE_KEY_LEN],
    model: &SecureStoreModel,
) -> Result<(), String> {
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| "the system random generator gives no nonce".to_string())?;

    let mut sealed = Zeroizing::new(prost::Message::encode_to_vec(model));

    let mut header = [0u8; HEADER_LEN];
    header[..MAGIC.len()].copy_from_slice(MAGIC);
    header[MAGIC.len()] = VERSION;

    store_cipher(files_key)
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&header[..]),
            &mut *sealed,
        )
        .map_err(|_| "the secure store can not be encrypted".to_string())?;

    let mut content = Vec::with_capacity(HEADER_LEN + NONCE_LEN + sealed.len());
    content.extend_from_slice(&header);
    content.extend_from_slice(&nonce);
    content.extend_from_slice(&sealed);

    let target = std::path::Path::new(path);

    if let Some(folder) = target
        .parent()
        .filter(|folder| !folder.as_os_str().is_empty())
    {
        std::fs::create_dir_all(folder).map_err(|err| {
            format!(
                "the folder of the secure store {} can not be created: {err}",
                folder.display()
            )
        })?;
    }

    let mut temporary = target.as_os_str().to_owned();
    temporary.push(format!(".tmp-{}", std::process::id()));
    let temporary = std::path::PathBuf::from(temporary);

    let written =
        write_owner_only(&temporary, &content).and_then(|_| std::fs::rename(&temporary, target));

    if let Err(err) = written {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!("the secure store {path} can not be written: {err}"));
    }

    Ok(())
}

fn write_owner_only(path: &std::path::Path, content: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;
    file.write_all(content)?;
    file.sync_all()
}

fn store_cipher(files_key: &[u8; SECURE_KEY_LEN]) -> LessSafeKey {
    let mut key = Zeroizing::new([0u8; SECURE_KEY_LEN]);

    hkdf::Hkdf::<Sha256>::new(None, files_key)
        .expand(STORE_KEY_INFO, &mut key[..])
        .expect("32 bytes is a length HKDF-SHA-256 gives");

    LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key[..]).expect("32 bytes is an AES-256 key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_path(name: &str) -> String {
        std::env::temp_dir()
            .join(format!(
                "my-reverse-proxy-secure-store-{name}-{}",
                std::process::id()
            ))
            .to_str()
            .unwrap()
            .to_string()
    }

    fn model() -> SecureStoreModel {
        SecureStoreModel {
            network_keys: vec![vec![1u8; 32], vec![2u8; 32]],
            private_keys: vec![StoredPrivateKey {
                id: "london".to_string(),
                ed25519: vec![3u8; 32],
            }],
        }
    }

    #[test]
    fn what_is_written_opens_with_the_same_key() {
        let path = temporary_path("roundtrip");
        let key = [7u8; 32];

        assert!(matches!(
            read_secure_store(&path, &key).unwrap(),
            SecureStoreLookup::Missing
        ));

        write_secure_store(&path, &key, &model()).unwrap();

        let lookup = read_secure_store(&path, &key).unwrap();
        let content = std::fs::read(&path).unwrap();

        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777
        };

        std::fs::remove_file(&path).unwrap();

        let SecureStoreLookup::Opened(opened) = lookup else {
            panic!("the store does not open with its key");
        };
        assert_eq!(opened, model());

        // Nothing of what is in it is to be seen in the file.
        assert!(!content.windows(32).any(|window| window == [1u8; 32]));

        #[cfg(unix)]
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn another_key_or_a_damaged_file_does_not_open_the_store() {
        let path = temporary_path("wrong-key");
        write_secure_store(&path, &[7u8; 32], &model()).unwrap();

        let wrong_key = read_secure_store(&path, &[8u8; 32]).unwrap();

        let mut content = std::fs::read(&path).unwrap();
        let last = content.len() - 1;
        content[last] ^= 1;
        std::fs::write(&path, &content).unwrap();
        let damaged = read_secure_store(&path, &[7u8; 32]).unwrap();

        std::fs::remove_file(&path).unwrap();

        assert!(matches!(wrong_key, SecureStoreLookup::WrongKey));
        assert!(matches!(damaged, SecureStoreLookup::WrongKey));
    }

    #[test]
    fn a_file_which_is_not_a_store_is_an_error() {
        let path = temporary_path("not-a-store");
        std::fs::write(&path, b"hosts: {}\n and more of a settings file").unwrap();

        let result = read_secure_store(&path, &[7u8; 32]);

        std::fs::remove_file(&path).unwrap();

        let err = result.err().unwrap();
        assert!(err.contains("is not a secure store"), "{err}");
    }

    #[test]
    fn a_missing_folder_is_created() {
        let folder = temporary_path("folder");
        let path = format!("{folder}/nested/store");

        write_secure_store(&path, &[7u8; 32], &model()).unwrap();
        let lookup = read_secure_store(&path, &[7u8; 32]).unwrap();

        std::fs::remove_dir_all(&folder).unwrap();

        assert!(matches!(lookup, SecureStoreLookup::Opened(_)));
    }
}

use std::{collections::HashMap, sync::Arc};

use arc_swap::ArcSwapOption;
use ed25519_dalek::SigningKey;

use super::*;

/// The secure side of the proxy: whether it is initialized, the store it opened, the network keys
/// and the private keys. See docs/secure-parameters.md.
pub struct SecureState {
    /// Held by whatever writes the store - an initialize, a private key installed or removed - one
    /// at a time.
    write_lock: tokio::sync::Mutex<()>,
    opened: ArcSwapOption<OpenedStore>,
    pub network_keys: NetworkKeys,
    /// The private keys of the store. An `Arc` of its own: a gateway client takes its key from here
    /// at every connect.
    pub private_keys: Arc<PrivateKeys>,
}

/// The store `POST /api/initialize` opened, and the files key it opened it with: kept in memory
/// until the process stops, and written nowhere. `model` is what the file holds now.
struct OpenedStore {
    path: String,
    files_key: SecureKey,
    model: parking_lot::Mutex<SecureStoreModel>,
}

/// Why the store was not changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecureStoreError {
    /// `POST /api/initialize` has not opened the store yet.
    NotInitialized,
    /// The store can not be written: the message says which file and why.
    Failed(String),
}

/// What an initialize did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitializeOutcome {
    /// There was no store: it is created, encrypted with this key.
    Created,
    /// The store opened with this key - or it already was, with this same key.
    Initialized,
}

impl InitializeOutcome {
    /// The word the caller is answered with.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Created => "Created",
            Self::Initialized => "Initialized",
        }
    }
}

/// Why an initialize did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitializeError {
    /// A key which is not base64 of 32 bytes, or an empty list of network keys.
    BadRequest(String),
    /// The store is there and this key does not open it, or the proxy is already initialized with
    /// another key. Nothing changed.
    InvalidKey,
    /// The store can not be read or written: the message says which file and why.
    Failed(String),
}

impl SecureState {
    pub fn new() -> Self {
        Self {
            write_lock: tokio::sync::Mutex::new(()),
            opened: ArcSwapOption::empty(),
            network_keys: NetworkKeys::new(),
            private_keys: Arc::new(PrivateKeys::new()),
        }
    }

    /// Whether `POST /api/initialize` has succeeded since the proxy started.
    pub fn is_initialized(&self) -> bool {
        self.opened.load().is_some()
    }

    /// `POST /api/initialize`: opens the store at `store_file` with `key` - or creates it, if
    /// there is none - and takes its network keys. `network_keys`, when given, replaces the whole
    /// list the store has.
    ///
    /// Once initialized, the store stays where it was opened: the same key answers `Initialized`
    /// (and may change the network keys), any other is `InvalidKey`.
    pub async fn initialize(
        &self,
        store_file: &str,
        key: &str,
        network_keys: Option<&[String]>,
    ) -> Result<InitializeOutcome, InitializeError> {
        let files_key = parse_secure_key(key, "key").map_err(InitializeError::BadRequest)?;

        let network_keys = match network_keys {
            Some(list) => Some(parse_network_keys(list)?),
            None => None,
        };

        let _writing = self.write_lock.lock().await;

        if let Some(opened) = self.opened.load_full() {
            if !same_secure_key(&opened.files_key, &files_key) {
                return Err(InitializeError::InvalidKey);
            }

            if let Some(network_keys) = network_keys {
                // Everything else the store holds stays as it is.
                let mut model = opened.model.lock().clone();
                model.network_keys = to_bytes(&network_keys);
                write_store(opened.path.clone(), files_key, model.clone())
                    .await
                    .map_err(InitializeError::Failed)?;
                *opened.model.lock() = model;
                self.network_keys.set(network_keys);
            }

            return Ok(InitializeOutcome::Initialized);
        }

        let path = crate::settings::expand_home(store_file).map_err(InitializeError::Failed)?;

        let lookup = {
            let path = path.clone();
            let files_key = files_key.clone();
            tokio::task::spawn_blocking(move || read_secure_store(&path, &files_key))
                .await
                .map_err(|err| {
                    InitializeError::Failed(format!("reading the secure store did not end: {err}"))
                })?
                .map_err(InitializeError::Failed)?
        };

        let (outcome, model) = match lookup {
            SecureStoreLookup::WrongKey => return Err(InitializeError::InvalidKey),
            SecureStoreLookup::Missing => {
                let model = SecureStoreModel {
                    network_keys: to_bytes(network_keys.as_deref().unwrap_or_default()),
                    private_keys: Vec::new(),
                };
                write_store(path.clone(), files_key.clone(), model.clone())
                    .await
                    .map_err(InitializeError::Failed)?;
                (InitializeOutcome::Created, model)
            }
            SecureStoreLookup::Opened(mut model) => {
                if let Some(network_keys) = network_keys.as_ref() {
                    model.network_keys = to_bytes(network_keys);
                    write_store(path.clone(), files_key.clone(), model.clone())
                        .await
                        .map_err(InitializeError::Failed)?;
                }
                (InitializeOutcome::Initialized, model)
            }
        };

        let network_keys = from_bytes(&path, &model.network_keys)?;
        let private_keys =
            private_keys_of(&path, &model.private_keys).map_err(InitializeError::Failed)?;

        self.network_keys.set(network_keys);
        self.private_keys.set_all(private_keys);
        self.opened.store(Some(Arc::new(OpenedStore {
            path,
            files_key,
            model: parking_lot::Mutex::new(model),
        })));

        Ok(outcome)
    }

    /// Installs `key` under `id` - in place of the key the id had, if it had one - and writes the
    /// store. A gateway client which names `id` signs its next connect with it.
    pub async fn set_private_key(&self, id: &str, key: SigningKey) -> Result<(), SecureStoreError> {
        self.change_private_keys(|model| {
            model.private_keys.retain(|itm| itm.id != id);
            model.private_keys.push(StoredPrivateKey {
                id: id.to_string(),
                ed25519: key.to_bytes().to_vec(),
            });
            model.private_keys.sort_by(|a, b| a.id.cmp(&b.id));
            true
        })
        .await
        .map(|_| ())
    }

    /// Removes the key `id` and writes the store. `false`: there was no such key, and nothing is
    /// written.
    pub async fn delete_private_key(&self, id: &str) -> Result<bool, SecureStoreError> {
        self.change_private_keys(|model| {
            let before = model.private_keys.len();
            model.private_keys.retain(|itm| itm.id != id);
            model.private_keys.len() != before
        })
        .await
    }

    /// `change` the model the store holds; when it says it changed something, the store is written,
    /// and only then are the private keys in memory replaced.
    async fn change_private_keys(
        &self,
        change: impl FnOnce(&mut SecureStoreModel) -> bool,
    ) -> Result<bool, SecureStoreError> {
        let _writing = self.write_lock.lock().await;

        let opened = self
            .opened
            .load_full()
            .ok_or(SecureStoreError::NotInitialized)?;

        let mut model = opened.model.lock().clone();

        if !change(&mut model) {
            return Ok(false);
        }

        let private_keys =
            private_keys_of(&opened.path, &model.private_keys).map_err(SecureStoreError::Failed)?;

        write_store(opened.path.clone(), opened.files_key.clone(), model.clone())
            .await
            .map_err(SecureStoreError::Failed)?;

        *opened.model.lock() = model;
        self.private_keys.set_all(private_keys);

        Ok(true)
    }
}

/// The private keys of the store as signing keys, by their ids.
fn private_keys_of(
    path: &str,
    keys: &[StoredPrivateKey],
) -> Result<HashMap<String, Arc<SigningKey>>, String> {
    keys.iter()
        .map(|itm| {
            let bytes: [u8; 32] = itm.ed25519.as_slice().try_into().map_err(|_| {
                format!(
                    "the secure store {path} has a private key '{}' of {} bytes",
                    itm.id,
                    itm.ed25519.len()
                )
            })?;
            Ok((itm.id.clone(), Arc::new(SigningKey::from_bytes(&bytes))))
        })
        .collect()
}

/// `network_keys` of the request: at least one, each base64 of 32 bytes. A key given twice is
/// kept once, where it is first.
fn parse_network_keys(list: &[String]) -> Result<Vec<SecureKey>, InitializeError> {
    if list.is_empty() {
        return Err(InitializeError::BadRequest(
            "network_keys is an empty list: leave it out to keep the network keys the store has"
                .to_string(),
        ));
    }

    let mut result: Vec<SecureKey> = Vec::with_capacity(list.len());

    for (index, text) in list.iter().enumerate() {
        let key = parse_secure_key(text, &format!("network_keys[{index}]"))
            .map_err(InitializeError::BadRequest)?;

        if !result.iter().any(|known| same_secure_key(known, &key)) {
            result.push(key);
        }
    }

    Ok(result)
}

fn to_bytes(keys: &[SecureKey]) -> Vec<Vec<u8>> {
    keys.iter().map(|key| key.to_vec()).collect()
}

fn from_bytes(path: &str, keys: &[Vec<u8>]) -> Result<Vec<SecureKey>, InitializeError> {
    keys.iter()
        .map(|bytes| {
            let key: [u8; SECURE_KEY_LEN] = bytes.as_slice().try_into().map_err(|_| {
                InitializeError::Failed(format!(
                    "the secure store {path} has a network key of {} bytes",
                    bytes.len()
                ))
            })?;
            Ok(zeroize::Zeroizing::new(key))
        })
        .collect()
}

async fn write_store(
    path: String,
    files_key: SecureKey,
    model: SecureStoreModel,
) -> Result<(), String> {
    tokio::task::spawn_blocking(move || write_secure_store(&path, &files_key, &model))
        .await
        .map_err(|err| format!("writing the secure store did not end: {err}"))?
}

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::*;

    fn text(byte: u8) -> String {
        base64::engine::general_purpose::STANDARD.encode([byte; SECURE_KEY_LEN])
    }

    fn temporary_path(name: &str) -> String {
        std::env::temp_dir()
            .join(format!(
                "my-reverse-proxy-secure-state-{name}-{}",
                std::process::id()
            ))
            .to_str()
            .unwrap()
            .to_string()
    }

    fn opens_with(state: &SecureState, byte: u8) -> bool {
        let body = encrypt_for_tests(&[byte; SECURE_KEY_LEN], b"data");
        state.network_keys.try_open(&body).is_some()
    }

    #[tokio::test]
    async fn the_first_initialize_creates_the_store_and_the_next_ones_open_it() {
        let path = temporary_path("lifecycle");
        let _ = std::fs::remove_file(&path);

        let state = SecureState::new();
        assert!(!state.is_initialized());

        let outcome = state
            .initialize(&path, &text(1), Some(&[text(10), text(11)]))
            .await
            .unwrap();
        assert_eq!(outcome, InitializeOutcome::Created);
        assert!(state.is_initialized());
        assert!(opens_with(&state, 10) && opens_with(&state, 11));

        // The same key again changes nothing; another one is refused.
        assert_eq!(
            state.initialize(&path, &text(1), None).await,
            Ok(InitializeOutcome::Initialized)
        );
        assert_eq!(
            state.initialize(&path, &text(2), None).await,
            Err(InitializeError::InvalidKey)
        );
        assert!(opens_with(&state, 10));

        // After a restart: the store opens with its key, and the network keys come out of it.
        let restarted = SecureState::new();
        assert_eq!(
            restarted.initialize(&path, &text(2), None).await,
            Err(InitializeError::InvalidKey)
        );
        assert!(!restarted.is_initialized());

        assert_eq!(
            restarted.initialize(&path, &text(1), None).await,
            Ok(InitializeOutcome::Initialized)
        );
        assert!(opens_with(&restarted, 10) && opens_with(&restarted, 11));

        // network_keys replaces the whole list, and the store keeps the new one.
        restarted
            .initialize(&path, &text(1), Some(&[text(12)]))
            .await
            .unwrap();
        assert!(opens_with(&restarted, 12) && !opens_with(&restarted, 10));

        let again = SecureState::new();
        again.initialize(&path, &text(1), None).await.unwrap();

        std::fs::remove_file(&path).unwrap();

        assert!(opens_with(&again, 12) && !opens_with(&again, 11));
    }

    /// The private keys are kept by the store: a restart opens them, and new network keys given
    /// to initialize leave them as they are.
    #[tokio::test]
    async fn the_private_keys_are_kept_by_the_store() {
        let path = temporary_path("private-keys");
        let _ = std::fs::remove_file(&path);

        let state = SecureState::new();

        // Nothing is installed before the store is open.
        assert_eq!(
            state
                .set_private_key("london", SigningKey::from_bytes(&[7; 32]))
                .await,
            Err(SecureStoreError::NotInitialized)
        );

        state
            .initialize(&path, &text(1), Some(&[text(10)]))
            .await
            .unwrap();

        state
            .set_private_key("london", SigningKey::from_bytes(&[7; 32]))
            .await
            .unwrap();
        state
            .set_private_key("berlin", SigningKey::from_bytes(&[8; 32]))
            .await
            .unwrap();
        assert!(!state.delete_private_key("paris").await.unwrap());

        // New network keys: the private keys stay.
        state
            .initialize(&path, &text(1), Some(&[text(11)]))
            .await
            .unwrap();

        let restarted = SecureState::new();
        restarted.initialize(&path, &text(1), None).await.unwrap();

        let ids: Vec<String> = restarted
            .private_keys
            .list()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert_eq!(ids, ["berlin", "london"]);
        assert_eq!(
            restarted.private_keys.get("london").unwrap().to_bytes(),
            [7; 32]
        );
        assert!(opens_with(&restarted, 11) && !opens_with(&restarted, 10));

        assert!(restarted.delete_private_key("london").await.unwrap());

        let again = SecureState::new();
        again.initialize(&path, &text(1), None).await.unwrap();

        std::fs::remove_file(&path).unwrap();

        assert!(again.private_keys.get("london").is_none());
        assert!(again.private_keys.get("berlin").is_some());
    }

    #[tokio::test]
    async fn a_store_is_created_without_network_keys_too() {
        let path = temporary_path("no-network-keys");
        let _ = std::fs::remove_file(&path);

        let state = SecureState::new();
        let outcome = state.initialize(&path, &text(1), None).await;

        std::fs::remove_file(&path).unwrap();

        assert_eq!(outcome, Ok(InitializeOutcome::Created));
        assert_eq!(state.network_keys.count(), 0);
    }

    #[tokio::test]
    async fn a_request_which_can_not_work_changes_nothing() {
        let path = temporary_path("bad-request");
        let _ = std::fs::remove_file(&path);

        let state = SecureState::new();

        for (key, network_keys) in [
            ("not a key".to_string(), None),
            (text(1), Some(vec![])),
            (text(1), Some(vec![text(2), "AAAA".to_string()])),
        ] {
            let result = state.initialize(&path, &key, network_keys.as_deref()).await;
            assert!(
                matches!(result, Err(InitializeError::BadRequest(_))),
                "{result:?}"
            );
        }

        assert!(!state.is_initialized());
        assert!(!std::path::Path::new(&path).exists());
    }

    #[tokio::test]
    async fn a_key_given_twice_is_kept_once() {
        let path = temporary_path("twice");
        let _ = std::fs::remove_file(&path);

        let state = SecureState::new();
        state
            .initialize(
                &path,
                &text(1),
                Some(&[text(3), format!(" {}\n", text(3)), text(4)]),
            )
            .await
            .unwrap();

        std::fs::remove_file(&path).unwrap();

        assert_eq!(state.network_keys.count(), 2);
    }
}

use std::{collections::HashMap, sync::Arc};

use arc_swap::ArcSwap;

/// The sets of keys requests are checked against: every set of the settings applied, with the
/// keys the urls of `real_time_configurations` gave. Read on every request to a guarded location
/// without a lock; replaced as a whole when the settings or an answer of a url change.
pub struct ApiKeysStore {
    sets: ArcSwap<HashMap<String, Vec<Box<[u8]>>>>,
    /// Sets the tests add next to the published ones: the tests share this store, and each of
    /// them uses ids of its own.
    #[cfg(test)]
    sets_of_tests: parking_lot::Mutex<HashMap<String, Vec<Box<[u8]>>>>,
}

impl ApiKeysStore {
    pub fn new() -> Self {
        Self {
            sets: ArcSwap::from_pointee(HashMap::new()),
            #[cfg(test)]
            sets_of_tests: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Takes `sets` in place of the sets published before.
    pub fn publish(&self, sets: &HashMap<String, Vec<crate::types::ProtectedString>>) {
        let sets = sets
            .iter()
            .map(|(id, keys)| (id.clone(), to_bytes(keys)))
            .collect();

        self.sets.store(Arc::new(sets));
    }

    /// Whether `presented` is a key of the set `id`. Every key of the set is compared, each in a
    /// time which does not depend on where the two differ.
    pub fn accepts(&self, id: &str, presented: &[u8]) -> bool {
        let sets = self.sets.load();

        #[allow(unused_mut)]
        let mut accepted = is_one_of(sets.get(id), presented);

        #[cfg(test)]
        {
            accepted |= is_one_of(self.sets_of_tests.lock().get(id), presented);
        }

        accepted
    }

    #[cfg(test)]
    pub fn add_for_tests(&self, id: &str, keys: &[&str]) {
        let keys: Vec<crate::types::ProtectedString> =
            keys.iter().map(|key| (*key).into()).collect();

        self.sets_of_tests
            .lock()
            .entry(id.to_string())
            .or_default()
            .extend(to_bytes(&keys));
    }
}

fn to_bytes(keys: &[crate::types::ProtectedString]) -> Vec<Box<[u8]>> {
    keys.iter().map(|key| key.as_bytes().into()).collect()
}

fn is_one_of(keys: Option<&Vec<Box<[u8]>>>, presented: &[u8]) -> bool {
    let mut found = false;

    // No early way out: the time does not tell which key - or whether any - matched.
    for key in keys.into_iter().flatten() {
        found |= constant_time_eq(key, presented);
    }

    found
}

/// Compares in a time which depends on the lengths only.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;

    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }

    std::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sets(items: &[(&str, &[&str])]) -> HashMap<String, Vec<crate::types::ProtectedString>> {
        items
            .iter()
            .map(|(id, keys)| (id.to_string(), keys.iter().map(|key| (*key).into()).collect()))
            .collect()
    }

    #[test]
    fn a_published_set_replaces_the_one_before() {
        let store = ApiKeysStore::new();
        assert!(!store.accepts("clients", b"key-1"));

        store.publish(&sets(&[("clients", &["key-1"]), ("admins", &["key-a"])]));
        assert!(store.accepts("clients", b"key-1"));
        assert!(store.accepts("admins", b"key-a"));
        assert!(!store.accepts("clients", b"key-a"));

        store.publish(&sets(&[("clients", &["key-2"])]));
        assert!(!store.accepts("clients", b"key-1"));
        assert!(store.accepts("clients", b"key-2"));
        assert!(!store.accepts("admins", b"key-a"));
    }

    /// A set declared with no keys - or one nobody declares - lets nobody through.
    #[test]
    fn a_set_with_no_keys_lets_nobody_through() {
        let store = ApiKeysStore::new();
        store.publish(&sets(&[("empty", &[])]));

        assert!(!store.accepts("empty", b""));
        assert!(!store.accepts("empty", b"anything"));
        assert!(!store.accepts("not-declared", b""));
    }

    #[test]
    fn constant_time_eq_is_eq() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"abc", b"xbc"));
    }
}

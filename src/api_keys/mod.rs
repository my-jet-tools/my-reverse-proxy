//! `api_keys:` and `api_keys_auth:` - the keys a request has to carry in `X-Api-Key` to get to a
//! location they guard.
//!
//! A set of keys has an id, and is put together from every place which declares keys under that
//! id: the settings files, the dynamic settings file, and the answers of
//! `real_time_configurations.urls`. `api_keys_auth: <id>` guards an endpoint - each of its
//! locations - or one location; `api_keys_auth: none` on a location opens it again.
//!
//! A set with no keys in it - one nothing declares, or a url has not given yet - lets nobody
//! through: the endpoint is served, and a guarded location answers everybody with 401.

mod api_keys_store;
pub use api_keys_store::*;

use std::{collections::HashMap, net::IpAddr};

use crate::types::ProtectedString;

/// The request header a key is read from - its name is matched case-insensitively.
pub const API_KEY_HEADER: &str = "x-api-key";

/// `api_keys_auth: none`: the location is open although its endpoint is guarded - or the
/// endpoint is, although its template guards it. Not an id: no set can be declared under it.
pub const NO_API_KEYS: &str = "none";

pub fn is_no_api_keys(value: &str) -> bool {
    value.trim().eq_ignore_ascii_case(NO_API_KEYS)
}

/// The set of keys a location is guarded with: its own `api_keys_auth`, or else the one of its
/// endpoint - which may come from the template of the endpoint. `none` guards with nothing.
pub fn resolve_api_keys_auth(location: Option<&str>, endpoint: Option<&str>) -> Option<String> {
    let value = location.or(endpoint)?;

    if is_no_api_keys(value) {
        return None;
    }

    Some(value.to_string())
}

/// Checks the keys of the set `id` - as a settings file or a url gives them, the variables put
/// in - and returns them as they are compared: without the spaces around them, which the value
/// of a header does not have either.
///
/// The keys are secrets - a [`ProtectedString`] each from the moment they are read: no error says
/// what a key is.
pub fn check_api_keys(
    id: &str,
    keys: Vec<ProtectedString>,
) -> Result<Vec<ProtectedString>, String> {
    if id.trim().is_empty() {
        return Err("api_keys: an id can not be empty".to_string());
    }

    if is_no_api_keys(id) {
        return Err(format!(
            "api_keys: '{id}' can not be an id - 'api_keys_auth: {NO_API_KEYS}' is what opens a location"
        ));
    }

    let mut result = Vec::with_capacity(keys.len());

    for key in keys {
        let key = key.as_str().trim();

        if key.is_empty() {
            return Err(format!("api_keys '{id}': a key is empty"));
        }

        // A ${UPPER_CASE} name is left in a value as it is written (it is one of the system
        // variables, put in per request where a header takes them): the key would be the very
        // text of the placeholder, which anybody can read in the settings.
        if key.contains("${") {
            return Err(format!(
                "api_keys '{id}': a key has a variable which is not put in. A key takes ${{lower_case}} variables: a ${{UPPER_CASE}} one would stay in the key as it is written"
            ));
        }

        if key.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err(format!(
                "api_keys '{id}': a key has a control character, which no header can carry"
            ));
        }

        if !result
            .iter()
            .any(|existing: &ProtectedString| existing.as_str() == key)
        {
            result.push(ProtectedString::from(key));
        }
    }

    Ok(result)
}

/// Puts the keys of `from` into `into`: the keys of one id from several places make one set.
pub fn merge_api_keys(
    into: &mut HashMap<String, Vec<ProtectedString>>,
    from: &HashMap<String, Vec<ProtectedString>>,
) {
    for (id, keys) in from {
        let set = into.entry(id.clone()).or_default();

        for key in keys {
            if !set.contains(key) {
                set.push(key.clone());
            }
        }
    }
}

/// Whether a request whose `X-Api-Key` headers are `values` gets through the set `id`: it has to
/// carry exactly one, and that one has to be a key of the set. Two are refused whatever they are:
/// the header goes on to the upstream, which might read the other one.
pub fn request_has_api_key<'a>(
    store: &ApiKeysStore,
    id: &str,
    mut values: impl Iterator<Item = &'a [u8]>,
) -> bool {
    let Some(value) = values.next() else {
        return false;
    };

    if values.next().is_some() {
        return false;
    }

    let value = trim_ows(value);

    if value.is_empty() {
        return false;
    }

    store.accepts(id, value)
}

/// A request a guarded location refused: a hard failure of its source for the IP block-list -
/// five within 15 seconds block the source for 5 minutes. An address of
/// `global_settings.ip_blocklist_white_list` is not counted.
pub fn register_rejection(ip: Option<IpAddr>) {
    let Some(ip) = ip else {
        return;
    };

    // Every test connects from the loopback, and the tests share one block-list: a test of a
    // wrong key would block the tests which run next to it. What is counted is tested on a
    // block-list of its own.
    #[cfg(test)]
    if ip.is_loopback() {
        return;
    }

    crate::app::APP_CTX
        .ip_blocklist
        .register_failure(ip, crate::app::FailureSeverity::Hard);
}

/// Makes the sets of keys of `settings` - of the files, and what the urls gave - the ones
/// requests are checked against.
pub fn publish_api_keys(settings: &crate::settings_compiled::SettingsCompiled) {
    crate::app::APP_CTX
        .api_keys
        .publish(&settings.get_api_keys());
}

/// The value of a header without the spaces and tabs around it (RFC 9110 "OWS").
fn trim_ows(value: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = value.len();

    while start < end && (value[start] == b' ' || value[start] == b'\t') {
        start += 1;
    }

    while end > start && (value[end - 1] == b' ' || value[end - 1] == b'\t') {
        end -= 1;
    }

    &value[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_location_takes_the_set_of_its_endpoint_unless_it_names_its_own() {
        assert_eq!(resolve_api_keys_auth(None, None), None);
        assert_eq!(
            resolve_api_keys_auth(None, Some("clients")),
            Some("clients".to_string())
        );
        assert_eq!(
            resolve_api_keys_auth(Some("admins"), Some("clients")),
            Some("admins".to_string())
        );
        assert_eq!(
            resolve_api_keys_auth(Some("admins"), None),
            Some("admins".to_string())
        );
    }

    #[test]
    fn none_opens_a_location_and_an_endpoint() {
        assert_eq!(resolve_api_keys_auth(Some("none"), Some("clients")), None);
        assert_eq!(resolve_api_keys_auth(Some(" None "), Some("clients")), None);
        assert_eq!(resolve_api_keys_auth(None, Some("none")), None);
        assert_eq!(
            resolve_api_keys_auth(Some("clients"), Some("none")),
            Some("clients".to_string())
        );
    }

    #[test]
    fn the_keys_are_compared_without_the_spaces_around_them() {
        let keys = check_api_keys(
            "clients",
            vec![
                " key-1".into(),
                "key-2\t".into(),
                "key-1".into(),
            ],
        )
        .unwrap();

        assert_eq!(keys, ["key-1", "key-2"]);
    }

    #[test]
    fn a_set_which_can_not_work_is_refused() {
        for (id, keys) in [
            ("none", vec!["key"]),
            ("NONE", vec!["key"]),
            ("", vec!["key"]),
            ("clients", vec![""]),
            ("clients", vec!["   "]),
            ("clients", vec!["${MCP_KEY}"]),
            ("clients", vec!["prefix-${MCP_KEY}"]),
            ("clients", vec!["line\nbreak"]),
            ("clients", vec!["nul\0"]),
        ] {
            let keys: Vec<ProtectedString> = keys.into_iter().map(|key| key.into()).collect();
            assert!(check_api_keys(id, keys.clone()).is_err(), "{id} {keys:?}");
        }

        // No set at all is not a mistake: it lets nobody through.
        assert!(check_api_keys("clients", vec![]).unwrap().is_empty());
    }

    #[test]
    fn no_error_tells_a_key() {
        let err = check_api_keys(
            "clients",
            vec!["very-secret".into(), "${SECRET_PART}".into()],
        )
        .unwrap_err();

        assert!(!err.contains("very-secret"), "{err}");
        assert!(!err.contains("SECRET_PART"), "{err}");
    }

    #[test]
    fn the_keys_of_one_id_from_several_places_make_one_set() {
        let mut sets: HashMap<String, Vec<ProtectedString>> = HashMap::new();

        merge_api_keys(
            &mut sets,
            &HashMap::from([
                (
                    "clients".to_string(),
                    vec!["a".into(), "b".into()],
                ),
                ("admins".to_string(), vec!["x".into()]),
            ]),
        );
        merge_api_keys(
            &mut sets,
            &HashMap::from([(
                "clients".to_string(),
                vec!["b".into(), "c".into()],
            )]),
        );

        assert_eq!(sets["clients"], ["a", "b", "c"]);
        assert_eq!(sets["admins"], ["x"]);
    }

    #[test]
    fn a_request_gets_through_with_exactly_one_right_key() {
        let store = ApiKeysStore::new();
        store.publish(&HashMap::from([(
            "clients".to_string(),
            vec!["key-1".into(), "key-2".into()],
        )]));

        let check =
            |id: &str, values: &[&[u8]]| request_has_api_key(&store, id, values.iter().copied());

        assert!(check("clients", &[b"key-1"]));
        assert!(check("clients", &[b"key-2"]));
        assert!(check("clients", &[b"  key-2\t"]));

        assert!(!check("clients", &[]));
        assert!(!check("clients", &[b""]));
        assert!(!check("clients", &[b"key-3"]));
        assert!(!check("clients", &[b"key-1x"]));
        assert!(!check("clients", &[b"KEY-1"]));
        assert!(!check("clients", &[b"key-1", b"key-1"]));
        assert!(!check("clients", &[b"key-1", b"key-3"]));
        assert!(!check("admins", &[b"key-1"]));
    }
}

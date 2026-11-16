use std::collections::BTreeMap;

use serde::*;

use crate::types::ProtectedString;

/// `request_with_header_only:` of an endpoint, as the settings write it: the headers, each with
/// the one value it has to have, which every request to the endpoint comes with.
///
/// ```yaml
/// request_with_header_only:
/// - X-Zone-Secret: <a long random string>
/// ```
///
/// An item may name several headers: every header of every item is required. The values are
/// secrets, a [`ProtectedString`] each from the moment they are read: `{:?}` writes them as `***`.
/// See [`crate::required_headers`].
#[derive(Serialize, Deserialize, Clone, Default, Debug)]
#[serde(transparent)]
pub struct RequestWithHeaderOnlySettings(pub Vec<BTreeMap<String, ProtectedString>>);

impl RequestWithHeaderOnlySettings {
    /// Every header with its value, in the order of the list.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &ProtectedString)> {
        self.0.iter().flat_map(|item| {
            item.iter()
                .map(|(name, value)| (name.as_str(), value))
        })
    }

    /// Every header as `<name>: ***` - all that may be shown of it.
    pub fn masked(&self) -> Vec<String> {
        self.iter()
            .map(|(name, _)| format!("{name}: {}", ProtectedString::MASK))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "s3cr3t-0123456789abcdef";

    fn settings() -> RequestWithHeaderOnlySettings {
        my_settings_reader::serde_yaml::from_str(&format!(
            "- X-Zone-Secret: {SECRET}\n- X-Other: other-value\n  X-Third: third-value\n"
        ))
        .unwrap()
    }

    #[test]
    fn the_list_of_the_settings_is_read_in_its_order() {
        let headers: Vec<_> = settings()
            .iter()
            .map(|(name, _)| name.to_string())
            .collect();
        assert_eq!(headers, vec!["X-Zone-Secret", "X-Other", "X-Third"]);
    }

    #[test]
    fn a_value_is_never_shown() {
        let settings = settings();
        let debug = format!("{settings:?}");

        assert!(!debug.contains(SECRET), "{debug}");
        assert!(debug.contains("\"X-Zone-Secret\": \"***\""), "{debug}");
        assert_eq!(
            settings.masked(),
            vec!["X-Zone-Secret: ***", "X-Other: ***", "X-Third: ***"]
        );
    }
}

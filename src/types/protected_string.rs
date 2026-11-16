use serde::{Deserialize, Serialize};

/// A secret: an api key, a value of `request_with_header_only`, a variable, a password, a client
/// secret. It is wrapped once - where it comes in: when the settings are read, when a header of a
/// request is taken for a log - and from then on it can not get into a log, an error or a page by
/// mistake: `{:?}` writes [`ProtectedString::MASK`], whatever it holds. What it holds is read with
/// [`ProtectedString::as_str`], by what has to use it - the comparison of a key, the request to
/// Google, the login over ssh.
///
/// There is no `Display`, on purpose: with it comes `to_string()`, which would quietly make the
/// secret `***` where it is used for real - sent to Google as `***`. Without it `{}` and
/// `to_string()` do not compile, and a use of the secret is always a visible `as_str()`.
///
/// Serialized as it is: settings written back, or compared with other settings
/// (`same_host`), keep the secret - a mask would make every two secrets the same.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProtectedString(String);

impl ProtectedString {
    /// What a secret is written as.
    pub const MASK: &'static str = "***";

    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for ProtectedString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for ProtectedString {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

/// Compared by what it holds - nothing of it is written out.
impl PartialEq<str> for ProtectedString {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for ProtectedString {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// As `{:?}` writes a `&str`, quoted - so a map or a struct of them reads as before.
impl std::fmt::Debug for ProtectedString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(Self::MASK, f)
    }
}

#[cfg(test)]
mod tests {
    use super::ProtectedString;

    const SECRET: &str = "the-s3cr3t-value";

    #[test]
    fn it_is_never_written_out() {
        let secret = ProtectedString::new(SECRET);

        assert_eq!(format!("{secret:?}"), "\"***\"");
        assert_eq!(format!("{:#?}", Some(&secret)), "Some(\n    \"***\",\n)");

        #[derive(Debug)]
        #[allow(dead_code)]
        struct Settings {
            client_secret: ProtectedString,
        }

        let line = format!(
            "{:?}",
            Settings {
                client_secret: secret.clone()
            }
        );
        assert!(!line.contains(SECRET), "{line}");

        assert_eq!(secret.as_str(), SECRET);
    }

    /// Settings written back, or compared, keep what it holds.
    #[test]
    fn it_is_serialized_and_compared_as_it_is() {
        let secret = ProtectedString::new(SECRET);

        assert_eq!(
            serde_json::to_string(&secret).unwrap(),
            format!("\"{SECRET}\"")
        );

        let read: ProtectedString = serde_yaml::from_str(SECRET).unwrap();
        assert_eq!(read, secret);
        assert_ne!(read, ProtectedString::new("another"));
    }
}

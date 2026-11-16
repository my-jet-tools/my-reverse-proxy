use crate::required_headers::RequiredHeaders;

use super::ProtectedString;

/// The headers whose values are secrets, whatever endpoint they come to - written in lowercase,
/// and matched in every spelling an upstream reads as the same header
/// ([`crate::cloudflare::header_name_is`]: any letter case, `_` for `-`). The headers of
/// `request_with_header_only` of an endpoint are secrets as well: see [`HeaderValue::new`].
const PROTECTED_HEADERS: [&str; 5] = [
    // A key of `api_keys_auth`.
    crate::api_keys::API_KEY_HEADER,
    // Basic credentials, a bearer token - the access tokens the proxy's OAuth server mints too.
    "authorization",
    "proxy-authorization",
    // A session: the Google sign-in of the proxy is one.
    "cookie",
    "set-cookie",
];

/// The value of a header, as a log or a page takes it. It is made by the name of its header, in
/// [`HeaderValue::new`] - the one place which says whose values are secrets: such a value is a
/// [`ProtectedString`], and is written as `***`.
#[derive(Clone)]
pub enum HeaderValue {
    String(String),
    Protected(ProtectedString),
}

impl HeaderValue {
    /// `required`: the headers of `request_with_header_only` the header may be one of - of the
    /// endpoint of the request, or of every endpoint of the port while it is not known which one
    /// the request is of.
    pub fn new(name: &[u8], value: &[u8], required: &[&RequiredHeaders]) -> Self {
        let value = String::from_utf8_lossy(value).into_owned();

        let is_protected = PROTECTED_HEADERS
            .iter()
            .any(|header| crate::cloudflare::header_name_is(name, header))
            || required.iter().any(|required| required.covers(name));

        if is_protected {
            Self::Protected(value.into())
        } else {
            Self::String(value)
        }
    }
}

/// The value itself - `***` for a secret.
impl std::fmt::Display for HeaderValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String(value) => f.write_str(value),
            Self::Protected(_) => f.write_str(ProtectedString::MASK),
        }
    }
}

/// Quoted, as `{:?}` writes a header value of hyper - `"***"` for a secret.
impl std::fmt::Debug for HeaderValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String(value) => std::fmt::Debug::fmt(value, f),
            Self::Protected(value) => std::fmt::Debug::fmt(value, f),
        }
    }
}

/// The headers of a request or of a response, as a log or a page takes them: each value made by
/// [`HeaderValue::new`]. `{:?}` writes them the way it writes a `HeaderMap`.
pub struct HeaderList(Vec<(String, HeaderValue)>);

impl HeaderList {
    /// `required`: see [`HeaderValue::new`].
    pub fn new(headers: &hyper::HeaderMap, required: &[&RequiredHeaders]) -> Self {
        Self(
            headers
                .iter()
                .map(|(name, value)| {
                    let name = name.as_str();
                    let value = HeaderValue::new(name.as_bytes(), value.as_bytes(), required);
                    (name.to_string(), value)
                })
                .collect(),
        )
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &HeaderValue)> {
        self.0.iter().map(|(name, value)| (name.as_str(), value))
    }
}

impl std::fmt::Debug for HeaderList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "the-s3cr3t-value";

    fn headers(items: &[(&str, &str)]) -> hyper::HeaderMap {
        let mut headers = hyper::HeaderMap::new();

        for (name, value) in items {
            headers.append(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }

        headers
    }

    #[test]
    fn a_secret_header_is_written_as_masked_in_every_spelling() {
        let headers = headers(&[
            ("host", "api.example.com"),
            ("X-API-Key", SECRET),
            ("x_api_key", SECRET),
            ("authorization", SECRET),
            ("proxy-authorization", SECRET),
            ("cookie", SECRET),
            ("set-cookie", SECRET),
            ("x-api-keys", "not-a-secret"),
        ]);

        let list = HeaderList::new(&headers, &[]);
        let line = format!("{list:?}");

        assert!(!line.contains(SECRET), "{line}");
        assert!(line.contains("\"x-api-key\": \"***\""), "{line}");
        assert!(line.contains("\"x_api_key\": \"***\""), "{line}");
        assert!(line.contains("\"authorization\": \"***\""), "{line}");
        assert!(line.contains("\"cookie\": \"***\""), "{line}");
        assert!(line.contains("\"host\": \"api.example.com\""), "{line}");
        assert!(line.contains("\"x-api-keys\": \"not-a-secret\""), "{line}");

        for (name, value) in list.iter() {
            assert!(!value.to_string().contains(SECRET), "{name}: {value}");
        }
    }

    /// A header of `request_with_header_only` is a secret where the settings name it.
    #[test]
    fn a_required_header_is_written_as_masked() {
        let settings: crate::settings::RequestWithHeaderOnlySettings =
            serde_yaml::from_str(&format!("- X-Zone-Secret: {SECRET}")).unwrap();
        let required = RequiredHeaders::compile(Some(&settings)).unwrap();

        let headers = headers(&[("x-zone-secret", SECRET), ("x-zone_secret", SECRET)]);

        let line = format!("{:?}", HeaderList::new(&headers, &[&required]));
        assert!(!line.contains(SECRET), "{line}");
        assert!(line.contains("\"x-zone-secret\": \"***\""), "{line}");
        assert!(line.contains("\"x-zone_secret\": \"***\""), "{line}");

        // Not where they do not.
        let line = format!("{:?}", HeaderList::new(&headers, &[]));
        assert!(line.contains(SECRET), "{line}");
    }
}

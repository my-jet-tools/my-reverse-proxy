//! `request_with_header_only:` of an endpoint: the headers, each with the one value it has to
//! have, which every request to the endpoint comes with.
//!
//! ```yaml
//! hosts:
//!   api.example.com:443:
//!     endpoint:
//!       type: https2
//!       cloudflare: true
//!       request_with_header_only:
//!       - X-Zone-Secret: ${zone_secret}
//! ```
//!
//! Made for an endpoint behind Cloudflare: a rule of the zone writes the header into every request
//! it sends to the origin, and a request which reached the origin through Cloudflare some other
//! way - a Worker of another account names any `Host` it likes, and comes from the very networks
//! of Cloudflare - can not know it.
//!
//! - A request without one of the headers, with one of them twice, or with another value is taken
//!   for a break-in: the connection is closed without a word, and the request is journaled (see
//!   [`crate::cloudflare::DeviationJournal`]) - with the name of the header, never a value.
//! - A header is looked for by its name in any case, and in no other spelling (`X_Zone_Secret`):
//!   Cloudflare passes on what a visitor sends under such a name, and a visitor must not make a
//!   request look like one with the header twice - and so close a connection Cloudflare carries
//!   the requests of other visitors on.
//! - The headers are the proxy's alone: none of them reaches an upstream, in no spelling an
//!   upstream could read as it. A value is a [`ProtectedString`] from the settings on, and so is a
//!   header of a request under one of the names wherever the headers are logged
//!   ([`crate::types::HeaderList`]): it is written as `***`.
//!
//! A byte bridge (`type: tcp`, `type: mcp`) reads no headers: with the setting it serves nobody.

use crate::cloudflare::{header_name_is, Deviation, RequestClient};
use crate::configurations::HttpEndpointInfo;
use crate::settings::RequestWithHeaderOnlySettings;
use crate::types::{ConnectionIp, ProtectedString};

/// Headers which can not be required (as [`header_name_is`] takes a name): a request can not go
/// on without them - they carry its host, its body, its connection -, or the proxy writes them
/// itself, or their value is never the same twice.
const NOT_REQUIRABLE: [&str; 18] = [
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "upgrade",
    "te",
    "trailer",
    "expect",
    "cookie",
    "x-forwarded-for",
    "x-real-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "cf-connecting-ipv6",
    "cf-ipcountry",
    crate::forwarded_user::HEADER,
];

#[derive(Clone)]
struct RequiredHeader {
    /// As the settings name it, in lowercase: a header of a request is it in any case.
    name: String,
    /// The same, as [`header_name_is`] takes it: with `-` for `_`.
    read_as: String,
    value: ProtectedString,
}

/// `request_with_header_only:` of an endpoint, compiled. Empty: every request goes on.
#[derive(Clone, Default)]
pub struct RequiredHeaders {
    headers: Vec<RequiredHeader>,
}

impl RequiredHeaders {
    /// `settings`, with the variables already put in. Refused: a header which no request could
    /// ever come with, and one which can not be taken away from a request. An error names the
    /// header, and never tells its value.
    pub fn compile(settings: Option<&RequestWithHeaderOnlySettings>) -> Result<Self, String> {
        let mut headers: Vec<RequiredHeader> = Vec::new();

        for (name, value) in settings.into_iter().flat_map(|settings| settings.iter()) {
            if !is_token(name) {
                return Err(format!(
                    "request_with_header_only: {name:?} is not a header name"
                ));
            }

            let name = name.to_ascii_lowercase();
            let read_as = name.replace('_', "-");

            if NOT_REQUIRABLE.contains(&read_as.as_str()) {
                return Err(format!(
                    "request_with_header_only: '{name}' can not be required - a request can not \
                     go on without it, or the proxy writes it itself"
                ));
            }

            if headers.iter().any(|header| header.read_as == read_as) {
                return Err(format!("request_with_header_only: '{name}' is named twice"));
            }

            if value.is_empty() {
                return Err(format!(
                    "request_with_header_only: the value of '{name}' is empty"
                ));
            }

            // A variable is lower_cased: `${ZONE_SECRET}` is not put in, and would be the value.
            if value.as_str().contains("${") {
                return Err(format!(
                    "request_with_header_only: the value of '{name}' has a placeholder which is \
                     not put in - a variable of the settings is written lower_cased: ${{name}}"
                ));
            }

            if !is_header_value(value.as_bytes()) {
                return Err(format!(
                    "request_with_header_only: the value of '{name}' can not come in a header - \
                     it has to be visible ASCII, with spaces only inside it"
                ));
            }

            headers.push(RequiredHeader {
                name,
                read_as,
                value: value.clone(),
            });
        }

        Ok(Self { headers })
    }

    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// The names of the headers, lowercase, in the order of the settings - never their values.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.headers.iter().map(|header| header.name.as_str())
    }

    /// What is wrong with a request - `None`: nothing. `headers` gives the headers of the request,
    /// each as its name and its value, as they came.
    pub fn deviation<'h, I>(&self, headers: impl Fn() -> I) -> Option<Deviation>
    where
        I: Iterator<Item = (&'h [u8], &'h [u8])>,
    {
        for header in &self.headers {
            let mut values = headers()
                .filter(|(name, _)| name.eq_ignore_ascii_case(header.name.as_bytes()))
                .map(|(_, value)| value);

            let Some(value) = values.next() else {
                return Some(Deviation::MissingRequiredHeader(header.name.clone()));
            };

            if values.next().is_some() {
                return Some(Deviation::SeveralRequiredHeader(header.name.clone()));
            }

            if !crate::oauth::constant_time_eq(value.trim_ascii(), header.value.as_bytes()) {
                return Some(Deviation::WrongRequiredHeader(header.name.clone()));
            }
        }

        None
    }

    /// Whether a request header named `name` is one of them, in any spelling an upstream could
    /// read as it ([`header_name_is`]): it never goes on to an upstream, and its value is logged
    /// as `***` ([`crate::types::HeaderValue::new`]).
    pub fn covers(&self, name: &[u8]) -> bool {
        self.headers
            .iter()
            .any(|header| header_name_is(name, &header.read_as))
    }
}

impl std::fmt::Debug for RequiredHeaders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map()
            .entries(self.headers.iter().map(|header| (&header.name, &header.value)))
            .finish()
    }
}

/// [`RequiredHeaders::deviation`] of `endpoint` for a request of `client` on a connection from
/// `peer`, journaled. Whether the request goes on - `false`: the connection is to be closed
/// without a word. `host`: what the request named, by its uri or by `Host`.
pub fn request_may_go_on<'h, I>(
    endpoint: &HttpEndpointInfo,
    peer: &ConnectionIp,
    client: &RequestClient,
    host: Option<&[u8]>,
    headers: impl Fn() -> I,
) -> bool
where
    I: Iterator<Item = (&'h [u8], &'h [u8])>,
{
    let Some(deviation) = endpoint.request_with_header_only.deviation(headers) else {
        return true;
    };

    crate::cloudflare::journal_request(endpoint.as_str(), peer, client, host, deviation);
    false
}

/// A header name of RFC 9110: one or more `tchar`.
fn is_token(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

/// A value which comes in a header as it is: visible ASCII, with spaces and tabs only inside it -
/// the ones at its ends are not of the value.
fn is_header_value(value: &[u8]) -> bool {
    let is_space = |byte: &u8| matches!(byte, b' ' | b'\t');

    !value.first().is_some_and(is_space)
        && !value.last().is_some_and(is_space)
        && value
            .iter()
            .all(|byte| (0x21..0x7f).contains(byte) || is_space(byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "s3cr3t-0123456789abcdef";

    fn settings(yaml: &str) -> RequestWithHeaderOnlySettings {
        my_settings_reader::serde_yaml::from_str(yaml).unwrap()
    }

    fn compile(yaml: &str) -> Result<RequiredHeaders, String> {
        RequiredHeaders::compile(Some(&settings(yaml)))
    }

    fn zone_secret() -> RequiredHeaders {
        compile(&format!("- X-Zone-Secret: {SECRET}\n")).unwrap()
    }

    fn deviation_of(required: &RequiredHeaders, headers: &[(&str, &str)]) -> Option<Deviation> {
        required.deviation(|| {
            headers
                .iter()
                .map(|(name, value)| (name.as_bytes(), value.as_bytes()))
        })
    }

    #[test]
    fn no_setting_lets_every_request_go_on() {
        let required = RequiredHeaders::compile(None).unwrap();

        assert!(required.is_empty());
        assert_eq!(deviation_of(&required, &[]), None);
        assert!(!required.covers(b"x-zone-secret"));
    }

    #[test]
    fn a_request_with_the_header_goes_on() {
        let required = zone_secret();

        assert_eq!(deviation_of(&required, &[("X-Zone-Secret", SECRET)]), None);
        // In any case, and with the whitespace an h1 value comes with.
        assert_eq!(
            deviation_of(&required, &[("x-zone-secret", &format!(" {SECRET}\t"))]),
            None
        );
    }

    #[test]
    fn a_request_without_the_header_or_with_another_value_does_not() {
        let required = zone_secret();
        let missing = Some(Deviation::MissingRequiredHeader(
            "x-zone-secret".to_string(),
        ));
        let wrong = Some(Deviation::WrongRequiredHeader("x-zone-secret".to_string()));

        assert_eq!(deviation_of(&required, &[]), missing);
        assert_eq!(deviation_of(&required, &[("X-Other", SECRET)]), missing);
        assert_eq!(
            deviation_of(&required, &[("X-Zone-Secret", "guess")]),
            wrong
        );
        assert_eq!(deviation_of(&required, &[("X-Zone-Secret", "")]), wrong);
        assert_eq!(
            deviation_of(&required, &[("X-Zone-Secret", &SECRET.to_uppercase())]),
            wrong
        );
        assert_eq!(
            deviation_of(
                &required,
                &[("X-Zone-Secret", &format!("{SECRET}, {SECRET}"))]
            ),
            wrong
        );
    }

    #[test]
    fn a_request_with_the_header_twice_does_not() {
        assert_eq!(
            deviation_of(
                &zone_secret(),
                &[("X-Zone-Secret", SECRET), ("x-zone-secret", SECRET)]
            ),
            Some(Deviation::SeveralRequiredHeader(
                "x-zone-secret".to_string()
            ))
        );
    }

    /// A visitor of the zone may send `X_Zone_Secret`, and Cloudflare passes it on next to the
    /// header its rule writes: it is not the header, so it is no second one - it is only never
    /// sent on.
    #[test]
    fn the_name_in_another_spelling_is_not_the_header_but_is_covered() {
        let required = zone_secret();

        assert_eq!(
            deviation_of(&required, &[("X_Zone_Secret", SECRET)]),
            Some(Deviation::MissingRequiredHeader(
                "x-zone-secret".to_string()
            ))
        );
        assert_eq!(
            deviation_of(
                &required,
                &[("X-Zone-Secret", SECRET), ("X_Zone_Secret", "anything")]
            ),
            None
        );

        for name in [
            "X-Zone-Secret",
            "x-zone-secret",
            "X_ZONE_SECRET",
            " X-Zone-Secret ",
        ] {
            assert!(required.covers(name.as_bytes()), "{name}");
        }

        assert!(!required.covers(b"X-Zone-Secrets"));
        assert!(!required.covers(b"X-Zone"));
    }

    #[test]
    fn every_header_of_every_item_is_required() {
        let required =
            compile("- X-Zone-Secret: one-value\n- X-Second: two\n  X-Third: three\n").unwrap();

        let all = [
            ("X-Zone-Secret", "one-value"),
            ("X-Second", "two"),
            ("X-Third", "three"),
        ];
        assert_eq!(deviation_of(&required, &all), None);
        assert_eq!(
            deviation_of(&required, &all[..2]),
            Some(Deviation::MissingRequiredHeader("x-third".to_string()))
        );
    }

    #[test]
    fn a_name_written_with_an_underscore_is_looked_for_as_it_is_written() {
        let required = compile("- X_Zone_Secret: value\n").unwrap();

        assert_eq!(deviation_of(&required, &[("x_zone_secret", "value")]), None);
        assert_eq!(
            deviation_of(&required, &[("X-Zone-Secret", "value")]),
            Some(Deviation::MissingRequiredHeader(
                "x_zone_secret".to_string()
            ))
        );
        assert!(required.covers(b"X-Zone-Secret"));
        assert!(required.covers(b"X_Zone_Secret"));
    }

    #[test]
    fn what_no_request_could_pass_does_not_compile() {
        for (yaml, expected) in [
            ("- \"X Zone\": value\n", "is not a header name"),
            ("- \"X-Zone:\": value\n", "is not a header name"),
            ("- \"\": value\n", "is not a header name"),
            ("- X-Zone-Secret: \"\"\n", "is empty"),
            ("- X-Zone-Secret: ${ZONE_SECRET}\n", "has a placeholder"),
            ("- X-Zone-Secret: \" value\"\n", "can not come in a header"),
            ("- X-Zone-Secret: \"value \"\n", "can not come in a header"),
            (
                "- X-Zone-Secret: \"va\\nlue\"\n",
                "can not come in a header",
            ),
            ("- X-Zone-Secret: \"знач\"\n", "can not come in a header"),
            (
                "- X-Zone-Secret: one\n- x-zone-secret: two\n",
                "is named twice",
            ),
            (
                "- X-Zone-Secret: one\n- X_Zone_Secret: two\n",
                "is named twice",
            ),
        ] {
            let err = compile(yaml)
                .err()
                .unwrap_or_else(|| panic!("{yaml} compiled"));
            assert!(err.contains(expected), "{yaml}: {err}");
        }

        // Spaces inside a value are of it.
        assert!(compile("- X-Zone-Secret: \"Bearer value\"\n").is_ok());
    }

    #[test]
    fn a_header_a_request_can_not_go_without_can_not_be_required() {
        for name in [
            "Host",
            "Content-Length",
            "Transfer_Encoding",
            "Connection",
            "Cookie",
            "X-Forwarded-For",
            "CF-Connecting-IP",
            "X-Forwarded-User",
        ] {
            let err = compile(&format!("- {name}: value\n")).unwrap_err();
            assert!(err.contains("can not be required"), "{name}: {err}");
        }
    }

    #[test]
    fn an_error_never_tells_the_value() {
        for yaml in [
            format!("- X-Zone-Secret: \"{SECRET} \"\n"),
            format!("- X-Zone-Secret: {SECRET}\n- X_Zone_Secret: {SECRET}\n"),
            format!("- Host: {SECRET}\n"),
        ] {
            let err = compile(&yaml).unwrap_err();
            assert!(!err.contains(SECRET), "{err}");
        }
    }

    #[test]
    fn a_value_is_logged_as_masked() {
        let required = zone_secret();

        let debug = format!("{required:?}");
        assert!(!debug.contains(SECRET), "{debug}");
        assert!(debug.contains("\"x-zone-secret\": \"***\""), "{debug}");

        // A header of a request under one of the names: see `crate::types::HeaderList`.
    }
}

//! `X-Forwarded-User`: who a request is of, as the proxy tells it to the upstream.
//!
//! It is the CN of a client certificate the endpoint's `client_certificate_ca` verified, or the
//! email of a Google sign-in (`google_auth`) - the identity `allowed_users` checks. The header is
//! always the proxy's own, on every http endpoint type and whatever the settings say: what the
//! client sent under that name is removed, `modify_http_headers` can not add it, and a request
//! with no such user reaches the upstream without one.

use crate::http_proxy_pass::HttpProxyPassIdentity;

/// The name, in lowercase: as every h2 header name is, and as hyper's `HeaderName::from_static`
/// takes it.
pub const HEADER: &str = "x-forwarded-user";

/// Whether an upstream could read a header named `name` as [`HEADER`] - one a client sent, to be
/// removed, or one `modify_http_headers` would add, to be ignored. Not only the name in any case:
/// also with whitespace around it (`X-Forwarded-User :`, which HTTP/1.1 forbids and a lenient
/// server trims) and with `_` for `-` (`X_Forwarded_User`, which CGI-style servers - PHP, WSGI,
/// Rack - read as the very same `HTTP_X_FORWARDED_USER`).
pub fn is_header_name(name: &[u8]) -> bool {
    let name = name.trim_ascii();

    name.len() == HEADER.len()
        && name.iter().zip(HEADER.as_bytes()).all(|(&byte, &expected)| {
            let byte = match byte {
                b'_' => b'-',
                byte => byte.to_ascii_lowercase(),
            };
            byte == expected
        })
}

/// What goes in [`HEADER`] for `identity`. `None` - the request goes without the header - when
/// the name can not travel in a header as it is: empty, with a control character (a CR or LF
/// would end the header and start another one), or with a space at an end, which a reader trims
/// off (` admin` would arrive as `admin`). A Google email is never such; the CN of a certificate
/// is whatever its ca wrote.
pub fn value_of(identity: &HttpProxyPassIdentity) -> Option<&str> {
    let value = identity.as_str();
    let bytes = value.as_bytes();

    let fits = !bytes.is_empty()
        && bytes.iter().all(|&byte| byte >= 0x20 && byte != 0x7f)
        && !bytes.starts_with(b" ")
        && !bytes.ends_with(b" ");

    fits.then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Email;

    fn user(name: &str) -> HttpProxyPassIdentity {
        HttpProxyPassIdentity::GoogleUser(Email::new(name.to_string()))
    }

    #[test]
    fn the_name_is_found_in_every_spelling_an_upstream_could_read_as_it() {
        for name in [
            "x-forwarded-user",
            "X-Forwarded-User",
            "X-FORWARDED-USER",
            "X_Forwarded_User",
            "x_forwarded-user",
            "X-Forwarded-User ",
            " X-Forwarded-User",
            "X-Forwarded-User\t",
        ] {
            assert!(is_header_name(name.as_bytes()), "{name:?}");
        }

        for name in [
            "x-forwarded-for",
            "x-forwarded-users",
            "x-forwarded-use",
            "forwarded-user",
            "x-forwarded user",
            "",
        ] {
            assert!(!is_header_name(name.as_bytes()), "{name:?}");
        }
    }

    #[test]
    fn a_name_which_can_not_travel_in_a_header_as_it_is_is_not_sent() {
        assert_eq!(
            value_of(&user("someone@example.com")),
            Some("someone@example.com")
        );
        assert_eq!(value_of(&user("Иван Петров")), Some("Иван Петров"));

        for name in [
            "",
            "admin\r\nX-Admin: 1",
            "admin\n",
            "a\tb",
            "a\u{7f}b",
            " admin",
            "admin ",
        ] {
            assert_eq!(value_of(&user(name)), None, "{name:?}");
        }
    }
}

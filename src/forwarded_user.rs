//! `X-Forwarded-User` and `X-Forwarded-ClientCertId`: who a request is of, as the proxy tells it
//! to the upstream.
//!
//! `X-Forwarded-User` is the CN of a client certificate the endpoint's `client_certificate_ca`
//! verified, or the email of a Google sign-in (`google_auth`) - the identity `allowed_users`
//! checks. `X-Forwarded-ClientCertId` goes with it when that identity is a client certificate:
//! the serial of the certificate, in decimal - the id ca-api gives it. The headers are always the
//! proxy's own, on every http endpoint type and whatever the settings say: what the client sent
//! under those names is removed, `modify_http_headers` can not add them, and a request with no
//! such user reaches the upstream without them.

use crate::http_proxy_pass::HttpProxyPassIdentity;

/// The name, in lowercase: as every h2 header name is, and as hyper's `HeaderName::from_static`
/// takes it.
pub const HEADER: &str = "x-forwarded-user";

/// `X-Forwarded-ClientCertId`, in lowercase like [`HEADER`].
pub const CLIENT_CERT_ID_HEADER: &str = "x-forwarded-clientcertid";

/// Whether an upstream could read a header named `name` as [`HEADER`] or
/// [`CLIENT_CERT_ID_HEADER`] - one a client sent, to be removed, or one `modify_http_headers`
/// would add, to be ignored. Not only the name in any case: also with whitespace around it
/// (`X-Forwarded-User :`, which HTTP/1.1 forbids and a lenient server trims) and with `_` for `-`
/// (`X_Forwarded_User`, which CGI-style servers - PHP, WSGI, Rack - read as the very same
/// `HTTP_X_FORWARDED_USER`).
pub fn is_header_name(name: &[u8]) -> bool {
    let name = name.trim_ascii();

    reads_as(name, HEADER) || reads_as(name, CLIENT_CERT_ID_HEADER)
}

/// Whether `name` is `header` (lowercase, with `-`) in any case and with `_` for `-`.
fn reads_as(name: &[u8], header: &str) -> bool {
    name.len() == header.len()
        && name
            .iter()
            .zip(header.as_bytes())
            .all(|(&byte, &expected)| {
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

/// What goes in [`CLIENT_CERT_ID_HEADER`] for `identity`: the serial of its client certificate,
/// in decimal - only digits, so it always travels, even when the CN does not. `None` - the
/// request goes without the header - for a Google sign-in: the header tells which certificate the
/// user is, so it is there only when the user is a certificate.
pub fn client_cert_id_of(identity: &HttpProxyPassIdentity) -> Option<&str> {
    match identity {
        HttpProxyPassIdentity::ClientCert(certificate) => Some(certificate.serial.as_str()),
        HttpProxyPassIdentity::GoogleUser(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::tcp_listener::https::ClientCertificateData;
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
            "x-forwarded-clientcertid",
            "X-Forwarded-ClientCertId",
            "X-FORWARDED-CLIENTCERTID",
            "X_Forwarded_ClientCertId",
            "X-Forwarded-ClientCertId ",
            " X-Forwarded-ClientCertId",
        ] {
            assert!(is_header_name(name.as_bytes()), "{name:?}");
        }

        for name in [
            "x-forwarded-for",
            "x-forwarded-users",
            "x-forwarded-use",
            "forwarded-user",
            "x-forwarded user",
            "x-forwarded-clientcertids",
            "x-forwarded-clientcert",
            "x-forwarded-client-certid",
            "",
        ] {
            assert!(!is_header_name(name.as_bytes()), "{name:?}");
        }
    }

    #[test]
    fn the_client_cert_id_is_the_serial_of_a_certificate_and_of_nobody_else() {
        let certificate = |cn: &str| {
            HttpProxyPassIdentity::ClientCert(Arc::new(ClientCertificateData {
                cn: cn.to_string(),
                serial: "42".to_string(),
                ca_id: "ca".to_string(),
                accepted_outside_validity: false,
            }))
        };

        assert_eq!(client_cert_id_of(&certificate("partner")), Some("42"));
        // A CN which can not travel keeps out `X-Forwarded-User` only.
        assert_eq!(value_of(&certificate("partner\r\n")), None);
        assert_eq!(client_cert_id_of(&certificate("partner\r\n")), Some("42"));
        assert_eq!(client_cert_id_of(&certificate("")), Some("42"));

        assert_eq!(client_cert_id_of(&user("someone@example.com")), None);
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

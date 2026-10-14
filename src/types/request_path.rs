use std::borrow::Cow;

/// `true`: the path has a segment which may be resolved away on the way to the resource - `..`,
/// `.` or an empty one - written as it is or percent-encoded.
///
/// A location is picked by what the request path starts with, and the rules of the location -
/// its `auth_header`, its `whitelisted_ip` - are the rules of the request. The path goes on to
/// the upstream as it was received, and an upstream resolves such segments: `/open/../secure/x`
/// is picked by the location `/open` and is `/secure/x` to the upstream - served past the rules
/// of the location `/secure`. `//secure/x` and `/./secure/x` get past them the same way. So a
/// request is taken only when its path names the resource in one way; any other is answered 400
/// before a location is looked for.
///
/// `path`: the request path as received - not decoded, without the query string. It is decoded
/// for the check only, and once. A backslash is taken for a separator as well: there are
/// upstreams to which it is one. What follows a `;` in a segment is left out: `..;` is `..` to
/// an upstream which takes the path parameters off first.
///
/// A path which does not start with `/` - `*`, `host:443`, `http://host/x` - is not looked at:
/// every location starts with `/`, so such a path is matched by none.
pub fn has_ambiguous_segment(path: &str) -> bool {
    if !path.starts_with('/') {
        return false;
    }

    let decoded = percent_decode_once(path.as_bytes());

    let mut segments = decoded[1..].split(|b| *b == b'/' || *b == b'\\').peekable();

    while let Some(segment) = segments.next() {
        // The last segment may be empty: `/api/`.
        if segment.is_empty() {
            if segments.peek().is_some() {
                return true;
            }

            continue;
        }

        let name = match segment.iter().position(|b| *b == b';') {
            Some(parameters) => &segment[..parameters],
            None => segment,
        };

        if name == b"." || name == b".." {
            return true;
        }
    }

    false
}

/// Whether a request with this target is a request of the location with the path
/// `location_path`: the path of the request starts with it, letters compared without their case.
///
/// Both are compared decoded - one pass. An upstream decodes a path, so `/%73ecure/x` is
/// `/secure/x` to it: picked by the path as it is written, such a request would go to another
/// location and be served past the rules of the location `/secure`. The path which goes on to
/// the upstream stays as it was received.
///
/// `target`: the request target as received - the query string, when there is one, is cut off
/// here.
pub fn is_path_of_location(target: &str, location_path: &str) -> bool {
    let path = match target.find(['?', '#']) {
        Some(end) => &target[..end],
        None => target,
    };

    let path = percent_decode_once(path.as_bytes());
    let location_path = percent_decode_once(location_path.as_bytes());

    match path.get(..location_path.len()) {
        Some(start) => start.eq_ignore_ascii_case(&location_path),
        None => false,
    }
}

/// A request path as it goes into a log line or to stdout: escaped the way `{:?}` does it, and
/// cut at 200 bytes.
///
/// The path is what the client sent, whole and as it is. A line break in it would start a line
/// of its own in a log, an escape sequence would be played by the terminal the log is read in,
/// and it can be as long as a request line can.
pub fn path_for_log(path: &str) -> String {
    const MAX_LEN: usize = 200;

    if path.len() <= MAX_LEN {
        return format!("{path:?}");
    }

    let mut end = MAX_LEN;
    while !path.is_char_boundary(end) {
        end -= 1;
    }

    format!("{:?}... ({} bytes)", &path[..end], path.len())
}

/// One pass: `%XX` with two hex digits becomes the byte, anything else stays as it is - no `+`
/// for a space, no second pass. `url_utils::decode_from_url_string` is not used on purpose: on
/// an escape it can not read it gives the whole string back as it was, so one `%zz` would hide
/// a `%2e%2e` next to it.
pub fn percent_decode_once(src: &[u8]) -> Cow<'_, [u8]> {
    if !src.contains(&b'%') {
        return Cow::Borrowed(src);
    }

    let mut result = Vec::with_capacity(src.len());
    let mut i = 0;

    while i < src.len() {
        if src[i] == b'%' && i + 2 < src.len() {
            if let (Some(high), Some(low)) = (hex_digit(src[i + 1]), hex_digit(src[i + 2])) {
                result.push(high << 4 | low);
                i += 3;
                continue;
            }
        }

        result.push(src[i]);
        i += 1;
    }

    Cow::Owned(result)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{has_ambiguous_segment, is_path_of_location, path_for_log};

    #[test]
    fn a_path_goes_to_a_log_escaped_and_cut() {
        assert_eq!(path_for_log("/index.html"), "\"/index.html\"");
        assert_eq!(
            path_for_log("/a\r\nFAKE LOG LINE\x1b[31m"),
            "\"/a\\r\\nFAKE LOG LINE\\u{1b}[31m\""
        );

        let long = format!("/{}", "a".repeat(5000));
        let logged = path_for_log(&long);
        assert_eq!(logged, format!("\"/{}\"... (5001 bytes)", "a".repeat(199)));

        // Cut between letters, not through one.
        let long = format!("/{}", "\u{20ac}".repeat(100));
        let logged = path_for_log(&long);
        assert!(logged.ends_with("\"... (301 bytes)"), "{logged}");
        assert_eq!(logged.matches('\u{20ac}').count(), 66);
    }

    #[test]
    fn a_location_is_picked_by_the_decoded_path() {
        for target in [
            "/secure",
            "/secure/x",
            "/secure/x?v=1",
            "/SECURE/x",
            "/secureX",
            "/%73ecure/x",
            "/%53ecure/x",
            "/s%65cur%65/x",
            "/%73%65%63%75%72%65/x",
            "/%73ecure?v=1",
        ] {
            assert!(is_path_of_location(target, "/secure"), "{target}");
        }

        for target in [
            "/",
            "/secur",
            "/open/secure",
            "/open?next=/secure",
            "/open#/secure",
            // Decoded once: this is the name `%73ecure`.
            "/%2573ecure/x",
            "/%7",
            "*",
        ] {
            assert!(!is_path_of_location(target, "/secure"), "{target}");
        }

        // Every path is a path of the location `/`.
        for target in ["/", "/x", "/%73ecure/x", "/?v=1"] {
            assert!(is_path_of_location(target, "/"), "{target}");
        }
    }

    /// A location path written with an escape is the same path as one written without it.
    #[test]
    fn a_location_path_is_decoded_as_well() {
        assert!(is_path_of_location("/my%20docs/x", "/my%20docs"));
        assert!(is_path_of_location("/my%20docs/x", "/my docs"));
        assert!(!is_path_of_location("/my-docs/x", "/my%20docs"));
    }

    /// The request path is cut by bytes: a letter of several bytes is not cut through.
    #[test]
    fn a_path_which_is_not_ascii_is_compared_by_bytes() {
        assert!(!is_path_of_location("/\u{20ac}", "/x"));
        assert!(!is_path_of_location("/\u{20ac}uro", "/xy"));
        assert!(is_path_of_location("/\u{20ac}uro/x", "/\u{20ac}uro"));
        assert!(is_path_of_location("/%E2%82%ACuro/x", "/\u{20ac}uro"));
    }

    #[test]
    fn a_path_which_names_its_resource_in_one_way_passes() {
        for path in [
            "/",
            "/index.html",
            "/api/v1/users",
            "/api/",
            "/a/b/",
            "/.well-known/acme-challenge/x",
            "/.env",
            "/a..b",
            "/..a",
            "/a..",
            "/a../b",
            "/...",
            "/.../x",
            "/a.",
            "/.a",
            "/file%20name.txt",
            "/100%.txt",
            "/a%2",
            "/a%",
            "/%zz",
            "/a%2fb",
            "/a\\b",
            "/users;id=5/orders",
            "/;id=5",
            "/a;..",
            "/файл.txt",
            "/%D1%84.txt",
            // Encoded twice: after the one pass it is a name, not a segment.
            "/%252e%252e/secure",
            "/%252fsecure",
        ] {
            assert!(!has_ambiguous_segment(path), "{path}");
        }
    }

    #[test]
    fn a_parent_segment_is_found_however_it_is_written() {
        for path in [
            "/..",
            "/../",
            "/open/../secure/x",
            "/open/..",
            "/open/%2e%2e/secure/x",
            "/open/%2E%2E/secure/x",
            "/open/.%2e/secure/x",
            "/open/%2e./secure/x",
            "/open/..%2fsecure/x",
            "/open/..%2Fsecure/x",
            "/open%2f..%2fsecure/x",
            "/open/..\\secure/x",
            "/open\\..\\secure\\x",
            "/open/..%5csecure/x",
            "/open/..%5Csecure/x",
            // To an upstream which takes path parameters off first this is `..`.
            "/open/..;/secure/x",
            "/open/..;a=b/secure/x",
            "/open/%2e%2e;/secure/x",
            "/open/..%3b/secure/x",
            // A `%` which starts no escape does not hide the escape next to it.
            "/%zz/%2e%2e/secure/x",
        ] {
            assert!(has_ambiguous_segment(path), "{path}");
        }
    }

    #[test]
    fn a_segment_which_changes_nothing_is_found() {
        for path in [
            "//",
            "//secure/x",
            "///secure/x",
            "/open//secure/x",
            "/%2fsecure/x",
            "/%2Fsecure/x",
            "/\\secure/x",
            "/%5csecure/x",
            "/open//",
            "/.",
            "/./",
            "/./secure/x",
            "/open/./secure/x",
            "/open/.",
            "/%2e/secure/x",
            "/%2E/secure/x",
            "/.;/secure/x",
            "/.;a=b/secure/x",
        ] {
            assert!(has_ambiguous_segment(path), "{path}");
        }
    }

    /// No location starts with anything but `/`: such a path is matched by none.
    #[test]
    fn a_path_which_is_not_origin_form_is_not_looked_at() {
        for path in ["*", "host:443", "http://host/a/../b", "", "..", "a//b"] {
            assert!(!has_ambiguous_segment(path), "{path}");
        }
    }
}

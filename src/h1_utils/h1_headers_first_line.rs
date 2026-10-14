pub struct H1HeadersFirstLine<'s> {
    pub data: &'s [u8],
}

/// The method and the target of a request line: `METHOD SP target SP version`.
///
/// `None`: the line is not made this way. `verify_http11_first_line` lets no such request line
/// in - but a line is cut by what is in it, not by what the check before it promised: the same
/// reader takes a status line (`HTTP/1.1 200 OK`), and a client can send one.
pub fn split_request_line(line: &[u8]) -> Option<(&str, &str)> {
    let line = std::str::from_utf8(line).ok()?;

    let mut parts = line.splitn(3, ' ');

    let method = parts.next()?;
    let target = parts.next()?;
    parts.next()?;

    Some((method, target))
}

impl<'s> H1HeadersFirstLine<'s> {
    pub fn get_path_and_query(&self) -> &'s str {
        self.get_verb_and_path().1
    }

    /// A line which is not a request line has no verb and no target: both are empty, and an
    /// empty target is a path of no location.
    pub fn get_verb_and_path(&self) -> (&'s str, &'s str) {
        split_request_line(self.data).unwrap_or(("", ""))
    }

    /// Verb, path and query string. `?` starts the query; a fragment is cut off, as hyper does.
    pub fn get_verb_path_and_query(&self) -> (&'s str, &'s str, Option<&'s str>) {
        let (verb, target) = self.get_verb_and_path();

        let target = match target.find('#') {
            Some(index) => &target[..index],
            None => target,
        };

        match target.find('?') {
            Some(index) => (verb, &target[..index], Some(&target[index + 1..])),
            None => (verb, target, None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_split(line: &str, expected: (&str, &str, Option<&str>)) {
        let first_line = H1HeadersFirstLine {
            data: line.as_bytes(),
        };

        assert_eq!(first_line.get_verb_path_and_query(), expected, "{line}");
    }

    #[test]
    fn the_query_string_is_not_a_part_of_the_path() {
        assert_split(
            "GET /index.html?v=1 HTTP/1.1",
            ("GET", "/index.html", Some("v=1")),
        );
        assert_split("GET / HTTP/1.1", ("GET", "/", None));
        assert_split("POST /../x?y HTTP/1.1", ("POST", "/../x", Some("y")));

        // The query starts at the first `?`.
        assert_split("GET /a?b?c HTTP/1.1", ("GET", "/a", Some("b?c")));
    }

    #[test]
    fn the_root_with_a_query_string_is_the_root() {
        assert_split("GET /?utm=x HTTP/1.1", ("GET", "/", Some("utm=x")));
        assert_split("GET /? HTTP/1.1", ("GET", "/", Some("")));
    }

    #[test]
    fn a_fragment_is_cut_off() {
        assert_split("GET /a#frag HTTP/1.1", ("GET", "/a", None));
        assert_split("GET /a?b#frag HTTP/1.1", ("GET", "/a", Some("b")));
        assert_split("GET /a#frag?b HTTP/1.1", ("GET", "/a", None));
    }

    /// Nothing is decoded: an encoded `?` is a part of the name.
    #[test]
    fn an_encoded_question_mark_stays_in_the_path() {
        assert_split("GET /a%3Fb HTTP/1.1", ("GET", "/a%3Fb", None));
        assert_split("GET /a%3fb?c HTTP/1.1", ("GET", "/a%3fb", Some("c")));
    }

    /// A line which is not `METHOD SP target SP version` is read without a panic: it has no verb
    /// and no target.
    #[test]
    fn a_line_which_is_not_a_request_line_has_no_verb_and_no_target() {
        for line in [
            "GET\t/\tHTTP/1.1",
            "GET\t/ HTTP/1.1",
            "GET /\tHTTP/1.1",
            "GET /",
            "GET",
            "",
            "HTTP/1.1\t200\tOK",
        ] {
            let first_line = H1HeadersFirstLine {
                data: line.as_bytes(),
            };

            assert_eq!(first_line.get_verb_and_path(), ("", ""), "{line:?}");
            assert_eq!(first_line.get_path_and_query(), "", "{line:?}");
            assert_eq!(
                first_line.get_verb_path_and_query(),
                ("", "", None),
                "{line:?}"
            );
        }

        let not_utf8 = H1HeadersFirstLine {
            data: b"GET /\xff HTTP/1.1",
        };
        assert_eq!(not_utf8.get_verb_and_path(), ("", ""));
    }

    /// `get_verb_and_path` goes on giving the whole request target: the oauth gate splits it
    /// itself.
    #[test]
    fn the_verb_and_the_whole_target_are_still_there() {
        let first_line = H1HeadersFirstLine {
            data: b"GET /index.html?v=1 HTTP/1.1",
        };

        assert_eq!(first_line.get_verb_and_path(), ("GET", "/index.html?v=1"));
        assert_eq!(first_line.get_path_and_query(), "/index.html?v=1");
    }
}

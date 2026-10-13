use rust_extensions::slice_of_u8_utils::SliceOfU8Ext;

pub struct H1HeadersFirstLine<'s> {
    pub data: &'s [u8],
}

impl<'s> H1HeadersFirstLine<'s> {
    pub fn get_path_and_query(&self) -> &str {
        let index_start = self.data.find_byte_pos(b' ', 0).unwrap() + 1;
        let index_end = self.data.find_byte_pos(b' ', index_start).unwrap();

        std::str::from_utf8(&self.data[index_start..index_end]).unwrap()
    }

    pub fn get_verb_and_path(&self) -> (&str, &str) {
        let index_start = self.data.find_byte_pos(b' ', 0).unwrap();
        let index_end = self.data.find_byte_pos(b' ', index_start + 1).unwrap();

        let verb = std::str::from_utf8(&self.data[..index_start]).unwrap();
        let path = std::str::from_utf8(&self.data[index_start + 1..index_end]).unwrap();

        (verb, path)
    }

    /// Verb, path and query string. `?` starts the query; a fragment is cut off, as hyper does.
    pub fn get_verb_path_and_query(&self) -> (&str, &str, Option<&str>) {
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

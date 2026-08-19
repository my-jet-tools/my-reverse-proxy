use rust_extensions::slice_of_u8_utils::SliceOfU8Ext;
#[derive(Clone, Copy)]
pub struct HeaderPosition {
    pub start: usize,
    pub end: usize,
}

pub struct HttpHeader<'s> {
    payload: &'s [u8],
    header_start: usize,
    header_separator_index: usize,
    header_end: usize,
}

impl<'s> HttpHeader<'s> {
    pub fn new(payload: &'s [u8], header_start_pos: usize, header_end: usize) -> Option<Self> {
        let header_separator_index = payload.find_byte_pos(b':', header_start_pos)?;

        Self {
            payload,
            header_start: header_start_pos,
            header_separator_index,
            header_end,
        }
        .into()
    }
    pub fn is_my_header_name(&self, value: &[u8]) -> bool {
        if self.header_separator_index - self.header_start != value.len() {
            return false;
        }

        let header_name = &self.payload[self.header_start..self.header_separator_index];

        compare_case_insensitive(header_name, value)
    }

    /// Where the value starts: right after the colon, past the optional whitespace.
    /// HTTP allows none of it (`Name:value`) or several (`Name:\t  value`), so the
    /// separator is NOT always exactly ": " — assuming it dropped the first
    /// character of every space-less value (a `Content-Length:1024` was read as
    /// 24, truncating the relayed body) and went out of bounds on a valueless
    /// header (`Name:`), panicking the task that was parsing the head.
    fn value_start(&self) -> usize {
        let mut start = self.header_separator_index + 1;

        while start < self.header_end
            && (self.payload[start] == b' ' || self.payload[start] == b'\t')
        {
            start += 1;
        }

        start
    }

    pub fn get_value_as_str(&self) -> Option<&str> {
        let value = &self.payload[self.value_start()..self.header_end];

        match std::str::from_utf8(value) {
            Ok(value) => Some(value.trim()),
            Err(_) => None,
        }
    }

    pub fn get_value(&self) -> HeaderPosition {
        HeaderPosition {
            start: self.value_start(),
            end: self.header_end,
        }
    }

    pub fn get_usize_value(&self) -> Option<usize> {
        let value = self.get_value_as_str()?;
        match value.parse() {
            Ok(result) => Some(result),
            Err(_) => None,
        }
    }
}

/// Case-insensitive equality of two byte strings.
///
/// The length check is not an optimisation: iterating `right` and pulling from
/// `left` unconditionally panicked whenever `left` was shorter (a client sending
/// `Upgrade: h2c` — which is what curl does when it tries to upgrade a plaintext
/// connection to h2 — killed the task comparing it against "websocket"), and
/// returned true on a mere prefix whenever `left` was longer.
pub fn compare_case_insensitive(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    left.iter()
        .zip(right.iter())
        .all(|(l, r)| to_lower_case(*l) == to_lower_case(*r))
}

fn to_lower_case(b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' {
        return b - b'A' + b'a';
    }

    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tests() {
        assert_eq!(to_lower_case(b'A'), b'a');

        assert_eq!(to_lower_case(b'a'), b'a');
        assert_eq!(to_lower_case(b'Z'), b'z');
    }

    /// `header_end` is the end of the header line (its value, without the CRLF).
    fn header_of(line: &[u8]) -> HttpHeader<'_> {
        HttpHeader::new(line, 0, line.len()).unwrap()
    }

    /// The whitespace after the colon is optional in HTTP. Assuming exactly one
    /// dropped the first character of the value — for Content-Length that silently
    /// truncated the relayed body and desynced the connection.
    #[test]
    fn a_value_is_read_whatever_the_whitespace_after_the_colon() {
        assert_eq!(
            header_of(b"Content-Length: 1024").get_usize_value(),
            Some(1024)
        );
        assert_eq!(
            header_of(b"Content-Length:1024").get_usize_value(),
            Some(1024)
        );
        assert_eq!(
            header_of(b"Content-Length:\t  1024  ").get_usize_value(),
            Some(1024)
        );
    }

    /// A valueless header is legal and used to panic here: the value slice started
    /// one byte past its end.
    #[test]
    fn a_valueless_header_is_empty_rather_than_a_panic() {
        assert_eq!(header_of(b"X-Empty:").get_value_as_str(), Some(""));
        assert_eq!(header_of(b"X-Empty:  ").get_value_as_str(), Some(""));
        assert_eq!(header_of(b"X-Empty:").get_usize_value(), None);
    }

    /// The value positions must line up with the same whitespace rule.
    #[test]
    fn the_value_position_skips_the_whitespace_too() {
        let line = b"Host:example.com";
        let position = header_of(line).get_value();
        assert_eq!(&line[position.start..position.end], b"example.com");
    }

    /// The panic this comparison used to be: a client-supplied value shorter than
    /// what it is compared against.
    #[test]
    fn a_shorter_value_does_not_panic() {
        assert!(!compare_case_insensitive(b"h2c", b"websocket"));
        assert!(!compare_case_insensitive(b"", b"websocket"));
    }

    #[test]
    fn a_prefix_is_not_a_match() {
        assert!(!compare_case_insensitive(
            b"websocket-and-more",
            b"websocket"
        ));
    }

    #[test]
    fn equal_values_match_regardless_of_case() {
        assert!(compare_case_insensitive(b"WebSocket", b"websocket"));
        assert!(compare_case_insensitive(b"websocket", b"websocket"));
    }
}

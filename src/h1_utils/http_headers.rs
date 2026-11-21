use super::*;
use rust_extensions::{slice_of_u8_utils::SliceOfU8Ext, str_utils::StrUtils};

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum HttpContentLength {
    None,
    Known(usize),
    Chunked,
}

pub struct Http1Headers {
    pub first_line_end: usize,
    pub end: usize,
    pub content_length: HttpContentLength,
    pub host_value: Option<HeaderPosition>,
    pub cookie_value: Option<HeaderPosition>,
    pub upgrade_value: Option<HeaderPosition>,
}

impl Http1Headers {
    /// Status code of a RESPONSE first line (`HTTP/1.1 200 OK`). `None` when the
    /// first line is a request line instead of a status line.
    ///
    /// Needed to tell an interim 1xx response (a `100 Continue` answering the
    /// client's `Expect: 100-continue`) from the real one: relayed to the client as
    /// the response, an interim status leaves it waiting for a body that never
    /// comes.
    pub fn get_status_code(&self, src: &[u8]) -> Option<u16> {
        let first_line = &src[..self.first_line_end];

        if !first_line.starts_with(b"HTTP/") {
            return None;
        }

        let version_end = first_line.find_byte_pos(b' ', 0)?;
        let status = &first_line[version_end + 1..];
        let status_end = status.find_byte_pos(b' ', 0).unwrap_or(status.len());

        std::str::from_utf8(&status[..status_end])
            .ok()?
            .parse()
            .ok()
    }

    /// `None`: there is no whole head yet, or it does not parse.
    #[cfg(test)]
    pub fn parse(src: &[u8]) -> Option<Self> {
        Self::try_parse(src).ok().flatten()
    }

    /// `Ok(None)`: there is no whole head yet - more has to be read. `Err`: the first line is
    /// there and is not one of HTTP/1.1, and nothing which comes after it can change that.
    pub fn try_parse(src: &[u8]) -> Result<Option<Self>, &'static str> {
        let Some(first_line_end) = src.find_sequence_pos(crate::consts::HTTP_CR_LF, 0) else {
            return Ok(None);
        };

        if verify_http11_first_line(&src[..first_line_end]).is_err() {
            return Err("Invalid HTTP/1.1 first line");
        }

        Ok(Self::parse_after_first_line(src, first_line_end))
    }

    /// The head of a client's request: [`Self::try_parse`] - and an error for a head which could
    /// be read another way than this one.
    ///
    /// The lines of a request head go upstream as they came (`compile_head`), and the upstream
    /// finds where the request ends by them on its own. Where it could find another end than
    /// the proxy does, it would read a second request out of the body of the first, and serve it
    /// past every check of the location (request smuggling). So such a head is refused, as nginx
    /// refuses it:
    /// - `Content-Length` and `Transfer-Encoding` together - an upstream goes by the second;
    /// - `Content-Length` twice, or one which is not a number;
    /// - `Transfer-Encoding` twice, or other than `chunked`;
    /// - a line which is not `name: value`: no colon, or a byte of no token in the name -
    ///   whitespace before the colon, a folded line;
    /// - a control character in a value: a lone LF, which an upstream may take for the end of a
    ///   line (RFC 9112 §2.2), a lone CR, a NUL;
    /// - `Host` twice: the proxy routes by one of them, the upstream may take the other.
    pub fn try_parse_request(src: &[u8]) -> Result<Option<Self>, &'static str> {
        let parsed = Self::try_parse(src)?;

        // The head is whole once the empty line is there. Until then, more is read.
        if src.find_sequence_pos(b"\r\n\r\n", 0).is_none() {
            return Ok(None);
        }

        let Some(headers) = parsed else {
            return Err("A request head which does not parse");
        };

        verify_request_lines(src, &headers)?;

        Ok(Some(headers))
    }

    fn parse_after_first_line(src: &[u8], first_line_end: usize) -> Option<Self> {
        const HOST_HEADER: &[u8] = b"host";
        const COOKIE_HEADER: &[u8] = b"cookie";
        const CONTENT_LEN_HEADER: &[u8] = b"content-length";
        const TRANSFER_ENCODING_HEADER: &[u8] = b"transfer-encoding";
        const UPGRADE_HEADER: &[u8] = b"upgrade";

        let mut host_value = None;
        let mut cookie_value = None;
        let mut upgrade_value = None;
        let mut content_length = HttpContentLength::None;

        let mut header_start_pos = first_line_end + crate::consts::HTTP_CR_LF.len();
        loop {
            let end = src.find_sequence_pos(crate::consts::HTTP_CR_LF, header_start_pos)?;

            if end == header_start_pos {
                return Some(Self {
                    first_line_end,
                    host_value,
                    cookie_value,
                    upgrade_value,
                    content_length,
                    end: end + crate::consts::HTTP_CR_LF.len(),
                });
            }

            let http_header = HttpHeader::new(src, header_start_pos, end)?;

            if http_header.is_my_header_name(HOST_HEADER) {
                host_value = Some(http_header.get_value());
            } else if http_header.is_my_header_name(COOKIE_HEADER) {
                cookie_value = Some(http_header.get_value());
            } else if http_header.is_my_header_name(CONTENT_LEN_HEADER) {
                content_length = HttpContentLength::Known(http_header.get_usize_value()?);
            } else if http_header.is_my_header_name(TRANSFER_ENCODING_HEADER) {
                let value = http_header.get_value_as_str()?;
                if value.eq_case_insensitive("chunked") {
                    content_length = HttpContentLength::Chunked;
                }
            } else if http_header.is_my_header_name(UPGRADE_HEADER) {
                upgrade_value = Some(http_header.get_value());
            }

            header_start_pos = end + crate::consts::HTTP_CR_LF.len();
        }
    }

    pub fn get_first_line<'s>(&self, src: &'s [u8]) -> H1HeadersFirstLine<'s> {
        H1HeadersFirstLine {
            data: &src[..self.first_line_end],
        }
    }

    /// Linear scan over the header block looking for `name` (case-insensitive).
    /// Returns the trimmed UTF-8 value, or `None` if the header is missing or
    /// has non-UTF-8 bytes. Use for headers not preparsed into `Http1Headers`
    /// (e.g. `proxy-to`).
    pub fn find_header_value_str<'s>(&self, src: &'s [u8], name: &[u8]) -> Option<&'s str> {
        let mut pos = self.first_line_end + crate::consts::HTTP_CR_LF.len();
        loop {
            let end = src.find_sequence_pos(crate::consts::HTTP_CR_LF, pos)?;
            if end == pos {
                return None;
            }
            let value_pos = {
                let http_header = HttpHeader::new(src, pos, end)?;
                if http_header.is_my_header_name(name) {
                    Some(http_header.get_value())
                } else {
                    None
                }
            };
            if let Some(value_pos) = value_pos {
                return std::str::from_utf8(&src[value_pos.start..value_pos.end])
                    .ok()
                    .map(str::trim);
            }
            pos = end + crate::consts::HTTP_CR_LF.len();
        }
    }

    /// Every header of the head, in the order they came: its name and its value, as they are
    /// written around the `:` - the value with the whitespace before it.
    pub fn headers_of<'s>(&self, src: &'s [u8]) -> impl Iterator<Item = (&'s [u8], &'s [u8])> + 's {
        let mut pos = self.first_line_end + crate::consts::HTTP_CR_LF.len();

        std::iter::from_fn(move || loop {
            let end = src.find_sequence_pos(crate::consts::HTTP_CR_LF, pos)?;

            if end == pos {
                return None;
            }

            let line = &src[pos..end];
            pos = end + crate::consts::HTTP_CR_LF.len();

            if let Some(colon) = line.iter().position(|&byte| byte == b':') {
                return Some((&line[..colon], &line[colon + 1..]));
            }
        })
    }

    /// Every value of the headers an upstream could read as `header` (written in lowercase - see
    /// [`crate::cloudflare::header_name_is`]), in the order they came. A name sent twice, or once
    /// as `CF-Connecting-IP` and once as `CF_Connecting_IP`, gives two values.
    pub fn header_values_read_as<'s>(&self, src: &'s [u8], header: &str) -> Vec<&'s [u8]> {
        let mut result = Vec::new();
        let mut pos = self.first_line_end + crate::consts::HTTP_CR_LF.len();

        while let Some(end) = src.find_sequence_pos(crate::consts::HTTP_CR_LF, pos) {
            if end == pos {
                break;
            }

            let line = &src[pos..end];

            if let Some(colon) = line.iter().position(|&byte| byte == b':') {
                if crate::cloudflare::header_name_is(&line[..colon], header) {
                    result.push(&line[colon + 1..]);
                }
            }

            pos = end + crate::consts::HTTP_CR_LF.len();
        }

        result
    }

    pub fn push_first_line_with_other_path(
        &self,
        data: &[u8],
        path: &str,
        out: &mut Http1HeadersBuilder,
    ) {
        let buffer = &data[..self.first_line_end];

        let items = buffer.split(|b| *b == b' ');

        for (no, itm) in items.enumerate() {
            if no > 0 {
                out.push_space();
            }
            if no == 1 {
                out.push_raw_payload(path.as_bytes());
            } else {
                out.push_raw_payload(itm);
            }
        }
    }
}

/// The checks of [`Http1Headers::try_parse_request`] on the lines of a whole head.
fn verify_request_lines(src: &[u8], headers: &Http1Headers) -> Result<(), &'static str> {
    let mut content_lengths = 0;
    let mut transfer_encodings = 0;
    let mut hosts = 0;

    let mut pos = headers.first_line_end + crate::consts::HTTP_CR_LF.len();
    // Where the empty line which ends the head starts.
    let end = headers.end - crate::consts::HTTP_CR_LF.len();

    while pos < end {
        let line_end = src
            .find_sequence_pos(crate::consts::HTTP_CR_LF, pos)
            .unwrap_or(end);
        let line = &src[pos..line_end];
        pos = line_end + crate::consts::HTTP_CR_LF.len();

        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            return Err("A header line with no colon");
        };

        let name = &line[..colon];
        let value = &line[colon + 1..];

        if name.is_empty() || !name.iter().all(|byte| is_token_byte(*byte)) {
            return Err("A header name which is not a token");
        }

        if !value.iter().all(|byte| is_field_value_byte(*byte)) {
            return Err("A control character in a header value");
        }

        if name.eq_ignore_ascii_case(b"content-length") {
            content_lengths += 1;

            let value = trim_whitespace(value);
            if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
                return Err("A Content-Length which is not a number");
            }
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            transfer_encodings += 1;

            if !trim_whitespace(value).eq_ignore_ascii_case(b"chunked") {
                return Err("A Transfer-Encoding other than chunked");
            }
        } else if name.eq_ignore_ascii_case(b"host") {
            hosts += 1;
        }
    }

    if content_lengths > 1 {
        return Err("Content-Length twice");
    }

    if transfer_encodings > 1 {
        return Err("Transfer-Encoding twice");
    }

    if content_lengths > 0 && transfer_encodings > 0 {
        return Err("Content-Length and Transfer-Encoding together");
    }

    if hosts > 1 {
        return Err("Host twice");
    }

    Ok(())
}

/// `tchar` of RFC 9110: what a header name is made of.
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// What a header value may have in it (RFC 9110 §5.5): visible characters, space and tab, and
/// the bytes above ASCII - no other control character.
fn is_field_value_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b' '..=b'~' | 0x80..=0xFF)
}

fn trim_whitespace(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !matches!(byte, b' ' | b'\t'))
        .map_or(start, |pos| pos + 1);

    &value[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_length_parsing() {
        // Test with Content-Length header
        let http_request =
            b"POST /api/data HTTP/1.1\r\nContent-Length: 1024\r\nHost: example.com\r\n\r\n";
        let headers = Http1Headers::parse(http_request);
        assert!(headers.is_some());
        let headers = headers.unwrap();
        assert_eq!(headers.content_length, HttpContentLength::Known(1024));
    }

    #[test]
    fn test_content_length_case_insensitive() {
        // Test with case-insensitive Content-Length header
        let http_request =
            b"POST /api/data HTTP/1.1\r\ncontent-length: 2048\r\nHost: example.com\r\n\r\n";
        let headers = Http1Headers::parse(http_request);
        assert!(headers.is_some());
        let headers = headers.unwrap();
        assert_eq!(headers.content_length, HttpContentLength::Known(2048));
    }

    #[test]
    fn test_content_length_with_whitespace() {
        // Test with Content-Length header that has whitespace
        let http_request =
            b"POST /api/data HTTP/1.1\r\nContent-Length:  512  \r\nHost: example.com\r\n\r\n";
        let headers = Http1Headers::parse(http_request);
        assert!(headers.is_some());
        let headers = headers.unwrap();
        assert_eq!(headers.content_length, HttpContentLength::Known(512));
    }

    #[test]
    fn test_no_content_length_header() {
        // Test without Content-Length header
        let http_request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let headers = Http1Headers::parse(http_request);
        assert!(headers.is_some());
        let headers = headers.unwrap();
        assert_eq!(headers.content_length, HttpContentLength::None);
    }

    #[test]
    fn test_chunked_transfer_encoding() {
        // Test with Transfer-Encoding: chunked header
        let http_request =
            b"POST /api/data HTTP/1.1\r\nTransfer-Encoding: chunked\r\nHost: example.com\r\n\r\n";
        let headers = Http1Headers::parse(http_request);
        assert!(headers.is_some());
        let headers = headers.unwrap();
        assert_eq!(headers.content_length, HttpContentLength::Chunked);
    }

    #[test]
    fn test_chunked_transfer_encoding_case_insensitive() {
        // Test with case-insensitive Transfer-Encoding: chunked header
        let http_request =
            b"POST /api/data HTTP/1.1\r\ntransfer-encoding: CHUNKED\r\nHost: example.com\r\n\r\n";
        let headers = Http1Headers::parse(http_request);
        assert!(headers.is_some());
        let headers = headers.unwrap();
        assert_eq!(headers.content_length, HttpContentLength::Chunked);
    }
}

#[cfg(test)]
mod status_code_tests {
    use super::*;

    fn parse(src: &[u8]) -> Http1Headers {
        Http1Headers::parse(src).unwrap()
    }

    #[test]
    fn an_interim_status_is_read_as_such() {
        let src = b"HTTP/1.1 100 Continue\r\n\r\n";
        assert_eq!(parse(src).get_status_code(src), Some(100));
    }

    #[test]
    fn a_final_status_is_read() {
        let src = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(parse(src).get_status_code(src), Some(200));

        let src = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(parse(src).get_status_code(src), Some(502));
    }

    /// A request has no status code — the same parser runs over request heads.
    #[test]
    fn a_request_line_has_no_status() {
        let src = b"POST /upload HTTP/1.1\r\nHost: h\r\n\r\n";
        assert_eq!(parse(src).get_status_code(src), None);
    }
}

#[cfg(test)]
mod optional_whitespace_tests {
    use super::*;

    /// The whitespace after a colon is optional in HTTP, so a head written without
    /// it must parse to the same thing.
    #[test]
    fn a_head_without_whitespace_after_the_colons_parses() {
        let src = b"POST /upload HTTP/1.1\r\nHost:localhost:8801\r\nContent-Length:10\r\n\r\n";
        let headers = Http1Headers::parse(src).expect("head must parse");

        assert_eq!(headers.content_length, HttpContentLength::Known(10));

        let host = headers.host_value.expect("host must be found");
        assert_eq!(&src[host.start..host.end], b"localhost:8801");
    }

    #[test]
    fn the_same_head_with_whitespace_parses_identically() {
        let src = b"POST /upload HTTP/1.1\r\nHost: localhost:8801\r\nContent-Length: 10\r\n\r\n";
        let headers = Http1Headers::parse(src).expect("head must parse");

        assert_eq!(headers.content_length, HttpContentLength::Known(10));

        let host = headers.host_value.expect("host must be found");
        assert_eq!(&src[host.start..host.end], b"localhost:8801");
    }
}

#[cfg(test)]
mod request_framing_tests {
    use super::*;

    fn request(lines: &[u8]) -> Vec<u8> {
        let mut src = b"POST /x HTTP/1.1\r\nHost: example.com\r\n".to_vec();
        src.extend_from_slice(lines);
        src.extend_from_slice(b"\r\n");
        src
    }

    #[test]
    fn a_head_read_one_way_only_is_taken() {
        for (lines, framing) in [
            (&b""[..], HttpContentLength::None),
            (b"Content-Length: 5\r\n", HttpContentLength::Known(5)),
            (b"content-length:5\r\n", HttpContentLength::Known(5)),
            (b"Content-Length: \t007 \r\n", HttpContentLength::Known(7)),
            (
                b"Transfer-Encoding: Chunked\r\n",
                HttpContentLength::Chunked,
            ),
            (
                b"transfer-encoding:chunked \r\n",
                HttpContentLength::Chunked,
            ),
            // A value may have tabs, and bytes above ASCII - UTF-8, a file name.
            (b"X-Note: a\tb \xd1\x84\r\n", HttpContentLength::None),
            (b"X-Empty:\r\n", HttpContentLength::None),
            (b"X-Odd_Name.1~: v\r\n", HttpContentLength::None),
        ] {
            let src = request(lines);
            let shown = String::from_utf8_lossy(lines);

            let headers = Http1Headers::try_parse_request(&src)
                .unwrap_or_else(|err| panic!("{shown:?}: {err}"))
                .unwrap_or_else(|| panic!("{shown:?}: not whole"));

            assert_eq!(headers.content_length, framing, "{shown:?}");
            assert_eq!(headers.end, src.len(), "{shown:?}");
        }
    }

    #[test]
    fn a_head_which_could_be_read_two_ways_is_refused() {
        for lines in [
            "Content-Length: 1\r\nTransfer-Encoding: chunked\r\n",
            "Transfer-Encoding: chunked\r\nContent-Length: 1\r\n",
            "Content-Length: 1\r\nContent-Length: 2\r\n",
            "Content-Length: 1\r\nContent-Length: 1\r\n",
            "Content-Length: +1\r\n",
            "Content-Length: -1\r\n",
            "Content-Length: 1, 1\r\n",
            "Content-Length: 1 1\r\n",
            "Content-Length:\r\n",
            "Content-Length: 99999999999999999999999\r\n",
            "Transfer-Encoding: gzip, chunked\r\n",
            "Transfer-Encoding: chunked, chunked\r\n",
            "Transfer-Encoding: identity\r\n",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
            "Transfer-Encoding : chunked\r\n",
            "Transfer-Encoding\t: chunked\r\n",
            " Transfer-Encoding: chunked\r\n",
            "Transfer-Encoding:\r\n chunked\r\n",
            "X-Note: a\nTransfer-Encoding: chunked\r\n",
            "X-Note: a\rb\r\n",
            "X-Note: a\0b\r\n",
            "X-Note: a\x7fb\r\n",
            "X Note: a\r\n",
            "Host: other.example.com\r\n",
            "A line with no colon\r\n",
            ": a value with no name\r\n",
        ] {
            let src = request(lines.as_bytes());

            assert!(
                Http1Headers::try_parse_request(&src).is_err(),
                "{lines:?} was taken"
            );
        }
    }

    #[test]
    fn a_head_which_is_not_whole_yet_is_waited_for() {
        for src in [
            "POST /x HTTP/1.1\r\nHost: example.com\r\n".as_bytes(),
            b"POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\nTransfer-Encoding: ch",
            b"POST /x HTTP/1.1\r\nA line with no colon\r\n",
        ] {
            assert!(
                matches!(Http1Headers::try_parse_request(src), Ok(None)),
                "{:?}",
                String::from_utf8_lossy(src)
            );
        }
    }

    #[test]
    fn the_head_of_a_response_is_read_as_before() {
        // An upstream is not held to the rules of a client's request.
        let src = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n";
        let headers = Http1Headers::try_parse(src).unwrap().unwrap();
        assert_eq!(headers.content_length, HttpContentLength::Known(2));
    }
}

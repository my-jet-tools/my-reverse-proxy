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

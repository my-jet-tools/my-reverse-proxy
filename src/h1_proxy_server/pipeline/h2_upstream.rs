//! A request of an h1 client to an h2 upstream - an `http2`, `mcp-h2` or `unix+http2` location.
//!
//! The reader does for it what it does for any request - resolves the location, compiles the
//! head with every rule applied, streams the body - and only the worker differs: instead of
//! writing the head to an h1 connection it turns it into an h2 request and sends it through the
//! location's h2 pool (the same pools and sources the hyper path uses), then writes the response
//! back as h1. So an h1 client stays on this pipeline whatever its upstream speaks.
//!
//! An h2 request is a [`http::Request`] with a `HeaderMap` - the h2 client takes nothing else -
//! so here the head is parsed once more. The response head goes the other way: it is written as
//! h1 and compiled by [`compile_head`], the very function which compiles the head of an h1
//! upstream's response.

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Frame;
use tokio::sync::mpsc;

use crate::configurations::{HttpEndpointInfo, ProxyPassLocationConfig};
use crate::h1_proxy_server::{compile_head, H1HeadersKind, HttpConnectionInfo, HttpHeadersReader};
use crate::h1_utils::{Http1Headers, Http1HeadersBuilder, HttpContentLength};
use crate::http_proxy_pass::content_source::{HttpProxyPassContentSource, HttpResponse};
use crate::http_proxy_pass::ProxyPassError;

use super::ResponseEvent;

/// What an h1 client which sent `Expect: 100-continue` waits for before it sends the body. An h2
/// upstream can not be asked for it - the h2 client does not pass interim responses on - so the
/// proxy answers it itself, as soon as it takes the request.
const CONTINUE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";

/// The last chunk of a chunked body, with no trailers.
const LAST_CHUNK: &[u8] = b"0\r\n\r\n";

/// Everything one request's h2 worker needs. Built by the reader in place of an
/// [`super::UpstreamRequest`].
pub struct H2UpstreamRequest {
    pub content_source: Arc<HttpProxyPassContentSource>,
    pub end_point_info: Arc<HttpEndpointInfo>,
    pub location: Arc<ProxyPassLocationConfig>,
    pub http_connection_info: HttpConnectionInfo,
    pub location_id: i64,
    pub is_mcp: bool,
    /// The compiled request head, as it would go to an h1 upstream.
    pub head: Vec<u8>,
    /// How the client frames the body: a chunked one comes through `body_rx` with its framing.
    pub request_content_length: HttpContentLength,
    /// The request is a `HEAD`: its response has no body, whatever its headers say.
    pub is_head: bool,
    pub body_rx: mpsc::Receiver<Vec<u8>>,
    pub response_tx: mpsc::Sender<ResponseEvent>,
}

pub async fn run_h2_upstream_request(req: H2UpstreamRequest) {
    let H2UpstreamRequest {
        content_source,
        end_point_info,
        location,
        http_connection_info,
        location_id,
        is_mcp,
        head,
        request_content_length,
        is_head,
        body_rx,
        response_tx,
    } = req;

    let endpoint = end_point_info.host_endpoint.as_str();
    let ip = http_connection_info.connection_ip.get_ip_log();

    let (parts, expects_continue) = match h2_request_head(&head) {
        Ok(parsed) => parsed,
        Err(reason) => {
            // The head was compiled by this proxy and parsed once already: this is a value the
            // h2 client refuses, a header value h1 lets through and h2 does not.
            crate::app::APP_CTX.proxy_logs.write_returned_5xx(
                endpoint,
                Some(location_id),
                ip,
                502,
                format!("the request can not be sent to h2 upstream: {}", reason),
            );
            fail(
                &response_tx,
                is_mcp,
                crate::error_templates::ERROR_GETTING_CONTENT_FROM_REMOTE_RESOURCE.as_slice(),
            )
            .await;
            return;
        }
    };

    if expects_continue
        && response_tx
            .send(ResponseEvent::Chunk(CONTINUE.to_vec()))
            .await
            .is_err()
    {
        return; // writer/client gone
    }

    let taken_from_client = Arc::new(AtomicU64::new(0));

    let result = match request_content_length {
        // No body: the buffered send, which fails an idempotent request over to another
        // connection of the pool when the first one turns out to be dead.
        HttpContentLength::None | HttpContentLength::Known(0) => {
            let request =
                hyper::Request::from_parts(parts, http_body_util::Full::new(Bytes::new()));
            content_source.send_request(request).await
        }
        HttpContentLength::Known(size) => {
            let body = RequestBody::new(body_rx, None, taken_from_client.clone());
            let request = hyper::Request::from_parts(parts, body.boxed());
            content_source
                .send_streamed_request(request, Some(size))
                .await
        }
        HttpContentLength::Chunked => {
            let body = RequestBody::new(
                body_rx,
                Some(Dechunker::default()),
                taken_from_client.clone(),
            );
            let request = hyper::Request::from_parts(parts, body.boxed());
            content_source.send_streamed_request(request, None).await
        }
    };

    let response = match result {
        Ok(HttpResponse::Response(response)) => response,
        Ok(HttpResponse::WebSocketUpgrade { .. }) => {
            // Only an extended CONNECT is answered with an upgrade, and the reader sends a
            // websocket handshake down another path.
            crate::app::APP_CTX.proxy_logs.write_returned_5xx(
                endpoint,
                Some(location_id),
                ip,
                502,
                "h2 upstream answered a request with an upgrade".to_string(),
            );
            fail(
                &response_tx,
                is_mcp,
                crate::error_templates::ERROR_GETTING_CONTENT_FROM_REMOTE_RESOURCE.as_slice(),
            )
            .await;
            return;
        }
        Err(err) => {
            let (page, status) = page_of(&err);
            crate::app::APP_CTX.proxy_logs.write_returned_5xx(
                endpoint,
                Some(location_id),
                ip,
                status,
                format!(
                    "h2 upstream {} did not answer: {:?}",
                    location.proxy_pass_to, err
                ),
            );
            fail(&response_tx, is_mcp, page).await;
            return;
        }
    };

    let (parts, mut body) = response.into_parts();

    let status = parts.status.as_u16();
    let has_body = !is_head && status >= 200 && status != 204 && status != 304;
    // h2 has no framing of its own in the headers: a response which does not say its length is
    // sent chunked, so the connection can serve the next request after it.
    let chunked = has_body && !parts.headers.contains_key(http::header::CONTENT_LENGTH);

    let raw_head = h1_response_head(parts.status, &parts.headers, chunked);

    let mut compiled = Http1HeadersBuilder::new();
    let compiled_head = match Http1Headers::try_parse(&raw_head) {
        Ok(Some(headers)) => compile_head(
            HttpHeadersReader {
                http_headers: &headers,
                payload: &raw_head,
            },
            &mut compiled,
            H1HeadersKind::Response(&end_point_info, &location),
            &http_connection_info,
            &None,
            None,
            None,
        )
        .map_err(|err| format!("{:?}", err)),
        Ok(None) => Err("the head does not parse as h1".to_string()),
        Err(reason) => Err(reason.to_string()),
    };

    if let Err(reason) = compiled_head {
        crate::app::APP_CTX.proxy_logs.write_returned_5xx(
            endpoint,
            Some(location_id),
            ip,
            502,
            format!(
                "the response head of h2 upstream {} can not be written as h1: {}",
                location.proxy_pass_to, reason
            ),
        );
        fail(
            &response_tx,
            is_mcp,
            crate::error_templates::UPSTREAM_IS_NOT_HTTP.as_slice(),
        )
        .await;
        return;
    }

    // From here on the client begins receiving the response - any failure must Abort.
    if response_tx
        .send(ResponseEvent::Chunk(compiled.into_bytes()))
        .await
        .is_err()
    {
        return;
    }

    // The same carve-out as the h1 worker: an MCP listening stream idles between messages for
    // far longer than an ordinary response body would.
    let read_timeout = if is_mcp {
        crate::consts::DEFAULT_MCP_READ_TIMEOUT
    } else {
        end_point_info.timeouts.read_timeout
    };

    let mut bytes_to_client = 0u64;

    if has_body {
        loop {
            let frame = match tokio::time::timeout(read_timeout, body.frame()).await {
                Ok(Some(Ok(frame))) => frame,
                Ok(None) => break,
                Ok(Some(Err(err))) => {
                    crate::app::APP_CTX.proxy_logs.write_returned_5xx(
                        endpoint,
                        Some(location_id),
                        ip,
                        502,
                        format!(
                            "h2 upstream {} broke the response body: {}",
                            location.proxy_pass_to, err
                        ),
                    );
                    let _ = response_tx.send(ResponseEvent::Abort).await;
                    return;
                }
                Err(_) => {
                    crate::app::APP_CTX.proxy_logs.write_returned_5xx(
                        endpoint,
                        Some(location_id),
                        ip,
                        502,
                        format!(
                            "h2 upstream {} sent nothing of the response body for {:?}",
                            location.proxy_pass_to, read_timeout
                        ),
                    );
                    let _ = response_tx.send(ResponseEvent::Abort).await;
                    return;
                }
            };

            // Trailers have no place in an h1 response this proxy writes: they are dropped.
            let Ok(data) = frame.into_data() else {
                continue;
            };

            if data.is_empty() {
                continue;
            }

            bytes_to_client += data.len() as u64;

            let chunk = if chunked {
                as_chunk(&data)
            } else {
                Vec::from(data)
            };

            if response_tx.send(ResponseEvent::Chunk(chunk)).await.is_err() {
                return; // writer/client gone
            }
        }

        if chunked
            && response_tx
                .send(ResponseEvent::Chunk(LAST_CHUNK.to_vec()))
                .await
                .is_err()
        {
            return;
        }
    }

    if response_tx.send(ResponseEvent::Done).await.is_err() {
        return;
    }

    crate::app::APP_CTX
        .traffic
        .record_c2s(endpoint, taken_from_client.load(Ordering::Relaxed));
    crate::app::APP_CTX
        .traffic
        .record_s2c(endpoint, bytes_to_client);
}

/// Finish a request which failed before the client received a single byte: the page, or for
/// MCP the connection closed - the same rule as `fail_request` of the h1 worker. The request body
/// went with the request; if the reader is still sending it, it finds the channel closed and
/// closes the connection behind the page.
async fn fail(response_tx: &mpsc::Sender<ResponseEvent>, is_mcp: bool, page: &[u8]) {
    if is_mcp {
        let _ = response_tx.send(ResponseEvent::Abort).await;
        return;
    }

    if response_tx
        .send(ResponseEvent::Chunk(page.to_vec()))
        .await
        .is_ok()
    {
        let _ = response_tx.send(ResponseEvent::Done).await;
    }
}

/// The page, and the status to log, for an h2 upstream which did not answer.
fn page_of(err: &ProxyPassError) -> (&'static [u8], u16) {
    let is_timeout = matches!(
        err,
        ProxyPassError::Timeout
            | ProxyPassError::MyHttpClientError(my_http_client::MyHttpClientError::RequestTimeout(
                _
            ))
    );

    if is_timeout {
        (crate::error_templates::ERROR_TIMEOUT.as_slice(), 503)
    } else {
        (
            crate::error_templates::REMOTE_RESOURCE_IS_NOT_AVAILABLE.as_slice(),
            503,
        )
    }
}

/// Headers of h1 which mean something only on the connection they came over. h2 forbids them -
/// the h2 client would refuse the request - and on an h1 response the proxy writes its own.
fn is_connection_header(name: &http::HeaderName) -> bool {
    name == http::header::CONNECTION
        || name == http::header::TRANSFER_ENCODING
        || name == http::header::UPGRADE
        || name == http::header::TE
        || name == "keep-alive"
        || name == "proxy-connection"
        || name == "http2-settings"
}

/// The compiled h1 request head as the parts of an h2 request, and whether the client asked for
/// `100 Continue`.
///
/// The target stays as it came - origin-form - and the version stays HTTP/1.1: the h2 client
/// then sends `:scheme` `http` and no `:authority`, and the `Host` header goes on as a header,
/// exactly as the hyper path sends what an h1 client asked of an h2 upstream. The length is not
/// taken over either: the send sets `content-length` from what the body is.
fn h2_request_head(head: &[u8]) -> Result<(http::request::Parts, bool), &'static str> {
    let mut lines = head.split(|b| *b == b'\n').map(|line| match line.last() {
        Some(b'\r') => &line[..line.len() - 1],
        _ => line,
    });

    let first_line = lines.next().ok_or("no request line")?;
    let mut tokens = first_line.split(|b| *b == b' ');
    let method = tokens.next().ok_or("no method")?;
    let target = tokens.next().ok_or("no target")?;

    let (mut parts, _) = http::Request::new(()).into_parts();
    parts.method = http::Method::from_bytes(method).map_err(|_| "the method is not valid")?;
    parts.uri = http::Uri::try_from(target).map_err(|_| "the target is not a valid uri")?;
    parts.version = http::Version::HTTP_11;

    let mut expects_continue = false;

    for line in lines {
        if line.is_empty() {
            break;
        }

        let colon = line
            .iter()
            .position(|b| *b == b':')
            .ok_or("a header without `:`")?;

        let name = http::HeaderName::from_bytes(&line[..colon])
            .map_err(|_| "a header name is not valid")?;
        let value = http::HeaderValue::from_bytes(line[colon + 1..].trim_ascii())
            .map_err(|_| "a header value is not valid")?;

        if is_connection_header(&name) || name == http::header::CONTENT_LENGTH {
            continue;
        }

        if name == http::header::EXPECT {
            expects_continue = value.as_bytes().eq_ignore_ascii_case(b"100-continue");
            continue;
        }

        parts.headers.append(name, value);
    }

    Ok((parts, expects_continue))
}

/// The head of an h2 response written as h1, ready for [`compile_head`]. `chunked`: the body is
/// going to be sent chunked, and the head says so.
fn h1_response_head(status: http::StatusCode, headers: &http::HeaderMap, chunked: bool) -> Vec<u8> {
    const CR_LF: &[u8] = crate::consts::HTTP_CR_LF;

    let mut head = Vec::with_capacity(256);

    head.extend_from_slice(b"HTTP/1.1 ");
    head.extend_from_slice(status.as_str().as_bytes());
    head.push(b' ');
    head.extend_from_slice(status.canonical_reason().unwrap_or("Status").as_bytes());
    head.extend_from_slice(CR_LF);

    for (name, value) in headers {
        if is_connection_header(name) {
            continue;
        }

        head.extend_from_slice(name.as_str().as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(CR_LF);
    }

    if chunked {
        head.extend_from_slice(b"Transfer-Encoding: chunked");
        head.extend_from_slice(CR_LF);
    }

    head.extend_from_slice(CR_LF);

    head
}

/// One piece of a chunked body: the size line, the data and the line end.
fn as_chunk(data: &[u8]) -> Vec<u8> {
    let size_line = format!("{:x}\r\n", data.len());

    let mut chunk = Vec::with_capacity(size_line.len() + data.len() + 2);
    chunk.extend_from_slice(size_line.as_bytes());
    chunk.extend_from_slice(data);
    chunk.extend_from_slice(crate::consts::HTTP_CR_LF);

    chunk
}

/// The request body as the h2 client takes it: what the reader takes off the client, frame by
/// frame as it comes - a chunked body without its framing. Nothing is gathered.
struct RequestBody {
    rx: mpsc::Receiver<Vec<u8>>,
    dechunker: Option<Dechunker>,
    /// The data of a chunked piece which is not given out yet - one piece can carry several
    /// chunks.
    pending: VecDeque<Bytes>,
    /// Bytes taken off the client, framing included (traffic accounting).
    taken: Arc<AtomicU64>,
}

impl RequestBody {
    fn new(
        rx: mpsc::Receiver<Vec<u8>>,
        dechunker: Option<Dechunker>,
        taken: Arc<AtomicU64>,
    ) -> Self {
        Self {
            rx,
            dechunker,
            pending: VecDeque::new(),
            taken,
        }
    }
}

impl hyper::body::Body for RequestBody {
    type Data = Bytes;
    type Error = String;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, String>>> {
        let this = self.get_mut();

        loop {
            if let Some(data) = this.pending.pop_front() {
                return Poll::Ready(Some(Ok(Frame::data(data))));
            }

            let piece = match this.rx.poll_recv(cx) {
                Poll::Ready(Some(piece)) => piece,
                // The reader closes the channel when the body is over - or when it could not
                // read it to its end. A known length is checked by the h2 client itself; a
                // chunked body is complete only with its last chunk, and one which is not must
                // not reach the upstream as if it were.
                Poll::Ready(None) => {
                    return match &this.dechunker {
                        Some(dechunker) if !dechunker.is_done() => Poll::Ready(Some(Err(
                            "the chunked request body ended before its last chunk".to_string(),
                        ))),
                        _ => Poll::Ready(None),
                    };
                }
                Poll::Pending => return Poll::Pending,
            };

            this.taken.fetch_add(piece.len() as u64, Ordering::Relaxed);

            let piece = Bytes::from(piece);

            match this.dechunker.as_mut() {
                Some(dechunker) => {
                    if let Err(reason) = dechunker.feed(&piece, &mut this.pending) {
                        return Poll::Ready(Some(Err(reason.to_string())));
                    }
                }
                None => {
                    if !piece.is_empty() {
                        this.pending.push_back(piece);
                    }
                }
            }
        }
    }
}

/// Takes the framing off a chunked body: the size lines and the line ends. It is fed what the
/// reader relays - pieces cut anywhere, a size line included - and gives out the data as slices
/// of those pieces, with no copy. The reader has checked the framing on its way, so anything
/// unexpected here is an error, not something to recover from.
#[derive(Default)]
struct Dechunker {
    state: DechunkState,
}

#[derive(Default, Clone, Copy, PartialEq, Debug)]
enum DechunkState {
    /// Reading the size line, with the size so far.
    #[default]
    Size,
    SizeDigits(usize),
    /// The `\n` of the size line.
    SizeEnd(usize),
    /// Data of the chunk, with how much of it is left.
    Data(usize),
    /// The line end behind the data: `true` while its `\r` is still to come.
    DataEnd(bool),
    /// The line end behind the last chunk: `true` while its `\r` is still to come.
    LastEnd(bool),
    Done,
}

impl Dechunker {
    fn is_done(&self) -> bool {
        self.state == DechunkState::Done
    }

    fn feed(&mut self, piece: &Bytes, out: &mut VecDeque<Bytes>) -> Result<(), &'static str> {
        let mut pos = 0;

        while pos < piece.len() {
            let byte = piece[pos];

            self.state = match self.state {
                DechunkState::Size | DechunkState::SizeDigits(_) => {
                    let size = match self.state {
                        DechunkState::SizeDigits(size) => size,
                        _ => 0,
                    };

                    pos += 1;

                    if byte == b'\r' && self.state != DechunkState::Size {
                        DechunkState::SizeEnd(size)
                    } else {
                        let digit = (byte as char)
                            .to_digit(16)
                            .ok_or("a chunk size is not a hex number")?;
                        let size = size
                            .checked_mul(16)
                            .and_then(|size| size.checked_add(digit as usize))
                            .ok_or("a chunk size is too big")?;
                        DechunkState::SizeDigits(size)
                    }
                }
                DechunkState::SizeEnd(size) => {
                    if byte != b'\n' {
                        return Err("a chunk size line does not end with CRLF");
                    }

                    pos += 1;

                    if size == 0 {
                        DechunkState::LastEnd(true)
                    } else {
                        DechunkState::Data(size)
                    }
                }
                DechunkState::Data(left) => {
                    let taken = left.min(piece.len() - pos);
                    out.push_back(piece.slice(pos..pos + taken));
                    pos += taken;

                    if taken == left {
                        DechunkState::DataEnd(true)
                    } else {
                        DechunkState::Data(left - taken)
                    }
                }
                DechunkState::DataEnd(expects_cr) | DechunkState::LastEnd(expects_cr) => {
                    let expected = if expects_cr { b'\r' } else { b'\n' };

                    if byte != expected {
                        return Err("chunk data does not end with CRLF");
                    }

                    pos += 1;

                    match (self.state, expects_cr) {
                        (DechunkState::DataEnd(_), true) => DechunkState::DataEnd(false),
                        (DechunkState::DataEnd(_), false) => DechunkState::Size,
                        (_, true) => DechunkState::LastEnd(false),
                        (_, false) => DechunkState::Done,
                    }
                }
                DechunkState::Done => return Err("bytes after the last chunk"),
            };
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dechunk(pieces: &[&[u8]]) -> Result<(Vec<u8>, bool), &'static str> {
        let mut dechunker = Dechunker::default();
        let mut out = VecDeque::new();

        for piece in pieces {
            dechunker.feed(&Bytes::copy_from_slice(piece), &mut out)?;
        }

        Ok((out.iter().flatten().copied().collect(), dechunker.is_done()))
    }

    #[test]
    fn a_chunked_body_loses_its_framing() {
        let (data, done) = dechunk(&[b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"]).unwrap();

        assert_eq!(data, b"hello world");
        assert!(done);
    }

    /// The reader relays pieces cut anywhere: in a size line, in the data, in a line end.
    #[test]
    fn pieces_cut_anywhere_give_the_same_data() {
        let wire: &[u8] = b"a\r\n0123456789\r\n3\r\nabc\r\n0\r\n\r\n";

        for cut in 1..wire.len() {
            let (data, done) = dechunk(&[&wire[..cut], &wire[cut..]]).unwrap();
            assert_eq!(data, b"0123456789abc", "cut at {cut}");
            assert!(done, "cut at {cut}");
        }

        let bytes: Vec<&[u8]> = wire.chunks(1).collect();
        let (data, done) = dechunk(&bytes).unwrap();
        assert_eq!(data, b"0123456789abc");
        assert!(done);
    }

    #[test]
    fn a_body_without_its_last_chunk_is_not_done() {
        let (data, done) = dechunk(&[b"5\r\nhello\r\n"]).unwrap();

        assert_eq!(data, b"hello");
        assert!(!done);
    }

    #[test]
    fn broken_framing_is_an_error() {
        assert!(dechunk(&[b"x\r\n"]).is_err());
        assert!(dechunk(&[b"\r\n"]).is_err());
        assert!(dechunk(&[b"3\r\nabcX"]).is_err());
        assert!(dechunk(&[b"0\r\n\r\nmore"]).is_err());
    }

    #[test]
    fn the_request_head_becomes_h2_parts() {
        let head = b"POST /api/x?y=1 HTTP/1.1\r\nHost: rms-desk.com\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\nX-Forwarded-For: 10.0.0.1\r\nAccept: a\r\nAccept: b\r\n\r\n";

        let (parts, expects_continue) = h2_request_head(head).unwrap();

        assert_eq!(parts.method, http::Method::POST);
        assert_eq!(parts.uri, "/api/x?y=1");
        assert_eq!(parts.version, http::Version::HTTP_11);
        assert_eq!(parts.headers.get("host").unwrap(), "rms-desk.com");
        assert_eq!(parts.headers.get("x-forwarded-for").unwrap(), "10.0.0.1");
        assert_eq!(parts.headers.get_all("accept").iter().count(), 2);
        assert!(parts.headers.get("connection").is_none());
        assert!(parts.headers.get("transfer-encoding").is_none());
        assert!(
            parts.headers.get("content-length").is_none(),
            "the send sets the length from the body"
        );
        assert!(!expects_continue);
    }

    #[test]
    fn expect_100_continue_is_answered_by_the_proxy_not_sent_on() {
        let head =
            b"PUT /upload HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n";

        let (parts, expects_continue) = h2_request_head(head).unwrap();

        assert!(expects_continue);
        assert!(parts.headers.get("expect").is_none());
    }

    #[test]
    fn a_response_without_a_length_is_written_chunked() {
        let mut headers = http::HeaderMap::new();
        headers.insert("content-type", "text/event-stream".parse().unwrap());

        let head = h1_response_head(http::StatusCode::OK, &headers, true);

        assert_eq!(
            head,
            b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n"
        );

        let parsed = Http1Headers::try_parse(&head).unwrap().unwrap();
        assert_eq!(parsed.content_length, HttpContentLength::Chunked);
    }

    #[test]
    fn a_response_with_a_length_keeps_it() {
        let mut headers = http::HeaderMap::new();
        headers.insert("content-length", "11".parse().unwrap());

        let head = h1_response_head(http::StatusCode::NOT_FOUND, &headers, false);

        assert_eq!(
            head,
            b"HTTP/1.1 404 Not Found\r\ncontent-length: 11\r\n\r\n"
        );

        let parsed = Http1Headers::try_parse(&head).unwrap().unwrap();
        assert_eq!(parsed.content_length, HttpContentLength::Known(11));
    }

    #[test]
    fn a_piece_of_data_becomes_one_chunk() {
        assert_eq!(as_chunk(b"hello world, hi"), b"f\r\nhello world, hi\r\n");
    }
}

//! What an `http` endpoint does with a request the h1 pipeline can not read the way it was
//! meant - end to end, through the entry the tcp listener uses. Each of these used to end in a
//! panic of the connection task, or in bytes read as text without a check.
//!
//! The endpoint and the upstream are the ones of `ambiguous_path_tests`: `/open`, `/secure`
//! with an `api_keys_auth`, and `/`. The upstream records every request line it gets.
//!
//! The lines of a request head go upstream as they came, and the upstream finds where the
//! request ends by them on its own: a head it could read another way than the proxy did is
//! refused (see `Http1Headers::try_parse_request`).

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use super::ambiguous_path_tests::{start_endpoint, H1Client, Upstream};
use crate::configurations::ListenHttpEndpointType;

const TIMEOUT: Duration = Duration::from_secs(5);

/// Sends `request` as it is and gives back everything the proxy wrote before it closed the
/// connection.
async fn send_and_read_to_the_close(port: u16, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(request).await.unwrap();

    let mut received = Vec::new();
    tokio::time::timeout(TIMEOUT, stream.read_to_end(&mut received))
        .await
        .expect("the connection is still open")
        // A reset is a close as well.
        .ok();

    received
}

async fn assert_serves(port: u16) {
    let mut client = H1Client::connect(port).await;
    let response = client.get("/open/x", None).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"/open/x");
}

/// A request line is `METHOD SP target SP HTTP/1.1`. One written with a TAB, or with two spaces
/// in a row, is three tokens only to a reader which cuts by any whitespace: here it is refused
/// at once - the connection is closed, and nothing is sent on to the upstream.
#[tokio::test]
async fn a_request_line_which_is_not_single_spaced_closes_the_connection() {
    let upstream = Upstream::start().await;
    let port = start_endpoint(ListenHttpEndpointType::Http1, upstream.port).await;

    for request_line in [
        "GET\t/open/x\tHTTP/1.1",
        "GET\t/open/x HTTP/1.1",
        "GET /open/x\tHTTP/1.1",
        "GET  /open/x HTTP/1.1",
        "GET /open/x  HTTP/1.1",
        " GET /open/x HTTP/1.1",
        "GET /open/x HTTP/1.1 ",
        "GET /open/x /secure/x HTTP/1.1",
        // A status line is not a request, with any whitespace in it.
        "HTTP/1.1\t200\tOK",
    ] {
        let request = format!("{request_line}\r\nHost: localhost:{port}\r\n\r\n");

        let received = send_and_read_to_the_close(port, request.as_bytes()).await;

        assert!(
            !received.starts_with(b"HTTP/1.1 200"),
            "{request_line:?}: {:?}",
            String::from_utf8_lossy(&received)
        );
        assert_eq!(upstream.requests(), [""; 0], "{request_line:?}");
    }

    assert_serves(port).await;
}

/// A path is compared with the path of a location by bytes: a letter of several bytes at the
/// place where the path of a location ends is not cut through.
#[tokio::test]
async fn a_path_which_is_not_ascii_is_proxied() {
    let upstream = Upstream::start().await;
    let port = start_endpoint(ListenHttpEndpointType::Http1, upstream.port).await;

    // `/open` is 5 bytes and `/secure` is 7: both end inside the letter of one of these.
    for target in [
        "/abc\u{20ac}",
        "/abcde\u{20ac}",
        "/\u{20ac}",
        "/open/\u{20ac}",
    ] {
        let mut client = H1Client::connect(port).await;

        let response = client.get(target, None).await;
        assert_eq!(response.status, 200, "{target}");
        assert_eq!(response.body, target.as_bytes(), "{target}");
    }

    assert_eq!(upstream.requests().len(), 4);
}

/// A header name is bytes off the wire. One which is not UTF-8 is not a name: the request is
/// not sent on.
#[tokio::test]
async fn a_header_name_which_is_not_utf8_closes_the_connection() {
    let upstream = Upstream::start().await;
    let port = start_endpoint(ListenHttpEndpointType::Http1, upstream.port).await;

    let mut request = format!("GET /open/x HTTP/1.1\r\nHost: localhost:{port}\r\n").into_bytes();
    request.extend_from_slice(b"X-\xff\xfe\xc3: 1\r\n\r\n");

    let received = send_and_read_to_the_close(port, &request).await;

    assert!(
        !received.starts_with(b"HTTP/1.1 200"),
        "{:?}",
        String::from_utf8_lossy(&received)
    );
    assert_eq!(upstream.requests(), [""; 0]);

    assert_serves(port).await;
}

/// The size of a chunk is at most 16 hex digits and the chunk around it has to fit a number.
/// A size line which does not is the end of the connection - not a size read wrong, after which
/// the rest of the body would be read as the next request.
#[tokio::test]
async fn a_chunk_size_which_does_not_fit_closes_the_connection() {
    for size_line in [
        // One digit more than a u64 has: multiplied through, it would come out as 0 - the
        // last chunk.
        "10000000000000000",
        "FFFFFFFFFFFFFFFF",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0005",
        "",
    ] {
        let upstream = Upstream::start().await;
        let port = start_endpoint(ListenHttpEndpointType::Http1, upstream.port).await;

        let request = format!(
            "POST /open/x HTTP/1.1\r\nHost: localhost:{port}\r\nTransfer-Encoding: chunked\r\n\r\n\
             {size_line}\r\n\r\n\
             GET /open/smuggled HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n"
        );

        // The connection is closed: the read comes to its end.
        send_and_read_to_the_close(port, request.as_bytes()).await;

        // The upstream may have got the head of the request before its body failed. What
        // came behind the size line was a body, and is no request.
        for request_line in upstream.requests() {
            assert_eq!(request_line, "POST /open/x HTTP/1.1", "{size_line:?}");
        }

        assert_serves(port).await;
    }
}

// ---------------------------------------------------------------------------------------------
// Where a request ends: read one way only
// ---------------------------------------------------------------------------------------------

/// A request which an upstream reading by RFC 9112 ends elsewhere than the proxy: the upstream
/// finds a second request in the body of the first, and serves it past the checks of the
/// location - here `GET /secure/x` with no key of its `api_keys_auth`.
#[tokio::test]
async fn a_request_hidden_in_the_body_of_another_never_reaches_the_upstream() {
    let mut leaked = Vec::new();

    for framing in [
        // The upstream goes by `Transfer-Encoding`; the proxy went by the one which came last.
        "Transfer-Encoding: chunked\r\nContent-Length: {len}\r\n",
        // `Transfer-Encoding` is a line of its own to the upstream - and a part of the value
        // of `X-Note` to a reader which ends a line at CRLF only.
        "X-Note: a\nTransfer-Encoding: chunked\r\nContent-Length: {len}\r\n",
    ] {
        let upstream = KeepAliveUpstream::start().await;
        let port = start_endpoint(ListenHttpEndpointType::Http1, upstream.port).await;

        let smuggled = format!("GET /secure/x HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n");
        let body = format!("0\r\n\r\n{smuggled}");
        let lines = framing.replace("{len}", &body.len().to_string());

        let request =
            format!("POST /open/x HTTP/1.1\r\nHost: localhost:{port}\r\n{lines}\r\n{body}");

        send_and_read_for(port, request.as_bytes(), Duration::from_secs(1)).await;

        let requests = upstream.requests();
        if requests.iter().any(|line| line.contains("/secure")) {
            leaked.push(format!("{lines:?}: the upstream got {requests:?}"));
        }
    }

    assert!(leaked.is_empty(), "{leaked:#?}");
}

/// Heads which two readers could take two ways: the request is not sent on, and the connection
/// is closed - as for every other head which does not parse.
#[tokio::test]
async fn a_head_which_could_be_read_two_ways_closes_the_connection() {
    let upstream = Upstream::start().await;
    let port = start_endpoint(ListenHttpEndpointType::Http1, upstream.port).await;

    for lines in [
        "Content-Length: 1\r\nTransfer-Encoding: chunked\r\n",
        "Transfer-Encoding: chunked\r\nContent-Length: 1\r\n",
        "Content-Length: 1\r\nContent-Length: 2\r\n",
        "Content-Length: 1\r\nContent-Length: 1\r\n",
        "Content-Length: +1\r\n",
        "Content-Length: 1, 1\r\n",
        "Content-Length: 99999999999999999999999\r\n",
        "Transfer-Encoding: gzip, chunked\r\n",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
        "Transfer-Encoding : chunked\r\n",
        "Transfer-Encoding:\r\n chunked\r\n",
        "X-Note: a\nTransfer-Encoding: chunked\r\n",
        "X-Note: a\rb\r\n",
        "X-Note: a\0b\r\n",
        "Host: localhost\r\n",
        "A line with no colon\r\n",
        ": a value with no name\r\n",
    ] {
        let request = format!("POST /open/x HTTP/1.1\r\nHost: localhost:{port}\r\n{lines}\r\n");

        let received = send_and_read_to_the_close(port, request.as_bytes()).await;

        assert!(
            !received.starts_with(b"HTTP/1.1 200"),
            "{lines:?}: {:?}",
            String::from_utf8_lossy(&received)
        );
        assert_eq!(upstream.requests(), [""; 0], "{lines:?}");
    }

    assert_serves(port).await;
}

/// Sends `request` as it is and gives back what the proxy wrote within `time`, or before it
/// closed the connection.
async fn send_and_read_for(port: u16, request: &[u8], time: Duration) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(request).await.unwrap();

    let mut received = Vec::new();
    let _ = tokio::time::timeout(time, stream.read_to_end(&mut received)).await;

    received
}

/// An upstream which reads a connection the way RFC 9112 lets a server read it - and the way
/// Go's net/http does: request after request on one connection, `Transfer-Encoding: chunked`
/// over `Content-Length`, and a lone LF taken for the end of a line (§2.2). It keeps the request
/// lines it got, and answers each request with its target.
struct KeepAliveUpstream {
    port: u16,
    request_lines: Arc<Mutex<Vec<String>>>,
}

impl KeepAliveUpstream {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let request_lines = Arc::new(Mutex::new(Vec::new()));
        let recorded = request_lines.clone();

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve_requests(stream, recorded.clone()));
            }
        });

        Self {
            port,
            request_lines,
        }
    }

    fn requests(&self) -> Vec<String> {
        self.request_lines.lock().unwrap().clone()
    }
}

async fn serve_requests(mut stream: TcpStream, recorded: Arc<Mutex<Vec<String>>>) -> Option<()> {
    let mut received = Vec::new();

    loop {
        let request_line = next_line(&mut stream, &mut received).await?;
        recorded.lock().unwrap().push(request_line.clone());

        let mut chunked = false;
        let mut length = 0;

        loop {
            let line = next_line(&mut stream, &mut received).await?;

            if line.is_empty() {
                break;
            }

            let Some((name, value)) = line.split_once(':') else {
                continue;
            };

            if name.eq_ignore_ascii_case("transfer-encoding") {
                chunked = value.trim().eq_ignore_ascii_case("chunked");
            } else if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().unwrap_or(0);
            }
        }

        if chunked {
            loop {
                let size_line = next_line(&mut stream, &mut received).await?;
                let size = usize::from_str_radix(size_line.trim(), 16).ok()?;

                if size == 0 {
                    // The trailers, up to the empty line.
                    while !next_line(&mut stream, &mut received).await?.is_empty() {}
                    break;
                }

                take_bytes(&mut stream, &mut received, size + 2).await?;
            }
        } else {
            take_bytes(&mut stream, &mut received, length).await?;
        }

        let target = request_line.split(' ').nth(1).unwrap_or_default();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            target.len(),
            target
        );
        stream.write_all(response.as_bytes()).await.ok()?;
    }
}

/// The next line of `stream` - without its LF, and without a CR before it. `None`: the
/// connection is over.
async fn next_line(stream: &mut TcpStream, received: &mut Vec<u8>) -> Option<String> {
    loop {
        if let Some(end) = received.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = received.drain(..=end).collect();
            let line = &line[..line.len() - 1];
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            return Some(String::from_utf8_lossy(line).into_owned());
        }

        read_more_of(stream, received).await?;
    }
}

async fn take_bytes(stream: &mut TcpStream, received: &mut Vec<u8>, size: usize) -> Option<()> {
    while received.len() < size {
        read_more_of(stream, received).await?;
    }

    received.drain(..size);
    Some(())
}

async fn read_more_of(stream: &mut TcpStream, received: &mut Vec<u8>) -> Option<()> {
    let mut buffer = [0u8; 4096];

    match tokio::time::timeout(TIMEOUT, stream.read(&mut buffer)).await {
        Ok(Ok(read)) if read > 0 => {
            received.extend_from_slice(&buffer[..read]);
            Some(())
        }
        _ => None,
    }
}

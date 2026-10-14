//! What an `http` endpoint does with a request the h1 pipeline can not read the way it was
//! meant - end to end, through the entry the tcp listener uses. Each of these used to end in a
//! panic of the connection task, or in bytes read as text without a check.
//!
//! The endpoint and the upstream are the ones of `ambiguous_path_tests`: `/open`, `/secure`
//! with an `auth_header`, and `/`. The upstream records every request line it gets.

use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
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

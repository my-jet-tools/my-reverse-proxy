//! A location with `strip_path: true` sends its upstream the request target without the part of
//! the path which picked the location: end to end, on an `http` endpoint (the h1 pipeline) and
//! on an `http2` one (hyper, h2c by prior knowledge).
//!
//! The upstream answers every request with the target it got, and keeps the request lines.

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use super::ambiguous_path_tests::{
    find, start_endpoint_with_locations, H1Client, H2Client, Upstream,
};
use crate::configurations::ListenHttpEndpointType;

/// Sent by the client, and what the upstream gets.
const STRIPPED: [(&str, &str); 16] = [
    ("/prefix/metrics?x=1", "/metrics?x=1"),
    ("/prefix/", "/"),
    ("/prefix/?x=1", "/?x=1"),
    ("/prefix/a/b", "/a/b"),
    // Letters in whatever case they came, escapes in the prefix: matched decoded, cut whole.
    ("/PREFIX/metrics?x=1", "/metrics?x=1"),
    ("/%70refix/metrics", "/metrics"),
    ("/%50REFIX/metrics", "/metrics"),
    ("/prefix%2Fmetrics", "/metrics"),
    // What follows the cut goes on as it was sent: escapes, the query.
    (
        "/prefix/m%65trics?next=/prefix/",
        "/m%65trics?next=/prefix/",
    ),
    ("/prefix/a%2Fb?q=%20", "/a%2Fb?q=%20"),
    // A location path without a trailing `/`: the `/` of the rest is the leading one.
    ("/mt4/metrics", "/metrics"),
    ("/mt4", "/"),
    ("/mt4?x=1", "/?x=1"),
    ("/MT4/metrics", "/metrics"),
    // It is a prefix of the path, not of a segment.
    ("/mt4x/metrics", "/x/metrics"),
    ("/mt4.json", "/.json"),
];

/// Under a location without `strip_path`: they go on as they came.
const AS_RECEIVED: [&str; 5] = [
    "/keep/x",
    "/keep/x?y=1",
    "/other/prefix/x",
    // `/prefix/` is longer than these.
    "/prefix",
    "/prefix?x=1",
];

/// One keep-alive connection, one request after another.
const ON_ONE_CONNECTION: [(&str, &str); 4] = [
    ("/prefix/a", "/a"),
    ("/keep/x", "/keep/x"),
    ("/PREFIX/", "/"),
    ("/mt4/b", "/b"),
];

/// The cut joins what was on its two sides into a `..`, a `.` or an empty segment - which the
/// path did not have as it came. Answered 400, as a path which came so is.
const AMBIGUOUS_AT_THE_SEAM: [&str; 4] = ["/mt4..%2Fx", "/mt4.%2Fx", "/mt4%2Fx", "/mt4..;/x"];

/// `/prefix/` and `/mt4` with `strip_path`, `/keep/` and `/` without, all to the same upstream.
fn locations(upstream_port: u16) -> String {
    let to = format!("'http://127.0.0.1:{upstream_port}'");

    format!(
        "- path: /prefix/\n  type: http\n  proxy_pass_to: {to}\n  strip_path: true\n\
         - path: /mt4\n  type: http\n  proxy_pass_to: {to}\n  strip_path: true\n\
         - path: /keep/\n  type: http\n  proxy_pass_to: {to}\n\
         - path: /\n  type: http\n  proxy_pass_to: {to}\n"
    )
}

fn request_lines<'s>(targets: impl IntoIterator<Item = &'s str>) -> Vec<String> {
    targets
        .into_iter()
        .map(|target| format!("GET {target} HTTP/1.1"))
        .collect()
}

/// What the upstream gets, in the order the tests send it.
fn expected_at_the_upstream() -> Vec<String> {
    request_lines(
        STRIPPED
            .iter()
            .map(|(_, expected)| *expected)
            .chain(AS_RECEIVED)
            .chain(ON_ONE_CONNECTION.iter().map(|(_, expected)| *expected)),
    )
}

#[tokio::test]
async fn http_a_location_with_strip_path_sends_the_rest_of_the_target() {
    let upstream = Upstream::start().await;
    let port =
        start_endpoint_with_locations(ListenHttpEndpointType::Http1, &locations(upstream.port))
            .await;

    for (target, expected) in STRIPPED {
        let mut client = H1Client::connect(port).await;
        let response = client.get(target, None).await;
        assert_eq!(response.status, 200, "{target}");
        assert_eq!(response.body, expected.as_bytes(), "{target}");
    }

    for target in AS_RECEIVED {
        let mut client = H1Client::connect(port).await;
        let response = client.get(target, None).await;
        assert_eq!(response.status, 200, "{target}");
        assert_eq!(response.body, target.as_bytes(), "{target}");
    }

    let mut client = H1Client::connect(port).await;
    for (target, expected) in ON_ONE_CONNECTION {
        let response = client.get(target, None).await;
        assert_eq!(response.status, 200, "{target}");
        assert_eq!(response.body, expected.as_bytes(), "{target}");
    }

    // An ordinary answer: the connection goes on after it, and nothing goes upstream.
    for target in AMBIGUOUS_AT_THE_SEAM {
        let response = client.get(target, None).await;
        assert_eq!(response.status, 400, "{target}");
    }

    assert_eq!(upstream.requests(), expected_at_the_upstream());
}

/// A WebSocket handshake goes on to the upstream with the head the reader compiled: the target
/// in its request line is the stripped one. The upstream here refuses the upgrade, and its
/// answer is relayed.
#[tokio::test]
async fn http_a_websocket_upgrade_through_a_location_with_strip_path_is_stripped() {
    let upstream = Upstream::start().await;
    let port =
        start_endpoint_with_locations(ListenHttpEndpointType::Http1, &locations(upstream.port))
            .await;

    let mut client = H1Client::connect(port).await;
    client
        .stream
        .write_all(
            format!(
                "GET /prefix/ws?room=1 HTTP/1.1\r\nHost: localhost:{port}\r\nUpgrade: websocket\r\n\
                 Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                 Sec-WebSocket-Version: 13\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let response = client.read_response().await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"/ws?room=1");

    assert_eq!(upstream.requests(), ["GET /ws?room=1 HTTP/1.1"]);
}

/// All of it on one h2c connection: hyper takes the client's uri in absolute form, and the cut
/// keeps its scheme and authority.
#[tokio::test]
async fn http2_a_location_with_strip_path_sends_the_rest_of_the_target() {
    let upstream = Upstream::start().await;
    let port =
        start_endpoint_with_locations(ListenHttpEndpointType::Http2, &locations(upstream.port))
            .await;

    let mut client = H2Client::connect(port).await;

    for (target, expected) in STRIPPED
        .iter()
        .copied()
        .chain(AS_RECEIVED.iter().map(|target| (*target, *target)))
        .chain(ON_ONE_CONNECTION)
    {
        let response = client.get(target, None).await;
        assert_eq!(response.status, 200, "{target}");
        assert_eq!(response.body, expected.as_bytes(), "{target}");
    }

    for target in AMBIGUOUS_AT_THE_SEAM {
        let response = client.get(target, None).await;
        assert_eq!(response.status, 400, "{target}");
        assert_eq!(response.body, b"Bad Request", "{target}");
    }

    assert_eq!(upstream.requests(), expected_at_the_upstream());
}

/// A `dynamic` location sends the request to the upstream the client names in `proxy-to`, and
/// with `strip_path` the target without the location path - on both paths of the proxy.
#[tokio::test]
async fn a_dynamic_location_with_strip_path_sends_the_rest_of_the_target() {
    let upstream = Upstream::start().await;
    let proxy_to = format!("http://127.0.0.1:{}", upstream.port);
    let locations = "- path: /dynamic/\n  type: dynamic\n  strip_path: true\n";

    let port = start_endpoint_with_locations(ListenHttpEndpointType::Http1, locations).await;
    let mut client = H1Client::connect(port).await;
    client
        .stream
        .write_all(
            format!(
                "GET /dynamic/metrics?x=1 HTTP/1.1\r\nHost: localhost:{port}\r\nproxy-to: {proxy_to}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let response = client.read_response().await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"/metrics?x=1");

    let port = start_endpoint_with_locations(ListenHttpEndpointType::Http2, locations).await;
    let (status, body) = h2_get_with_proxy_to(port, "/DYNAMIC/a/b?y=2", &proxy_to).await;
    assert_eq!(status, 200);
    assert_eq!(body, b"/a/b?y=2");

    assert_eq!(
        upstream.requests(),
        ["GET /metrics?x=1 HTTP/1.1", "GET /a/b?y=2 HTTP/1.1"]
    );
}

/// A `GET` over h2c with the header `proxy-to`: the status and the body of the answer.
async fn h2_get_with_proxy_to(port: u16, target: &str, proxy_to: &str) -> (u16, Vec<u8>) {
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();

    let (mut sender, connection) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(stream),
    )
    .await
    .unwrap();
    tokio::spawn(connection);

    let request = hyper::Request::builder()
        .uri(format!("http://localhost:{port}{target}"))
        .header("proxy-to", proxy_to)
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();

    let response = sender.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();

    (status, body.to_vec())
}

/// `${PATH_AND_QUERY}` is the path and query of the request the client sent - a location with
/// `strip_path` does not change what it is - on both paths of the proxy.
#[tokio::test]
async fn path_and_query_in_a_request_header_is_the_one_of_the_client() {
    let upstream_port = start_head_echo().await;

    let locations = format!(
        "- path: /prefix/\n  type: http\n  proxy_pass_to: 'http://127.0.0.1:{upstream_port}'\n  strip_path: true\n  \
         modify_http_headers:\n    add:\n      request:\n      - name: x-client-path\n        value: ${{PATH_AND_QUERY}}\n"
    );

    for endpoint_type in [ListenHttpEndpointType::Http1, ListenHttpEndpointType::Http2] {
        let port = start_endpoint_with_locations(endpoint_type, &locations).await;

        let response = match endpoint_type {
            ListenHttpEndpointType::Http1 => {
                let mut client = H1Client::connect(port).await;
                client.get("/prefix/metrics?x=1", None).await
            }
            _ => {
                let mut client = H2Client::connect(port).await;
                client.get("/prefix/metrics?x=1", None).await
            }
        };

        assert_eq!(response.status, 200, "{}", endpoint_type.as_str());

        let head = String::from_utf8(response.body).unwrap().to_lowercase();

        assert!(
            head.starts_with("get /metrics?x=1 http/1.1\r\n"),
            "{}: {head}",
            endpoint_type.as_str()
        );
        assert!(
            head.contains("\r\nx-client-path: /prefix/metrics?x=1\r\n"),
            "{}: {head}",
            endpoint_type.as_str()
        );
    }
}

/// An HTTP/1.1 upstream which answers every request with the head of it.
async fn start_head_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };

            tokio::spawn(async move {
                let mut received = Vec::new();
                let mut buffer = [0u8; 4096];

                // One request a connection, none of them with a body.
                let head_end = loop {
                    if let Some(end) = find(&received, b"\r\n\r\n") {
                        break end + 4;
                    }

                    match stream.read(&mut buffer).await {
                        Ok(read) if read > 0 => received.extend_from_slice(&buffer[..read]),
                        _ => return,
                    }
                };

                let mut response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {head_end}\r\nConnection: close\r\n\r\n"
                )
                .into_bytes();
                response.extend_from_slice(&received[..head_end]);

                let _ = stream.write_all(&response).await;
            });
        }
    });

    port
}

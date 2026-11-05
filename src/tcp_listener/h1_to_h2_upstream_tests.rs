//! An h1 client of an `http` endpoint, a location whose upstream speaks h2 (h2c by prior
//! knowledge): end to end through the h1 pipeline. The reader compiles the head and streams the
//! body as it does for any upstream; the request goes through the location's h2 pool and the
//! response comes back as h1 - with its own length, or chunked when the upstream gave none.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Notify,
};

use super::ambiguous_path_tests::{find, start_endpoint_with_locations};
use crate::configurations::ListenHttpEndpointType;

const TIMEOUT: Duration = Duration::from_secs(10);

/// `/big` answers this many frames of [`BIG_FRAME`] bytes, with no length.
const BIG_FRAMES: usize = 32;
const BIG_FRAME: usize = 64 * 1024;

/// A request as the h2 upstream got it.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    target: String,
    headers: http::HeaderMap,
    body: Vec<u8>,
}

/// An h2c upstream. `/sse` sends one event, waits for [`H2Upstream::release`], sends another;
/// `/big` sends [`BIG_FRAMES`] frames; anything else answers the request body - or the target
/// when there is none - with its length.
struct H2Upstream {
    port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
    release: Arc<Notify>,
}

impl H2Upstream {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let seen = Arc::new(Mutex::new(Vec::new()));
        let release = Arc::new(Notify::new());

        let (recorded, released) = (seen.clone(), release.clone());

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };

                let (recorded, released) = (recorded.clone(), released.clone());

                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |request| {
                        let (recorded, released) = (recorded.clone(), released.clone());
                        async move { Ok::<_, Infallible>(answer(request, recorded, released).await) }
                    });

                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });

        Self {
            port,
            seen,
            release,
        }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

async fn answer(
    request: hyper::Request<hyper::body::Incoming>,
    seen: Arc<Mutex<Vec<Seen>>>,
    release: Arc<Notify>,
) -> hyper::Response<BoxBody<Bytes, Infallible>> {
    let (parts, body) = request.into_parts();
    let body = body.collect().await.unwrap().to_bytes().to_vec();

    let target = parts
        .uri
        .path_and_query()
        .map(|path_and_query| path_and_query.as_str().to_string())
        .unwrap_or_default();

    seen.lock().unwrap().push(Seen {
        method: parts.method.to_string(),
        target: target.clone(),
        headers: parts.headers.clone(),
        body: body.clone(),
    });

    let body = match parts.uri.path() {
        "/sse" => {
            let events = futures::stream::unfold(0u8, move |step| {
                let release = release.clone();
                async move {
                    let event: &'static [u8] = match step {
                        0 => b"data: 1\n\n",
                        1 => {
                            release.notified().await;
                            b"data: 2\n\n"
                        }
                        _ => return None,
                    };
                    Some((Ok(Frame::data(Bytes::from_static(event))), step + 1))
                }
            });

            return hyper::Response::builder()
                .header("content-type", "text/event-stream")
                .body(BodyExt::boxed(StreamBody::new(events)))
                .unwrap();
        }
        "/big" => {
            let frames = futures::stream::iter(
                (0..BIG_FRAMES).map(|no| Ok(Frame::data(Bytes::from(big_frame(no))))),
            );

            return hyper::Response::builder()
                .body(BodyExt::boxed(StreamBody::new(frames)))
                .unwrap();
        }
        _ if body.is_empty() => target.into_bytes(),
        _ => body,
    };

    hyper::Response::builder()
        .header("x-upstream", "h2")
        .body(Full::new(Bytes::from(body)).boxed())
        .unwrap()
}

fn big_frame(no: usize) -> Vec<u8> {
    (0..BIG_FRAME)
        .map(|i| ((no * BIG_FRAME + i) % 251) as u8)
        .collect()
}

/// The proxy under test: an `http` endpoint with `/api/` and `/` on the h2 upstream as
/// `http2` locations, and `/tools` on it as an `mcp-h2` one.
async fn start_proxy(upstream_port: u16) -> u16 {
    let to = format!("'http://127.0.0.1:{upstream_port}'");

    start_endpoint_with_locations(
        ListenHttpEndpointType::Http1,
        &format!(
            "- path: /tools\n  type: mcp-h2\n  proxy_pass_to: 'http://127.0.0.1:{upstream_port}/mcp'\n\
             - path: /api/\n  type: http2\n  proxy_pass_to: {to}\n\
             - path: /\n  type: http2\n  proxy_pass_to: {to}\n"
        ),
    )
    .await
}

struct Response {
    status: u16,
    head: String,
    body: Vec<u8>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().find_map(|line| {
            let (header, value) = line.split_once(':')?;
            header.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }
}

/// A raw h1 client: it sends what it is given and reads responses framed either way.
struct Client {
    stream: TcpStream,
    port: u16,
    received: Vec<u8>,
}

impl Client {
    async fn connect(port: u16) -> Self {
        Self {
            stream: TcpStream::connect(("127.0.0.1", port)).await.unwrap(),
            port,
            received: Vec::new(),
        }
    }

    /// `headers`: more header lines, each one with its `\r\n`.
    async fn send_head(&mut self, method: &str, target: &str, headers: &str) {
        let head = format!(
            "{method} {target} HTTP/1.1\r\nHost: localhost:{}\r\n{headers}\r\n",
            self.port
        );
        self.send(head.as_bytes()).await;
    }

    async fn send(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).await.unwrap();
    }

    async fn get(&mut self, target: &str) -> Response {
        self.send_head("GET", target, "").await;
        self.read_response().await
    }

    async fn read_more(&mut self) {
        let mut buffer = [0u8; 16 * 1024];

        let read = tokio::time::timeout(TIMEOUT, self.stream.read(&mut buffer))
            .await
            .expect("nothing came in time")
            .unwrap();

        assert!(
            read > 0,
            "the connection was closed: {:?}",
            String::from_utf8_lossy(&self.received)
        );

        self.received.extend_from_slice(&buffer[..read]);
    }

    /// Reads until `needle` is in what came, and leaves it there.
    async fn wait_for(&mut self, needle: &[u8]) {
        while find(&self.received, needle).is_none() {
            self.read_more().await;
        }
    }

    async fn read_head(&mut self) -> (u16, String) {
        self.wait_for(b"\r\n\r\n").await;

        let end = find(&self.received, b"\r\n\r\n").unwrap() + 4;
        let head = String::from_utf8(self.received.drain(..end).collect()).unwrap();
        let status = head[9..12].parse().unwrap();

        (status, head)
    }

    async fn read_response(&mut self) -> Response {
        let (status, head) = self.read_head().await;
        let mut response = Response {
            status,
            head,
            body: Vec::new(),
        };

        response.body = if let Some(length) = response.header("content-length") {
            let length: usize = length.parse().unwrap();
            while self.received.len() < length {
                self.read_more().await;
            }
            self.received.drain(..length).collect()
        } else {
            assert_eq!(
                response.header("transfer-encoding"),
                Some("chunked"),
                "{}",
                response.head
            );
            self.read_chunked_body().await
        };

        response
    }

    async fn read_chunked_body(&mut self) -> Vec<u8> {
        let mut body = Vec::new();

        loop {
            self.wait_for(b"\r\n").await;
            let line_end = find(&self.received, b"\r\n").unwrap();
            let size =
                usize::from_str_radix(std::str::from_utf8(&self.received[..line_end]).unwrap(), 16)
                    .unwrap();
            self.received.drain(..line_end + 2);

            while self.received.len() < size + 2 {
                self.read_more().await;
            }

            body.extend(self.received.drain(..size));
            assert_eq!(self.received.drain(..2).collect::<Vec<u8>>(), b"\r\n");

            if size == 0 {
                return body;
            }
        }
    }
}

#[tokio::test]
async fn a_get_goes_to_the_h2_upstream_and_back_on_a_kept_connection() {
    let upstream = H2Upstream::start().await;
    let port = start_proxy(upstream.port).await;

    let mut client = Client::connect(port).await;

    for target in ["/api/x?y=1", "/other"] {
        let response = client.get(target).await;
        assert_eq!(response.status, 200, "{target}");
        assert_eq!(response.body, target.as_bytes(), "{target}");
        assert_eq!(response.header("x-upstream"), Some("h2"), "{target}");
    }

    let seen = upstream.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].method, "GET");
    assert_eq!(seen[0].target, "/api/x?y=1");
    assert_eq!(
        seen[0].headers.get("host").unwrap(),
        format!("localhost:{port}").as_str()
    );
    assert_eq!(seen[0].headers.get("x-forwarded-for").unwrap(), "127.0.0.1");
    assert_eq!(seen[1].target, "/other");
}

#[tokio::test]
async fn a_body_of_known_length_goes_to_the_h2_upstream() {
    let upstream = H2Upstream::start().await;
    let port = start_proxy(upstream.port).await;

    let mut client = Client::connect(port).await;
    client
        .send_head("POST", "/api/echo", "Content-Length: 11\r\n")
        .await;
    client.send(b"hello world").await;

    let response = client.read_response().await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"hello world");

    let seen = upstream.seen();
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].body, b"hello world");
    assert_eq!(seen[0].headers.get("content-length").unwrap(), "11");
}

/// The upstream gets the data of the chunks, not their framing.
#[tokio::test]
async fn a_chunked_body_goes_to_the_h2_upstream_without_its_framing() {
    let upstream = H2Upstream::start().await;
    let port = start_proxy(upstream.port).await;

    let mut client = Client::connect(port).await;
    client
        .send_head("POST", "/api/echo", "Transfer-Encoding: chunked\r\n")
        .await;
    client.send(b"5\r\nhello\r\n").await;
    client.send(b"6\r\n world\r\n0\r\n\r\n").await;

    let response = client.read_response().await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"hello world");

    let seen = upstream.seen();
    assert_eq!(seen[0].body, b"hello world");
    assert!(seen[0].headers.get("transfer-encoding").is_none());

    // The connection is in step for the next request.
    let response = client.get("/api/next").await;
    assert_eq!(response.body, b"/api/next");
}

/// The client waits for `100 Continue` before it sends the body. The h2 upstream is not asked
/// for one: the proxy answers it.
#[tokio::test]
async fn expect_100_continue_is_answered_before_the_body_is_sent() {
    let upstream = H2Upstream::start().await;
    let port = start_proxy(upstream.port).await;

    let mut client = Client::connect(port).await;
    client
        .send_head(
            "PUT",
            "/api/upload",
            "Expect: 100-continue\r\nContent-Length: 5\r\n",
        )
        .await;

    let (status, _) = client.read_head().await;
    assert_eq!(status, 100);

    client.send(b"hello").await;

    let response = client.read_response().await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"hello");

    assert!(upstream.seen()[0].headers.get("expect").is_none());
}

/// A response with no length is sent chunked, and every frame goes out as it comes: the first
/// event reaches the client while the upstream still holds the second one.
#[tokio::test]
async fn an_event_stream_reaches_the_client_as_it_comes() {
    let upstream = H2Upstream::start().await;
    let port = start_proxy(upstream.port).await;

    let mut client = Client::connect(port).await;
    client.send_head("GET", "/sse", "").await;

    let (status, head) = client.read_head().await;
    assert_eq!(status, 200);
    let response = Response {
        status,
        head,
        body: Vec::new(),
    };
    assert_eq!(response.header("transfer-encoding"), Some("chunked"));
    assert_eq!(response.header("content-type"), Some("text/event-stream"));

    client.wait_for(b"data: 1").await;
    upstream.release.notify_one();

    assert_eq!(client.read_chunked_body().await, b"data: 1\n\ndata: 2\n\n");

    // The chunked end is where the response ends: the connection goes on.
    let response = client.get("/after").await;
    assert_eq!(response.body, b"/after");
}

#[tokio::test]
async fn a_big_response_streams_through_whole() {
    let upstream = H2Upstream::start().await;
    let port = start_proxy(upstream.port).await;

    let mut client = Client::connect(port).await;
    let response = client.get("/big").await;

    assert_eq!(response.status, 200);
    let expected: Vec<u8> = (0..BIG_FRAMES).flat_map(big_frame).collect();
    assert_eq!(response.body.len(), expected.len());
    assert!(response.body == expected, "the body came changed");
}

/// The response to a `HEAD` is its head alone, whatever its headers say: a body after it would
/// be read as the next response.
#[tokio::test]
async fn a_head_request_gets_no_body() {
    let upstream = H2Upstream::start().await;
    let port = start_proxy(upstream.port).await;

    let mut client = Client::connect(port).await;
    client.send_head("HEAD", "/api/x", "").await;

    let (status, head) = client.read_head().await;
    assert_eq!(status, 200);
    assert!(
        !head.to_ascii_lowercase().contains("transfer-encoding"),
        "{head}"
    );

    let response = client.get("/api/y").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"/api/y");

    assert_eq!(upstream.seen()[0].method, "HEAD");
}

/// An `mcp-h2` location under an `http` endpoint: the request goes to the MCP path of the
/// upstream.
#[tokio::test]
async fn an_mcp_h2_location_sends_to_its_mcp_path() {
    let upstream = H2Upstream::start().await;
    let port = start_proxy(upstream.port).await;

    let request = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;

    let mut client = Client::connect(port).await;
    client
        .send_head(
            "POST",
            "/tools",
            &format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                request.len()
            ),
        )
        .await;
    client.send(request).await;

    let response = client.read_response().await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, request);

    assert_eq!(upstream.seen()[0].target, "/mcp");
}

#[tokio::test]
async fn an_h2_upstream_which_is_down_gets_the_error_page() {
    // A port nobody listens on.
    let closed_port = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    };

    let port = start_proxy(closed_port).await;

    let mut client = Client::connect(port).await;
    let response = client.get("/api/x").await;

    assert_eq!(response.status, 503);
}

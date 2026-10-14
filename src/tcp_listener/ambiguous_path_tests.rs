//! A request whose path names its resource in more than one way - a `..`, a `.` or an empty
//! segment - gets to no location: end to end, on an `http` endpoint (the h1 pipeline) and on an
//! `http2` one (hyper).
//!
//! The endpoint has open locations next to a guarded one, all to the same upstream: `/open`,
//! `/secure` with an `auth_header`, and `/` for everything else. A location is picked by what
//! the path starts with and the path goes to the upstream as it was received, so
//! `/open/../secure/x` would be let in by `/open` and served by the upstream as `/secure/x`.
//! The upstream here records every request line it gets: a refused request is one it never saw.
//!
//! For the same reason a location is picked by the path decoded: `/%73ecure/x` is `/secure/x`
//! to an upstream, and is held to the rules of `/secure` here.
//!
//! The HTTP/1.1 client is a socket written to by hand: what a test sends is what gets to the
//! wire, a `..` in the path included.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::{
    configurations::{EndpointHttpHostString, ListenHttpEndpointType},
    settings::HostSettings,
    settings_compiled::SettingsCompiled,
};

const TIMEOUT: Duration = Duration::from_secs(5);

const SECRET: &str = "Bearer secret";

/// Each of these starts with `/open` and is `/secure/x` to an upstream which resolves the
/// segment, decodes the path, takes `\` for a separator or takes path parameters off.
const AROUND_THE_GUARD: [&str; 14] = [
    "/open/../secure/x",
    "/open/%2e%2e/secure/x",
    "/open/%2E%2E/secure/x",
    "/open/.%2e/secure/x",
    "/open/..%2fsecure/x",
    "/open%2f..%2fsecure/x",
    "/open/..\\secure/x",
    "/open/..%5csecure/x",
    "/open/..;/secure/x",
    "/open/../secure/x?v=1",
    // Without `..`: to an upstream these are `/open/secure/x` - another way to write a path,
    // which a location written for it would not see.
    "/open//secure/x",
    "/open/./secure/x",
    "/open/%2e/secure/x",
    "/open/%2fsecure/x",
];

/// These start with neither path: they would be let in by the location `/`.
const TO_NO_LOCATION: [&str; 4] = ["//secure/x", "/./secure/x", "/../secure/x", "/%2fsecure/x"];

/// Dots in a name, and anything in a query string, are not segments.
const ORDINARY: [&str; 6] = [
    "/open/x",
    "/open/a..b",
    "/open/..a",
    "/open/.well-known/x",
    "/open/x?next=/../y",
    "/open/x?a=//b/./c",
];

#[tokio::test]
async fn http_a_path_around_the_guarded_location_is_refused() {
    let upstream = Upstream::start().await;
    let port = start_endpoint(ListenHttpEndpointType::Http1, upstream.port).await;

    for target in AROUND_THE_GUARD.iter().chain(TO_NO_LOCATION.iter()) {
        let mut client = H1Client::connect(port).await;

        let response = client.get(target, None).await;
        assert_eq!(response.status, 400, "{target}");
        assert_eq!(upstream.requests(), [""; 0], "{target}");
    }
}

/// A refused request is an ordinary response: its body is read off the connection, and the
/// next request on it is served.
#[tokio::test]
async fn http_the_connection_goes_on_after_a_refused_path() {
    let upstream = Upstream::start().await;
    let port = start_endpoint(ListenHttpEndpointType::Http1, upstream.port).await;

    let mut client = H1Client::connect(port).await;

    let response = client.get("/open/../secure/x", None).await;
    assert_eq!(response.status, 400);

    let response = client
        .request(
            "POST",
            "/open//secure/x",
            "Content-Length: 11\r\n",
            b"GET / HTTP/",
        )
        .await;
    assert_eq!(response.status, 400);

    let response = client
        .request(
            "POST",
            "/open/./secure/x",
            "Transfer-Encoding: chunked\r\n",
            b"5\r\nhello\r\n0\r\n\r\n",
        )
        .await;
    assert_eq!(response.status, 400);

    let response = client.get("/open/x", None).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"/open/x");

    assert_eq!(upstream.requests(), ["GET /open/x HTTP/1.1"]);
}

#[tokio::test]
async fn http_the_locations_serve_as_they_did() {
    let upstream = Upstream::start().await;
    let port = start_endpoint(ListenHttpEndpointType::Http1, upstream.port).await;

    for target in ORDINARY {
        let mut client = H1Client::connect(port).await;

        let response = client.get(target, None).await;
        assert_eq!(response.status, 200, "{target}");
        assert_eq!(response.body, target.as_bytes(), "{target}");
    }

    let mut client = H1Client::connect(port).await;
    let response = client.get("/secure/x", None).await;
    assert_eq!(response.status, 401);

    let mut client = H1Client::connect(port).await;
    let response = client.get("/secure/x", Some(SECRET)).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"/secure/x");

    let mut expected: Vec<String> = ORDINARY
        .iter()
        .map(|target| format!("GET {target} HTTP/1.1"))
        .collect();
    expected.push("GET /secure/x HTTP/1.1".to_string());

    assert_eq!(upstream.requests(), expected);
}

#[tokio::test]
async fn http2_a_path_around_the_guarded_location_is_refused() {
    let upstream = Upstream::start().await;
    let port = start_endpoint(ListenHttpEndpointType::Http2, upstream.port).await;

    let mut client = H2Client::connect(port).await;

    for target in AROUND_THE_GUARD.iter().chain(TO_NO_LOCATION.iter()) {
        let response = client.get(target, None).await;
        assert_eq!(response.status, 400, "{target}");
        assert_eq!(response.body, b"Bad Request", "{target}");
        assert_eq!(upstream.requests(), [""; 0], "{target}");
    }

    // The connection serves after that as it did.
    let response = client.get("/open/x", None).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"/open/x");
}

#[tokio::test]
async fn http2_the_locations_serve_as_they_did() {
    let upstream = Upstream::start().await;
    let port = start_endpoint(ListenHttpEndpointType::Http2, upstream.port).await;

    let mut client = H2Client::connect(port).await;

    for target in ORDINARY {
        let response = client.get(target, None).await;
        assert_eq!(response.status, 200, "{target}");
        assert_eq!(response.body, target.as_bytes(), "{target}");
    }

    let response = client.get("/secure/x", None).await;
    assert_eq!(response.status, 401);

    // The page of an error is a page: the head of the response is the one hyper makes, and
    // no second one stands at the start of the body.
    let page = String::from_utf8(response.body).unwrap();
    assert!(page.contains("Unauthorized request"), "{page}");
    assert!(!page.contains("HTTP/1.1"), "{page}");
    assert!(!page.contains("content-length"), "{page}");

    let response = client.get("/secure/x", Some(SECRET)).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"/secure/x");
}

/// `/secure` with a letter of it percent-encoded: the same path to an upstream which decodes it,
/// and another one to a comparison of the bytes - one the location `/` would take.
const GUARDED_ENCODED: [&str; 4] = [
    "/%73ecure/x",
    "/%53ECURE/x",
    "/s%65cure/x",
    "/%73%65%63%75%72%65/x",
];

#[tokio::test]
async fn http_a_guarded_location_is_picked_by_the_decoded_path() {
    let upstream = Upstream::start().await;
    let port = start_endpoint(ListenHttpEndpointType::Http1, upstream.port).await;

    for target in GUARDED_ENCODED {
        let mut client = H1Client::connect(port).await;
        let response = client.get(target, None).await;
        assert_eq!(response.status, 401, "{target}");
        assert_eq!(upstream.requests(), [""; 0], "{target}");
    }

    // With the token it is served, and the upstream gets the path as it was received.
    let mut client = H1Client::connect(port).await;
    let response = client.get("/%73ecure/x", Some(SECRET)).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"/%73ecure/x");
    assert_eq!(upstream.requests(), ["GET /%73ecure/x HTTP/1.1"]);

    // An escape in a path which is under no other location: the location `/` takes it.
    let mut client = H1Client::connect(port).await;
    let response = client.get("/%6fther/x", None).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"/%6fther/x");
}

#[tokio::test]
async fn http2_a_guarded_location_is_picked_by_the_decoded_path() {
    let upstream = Upstream::start().await;
    let port = start_endpoint(ListenHttpEndpointType::Http2, upstream.port).await;

    let mut client = H2Client::connect(port).await;

    for target in GUARDED_ENCODED {
        let response = client.get(target, None).await;
        assert_eq!(response.status, 401, "{target}");
        assert_eq!(upstream.requests(), [""; 0], "{target}");
    }

    let response = client.get("/%73ecure/x", Some(SECRET)).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"/%73ecure/x");
    assert_eq!(upstream.requests(), ["GET /%73ecure/x HTTP/1.1"]);

    let response = client.get("/%6fther/x", None).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"/%6fther/x");
}

/// An HTTP/1.1 upstream which answers every request with its own target and keeps the request
/// lines it got.
pub(super) struct Upstream {
    pub(super) port: u16,
    request_lines: Arc<Mutex<Vec<String>>>,
}

impl Upstream {
    pub(super) async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let request_lines = Arc::new(Mutex::new(Vec::new()));
        let recorded = request_lines.clone();

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };

                let recorded = recorded.clone();

                tokio::spawn(async move {
                    let mut received = Vec::new();
                    let mut buffer = [0u8; 4096];

                    // One request a connection, none of them with a body.
                    while find(&received, b"\r\n\r\n").is_none() {
                        match tokio::time::timeout(TIMEOUT, stream.read(&mut buffer)).await {
                            Ok(Ok(read)) if read > 0 => received.extend_from_slice(&buffer[..read]),
                            _ => return,
                        }
                    }

                    let head = String::from_utf8_lossy(&received);
                    let request_line = head.lines().next().unwrap_or_default().to_string();
                    let target = request_line
                        .split(' ')
                        .nth(1)
                        .unwrap_or_default()
                        .to_string();

                    recorded.lock().unwrap().push(request_line);

                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        target.len(),
                        target
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });

        Self {
            port,
            request_lines,
        }
    }

    pub(super) fn requests(&self) -> Vec<String> {
        self.request_lines.lock().unwrap().clone()
    }
}

/// The proxy under test: one endpoint on a free port with the locations `/open`, `/secure` and
/// `/`, compiled from settings the same way a settings file is.
pub(super) async fn start_endpoint(
    endpoint_type: ListenHttpEndpointType,
    upstream_port: u16,
) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listening_addr = listener.local_addr().unwrap();

    let host_settings: HostSettings = my_settings_reader::serde_yaml::from_str(&format!(
        "endpoint:\n  type: {}\nlocations:\n\
         - path: /open\n  type: http\n  proxy_pass_to: 'http://127.0.0.1:{upstream_port}'\n\
         - path: /secure\n  type: http\n  proxy_pass_to: 'http://127.0.0.1:{upstream_port}'\n  auth_header: '{SECRET}'\n\
         - path: /\n  type: http\n  proxy_pass_to: 'http://127.0.0.1:{upstream_port}'\n",
        endpoint_type.as_str(),
    ))
    .unwrap();

    let host_endpoint =
        EndpointHttpHostString::new(format!("localhost:{}", listening_addr.port())).unwrap();

    let endpoint_info = crate::scripts::compile_http_configuration(
        &SettingsCompiled::default(),
        host_endpoint,
        &host_settings,
        endpoint_type,
    )
    .await
    .unwrap();

    let configuration =
        Arc::new(crate::scripts::merge_http_into_existing(None, endpoint_info).unwrap());

    tokio::spawn(async move {
        loop {
            let Ok((tcp_stream, client_addr)) = listener.accept().await else {
                return;
            };

            match endpoint_type {
                ListenHttpEndpointType::Http1 => {
                    crate::h1_proxy_server::kick_h1_tcp_reverse_proxy_server_from_http(
                        tcp_stream,
                        client_addr,
                        configuration.clone(),
                    );
                }
                _ => {
                    super::http2::handle_connection(
                        (tcp_stream, client_addr).into(),
                        listening_addr.into(),
                        configuration.clone(),
                    )
                    .await;
                }
            }
        }
    });

    listening_addr.port()
}

pub(super) struct Response {
    pub(super) status: u16,
    pub(super) body: Vec<u8>,
}

pub(super) struct H1Client {
    pub(super) stream: TcpStream,
    port: u16,
    /// What was read past the end of the last response.
    received: Vec<u8>,
}

impl H1Client {
    pub(super) async fn connect(port: u16) -> Self {
        Self {
            stream: TcpStream::connect(("127.0.0.1", port)).await.unwrap(),
            port,
            received: Vec::new(),
        }
    }

    pub(super) async fn get(&mut self, target: &str, authorization: Option<&str>) -> Response {
        let headers = match authorization {
            Some(authorization) => format!("Authorization: {authorization}\r\n"),
            None => String::new(),
        };

        self.request("GET", target, &headers, b"").await
    }

    /// `headers`: more header lines, each one with its `\r\n`.
    async fn request(
        &mut self,
        method: &str,
        target: &str,
        headers: &str,
        body: &[u8],
    ) -> Response {
        let mut request = format!(
            "{method} {target} HTTP/1.1\r\nHost: localhost:{}\r\n{headers}\r\n",
            self.port
        )
        .into_bytes();
        request.extend_from_slice(body);

        self.stream.write_all(&request).await.unwrap();

        self.read_response().await
    }

    /// Every response here has a `content-length`.
    pub(super) async fn read_response(&mut self) -> Response {
        let head_end = loop {
            if let Some(end) = find(&self.received, b"\r\n\r\n") {
                break end + 4;
            }

            assert!(
                self.read_more().await > 0,
                "connection closed before the response head: {:?}",
                String::from_utf8_lossy(&self.received)
            );
        };

        let head = String::from_utf8(self.received[..head_end].to_vec()).unwrap();

        let content_length: usize = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().unwrap())
            })
            .unwrap_or_else(|| panic!("no content-length in: {}", head));

        while self.received.len() < head_end + content_length {
            assert!(
                self.read_more().await > 0,
                "connection closed before the end of the response body"
            );
        }

        let body = self.received[head_end..head_end + content_length].to_vec();
        self.received.drain(..head_end + content_length);

        // `HTTP/1.1 200 OK`
        let status = head[9..12].parse().unwrap();

        Response { status, body }
    }

    async fn read_more(&mut self) -> usize {
        let mut buffer = [0u8; 4096];

        let read = tokio::time::timeout(TIMEOUT, self.stream.read(&mut buffer))
            .await
            .expect("no response in time")
            .unwrap();

        self.received.extend_from_slice(&buffer[..read]);

        read
    }
}

/// An h2c client: the `:path` it sends is the target as it is written.
struct H2Client {
    sender: hyper::client::conn::http2::SendRequest<Empty<Bytes>>,
    port: u16,
}

impl H2Client {
    async fn connect(port: u16) -> Self {
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

        let (sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                .await
                .unwrap();

        tokio::spawn(connection);

        Self { sender, port }
    }

    async fn get(&mut self, target: &str, authorization: Option<&str>) -> Response {
        let uri: hyper::Uri = format!("http://localhost:{}{target}", self.port)
            .parse()
            .unwrap_or_else(|err| panic!("{target}: {err}"));

        // Nothing on the way to the wire may have rewritten the path.
        assert_eq!(uri.path_and_query().unwrap().as_str(), target);

        let mut request = hyper::Request::builder().method("GET").uri(uri);
        if let Some(authorization) = authorization {
            request = request.header("authorization", authorization);
        }

        let response = tokio::time::timeout(
            TIMEOUT,
            self.sender
                .send_request(request.body(Empty::<Bytes>::new()).unwrap()),
        )
        .await
        .expect("no response in time")
        .unwrap();

        let status = response.status().as_u16();
        let body = response.into_body().collect().await.unwrap().to_bytes();

        Response {
            status,
            body: body.to_vec(),
        }
    }
}

pub(super) fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

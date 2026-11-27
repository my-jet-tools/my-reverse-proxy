//! An MCP server on a unix socket of this host, published by an `mcp` / `mcp-h2` location whose
//! `proxy_pass_to` is `<socket file>:<path>`: end to end, for an http/1.1 client (the h1
//! pipeline) and an h2 one (hyper), on an `http` endpoint, which tells them apart by the first
//! bytes. The upstream records the request lines it gets: every request goes to the path after
//! the socket file, whatever path the client asked the location for.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::AsyncWriteExt;

use super::ambiguous_path_tests::{start_endpoint_with_locations, H1Client, H2Client, Response};
use crate::configurations::ListenHttpEndpointType;

/// A JSON-RPC request, as an MCP client posts it.
const REQUEST: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;

#[derive(Clone, Copy)]
enum Protocol {
    Http1,
    /// h2 by prior knowledge: there is no TLS on a socket, so no ALPN either.
    H2c,
}

/// An upstream on a socket file of its own, removed when the test ends. It answers a request with
/// its body - or, when it has none, with its request line - and remembers the request lines.
struct SocketUpstream {
    path: String,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Drop for SocketUpstream {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.path.as_str());
    }
}

impl SocketUpstream {
    fn in_temp_dir(protocol: Protocol) -> Self {
        Self::start(std::env::temp_dir().to_str().unwrap(), protocol)
    }

    /// `dir`: the folder of the socket file.
    fn start(dir: &str, protocol: Protocol) -> Self {
        // Short: a socket path has room for about 100 bytes.
        let path = format!(
            "{}/mrp-mcp-{}.sock",
            dir.trim_end_matches('/'),
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        );

        let listener = tokio::net::UnixListener::bind(path.as_str()).unwrap();

        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = seen.clone();

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let recorded = recorded.clone();
                let service =
                    hyper::service::service_fn(move |request| answer(request, recorded.clone()));

                tokio::spawn(async move {
                    let io = TokioIo::new(stream);

                    match protocol {
                        Protocol::Http1 => {
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, service)
                                .await;
                        }
                        Protocol::H2c => {
                            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                                .serve_connection(io, service)
                                .await;
                        }
                    }
                });
            }
        });

        Self { path, seen }
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

async fn answer(
    request: hyper::Request<hyper::body::Incoming>,
    seen: Arc<Mutex<Vec<String>>>,
) -> Result<hyper::Response<Full<Bytes>>, Infallible> {
    let request_line = format!(
        "{} {}",
        request.method(),
        request
            .uri()
            .path_and_query()
            .map(|path_and_query| path_and_query.as_str())
            .unwrap_or_default()
    );

    seen.lock().unwrap().push(request_line.clone());

    let body = request.into_body().collect().await.unwrap().to_bytes();

    let body = if body.is_empty() {
        Bytes::from(request_line)
    } else {
        body
    };

    Ok(hyper::Response::new(Full::new(body)))
}

/// An `http` endpoint with the location `/service` of the type and to the upstream given.
async fn start_proxy(location_type: &str, proxy_pass_to: &str) -> u16 {
    start_endpoint_with_locations(
        ListenHttpEndpointType::Http1,
        &format!("- path: /service\n  type: {location_type}\n  proxy_pass_to: '{proxy_pass_to}'\n"),
    )
    .await
}

/// [`REQUEST`] posted to `target` by an http/1.1 client.
async fn post_over_h1(port: u16, target: &str) -> Response {
    let mut client = H1Client::connect(port).await;

    let head = format!(
        "POST {target} HTTP/1.1\r\nHost: localhost:{port}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n",
        REQUEST.len()
    );

    client.stream.write_all(head.as_bytes()).await.unwrap();
    client.stream.write_all(REQUEST).await.unwrap();

    client.read_response().await
}

#[tokio::test]
async fn an_mcp_location_sends_to_the_path_after_its_socket_file() {
    let upstream = SocketUpstream::in_temp_dir(Protocol::Http1);
    let port = start_proxy("mcp", &format!("{}:/mcp", upstream.path)).await;

    let response = post_over_h1(port, "/service").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, REQUEST);

    let response = H2Client::connect(port)
        .await
        .get("/service/sse?session=1", None)
        .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"GET /mcp");

    assert_eq!(upstream.seen(), ["POST /mcp", "GET /mcp"]);
}

/// The h1 pipeline sends to an h2 upstream through its pool, hyper directly.
#[tokio::test]
async fn an_mcp_h2_location_sends_to_the_path_after_its_socket_file() {
    let upstream = SocketUpstream::in_temp_dir(Protocol::H2c);
    let port = start_proxy("mcp-h2", &format!("{}:/api/mcp?tenant=a", upstream.path)).await;

    let response = post_over_h1(port, "/service").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, REQUEST);

    let response = H2Client::connect(port).await.get("/service", None).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"GET /api/mcp?tenant=a");

    assert_eq!(
        upstream.seen(),
        ["POST /api/mcp?tenant=a", "GET /api/mcp?tenant=a"]
    );
}

/// `~/...`: the home directory, for the h1 pipeline as for hyper.
#[tokio::test]
async fn a_socket_file_in_the_home_directory() {
    let home = crate::settings::home_dir().unwrap();
    let upstream = SocketUpstream::start(&home, Protocol::Http1);

    let in_home = upstream.path.replacen(home.trim_end_matches('/'), "~", 1);
    assert!(in_home.starts_with("~/"), "{in_home}");

    let port = start_proxy("mcp", &format!("{in_home}:/mcp")).await;

    let response = post_over_h1(port, "/service").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, REQUEST);

    let response = H2Client::connect(port).await.get("/service", None).await;
    assert_eq!(response.status, 200);

    assert_eq!(upstream.seen(), ["POST /mcp", "GET /mcp"]);
}

/// A location which sends the client's own path on, to a unix socket url: over the socket on the
/// h1 pipeline - which used to dial it as a tcp address - as on hyper.
#[tokio::test]
async fn an_http_location_to_a_unix_socket_url() {
    let upstream = SocketUpstream::in_temp_dir(Protocol::Http1);
    let port = start_proxy("http", &format!("unix+http://{}", upstream.path)).await;

    let response = H1Client::connect(port).await.get("/service/x", None).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"GET /service/x");

    let response = H2Client::connect(port).await.get("/service/y", None).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"GET /service/y");
}

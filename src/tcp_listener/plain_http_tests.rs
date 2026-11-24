//! `http` and `http2` endpoints are one type under two names (`plain_http`). Through the real
//! accept loops - a tcp port (`start_listen_tcp_server`) and a unix socket
//! (`start_listen_unix_server`) - with endpoints compiled from YAML: an http/1.1 client and an h2
//! client by prior knowledge are served on the same port whichever name the endpoint has, and the
//! two names share a port.

use std::{collections::HashMap, convert::Infallible, net::SocketAddr, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::{
    configurations::{EndpointPort, ListenConfiguration},
    settings::SettingsModel,
    settings_compiled::SettingsCompiled,
    test_ports::free_port,
};

const TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn an_http_and_an_http2_endpoint_each_serve_http1_and_h2_clients() {
    for endpoint_type in ["http", "http2"] {
        let upstream = start_upstream("up").await;
        let port = free_port().await;
        let host = format!("localhost:{port}");

        apply_settings(&format!(
            "hosts:\n  {host}:\n    endpoint:\n      type: {endpoint_type}\n    locations:\n    - proxy_pass_to: http://127.0.0.1:{upstream}\n"
        ))
        .await;
        serve_tcp(port);

        // Two requests on one keep-alive connection, by the h1 pipeline.
        let mut client = connect_tcp(port).await;
        assert_eq!(
            h1_get(&mut client, &host, "/a").await,
            (200, "up /a".to_string()),
            "{endpoint_type}"
        );
        assert_eq!(
            h1_get(&mut client, &host, "/b").await,
            (200, "up /b".to_string()),
            "{endpoint_type}"
        );

        // Two requests on one h2 connection, by hyper.
        let mut sender = h2_handshake(connect_tcp(port).await).await;
        assert_eq!(
            h2_get(&mut sender, &host, "/c").await,
            (200, "up /c".to_string()),
            "{endpoint_type}"
        );
        assert_eq!(
            h2_get(&mut sender, &host, "/d").await,
            (200, "up /d".to_string()),
            "{endpoint_type}"
        );
    }
}

/// A host of `type: http` and one of `type: http2` on one port: each serves its requests, in
/// either protocol.
#[tokio::test]
async fn an_http_and_an_http2_endpoint_share_a_port() {
    let upstream_a = start_upstream("a").await;
    let upstream_b = start_upstream("b").await;
    let port = free_port().await;

    apply_settings(&format!(
        "hosts:\n  a.localhost:{port}:\n    endpoint:\n      type: http\n    locations:\n    - proxy_pass_to: http://127.0.0.1:{upstream_a}\n  b.localhost:{port}:\n    endpoint:\n      type: http2\n    locations:\n    - proxy_pass_to: http://127.0.0.1:{upstream_b}\n"
    ))
    .await;
    serve_tcp(port);

    let host_a = format!("a.localhost:{port}");
    let host_b = format!("b.localhost:{port}");

    let mut client = connect_tcp(port).await;
    assert_eq!(
        h1_get(&mut client, &host_a, "/x").await,
        (200, "a /x".to_string())
    );
    assert_eq!(
        h1_get(&mut client, &host_b, "/x").await,
        (200, "b /x".to_string())
    );

    let mut sender = h2_handshake(connect_tcp(port).await).await;
    assert_eq!(
        h2_get(&mut sender, &host_a, "/y").await,
        (200, "a /y".to_string())
    );
    assert_eq!(
        h2_get(&mut sender, &host_b, "/y").await,
        (200, "b /y".to_string())
    );
}

/// The same on a unix socket, where there was no h2 for `type: http` and no http/1.1 for
/// `type: http2` either.
#[cfg(unix)]
#[tokio::test]
async fn a_unix_socket_endpoint_serves_http1_and_h2_clients() {
    for endpoint_type in ["http", "http2"] {
        let upstream = start_upstream("unix").await;
        // Short: a unix socket path has room for about a hundred bytes.
        let path = format!("/tmp/mrp-plain-{}.sock", uuid::Uuid::new_v4().simple());

        apply_settings(&format!(
            "hosts:\n  {path}:\n    endpoint:\n      type: {endpoint_type}\n    locations:\n    - proxy_pass_to: http://127.0.0.1:{upstream}\n"
        ))
        .await;
        super::start_listen_unix_server(std::sync::Arc::new(path.clone()));

        let mut client = connect_unix(&path).await;
        assert_eq!(
            h1_get(&mut client, "localhost", "/a").await,
            (200, "unix /a".to_string()),
            "{endpoint_type}"
        );

        let mut sender = h2_handshake(connect_unix(&path).await).await;
        assert_eq!(
            h2_get(&mut sender, "localhost", "/b").await,
            (200, "unix /b".to_string()),
            "{endpoint_type}"
        );

        let _ = std::fs::remove_file(&path);
    }
}

// ---------------------------------------------------------------------------------------------
// The clients
// ---------------------------------------------------------------------------------------------

/// A `GET` over http/1.1: the status and the body. The upstream gives every answer a length.
async fn h1_get<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    host: &str,
    path: &str,
) -> (u16, String) {
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();

    tokio::time::timeout(TIMEOUT, read_h1_response(stream))
        .await
        .expect("no answer in time")
}

async fn read_h1_response<S: AsyncRead + Unpin>(stream: &mut S) -> (u16, String) {
    let mut received = Vec::new();
    let mut buffer = [0u8; 4096];

    let head_end = loop {
        if let Some(end) = received.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }

        let read = stream.read(&mut buffer).await.unwrap();
        assert!(read > 0, "closed before the head of the answer");
        received.extend_from_slice(&buffer[..read]);
    };

    let head = String::from_utf8(received[..head_end].to_vec()).unwrap();
    let status: u16 = head[9..12].parse().unwrap();

    let length: usize = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().unwrap())
        })
        .unwrap_or_else(|| panic!("an answer with no length: {head}"));

    while received.len() < head_end + length {
        let read = stream.read(&mut buffer).await.unwrap();
        assert!(read > 0, "closed in the middle of the answer");
        received.extend_from_slice(&buffer[..read]);
    }

    let body = String::from_utf8(received[head_end..head_end + length].to_vec()).unwrap();
    (status, body)
}

/// An h2 connection by prior knowledge: the client preface is the first thing it sends.
async fn h2_handshake<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
) -> hyper::client::conn::http2::SendRequest<Empty<Bytes>> {
    let (sender, connection) =
        tokio::time::timeout(
            TIMEOUT,
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream)),
        )
        .await
        .expect("no h2 handshake in time")
        .unwrap();

    tokio::spawn(connection);

    sender
}

async fn h2_get(
    sender: &mut hyper::client::conn::http2::SendRequest<Empty<Bytes>>,
    host: &str,
    path: &str,
) -> (u16, String) {
    let request = hyper::Request::get(format!("http://{host}{path}"))
        .body(Empty::<Bytes>::new())
        .unwrap();

    let response = tokio::time::timeout(TIMEOUT, sender.send_request(request))
        .await
        .expect("no answer in time")
        .unwrap();

    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();

    (status, String::from_utf8_lossy(&body).to_string())
}

// ---------------------------------------------------------------------------------------------
// The upstream and the proxy
// ---------------------------------------------------------------------------------------------

/// An http/1.1 upstream which answers every request with `<name> <path>`.
async fn start_upstream(name: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };

            let service = hyper::service::service_fn(
                move |request: hyper::Request<hyper::body::Incoming>| async move {
                    let body = format!("{name} {}", request.uri().path());
                    Ok::<_, Infallible>(hyper::Response::new(Full::new(Bytes::from(body))))
                },
            );

            tokio::spawn(
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service),
            );
        }
    });

    port
}

/// What `flows::load_everything_from_settings` does with a settings file: every host is
/// compiled by `scripts::compile_host_configuration` - into what the hosts before it on its port
/// made of it - and the ports are published into the live configuration, where the accept loops
/// look them up.
async fn apply_settings(yaml: &str) {
    let model: SettingsModel = my_settings_reader::serde_yaml::from_str(yaml)
        .unwrap_or_else(|err| panic!("the settings do not parse: {err}\n{yaml}"));

    let settings = SettingsCompiled {
        hosts: model.hosts,
        global_settings: model.global_settings,
        ..Default::default()
    };

    let mut ports: HashMap<EndpointPort, ListenConfiguration> = HashMap::new();

    for (host_id, host_settings) in &settings.hosts {
        let endpoint_host = settings.get_endpoint_host_string(host_id).unwrap();
        let port = endpoint_host.get_port();
        let existing = ports.remove(&port);

        let configuration = crate::scripts::compile_host_configuration(
            &settings,
            endpoint_host,
            host_settings,
            existing,
        )
        .await
        .unwrap_or_else(|err| panic!("{host_id} does not compile: {err}\n{yaml}"));

        ports.insert(port, configuration);
    }

    crate::app::APP_CTX
        .current_configuration
        .write(move |config| {
            for (port, configuration) in ports {
                match port {
                    EndpointPort::Tcp(port) => {
                        config.listen_tcp_endpoints.insert(port, configuration);
                    }
                    EndpointPort::UnixSocket(path) => {
                        config.listen_unix_socket_endpoints.insert(path, configuration);
                    }
                }
            }
        })
        .await;
}

/// The accept loop the proxy runs for a tcp port, on the loopback.
fn serve_tcp(port: u16) {
    super::start_listen_tcp_server(SocketAddr::from(([127, 0, 0, 1], port)));
}

/// The accept loop is started by a spawned task: the port may not be listening yet.
async fn connect_tcp(port: u16) -> TcpStream {
    for _ in 0..100 {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
            return stream;
        }

        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    panic!("nothing listens on port {port}");
}

/// The same for a unix socket, which the accept loop binds once it removed the file of the last
/// one.
#[cfg(unix)]
async fn connect_unix(path: &str) -> tokio::net::UnixStream {
    for _ in 0..100 {
        if let Ok(stream) = tokio::net::UnixStream::connect(path).await {
            return stream;
        }

        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    panic!("nothing listens on {path}");
}

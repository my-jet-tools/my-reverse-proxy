//! Slow clients: a connection which never finishes what it has to send must not be held open.
//!
//! Every test goes through the real accept loop (`start_listen_tcp_server`) with endpoints
//! compiled from YAML - with the timeouts cut to [`SHORT`] - and talks to it over a raw socket:
//! - an http/1.1 head that never ends, or comes a byte at a time, is cut at
//!   `header_read_timeout`, and so is a keep-alive connection that sends no next request - but
//!   not while an answer is still on its way;
//! - a connection to a TLS port that sends nothing is cut at `tls_handshake_timeout`;
//! - an `https2` / `http2` connection that sends no request is cut at `header_read_timeout`;
//! - a body the proxy waits for whole is answered `408` once it stops coming (`read_timeout`);
//! - `tcp` and `mcp` endpoints, which never read a head, are not cut by any of it.
//!
//! After each refusal an ordinary request on a new connection is served.

use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use my_tls::tokio_rustls::{
    client::TlsStream,
    rustls::{
        self,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
        DigitallySignedStruct, SignatureScheme,
    },
    TlsConnector,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::{
    configurations::EndpointPort, settings::SettingsModel, settings_compiled::SettingsCompiled,
};

/// The timeout under test, wherever it is set.
const SHORT: Duration = Duration::from_millis(1000);

/// A connection cut by a timeout of [`SHORT`] is closed no sooner than this...
const NOT_BEFORE: Duration = Duration::from_millis(700);

/// ...and no later than this.
const NOT_AFTER: Duration = Duration::from_millis(4000);

/// How long the upstream takes on `/slow`: longer than [`SHORT`].
const SLOW_ANSWER: Duration = Duration::from_millis(2000);

// ---------------------------------------------------------------------------------------------
// http/1.1 (the proxy's own pipeline): `http` endpoint
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn http_a_head_without_its_end_is_cut_at_the_header_timeout() {
    let site = Site::start("http", "      header_read_timeout: 1000\n").await;

    let mut client = site.connect().await;
    client
        .write_all(site.head_start("GET /").as_bytes())
        .await
        .unwrap();

    assert_closed_by_timeout(&mut client).await;

    site.assert_served_on_a_new_connection().await;
}

/// The slowloris case: every byte comes well within `read_timeout`, the head never ends.
#[tokio::test]
async fn http_a_head_sent_a_byte_at_a_time_is_cut_at_the_header_timeout() {
    let site = Site::start("http", "      header_read_timeout: 1000\n").await;

    let mut client = site.connect().await;
    client
        .write_all(site.head_start("GET /").as_bytes())
        .await
        .unwrap();

    let started = Instant::now();

    while started.elapsed() < NOT_AFTER {
        if client.write_all(b"x").await.is_err() {
            break;
        }

        let mut buffer = [0u8; 64];
        match tokio::time::timeout(Duration::from_millis(200), client.read(&mut buffer)).await {
            // Still waiting for the rest of the head.
            Err(_) => {}
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(_)) => panic!("an answer to a head that never ended"),
        }
    }

    let elapsed = started.elapsed();
    assert!(
        (NOT_BEFORE..NOT_AFTER).contains(&elapsed),
        "a head sent a byte at a time was held for {elapsed:?}"
    );

    site.assert_served_on_a_new_connection().await;
}

#[tokio::test]
async fn http_a_keep_alive_connection_with_no_next_request_is_closed_at_the_header_timeout() {
    let site = Site::start("http", "      header_read_timeout: 1000\n").await;

    let mut client = site.connect().await;
    assert_eq!(site.get(&mut client, "/").await, (200, "ok".to_string()));

    assert_closed_by_timeout(&mut client).await;
}

/// The wait for the next request starts when the answer to the last one is out: an answer slower
/// than the header timeout is delivered whole, and the connection goes on.
#[tokio::test]
async fn http_an_answer_slower_than_the_header_timeout_is_delivered_and_the_connection_goes_on() {
    let site = Site::start("http", "      header_read_timeout: 1000\n").await;

    let mut client = site.connect().await;
    assert_eq!(site.get(&mut client, "/slow").await, (200, "slow".to_string()));
    assert_eq!(site.get(&mut client, "/").await, (200, "ok".to_string()));
}

// ---------------------------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------------------------

/// Set in `global_settings`: the handshake is over before any endpoint is picked.
#[tokio::test]
async fn https_a_client_which_sends_nothing_is_cut_at_the_tls_handshake_timeout() {
    let site = Site::start_with_global("https", "", "  tls_handshake_timeout: 1000\n").await;

    let mut client = site.connect().await;
    assert_closed_by_timeout(&mut client).await;

    let mut client = site.connect_tls(b"http/1.1").await;
    assert_eq!(site.get(&mut client, "/").await, (200, "ok".to_string()));
}

#[tokio::test]
async fn https_a_head_without_its_end_is_cut_at_the_header_timeout() {
    let site = Site::start("https", "      header_read_timeout: 1000\n").await;

    let mut client = site.connect_tls(b"http/1.1").await;
    client
        .write_all(site.head_start("GET /").as_bytes())
        .await
        .unwrap();

    assert_closed_by_timeout(&mut client).await;

    let mut client = site.connect_tls(b"http/1.1").await;
    assert_eq!(site.get(&mut client, "/").await, (200, "ok".to_string()));
}

// ---------------------------------------------------------------------------------------------
// hyper: `https2` and `http2` endpoints
// ---------------------------------------------------------------------------------------------

/// The auto builder reads the opening bytes to tell h2 from http/1.1 - with no limit of its own.
#[tokio::test]
async fn https2_a_client_which_sends_nothing_after_the_handshake_is_cut() {
    let site = Site::start("https2", "      header_read_timeout: 1000\n").await;

    let mut client = site.connect_tls(b"h2").await;
    assert_closed_by_timeout(&mut client).await;

    let mut client = site.connect_tls(b"http/1.1").await;
    assert_eq!(site.get(&mut client, "/").await, (200, "ok".to_string()));
}

#[tokio::test]
async fn https2_an_http1_head_without_its_end_is_cut_at_the_header_timeout() {
    let site = Site::start("https2", "      header_read_timeout: 1000\n").await;

    let mut client = site.connect_tls(b"http/1.1").await;
    client
        .write_all(site.head_start("GET /").as_bytes())
        .await
        .unwrap();

    assert_closed_by_timeout(&mut client).await;

    let mut client = site.connect_tls(b"http/1.1").await;
    assert_eq!(site.get(&mut client, "/").await, (200, "ok".to_string()));
}

#[tokio::test]
async fn https2_an_http1_keep_alive_connection_with_no_next_request_is_closed() {
    let site = Site::start("https2", "      header_read_timeout: 1000\n").await;

    let mut client = site.connect_tls(b"http/1.1").await;
    assert_eq!(site.get(&mut client, "/").await, (200, "ok".to_string()));

    assert_closed_by_timeout(&mut client).await;
}

/// To an http/1.1 upstream the body is sent whole: the proxy waits for all of it, but no longer
/// than `read_timeout` of silence.
#[tokio::test]
async fn https2_a_body_that_stops_coming_is_answered_408() {
    let site = Site::start("https2", "      read_timeout: 1000\n").await;

    let mut client = site.connect_tls(b"http/1.1").await;
    let head = format!(
        "POST /echo HTTP/1.1\r\nHost: localhost:{}\r\ncontent-length: 10\r\n\r\nab",
        site.port
    );
    client.write_all(head.as_bytes()).await.unwrap();

    let started = Instant::now();
    let (status, _) = tokio::time::timeout(NOT_AFTER, read_response(&mut client))
        .await
        .expect("no answer to a body that stopped coming");
    let elapsed = started.elapsed();

    assert_eq!(status, 408);
    assert!(
        (NOT_BEFORE..NOT_AFTER).contains(&elapsed),
        "answered after {elapsed:?}"
    );

    let mut client = site.connect_tls(b"http/1.1").await;
    assert_eq!(site.get(&mut client, "/").await, (200, "ok".to_string()));
}

/// No TLS here: the h2 connection sends its SETTINGS and waits for the client preface.
#[tokio::test]
async fn http2_a_client_which_sends_nothing_is_cut() {
    let site = Site::start("http2", "      header_read_timeout: 1000\n").await;

    let mut client = site.connect().await;
    assert_closed_by_timeout_after_the_server_preface(&mut client).await;
}

// ---------------------------------------------------------------------------------------------
// No HTTP head to read: `tcp` and `mcp` endpoints
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn tcp_a_silent_connection_is_not_cut_by_the_header_timeout() {
    let echo = start_echo().await;
    let port = free_port().await;

    apply_settings(&format!(
        "global_settings:\n  header_read_timeout: 1000\n  tls_handshake_timeout: 1000\nhosts:\n  localhost:{port}:\n    endpoint:\n      type: tcp\n    locations:\n    - proxy_pass_to: '{echo}'\n"
    ))
    .await;
    serve(port);

    let mut client = connect_to(port).await;
    assert_still_open_after_the_timeouts(&mut client).await;
}

#[tokio::test]
async fn mcp_a_silent_connection_is_not_cut_by_the_header_timeout() {
    let echo = start_echo().await;
    let port = free_port().await;

    apply_settings(&format!(
        "global_settings:\n  header_read_timeout: 1000\nhosts:\n  localhost:{port}:\n    endpoint:\n      type: mcp\n    locations:\n    - proxy_pass_to: http://{echo}\n"
    ))
    .await;
    serve(port);

    let mut client = tls_connect(port, b"http/1.1").await;
    assert_still_open_after_the_timeouts(&mut client).await;
}

// ---------------------------------------------------------------------------------------------
// The checks
// ---------------------------------------------------------------------------------------------

/// The proxy closes the connection - with nothing sent - at a timeout of [`SHORT`].
async fn assert_closed_by_timeout<S: AsyncRead + Unpin>(client: &mut S) {
    let started = Instant::now();

    let mut buffer = [0u8; 1024];
    let read = tokio::time::timeout(NOT_AFTER, client.read(&mut buffer))
        .await
        .expect("the connection was not closed");

    let elapsed = started.elapsed();

    match read {
        Ok(0) | Err(_) => {}
        Ok(size) => panic!(
            "the proxy answered instead of closing: {:?}",
            String::from_utf8_lossy(&buffer[..size])
        ),
    }

    assert!(
        elapsed >= NOT_BEFORE,
        "closed after {elapsed:?}: too soon to be the timeout"
    );
}

/// The same for an h2 connection, whose server speaks first: what it sends before it closes is
/// its SETTINGS, read and dropped.
async fn assert_closed_by_timeout_after_the_server_preface<S: AsyncRead + Unpin>(client: &mut S) {
    let started = Instant::now();
    let mut buffer = [0u8; 1024];

    loop {
        let read = tokio::time::timeout(NOT_AFTER, client.read(&mut buffer))
            .await
            .expect("the connection was not closed");

        match read {
            Ok(0) | Err(_) => break,
            Ok(_) => assert!(started.elapsed() < NOT_AFTER, "the connection was not closed"),
        }
    }

    let elapsed = started.elapsed();
    assert!(
        (NOT_BEFORE..NOT_AFTER).contains(&elapsed),
        "closed after {elapsed:?}"
    );
}

/// Silent for twice the timeouts, then the bytes still go through to the echo and back.
async fn assert_still_open_after_the_timeouts<S: AsyncRead + AsyncWrite + Unpin>(client: &mut S) {
    let mut buffer = [0u8; 4];

    match tokio::time::timeout(SHORT * 2, client.read(&mut buffer)).await {
        Err(_) => {}
        Ok(read) => panic!("the connection did not stay open: {read:?}"),
    }

    client.write_all(b"ping").await.unwrap();
    tokio::time::timeout(NOT_AFTER, client.read_exact(&mut buffer))
        .await
        .expect("no echo")
        .unwrap();
    assert_eq!(&buffer, b"ping");
}

// ---------------------------------------------------------------------------------------------
// The site: one endpoint in front of an upstream
// ---------------------------------------------------------------------------------------------

struct Site {
    port: u16,
}

impl Site {
    /// `endpoint_lines`: more keys of the `endpoint` section, indented by six spaces.
    async fn start(endpoint_type: &str, endpoint_lines: &str) -> Self {
        Self::start_with_global(endpoint_type, endpoint_lines, "").await
    }

    /// `global_lines`: keys of `global_settings`, indented by two spaces.
    async fn start_with_global(endpoint_type: &str, endpoint_lines: &str, global_lines: &str) -> Self {
        let upstream = start_upstream().await;
        let port = free_port().await;

        let global = if global_lines.is_empty() {
            String::new()
        } else {
            format!("global_settings:\n{global_lines}")
        };

        apply_settings(&format!(
            "{global}hosts:\n  localhost:{port}:\n    endpoint:\n      type: {endpoint_type}\n{endpoint_lines}    locations:\n    - proxy_pass_to: http://127.0.0.1:{upstream}\n"
        ))
        .await;
        serve(port);

        Self { port }
    }

    async fn connect(&self) -> TcpStream {
        connect_to(self.port).await
    }

    async fn connect_tls(&self, alpn: &[u8]) -> TlsStream<TcpStream> {
        tls_connect(self.port, alpn).await
    }

    /// The start of a request head with no empty line to end it.
    fn head_start(&self, method_and_path: &str) -> String {
        format!("{method_and_path} HTTP/1.1\r\nHost: localhost:{}\r\nx-slow: ", self.port)
    }

    async fn get<S: AsyncRead + AsyncWrite + Unpin>(&self, client: &mut S, path: &str) -> (u16, String) {
        let request = format!("GET {path} HTTP/1.1\r\nHost: localhost:{}\r\n\r\n", self.port);
        client.write_all(request.as_bytes()).await.unwrap();

        tokio::time::timeout(NOT_AFTER, read_response(client))
            .await
            .expect("no answer in time")
    }

    async fn assert_served_on_a_new_connection(&self) {
        let mut client = self.connect().await;
        assert_eq!(self.get(&mut client, "/").await, (200, "ok".to_string()));
    }
}

/// The status and the body, by `content-length` or by chunks.
async fn read_response<S: AsyncRead + Unpin>(stream: &mut S) -> (u16, String) {
    let mut received = Vec::new();

    let head_end = loop {
        if let Some(end) = received.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }

        read_more(stream, &mut received).await;
    };

    let head = String::from_utf8(received[..head_end].to_vec()).unwrap();
    let status: u16 = head[9..12].parse().unwrap();
    let head_lower = head.to_ascii_lowercase();

    if let Some(length) = head_lower
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
    {
        let length: usize = length.trim().parse().unwrap();

        while received.len() < head_end + length {
            read_more(stream, &mut received).await;
        }

        let body = String::from_utf8(received[head_end..head_end + length].to_vec()).unwrap();
        return (status, body);
    }

    assert!(
        head_lower.contains("transfer-encoding: chunked"),
        "an answer with no length: {head}"
    );

    let mut body = Vec::new();
    let mut pos = head_end;

    loop {
        let size_end = loop {
            if let Some(end) = received[pos..].windows(2).position(|window| window == b"\r\n") {
                break pos + end;
            }

            read_more(stream, &mut received).await;
        };

        let size_line = std::str::from_utf8(&received[pos..size_end]).unwrap();
        let size = usize::from_str_radix(size_line.split(';').next().unwrap().trim(), 16).unwrap();
        let data_start = size_end + 2;

        while received.len() < data_start + size + 2 {
            read_more(stream, &mut received).await;
        }

        if size == 0 {
            return (status, String::from_utf8(body).unwrap());
        }

        body.extend_from_slice(&received[data_start..data_start + size]);
        pos = data_start + size + 2;
    }
}

async fn read_more<S: AsyncRead + Unpin>(stream: &mut S, received: &mut Vec<u8>) {
    let mut buffer = [0u8; 4096];
    let read = stream.read(&mut buffer).await.unwrap();

    assert!(
        read > 0,
        "the connection closed in the middle of an answer: {:?}",
        String::from_utf8_lossy(received)
    );

    received.extend_from_slice(&buffer[..read]);
}

/// An http/1.1 upstream: `ok` for `/`, `slow` for `/slow` after [`SLOW_ANSWER`], and the length
/// of the body for `/echo`.
async fn start_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };

            let service = hyper::service::service_fn(
                |request: hyper::Request<hyper::body::Incoming>| async move {
                    let body = match request.uri().path() {
                        "/slow" => {
                            tokio::time::sleep(SLOW_ANSWER).await;
                            "slow".to_string()
                        }
                        "/echo" => {
                            let body = request.into_body().collect().await.unwrap().to_bytes();
                            body.len().to_string()
                        }
                        _ => "ok".to_string(),
                    };

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

/// Sends back whatever it gets.
async fn start_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };

            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });

    addr
}

// ---------------------------------------------------------------------------------------------
// The proxy
// ---------------------------------------------------------------------------------------------

/// What `flows::load_everything_from_settings` does with a settings file: every host is
/// compiled by `scripts::compile_host_configuration` and published into the live configuration,
/// where the accept loop looks its port up.
async fn apply_settings(yaml: &str) {
    // What main() does before anything touches TLS.
    my_tls::install_default_crypto_providers();

    let model: SettingsModel = my_settings_reader::serde_yaml::from_str(yaml)
        .unwrap_or_else(|err| panic!("the settings do not parse: {err}\n{yaml}"));

    let settings = SettingsCompiled {
        hosts: model.hosts,
        global_settings: model.global_settings,
        ..Default::default()
    };

    for (host_id, host_settings) in &settings.hosts {
        let endpoint_host = settings.get_endpoint_host_string(host_id).unwrap();

        let EndpointPort::Tcp(port) = endpoint_host.get_port() else {
            panic!("{host_id} is not a tcp port");
        };

        let configuration =
            crate::scripts::compile_host_configuration(&settings, endpoint_host, host_settings, None)
                .await
                .unwrap_or_else(|err| panic!("{host_id} does not compile: {err}\n{yaml}"));

        crate::app::APP_CTX
            .current_configuration
            .write(move |config| {
                config.listen_tcp_endpoints.insert(port, configuration);
            })
            .await;
    }
}

/// The accept loop the proxy runs for a tcp port, on the loopback.
fn serve(port: u16) {
    super::start_listen_tcp_server(SocketAddr::from(([127, 0, 0, 1], port)));
}

async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The accept loop is started by a spawned task: the port may not be listening yet.
async fn connect_to(port: u16) -> TcpStream {
    for _ in 0..100 {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
            return stream;
        }

        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    panic!("nothing listens on port {port}");
}

/// A finished TLS handshake with `localhost` as the server name and `alpn` as the one protocol
/// offered.
async fn tls_connect(port: u16, alpn: &[u8]) -> TlsStream<TcpStream> {
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];

    let tcp_stream = connect_to(port).await;

    tokio::time::timeout(
        NOT_AFTER,
        TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("localhost").unwrap(), tcp_stream),
    )
    .await
    .expect("no TLS handshake in time")
    .unwrap()
}

/// The endpoint serves the proxy's self-signed certificate; what is under test is what happens
/// around the handshake, not the certificate.
#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

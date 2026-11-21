//! A request body through an `https2` endpoint to an http/1.1 upstream: whatever framing the
//! client used, the upstream gets the body the client sent as the body of one request - with a
//! `content-length` and no `transfer-encoding`.
//!
//! The hyper path collects the body whole before it goes to an http/1.1 upstream, and the
//! client's headers go with it. A `transfer-encoding: chunked` of an http/1.1 client then
//! announces chunks in front of bytes which are no longer chunked, and an h2 body comes with no
//! length at all: either way the upstream reads where the request ends from the body itself, and
//! a body which is written as a request is one more request (request smuggling) - past the checks
//! of the location, on a pooled connection other clients share.
//!
//! The upstream here reads every request by its own framing and keeps the connection open, so a
//! request smuggled in a body shows up as one more request.

use std::{
    convert::Infallible,
    io::Read,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use hyper_util::rt::{TokioExecutor, TokioIo};
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
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::{
    configurations::{EndpointHttpHostString, ListenHttpEndpointType},
    settings::HostSettings,
    settings_compiled::SettingsCompiled,
};

const TIMEOUT: Duration = Duration::from_secs(5);

/// How long the upstream is given to read what came after the request the client got its
/// answer to: a smuggled request is in the same bytes, so it is read right after.
const SETTLE: Duration = Duration::from_millis(300);

/// A body which ends a chunked one and goes on as a request of its own.
const ENDS_THE_CHUNKS: &[u8] = b"0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: localhost\r\n\r\n";

/// A body which is a request of its own when nothing says where the body ends.
const IS_A_REQUEST: &[u8] = b"GET /smuggled HTTP/1.1\r\nHost: localhost\r\n\r\n";

#[tokio::test]
async fn an_http1_chunked_body_reaches_an_http1_upstream_as_one_request() {
    let upstream = RecordingUpstream::start().await;
    let port = start_https2_endpoint(&upstream, "").await;

    let mut stream = connect_tls(port, b"http/1.1").await;

    let mut request = format!(
        "POST /x HTTP/1.1\r\nHost: localhost:{port}\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
        ENDS_THE_CHUNKS.len()
    )
    .into_bytes();
    request.extend_from_slice(ENDS_THE_CHUNKS);
    request.extend_from_slice(b"\r\n0\r\n\r\n");

    stream.write_all(&request).await.unwrap();

    let head = read_response_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");

    tokio::time::sleep(SETTLE).await;

    assert_one_framed_request(&upstream, ENDS_THE_CHUNKS);
}

#[tokio::test]
async fn an_h2_body_without_a_length_reaches_an_http1_upstream_as_one_request() {
    let upstream = RecordingUpstream::start().await;
    let port = start_https2_endpoint(&upstream, "").await;

    let stream = connect_tls(port, b"h2").await;

    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(connection);

    // A stream of frames has no size hint: hyper sends it with no `content-length`.
    let body = StreamBody::new(futures::stream::iter(vec![Ok::<_, Infallible>(
        Frame::data(Bytes::from_static(IS_A_REQUEST)),
    )]));

    let request = hyper::Request::builder()
        .method("POST")
        .uri(format!("https://localhost:{port}/x"))
        .body(body)
        .unwrap();

    assert!(request.headers().get("content-length").is_none());

    let response = tokio::time::timeout(TIMEOUT, sender.send_request(request))
        .await
        .expect("no response in time")
        .unwrap();
    assert_eq!(response.status(), 200);
    let _ = response.into_body().collect().await;

    tokio::time::sleep(SETTLE).await;

    assert_one_framed_request(&upstream, IS_A_REQUEST);
}

/// `compress: true` gzips the body and gives it its length; the `transfer-encoding` of the
/// client must not go along with that length.
#[tokio::test]
async fn a_compressed_chunked_body_reaches_an_http1_upstream_with_one_length() {
    let upstream = RecordingUpstream::start().await;
    let port = start_https2_endpoint(&upstream, "  compress: true\n").await;

    let mut stream = connect_tls(port, b"http/1.1").await;

    // Long enough to be compressed.
    let payload: Vec<u8> = ENDS_THE_CHUNKS.iter().copied().cycle().take(4096).collect();

    let mut request = format!(
        "POST /x HTTP/1.1\r\nHost: localhost:{port}\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
        payload.len()
    )
    .into_bytes();
    request.extend_from_slice(&payload);
    request.extend_from_slice(b"\r\n0\r\n\r\n");

    stream.write_all(&request).await.unwrap();

    let head = read_response_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");

    tokio::time::sleep(SETTLE).await;

    let requests = upstream.requests();
    assert_eq!(requests.len(), 1, "{requests:#?}");

    let request = &requests[0];
    assert_eq!(request.line, "POST /x HTTP/1.1");
    assert_eq!(request.header("transfer-encoding"), None, "{request:#?}");
    assert_eq!(request.header("content-encoding"), Some("gzip"));
    assert_eq!(
        request.header("content-length"),
        Some(request.body.len().to_string().as_str())
    );

    let mut decompressed = Vec::new();
    flate2::read::GzDecoder::new(request.body.as_slice())
        .read_to_end(&mut decompressed)
        .unwrap();
    assert_eq!(decompressed, payload);
}

fn assert_one_framed_request(upstream: &RecordingUpstream, body: &[u8]) {
    let requests = upstream.requests();
    assert_eq!(requests.len(), 1, "{requests:#?}");

    let request = &requests[0];
    assert_eq!(request.line, "POST /x HTTP/1.1");
    assert_eq!(request.header("transfer-encoding"), None, "{request:#?}");
    assert_eq!(
        request.header("content-length"),
        Some(body.len().to_string().as_str()),
        "{request:#?}"
    );
    assert_eq!(request.body, body);
}

/// A request as the upstream read it.
struct Recorded {
    line: String,
    /// Names in lower case.
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Recorded {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header == name)
            .map(|(_, value)| value.as_str())
    }
}

impl std::fmt::Debug for Recorded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recorded")
            .field("line", &self.line)
            .field("headers", &self.headers)
            .field("body", &String::from_utf8_lossy(&self.body))
            .finish()
    }
}

/// An http/1.1 upstream which reads every request by its framing - `transfer-encoding: chunked`
/// first, then `content-length`, else no body - answers each one, and keeps the connection open
/// for the next.
struct RecordingUpstream {
    port: u16,
    requests: Arc<Mutex<Vec<Recorded>>>,
}

impl RecordingUpstream {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };

                tokio::spawn(serve_upstream_connection(stream, recorded.clone()));
            }
        });

        Self { port, requests }
    }

    fn requests(&self) -> std::sync::MutexGuard<'_, Vec<Recorded>> {
        self.requests.lock().unwrap()
    }
}

async fn serve_upstream_connection(mut stream: TcpStream, recorded: Arc<Mutex<Vec<Recorded>>>) {
    let mut received = Vec::new();

    loop {
        let head_end = loop {
            if let Some(end) = find(&received, b"\r\n\r\n") {
                break end + 4;
            }

            if !read_more(&mut stream, &mut received).await {
                return;
            }
        };

        let head = String::from_utf8_lossy(&received[..head_end]).to_string();
        received.drain(..head_end);

        let mut lines = head.split("\r\n");
        let line = lines.next().unwrap_or_default().to_string();
        let headers: Vec<(String, String)> = lines
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                Some((name.trim().to_ascii_lowercase(), value.trim().to_string()))
            })
            .collect();

        let is_chunked = headers.iter().any(|(name, value)| {
            name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked")
        });

        let content_length = headers
            .iter()
            .find(|(name, _)| name == "content-length")
            .and_then(|(_, value)| value.parse::<usize>().ok());

        let body = if is_chunked {
            read_chunked_body(&mut stream, &mut received).await
        } else if let Some(content_length) = content_length {
            let mut complete = true;
            while received.len() < content_length {
                if !read_more(&mut stream, &mut received).await {
                    complete = false;
                    break;
                }
            }

            complete.then(|| received.drain(..content_length).collect())
        } else {
            Some(Vec::new())
        };

        let Some(body) = body else {
            // What the body was could not be read: it is recorded as it is, and the connection
            // ends.
            recorded.lock().unwrap().push(Recorded {
                line,
                headers,
                body: std::mem::take(&mut received),
            });
            return;
        };

        recorded.lock().unwrap().push(Recorded {
            line,
            headers,
            body,
        });

        if stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .is_err()
        {
            return;
        }
    }
}

/// `None`: the chunks do not parse, or the connection ended in them.
async fn read_chunked_body(stream: &mut TcpStream, received: &mut Vec<u8>) -> Option<Vec<u8>> {
    let mut body = Vec::new();

    loop {
        let line_end = loop {
            if let Some(end) = find(received, b"\r\n") {
                break end;
            }

            if !read_more(stream, received).await {
                return None;
            }
        };

        let size_line = String::from_utf8_lossy(&received[..line_end]).to_string();
        let size = size_line.split(';').next()?.trim();
        let size = usize::from_str_radix(size, 16).ok()?;
        received.drain(..line_end + 2);

        // The chunk and its `\r\n`; the last chunk has no data, and no trailers come here.
        while received.len() < size + 2 {
            if !read_more(stream, received).await {
                return None;
            }
        }

        if &received[size..size + 2] != b"\r\n" {
            return None;
        }

        body.extend_from_slice(&received[..size]);
        received.drain(..size + 2);

        if size == 0 {
            return Some(body);
        }
    }
}

/// `false`: the connection ended, or nothing came in time.
async fn read_more(stream: &mut (impl AsyncRead + Unpin), received: &mut Vec<u8>) -> bool {
    let mut buffer = [0u8; 4096];

    match tokio::time::timeout(TIMEOUT, stream.read(&mut buffer)).await {
        Ok(Ok(read)) if read > 0 => {
            received.extend_from_slice(&buffer[..read]);
            true
        }
        _ => false,
    }
}

fn find(data: &[u8], what: &[u8]) -> Option<usize> {
    data.windows(what.len()).position(|window| window == what)
}

async fn read_response_head(stream: &mut TlsStream<TcpStream>) -> String {
    let mut received = Vec::new();

    loop {
        if let Some(end) = find(&received, b"\r\n\r\n") {
            return String::from_utf8_lossy(&received[..end]).to_string();
        }

        assert!(
            read_more(stream, &mut received).await,
            "no response head: {:?}",
            String::from_utf8_lossy(&received)
        );
    }
}

/// The proxy under test: one `https2` endpoint on a free port, its one location `/` an `http`
/// one in front of the upstream, compiled from settings the same way a settings file is.
///
/// `location_settings`: more lines for the location, indented by two spaces.
async fn start_https2_endpoint(upstream: &RecordingUpstream, location_settings: &str) -> u16 {
    // What main() does before anything touches TLS.
    my_tls::install_default_crypto_providers();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listening_addr = listener.local_addr().unwrap();

    let host_settings: HostSettings = my_settings_reader::serde_yaml::from_str(&format!(
        "endpoint:\n  type: https2\nlocations:\n- path: /\n  type: http\n  proxy_pass_to: 'http://127.0.0.1:{}'\n{location_settings}",
        upstream.port
    ))
    .unwrap();

    let host_endpoint =
        EndpointHttpHostString::new(format!("localhost:{}", listening_addr.port())).unwrap();

    let endpoint_info = crate::scripts::compile_http_configuration(
        &SettingsCompiled::default(),
        host_endpoint,
        &host_settings,
        ListenHttpEndpointType::Https2,
    )
    .await
    .unwrap();

    let configuration =
        Arc::new(crate::scripts::merge_http_into_existing(None, endpoint_info).unwrap());

    tokio::spawn(async move {
        let mut connection_id = 0;

        loop {
            let Ok((tcp_stream, client_addr)) = listener.accept().await else {
                return;
            };

            connection_id += 1;

            super::handle_connection(
                tcp_stream,
                client_addr,
                listening_addr,
                configuration.clone(),
                connection_id,
                crate::app::ConnectionSlot::unlimited(),
            );
        }
    });

    listening_addr.port()
}

/// The endpoint offers `h2`, `http/1.1` and `http/1.0`; the one protocol the client offers is
/// what gets negotiated, and that picks the path under test.
async fn connect_tls(port: u16, alpn: &[u8]) -> TlsStream<TcpStream> {
    let mut client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    client_config.alpn_protocols = vec![alpn.to_vec()];

    let tcp_stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

    let tls_stream = TlsConnector::from(Arc::new(client_config))
        .connect(ServerName::try_from("localhost").unwrap(), tcp_stream)
        .await
        .unwrap();

    assert_eq!(tls_stream.get_ref().1.alpn_protocol(), Some(alpn));

    tls_stream
}

/// The endpoint serves the proxy's self-signed certificate; what is under test is what happens
/// after the handshake, not the certificate.
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

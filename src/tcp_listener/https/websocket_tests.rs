//! Websockets through an `https2` endpoint to an http/1.1 upstream on a unix
//! socket, driven through the same entry the tcp listener uses
//! (`handle_connection`: TLS with ALPN, endpoint resolution, hyper,
//! `HttpProxyPass`, the unix pool, the websocket pump).
//!
//! An `https2` endpoint takes a websocket two ways, and the client's ALPN pick
//! decides which: an HTTP/1.1 `Upgrade` (what Cloudflare sends to an origin) or
//! an RFC 8441 extended CONNECT over h2 (what a browser sends once the endpoint
//! advertises SETTINGS_ENABLE_CONNECT_PROTOCOL). Both must keep the tunnel open
//! past the handshake and carry the upstream's close frame to the client.

use std::{convert::Infallible, sync::Arc, time::Duration};

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use http_body_util::{Empty, Full};
use hyper::upgrade::Upgraded;
use hyper_tungstenite::{
    tungstenite::{
        protocol::{frame::coding::CloseCode, CloseFrame, Role},
        Message,
    },
    HyperWebsocket, WebSocketStream,
};
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
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixListener},
};

use crate::{
    configurations::{EndpointHttpHostString, ListenHttpEndpointType},
    settings::HostSettings,
    settings_compiled::SettingsCompiled,
};

const TIMEOUT: Duration = Duration::from_secs(5);

const NO_SESSION_TOKEN: &str = "no session token";

/// The endpoint's read timeout in the idle tests: short enough to hit in a test, long enough to
/// tell a silent direction from a silent session.
const IDLE_READ_TIMEOUT: Duration = Duration::from_secs(1);

/// A one-way stream: this many messages, one every fifth of the read timeout - three read
/// timeouts in all.
const ONE_WAY_MESSAGES: usize = 15;

#[tokio::test]
async fn http1_upgrade_keeps_the_tunnel_open_past_the_handshake() {
    let upstream = start_upstream(UpstreamBehaviour::Echo);
    let port = start_https2_endpoint(&upstream).await;

    assert_echoes_past_the_handshake(connect_with_http1_upgrade(port).await).await;
}

#[tokio::test]
async fn http1_upgrade_delivers_the_upstream_close_frame() {
    let upstream = start_upstream(UpstreamBehaviour::CloseRightAway);
    let port = start_https2_endpoint(&upstream).await;

    assert_receives_the_upstream_close_frame(connect_with_http1_upgrade(port).await).await;
}

#[tokio::test]
async fn h2_extended_connect_keeps_the_tunnel_open_past_the_handshake() {
    let upstream = start_upstream(UpstreamBehaviour::Echo);
    let port = start_https2_endpoint(&upstream).await;

    assert_echoes_past_the_handshake(connect_with_h2_extended_connect(port).await).await;
}

#[tokio::test]
async fn h2_extended_connect_delivers_the_upstream_close_frame() {
    let upstream = start_upstream(UpstreamBehaviour::CloseRightAway);
    let port = start_https2_endpoint(&upstream).await;

    assert_receives_the_upstream_close_frame(connect_with_h2_extended_connect(port).await).await;
}

#[tokio::test]
async fn http1_upgrade_carries_a_one_way_upstream_stream_past_the_read_timeout() {
    let upstream = start_upstream(UpstreamBehaviour::Push);
    let port = start_https2_endpoint_with_idle_read_timeout(&upstream).await;

    assert_receives_every_pushed_message(connect_with_http1_upgrade(port).await).await;
}

#[tokio::test]
async fn h2_extended_connect_carries_a_one_way_upstream_stream_past_the_read_timeout() {
    let upstream = start_upstream(UpstreamBehaviour::Push);
    let port = start_https2_endpoint_with_idle_read_timeout(&upstream).await;

    assert_receives_every_pushed_message(connect_with_h2_extended_connect(port).await).await;
}

#[tokio::test]
async fn http1_upgrade_carries_a_one_way_client_stream_past_the_read_timeout() {
    let upstream = start_upstream(UpstreamBehaviour::Count);
    let port = start_https2_endpoint_with_idle_read_timeout(&upstream).await;

    assert_upstream_receives_every_message(connect_with_http1_upgrade(port).await).await;
}

#[tokio::test]
async fn h2_extended_connect_carries_a_one_way_client_stream_past_the_read_timeout() {
    let upstream = start_upstream(UpstreamBehaviour::Count);
    let port = start_https2_endpoint_with_idle_read_timeout(&upstream).await;

    assert_upstream_receives_every_message(connect_with_h2_extended_connect(port).await).await;
}

#[tokio::test]
async fn http1_upgrade_closes_a_session_silent_both_ways_after_the_read_timeout() {
    let upstream = start_upstream(UpstreamBehaviour::Count);
    let port = start_https2_endpoint_with_idle_read_timeout(&upstream).await;

    assert_closed_after_the_read_timeout(connect_with_http1_upgrade(port).await).await;
}

#[tokio::test]
async fn h2_extended_connect_closes_a_session_silent_both_ways_after_the_read_timeout() {
    let upstream = start_upstream(UpstreamBehaviour::Count);
    let port = start_https2_endpoint_with_idle_read_timeout(&upstream).await;

    assert_closed_after_the_read_timeout(connect_with_h2_extended_connect(port).await).await;
}

/// Two round trips with a pause after each: the tunnel has to outlive the
/// handshake, not just carry the first frame.
async fn assert_echoes_past_the_handshake<S>(mut websocket: WebSocketStream<S>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    for text in ["first", "second"] {
        websocket.send(Message::text(text)).await.unwrap();
        assert_eq!(next_message(&mut websocket).await, Message::text(text));

        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

async fn assert_receives_the_upstream_close_frame<S>(mut websocket: WebSocketStream<S>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match next_message(&mut websocket).await {
        Message::Close(Some(frame)) => {
            assert_eq!(frame.code, CloseCode::Policy);
            assert_eq!(frame.reason.as_str(), NO_SESSION_TOKEN);
        }
        other => panic!("expected the upstream's close frame, got {:?}", other),
    }
}

/// The upstream pushes for three read timeouts while the client sends nothing: the session is not
/// idle, only one direction of it is.
async fn assert_receives_every_pushed_message<S>(mut websocket: WebSocketStream<S>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    for index in 0..ONE_WAY_MESSAGES {
        assert_eq!(
            next_message(&mut websocket).await,
            Message::text(index.to_string())
        );
    }
}

/// The client sends for three read timeouts while the upstream answers nothing, then asks the
/// upstream how many messages it got.
async fn assert_upstream_receives_every_message<S>(mut websocket: WebSocketStream<S>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    for index in 0..ONE_WAY_MESSAGES {
        tokio::time::sleep(IDLE_READ_TIMEOUT / 5).await;
        websocket
            .send(Message::text(index.to_string()))
            .await
            .unwrap();
    }

    websocket.send(Message::text(COUNT_QUERY)).await.unwrap();

    assert_eq!(
        next_message(&mut websocket).await,
        Message::text(ONE_WAY_MESSAGES.to_string())
    );
}

/// Neither side sends anything: the session goes once it has been idle for the read timeout.
async fn assert_closed_after_the_read_timeout<S>(mut websocket: WebSocketStream<S>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let started = std::time::Instant::now();

    let ended = tokio::time::timeout(TIMEOUT, websocket.next())
        .await
        .expect("the idle session is still open");

    assert!(
        !matches!(ended, Some(Ok(Message::Text(_) | Message::Binary(_)))),
        "a message on a silent session: {:?}",
        ended
    );
    assert!(
        started.elapsed() >= IDLE_READ_TIMEOUT * 8 / 10,
        "closed after {:?}, before the read timeout",
        started.elapsed()
    );
}

async fn next_message<S>(websocket: &mut WebSocketStream<S>) -> Message
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(TIMEOUT, websocket.next())
        .await
        .expect("no websocket message in time")
        .expect("websocket ended without a close frame")
        .expect("websocket failed")
}

/// Upgrades `/ws` over HTTP/1.1 exactly as `curl --http1.1` or Cloudflare does,
/// with the RFC 6455 sample key, and hands the stream over once the `101` is in.
async fn connect_with_http1_upgrade(port: u16) -> WebSocketStream<TlsStream<TcpStream>> {
    let mut tls_stream = connect_tls(port, b"http/1.1").await;

    let request = format!(
        "GET /ws HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    );
    tls_stream.write_all(request.as_bytes()).await.unwrap();

    let (head, leftover) = read_response_head(&mut tls_stream).await;
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "expected a 101, got: {}",
        head
    );
    assert!(
        head.contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
        "the 101 does not accept the sample key: {}",
        head
    );

    WebSocketStream::from_partially_read(tls_stream, leftover, Role::Client, None).await
}

/// Opens `/ws` with an RFC 8441 extended CONNECT on an h2 connection.
async fn connect_with_h2_extended_connect(port: u16) -> WebSocketStream<TokioIo<Upgraded>> {
    let tls_stream = connect_tls(port, b"h2").await;

    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls_stream))
            .await
            .unwrap();
    tokio::spawn(connection);

    let mut request = hyper::Request::builder()
        .method(hyper::Method::CONNECT)
        .uri(format!("https://localhost:{port}/ws"))
        .header("sec-websocket-version", "13")
        .body(Empty::<Bytes>::new())
        .unwrap();
    request
        .extensions_mut()
        .insert(hyper::ext::Protocol::from_static("websocket"));

    let response = tokio::time::timeout(TIMEOUT, sender.send_request(request))
        .await
        .expect("no response to the extended CONNECT in time")
        .unwrap();
    assert_eq!(response.status(), hyper::StatusCode::OK);

    let upgraded = hyper::upgrade::on(response).await.unwrap();

    WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Client, None).await
}

/// The endpoint offers `h2`, `http/1.1` and `http/1.0`; the one protocol the
/// client offers is what gets negotiated, and that picks the path under test.
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

/// Reads up to the end of the response head; whatever came after it in the
/// same reads is the start of the websocket stream.
async fn read_response_head(stream: &mut TlsStream<TcpStream>) -> (String, Vec<u8>) {
    let mut received = Vec::new();
    let mut buffer = [0u8; 1024];

    loop {
        if let Some(end) = received.windows(4).position(|window| window == b"\r\n\r\n") {
            let leftover = received.split_off(end + 4);
            return (String::from_utf8(received).unwrap(), leftover);
        }

        let read = tokio::time::timeout(TIMEOUT, stream.read(&mut buffer))
            .await
            .expect("no response head in time")
            .unwrap();

        assert!(
            read > 0,
            "connection closed before the response head: {:?}",
            String::from_utf8_lossy(&received)
        );

        received.extend_from_slice(&buffer[..read]);
    }
}

/// The proxy under test: one `https2` endpoint on a free port, with a single
/// `unix+http` location in front of the upstream socket. The configuration is
/// compiled from settings the same way a settings file is.
async fn start_https2_endpoint(upstream: &UpstreamSocket) -> u16 {
    start_https2_endpoint_with(upstream, "").await
}

/// The same endpoint with its read timeout cut to [`IDLE_READ_TIMEOUT`].
async fn start_https2_endpoint_with_idle_read_timeout(upstream: &UpstreamSocket) -> u16 {
    let endpoint_settings = format!("  read_timeout: {}\n", IDLE_READ_TIMEOUT.as_millis());
    start_https2_endpoint_with(upstream, &endpoint_settings).await
}

/// `endpoint_settings`: more lines for the `endpoint` section, indented by two spaces.
async fn start_https2_endpoint_with(upstream: &UpstreamSocket, endpoint_settings: &str) -> u16 {
    // What main() does before anything touches TLS.
    my_tls::install_default_crypto_providers();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listening_addr = listener.local_addr().unwrap();

    let host_settings: HostSettings = my_settings_reader::serde_yaml::from_str(&format!(
        "endpoint:\n  type: https2\n{}locations:\n- path: /ws\n  type: unix+http\n  proxy_pass_to: '{}'\n",
        endpoint_settings, upstream.path
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
            );
        }
    });

    listening_addr.port()
}

#[derive(Clone, Copy)]
enum UpstreamBehaviour {
    /// Sends every text or binary message back.
    Echo,
    /// Refuses the session as soon as the upgrade is done, the way an upstream
    /// that finds no session token does.
    CloseRightAway,
    /// Sends [`ONE_WAY_MESSAGES`] messages, one every fifth of the idle read
    /// timeout, and reads nothing.
    Push,
    /// Sends nothing but, on a [`COUNT_QUERY`], the number of messages it got
    /// before it.
    Count,
}

const COUNT_QUERY: &str = "how many?";

/// A unix socket path of its own for each test, removed when the test ends.
struct UpstreamSocket {
    path: String,
}

impl Drop for UpstreamSocket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.path.as_str());
    }
}

/// A websocket upstream on a unix socket, served by hyper with upgrades on, as
/// an http/1.1 MyJetTools service is.
fn start_upstream(behaviour: UpstreamBehaviour) -> UpstreamSocket {
    // Short on purpose: a unix socket path is limited to ~100 bytes.
    let file_name = format!(
        "mrp-ws-{}.sock",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );

    let socket = UpstreamSocket {
        path: std::env::temp_dir()
            .join(file_name)
            .to_str()
            .unwrap()
            .to_string(),
    };

    let listener = UnixListener::bind(socket.path.as_str()).unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((unix_stream, _)) = listener.accept().await else {
                return;
            };

            let service = hyper::service::service_fn(
                move |mut request: hyper::Request<hyper::body::Incoming>| async move {
                    let (response, websocket) =
                        hyper_tungstenite::upgrade(&mut request, None).unwrap();

                    tokio::spawn(serve_upstream_websocket(websocket, behaviour));

                    Ok::<hyper::Response<Full<Bytes>>, Infallible>(response)
                },
            );

            tokio::spawn(
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(unix_stream), service)
                    .with_upgrades(),
            );
        }
    });

    socket
}

async fn serve_upstream_websocket(websocket: HyperWebsocket, behaviour: UpstreamBehaviour) {
    let Ok(mut websocket) = websocket.await else {
        return;
    };

    match behaviour {
        UpstreamBehaviour::Echo => {}
        UpstreamBehaviour::CloseRightAway => {
            let close = CloseFrame {
                code: CloseCode::Policy,
                reason: NO_SESSION_TOKEN.into(),
            };

            if websocket.send(Message::Close(Some(close))).await.is_err() {
                return;
            }
        }
        UpstreamBehaviour::Push => {
            for index in 0..ONE_WAY_MESSAGES {
                tokio::time::sleep(IDLE_READ_TIMEOUT / 5).await;

                if websocket
                    .send(Message::text(index.to_string()))
                    .await
                    .is_err()
                {
                    return;
                }
            }

            // Held open until the client is done with it.
            while let Some(Ok(_)) = websocket.next().await {}
            return;
        }
        UpstreamBehaviour::Count => {
            let mut count = 0usize;

            while let Some(Ok(message)) = websocket.next().await {
                if message == Message::text(COUNT_QUERY) {
                    if websocket
                        .send(Message::text(count.to_string()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                } else if message.is_text() || message.is_binary() {
                    count += 1;
                }
            }

            return;
        }
    }

    while let Some(Ok(message)) = websocket.next().await {
        if !(message.is_text() || message.is_binary()) {
            continue;
        }

        if websocket.send(message).await.is_err() {
            return;
        }
    }
}

/// The endpoint serves the proxy's self-signed certificate; what is under test
/// is what happens after the handshake, not the certificate.
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

//! TLS session resumption on `https` and `https2` endpoints, driven through the entry the tcp
//! listener uses (`handle_connection`: TLS with SNI, endpoint resolution, the request handler
//! of the endpoint type, the upstream).
//!
//! A client which keeps its sessions connects twice. An endpoint without a client certificate
//! resumes the second connection; an endpoint which requires one never does - every connection
//! there is a full handshake, which is what verifies the certificate and hands it to the
//! request handler.
//!
//! Before a client connects again it makes a request and reads the answer: a TLS 1.3 server
//! sends its tickets after the handshake, and a client which never reads holds none.

use std::{convert::Infallible, sync::Arc, time::Duration};

use bytes::Bytes;
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use my_tls::tokio_rustls::{
    client::TlsStream,
    rustls::{
        self,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
        version::{TLS12, TLS13},
        DigitallySignedStruct, HandshakeKind, SignatureScheme, SupportedProtocolVersion,
    },
    TlsConnector,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::{
    configurations::{EndpointHttpHostString, ListenHttpEndpointType, SslCertificateIdRef},
    settings::{ClientCertificateCaSettings, HostSettings},
    settings_compiled::SettingsCompiled,
};

const TIMEOUT: Duration = Duration::from_secs(5);

/// The request header the endpoint fills with `${CLIENT_CERT_CN}`; the upstream answers with
/// what it got in it.
const CN_HEADER: &str = "x-client-cn";

const CLIENT_CN: &str = "resumption-test-client";

#[tokio::test]
async fn https1_resumes_a_tls13_session() {
    assert_resumes(ListenHttpEndpointType::Https1, &TLS13).await;
}

#[tokio::test]
async fn https1_resumes_a_tls12_session() {
    assert_resumes(ListenHttpEndpointType::Https1, &TLS12).await;
}

#[tokio::test]
async fn https2_resumes_a_tls13_session() {
    assert_resumes(ListenHttpEndpointType::Https2, &TLS13).await;
}

#[tokio::test]
async fn https2_resumes_a_tls12_session() {
    assert_resumes(ListenHttpEndpointType::Https2, &TLS12).await;
}

#[tokio::test]
async fn https1_with_a_client_certificate_never_resumes_tls13() {
    assert_client_certificate_endpoint_never_resumes(ListenHttpEndpointType::Https1, &TLS13).await;
}

#[tokio::test]
async fn https1_with_a_client_certificate_never_resumes_tls12() {
    assert_client_certificate_endpoint_never_resumes(ListenHttpEndpointType::Https1, &TLS12).await;
}

#[tokio::test]
async fn https2_with_a_client_certificate_never_resumes_tls13() {
    assert_client_certificate_endpoint_never_resumes(ListenHttpEndpointType::Https2, &TLS13).await;
}

#[tokio::test]
async fn https2_with_a_client_certificate_never_resumes_tls12() {
    assert_client_certificate_endpoint_never_resumes(ListenHttpEndpointType::Https2, &TLS12).await;
}

async fn assert_resumes(
    endpoint_type: ListenHttpEndpointType,
    version: &'static SupportedProtocolVersion,
) {
    let upstream_port = start_upstream().await;
    let port = start_endpoint(endpoint_type, upstream_port, None).await;

    let client = client_config(version, None);

    let mut first = connect(port, &client).await;
    assert_eq!(
        first.get_ref().1.handshake_kind(),
        Some(HandshakeKind::Full)
    );
    assert_eq!(request(&mut first, port).await, "cn=");

    let mut second = connect(port, &client).await;
    assert_eq!(
        second.get_ref().1.handshake_kind(),
        Some(HandshakeKind::Resumed),
        "the second connection did a full handshake"
    );
    assert_eq!(request(&mut second, port).await, "cn=");
}

/// The client holds a session for the same server name - from an endpoint without a client
/// certificate, which resumes it - and still gets a full handshake, with its certificate seen
/// by the request handler, on every connection to the endpoint requiring one.
async fn assert_client_certificate_endpoint_never_resumes(
    endpoint_type: ListenHttpEndpointType,
    version: &'static SupportedProtocolVersion,
) {
    let test_ca = TestCa::generate();
    let ca_id = test_ca.load_into_proxy().await;

    let upstream_port = start_upstream().await;
    let open_port = start_endpoint(endpoint_type, upstream_port, None).await;
    let guarded_port = start_endpoint(endpoint_type, upstream_port, Some(ca_id.as_str())).await;

    let client = client_config(version, Some(&test_ca));

    let mut open = connect(open_port, &client).await;
    assert_eq!(open.get_ref().1.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(request(&mut open, open_port).await, "cn=");

    let mut open = connect(open_port, &client).await;
    assert_eq!(
        open.get_ref().1.handshake_kind(),
        Some(HandshakeKind::Resumed),
        "the client holds no session to offer"
    );
    assert_eq!(request(&mut open, open_port).await, "cn=");

    for attempt in 1..=2 {
        let mut guarded = connect(guarded_port, &client).await;

        assert_eq!(
            guarded.get_ref().1.handshake_kind(),
            Some(HandshakeKind::Full),
            "connection {attempt} to the endpoint requiring a client certificate resumed"
        );

        assert_eq!(
            request(&mut guarded, guarded_port).await,
            format!("cn={CLIENT_CN}"),
            "connection {attempt}: the request handler did not see the client certificate"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------------------------

/// One config for every connection of a test: its session store is what resumes. It keeps
/// sessions in memory - the rustls default.
fn client_config(
    version: &'static SupportedProtocolVersion,
    client_certificate: Option<&TestCa>,
) -> Arc<rustls::ClientConfig> {
    let builder = rustls::ClientConfig::builder_with_protocol_versions(&[version])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert));

    let mut config = match client_certificate {
        Some(test_ca) => builder
            .with_client_auth_cert(
                vec![test_ca.client_cert.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(test_ca.client_key.clone())),
            )
            .unwrap(),
        None => builder.with_no_client_auth(),
    };

    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Arc::new(config)
}

async fn connect(port: u16, client: &Arc<rustls::ClientConfig>) -> TlsStream<TcpStream> {
    let tcp_stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

    tokio::time::timeout(
        TIMEOUT,
        TlsConnector::from(client.clone())
            .connect(ServerName::try_from("localhost").unwrap(), tcp_stream),
    )
    .await
    .expect("no TLS handshake in time")
    .unwrap()
}

/// `GET /` over HTTP/1.1; the body of a `200` answer.
async fn request(stream: &mut TlsStream<TcpStream>, port: u16) -> String {
    let request = format!("GET / HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();

    let (head, body) = tokio::time::timeout(TIMEOUT, read_response(stream))
        .await
        .expect("no response in time");

    assert!(head.starts_with("HTTP/1.1 200"), "{head}");

    body
}

/// The head, and the body by its `content-length` or its chunks.
async fn read_response(stream: &mut TlsStream<TcpStream>) -> (String, String) {
    let mut received = Vec::new();

    let head_end = loop {
        if let Some(end) = received.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }

        read_more(stream, &mut received).await;
    };

    let head = String::from_utf8(received[..head_end].to_vec()).unwrap();
    let head_lower = head.to_ascii_lowercase();

    if let Some(content_length) = head_lower
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
    {
        let content_length: usize = content_length.trim().parse().unwrap();

        while received.len() < head_end + content_length {
            read_more(stream, &mut received).await;
        }

        let body = &received[head_end..head_end + content_length];
        return (head, String::from_utf8(body.to_vec()).unwrap());
    }

    assert!(
        head_lower.contains("transfer-encoding: chunked"),
        "a response with no length: {head}"
    );

    let mut body = Vec::new();
    let mut pos = head_end;

    loop {
        let size_end = loop {
            if let Some(end) = received[pos..]
                .windows(2)
                .position(|window| window == b"\r\n")
            {
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
            return (head, String::from_utf8(body).unwrap());
        }

        body.extend_from_slice(&received[data_start..data_start + size]);
        pos = data_start + size + 2;
    }
}

async fn read_more(stream: &mut TlsStream<TcpStream>, received: &mut Vec<u8>) {
    let mut buffer = [0u8; 4096];
    let read = stream.read(&mut buffer).await.unwrap();

    assert!(
        read > 0,
        "connection closed in the middle of the response: {:?}",
        String::from_utf8_lossy(received)
    );

    received.extend_from_slice(&buffer[..read]);
}

// ---------------------------------------------------------------------------------------------
// The proxy
// ---------------------------------------------------------------------------------------------

/// One endpoint on a free port with a single location in front of the upstream, compiled from
/// settings the way a settings file is. With `client_ca_id` the endpoint requires a client
/// certificate of that ca.
async fn start_endpoint(
    endpoint_type: ListenHttpEndpointType,
    upstream_port: u16,
    client_ca_id: Option<&str>,
) -> u16 {
    // What main() does before anything touches TLS.
    my_tls::install_default_crypto_providers();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listening_addr = listener.local_addr().unwrap();

    let type_name = match endpoint_type {
        ListenHttpEndpointType::Https1 => "https",
        ListenHttpEndpointType::Https2 => "https2",
        _ => panic!("not a TLS endpoint type"),
    };

    let client_ca_line = match client_ca_id {
        Some(ca_id) => format!("  client_certificate_ca: {ca_id}\n"),
        None => String::new(),
    };

    let host_settings: HostSettings = my_settings_reader::serde_yaml::from_str(&format!(
        "endpoint:\n  type: {type_name}\n{client_ca_line}locations:\n- path: /\n  proxy_pass_to: 'http://127.0.0.1:{upstream_port}'\n  modify_http_headers:\n    add:\n      request:\n      - name: {CN_HEADER}\n        value: '${{CLIENT_CERT_CN}}'\n"
    ))
    .unwrap();

    let settings = SettingsCompiled {
        client_certificate_ca: client_ca_id
            .map(|ca_id| ClientCertificateCaSettings {
                id: ca_id.to_string(),
                ca: None,
                revocation_list: None,
                unlimited_expiration: None,
            })
            .into_iter()
            .collect(),
        ..Default::default()
    };

    let host_endpoint =
        EndpointHttpHostString::new(format!("localhost:{}", listening_addr.port())).unwrap();

    let endpoint_info = crate::scripts::compile_http_configuration(
        &settings,
        host_endpoint,
        &host_settings,
        endpoint_type,
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

/// An http/1.1 upstream: answers every request with `cn=` and the value of [`CN_HEADER`].
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
                    let cn = request
                        .headers()
                        .get(CN_HEADER)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default()
                        .to_string();

                    Ok::<_, Infallible>(hyper::Response::new(Full::new(Bytes::from(format!(
                        "cn={cn}"
                    )))))
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

// ---------------------------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------------------------

/// A client-certificate ca and one client certificate it issued, made for the test.
struct TestCa {
    ca_cert: CertificateDer<'static>,
    client_cert: CertificateDer<'static>,
    client_key: Vec<u8>,
}

impl TestCa {
    fn generate() -> Self {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
            KeyPair, KeyUsagePurpose,
        };

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "resumption test ca");
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);

        let client_key = KeyPair::generate().unwrap();
        let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        client_params
            .distinguished_name
            .push(DnType::CommonName, CLIENT_CN);
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_cert = client_params.signed_by(&client_key, &issuer).unwrap();

        Self {
            ca_cert: ca_cert.der().clone(),
            client_cert: client_cert.der().clone(),
            client_key: client_key.serialize_der(),
        }
    }

    /// Loads the ca under an id of its own - the certificate cache is shared by every test -
    /// the way an upload from the admin ui does, and returns the id.
    async fn load_into_proxy(&self) -> String {
        let ca_id = format!(
            "resumption-test-ca-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        );

        let ca = Arc::new(
            super::ClientCertificateCa::new(vec![self.ca_cert.clone()], None, vec![], None)
                .unwrap(),
        );

        let id = ca_id.clone();
        crate::app::APP_CTX
            .ssl_certificates_cache
            .write(move |cache| {
                cache
                    .client_ca
                    .insert(SslCertificateIdRef::new(id.as_str()), ca);
            })
            .await;

        ca_id
    }
}

/// The endpoint serves the proxy's self-signed certificate; what is under test is whether the
/// handshake resumes, not the certificate.
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

//! `api_keys_auth` end to end, on an `http` endpoint (the h1 pipeline) and on an `http2` one
//! (hyper): which requests get to the upstream, and what the upstream gets.
//!
//! The keys are added to `APP_CTX.api_keys` next to the ones of the other tests, each test under
//! ids of its own. The upstream answers every request with the `X-Api-Key` values it got, so a
//! test sees both whether a request got through and what went on with it.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
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
    app::APP_CTX,
    configurations::{EndpointHttpHostString, ListenHttpEndpointType},
    settings::{EndpointTemplateSettings, HostSettings},
    settings_compiled::SettingsCompiled,
};

const TIMEOUT: Duration = Duration::from_secs(5);

const ENDPOINT_TYPES: [ListenHttpEndpointType; 2] =
    [ListenHttpEndpointType::Http1, ListenHttpEndpointType::Http2];

/// What the upstream answers when the request carried no `X-Api-Key`.
const NO_KEY: &str = "-";

/// A set of keys under an id no other test has.
fn set_of_keys(name: &str, keys: &[&str]) -> String {
    let id = format!(
        "api_keys_tests_{name}_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );

    APP_CTX.api_keys.add_for_tests(&id, keys);

    id
}

/// An HTTP/1.1 upstream which answers every request with the values of the `X-Api-Key` headers
/// it got - `-` for none - and counts the requests.
struct Upstream {
    port: u16,
    requests: Arc<AtomicUsize>,
}

impl Upstream {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(AtomicUsize::new(0));
        let counted = requests.clone();

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };

                let counted = counted.clone();

                tokio::spawn(async move {
                    let Some(head) = read_head(&mut stream).await else {
                        return;
                    };

                    counted.fetch_add(1, Ordering::SeqCst);

                    let keys: Vec<&str> = head
                        .lines()
                        .skip(1)
                        .filter_map(|line| line.split_once(':'))
                        .filter(|(name, _)| name.trim().eq_ignore_ascii_case("x-api-key"))
                        .map(|(_, value)| value.trim())
                        .collect();

                    let body = if keys.is_empty() {
                        NO_KEY.to_string()
                    } else {
                        keys.join(",")
                    };

                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });

        Self { port, requests }
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

async fn read_head(stream: &mut TcpStream) -> Option<String> {
    let mut received = Vec::new();
    let mut buffer = [0u8; 4096];

    while find(&received, b"\r\n\r\n").is_none() {
        match tokio::time::timeout(TIMEOUT, stream.read(&mut buffer)).await {
            Ok(Ok(read)) if read > 0 => received.extend_from_slice(&buffer[..read]),
            _ => return None,
        }
    }

    Some(String::from_utf8_lossy(&received).to_string())
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// The proxy under test: one endpoint on a free port, compiled from `host_yaml` - the
/// `endpoint:` and the `locations:` of a host, as a settings file writes them - with the
/// settings `settings` (its templates).
async fn start_endpoint(
    endpoint_type: ListenHttpEndpointType,
    host_yaml: &str,
    settings: &SettingsCompiled,
) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listening_addr = listener.local_addr().unwrap();

    let host_yaml = host_yaml.replace("{type}", endpoint_type.as_str());
    let host_settings: HostSettings = my_settings_reader::serde_yaml::from_str(&host_yaml)
        .unwrap_or_else(|err| panic!("{err}\n{host_yaml}"));

    let host_endpoint =
        EndpointHttpHostString::new(format!("localhost:{}", listening_addr.port())).unwrap();

    let endpoint_info = crate::scripts::compile_http_configuration(
        settings,
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

/// One request on a connection of its own: the status, and the body - what the upstream got in
/// `X-Api-Key` if it got the request. `headers` are sent as they are given, one each, in their
/// order and their letter case.
async fn request(
    endpoint_type: ListenHttpEndpointType,
    port: u16,
    target: &str,
    headers: &[(&str, &str)],
) -> (u16, String) {
    match endpoint_type {
        ListenHttpEndpointType::Http1 => h1_request(port, target, headers).await,
        _ => h2_request(port, target, headers).await,
    }
}

async fn h1_request(port: u16, target: &str, headers: &[(&str, &str)]) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

    let mut request = format!("GET {target} HTTP/1.1\r\nHost: localhost:{port}\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("Connection: close\r\n\r\n");

    stream.write_all(request.as_bytes()).await.unwrap();

    let mut received = Vec::new();
    let mut buffer = [0u8; 4096];

    let head_end = loop {
        if let Some(head_end) = find(&received, b"\r\n\r\n") {
            break head_end;
        }

        let read = tokio::time::timeout(TIMEOUT, stream.read(&mut buffer))
            .await
            .expect("no response in time")
            .unwrap();
        assert!(read > 0, "closed before a response");
        received.extend_from_slice(&buffer[..read]);
    };

    let head = String::from_utf8_lossy(&received[..head_end]).to_string();
    let status: u16 = head
        .split(' ')
        .nth(1)
        .and_then(|status| status.parse().ok())
        .unwrap_or_else(|| panic!("{head}"));

    let content_length: Option<usize> = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("content-length") {
            value.trim().parse().ok()
        } else {
            None
        }
    });

    let body_start = head_end + 4;

    loop {
        let have = received.len() - body_start;

        if content_length.is_some_and(|content_length| have >= content_length) {
            break;
        }

        let read = match tokio::time::timeout(TIMEOUT, stream.read(&mut buffer)).await {
            Ok(Ok(read)) => read,
            _ => break,
        };

        if read == 0 {
            break;
        }

        received.extend_from_slice(&buffer[..read]);
    }

    let mut body = received[body_start..].to_vec();
    if let Some(content_length) = content_length {
        body.truncate(content_length);
    }

    (status, String::from_utf8_lossy(&body).to_string())
}

async fn h2_request(port: u16, target: &str, headers: &[(&str, &str)]) -> (u16, String) {
    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .unwrap();

    tokio::spawn(connection);

    let mut request = hyper::Request::builder()
        .method("GET")
        .uri(format!("http://localhost:{port}{target}"));

    for (name, value) in headers {
        request = request.header(*name, *value);
    }

    let response = tokio::time::timeout(
        TIMEOUT,
        sender.send_request(request.body(Empty::<Bytes>::new()).unwrap()),
    )
    .await
    .expect("no response in time")
    .unwrap();

    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();

    (status, String::from_utf8_lossy(&body).to_string())
}

fn guarded_host(upstream: &Upstream, endpoint_keys: &str) -> String {
    format!(
        "endpoint:\n  type: {{type}}\n  api_keys_auth: {endpoint_keys}\nlocations:\n- path: /\n  proxy_pass_to: http://127.0.0.1:{}\n",
        upstream.port
    )
}

#[tokio::test]
async fn an_endpoint_takes_requests_with_a_key_of_its_set_only() {
    let keys = set_of_keys("endpoint", &["key-1", "key-2"]);

    for endpoint_type in ENDPOINT_TYPES {
        let upstream = Upstream::start().await;
        let port = start_endpoint(
            endpoint_type,
            &guarded_host(&upstream, &keys),
            &SettingsCompiled::default(),
        )
        .await;

        let name = endpoint_type.as_str();

        for headers in [
            vec![],
            vec![("x-api-key", "key-3")],
            vec![("x-api-key", "key-1x")],
            vec![("x-api-key", "KEY-1")],
            vec![("x-api-key", "")],
            // Not where the key is looked for.
            vec![("authorization", "key-1")],
            // Two are refused whatever they are: the upstream might read the other one.
            vec![("x-api-key", "key-1"), ("x-api-key", "key-2")],
            vec![("x-api-key", "key-1"), ("x-api-key", "key-3")],
            vec![("x-api-key", "key-3"), ("x-api-key", "key-1")],
        ] {
            let (status, _) = request(endpoint_type, port, "/x", &headers).await;
            assert_eq!(status, 401, "{name}: {headers:?}");
        }

        assert_eq!(upstream.requests(), 0, "{name}");

        // The key goes on to the upstream as it came.
        for key in ["key-1", "key-2"] {
            assert_eq!(
                request(endpoint_type, port, "/x", &[("x-api-key", key)]).await,
                (200, key.to_string()),
                "{name}"
            );
        }

        // The name of the header is matched in any letter case.
        assert_eq!(
            request(endpoint_type, port, "/x", &[("X-API-Key", "key-1")])
                .await
                .0,
            200,
            "{name}"
        );

        assert_eq!(upstream.requests(), 3, "{name}");
    }
}

#[tokio::test]
async fn a_location_names_a_set_of_its_own_or_none() {
    let clients = set_of_keys("clients", &["client-key"]);
    let admins = set_of_keys("admins", &["admin-key"]);

    for endpoint_type in ENDPOINT_TYPES {
        let upstream = Upstream::start().await;

        let host = format!(
            "endpoint:\n  type: {{type}}\n  api_keys_auth: {clients}\nlocations:\n\
             - path: /admin\n  proxy_pass_to: http://127.0.0.1:{port}\n  api_keys_auth: {admins}\n\
             - path: /health\n  proxy_pass_to: http://127.0.0.1:{port}\n  api_keys_auth: none\n\
             - path: /\n  proxy_pass_to: http://127.0.0.1:{port}\n",
            port = upstream.port
        );

        let port = start_endpoint(endpoint_type, &host, &SettingsCompiled::default()).await;
        let name = endpoint_type.as_str();

        for (target, key, expected) in [
            ("/health", None, 200),
            ("/health", Some("client-key"), 200),
            ("/admin", None, 401),
            ("/admin", Some("client-key"), 401),
            ("/admin", Some("admin-key"), 200),
            ("/", None, 401),
            ("/", Some("admin-key"), 401),
            ("/", Some("client-key"), 200),
        ] {
            let headers: Vec<(&str, &str)> =
                key.map(|key| ("x-api-key", key)).into_iter().collect();
            let (status, _) = request(endpoint_type, port, target, &headers).await;
            assert_eq!(status, expected, "{name} {target} {key:?}");
        }
    }
}

/// A set nothing declares a key under - or a url has not given yet: the endpoint is served, and
/// lets nobody through.
#[tokio::test]
async fn a_set_with_no_keys_lets_nobody_through() {
    let id = format!(
        "api_keys_tests_never_declared_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );

    for endpoint_type in ENDPOINT_TYPES {
        let upstream = Upstream::start().await;
        let port = start_endpoint(
            endpoint_type,
            &guarded_host(&upstream, &id),
            &SettingsCompiled::default(),
        )
        .await;

        for headers in [
            vec![],
            vec![("x-api-key", "anything")],
            vec![("x-api-key", "")],
        ] {
            let (status, _) = request(endpoint_type, port, "/x", &headers).await;
            assert_eq!(status, 401, "{}: {headers:?}", endpoint_type.as_str());
        }

        assert_eq!(upstream.requests(), 0);
    }
}

#[tokio::test]
async fn the_template_guards_the_endpoint_and_none_takes_it_away() {
    let keys = set_of_keys("template", &["template-key"]);

    let settings = SettingsCompiled {
        endpoint_templates: HashMap::from([(
            "tpl".to_string(),
            EndpointTemplateSettings {
                ssl_certificate: None,
                client_certificate_ca: None,
                google_auth: None,
                oauth: None,
                modify_http_headers: None,
                whitelisted_ip: None,
                api_keys_auth: Some(keys.clone()),
            },
        )]),
        ..Default::default()
    };

    for endpoint_type in ENDPOINT_TYPES {
        let upstream = Upstream::start().await;
        let name = endpoint_type.as_str();

        let of_template = format!(
            "endpoint:\n  type: {{type}}\n  template_id: tpl\nlocations:\n- proxy_pass_to: http://127.0.0.1:{}\n",
            upstream.port
        );
        let port = start_endpoint(endpoint_type, &of_template, &settings).await;

        assert_eq!(
            request(endpoint_type, port, "/x", &[]).await.0,
            401,
            "{name}"
        );
        assert_eq!(
            request(endpoint_type, port, "/x", &[("x-api-key", "template-key")])
                .await
                .0,
            200,
            "{name}"
        );

        let opened = of_template.replace(
            "template_id: tpl",
            "template_id: tpl\n  api_keys_auth: none",
        );
        let port = start_endpoint(endpoint_type, &opened, &settings).await;

        assert_eq!(
            request(endpoint_type, port, "/x", &[]).await.0,
            200,
            "{name}"
        );
    }
}

/// The key is checked before the headers of the location are applied: one the upstream is not
/// to see is taken off with `modify_http_headers`, and the request still has to carry it.
#[tokio::test]
async fn a_key_is_kept_from_the_upstream_with_modify_http_headers() {
    let keys = set_of_keys("removed", &["removed-key"]);

    for endpoint_type in ENDPOINT_TYPES {
        let upstream = Upstream::start().await;

        let host = format!(
            "endpoint:\n  type: {{type}}\n  api_keys_auth: {keys}\nlocations:\n- proxy_pass_to: http://127.0.0.1:{}\n  modify_http_headers:\n    remove:\n      request:\n      - x-api-key\n",
            upstream.port
        );

        let port = start_endpoint(endpoint_type, &host, &SettingsCompiled::default()).await;
        let name = endpoint_type.as_str();

        assert_eq!(
            request(endpoint_type, port, "/x", &[]).await.0,
            401,
            "{name}"
        );
        assert_eq!(
            request(endpoint_type, port, "/x", &[("x-api-key", "removed-key")]).await,
            (200, NO_KEY.to_string()),
            "{name}"
        );
    }
}

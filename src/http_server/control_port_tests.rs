//! The control port end to end: the server `main()` starts, on a free port. The folder of the UI
//! is `./wwwroot` of the directory the process runs in - under `cargo test` that is the root of
//! the crate, so `/../Cargo.toml` names a file which is there and is not a file of the UI.
//!
//! The files are served by `StaticFilesMiddleware` of `my-http-server`, and it is what refuses
//! a path with a `..` segment: these tests hold the control port to it whatever the version of
//! the library is.
//!
//! The HTTP/1.1 client is a socket written to by hand: what a test sends is what gets to the
//! wire, a `..` in the path included.

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

use crate::settings::GlobalSettings;
use crate::test_ports::free_port;

const TIMEOUT: Duration = Duration::from_secs(5);

const SECRET: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----";

/// Paths which leave `./wwwroot` for the root of the crate, each in a spelling of its own.
const OUT_OF_THE_FOLDER: [&str; 10] = [
    "/../Cargo.toml",
    "/assets/../../Cargo.toml",
    "/api/../../Cargo.toml",
    "/%2e%2e/Cargo.toml",
    "/%2E%2E/Cargo.toml",
    "/.%2e/Cargo.toml",
    "/..%2fCargo.toml",
    "/..%5cCargo.toml",
    "/..\\Cargo.toml",
    "/../Cargo.toml?v=1",
];

#[tokio::test]
async fn the_files_of_the_ui_are_served() {
    let port = start_control_port().await;

    let index_html = std::fs::read("wwwroot/index.html").unwrap();
    let app_css = std::fs::read("wwwroot/assets/app.css").unwrap();

    for target in ["/", "/index.html", "/index.html?v=1"] {
        let response = get(port, target).await;
        assert_eq!(response.status, 200, "{target}");
        assert_eq!(response.body, index_html, "{target}");
    }

    let response = get(port, "/assets/app.css").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, app_css);

    // A route of the UI is not a file: the page is served, and the router of the UI takes it
    // from there.
    for target in [
        "/no-such-page",
        "/logs/endpoint/1",
        "/assets/no-such-file.css",
    ] {
        let response = get(port, target).await;
        assert_eq!(response.status, 200, "{target}");
        assert_eq!(response.body, index_html, "{target}");
    }
}

#[tokio::test]
async fn a_path_out_of_the_ui_folder_is_refused() {
    let port = start_control_port().await;

    let cargo_toml = std::fs::read("Cargo.toml").unwrap();

    for target in OUT_OF_THE_FOLDER {
        let response = get(port, target).await;
        assert_eq!(response.status, 403, "{target}");
        assert!(!contains(&response.body, &cargo_toml), "{target}");
    }

    // The files are served after that as they were.
    let response = get(port, "/index.html").await;
    assert_eq!(response.status, 200);
}

/// Enough `..` get to the root of the file system from any directory, and from there to any
/// file the process can read - a private key with the mode 0600 among them.
#[tokio::test]
async fn a_file_of_the_host_is_not_served_by_its_absolute_path() {
    let port = start_control_port().await;

    // On Windows a path from the root is one of the drive the process runs on, and the temp
    // folder may be on another one: the key goes to `target` of the crate there.
    #[cfg(unix)]
    let parent = std::env::temp_dir();
    #[cfg(not(unix))]
    let parent = std::env::current_dir().unwrap().join("target");

    let dir = parent.join(format!("control-port-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();

    let key = dir.join("id_ed25519");
    std::fs::write(&key, SECRET).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    // The path of the key from the root of the file system - on Windows without its drive, and
    // with `/` between its parts: `/Users/.../id_ed25519`.
    let key_path = key.to_str().unwrap();
    #[cfg(not(unix))]
    let key_path = key_path[key_path.find('\\').unwrap()..].replace('\\', "/");
    let target = format!("{}{}", "/..".repeat(32), key_path);

    // The path the request is made of is the file.
    assert_eq!(std::fs::read(format!("./wwwroot{target}")).unwrap(), SECRET);

    let response = get(port, &target).await;

    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(response.status, 403);
    assert!(!contains(&response.body, SECRET));
}

/// `http_control_port: 9000` - a bare port: the control port is served on the loopback address,
/// and on no other address of the host.
#[tokio::test]
async fn the_control_port_is_the_hosts_own_by_default() {
    let port = free_port().await;

    let settings: GlobalSettings =
        serde_yaml::from_str(&format!("http_control_port: {port}")).unwrap();

    let addr = settings.get_http_control_addr().unwrap();
    assert_eq!(addr, SocketAddr::from(([127, 0, 0, 1], port)));

    super::start_at(addr);
    wait_until_served(port).await;

    let response = get(port, "/index.html").await;
    assert_eq!(response.status, 200);

    // A host with an address of its own besides the loopback one: the port is closed there.
    if let Some(ip) = an_address_which_is_not_loopback().await {
        let connect = TcpStream::connect((ip, port));
        let connected = tokio::time::timeout(TIMEOUT, connect).await;
        assert!(!matches!(connected, Ok(Ok(_))), "served on {ip}:{port}");
    }
}

/// `http_control_port: 0.0.0.0:9000` - the whole address: the control port is served on every
/// IPv4 address of the host, the loopback one and the one of its network card.
#[tokio::test]
async fn the_control_port_listens_on_the_address_of_the_settings() {
    let port = free_port().await;

    let settings: GlobalSettings =
        serde_yaml::from_str(&format!("http_control_port: 0.0.0.0:{port}")).unwrap();

    let addr = settings.get_http_control_addr().unwrap();
    assert_eq!(addr, SocketAddr::from(([0, 0, 0, 0], port)));

    super::start_at(addr);
    wait_until_served(port).await;

    let response = get(port, "/index.html").await;
    assert_eq!(response.status, 200);

    if let Some(ip) = an_address_which_is_not_loopback().await {
        let connect = TcpStream::connect((ip, port));
        let connected = tokio::time::timeout(TIMEOUT, connect).await;
        assert!(matches!(connected, Ok(Ok(_))), "not served on {ip}:{port}");
    }
}

/// `GET /api/initialize` and `POST /api/initialize` share the route, each with its method. None of
/// these requests opens a store: the secure state of the tests is never initialized.
#[tokio::test]
async fn initialize_is_served_on_the_control_port() {
    let port = start_control_port().await;

    let response = get(port, "/api/initialize").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"False");

    let key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    // A key which is not base64 of 32 bytes, a body which is not the JSON, a field nobody reads.
    for body in [
        r#"{"key": "short"}"#.to_string(),
        "not json".to_string(),
        format!(r#"{{"key": "{key}", "network_keys": []}}"#),
        format!(r#"{{"key": "{key}", "network_key": "{key}"}}"#),
    ] {
        let response = post(port, "/api/initialize", "", &body).await;
        assert_eq!(response.status, 400, "{body}");
    }

    // The keys do not travel through a proxy.
    let response = post(
        port,
        "/api/initialize",
        "X-Forwarded-For: 203.0.113.7\r\n",
        &format!(r#"{{"key": "{key}"}}"#),
    )
    .await;
    assert_eq!(response.status, 403);

    let response = get(port, "/api/initialize").await;
    assert_eq!(response.body, b"False");
}

/// The private keys over the encrypted API: only an encrypted call is taken, and it is answered
/// encrypted with its key. The store of the tests is never opened: an installation is refused
/// for that.
#[tokio::test]
async fn the_private_keys_are_read_and_installed_encrypted_only() {
    use my_http_server::{EncryptedBody, HttpBodyEncryptionKey};
    use rust_extensions::date_time::DateTimeAsMicroseconds;

    crate::secure::use_test_network_key();
    let key = HttpBodyEncryptionKey::from_bytes(&crate::secure::TEST_NETWORK_KEY).unwrap();

    let port = start_control_port().await;
    let headers = "Content-Encoding: aes128gcm\r\n";

    let encrypted = |json: &str| {
        EncryptedBody {
            salt: EncryptedBody::random_salt(),
            timestamp: DateTimeAsMicroseconds::now(),
            body: json.as_bytes().to_vec(),
        }
        .encrypt(&key)
    };

    // The list, answered encrypted with the key of the call.
    let response = post_bytes(port, "/api/private-keys/v1/list", headers, &encrypted("{}")).await;
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    let answer = key.decrypt(&response.body).unwrap();
    let answer: serde_json::Value = serde_json::from_slice(&answer).unwrap();
    assert!(answer["private_keys"].is_array(), "{answer}");

    // An installation reaches the store, which is not open in the tests.
    let call = serde_json::json!({
        "id": "london",
        "private_key": crate::secure::openssh_private_key_for_tests(3, None),
    })
    .to_string();
    let response = post_bytes(port, "/api/private-keys/v1/set", headers, &encrypted(&call)).await;
    assert_eq!(
        response.status,
        503,
        "{}",
        String::from_utf8_lossy(&response.body)
    );

    // A key which is not one is refused for what it is - and not repeated.
    let call = r#"{"id": "london", "private_key": "not a key"}"#;
    let response = post_bytes(port, "/api/private-keys/v1/set", headers, &encrypted(call)).await;
    assert_eq!(response.status, 400);
    assert!(!String::from_utf8_lossy(&response.body).contains("not a key"));

    // In plain text: refused, whatever it says.
    for route in [
        "/api/private-keys/v1/set",
        "/api/private-keys/v1/delete",
        "/api/private-keys/v1/list",
    ] {
        let response = post(port, route, "", r#"{"id": "london"}"#).await;
        assert_eq!(response.status, 415, "{route}");
    }
}

/// One POST with a JSON body on a connection of its own; the response is read up to the close.
/// `headers` are more header lines, each ended with `\r\n`.
async fn post(port: u16, target: &str, headers: &str, body: &str) -> Response {
    post_bytes(port, target, headers, body.as_bytes()).await
}

async fn post_bytes(port: u16, target: &str, headers: &str, body: &[u8]) -> Response {
    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

    post_on(stream, &format!("localhost:{port}"), target, headers, body).await
}

/// `POST target` with `body` on `stream`; the response is read up to the close.
async fn post_on(
    mut stream: impl AsyncReadExt + AsyncWriteExt + Unpin,
    host: &str,
    target: &str,
    headers: &str,
    body: &[u8],
) -> Response {
    let head = format!(
        "POST {target} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{headers}Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();

    let mut received = Vec::new();
    tokio::time::timeout(TIMEOUT, stream.read_to_end(&mut received))
        .await
        .expect("no response in time")
        .unwrap();

    let head_end = find(&received, b"\r\n\r\n").expect("no response head") + 4;
    let head = String::from_utf8(received[..head_end].to_vec()).unwrap();

    Response {
        status: head[9..12].parse().unwrap(),
        body: received[head_end..].to_vec(),
    }
}

/// The control port server on a free port.
async fn start_control_port() -> u16 {
    let port = free_port().await;

    super::start_at(SocketAddr::from(([127, 0, 0, 1], port)));

    wait_until_served(port).await;

    port
}

/// The server binds its port in a task of its own.
async fn wait_until_served(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    panic!("the control port did not start");
}

/// The address the host would send from to the internet - the one of its network card. A udp
/// socket picks it on `connect`, and sends nothing. `None`: the host has no such route.
async fn an_address_which_is_not_loopback() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket.connect("192.0.2.1:9").await.ok()?;
    let ip = socket.local_addr().ok()?.ip();

    if ip.is_loopback() || ip.is_unspecified() {
        return None;
    }

    Some(ip)
}

struct Response {
    status: u16,
    body: Vec<u8>,
}

/// `global_settings.control_unix_socket`: the control port serves the same on the socket. A file
/// a run before left at the path is not in the way.
#[cfg(unix)]
#[tokio::test]
async fn the_control_port_is_served_on_a_unix_socket() {
    let path = std::env::temp_dir().join(format!("mrp-control-{}.sock", std::process::id()));
    let path = path.to_str().unwrap().to_string();
    std::fs::write(&path, b"left by a run before").unwrap();

    super::start_at_unix_socket(&path);

    let response = get_over_unix_socket(&path, "/api/initialize").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"False");

    let index_html = std::fs::read("wwwroot/index.html").unwrap();
    let response = get_over_unix_socket(&path, "/").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, index_html);

    // The keys are taken over the socket: a key which is no key is refused for what it is, not for
    // where it came from.
    let stream = tokio::net::UnixStream::connect(&path).await.unwrap();
    let response = post_on(
        stream,
        "localhost",
        "/api/initialize",
        "",
        br#"{"key": "short"}"#,
    )
    .await;
    assert_eq!(response.status, 400);

    // Not through a proxy, on the socket either: a request the proxy relays to it carries the
    // `X-Forwarded-For` the proxy writes.
    let stream = tokio::net::UnixStream::connect(&path).await.unwrap();
    let response = post_on(
        stream,
        "localhost",
        "/api/initialize",
        "X-Forwarded-For: 203.0.113.7\r\n",
        br#"{"key": "short"}"#,
    )
    .await;
    assert_eq!(response.status, 403);

    let _ = std::fs::remove_file(&path);
}

/// The control port decrypts a request encrypted with a network key (my-http-server, before the
/// action runs) and refuses a replayed one. The action sees the JSON alone: here `/api/initialize`
/// refuses the key in it for what it is.
#[tokio::test]
async fn an_encrypted_request_is_decrypted_and_a_replay_is_refused() {
    use my_http_server::{EncryptedBody, HttpBodyEncryptionKey};
    use rust_extensions::date_time::DateTimeAsMicroseconds;

    crate::secure::use_test_network_key();
    let key = HttpBodyEncryptionKey::from_bytes(&crate::secure::TEST_NETWORK_KEY).unwrap();

    let port = start_control_port().await;

    let encrypted = |timestamp: DateTimeAsMicroseconds| {
        EncryptedBody {
            salt: EncryptedBody::random_salt(),
            timestamp,
            body: br#"{"key": "short"}"#.to_vec(),
        }
        .encrypt(&key)
    };

    let body = encrypted(DateTimeAsMicroseconds::now());
    let headers = "Content-Encoding: aes128gcm\r\n";

    let response = post_bytes(port, "/api/initialize", headers, &body).await;
    assert_eq!(
        response.status,
        400,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    assert!(
        String::from_utf8_lossy(&response.body).contains("key is not base64"),
        "{}",
        String::from_utf8_lossy(&response.body)
    );

    // The same bytes once more: a replay.
    let response = post_bytes(port, "/api/initialize", headers, &body).await;
    assert_eq!(
        response.status,
        403,
        "{}",
        String::from_utf8_lossy(&response.body)
    );

    // A sender whose clock is a minute behind.
    let late = DateTimeAsMicroseconds::now().sub(Duration::from_secs(60));
    let response = post_bytes(port, "/api/initialize", headers, &encrypted(late)).await;
    assert_eq!(
        response.status,
        403,
        "{}",
        String::from_utf8_lossy(&response.body)
    );

    // Encrypted with a key the proxy does not have.
    let foreign = HttpBodyEncryptionKey::from_bytes(&[0xa5; 32]).unwrap();
    let body = EncryptedBody {
        salt: EncryptedBody::random_salt(),
        timestamp: DateTimeAsMicroseconds::now(),
        body: br#"{"key": "short"}"#.to_vec(),
    }
    .encrypt(&foreign);
    let response = post_bytes(port, "/api/initialize", headers, &body).await;
    assert_eq!(
        response.status,
        400,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
}

/// One request on a connection of its own to the unix socket at `path`, once it is served.
#[cfg(unix)]
async fn get_over_unix_socket(path: &str, target: &str) -> Response {
    for _ in 0..100 {
        if let Ok(stream) = tokio::net::UnixStream::connect(path).await {
            return get_on(stream, "localhost", target).await;
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    panic!("the control port is not served on the unix socket {path}");
}

/// One request on a connection of its own; the response is read up to the close.
async fn get(port: u16, target: &str) -> Response {
    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

    get_on(stream, &format!("localhost:{port}"), target).await
}

/// `GET target` on `stream`; the response is read up to the close.
async fn get_on(
    mut stream: impl AsyncReadExt + AsyncWriteExt + Unpin,
    host: &str,
    target: &str,
) -> Response {
    let request = format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut received = Vec::new();
    tokio::time::timeout(TIMEOUT, stream.read_to_end(&mut received))
        .await
        .expect("no response in time")
        .unwrap();

    let head_end = find(&received, b"\r\n\r\n").unwrap_or_else(|| {
        panic!(
            "no response head to {target}: {:?}",
            String::from_utf8_lossy(&received)
        )
    }) + 4;

    let head = String::from_utf8(received[..head_end].to_vec()).unwrap();

    // The body is everything up to the close only when it is not chunked.
    assert!(
        !head.to_ascii_lowercase().contains("transfer-encoding"),
        "{head}"
    );

    // `HTTP/1.1 200 OK`
    let status = head[9..12].parse().unwrap();

    Response {
        status,
        body: received[head_end..].to_vec(),
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find(haystack, needle).is_some()
}

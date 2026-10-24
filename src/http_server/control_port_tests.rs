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
    net::{TcpListener, TcpStream, UdpSocket},
};

use crate::settings::GlobalSettings;

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

/// `http_control_ip: 127.0.0.1` - the control port is served on the loopback address, and on no
/// other address of the host.
#[tokio::test]
async fn the_control_port_listens_on_the_http_control_ip() {
    let port = free_port().await;

    let settings: GlobalSettings = serde_yaml::from_str(&format!(
        "http_control_port: {port}\nhttp_control_ip: 127.0.0.1"
    ))
    .unwrap();

    let addr = super::control_port_addr(
        settings.get_http_control_ip().unwrap(),
        settings.http_control_port,
    );
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

/// Without `http_control_ip` the control port listens on every address, as it always did.
#[test]
fn the_control_port_listens_on_every_address_by_default() {
    let settings: GlobalSettings = serde_yaml::from_str("http_control_port: 9000").unwrap();

    assert_eq!(
        super::control_port_addr(
            settings.get_http_control_ip().unwrap(),
            settings.http_control_port
        ),
        SocketAddr::from(([0, 0, 0, 0], 9000))
    );

    assert_eq!(
        super::control_port_addr(None, None),
        SocketAddr::from(([0, 0, 0, 0], 8000))
    );
}

/// The control port server on a free port.
async fn start_control_port() -> u16 {
    let port = free_port().await;

    super::start_at(SocketAddr::from(([127, 0, 0, 1], port)));

    wait_until_served(port).await;

    port
}

async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
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

/// One request on a connection of its own; the response is read up to the close.
async fn get(port: u16, target: &str) -> Response {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

    let request =
        format!("GET {target} HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n");
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

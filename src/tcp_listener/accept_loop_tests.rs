//! The accept loop of a tcp port (`start_listen_tcp_server`): what it does with a connection
//! before any endpoint sees it, and that it takes the next connection while an earlier one is
//! still being set up.

use std::{net::SocketAddr, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
};

use crate::{
    configurations::EndpointPort, settings::SettingsModel, settings_compiled::SettingsCompiled,
};

/// Every connection the loop takes - whichever endpoint then serves it - writes without
/// waiting for the client to acknowledge the write before.
#[tokio::test]
async fn an_accepted_connection_sends_without_delay() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

    let _client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();

    let (accepted, _) = super::listen_tcp_server::accept_connection(&listener)
        .await
        .unwrap();

    assert!(accepted.nodelay().unwrap());
}

/// A `type: tcp` endpoint connects to its remote before it forwards a byte, for up to
/// `remote_connect_timeout`. A remote which does not answer must hold up only the connection
/// waiting for it: the next connection on the same port is served at once.
///
/// The first connection is taken while the endpoint points at a remote which never answers;
/// the endpoint is then pointed at an echo server, and the second connection must echo while
/// the first is still waiting for its remote.
#[tokio::test]
async fn a_remote_which_does_not_answer_holds_up_no_other_connection() {
    let silent_remote = SilentRemote::start().await;
    let echo_remote = start_echo_remote().await;

    let port = free_port().await;
    apply_tcp_endpoint(port, silent_remote.addr).await;
    super::start_listen_tcp_server(SocketAddr::from(([127, 0, 0, 1], port)));

    let mut waiting = connect_to_port(port).await;

    // Long enough for the first connection to look its endpoint up and start connecting to the
    // silent remote. Were it slower than this it would find the echo remote below, and the
    // check at the end would say so.
    tokio::time::sleep(Duration::from_millis(300)).await;

    apply_tcp_endpoint(port, echo_remote).await;

    let mut served = connect_to_port(port).await;
    served.write_all(b"ping").await.unwrap();

    let mut echo = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(1), served.read_exact(&mut echo))
        .await
        .expect("the second connection waited for the first one's remote")
        .unwrap();
    assert_eq!(&echo, b"ping");

    // The first connection really was still waiting for the silent remote: had it reached the
    // echo remote, this would come back.
    waiting.write_all(b"ping").await.unwrap();
    let mut buffer = [0u8; 4];
    let read = tokio::time::timeout(Duration::from_millis(300), waiting.read(&mut buffer)).await;
    assert!(
        read.is_err(),
        "the first connection was not waiting for its remote: {read:?}"
    );
}

/// How long a connect has to stay unanswered to count as one which waits.
const SILENT_PROBE: Duration = Duration::from_millis(300);

/// An address a connect to neither succeeds nor fails at - it waits, as a connect to a host
/// which is down does.
struct SilentRemote {
    addr: SocketAddr,
    /// The listener of a full backlog, and the connections filling it.
    _full_backlog: Option<(TcpListener, Vec<TcpStream>)>,
}

impl SilentRemote {
    /// Which address is silent depends on the platform, so each is probed: a listener with a
    /// full backlog on the loopback (Linux drops the SYNs it has no room for, macOS resets
    /// them); 127.0.0.2 (macOS has only 127.0.0.1 on the loopback and drops the rest of
    /// 127/8, Linux refuses it); 192.0.2.1, TEST-NET-1, which is routed nowhere (needs a
    /// network route).
    async fn start() -> Self {
        if let Some(remote) = Self::full_backlog().await {
            return remote;
        }

        for addr in ["127.0.0.2:9", "192.0.2.1:9"] {
            let addr: SocketAddr = addr.parse().unwrap();

            if tokio::time::timeout(SILENT_PROBE, TcpStream::connect(addr))
                .await
                .is_err()
            {
                return Self {
                    addr,
                    _full_backlog: None,
                };
            }
        }

        panic!("no address here leaves a connect waiting: the test can not make a silent remote");
    }

    async fn full_backlog() -> Option<Self> {
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let listener = socket.listen(1).unwrap();
        let addr = listener.local_addr().unwrap();

        // Nothing is ever accepted: connections are made until one is left waiting. How many
        // fit before that depends on the kernel.
        let mut backlog = Vec::new();

        for _ in 0..64 {
            match tokio::time::timeout(SILENT_PROBE, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => backlog.push(stream),
                Ok(Err(_)) => return None,
                Err(_) => {
                    return Some(Self {
                        addr,
                        _full_backlog: Some((listener, backlog)),
                    })
                }
            }
        }

        None
    }
}

/// Sends back whatever it gets, on every connection.
async fn start_echo_remote() -> SocketAddr {
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

/// Publishes a `type: tcp` endpoint on `port` to `remote` into the live configuration - where
/// the accept loop looks the port up for every connection - the way a settings reload does.
async fn apply_tcp_endpoint(port: u16, remote: SocketAddr) {
    let yaml = format!(
        "hosts:\n  localhost:{port}:\n    endpoint:\n      type: tcp\n    locations:\n    - proxy_pass_to: '{remote}'\n"
    );

    let model: SettingsModel = my_settings_reader::serde_yaml::from_str(&yaml).unwrap();

    let settings = SettingsCompiled {
        hosts: model.hosts,
        ..Default::default()
    };

    for (host_id, host_settings) in &settings.hosts {
        let endpoint_host = settings.get_endpoint_host_string(host_id).unwrap();

        let EndpointPort::Tcp(port) = endpoint_host.get_port() else {
            panic!("{host_id} is not a tcp port");
        };

        let configuration = crate::scripts::compile_host_configuration(
            &settings,
            endpoint_host,
            host_settings,
            None,
        )
        .await
        .unwrap();

        crate::app::APP_CTX
            .current_configuration
            .write(move |config| {
                config.listen_tcp_endpoints.insert(port, configuration);
            })
            .await;
    }
}

/// The accept loop is started by a spawned task: the port may not be listening yet.
async fn connect_to_port(port: u16) -> TcpStream {
    for _ in 0..100 {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
            return stream;
        }

        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    panic!("nothing listens on port {port}");
}

async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

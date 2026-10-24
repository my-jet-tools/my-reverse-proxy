use std::net::IpAddr;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use rust_extensions::date_time::DateTimeAsMicroseconds;
use tokio::net::{TcpListener, TcpStream};

use super::super::*;
use super::*;
use crate::tcp_gateway::handshake::{perform_server_handshake, HANDSHAKE_TIMEOUT};
use crate::types::WhiteListedIpList;

/// Pause after a failed `accept`. It fails when the process is out of file descriptors, and
/// retrying at once would only spin on the same error.
const ACCEPT_ERROR_DELAY: Duration = Duration::from_millis(100);

pub struct TcpGatewayServer {
    inner: Arc<TcpGatewayInner>,
    next_connection_id: AtomicU32,
    /// The accept loop: it owns the listener, which is closed when the loop is aborted.
    listener_task: tokio::task::AbortHandle,
}

impl TcpGatewayServer {
    /// Listens at `listen` by the time it returns. A port which can not be had is the error of
    /// this call - the startup ends on it - and not a panic of the accept loop's task, which
    /// would end the task alone and leave the process running with no gateway listener.
    pub fn new(
        listen: String,
        authorized_keys: Vec<VerifyingKey>,
        allowed_ip: Option<WhiteListedIpList>,
        debug: bool,
    ) -> Result<Self, String> {
        println!("Starting TCP Gateway Server at address: {}", listen);

        let listener = bind(listen.as_str())?;

        println!("GATEWAY bind happened to {}", listen);

        let inner = Arc::new(TcpGatewayInner::new_server(
            "ServerGateway".to_string(),
            listen,
            authorized_keys,
        ));
        println!("GATEWAY spawning {}", inner.gateway_host.as_str(),);

        // Plain tokio::spawn here (not spawn_named): this runs inside
        // `AppContext::new`, which executes within the `APP_CTX` LazyLock
        // initializer. spawn_named touches APP_CTX (prometheus counter), and
        // that re-entrant deref of the still-initializing APP_CTX would prevent
        // the accept loop from ever being scheduled.
        let listener_task =
            tokio::spawn(connection_loop(inner.clone(), listener, allowed_ip, debug))
                .abort_handle();

        Ok(Self {
            inner,
            next_connection_id: AtomicU32::new(0),
            listener_task,
        })
    }

    /// Ids of the connections the server opens carry [`SERVER_CONNECTION_ID_FLAG`], so they
    /// never collide with the ids a client gives the connections it opens.
    pub fn get_next_connection_id(&self) -> u32 {
        let id = self
            .next_connection_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        SERVER_CONNECTION_ID_FLAG | (id & !SERVER_CONNECTION_ID_FLAG)
    }

    pub fn get_gateway_connection(&self, gateway_id: &str) -> Option<Arc<TcpGatewayConnection>> {
        self.inner.get_gateway_connection(gateway_id)
    }

    pub fn get_gateway_connections(&self) -> Vec<Arc<TcpGatewayConnection>> {
        self.inner.get_gateway_connections()
    }

    pub async fn timer_1s(&self) {
        for connection in self.get_gateway_connections() {
            connection.one_second_timer_tick();
        }
    }
}

impl Drop for TcpGatewayServer {
    fn drop(&mut self) {
        println!(
            "Stopping TCP Gateway Server at address: {}",
            self.inner.gateway_host
        );
        self.inner.stop();

        // A server which is gone takes no connection: the port is closed, not left accepting
        // connections nothing will serve.
        self.listener_task.abort();
    }
}

/// `TcpListener::bind` without the `await`: [`TcpGatewayServer::new`] runs inside the `APP_CTX`
/// initializer, which is not async. Nothing here waits - `listen` is a literal address, so
/// nothing is resolved - and the socket is the one tokio's bind makes: on unix std sets
/// `SO_REUSEADDR` (on Windows neither of them does), and the same backlog. Like the
/// `tokio::spawn` next to it, it needs the runtime entered.
fn bind(listen: &str) -> Result<TcpListener, String> {
    std::net::TcpListener::bind(listen)
        .and_then(|listener| {
            // `from_std` takes the socket as it is, and a blocking one would park a runtime
            // thread in `accept`.
            listener.set_nonblocking(true)?;
            TcpListener::from_std(listener)
        })
        .map_err(|err| format!("Gateway server: can not listen at '{listen}': {err}"))
}

async fn connection_loop(
    tcp_gateway: Arc<TcpGatewayInner>,
    listener: TcpListener,
    allowed_ip: Option<WhiteListedIpList>,
    debug: bool,
) {
    while tcp_gateway.is_running() {
        let accept_result = listener.accept().await;

        let (tcp_stream, socket_addr) = match accept_result {
            Ok(value) => value,
            Err(err) => {
                println!(
                    "Failed to accept connection at {} for. Err: {:?}",
                    tcp_gateway.gateway_host.as_str(),
                    err
                );
                tokio::time::sleep(ACCEPT_ERROR_DELAY).await;
                continue;
            }
        };

        if let Some(allowed_ip) = allowed_ip.as_ref() {
            if !is_ip_allowed(allowed_ip, socket_addr.ip()) {
                println!(
                    "Rejected GATEWAY connection from host: {} on {}: the IP is not in allowed_ip",
                    socket_addr,
                    tcp_gateway.get_gateway_id()
                );
                // Dropping the stream closes it.
                continue;
            }
        }

        // Always log accepted inbound connections (not gated by debug) so the
        // operator can confirm the gateway is reachable.
        println!(
            "Accepted GATEWAY connection from host: {} on {}",
            socket_addr,
            tcp_gateway.get_gateway_id()
        );

        let tcp_gateway_clone = tcp_gateway.clone();
        crate::app::spawn_named(
            "tcp_gateway_server_inbound_handshake",
            handle_inbound(tcp_gateway_clone, tcp_stream, debug),
        );
    }
}

/// `allowed_ip` holds IPv4 addresses and ranges; an IPv6 peer passes only as an IPv4-mapped
/// address.
pub fn is_ip_allowed(allowed_ip: &WhiteListedIpList, ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(ip) => ip,
            None => return false,
        },
    };

    allowed_ip.is_whitelisted(&ip)
}

async fn handle_inbound(tcp_gateway: Arc<TcpGatewayInner>, mut stream: TcpStream, debug: bool) {
    // Every frame is written whole: there is nothing for the kernel to wait for.
    let _ = stream.set_nodelay(true);

    let authorized_keys = match tcp_gateway.authorized_keys.as_ref() {
        Some(keys) => keys.clone(),
        None => {
            eprintln!("Gateway server: no authorized_keys configured, dropping inbound");
            return;
        }
    };

    let handshake = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        perform_server_handshake(&mut stream, authorized_keys.as_slice()),
    )
    .await;

    let outcome = match handshake {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(err)) => {
            eprintln!(
                "Gateway server handshake failed at {}: {err}",
                tcp_gateway.gateway_host.as_str()
            );
            return;
        }
        Err(_) => {
            eprintln!(
                "Gateway server handshake at {} timed out after {:?}",
                tcp_gateway.gateway_host.as_str(),
                HANDSHAKE_TIMEOUT
            );
            return;
        }
    };

    if debug {
        println!(
            "Gateway server handshake ok with client '{}' (timestamp_us={}, compress={}: {})",
            outcome.gateway_name,
            outcome.timestamp_us,
            outcome.compression.as_u8(),
            outcome.compression
        );
    }

    let (read, write) = stream.into_split();
    let (sealer, opener) = outcome.session_keys.into_server_ends();

    // Packed with the level the client has asked for: compression is the client's setting, and
    // it is the same in both directions.
    let gateway_connection = TcpGatewayConnection::new(
        tcp_gateway.gateway_host.clone(),
        write.into(),
        sealer,
        outcome.compression,
        true,
    );

    let gateway_connection = Arc::new(gateway_connection);
    let timestamp = DateTimeAsMicroseconds::new(outcome.timestamp_us);
    gateway_connection.set_connection_timestamp(timestamp);
    gateway_connection.set_gateway_id(outcome.gateway_name.as_str());

    let displaced = tcp_gateway
        .register_gateway_connection(outcome.gateway_name.as_str(), gateway_connection.clone());

    // The client reconnected while its previous connection is still around - typically one the
    // client already gave up on, which this side has not noticed yet. Nothing routes to it any
    // more, so it goes, together with whatever was tunnelled through it.
    if let Some(displaced) = displaced {
        println!(
            "Gateway server: client '{}' reconnected - closing its previous connection",
            outcome.gateway_name
        );
        displaced.disconnect_gateway();
    }

    crate::app::spawn_named(
        "tcp_gateway_server_read_loop",
        crate::tcp_gateway::gateway_read_loop(
            tcp_gateway,
            read,
            opener,
            gateway_connection,
            TcpGatewayServerPacketHandler,
            debug,
        ),
    );
}

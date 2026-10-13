use std::{
    sync::{atomic::AtomicU32, Arc},
    time::Duration,
};

use ed25519_dalek::SigningKey;
use rust_extensions::date_time::DateTimeAsMicroseconds;
use tokio::net::TcpStream;

use crate::tcp_gateway::handshake::{perform_client_handshake, HANDSHAKE_TIMEOUT};
use crate::tcp_gateway::session::CompressionLevel;
use crate::tcp_gateway::{client::*, *};

/// Pause between a connection ending and the next connect. A lost connection is noticed at
/// once, so without it two clients misconfigured with the same gateway name - each displacing
/// the other's registration on the server - would reconnect in a tight loop.
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

pub struct TcpGatewayClientParams {
    pub id: String,
    pub remote_endpoint: String,
    pub signing_key: SigningKey,
    /// What the batches of the gateway connection are packed with, in both directions: the
    /// server packs what it sends with the level its client asks for in its handshake.
    pub compression: CompressionLevel,
    pub allow_incoming_forward_connections: bool,
    pub connect_timeout: Duration,
    pub debug: bool,
    pub sync_ssl_certificates: Vec<String>,
}

pub struct TcpGatewayClient {
    inner: Arc<TcpGatewayInner>,
    next_connection_id: AtomicU32,
}

impl TcpGatewayClient {
    pub fn new(params: TcpGatewayClientParams) -> Self {
        let TcpGatewayClientParams {
            id,
            remote_endpoint,
            signing_key,
            compression,
            allow_incoming_forward_connections,
            connect_timeout,
            debug,
            sync_ssl_certificates,
        } = params;

        let inner = Arc::new(TcpGatewayInner::new_client(
            id,
            remote_endpoint,
            signing_key,
            allow_incoming_forward_connections,
            sync_ssl_certificates,
            compression,
        ));
        let result = Self {
            inner: inner.clone(),
            next_connection_id: AtomicU32::new(0),
        };

        // Plain tokio::spawn here (not spawn_named): this runs inside
        // `AppContext::new`, which executes within the `APP_CTX` LazyLock
        // initializer. spawn_named touches APP_CTX (prometheus counter), and
        // that re-entrant deref of the still-initializing APP_CTX would prevent
        // the reconnect loop from ever being scheduled.
        tokio::spawn(connection_loop(inner.clone(), connect_timeout, debug));

        result
    }

    /// Ids of the connections a client opens never carry [`SERVER_CONNECTION_ID_FLAG`] - that
    /// bit marks the ones the server opens over the same gateway connection.
    pub fn get_next_connection_id(&self) -> u32 {
        let id = self
            .next_connection_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        id & !SERVER_CONNECTION_ID_FLAG
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

    pub fn get_sync_ssl_certificates(&self) -> &[String] {
        self.inner.sync_ssl_certificates.as_slice()
    }
}

impl Drop for TcpGatewayClient {
    fn drop(&mut self) {
        self.inner.stop();
    }
}

async fn connection_loop(inner: Arc<TcpGatewayInner>, connect_timeout: Duration, debug: bool) {
    while inner.is_running() {
        println!(
            "Gateway:[{}] Connecting to remote gateway with host '{}' and with timeout: {:?}",
            inner.get_gateway_id(),
            inner.gateway_host.as_str(),
            connect_timeout
        );
        let connect_feature = TcpStream::connect(inner.gateway_host.as_str());

        let connect_result = tokio::time::timeout(connect_timeout, connect_feature).await;

        if connect_result.is_err() {
            println!(
                "Gateway:[{}] Can not connect to Gateway Server with host '{}'. Timeout: {:?}",
                inner.get_gateway_id(),
                inner.gateway_host.as_str(),
                connect_timeout
            );
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }

        let mut tcp_stream = match connect_result.unwrap() {
            Ok(tcp_stream) => {
                // Every frame is written whole: there is nothing for the kernel to wait for.
                let _ = tcp_stream.set_nodelay(true);
                tcp_stream
            }
            Err(err) => {
                println!(
                    "Gateway[{}]. Can not connect. Err: {:?}",
                    inner.get_gateway_id(),
                    err
                );
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        let signing_key = inner
            .signing_key
            .as_ref()
            .expect("Gateway client missing signing_key")
            .as_ref()
            .clone();

        let handshake = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            perform_client_handshake(
                &mut tcp_stream,
                &signing_key,
                inner.gateway_id.as_str(),
                inner.compression,
            ),
        )
        .await;

        let session_keys = match handshake {
            Ok(Ok(key)) => key,
            Ok(Err(err)) => {
                eprintln!(
                    "Gateway:[{}] handshake to '{}' failed: {err}",
                    inner.get_gateway_id(),
                    inner.gateway_host.as_str(),
                );
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
            Err(_) => {
                eprintln!(
                    "Gateway:[{}] handshake to '{}' timed out after {:?}",
                    inner.get_gateway_id(),
                    inner.gateway_host.as_str(),
                    HANDSHAKE_TIMEOUT
                );
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        let (read, write) = tcp_stream.into_split();
        let (sealer, opener) = session_keys.into_client_ends();

        let gateway_connection = TcpGatewayConnection::new(
            inner.gateway_host.clone(),
            write.into(),
            sealer,
            inner.compression,
            inner.allow_incoming_forward_connections,
        );

        let gateway_connection = Arc::new(gateway_connection);
        let now = DateTimeAsMicroseconds::now();
        gateway_connection.set_connection_timestamp(now);
        gateway_connection.set_gateway_id(inner.gateway_id.as_str());

        // The previous connection is closed before the loop comes round again, so nothing
        // should be displaced - closing it anyway keeps one live connection per client.
        if let Some(displaced) =
            inner.register_gateway_connection(&inner.gateway_id, gateway_connection.clone())
        {
            displaced.disconnect_gateway();
        }

        crate::app::spawn_named(
            "tcp_gateway_client_read_loop",
            crate::tcp_gateway::gateway_read_loop(
                inner.clone(),
                read,
                opener,
                gateway_connection.clone(),
                TcpGatewayClientPacketHandler::new(debug),
                debug,
            ),
        );

        let sync_ids: Vec<&str> = inner
            .sync_ssl_certificates
            .iter()
            .map(|s| s.as_str())
            .collect();
        if !sync_ids.is_empty() {
            let request = TcpGatewayContract::SyncSslCertificatesRequest { cert_ids: sync_ids };
            gateway_connection.send_payload(&request);
        }

        super::gateway_ping_loop(gateway_connection.clone(), debug).await;

        // Whatever ended the ping loop, this connection is finished. Closing it ends its read
        // loop too - even one blocked on a socket whose peer vanished - which unregisters the
        // connection and closes everything tunnelled through it.
        gateway_connection.disconnect_gateway();
        inner.remove_gateway_connection(&inner.gateway_id, &gateway_connection);

        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

use std::{
    collections::HashMap,
    sync::{atomic::AtomicI64, Arc},
    time::Duration,
};

use arc_swap::ArcSwap;
use parking_lot::Mutex;

use rust_extensions::{
    date_time::{AtomicDateTimeAsMicroseconds, DateTimeAsMicroseconds},
    remote_endpoint::RemoteEndpointOwned,
    AtomicDuration, AtomicStopWatch, SliceOrVec,
};
use tokio_util::sync::CancellationToken;

use crate::{
    metrics::PerSecondAccumulator,
    network_stream::MyOwnedWriteHalf,
    tcp_gateway::session::{CompressionLevel, FrameSealer},
};

use super::{super::forwarded_connection::*, super::*};

/// The peer gives up on its own connect after the timeout carried by `CONNECT`; this covers
/// the round trip on top of it before the connect is considered unanswered.
pub const CONNECT_ACK_MARGIN: Duration = Duration::from_secs(5);

/// How long a file request waits for the peer's answer. The serving side gives up on a response
/// it could not send within the same time - nobody is waiting for it any more.
pub const FILE_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// File responses one gateway connection prepares at a time. A response holds its whole file in
/// memory, so on a slow link the rest of the requests wait for a slot holding nothing but a path.
const MAX_FILE_RESPONSES_IN_FLIGHT: usize = 4;

pub struct TcpGatewayConnection {
    gateway_id: ArcSwap<String>,
    pub addr: Arc<String>,
    inner: Arc<TcpConnectionInner>,
    last_incoming_payload_time: AtomicDateTimeAsMicroseconds,
    forward_connections: Mutex<HashMap<u32, Arc<TcpGatewayForwardConnection>>>,
    forward_proxy_handlers: Arc<ForwardProxyHandlers>,
    allow_incoming_forward_connection: bool,
    pub ping_stop_watch: AtomicStopWatch,
    pub last_ping_duration: AtomicDuration,
    pub file_requests: FileRequests,
    pub file_response_slots: tokio::sync::Semaphore,
    pub metrics: Mutex<GatewayConnectionMetrics>,
    /// Bytes off the wire and bytes onto it - the frames as they travel, sealed and packed -
    /// since the last tick of the metrics timer.
    pub in_per_second: PerSecondAccumulator,
    pub out_per_second: Arc<PerSecondAccumulator>,
    connection_timestamp: AtomicI64,
    pub created_at: DateTimeAsMicroseconds,
    compression: CompressionLevel,
}

impl TcpGatewayConnection {
    /// `sealer` seals what this side sends. `compression`: what the batches this side sends
    /// are packed with - the level the client has asked for in its handshake, on both ends.
    pub fn new(
        addr: Arc<String>,
        write_half: MyOwnedWriteHalf,
        sealer: FrameSealer,
        compression: CompressionLevel,
        allow_incoming_forward_connection: bool,
    ) -> Self {
        let out_per_second = Arc::new(PerSecondAccumulator::new());
        let inner = TcpConnectionInner::new_gateway_peer(
            write_half,
            sealer,
            compression,
            out_per_second.clone(),
        );
        Self {
            gateway_id: ArcSwap::from_pointee(String::new()),
            addr,
            inner,
            forward_connections: Mutex::default(),
            forward_proxy_handlers: Arc::new(Mutex::default()),
            last_incoming_payload_time: AtomicDateTimeAsMicroseconds::now(),
            ping_stop_watch: AtomicStopWatch::new(),
            last_ping_duration: AtomicDuration::from_micros(0),
            file_requests: FileRequests::new(),
            file_response_slots: tokio::sync::Semaphore::new(MAX_FILE_RESPONSES_IN_FLIGHT),
            allow_incoming_forward_connection,
            metrics: Mutex::default(),
            in_per_second: PerSecondAccumulator::new(),
            out_per_second,
            connection_timestamp: AtomicI64::new(0),
            created_at: DateTimeAsMicroseconds::now(),
            compression,
        }
    }

    /// What the batches this side sends are packed with.
    pub fn compression(&self) -> CompressionLevel {
        self.compression
    }

    pub fn set_connection_timestamp(&self, value: DateTimeAsMicroseconds) {
        self.connection_timestamp.store(
            value.unix_microseconds,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    pub fn get_connection_timestamp(&self) -> DateTimeAsMicroseconds {
        let result = self
            .connection_timestamp
            .load(std::sync::atomic::Ordering::Relaxed);

        DateTimeAsMicroseconds::new(result)
    }

    pub fn has_handshake(&self) -> bool {
        let result = self
            .connection_timestamp
            .load(std::sync::atomic::Ordering::Relaxed);

        result > 0
    }

    pub fn one_second_timer_tick(&self) {
        let in_per_second = self.in_per_second.get_per_second();
        let out_per_second = self.out_per_second.get_per_second();

        let mut write_access = self.metrics.lock();
        write_access.in_per_second.add(in_per_second);
        write_access.out_per_second.add(out_per_second);
    }

    pub fn set_gateway_id(&self, id: &str) {
        self.gateway_id.store(Arc::new(id.to_string()));
    }

    pub fn get_gateway_id(&self) -> Arc<String> {
        self.gateway_id.load_full()
    }

    /// Registers a forward connection. Returns `false` when the gateway connection is already
    /// down - the caller closes the connection then: the teardown which drains this registry
    /// may have run while the connection was being established, and would never see it.
    pub fn add_forward_connection(
        &self,
        connection_id: u32,
        connection: Arc<TcpGatewayForwardConnection>,
    ) -> bool {
        {
            let mut write_access = self.forward_connections.lock();
            write_access.insert(connection_id, connection);
        }

        if !self.is_gateway_connected() {
            self.remove_forward_connection(connection_id);
            return false;
        }

        true
    }

    pub fn get_forward_connection(
        &self,
        connection_id: u32,
    ) -> Option<Arc<TcpGatewayForwardConnection>> {
        let write_access = self.forward_connections.lock();
        write_access.get(&connection_id).cloned()
    }

    pub fn has_forward_connection(&self, connection_id: u32) -> bool {
        let read_access = self.forward_connections.lock();
        read_access.contains_key(&connection_id)
    }

    pub fn get_forward_connections_amount(&self) -> usize {
        let write_access = self.forward_connections.lock();
        write_access.len()
    }

    /// Active forward connections grouped by their remote target (route).
    pub fn get_forward_connections_by_route(&self) -> HashMap<String, usize> {
        let mut result = HashMap::new();
        let access = self.forward_connections.lock();
        for connection in access.values() {
            let route = connection.get_remote_endpoint();
            *result.entry(route.as_str().to_string()).or_insert(0) += 1;
        }
        result
    }

    pub fn remove_forward_connection(
        &self,
        connection_id: u32,
    ) -> Option<Arc<TcpGatewayForwardConnection>> {
        let mut write_access = self.forward_connections.lock();
        write_access.remove(&connection_id)
    }

    /// Unregisters forward connection `connection_id` and queues `close` for the peer under the
    /// same lock - if the connection was registered, or anyway with `send_force`. A frame for the
    /// connection handled meanwhile either still finds it, or finds it gone with the close already
    /// queued: its "not found" reply can not overtake the close, which would turn a clean close
    /// into an error on the peer.
    pub fn remove_forward_connection_and_send(
        &self,
        connection_id: u32,
        close: &TcpGatewayContract,
        send_force: bool,
    ) -> Option<Arc<TcpGatewayForwardConnection>> {
        let mut write_access = self.forward_connections.lock();
        let removed = write_access.remove(&connection_id);

        if send_force || removed.is_some() {
            self.send_payload(close);
        }

        removed
    }

    pub async fn connect_to_forward_proxy_connection(
        &self,
        remote_endpoint: Arc<RemoteEndpointOwned>,
        timeout: Duration,
        connection_id: u32,
    ) -> Result<TcpGatewayProxyForwardStream, String> {
        self.check_handshake(&remote_endpoint)?;

        let gateway_id = self.get_gateway_id();

        println!(
            "Connecting to {}->{} with timeout {:?} and id {}",
            gateway_id,
            remote_endpoint.as_str(),
            timeout,
            connection_id
        );

        let remote_host_port = remote_endpoint.get_host_port();

        let (handler, stream, acknowledgement) = TcpGatewayProxyForwardConnectionHandler::new(
            connection_id,
            self.inner.clone(),
            Arc::new(remote_host_port.as_str().to_string()),
            Arc::downgrade(&self.forward_proxy_handlers),
        );

        self.forward_proxy_handlers
            .lock()
            .insert(connection_id, handler);

        // From here on, every failure just drops `stream`: that takes the handler out of the
        // registry and tells the peer to close whatever it has connected by then.
        let connect_contract = TcpGatewayContract::Connect {
            connection_id,
            timeout,
            remote_host: remote_host_port.as_str(),
            receive_window: FLOW_CONTROL_WINDOW as u32,
        };

        if !self.send_payload(&connect_contract) {
            return Err(format!(
                "Connection to endpoint {} is lost",
                remote_host_port.as_str()
            ));
        }

        let wait_for = timeout + CONNECT_ACK_MARGIN;

        match tokio::time::timeout(wait_for, acknowledgement).await {
            Ok(Ok(Ok(()))) => {
                // The acceptor's window came ahead of CONNECT_OK. Under the protocol floor a
                // chunk might never fit, and the writer would stall without a word.
                if !initial_credit_is_enough(stream.send_credit_available()) {
                    return Err(format!(
                        "Cannot connect to {}. Flow control: window out of range",
                        remote_host_port.as_str()
                    ));
                }

                Ok(stream)
            }
            Ok(Ok(Err(err))) => Err(err),
            Ok(Err(_)) => Err(format!(
                "Cannot connect to {}. Gateway connection is lost",
                remote_host_port.as_str()
            )),
            Err(_) => Err(format!(
                "Cannot connect to {}. The gateway did not answer within {:?}",
                remote_host_port.as_str(),
                wait_for
            )),
        }
    }

    fn check_handshake(&self, remote_endpoint: &RemoteEndpointOwned) -> Result<(), String> {
        if self.has_handshake() {
            return Ok(());
        }

        println!("No Handshake");
        Err(format!(
            "Failed establishing connection to {}. Reason: Tcp gateway connection created at {} did not do handshake yet",
            remote_endpoint.as_str(),
            self.created_at.to_rfc3339()
        ))
    }

    pub fn notify_forward_proxy_connection_accepted(&self, connection_id: u32) {
        {
            let mut write_access = self.forward_proxy_handlers.lock();

            if let Some(connection) = write_access.get_mut(&connection_id) {
                connection.set_connected();
                return;
            }
        }

        // Nobody waits for this connection any more - the connect timed out or the stream was
        // dropped. Without telling the peer, its upstream connection would stay open.
        self.send_payload(&TcpGatewayContract::ConnectionError {
            connection_id,
            error: "Connection is not awaited any more",
        });
    }

    pub async fn request_file(&self, path: &str) -> Result<Vec<u8>, FileRequestError> {
        if !self.has_handshake() || !self.is_gateway_connected() {
            return Err(FileRequestError::GatewayDisconnected);
        }

        let (task_completion, request_id) = self.file_requests.start_request();

        // However this ends - an answer, a timeout, or the caller dropping this future - the
        // request leaves the registry.
        let _pending = PendingFileRequest {
            requests: &self.file_requests,
            request_id,
        };

        let request = TcpGatewayContract::GetFileRequest { path, request_id };
        if !self.send_payload(&request) {
            return Err(FileRequestError::GatewayDisconnected);
        }

        match tokio::time::timeout(FILE_REQUEST_TIMEOUT, task_completion.get_result()).await {
            Ok(result) => result,
            Err(_) => Err(FileRequestError::Timeout),
        }
    }

    pub async fn notify_file_response(
        &self,
        request_id: u32,
        status: GetFileStatus,
        content: SliceOrVec<'_, u8>,
    ) {
        match status {
            GetFileStatus::Ok => {
                self.file_requests
                    .set_content(request_id, content.into_vec());
            }
            GetFileStatus::Error => {
                self.file_requests
                    .set_error(request_id, FileRequestError::FileNotFound);
            }
        }
    }

    /// Closes the gateway connection together with everything that travels over it.
    pub fn disconnect_gateway(&self) {
        self.inner.disconnect();
        self.close_all_tunnels();
    }

    /// Cancelled once the gateway connection is disconnected - from this side, or because its
    /// writer failed.
    pub fn disconnected_token(&self) -> CancellationToken {
        self.inner.disconnected_token()
    }

    pub fn is_gateway_connected(&self) -> bool {
        self.inner.is_connected()
    }

    #[cfg(test)]
    pub fn write_budget_for_tests(&self) -> Option<Arc<tokio::sync::Semaphore>> {
        self.inner.write_budget()
    }

    pub fn is_incoming_forward_connection_allowed(&self) -> bool {
        self.allow_incoming_forward_connection
    }

    /// Sends upstream bytes of a forward connection to the peer as one frame - first waiting for
    /// the peer's credit, then for room in the write budget.
    /// Returns `false` once the connection is closed or the gateway connection is gone.
    ///
    /// Always one frame: the read loop re-sends the same chunk after its select drops a send for a
    /// failed write, and a send split into several frames would duplicate the part queued.
    pub async fn send_backward_payload(&self, connection_id: u32, payload: &[u8]) -> bool {
        debug_assert!(payload.len() <= MAX_PAYLOAD_CHUNK);

        let Some(forward_connection) = self.get_forward_connection(connection_id) else {
            return false;
        };

        // The connection's credit first, the shared budget second: a connection waiting for its
        // peer's reader holds no budget. The window closes once the connection is unregistered.
        let credit = match forward_connection
            .send_window()
            .acquire_many(payload.len() as u32)
            .await
        {
            Ok(permit) => permit,
            Err(_) => return false,
        };

        let payload = TcpGatewayContract::BackwardPayload {
            connection_id,
            payload: payload.into(),
        };

        let sent = self.send_payload_with_backpressure(&payload).await;

        // Spent once queued. A future dropped before - the read loop's select, the drain
        // deadline - gives the credit back.
        credit.forget();

        sent
    }

    /// The window of a connection the peer opened: what the raw writer hands to the target is
    /// credited back through this gateway connection.
    pub(crate) fn new_receive_window(&self, connection_id: u32) -> Arc<ReceiveWindow> {
        Arc::new(ReceiveWindow::new(connection_id, self.inner.clone()))
    }

    /// The peer's credit for a connection: one this side opened, or one the peer opened - the
    /// ends allocate ids apart. Credit for an id closed meanwhile is dropped without an answer:
    /// credit crossing a close is normal.
    pub fn incoming_window_update(&self, connection_id: u32, credit: u32) {
        if credit == 0 {
            return;
        }

        // Cloned out: no registry lock is held while a writer is woken.
        let initiated = self
            .forward_proxy_handlers
            .lock()
            .get(&connection_id)
            .map(|handler| handler.send_window());

        match initiated {
            Some(window) => add_credit(&window, credit),
            None => {
                if let Some(forward_connection) = self.get_forward_connection(connection_id) {
                    forward_connection.add_send_credit(credit);
                }
            }
        }
    }

    /// One tunnelled connection whose peer sent past the window it was given. The gateway
    /// connection and its other connections go on. Never waits: the read loop calls it.
    pub fn close_on_flow_control_violation(&self, connection_id: u32, reason: &'static str) {
        println!(
            "Gateway:[{}]. Connection {connection_id}: {reason}",
            self.get_gateway_id()
        );

        // Reset on both ends: an initiator's reader gets what is buffered and then an error, an
        // acceptor's target connection is reset.
        let end = ConnectionEnd::Reset(reason);
        self.end_tunnelled_connection(connection_id, end);
        self.send_payload(&end.to_contract(connection_id));
    }

    /// What the acceptor side holds for the target of `connection_id`, not yet written.
    #[cfg(test)]
    pub fn forward_buffered_for_tests(&self, connection_id: u32) -> Option<usize> {
        self.get_forward_connection(connection_id)
            .map(|forward_connection| forward_connection.buffered_for_tests())
    }

    pub fn incoming_payload_for_proxy_connection(&self, connection_id: u32, payload: &[u8]) {
        let receive_buffer = {
            let proxy_connection_access = self.forward_proxy_handlers.lock();

            let Some(proxy_connection) = proxy_connection_access.get(&connection_id) else {
                drop(proxy_connection_access);

                let gateway_id = self.get_gateway_id();
                println!(
                    "Gateway:[{}]. Proxy connection with id {} not found",
                    gateway_id, connection_id
                );

                // Closed on this side already - make sure the peer closes its end too.
                self.send_payload(&TcpGatewayContract::ConnectionError {
                    connection_id,
                    error: "Connection is not found",
                });
                return;
            };

            match &proxy_connection.status {
                TcpGatewayProxyForwardedConnectionStatus::AcknowledgingConnection => {
                    let gateway_id = self.get_gateway_id();
                    println!("Gateway:[{}] Can not accept payload with size: {} to connection {}. Connection is not acknowledged yet", gateway_id.as_str(), payload.len(), connection_id);
                    return;
                }
                TcpGatewayProxyForwardedConnectionStatus::Connected => {
                    proxy_connection.get_receive_buffer()
                }
                TcpGatewayProxyForwardedConnectionStatus::Disconnected(err) => {
                    let gateway_id = self.get_gateway_id();
                    println!("Gateway:[{}] Can not accept payload with size: {} to connection {}. Connection is disconnected with err: {}", gateway_id.as_str(), payload.len(), connection_id, err.as_str());
                    return;
                }
            }
        };

        if !receive_buffer.extend_from_slice(payload) {
            self.close_on_flow_control_violation(connection_id, "Flow control: window exceeded");
        }
    }

    /// Queues `[u8 TYPE][PAYLOAD]` as an inner frame - one no contract of this side makes.
    #[cfg(test)]
    pub fn send_raw_frame_for_tests(&self, inner_frame: &[u8]) -> bool {
        let mut frame = (inner_frame.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(inner_frame);
        self.inner.send_payload(frame)
    }

    /// Queues a control frame. Never waits, so the read loop may use it.
    pub fn send_payload<'d>(&self, payload: &TcpGatewayContract<'d>) -> bool {
        self.inner.send_payload(payload.to_plain_frame())
    }

    /// Queues a data frame once there is room for it in the write budget - see
    /// [`TcpConnectionInner::send_payload_with_backpressure`].
    pub async fn send_payload_with_backpressure<'d>(
        &self,
        payload: &TcpGatewayContract<'d>,
    ) -> bool {
        self.inner
            .send_payload_with_backpressure(payload.to_plain_frame())
            .await
    }

    pub fn set_last_incoming_payload_time(&self, time: DateTimeAsMicroseconds) {
        self.last_incoming_payload_time.update(time);
    }

    pub fn get_last_incoming_payload_time(&self) -> DateTimeAsMicroseconds {
        self.last_incoming_payload_time.as_date_time()
    }

    pub fn get_forward_proxy_connections_amount(&self) -> usize {
        let write_access = self.forward_proxy_handlers.lock();
        write_access.len()
    }

    /// Active proxy (outbound) connections grouped by their remote target (route).
    pub fn get_forward_proxy_connections_by_route(&self) -> HashMap<String, usize> {
        let mut result = HashMap::new();
        let access = self.forward_proxy_handlers.lock();
        for handler in access.values() {
            let route = handler.get_remote_host();
            *result.entry(route.as_str().to_string()).or_insert(0) += 1;
        }
        result
    }

    /// Ends `connection_id` on this side as `end` says - the peer ended it, or broke the protocol
    /// on it. A proxy stream's reader gets the buffered payloads first, then EOF after a clean
    /// close or an error after a reset. A forward connection hands the target what the peer sent
    /// and shuts its side down after a clean close; after a reset it drops that and resets the
    /// target connection. A connect still waiting for its answer fails.
    pub fn end_tunnelled_connection(&self, connection_id: u32, end: ConnectionEnd) {
        let handler = self.forward_proxy_handlers.lock().remove(&connection_id);

        if let Some(mut handler) = handler {
            match end {
                ConnectionEnd::Closed => {
                    handler.set_connection_error("The connection is closed by the peer".into());
                    handler.close();
                }
                ConnectionEnd::Reset(reason) => {
                    handler.set_connection_error(reason.into());
                    handler.abort();
                }
            }
        }

        // The id may name a forward connection on this side instead (the peer is the proxy
        // initiator). The two ends number their connections apart, so it is one or the other.
        if let Some(forward_connection) = self.remove_forward_connection(connection_id) {
            match end {
                ConnectionEnd::Closed => forward_connection.disconnect(),
                ConnectionEnd::Reset(_) => forward_connection.reset(),
            }
        }
    }

    /// Closes every connection tunnelled through this gateway connection and fails the file
    /// requests waiting on it: nothing travels over a gateway connection which is down, and
    /// left open they would only make their users wait for a timeout. The streams are cut short:
    /// readers get an error, and target connections are reset.
    fn close_all_tunnels(&self) {
        let proxy_handlers: Vec<_> = self
            .forward_proxy_handlers
            .lock()
            .drain()
            .map(|(_, handler)| handler)
            .collect();

        // Dropping a handler also fails a connect still waiting for the peer's answer.
        for handler in proxy_handlers {
            handler.abort();
        }

        let forward_connections: Vec<_> = self
            .forward_connections
            .lock()
            .drain()
            .map(|(_, connection)| connection)
            .collect();

        for connection in forward_connections {
            connection.reset();
        }

        self.file_requests.fail_all();
    }
}

impl Drop for TcpGatewayConnection {
    fn drop(&mut self) {
        self.close_all_tunnels();
    }
}

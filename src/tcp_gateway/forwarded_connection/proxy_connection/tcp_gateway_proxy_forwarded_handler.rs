use std::collections::HashMap;
use std::sync::{Arc, Weak};

use rust_extensions::StrOrString;
use tokio::sync::{oneshot, Semaphore};

use crate::tcp_gateway::{ReceiveWindow, TcpConnectionInner};

use super::{ProxyReceiveBuffer, ProxyReceiveClose, TcpGatewayProxyForwardStream};

/// Registry of active proxy (outbound) connections, keyed by connection id.
/// Lives on `TcpGatewayConnection`; streams hold a `Weak` to it so a
/// locally-closed stream can drop its own entry without an Arc cycle.
pub type ForwardProxyHandlers =
    parking_lot::Mutex<HashMap<u32, TcpGatewayProxyForwardConnectionHandler>>;

/// The peer's answer to a `CONNECT`: `Ok` on `CONNECT_OK`, the error it reported otherwise.
pub type ConnectAcknowledgement = oneshot::Receiver<Result<(), String>>;

#[derive(Clone)]
pub enum TcpGatewayProxyForwardedConnectionStatus {
    AcknowledgingConnection,
    Connected,
    Disconnected(StrOrString<'static>),
}

impl TcpGatewayProxyForwardedConnectionStatus {
    pub fn is_awaiting_connection(&self) -> bool {
        match self {
            Self::AcknowledgingConnection => true,
            Self::Connected | Self::Disconnected(_) => false,
        }
    }
}

pub struct TcpGatewayProxyForwardConnectionHandler {
    pub status: TcpGatewayProxyForwardedConnectionStatus,
    receive_buffer: Arc<ProxyReceiveBuffer>,
    remote_host: Arc<String>,
    acknowledge: Option<oneshot::Sender<Result<(), String>>>,
}

impl TcpGatewayProxyForwardConnectionHandler {
    /// Creates the handler together with the stream it feeds and the acknowledgement which
    /// resolves once the peer accepts or refuses the connection. Dropping the handler without
    /// an answer (the gateway connection went down) resolves it with a receive error.
    ///
    /// Both windows of the connection live in the receive buffer, which carries the connection's
    /// close state.
    pub fn new(
        connection_id: u32,
        connection_inner: Arc<TcpConnectionInner>,
        remote_host: Arc<String>,
        handlers_map: Weak<ForwardProxyHandlers>,
    ) -> (Self, TcpGatewayProxyForwardStream, ConnectAcknowledgement) {
        let receive_window = ReceiveWindow::new(connection_id, connection_inner.clone());
        let receive_buffer = Arc::new(ProxyReceiveBuffer::new(receive_window));
        let (acknowledge, acknowledgement) = oneshot::channel();

        let stream = TcpGatewayProxyForwardStream::new(
            connection_id,
            connection_inner,
            receive_buffer.clone(),
            handlers_map,
        );

        let handler = Self {
            status: TcpGatewayProxyForwardedConnectionStatus::AcknowledgingConnection,
            receive_buffer,
            remote_host,
            acknowledge: Some(acknowledge),
        };

        (handler, stream, acknowledgement)
    }

    pub fn get_remote_host(&self) -> Arc<String> {
        self.remote_host.clone()
    }

    pub fn get_receive_buffer(&self) -> Arc<ProxyReceiveBuffer> {
        self.receive_buffer.clone()
    }

    /// The peer's credit for what the stream sends.
    pub fn send_window(&self) -> Arc<Semaphore> {
        self.receive_buffer.send_window().clone()
    }

    pub fn set_connected(&mut self) {
        if self.status.is_awaiting_connection() {
            self.status = TcpGatewayProxyForwardedConnectionStatus::Connected;
            if let Some(acknowledge) = self.acknowledge.take() {
                let _ = acknowledge.send(Ok(()));
            }
        }
    }

    pub fn set_connection_error(&mut self, error: String) {
        if let TcpGatewayProxyForwardedConnectionStatus::Disconnected(_) = self.status {
            return;
        }

        if let Some(acknowledge) = self.acknowledge.take() {
            let _ = acknowledge.send(Err(error.clone()));
        }

        self.status = TcpGatewayProxyForwardedConnectionStatus::Disconnected(error.into());
    }

    /// The connection is closed: the reader gets what is buffered, then EOF.
    pub fn close(&self) {
        self.receive_buffer.close(ProxyReceiveClose::Closed);
    }

    /// The gateway connection is gone: the reader gets what is buffered, then an error.
    pub fn abort(&self) {
        self.receive_buffer.close(ProxyReceiveClose::Aborted);
    }
}

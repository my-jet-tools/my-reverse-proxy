use std::{
    collections::HashMap,
    sync::{atomic::AtomicBool, Arc},
};

use ed25519_dalek::{SigningKey, VerifyingKey};
use parking_lot::Mutex;

use super::{session::CompressionLevel, TcpGatewayConnection};

pub struct TcpGatewayInner {
    pub gateway_id: Arc<String>,
    pub gateway_host: Arc<String>,
    running: AtomicBool,
    connection: Mutex<HashMap<String, Arc<TcpGatewayConnection>>>,
    pub allow_incoming_forward_connections: bool,
    pub sync_ssl_certificates: Vec<String>,
    pub authorized_keys: Option<Arc<Vec<VerifyingKey>>>,
    pub signing_key: Option<Arc<SigningKey>>,
    /// A client: what the batches of its gateway connection are packed with, in both directions -
    /// it says so in its handshake. A server has no say of its own: it packs with the level each
    /// of its clients asks for.
    pub compression: CompressionLevel,
}

impl TcpGatewayInner {
    pub fn new_server(
        gateway_id: String,
        addr: String,
        authorized_keys: Vec<VerifyingKey>,
    ) -> Self {
        Self {
            gateway_id: Arc::new(gateway_id),
            gateway_host: Arc::new(addr),
            running: AtomicBool::new(true),
            connection: Mutex::default(),
            allow_incoming_forward_connections: true,
            sync_ssl_certificates: Vec::new(),
            authorized_keys: Some(Arc::new(authorized_keys)),
            signing_key: None,
            compression: CompressionLevel::OFF,
        }
    }

    pub fn new_client(
        gateway_id: String,
        addr: String,
        signing_key: SigningKey,
        allow_incoming_forward_connections: bool,
        sync_ssl_certificates: Vec<String>,
        compression: CompressionLevel,
    ) -> Self {
        Self {
            gateway_id: Arc::new(gateway_id),
            gateway_host: Arc::new(addr),
            running: AtomicBool::new(true),
            connection: Mutex::default(),
            allow_incoming_forward_connections,
            sync_ssl_certificates,
            authorized_keys: None,
            signing_key: Some(Arc::new(signing_key)),
            compression,
        }
    }

    /// Registers `connection` under `id` and returns the connection it displaced, which the
    /// caller closes: a peer that reconnected leaves its previous connection behind.
    pub fn register_gateway_connection(
        &self,
        id: &str,
        connection: Arc<TcpGatewayConnection>,
    ) -> Option<Arc<TcpGatewayConnection>> {
        let displaced = {
            let mut connection_access = self.connection.lock();
            connection_access.insert(id.to_string(), connection.clone())
        };

        displaced.filter(|itm| !Arc::ptr_eq(itm, &connection))
    }

    /// Unregisters `connection` - and only it. An old connection is often torn down after a
    /// reconnect has already registered the new one under the same id, and removing by id
    /// alone would leave a live connection that no route can find.
    pub fn remove_gateway_connection(&self, id: &str, connection: &Arc<TcpGatewayConnection>) {
        let mut connection_access = self.connection.lock();

        let is_registered = connection_access
            .get(id)
            .is_some_and(|registered| Arc::ptr_eq(registered, connection));

        if is_registered {
            connection_access.remove(id);
        }
    }

    pub fn get_gateway_connection(&self, id: &str) -> Option<Arc<TcpGatewayConnection>> {
        let connection_access = self.connection.lock();
        connection_access.get(id).cloned()
    }

    pub fn get_gateway_connections(&self) -> Vec<Arc<TcpGatewayConnection>> {
        let connection_access = self.connection.lock();
        connection_access.values().cloned().collect()
    }

    pub fn get_gateway_id(&self) -> &str {
        &self.gateway_id
    }

    pub fn stop(&self) {
        self.running
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::Relaxed)
    }
}

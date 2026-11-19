use std::{collections::HashMap, sync::Arc, time::Duration};

use arc_swap::ArcSwap;

use crate::{
    secure::{PrivateKeys, StoredGatewayConnection},
    tcp_gateway::{
        client::{GatewaySigningKey, TcpGatewayClient, TcpGatewayClientParams},
        session::CompressionLevel,
    },
};

/// The gateway clients: those of `gateway_clients` of the settings, started with the proxy, and
/// those of the connections of the secure store - started at initialize, and whenever a
/// connection is set over the encrypted API or MCP; stopped when it is removed.
pub struct GatewayClients {
    from_settings: HashMap<String, Arc<TcpGatewayClient>>,
    /// The clients of the store, with the connection each was started with.
    from_store: parking_lot::Mutex<HashMap<String, StoreClient>>,
    /// Every client by its id: where the routes look.
    all: ArcSwap<HashMap<String, Arc<TcpGatewayClient>>>,
}

struct StoreClient {
    connection: StoredGatewayConnection,
    client: Arc<TcpGatewayClient>,
}

impl GatewayClients {
    pub fn new(from_settings: HashMap<String, TcpGatewayClient>) -> Self {
        let from_settings: HashMap<String, Arc<TcpGatewayClient>> = from_settings
            .into_iter()
            .map(|(id, client)| (id, Arc::new(client)))
            .collect();

        Self {
            all: ArcSwap::from_pointee(from_settings.clone()),
            from_settings,
            from_store: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// The client of the gateway `id`.
    pub fn get(&self, id: &str) -> Option<Arc<TcpGatewayClient>> {
        self.all.load().get(id).cloned()
    }

    /// Every client, by its id.
    pub fn all(&self) -> Arc<HashMap<String, Arc<TcpGatewayClient>>> {
        self.all.load_full()
    }

    /// Whether the settings have a gateway client `id`: a connection of the store may not take
    /// its id.
    pub fn is_from_settings(&self, id: &str) -> bool {
        self.from_settings.contains_key(id)
    }

    /// Whether the client of the store connection `id` has its gateway connection up now.
    pub fn is_store_client_connected(&self, id: &str) -> bool {
        self.from_store
            .lock()
            .get(id)
            .is_some_and(|itm| !itm.client.get_gateway_connections().is_empty())
    }

    /// Makes the clients of the store what `connections` says. A client whose connection is gone
    /// or changed is shut down - its gateway connection and everything tunnelled through it are
    /// closed - and a client is started for each new or changed connection. One whose
    /// connection is the same goes on as it is.
    pub fn apply_store_connections(
        &self,
        connections: &[StoredGatewayConnection],
        private_keys: &Arc<PrivateKeys>,
    ) {
        let mut from_store = self.from_store.lock();

        let mut running = std::mem::take(&mut *from_store);
        let mut to_shut_down = Vec::new();

        for connection in connections {
            if self.from_settings.contains_key(&connection.id) {
                println!(
                    "Gateway connection '{}' of the secure store is not started: the settings have a gateway client with this id",
                    connection.id
                );
                continue;
            }

            if let Some(itm) = running.remove(&connection.id) {
                if itm.connection == *connection {
                    from_store.insert(connection.id.clone(), itm);
                    continue;
                }

                to_shut_down.push(itm.client);
            }

            match client_params(connection, private_keys) {
                Ok(params) => {
                    println!(
                        "Gateway connection '{}' of the secure store: the client to '{}' is started",
                        connection.id, connection.remote_host
                    );

                    from_store.insert(
                        connection.id.clone(),
                        StoreClient {
                            connection: connection.clone(),
                            client: Arc::new(TcpGatewayClient::new(params)),
                        },
                    );
                }
                Err(err) => println!(
                    "Gateway connection '{}' of the secure store is not started: {err}",
                    connection.id
                ),
            }
        }

        // What is left is gone from the store.
        for (id, itm) in running {
            println!("Gateway connection '{id}' of the secure store: the client is stopped");
            to_shut_down.push(itm.client);
        }

        let mut all = self.from_settings.clone();

        for (id, itm) in from_store.iter() {
            all.insert(id.clone(), itm.client.clone());
        }

        // The routes see the new clients before the old ones are closed.
        self.all.store(Arc::new(all));

        for client in to_shut_down {
            client.shutdown();
        }
    }
}

/// What the client of a connection of the store is started with. Its handshake is signed with
/// the private key of the store the connection names, taken at every connect.
fn client_params(
    connection: &StoredGatewayConnection,
    private_keys: &Arc<PrivateKeys>,
) -> Result<TcpGatewayClientParams, String> {
    let compression = u8::try_from(connection.compress)
        .ok()
        .and_then(|level| CompressionLevel::new(level).ok())
        .ok_or_else(|| format!("compress: there is no level {}", connection.compress))?;

    let connect_timeout = match connection.connect_timeout_ms {
        0 => crate::consts::DEFAULT_GATEWAY_CONNECT_TIMEOUT,
        milliseconds => Duration::from_millis(milliseconds),
    };

    Ok(TcpGatewayClientParams {
        id: connection.id.clone(),
        remote_endpoint: connection.remote_host.clone(),
        signing_key: GatewaySigningKey::Stored {
            id: connection.private_key.clone(),
            keys: private_keys.clone(),
        },
        compression,
        allow_incoming_forward_connections: connection.allow_incoming_forward_connections,
        connect_timeout,
        debug: connection.debug,
        sync_ssl_certificates: connection.sync_ssl_certificates.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A port nothing listens on: the clients of the test try it, and never connect.
    const NOWHERE: &str = "127.0.0.1:9";

    fn connection(id: &str, compress: u32) -> StoredGatewayConnection {
        StoredGatewayConnection {
            id: id.to_string(),
            remote_host: NOWHERE.to_string(),
            private_key: "key".to_string(),
            compress,
            ..Default::default()
        }
    }

    fn from_settings(id: &str) -> HashMap<String, TcpGatewayClient> {
        let client = TcpGatewayClient::new(TcpGatewayClientParams {
            id: id.to_string(),
            remote_endpoint: NOWHERE.to_string(),
            signing_key: GatewaySigningKey::Stored {
                id: "key".to_string(),
                keys: Arc::new(PrivateKeys::new()),
            },
            compression: CompressionLevel::OFF,
            allow_incoming_forward_connections: false,
            connect_timeout: Duration::from_millis(100),
            debug: false,
            sync_ssl_certificates: Vec::new(),
        });

        HashMap::from([(id.to_string(), client)])
    }

    #[tokio::test]
    async fn the_clients_of_the_store_follow_its_connections() {
        let clients = GatewayClients::new(from_settings("settings"));
        let keys = Arc::new(PrivateKeys::new());

        clients.apply_store_connections(&[connection("a", 0), connection("b", 0)], &keys);

        let a = clients.get("a").unwrap();
        let b = clients.get("b").unwrap();
        assert!(clients.get("settings").is_some());
        assert_eq!(clients.all().len(), 3);

        // `a` is the same and goes on; `b` changed and is started again; `c` is new.
        clients.apply_store_connections(
            &[connection("a", 0), connection("b", 1), connection("c", 0)],
            &keys,
        );

        assert!(Arc::ptr_eq(&clients.get("a").unwrap(), &a));
        assert!(a.is_running());

        let b_again = clients.get("b").unwrap();
        assert!(!Arc::ptr_eq(&b_again, &b));
        assert!(!b.is_running());
        assert!(b_again.is_running());
        assert!(clients.get("c").is_some());

        // Gone from the store: stopped, and no route finds it.
        clients.apply_store_connections(&[connection("c", 0)], &keys);

        assert!(clients.get("a").is_none() && clients.get("b").is_none());
        assert!(!a.is_running() && !b_again.is_running());
        assert!(clients.get("c").is_some());
        assert!(clients.get("settings").unwrap().is_running());
        assert!(!clients.is_store_client_connected("c"));
    }

    /// A connection of the store never displaces a client of the settings.
    #[tokio::test]
    async fn the_id_of_a_client_of_the_settings_is_not_taken() {
        let clients = GatewayClients::new(from_settings("london"));
        let settings_client = clients.get("london").unwrap();

        assert!(clients.is_from_settings("london"));

        clients.apply_store_connections(&[connection("london", 0)], &Arc::new(PrivateKeys::new()));

        assert!(Arc::ptr_eq(
            &clients.get("london").unwrap(),
            &settings_client
        ));
        assert!(settings_client.is_running());

        clients.apply_store_connections(&[], &Arc::new(PrivateKeys::new()));
        assert!(clients.get("london").unwrap().is_running());
    }
}

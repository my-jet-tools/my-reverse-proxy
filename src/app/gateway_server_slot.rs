use std::sync::Arc;

use arc_swap::ArcSwapOption;

use crate::{
    secure::{AuthorizedKeys, StoredGatewayServer},
    tcp_gateway::server::{GatewayServerKeys, TcpGatewayServer},
    types::WhiteListedIpList,
};

/// The gateway server of the proxy: the one of `gateway_server` of the settings, started with
/// the proxy, or - when the settings have none - the one of the secure store, started at
/// initialize and whenever it is set over the encrypted API, stopped when it is removed.
pub struct GatewayServerSlot {
    from_settings: Option<Arc<TcpGatewayServer>>,
    /// The server of the store, with what it was started with. Held by a change from its start to
    /// its end, the store written included: changes come one at a time.
    from_store: tokio::sync::Mutex<Option<StoreServer>>,
    /// The server which serves now: where the routes look.
    current: ArcSwapOption<TcpGatewayServer>,
}

struct StoreServer {
    model: StoredGatewayServer,
    server: Arc<TcpGatewayServer>,
}

/// A change of the server of the store, under way: nothing else changes it until it is dropped.
pub struct GatewayServerChange<'s> {
    slot: &'s GatewayServerSlot,
    from_store: tokio::sync::MutexGuard<'s, Option<StoreServer>>,
}

impl GatewayServerSlot {
    pub fn new(from_settings: Option<TcpGatewayServer>) -> Self {
        let from_settings = from_settings.map(Arc::new);

        Self {
            current: ArcSwapOption::new(from_settings.clone()),
            from_settings,
            from_store: tokio::sync::Mutex::new(None),
        }
    }

    /// The gateway server which serves now.
    pub fn get(&self) -> Option<Arc<TcpGatewayServer>> {
        self.current.load_full()
    }

    /// The server of the settings: while there is one, the store's is not started.
    pub fn settings_server(&self) -> Option<&Arc<TcpGatewayServer>> {
        self.from_settings.as_ref()
    }

    /// What the server of the store was started with, when it runs.
    #[cfg(test)]
    pub async fn store_server(&self) -> Option<StoredGatewayServer> {
        self.from_store
            .lock()
            .await
            .as_ref()
            .map(|itm| itm.model.clone())
    }

    /// Starts a change of the server of the store.
    pub async fn change(&self) -> GatewayServerChange<'_> {
        GatewayServerChange {
            slot: self,
            from_store: self.from_store.lock().await,
        }
    }
}

impl GatewayServerChange<'_> {
    /// Runs the server `model` says - none for `None` - in place of the store's one running now.
    /// On another port the new one listens before the one running stops: a port which can not be
    /// had is the error, and the one running goes on as it is, its clients connected. On the same
    /// port the one running lets go of it first, and is started again when the new one can not.
    pub async fn apply(
        &mut self,
        model: Option<&StoredGatewayServer>,
        authorized_keys: &Arc<AuthorizedKeys>,
    ) -> Result<(), String> {
        if let Some(settings_server) = self.slot.from_settings.as_ref() {
            return match model {
                None => Ok(()),
                Some(_) => Err(format!(
                    "The settings have a gateway server at {}: take it out of the settings to run the one of the secure store",
                    settings_server.listen_addr()
                )),
            };
        }

        if self.from_store.as_ref().map(|itm| &itm.model) == model {
            return Ok(());
        }

        let Some(model) = model else {
            if let Some(previous) = self.from_store.take() {
                self.slot.current.store(None);
                previous.server.shutdown().await;
            }

            return Ok(());
        };

        let same_port = self
            .from_store
            .as_ref()
            .is_some_and(|itm| itm.model.port == model.port);

        if !same_port {
            let server = start(model, authorized_keys)?;
            let previous = self.from_store.take();
            self.run(model.clone(), server);

            if let Some(previous) = previous {
                previous.server.shutdown().await;
            }

            return Ok(());
        }

        if let Some(previous) = self.from_store.take() {
            self.slot.current.store(None);
            previous.server.shutdown().await;

            return match start(model, authorized_keys) {
                Ok(server) => {
                    self.run(model.clone(), server);
                    Ok(())
                }
                Err(err) => {
                    match start(&previous.model, authorized_keys) {
                        Ok(server) => self.run(previous.model, server),
                        Err(again) => println!(
                            "Gateway server of the secure store: the one there was does not start again either: {again}"
                        ),
                    }

                    Err(err)
                }
            };
        }

        Ok(())
    }

    fn run(&mut self, model: StoredGatewayServer, server: TcpGatewayServer) {
        let server = Arc::new(server);
        self.slot.current.store(Some(server.clone()));
        *self.from_store = Some(StoreServer { model, server });
    }
}

/// The server of `model`: it lets in the keys the store authorizes - it has no files of keys.
fn start(
    model: &StoredGatewayServer,
    authorized_keys: &Arc<AuthorizedKeys>,
) -> Result<TcpGatewayServer, String> {
    let allowed_ip = if model.allowed_ip.is_empty() {
        None
    } else {
        Some(WhiteListedIpList::new(&model.allowed_ip))
    };

    TcpGatewayServer::new(
        format!("0.0.0.0:{}", model.port),
        GatewayServerKeys::new(Vec::new(), authorized_keys.clone()),
        allowed_ip,
        model.debug,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_ports::free_port;

    fn server_at(port: u16) -> StoredGatewayServer {
        StoredGatewayServer {
            port: port as u32,
            allowed_ip: Vec::new(),
            debug: false,
        }
    }

    async fn listens(port: u16) -> bool {
        tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
    }

    #[tokio::test]
    async fn the_server_of_the_store_is_started_replaced_and_stopped() {
        let slot = GatewayServerSlot::new(None);
        let keys = Arc::new(AuthorizedKeys::new());
        let (first, second) = (free_port().await, free_port().await);

        slot.change()
            .await
            .apply(Some(&server_at(first)), &keys)
            .await
            .unwrap();
        assert!(slot.get().is_some());
        assert!(listens(first).await);

        // The same port with another setting: stopped first, so the port is taken again.
        let debug = StoredGatewayServer {
            debug: true,
            ..server_at(first)
        };
        slot.change()
            .await
            .apply(Some(&debug), &keys)
            .await
            .unwrap();
        assert!(listens(first).await);
        assert_eq!(slot.store_server().await, Some(debug));

        slot.change()
            .await
            .apply(Some(&server_at(second)), &keys)
            .await
            .unwrap();
        assert!(listens(second).await);
        assert!(!listens(first).await);

        slot.change().await.apply(None, &keys).await.unwrap();
        assert!(slot.get().is_none());
        assert!(!listens(second).await);
    }

    /// A port which can not be had is the error, and the server there was goes on.
    #[tokio::test]
    async fn a_server_which_can_not_listen_leaves_the_one_there_was() {
        let slot = GatewayServerSlot::new(None);
        let keys = Arc::new(AuthorizedKeys::new());
        let running = free_port().await;

        let taken = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let taken_port = taken.local_addr().unwrap().port();

        slot.change()
            .await
            .apply(Some(&server_at(running)), &keys)
            .await
            .unwrap();

        let before = slot.get().unwrap();

        let err = slot
            .change()
            .await
            .apply(Some(&server_at(taken_port)), &keys)
            .await
            .unwrap_err();
        assert!(err.contains("can not listen"), "{err}");

        // Not even restarted: its clients stay connected.
        assert!(Arc::ptr_eq(&slot.get().unwrap(), &before));
        assert!(listens(running).await);
        assert_eq!(slot.store_server().await, Some(server_at(running)));
    }

    /// While the settings have a gateway server, the store's is refused.
    #[tokio::test]
    async fn the_server_of_the_settings_is_not_displaced() {
        let port = free_port().await;
        let settings_server = TcpGatewayServer::new(
            format!("127.0.0.1:{port}"),
            Vec::<ed25519_dalek::VerifyingKey>::new(),
            None,
            false,
        )
        .unwrap();

        let slot = GatewayServerSlot::new(Some(settings_server));
        let keys = Arc::new(AuthorizedKeys::new());

        let err = slot
            .change()
            .await
            .apply(Some(&server_at(free_port().await)), &keys)
            .await
            .unwrap_err();
        assert!(err.contains("The settings have a gateway server"), "{err}");

        slot.change().await.apply(None, &keys).await.unwrap();
        assert_eq!(
            slot.get().unwrap().listen_addr(),
            format!("127.0.0.1:{port}")
        );
    }
}

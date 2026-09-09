use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use tokio::sync::RwLock;

use crate::types::ListenHost;

use super::*;

pub struct AppConfiguration {
    inner: RwLock<AppConfigurationInner>,
    /// Bumped on every `write`. A connection snapshots its port configuration
    /// when it is accepted; comparing this against the generation it saw is a
    /// one-atomic-load way to notice a settings reload on a keep-alive / h2
    /// connection without taking the lock per request.
    generation: AtomicU64,
}

impl AppConfiguration {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(AppConfigurationInner::new()),
            generation: AtomicU64::new(0),
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Picks up a reloaded port configuration for a live connection.
    ///
    /// Returns the generation the caller must remember, plus the new
    /// `HttpListenPortConfiguration` when the port's configuration was replaced
    /// since `seen_generation`. `None` when nothing changed for this port —
    /// either no write happened, the write touched other state (ip lists,
    /// error map) so the port still holds the same Arc, or the port is no
    /// longer configured (the listener is being torn down; keep serving the
    /// snapshot until the connection ends).
    pub async fn pick_up_reload(
        &self,
        listen_host: &ListenHost,
        current: &Arc<HttpListenPortConfiguration>,
        seen_generation: u64,
    ) -> (u64, Option<Arc<HttpListenPortConfiguration>>) {
        let generation = self.generation();
        if generation == seen_generation {
            return (generation, None);
        }

        let live = self
            .get(|config| config.get_http_listen_config(listen_host))
            .await;

        let replaced = live.filter(|live| !Arc::ptr_eq(live, current));
        (generation, replaced)
    }

    pub async fn get<TResult>(
        &self,
        func: impl FnOnce(&AppConfigurationInner) -> TResult,
    ) -> TResult {
        let inner = self.inner.read().await;
        func(&inner)
    }

    pub async fn write(&self, func: impl FnOnce(&mut AppConfigurationInner)) {
        let mut inner = self.inner.write().await;
        func(&mut inner);
        // Under the write lock, so a reader that sees the new generation also
        // sees the new maps.
        self.generation.fetch_add(1, Ordering::AcqRel);
    }

    /*
    pub async fn write_with_result<TResult>(
        &self,
        func: impl FnOnce(&mut AppConfigurationInner) -> TResult,
    ) -> TResult {
        let mut inner = self.inner.write().await;
        func(&mut inner)
    }


    pub async fn get_ssl_certified_key(
        &self,
        listen_port: u16,
        server_name: &str,
    ) -> Result<Arc<CertifiedKey>, String> {
        if let Some(port_configuration) = self.http_endpoints.get(&listen_port) {
            let ssl_certificate_id = port_configuration.get_ssl_certificate(server_name);

            if ssl_certificate_id.is_none() {
                return Err(format!(
                    "No matching configuration for server_name {} on port {}.",
                    server_name, listen_port
                ));
            }

            let ssl_certificate_id = ssl_certificate_id.unwrap();

            if ssl_certificate_id.as_str() == SELF_SIGNED_CERT_NAME {
                return Ok(Arc::new(crate::self_signed_cert::generate(
                    server_name.to_string(),
                )?));
            }

            if let Some(key) = self
                .ssl_certificates_cache
                .get_certified_key(&ssl_certificate_id)
                .await
            {
                return Ok(key);
            } else {
                return Err(format!(
                    "Can not find ssl_certified_key for port: {}",
                    listen_port
                ));
            }
        } else {
            Err(format!(
                "Can not find ssl_certified_key for port: {}",
                listen_port
            ))
        }
    }

    pub fn get_http_endpoint_info(
        &self,
        listen_port: u16,
        server_name: &str,
    ) -> Result<Arc<HttpEndpointInfo>, String> {
        if let Some(listen_port_config) = self.http_endpoints.get(&listen_port) {
            for endpoint_info in &listen_port_config.endpoint_info {
                if endpoint_info.is_my_endpoint(server_name) {
                    return Ok(endpoint_info.clone());
                }
            }
        }

        Err(format!("Not port is listening at port: {}", listen_port))
    }
     */
}

#[cfg(test)]
mod pick_up_reload_tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::configurations::{ListenConfiguration, ListenHttpEndpointType};

    fn listen_host() -> ListenHost {
        ListenHost::Tcp("127.0.0.1:443".parse::<SocketAddr>().unwrap())
    }

    /// A port configuration with no endpoints: `pick_up_reload` decides on the
    /// identity of the `Arc`, never on its content.
    fn port_config() -> Arc<HttpListenPortConfiguration> {
        Arc::new(HttpListenPortConfiguration {
            endpoints: vec![],
            listen_endpoint_type: ListenHttpEndpointType::Https2,
            listen_host: listen_host(),
        })
    }

    async fn publish(config: &AppConfiguration, port_config: Arc<HttpListenPortConfiguration>) {
        config
            .write(|inner| {
                inner
                    .listen_tcp_endpoints
                    .insert(443, ListenConfiguration::Http(port_config));
            })
            .await;
    }

    #[tokio::test]
    async fn every_write_bumps_the_generation() {
        let config = AppConfiguration::new();
        let before = config.generation();

        publish(&config, port_config()).await;

        assert_eq!(config.generation(), before + 1);
    }

    #[tokio::test]
    async fn nothing_is_picked_up_while_the_generation_stands_still() {
        let config = AppConfiguration::new();
        let current = port_config();
        publish(&config, current.clone()).await;
        let seen = config.generation();

        let (generation, replaced) = config.pick_up_reload(&listen_host(), &current, seen).await;

        assert_eq!(generation, seen);
        assert!(replaced.is_none());
    }

    #[tokio::test]
    async fn a_write_that_leaves_this_port_alone_does_not_churn_the_connection() {
        let config = AppConfiguration::new();
        let current = port_config();
        publish(&config, current.clone()).await;
        let seen = config.generation();

        // A write to unrelated state — an ip list, the error map — bumps the
        // generation, but this port still holds the very same Arc.
        config
            .write(|inner| {
                inner
                    .error_configurations
                    .insert("some-host".to_string(), "boom".to_string());
            })
            .await;

        let (generation, replaced) = config.pick_up_reload(&listen_host(), &current, seen).await;

        assert!(generation > seen);
        assert!(replaced.is_none());
    }

    #[tokio::test]
    async fn a_replaced_port_configuration_is_handed_over() {
        let config = AppConfiguration::new();
        let current = port_config();
        publish(&config, current.clone()).await;
        let seen = config.generation();

        let reloaded = port_config();
        publish(&config, reloaded.clone()).await;

        let (generation, replaced) = config.pick_up_reload(&listen_host(), &current, seen).await;

        assert!(generation > seen);
        assert!(Arc::ptr_eq(
            &replaced.expect("the reload must be picked up"),
            &reloaded
        ));
    }

    #[tokio::test]
    async fn a_port_that_is_gone_leaves_the_connection_on_its_snapshot() {
        let config = AppConfiguration::new();
        let current = port_config();
        publish(&config, current.clone()).await;
        let seen = config.generation();

        config
            .write(|inner| {
                inner.listen_tcp_endpoints.remove(&443);
            })
            .await;

        let (generation, replaced) = config.pick_up_reload(&listen_host(), &current, seen).await;

        // The generation still advances, so the connection does not re-check on
        // every request for the rest of its life.
        assert!(generation > seen);
        assert!(replaced.is_none());
    }

    #[tokio::test]
    async fn a_raw_tcp_port_is_not_an_http_configuration() {
        let config = AppConfiguration::new();
        let current = port_config();
        publish(&config, current.clone()).await;

        let live = config
            .get(|inner| inner.get_http_listen_config(&listen_host()))
            .await;
        assert!(live.is_some());

        let other_host = ListenHost::Tcp("127.0.0.1:9999".parse::<SocketAddr>().unwrap());
        let live = config
            .get(|inner| inner.get_http_listen_config(&other_host))
            .await;
        assert!(live.is_none());
    }
}

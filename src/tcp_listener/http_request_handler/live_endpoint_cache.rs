use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;

use crate::configurations::HttpListenPortConfiguration;
use crate::http_proxy_pass::HttpProxyPass;

/// Per-connection state shared by the two hyper request handlers (`http.rs` for
/// an `http2` endpoint, `https.rs` for `https2`): the port configuration this
/// connection serves, plus the `HttpProxyPass` built lazily for each request
/// `Host`.
///
/// The two live together because they are invalidated together. A connection is
/// accepted with a snapshot of the port configuration, and an h2 connection
/// (every MCP client keeps one open for hours) would otherwise keep serving that
/// snapshot for its whole life — a `reload_settings` would not reach it, so a
/// changed `auth_header`, upstream or header rule would apply only to clients
/// that happened to reconnect. Reloads are not frequent, so the check is a
/// single atomic load per request and the lock is taken only when the generation
/// actually moved.
pub struct LiveEndpointCache {
    config: ArcSwap<HttpListenPortConfiguration>,
    /// `AppConfiguration::generation` as of the configuration currently stored.
    seen_generation: AtomicU64,
    proxy_passes: Mutex<HashMap<String, Arc<HttpProxyPass>>>,
}

impl LiveEndpointCache {
    pub fn new(listen_port_config: Arc<HttpListenPortConfiguration>) -> Self {
        Self {
            config: ArcSwap::from(listen_port_config),
            seen_generation: AtomicU64::new(crate::app::APP_CTX.current_configuration.generation()),
            proxy_passes: Mutex::new(HashMap::new()),
        }
    }

    /// The port configuration to serve this request with, after picking up a
    /// settings reload if one happened since the last request on this
    /// connection. When the configuration was replaced, the per-`Host`
    /// `HttpProxyPass` cache is dropped so the next lookup rebuilds it from the
    /// new endpoint info (new locations, new `auth_header`).
    ///
    /// Concurrent calls on one connection are harmless: they resolve to the same
    /// live `Arc`, and both clearing the cache and re-inserting a `HttpProxyPass`
    /// are idempotent.
    pub async fn load_current(&self) -> Arc<HttpListenPortConfiguration> {
        let current = self.config.load_full();

        let (generation, replaced) = crate::app::APP_CTX
            .current_configuration
            .pick_up_reload(
                &current.listen_host,
                &current,
                self.seen_generation.load(Ordering::Acquire),
            )
            .await;

        self.seen_generation.store(generation, Ordering::Release);

        let Some(replaced) = replaced else {
            return current;
        };

        // Dropped, NOT disposed: `HttpProxyPass::dispose` empties its `inner`,
        // which would fail an in-flight request of this connection at its
        // response-header step. Letting the Arc die with its last request is
        // what makes the swap invisible.
        self.proxy_passes.lock().unwrap().clear();

        self.config.store(replaced.clone());

        replaced
    }

    pub fn get(&self, host_key: &str) -> Option<Arc<HttpProxyPass>> {
        self.proxy_passes.lock().unwrap().get(host_key).cloned()
    }

    /// Publishes `proxy_pass` for `host_key`, unless another task built one for
    /// the same host meanwhile — then that one is returned, so a connection
    /// keeps a single `HttpProxyPass` per `Host`.
    pub fn insert_or_get_existing(
        &self,
        host_key: String,
        proxy_pass: Arc<HttpProxyPass>,
    ) -> Arc<HttpProxyPass> {
        let mut proxy_passes = self.proxy_passes.lock().unwrap();
        match proxy_passes.get(&host_key) {
            Some(existing) => existing.clone(),
            None => {
                proxy_passes.insert(host_key, proxy_pass.clone());
                proxy_pass
            }
        }
    }

    /// Connection teardown: here disposing IS correct — there is no further
    /// request to break.
    pub async fn dispose(&self) {
        let proxy_passes: Vec<Arc<HttpProxyPass>> = {
            let mut proxy_passes = self.proxy_passes.lock().unwrap();
            proxy_passes.drain().map(|(_, v)| v).collect()
        };

        for proxy_pass in proxy_passes {
            proxy_pass.dispose().await;
        }
    }
}

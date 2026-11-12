use std::{collections::HashMap, sync::Arc};

use parking_lot::Mutex;
use tokio::sync::Notify;

use crate::settings::HostSettings;

/// The hosts last read from `dynamic_hosts.url`, as they were read - before the variables are
/// put into them. A settings reload compiles them next to the hosts of the files, so they are
/// served after it as they were before.
pub struct DynamicHosts {
    inner: Mutex<DynamicHostsInner>,
    refresh_request: Notify,
}

#[derive(Default)]
struct DynamicHostsInner {
    /// The url `hosts` were read from.
    url: Option<String>,
    hosts: Arc<HashMap<String, HostSettings>>,
    /// Why the last read of the url failed - `None` once a read succeeds.
    last_error: Option<String>,
}

impl DynamicHosts {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(DynamicHostsInner::default()),
            refresh_request: Notify::new(),
        }
    }

    /// The hosts read from `url` - `None` if they were read from another url, or not yet.
    pub fn get_hosts(&self, url: &str) -> Option<Arc<HashMap<String, HostSettings>>> {
        let inner = self.inner.lock();

        if inner.url.as_deref() != Some(url) {
            return None;
        }

        Some(inner.hosts.clone())
    }

    pub fn set_hosts(&self, url: String, hosts: Arc<HashMap<String, HostSettings>>) {
        let mut inner = self.inner.lock();
        inner.url = Some(url);
        inner.hosts = hosts;
    }

    /// Whether `hosts` are the ones read from `url` before - written the same way or not.
    pub fn has_same_hosts(&self, url: &str, hosts: &HashMap<String, HostSettings>) -> bool {
        let current = match self.get_hosts(url) {
            Some(current) => current,
            None => return false,
        };

        same_hosts(current.as_ref(), hosts)
    }

    /// The settings have no `dynamic_hosts` any more.
    pub fn clear(&self) {
        *self.inner.lock() = DynamicHostsInner::default();
    }

    /// Remembers why the read of the url failed. `true` if the reason is not the one of the
    /// read before: a url which is down is told about once, not at every read.
    pub fn set_error(&self, err: String) -> bool {
        let mut inner = self.inner.lock();

        if inner.last_error.as_ref() == Some(&err) {
            return false;
        }

        inner.last_error = Some(err);
        true
    }

    /// The url is read. `true` if the read before had failed.
    pub fn clear_error(&self) -> bool {
        self.inner.lock().last_error.take().is_some()
    }

    pub fn get_last_error(&self) -> Option<String> {
        self.inner.lock().last_error.clone()
    }

    /// Has the url read now rather than when its interval is out - after a reload of the
    /// settings, which may name another url.
    pub fn request_refresh(&self) {
        self.refresh_request.notify_one();
    }

    pub async fn wait_for_refresh_request(&self) {
        self.refresh_request.notified().await;
    }
}

/// Two sets of hosts are the same if every host of one is in the other with the same settings.
/// Compared as JSON values: the order the keys are written in is not a difference.
pub fn same_hosts(a: &HashMap<String, HostSettings>, b: &HashMap<String, HostSettings>) -> bool {
    if a.len() != b.len() {
        return false;
    }

    a.iter()
        .all(|(host_id, host_settings)| match b.get(host_id) {
            Some(other) => same_host(host_settings, other),
            None => false,
        })
}

pub fn same_host(a: &HostSettings, b: &HostSettings) -> bool {
    match (serde_json::to_value(a), serde_json::to_value(b)) {
        (Ok(a), Ok(b)) => a == b,
        // Can not be told apart: taken for a change, which is applied.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts(yaml: &str) -> HashMap<String, HostSettings> {
        crate::settings::DynamicHostsModel::parse(yaml.as_bytes())
            .unwrap()
            .unwrap()
            .hosts
    }

    const HOSTS: &str = "hosts:\n  a.example.com:8000:\n    endpoint:\n      type: http\n    locations:\n    - proxy_pass_to: http://127.0.0.1:9000\n      path: /\n";

    #[test]
    fn the_hosts_are_of_the_url_they_were_read_from() {
        let dynamic_hosts = DynamicHosts::new();
        assert!(dynamic_hosts.get_hosts("http://a/hosts").is_none());

        dynamic_hosts.set_hosts("http://a/hosts".to_string(), Arc::new(hosts(HOSTS)));

        assert_eq!(dynamic_hosts.get_hosts("http://a/hosts").unwrap().len(), 1);
        assert!(dynamic_hosts.get_hosts("http://b/hosts").is_none());
        assert!(dynamic_hosts.has_same_hosts("http://a/hosts", &hosts(HOSTS)));
        assert!(!dynamic_hosts.has_same_hosts("http://b/hosts", &hosts(HOSTS)));

        dynamic_hosts.clear();
        assert!(dynamic_hosts.get_hosts("http://a/hosts").is_none());
    }

    #[test]
    fn the_order_the_settings_are_written_in_is_not_a_change() {
        let reordered = "hosts:\n  a.example.com:8000:\n    locations:\n    - path: /\n      proxy_pass_to: http://127.0.0.1:9000\n    endpoint:\n      type: http\n";
        assert!(same_hosts(&hosts(HOSTS), &hosts(reordered)));

        let changed = HOSTS.replace("9000", "9001");
        assert!(!same_hosts(&hosts(HOSTS), &hosts(&changed)));

        let another_host = HOSTS.replace("a.example.com", "b.example.com");
        assert!(!same_hosts(&hosts(HOSTS), &hosts(&another_host)));

        assert!(!same_hosts(&hosts(HOSTS), &HashMap::new()));
    }

    #[test]
    fn a_failure_is_told_about_once() {
        let dynamic_hosts = DynamicHosts::new();

        assert!(dynamic_hosts.set_error("refused".to_string()));
        assert!(!dynamic_hosts.set_error("refused".to_string()));
        assert!(dynamic_hosts.set_error("timeout".to_string()));

        assert!(dynamic_hosts.clear_error());
        assert!(!dynamic_hosts.clear_error());
        assert!(dynamic_hosts.set_error("timeout".to_string()));
    }
}

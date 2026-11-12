use std::{collections::HashMap, sync::Arc};

use parking_lot::Mutex;
use tokio::sync::Notify;

use crate::settings::{DynamicHostsModel, HostSettings};

/// What `dynamic_hosts.url` answered with last, as it was read - before the variables are put
/// into it. A settings reload compiles its hosts next to the hosts of the files, so they are
/// served after it as they were before.
pub struct DynamicHosts {
    inner: Mutex<DynamicHostsInner>,
    refresh_request: Notify,
}

#[derive(Default)]
struct DynamicHostsInner {
    /// The url `answer` was read from.
    url: Option<String>,
    answer: Arc<DynamicHostsModel>,
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

    /// What `url` answered with - `None` if the answer was read from another url, or not yet.
    pub fn get_answer(&self, url: &str) -> Option<Arc<DynamicHostsModel>> {
        let inner = self.inner.lock();

        if inner.url.as_deref() != Some(url) {
            return None;
        }

        Some(inner.answer.clone())
    }

    pub fn set_answer(&self, url: String, answer: Arc<DynamicHostsModel>) {
        let mut inner = self.inner.lock();
        inner.url = Some(url);
        inner.answer = answer;
    }

    /// Whether `answer` is what `url` answered with before - written the same way or not.
    pub fn has_same_answer(&self, url: &str, answer: &DynamicHostsModel) -> bool {
        let current = match self.get_answer(url) {
            Some(current) => current,
            None => return false,
        };

        same_hosts(&current.hosts, &answer.hosts)
            && current.additional_hosts == answer.additional_hosts
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

    fn answer(yaml: &str) -> DynamicHostsModel {
        DynamicHostsModel::parse(yaml.as_bytes()).unwrap().unwrap()
    }

    fn hosts(yaml: &str) -> HashMap<String, HostSettings> {
        answer(yaml).hosts
    }

    const HOSTS: &str = "hosts:\n  a.example.com:8000:\n    endpoint:\n      type: http\n    locations:\n    - proxy_pass_to: http://127.0.0.1:9000\n      path: /\n";

    #[test]
    fn the_answer_is_of_the_url_it_was_read_from() {
        let dynamic_hosts = DynamicHosts::new();
        assert!(dynamic_hosts.get_answer("http://a/hosts").is_none());

        dynamic_hosts.set_answer("http://a/hosts".to_string(), Arc::new(answer(HOSTS)));

        assert_eq!(
            dynamic_hosts
                .get_answer("http://a/hosts")
                .unwrap()
                .hosts
                .len(),
            1
        );
        assert!(dynamic_hosts.get_answer("http://b/hosts").is_none());
        assert!(dynamic_hosts.has_same_answer("http://a/hosts", &answer(HOSTS)));
        assert!(!dynamic_hosts.has_same_answer("http://b/hosts", &answer(HOSTS)));

        dynamic_hosts.clear();
        assert!(dynamic_hosts.get_answer("http://a/hosts").is_none());
    }

    /// The additional hosts of the answer are a part of it: another list is another answer.
    #[test]
    fn other_additional_hosts_are_another_answer() {
        let with_additional_hosts =
            format!("{HOSTS}additional_hosts:\n  a.example.com:8000:\n  - b.example.com\n");

        let dynamic_hosts = DynamicHosts::new();
        dynamic_hosts.set_answer(
            "http://a/hosts".to_string(),
            Arc::new(answer(&with_additional_hosts)),
        );

        assert!(dynamic_hosts.has_same_answer("http://a/hosts", &answer(&with_additional_hosts)));
        assert!(!dynamic_hosts.has_same_answer("http://a/hosts", &answer(HOSTS)));
        assert!(!dynamic_hosts.has_same_answer(
            "http://a/hosts",
            &answer(&with_additional_hosts.replace("b.example.com", "c.example.com"))
        ));
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

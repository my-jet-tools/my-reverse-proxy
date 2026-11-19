use std::{collections::HashMap, sync::Arc};

use parking_lot::Mutex;
use tokio::sync::Notify;

use crate::settings::{HostSettings, RealTimeConfigurationModel};

/// What each url of `real_time_configurations` answered last, as it was read - before the
/// variables are put into it - and why the last read of it failed, if it did. A settings reload
/// puts the answers next to the hosts of the files, so what the urls gave is served after it as
/// it was before.
pub struct RealTimeConfigurations {
    urls: Mutex<HashMap<String, UrlState>>,
    refresh_request: Notify,
}

#[derive(Default)]
struct UrlState {
    /// `None` until the url is read the first time.
    answer: Option<Arc<RealTimeConfigurationModel>>,
    /// Why the last read of the url failed - `None` once a read succeeds.
    last_error: Option<String>,
    /// Reads which failed since the last one which did not.
    failed_reads_in_a_row: u32,
}

impl RealTimeConfigurations {
    pub fn new() -> Self {
        Self {
            urls: Mutex::new(HashMap::new()),
            refresh_request: Notify::new(),
        }
    }

    /// What the urls `urls` answered with, in their order - each one which has answered.
    pub fn get_answers(&self, urls: &[String]) -> Vec<Arc<RealTimeConfigurationModel>> {
        let states = self.urls.lock();

        urls.iter()
            .filter_map(|url| states.get(url)?.answer.clone())
            .collect()
    }

    pub fn set_answer(&self, url: &str, answer: Arc<RealTimeConfigurationModel>) {
        self.urls.lock().entry(url.to_string()).or_default().answer = Some(answer);
    }

    /// Whether `answer` is what `url` answered with before - written the same way or not.
    pub fn has_same_answer(&self, url: &str, answer: &RealTimeConfigurationModel) -> bool {
        let states = self.urls.lock();

        let Some(current) = states.get(url).and_then(|state| state.answer.as_ref()) else {
            return false;
        };

        same_hosts(&current.hosts, &answer.hosts)
            && current.additional_hosts == answer.additional_hosts
            && current.api_keys == answer.api_keys
            && current.ip_white_lists == answer.ip_white_lists
    }

    /// Forgets the urls which are not in `urls` any more: a url put back into the list gives
    /// nothing until it is read again.
    pub fn keep_only(&self, urls: &[String]) {
        self.urls.lock().retain(|url, _| urls.contains(url));
    }

    /// The settings have no `real_time_configurations` any more.
    pub fn clear(&self) {
        self.urls.lock().clear();
    }

    /// Remembers why the read of `url` failed. `true` if the reason is not the one of the read
    /// before: a url which is down is told about once, not at every read.
    pub fn set_error(&self, url: &str, err: String) -> bool {
        let mut states = self.urls.lock();
        let state = states.entry(url.to_string()).or_default();

        if state.last_error.as_ref() == Some(&err) {
            return false;
        }

        state.last_error = Some(err);
        true
    }

    /// `url` is read. `true` if the read before had failed.
    pub fn clear_error(&self, url: &str) -> bool {
        match self.urls.lock().get_mut(url) {
            Some(state) => {
                state.failed_reads_in_a_row = 0;
                state.last_error.take().is_some()
            }
            None => false,
        }
    }

    /// A read of `url` failed. Once [`FAILED_READS_BEFORE_IP_LISTS_ARE_EMPTIED`] have failed in a
    /// row, the ip lists it gave are emptied - they stay declared, and let nobody in - until it
    /// answers again: a whitelist is not served for ever from a source which is gone. Its hosts and
    /// keys stay as they were.
    ///
    /// `true` if the lists were emptied by this read: what is served is to be put together anew.
    ///
    /// [`FAILED_READS_BEFORE_IP_LISTS_ARE_EMPTIED`]: crate::consts::FAILED_READS_BEFORE_IP_LISTS_ARE_EMPTIED
    pub fn note_failed_read(&self, url: &str) -> bool {
        let mut states = self.urls.lock();
        let state = states.entry(url.to_string()).or_default();

        state.failed_reads_in_a_row = state.failed_reads_in_a_row.saturating_add(1);

        if state.failed_reads_in_a_row < crate::consts::FAILED_READS_BEFORE_IP_LISTS_ARE_EMPTIED {
            return false;
        }

        let Some(answer) = state.answer.as_ref() else {
            return false;
        };

        if answer
            .ip_white_lists
            .values()
            .all(|entries| entries.is_empty())
        {
            return false;
        }

        let mut emptied = answer.as_ref().clone();
        for entries in emptied.ip_white_lists.values_mut() {
            entries.clear();
        }

        state.answer = Some(Arc::new(emptied));
        true
    }

    pub fn get_last_error(&self, url: &str) -> Option<String> {
        self.urls.lock().get(url)?.last_error.clone()
    }

    /// Has the urls read now rather than when the interval is out - after a reload of the
    /// settings, which may name other urls.
    pub fn request_refresh(&self) {
        self.refresh_request.notify_one();
    }

    pub async fn wait_for_refresh_request(&self) {
        self.refresh_request.notified().await;
    }
}

#[cfg(test)]
mod failed_reads_tests {
    use super::*;

    fn answer(yaml: &str) -> Arc<RealTimeConfigurationModel> {
        Arc::new(
            RealTimeConfigurationModel::parse(yaml.as_bytes())
                .unwrap()
                .unwrap(),
        )
    }

    const URL: &str = "http://ip-whitelister/api/export";

    /// Four failed reads change nothing; the fifth empties the ip lists - and only them.
    #[test]
    fn the_ip_lists_of_a_url_which_fails_five_times_in_a_row_are_emptied() {
        let urls = RealTimeConfigurations::new();
        urls.set_answer(
            URL,
            answer("ip_white_lists:\n  office:\n  - 10.0.0.0/24\n  vpn:\n  - 10.8.0.1\napi_keys:\n  clients:\n  - key-1\n"),
        );

        for _ in 1..crate::consts::FAILED_READS_BEFORE_IP_LISTS_ARE_EMPTIED {
            assert!(!urls.note_failed_read(URL));
        }

        let before = urls.get_answers(&[URL.to_string()]);
        assert_eq!(before[0].ip_white_lists["office"], ["10.0.0.0/24"]);

        assert!(urls.note_failed_read(URL));

        let after = urls.get_answers(&[URL.to_string()]);
        assert!(after[0].ip_white_lists["office"].is_empty());
        assert!(after[0].ip_white_lists["vpn"].is_empty());
        assert_eq!(after[0].api_keys["clients"], before[0].api_keys["clients"]);

        // Emptied already: nothing more to put together.
        assert!(!urls.note_failed_read(URL));
    }

    /// A read which does not fail starts the count again; the next answer brings the lists back.
    #[test]
    fn a_read_which_does_not_fail_starts_the_count_again() {
        let urls = RealTimeConfigurations::new();
        let lists = answer("ip_white_lists:\n  office:\n  - 10.0.0.5\n");
        urls.set_answer(URL, lists.clone());

        for _ in 1..crate::consts::FAILED_READS_BEFORE_IP_LISTS_ARE_EMPTIED {
            assert!(!urls.note_failed_read(URL));
        }

        urls.clear_error(URL);

        for _ in 1..crate::consts::FAILED_READS_BEFORE_IP_LISTS_ARE_EMPTIED {
            assert!(!urls.note_failed_read(URL));
        }
        assert!(urls.note_failed_read(URL));

        // It answers again: what it gives is not what is kept, and takes its place.
        assert!(!urls.has_same_answer(URL, &lists));
        urls.clear_error(URL);
        urls.set_answer(URL, lists);
        assert_eq!(
            urls.get_answers(&[URL.to_string()])[0].ip_white_lists["office"],
            ["10.0.0.5"]
        );
    }

    /// A url which never answered has nothing to empty.
    #[test]
    fn a_url_which_never_answered_has_no_lists_to_empty() {
        let urls = RealTimeConfigurations::new();

        for _ in 0..10 {
            assert!(!urls.note_failed_read(URL));
        }
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

    fn answer(yaml: &str) -> RealTimeConfigurationModel {
        RealTimeConfigurationModel::parse(yaml.as_bytes())
            .unwrap()
            .unwrap()
    }

    fn hosts(yaml: &str) -> HashMap<String, HostSettings> {
        answer(yaml).hosts
    }

    fn urls(items: &[&str]) -> Vec<String> {
        items.iter().map(|itm| itm.to_string()).collect()
    }

    const HOSTS: &str = "hosts:\n  a.example.com:8000:\n    endpoint:\n      type: http\n    locations:\n    - proxy_pass_to: http://127.0.0.1:9000\n      path: /\n";

    #[test]
    fn each_url_has_its_own_answer() {
        let state = RealTimeConfigurations::new();
        assert!(state.get_answers(&urls(&["http://a/cfg"])).is_empty());

        state.set_answer("http://a/cfg", Arc::new(answer(HOSTS)));

        assert_eq!(
            state.get_answers(&urls(&["http://a/cfg"]))[0].hosts.len(),
            1
        );
        assert!(state.get_answers(&urls(&["http://b/cfg"])).is_empty());
        assert!(state.has_same_answer("http://a/cfg", &answer(HOSTS)));
        assert!(!state.has_same_answer("http://b/cfg", &answer(HOSTS)));

        state.clear();
        assert!(state.get_answers(&urls(&["http://a/cfg"])).is_empty());
    }

    /// The answers come in the order of the urls asked for - which is what decides a host two
    /// urls give - and a url which has not answered is skipped.
    #[test]
    fn the_answers_come_in_the_order_of_the_urls() {
        let state = RealTimeConfigurations::new();
        state.set_answer("http://b/cfg", Arc::new(answer("api_keys:\n  b: []\n")));
        state.set_answer("http://a/cfg", Arc::new(answer("api_keys:\n  a: []\n")));

        let ids = |answers: Vec<Arc<RealTimeConfigurationModel>>| -> Vec<String> {
            answers
                .iter()
                .map(|itm| itm.api_keys.keys().next().unwrap().clone())
                .collect()
        };

        assert_eq!(
            ids(state.get_answers(&urls(&["http://a/cfg", "http://c/cfg", "http://b/cfg"]))),
            ["a", "b"]
        );
        assert_eq!(
            ids(state.get_answers(&urls(&["http://b/cfg", "http://a/cfg"]))),
            ["b", "a"]
        );
    }

    #[test]
    fn a_url_taken_out_of_the_list_is_forgotten() {
        let state = RealTimeConfigurations::new();
        state.set_answer("http://a/cfg", Arc::new(answer(HOSTS)));
        state.set_answer("http://b/cfg", Arc::new(answer(HOSTS)));
        state.set_error("http://b/cfg", "refused".to_string());

        state.keep_only(&urls(&["http://a/cfg"]));

        assert_eq!(
            state
                .get_answers(&urls(&["http://a/cfg", "http://b/cfg"]))
                .len(),
            1
        );
        assert!(state.get_last_error("http://b/cfg").is_none());
    }

    /// The additional hosts and the keys of the answer are a part of it: another list is another
    /// answer.
    #[test]
    fn other_additional_hosts_or_keys_are_another_answer() {
        let with_additional_hosts =
            format!("{HOSTS}additional_hosts:\n  a.example.com:8000:\n  - b.example.com\n");

        let state = RealTimeConfigurations::new();
        state.set_answer("http://a/cfg", Arc::new(answer(&with_additional_hosts)));

        assert!(state.has_same_answer("http://a/cfg", &answer(&with_additional_hosts)));
        assert!(!state.has_same_answer("http://a/cfg", &answer(HOSTS)));
        assert!(!state.has_same_answer(
            "http://a/cfg",
            &answer(&with_additional_hosts.replace("b.example.com", "c.example.com"))
        ));

        let with_keys = format!("{HOSTS}api_keys:\n  clients:\n  - key-1\n");
        state.set_answer("http://a/cfg", Arc::new(answer(&with_keys)));

        assert!(state.has_same_answer("http://a/cfg", &answer(&with_keys)));
        assert!(!state.has_same_answer("http://a/cfg", &answer(HOSTS)));
        assert!(!state.has_same_answer(
            "http://a/cfg",
            &answer(&with_keys.replace("key-1", "key-2"))
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
    fn a_failure_is_told_about_once_per_url() {
        let state = RealTimeConfigurations::new();

        assert!(state.set_error("http://a/cfg", "refused".to_string()));
        assert!(!state.set_error("http://a/cfg", "refused".to_string()));
        assert!(state.set_error("http://b/cfg", "refused".to_string()));
        assert!(state.set_error("http://a/cfg", "timeout".to_string()));

        assert!(state.clear_error("http://a/cfg"));
        assert!(!state.clear_error("http://a/cfg"));
        assert!(state.set_error("http://a/cfg", "timeout".to_string()));
        assert_eq!(
            state.get_last_error("http://b/cfg").as_deref(),
            Some("refused")
        );
    }
}

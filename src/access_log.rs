//! `access_log` of `global_settings`: a line for every request the http/https endpoints answer,
//! in a file - nginx's `access_log`. Off unless the settings name the file.
//!
//! ```text
//! 2026-11-20T19:42:47.504+00:00 203.0.113.7 example.com "GET /api/x HTTP/2.0" 200 1532 23ms
//! ```
//!
//! The time the request came, its client - behind Cloudflare the one of `CF-Connecting-IP` - the
//! host, the request, the status, the bytes of the body sent, and how long the answer took to its
//! last byte. An answer which did not go out whole ends with ` cut`.
//!
//! A request never waits for the file: the lines go through a queue to a task of their own, and
//! when the disk can not keep up, the lines which do not fit are dropped and counted.

use std::{
    io::Write,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

use arc_swap::ArcSwapOption;
use rust_extensions::date_time::DateTimeAsMicroseconds;
use tokio::sync::mpsc;

/// Lines waiting for the file.
const QUEUE_CAPACITY: usize = 16 * 1024;

/// What one write to the file takes at most.
const BATCH_SIZE: usize = 256 * 1024;

/// `access_log`, `access_log_max_size` and `access_log_files`, resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessLogSettings {
    /// The file, `~` expanded.
    pub path: PathBuf,
    /// The file is turned over past this size: it becomes `<file>.1`, `<file>.1` becomes
    /// `<file>.2`, and so on.
    pub max_size: u64,
    /// The turned-over files kept.
    pub files: u32,
}

impl AccessLogSettings {
    /// `None`: `access_log` is not given. Errors on a size which is not one.
    pub fn resolve(
        path: Option<&str>,
        max_size: Option<&str>,
        files: Option<u32>,
    ) -> Result<Option<Self>, String> {
        let Some(path) = path.map(str::trim).filter(|path| !path.is_empty()) else {
            return Ok(None);
        };

        let path = PathBuf::from(crate::settings::expand_home(path)?);

        let max_size = match max_size {
            Some(value) => crate::settings::parse_buffer_size(value.trim())
                .map_err(|err| format!("global_settings.access_log_max_size: {err}"))?,
            None => crate::consts::DEFAULT_ACCESS_LOG_MAX_SIZE,
        };

        if max_size == 0 {
            return Err("global_settings.access_log_max_size: 0 is no size of a file".to_string());
        }

        Ok(Some(Self {
            path,
            max_size: max_size as u64,
            files: files.unwrap_or(crate::consts::DEFAULT_ACCESS_LOG_FILES),
        }))
    }
}

/// The access log of the process.
pub struct AccessLog {
    writer: ArcSwapOption<Writer>,
    dropped: AtomicU64,
}

struct Writer {
    settings: AccessLogSettings,
    lines: mpsc::Sender<String>,
}

impl Default for AccessLog {
    fn default() -> Self {
        Self::new()
    }
}

impl AccessLog {
    pub fn new() -> Self {
        Self {
            writer: ArcSwapOption::empty(),
            dropped: AtomicU64::new(0),
        }
    }

    /// The log the settings ask for: started, moved to another file, or stopped. A writer which
    /// is replaced writes what it has queued and closes its file. Called within the runtime.
    pub fn apply(&self, settings: Option<AccessLogSettings>) {
        let current = self.writer.load();

        if current.as_ref().map(|writer| &writer.settings) == settings.as_ref() {
            return;
        }

        let Some(settings) = settings else {
            self.writer.store(None);
            return;
        };

        let (lines, receiver) = mpsc::channel(QUEUE_CAPACITY);
        crate::app::spawn_named("access_log_writer", run_writer(settings.clone(), receiver));

        self.writer
            .store(Some(Arc::new(Writer { settings, lines })));
    }

    pub fn is_on(&self) -> bool {
        self.writer.load().is_some()
    }

    /// The record of a request which came - `None` while the log is off, so nothing is spent on
    /// it then.
    pub fn record(
        &self,
        client: Option<String>,
        host: &str,
        method: &str,
        target: &str,
        protocol: &str,
    ) -> Option<AccessRecord> {
        self.writer.load().as_ref()?;

        Some(AccessRecord {
            moment: DateTimeAsMicroseconds::now(),
            started: Instant::now(),
            client: client.unwrap_or_else(|| "-".to_string()),
            host: escape(host),
            request: format!("{} {} {}", escape(method), escape(target), escape(protocol)),
        })
    }

    fn write(&self, line: String) {
        if let Some(writer) = self.writer.load().as_ref() {
            if writer.lines.try_send(line).is_err() {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// The lines dropped because the file could not keep up.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// The record of a request of hyper (`http2`, `https2`) - `None` while the log is off. `client`:
/// the peer, until the request tells another one ([`AccessRecord::set_client`]).
pub fn record_of_hyper_request<B>(
    request: &hyper::Request<B>,
    client: Option<String>,
) -> Option<AccessRecord> {
    let log = &crate::app::APP_CTX.access_log;

    if !log.is_on() {
        return None;
    }

    let host = match request.uri().authority() {
        Some(authority) => authority.as_str(),
        None => request
            .headers()
            .get(hyper::header::HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default(),
    };

    let target = request
        .uri()
        .path_and_query()
        .map(|path_and_query| path_and_query.as_str())
        .unwrap_or("/");

    log.record(
        client,
        host_without_port(host),
        request.method().as_str(),
        target,
        &format!("{:?}", request.version()),
    )
}

/// `example.com` of `example.com:8443`, `[::1]` of `[::1]:8443` - the host as the http/1.1
/// pipeline writes it.
fn host_without_port(host: &str) -> &str {
    if host.starts_with('[') {
        return match host.find(']') {
            Some(end) => &host[..=end],
            None => host,
        };
    }

    host.split(':').next().unwrap_or(host)
}

/// A request, as it came: its line is written once its answer is out - [`Self::answered`].
#[derive(Clone)]
pub struct AccessRecord {
    moment: DateTimeAsMicroseconds,
    started: Instant,
    client: String,
    host: String,
    request: String,
}

impl AccessRecord {
    /// The client - once it is known to be another than the peer (Cloudflare).
    pub fn set_client(&mut self, client: Option<String>) {
        self.client = client.unwrap_or_else(|| "-".to_string());
    }

    /// The answer is out - `whole`, or cut: the line goes to the log.
    pub fn answered(self, status: u16, body_bytes: u64, whole: bool) {
        crate::app::APP_CTX
            .access_log
            .write(self.line(status, body_bytes, whole));
    }

    fn line(&self, status: u16, body_bytes: u64, whole: bool) -> String {
        format!(
            "{} {} {} \"{}\" {} {} {}ms{}",
            self.moment.to_rfc3339(),
            self.client,
            self.host,
            self.request,
            status,
            body_bytes,
            self.started.elapsed().as_millis(),
            if whole { "" } else { " cut" }
        )
    }
}

/// A value from a request as it goes into a line: a quote, a backslash and anything not
/// printable written as an escape - a client can not start a line of its own.
fn escape(value: &str) -> String {
    let mut result = String::with_capacity(value.len());

    for c in value.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            c if c.is_control() => result.push_str(&format!("\\x{:02x}", c as u32)),
            c => result.push(c),
        }
    }

    if result.is_empty() {
        result.push('-');
    }

    result
}

async fn run_writer(settings: AccessLogSettings, mut lines: mpsc::Receiver<String>) {
    let mut file = AccessLogFile::new(settings);
    let mut dropped_told = crate::app::APP_CTX.access_log.dropped();

    while let Some(line) = lines.recv().await {
        let mut batch = String::new();

        // A gap in the log is told in the log.
        let dropped = crate::app::APP_CTX.access_log.dropped();
        if dropped > dropped_told {
            batch.push_str(&format!(
                "# {} {} lines were dropped: the file did not keep up\n",
                DateTimeAsMicroseconds::now().to_rfc3339(),
                dropped - dropped_told
            ));
            dropped_told = dropped;
        }

        batch.push_str(&line);
        batch.push('\n');

        while batch.len() < BATCH_SIZE {
            match lines.try_recv() {
                Ok(line) => {
                    batch.push_str(&line);
                    batch.push('\n');
                }
                Err(_) => break,
            }
        }

        file = match tokio::task::spawn_blocking(move || {
            file.write(batch.as_bytes());
            file
        })
        .await
        {
            Ok(file) => file,
            Err(_) => return,
        };
    }
}

/// The file of the log, turned over by size.
struct AccessLogFile {
    settings: AccessLogSettings,
    file: Option<std::fs::File>,
    size: u64,
    /// The error of opening the file is printed once, not for every line.
    open_error_told: bool,
}

impl AccessLogFile {
    fn new(settings: AccessLogSettings) -> Self {
        Self {
            settings,
            file: None,
            size: 0,
            open_error_told: false,
        }
    }

    fn write(&mut self, bytes: &[u8]) {
        if self.file.is_some() && self.size + bytes.len() as u64 > self.settings.max_size {
            self.turn_over();
        }

        if self.file.is_none() {
            self.open();
        }

        let Some(file) = self.file.as_mut() else {
            return;
        };

        if let Err(err) = file.write_all(bytes) {
            println!(
                "access_log: can not write to {}: {err}",
                self.settings.path.display()
            );
            self.file = None;
            return;
        }

        self.size += bytes.len() as u64;
    }

    fn open(&mut self) {
        if let Some(dir) = self.settings.path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }

        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.settings.path)
        {
            Ok(file) => {
                self.size = file.metadata().map(|meta| meta.len()).unwrap_or(0);
                self.file = Some(file);
                self.open_error_told = false;
            }
            Err(err) => {
                if !self.open_error_told {
                    println!(
                        "access_log: can not open {}: {err}",
                        self.settings.path.display()
                    );
                    self.open_error_told = true;
                }
            }
        }
    }

    /// `<file>` becomes `<file>.1`, `<file>.1` becomes `<file>.2` ... and the one past
    /// `access_log_files` is gone.
    fn turn_over(&mut self) {
        self.file = None;

        let path = &self.settings.path;
        let numbered = |n: u32| PathBuf::from(format!("{}.{n}", path.display()));

        if self.settings.files == 0 {
            let _ = std::fs::remove_file(path);
            return;
        }

        let _ = std::fs::remove_file(numbered(self.settings.files));

        for n in (1..self.settings.files).rev() {
            let _ = std::fs::rename(numbered(n), numbered(n + 1));
        }

        let _ = std::fs::rename(path, numbered(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "my-reverse-proxy-access-log-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn a_host_is_written_without_its_port() {
        assert_eq!(host_without_port("example.com:8443"), "example.com");
        assert_eq!(host_without_port("example.com"), "example.com");
        assert_eq!(host_without_port("[::1]:8443"), "[::1]");
    }

    #[test]
    fn a_value_of_a_request_can_not_start_a_line_of_its_own() {
        assert_eq!(escape("/a\"b\\c"), "/a\\\"b\\\\c");
        assert_eq!(escape("/a\nGET /b"), "/a\\x0aGET /b");
        assert_eq!(escape(""), "-");
    }

    #[test]
    fn a_line_tells_the_request_and_its_answer() {
        let record = AccessRecord {
            moment: DateTimeAsMicroseconds::now(),
            started: Instant::now(),
            client: "203.0.113.7".to_string(),
            host: "example.com".to_string(),
            request: "GET /x HTTP/2.0".to_string(),
        };

        let line = record.line(200, 1532, true);
        assert!(
            line.contains(" 203.0.113.7 example.com \"GET /x HTTP/2.0\" 200 1532 "),
            "{line}"
        );
        assert!(line.ends_with("ms"), "{line}");
        assert!(record.line(200, 10, false).ends_with("ms cut"));
    }

    #[test]
    fn the_file_is_turned_over_past_its_size_and_the_oldest_is_gone() {
        let dir = temp_dir("turn-over");
        let path = dir.join("access.log");
        let mut file = AccessLogFile::new(AccessLogSettings {
            path: path.clone(),
            max_size: 10,
            files: 2,
        });

        for line in ["aaaaaaaa\n", "bbbbbbbb\n", "cccccccc\n", "dddddddd\n"] {
            file.write(line.as_bytes());
        }

        let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap_or_default();
        assert_eq!(read("access.log"), "dddddddd\n");
        assert_eq!(read("access.log.1"), "cccccccc\n");
        assert_eq!(read("access.log.2"), "bbbbbbbb\n");
        assert!(!dir.join("access.log.3").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn settings_need_a_file_and_a_size() {
        assert_eq!(AccessLogSettings::resolve(None, None, None), Ok(None));
        assert_eq!(AccessLogSettings::resolve(Some(" "), None, None), Ok(None));

        let settings = AccessLogSettings::resolve(Some("/var/log/proxy/access.log"), None, None)
            .unwrap()
            .unwrap();
        assert_eq!(settings.max_size, 100 * 1024 * 1024);
        assert_eq!(settings.files, 5);

        assert!(AccessLogSettings::resolve(Some("/x.log"), Some("lots"), None).is_err());
        assert!(AccessLogSettings::resolve(Some("/x.log"), Some("0"), None).is_err());
    }
}

//! The journal of deviations: a line of text for every connection a `cloudflare: true` endpoint
//! closed, for every request closed for a header of `request_with_header_only` (with the name of
//! the header - never a value), and for every Cloudflare server which reached an endpoint without
//! the flag. Each address of a line comes with its country (see [`country_of`]).
//!
//! Whoever is turned away decides how many deviations there are and part of what they say, so the
//! journal is bounded every way: a deviation is put in a queue of [`QUEUE_CAPACITY`] and the
//! connection goes on - past that, deviations are not even queued; one task takes them out at the
//! pace it writes them; a file is of one hour (UTC) and is written up to [`MAX_FILE_SIZE`] - past
//! that, the rest of the hour is not written, it is known to be a lot; a file older than
//! [`KEEP_HOURS`] is deleted. Nothing of it ever holds up a connection or stops the proxy: a
//! journal which can not be written is told of in the console, once an hour.

use std::{
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
};

use tokio::sync::mpsc;

use crate::types::ConnectionIp;

use super::{printable, Deviation};

pub const QUEUE_CAPACITY: usize = 10_000;
pub const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;
pub const KEEP_HOURS: i64 = 24;

const FILE_PREFIX: &str = "cloudflare-deviations-";
const FILE_SUFFIX: &str = ".log";

/// The folder of the journal, in the home directory: `$HOME/logs`.
pub fn journal_dir() -> Result<PathBuf, String> {
    Ok(Path::new(&crate::settings::home_dir()?).join("logs"))
}

pub struct DeviationEvent {
    pub at_unix_micros: i64,
    pub endpoint: String,
    pub peer: Option<IpAddr>,
    /// The client of the request, when it is not the peer: the address of its `CF-Connecting-IP`.
    pub client: Option<IpAddr>,
    /// Of the request or of the TLS handshake - as the client sent it, made printable.
    pub host: Option<String>,
    pub deviation: Deviation,
}

impl DeviationEvent {
    fn to_line(&self) -> String {
        let mut line = format!(
            "{} endpoint={} reason={} peer={} peer_country={}",
            format_utc(self.at_unix_micros),
            self.endpoint,
            self.deviation.as_code(),
            match self.peer {
                Some(peer) => peer.to_string(),
                None => "-".to_string(),
            },
            country_of(self.peer),
        );

        if let Some(client) = self.client {
            line.push_str(" client=");
            line.push_str(&client.to_string());
            line.push_str(" client_country=");
            line.push_str(&country_of(Some(client)));
        }

        if let Some(host) = self.host.as_ref() {
            line.push_str(" host=\"");
            line.push_str(host);
            line.push('"');
        }

        // A name of the settings: a header name, nothing to make printable.
        if let Some(header) = self.deviation.required_header() {
            line.push_str(" header=");
            line.push_str(header);
        }

        if let Deviation::InvalidCfConnectingIp(value) = &self.deviation {
            line.push_str(" value=\"");
            line.push_str(value);
            line.push('"');
        }

        line.push('\n');
        line
    }
}

/// The country of `ip` as the country database of [`crate::ip_db`] gives it: the ISO 3166 code of
/// two letters - `-` for an address it has no country for (a private one, the loopback, one it does
/// not know), and for no address at all (a unix socket). Looked up by the writer of the journal,
/// not by the connection which is turned away.
fn country_of(ip: Option<IpAddr>) -> String {
    // An IPv4 client of a dual-stack listener comes as `::ffff:a.b.c.d`: it is looked up as the
    // IPv4 address it is.
    ip.and_then(|ip| crate::ip_db::lookup_country(ip.to_canonical()))
        // Two upper case letters, as the database is read: printable as they are.
        .map(|code| String::from_utf8_lossy(&code).into_owned())
        .unwrap_or_else(|| "-".to_string())
}

pub struct DeviationJournal {
    sender: mpsc::Sender<DeviationEvent>,
    receiver: parking_lot::Mutex<Option<mpsc::Receiver<DeviationEvent>>>,
}

impl DeviationJournal {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel(QUEUE_CAPACITY);

        Self {
            sender,
            receiver: parking_lot::Mutex::new(Some(receiver)),
        }
    }

    /// Queues a deviation, and returns at once. A full queue takes nothing more until the writer
    /// catches up.
    pub fn write(
        &self,
        endpoint: &str,
        peer: &ConnectionIp,
        client: Option<IpAddr>,
        host: Option<&[u8]>,
        deviation: Deviation,
    ) {
        let _ = self.sender.try_send(DeviationEvent {
            at_unix_micros: rust_extensions::date_time::DateTimeAsMicroseconds::now()
                .unix_microseconds,
            endpoint: endpoint.to_string(),
            peer: peer.get_ip_addr(),
            client,
            host: host.map(printable),
            deviation,
        });
    }

    /// Starts the task which writes the queued deviations to the files of `dir`. Once: a second
    /// call has nothing to take.
    pub fn start(&self, dir: PathBuf) {
        let Some(receiver) = self.receiver.lock().take() else {
            return;
        };

        crate::app::spawn_named("cloudflare_deviation_journal", run_writer(dir, receiver));
    }
}

/// The most deviations taken out of the queue for one write.
const BATCH: usize = 1000;

async fn run_writer(dir: PathBuf, mut receiver: mpsc::Receiver<DeviationEvent>) {
    let mut writer = JournalWriter::new(dir);

    while let Some(event) = receiver.recv().await {
        let mut batch = Vec::with_capacity(16);
        batch.push(event);

        while batch.len() < BATCH {
            match receiver.try_recv() {
                Ok(event) => batch.push(event),
                Err(_) => break,
            }
        }

        // The files are written by the blocking calls of `std::fs`, off the runtime's threads.
        writer = match tokio::task::spawn_blocking(move || {
            writer.write(&batch);
            writer
        })
        .await
        {
            Ok(writer) => writer,
            Err(_) => return,
        };
    }
}

/// The file of the hour being written.
struct HourFile {
    hour: i64,
    file: Option<std::fs::File>,
    size: u64,
    /// The file reached [`MAX_FILE_SIZE`] - and the console was told so.
    full: bool,
    /// The file can not be written - and the console was told so.
    broken: bool,
}

pub struct JournalWriter {
    dir: PathBuf,
    current: Option<HourFile>,
}

impl JournalWriter {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir, current: None }
    }

    pub fn write(&mut self, events: &[DeviationEvent]) {
        let mut pending = Vec::new();

        for event in events {
            let hour = event.at_unix_micros.div_euclid(MICROS_IN_HOUR);

            if self.current.as_ref().map(|current| current.hour) != Some(hour) {
                self.flush(&mut pending);
                self.open_hour(hour);
            }

            let Some(current) = self.current.as_mut() else {
                continue;
            };

            if current.broken || current.full {
                continue;
            }

            let line = event.to_line();

            if current.size + pending.len() as u64 + line.len() as u64 > MAX_FILE_SIZE {
                current.full = true;
                println!(
                    "Cloudflare deviations: {} reached {} MB - the rest of the hour is not written",
                    self.dir.join(file_name(hour)).display(),
                    MAX_FILE_SIZE / 1024 / 1024
                );
                continue;
            }

            pending.extend_from_slice(line.as_bytes());
        }

        self.flush(&mut pending);
    }

    fn flush(&mut self, pending: &mut Vec<u8>) {
        if pending.is_empty() {
            return;
        }

        if let Some(current) = self.current.as_mut() {
            if let Some(file) = current.file.as_mut() {
                match file.write_all(pending) {
                    Ok(()) => current.size += pending.len() as u64,
                    Err(err) => {
                        current.broken = true;
                        current.file = None;
                        println!(
                            "Cloudflare deviations: can not write to {}: {err}. Not written until \
                             the next hour",
                            self.dir.join(file_name(current.hour)).display()
                        );
                    }
                }
            }
        }

        pending.clear();
    }

    /// Starts writing the file of `hour` - after what was written of it before, if the proxy was
    /// restarted within the hour - and deletes the files past [`KEEP_HOURS`].
    fn open_hour(&mut self, hour: i64) {
        self.collect_garbage(hour);

        let path = self.dir.join(file_name(hour));

        let opened = std::fs::create_dir_all(&self.dir).and_then(|_| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
        });

        self.current = Some(match opened {
            Ok(file) => {
                let size = file.metadata().map(|metadata| metadata.len()).unwrap_or(0);
                HourFile {
                    hour,
                    file: Some(file),
                    size,
                    full: false,
                    broken: false,
                }
            }
            Err(err) => {
                println!(
                    "Cloudflare deviations: can not open {}: {err}. Not written until the next hour",
                    path.display()
                );
                HourFile {
                    hour,
                    file: None,
                    size: 0,
                    full: false,
                    broken: true,
                }
            }
        });
    }

    /// Deletes the files of the journal of an hour more than [`KEEP_HOURS`] before `hour`. Only
    /// its own: other logs may live in the folder.
    fn collect_garbage(&self, hour: i64) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(file_hour) = name.to_str().and_then(hour_of_file_name) else {
                continue;
            };

            if file_hour <= hour - KEEP_HOURS {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

const MICROS_IN_HOUR: i64 = 3_600_000_000;

/// `cloudflare-deviations-2026-11-15-14.log` for the hour 14:00-15:00 UTC of 2026-11-15.
fn file_name(hour: i64) -> String {
    let (year, month, day) = civil_from_days(hour.div_euclid(24));
    format!(
        "{FILE_PREFIX}{year:04}-{month:02}-{day:02}-{:02}{FILE_SUFFIX}",
        hour.rem_euclid(24)
    )
}

/// The hour of a file of the journal by its name - `None`: the file is not one of the journal.
fn hour_of_file_name(name: &str) -> Option<i64> {
    let stamp = name.strip_prefix(FILE_PREFIX)?.strip_suffix(FILE_SUFFIX)?;
    let mut parts = stamp.split('-');

    let year: i64 = parts.next()?.parse().ok()?;
    let month: u32 = parts.next()?.parse().ok()?;
    let day: u32 = parts.next()?.parse().ok()?;
    let hour: i64 = parts.next()?.parse().ok()?;

    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    if !(0..24).contains(&hour) {
        return None;
    }

    Some(days_from_civil(year, month, day) * 24 + hour)
}

/// `2026-11-15T14:03:21.512Z`.
fn format_utc(unix_micros: i64) -> String {
    let seconds = unix_micros.div_euclid(1_000_000);
    let millis = unix_micros.rem_euclid(1_000_000) / 1000;
    let (year, month, day) = civil_from_days(seconds.div_euclid(86_400));
    let in_day = seconds.rem_euclid(86_400);

    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        in_day / 3600,
        in_day % 3600 / 60,
        in_day % 60
    )
}

/// The date of a day counted from 1970-01-01 (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

/// The day counted from 1970-01-01 of a date - the inverse of [`civil_from_days`].
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let month = month as i64;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-11-15T14:03:21.512Z
    const AT: i64 = 1_794_751_401_512_000;

    fn event(at_unix_micros: i64, deviation: Deviation) -> DeviationEvent {
        DeviationEvent {
            at_unix_micros,
            endpoint: "api.example.com:443".to_string(),
            peer: Some("203.0.113.7".parse().unwrap()),
            client: None,
            host: Some("api.example.com".to_string()),
            deviation,
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "my-reverse-proxy-journal-{name}-{}",
            uuid::Uuid::new_v4()
        ));
        dir
    }

    #[test]
    fn dates_are_utc() {
        assert_eq!(format_utc(AT), "2026-11-15T14:03:21.512Z");
        assert_eq!(format_utc(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            file_name(AT / MICROS_IN_HOUR),
            "cloudflare-deviations-2026-11-15-14.log"
        );
    }

    #[test]
    fn a_file_name_gives_back_its_hour_and_no_other_name_does() {
        for hour in [0, AT / MICROS_IN_HOUR, 500_000] {
            assert_eq!(hour_of_file_name(&file_name(hour)), Some(hour));
        }

        for name in [
            "cloudflare-deviations-2026-11-15-24.log",
            "cloudflare-deviations-2026-13-15-14.log",
            "cloudflare-deviations-2026-11-15.log",
            "cloudflare-deviations-2026-11-15-14.txt",
            "other-2026-11-15-14.log",
            "app.log",
        ] {
            assert_eq!(hour_of_file_name(name), None, "{name}");
        }
    }

    #[test]
    fn a_line_tells_the_deviation() {
        assert_eq!(
            event(AT, Deviation::NotCloudflarePeer).to_line(),
            "2026-11-15T14:03:21.512Z endpoint=api.example.com:443 reason=not_cloudflare_peer \
             peer=203.0.113.7 peer_country=- host=\"api.example.com\"\n"
        );

        assert_eq!(
            event(AT, Deviation::InvalidCfConnectingIp(printable(b"x\ny"))).to_line(),
            "2026-11-15T14:03:21.512Z endpoint=api.example.com:443 reason=bad_cf_connecting_ip \
             peer=203.0.113.7 peer_country=- host=\"api.example.com\" value=\"x\\x0ay\"\n"
        );
    }

    /// A request closed for a header of `request_with_header_only`: the name of the header, and
    /// the client Cloudflare told, when it came through Cloudflare - never a value.
    #[test]
    fn a_line_of_a_required_header_names_it_and_the_client() {
        let mut through_cloudflare = event(
            AT,
            Deviation::WrongRequiredHeader("x-zone-secret".to_string()),
        );
        through_cloudflare.client = Some("198.51.100.4".parse().unwrap());

        assert_eq!(
            through_cloudflare.to_line(),
            "2026-11-15T14:03:21.512Z endpoint=api.example.com:443 reason=wrong_required_header \
             peer=203.0.113.7 peer_country=- client=198.51.100.4 client_country=- \
             host=\"api.example.com\" header=x-zone-secret\n"
        );

        assert_eq!(
            event(
                AT,
                Deviation::MissingRequiredHeader("x-zone-secret".to_string())
            )
            .to_line(),
            "2026-11-15T14:03:21.512Z endpoint=api.example.com:443 reason=no_required_header \
             peer=203.0.113.7 peer_country=- host=\"api.example.com\" header=x-zone-secret\n"
        );
    }

    /// Each address comes with its country by the country database - an IPv4 address of a
    /// dual-stack listener (`::ffff:a.b.c.d`) as the IPv4 address it is - and `-` for one the
    /// database has no country for, or for no address at all.
    #[test]
    fn a_line_tells_the_country_of_each_address() {
        let mut through_cloudflare = event(
            AT,
            Deviation::MissingRequiredHeader("x-zone-secret".to_string()),
        );
        through_cloudflare.peer = Some("::ffff:8.8.8.8".parse().unwrap());
        through_cloudflare.client = Some("1.0.0.0".parse().unwrap());

        assert_eq!(
            through_cloudflare.to_line(),
            "2026-11-15T14:03:21.512Z endpoint=api.example.com:443 reason=no_required_header \
             peer=::ffff:8.8.8.8 peer_country=US client=1.0.0.0 client_country=AU \
             host=\"api.example.com\" header=x-zone-secret\n"
        );

        let mut private = event(AT, Deviation::NotCloudflarePeer);
        private.peer = Some("10.0.0.5".parse().unwrap());
        assert!(
            private.to_line().contains(" peer=10.0.0.5 peer_country=- "),
            "{}",
            private.to_line()
        );

        let mut unix_socket = event(AT, Deviation::NotCloudflarePeer);
        unix_socket.peer = None;
        assert!(
            unix_socket.to_line().contains(" peer=- peer_country=- "),
            "{}",
            unix_socket.to_line()
        );
    }

    #[test]
    fn deviations_go_to_the_file_of_their_hour() {
        let dir = temp_dir("hours");
        let mut writer = JournalWriter::new(dir.clone());

        writer.write(&[
            event(AT, Deviation::NotCloudflarePeer),
            event(AT + 1000, Deviation::MissingCfConnectingIp),
            event(AT + MICROS_IN_HOUR, Deviation::RangesNotLoaded),
        ]);

        let first = std::fs::read_to_string(dir.join(file_name(AT / MICROS_IN_HOUR))).unwrap();
        assert_eq!(first.lines().count(), 2, "{first}");
        assert!(first.contains("reason=no_cf_connecting_ip"), "{first}");

        let second = std::fs::read_to_string(dir.join(file_name(AT / MICROS_IN_HOUR + 1))).unwrap();
        assert_eq!(second.lines().count(), 1, "{second}");

        // A writer started anew within the hour - the proxy was restarted - writes on after it.
        JournalWriter::new(dir.clone())
            .write(&[event(AT + MICROS_IN_HOUR + 1, Deviation::NotCloudflarePeer)]);
        let second = std::fs::read_to_string(dir.join(file_name(AT / MICROS_IN_HOUR + 1))).unwrap();
        assert_eq!(second.lines().count(), 2, "{second}");

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_hour_is_written_up_to_the_size_of_a_file() {
        let dir = temp_dir("full");
        let path = dir.join(file_name(AT / MICROS_IN_HOUR));

        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, vec![b'x'; MAX_FILE_SIZE as usize - 10]).unwrap();

        let mut writer = JournalWriter::new(dir.clone());
        writer.write(&[event(AT, Deviation::NotCloudflarePeer)]);
        writer.write(&[event(AT + 1, Deviation::NotCloudflarePeer)]);

        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            MAX_FILE_SIZE - 10,
            "a line went past the size of the file"
        );

        // The next hour is a file of its own, written again.
        writer.write(&[event(AT + MICROS_IN_HOUR, Deviation::NotCloudflarePeer)]);
        assert!(dir.join(file_name(AT / MICROS_IN_HOUR + 1)).exists());

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn files_past_a_day_are_deleted_and_nothing_else_is() {
        let dir = temp_dir("gc");
        std::fs::create_dir_all(&dir).unwrap();

        let hour = AT / MICROS_IN_HOUR;
        let expired = dir.join(file_name(hour - KEEP_HOURS));
        let kept = dir.join(file_name(hour - KEEP_HOURS + 1));
        let other = dir.join("app-2020-01-01.log");

        for path in [&expired, &kept, &other] {
            std::fs::write(path, b"x").unwrap();
        }

        JournalWriter::new(dir.clone()).write(&[event(AT, Deviation::NotCloudflarePeer)]);

        assert!(
            !expired.exists(),
            "a file of {KEEP_HOURS} hours ago is kept"
        );
        assert!(kept.exists());
        assert!(other.exists(), "a file of another log is deleted");

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_folder_which_can_not_be_written_stops_nothing() {
        let file_in_the_way = temp_dir("blocked");
        std::fs::write(&file_in_the_way, b"x").unwrap();

        // The folder is a file: nothing can be created in it.
        let mut writer = JournalWriter::new(file_in_the_way.join("logs"));
        writer.write(&[event(AT, Deviation::NotCloudflarePeer)]);
        writer.write(&[event(AT + 1, Deviation::NotCloudflarePeer)]);

        std::fs::remove_file(file_in_the_way).unwrap();
    }

    #[tokio::test]
    async fn the_queue_takes_no_more_than_its_capacity() {
        let journal = DeviationJournal::new();
        let peer = ConnectionIp::Tcp("203.0.113.7:5000".parse().unwrap());

        for _ in 0..QUEUE_CAPACITY + 100 {
            journal.write(
                "api.example.com:443",
                &peer,
                None,
                None,
                Deviation::NotCloudflarePeer,
            );
        }

        let mut receiver = journal.receiver.lock().take().unwrap();
        let mut queued = 0;
        while receiver.try_recv().is_ok() {
            queued += 1;
        }

        assert_eq!(queued, QUEUE_CAPACITY);
    }
}

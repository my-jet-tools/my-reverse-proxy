//! The limits of one client connection of the http/https endpoints: settings of
//! `global_settings`, resolved into every endpoint as the global timeouts are.

/// The limits of a client connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionSettings {
    /// `max_requests_per_connection`: after so many requests a connection is closed - an h2 one
    /// with a GOAWAY, an http/1.1 one once the answer to the last of them is out. nginx:
    /// `keepalive_requests`.
    pub max_requests_per_connection: u32,
    /// `max_request_head_size`: the most the head of an http/1.1 request may take - its request
    /// line and every header. A larger one is answered `431`. nginx:
    /// `large_client_header_buffers`.
    pub max_request_head_size: usize,
    /// `h2_max_concurrent_streams`: the requests an h2 client may have open at once on one
    /// connection. nginx: `http2_max_concurrent_streams`.
    pub h2_max_concurrent_streams: u32,
    /// `h2_max_header_list_size`: the most the headers of an h2 request may take, decoded.
    pub h2_max_header_list_size: u32,
}

impl Default for ConnectionSettings {
    fn default() -> Self {
        Self {
            max_requests_per_connection: crate::consts::DEFAULT_MAX_REQUESTS_PER_CONNECTION,
            max_request_head_size: crate::consts::DEFAULT_MAX_REQUEST_HEAD_SIZE,
            h2_max_concurrent_streams: crate::consts::DEFAULT_H2_MAX_CONCURRENT_STREAMS,
            h2_max_header_list_size: crate::consts::DEFAULT_H2_MAX_HEADER_LIST_SIZE,
        }
    }
}

/// The least `max_request_head_size`: hyper can not read an http/1.1 head with less.
const MIN_REQUEST_HEAD_SIZE: usize = 8 * 1024;

/// The most `max_request_head_size`: the read buffer of the http/1.1 pipeline.
const MAX_REQUEST_HEAD_SIZE: usize = 1024 * 1024;

impl ConnectionSettings {
    /// The settings out of `global_settings` - each a default where it is not given. Errors on a
    /// value out of its range, so a typo fails the settings load.
    pub fn resolve(
        max_requests_per_connection: Option<u32>,
        max_request_head_size: Option<&str>,
        h2_max_concurrent_streams: Option<u32>,
        h2_max_header_list_size: Option<&str>,
    ) -> Result<Self, String> {
        let defaults = Self::default();

        let max_requests_per_connection =
            max_requests_per_connection.unwrap_or(defaults.max_requests_per_connection);
        if max_requests_per_connection == 0 {
            return Err(
                "global_settings.max_requests_per_connection: 0 would serve no request".to_string(),
            );
        }

        let max_request_head_size = match max_request_head_size {
            Some(value) => {
                let size = parse_size("global_settings.max_request_head_size", value)?;

                if !(MIN_REQUEST_HEAD_SIZE..=MAX_REQUEST_HEAD_SIZE).contains(&size) {
                    return Err(format!(
                        "global_settings.max_request_head_size: '{value}' - it has to be from \
                         8Kb to 1Mb"
                    ));
                }

                size
            }
            None => defaults.max_request_head_size,
        };

        let h2_max_concurrent_streams =
            h2_max_concurrent_streams.unwrap_or(defaults.h2_max_concurrent_streams);
        if h2_max_concurrent_streams == 0 {
            return Err(
                "global_settings.h2_max_concurrent_streams: 0 would serve no request".to_string(),
            );
        }

        let h2_max_header_list_size = match h2_max_header_list_size {
            Some(value) => {
                let size = parse_size("global_settings.h2_max_header_list_size", value)?;

                if size == 0 || size > u32::MAX as usize {
                    return Err(format!(
                        "global_settings.h2_max_header_list_size: '{value}' is not a size an h2 \
                         client can be told"
                    ));
                }

                size as u32
            }
            None => defaults.h2_max_header_list_size,
        };

        Ok(Self {
            max_requests_per_connection,
            max_request_head_size,
            h2_max_concurrent_streams,
            h2_max_header_list_size,
        })
    }

    /// The largest of each. A port shared by several endpoints does not know which of them a
    /// connection is for until the ClientHello (or the first request) has been read, and until
    /// then no endpoint may be held to less than its own setting.
    pub fn largest(&self, other: &Self) -> Self {
        Self {
            max_requests_per_connection: self
                .max_requests_per_connection
                .max(other.max_requests_per_connection),
            max_request_head_size: self.max_request_head_size.max(other.max_request_head_size),
            h2_max_concurrent_streams: self
                .h2_max_concurrent_streams
                .max(other.h2_max_concurrent_streams),
            h2_max_header_list_size: self
                .h2_max_header_list_size
                .max(other.h2_max_header_list_size),
        }
    }
}

fn parse_size(setting: &str, value: &str) -> Result<usize, String> {
    crate::settings::parse_buffer_size(value.trim()).map_err(|err| format!("{setting}: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_given_is_the_defaults() {
        let settings = ConnectionSettings::resolve(None, None, None, None).unwrap();
        assert_eq!(settings, ConnectionSettings::default());
        assert_eq!(settings.max_requests_per_connection, 1000);
        assert_eq!(settings.max_request_head_size, 64 * 1024);
        assert_eq!(settings.h2_max_concurrent_streams, 128);
        assert_eq!(settings.h2_max_header_list_size, 16 * 1024);
    }

    #[test]
    fn given_values_are_taken() {
        let settings =
            ConnectionSettings::resolve(Some(10), Some("32Kb"), Some(50), Some("8Kb")).unwrap();
        assert_eq!(settings.max_requests_per_connection, 10);
        assert_eq!(settings.max_request_head_size, 32 * 1024);
        assert_eq!(settings.h2_max_concurrent_streams, 50);
        assert_eq!(settings.h2_max_header_list_size, 8 * 1024);
    }

    #[test]
    fn a_value_out_of_its_range_fails_the_load() {
        assert!(ConnectionSettings::resolve(Some(0), None, None, None).is_err());
        assert!(ConnectionSettings::resolve(None, Some("4Kb"), None, None).is_err());
        assert!(ConnectionSettings::resolve(None, Some("2Mb"), None, None).is_err());
        assert!(ConnectionSettings::resolve(None, Some("lots"), None, None).is_err());
        assert!(ConnectionSettings::resolve(None, None, Some(0), None).is_err());
        assert!(ConnectionSettings::resolve(None, None, None, Some("0")).is_err());
        assert!(ConnectionSettings::resolve(None, None, None, Some("8Gb")).is_err());
    }
}

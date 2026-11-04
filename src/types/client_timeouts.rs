use std::time::Duration;

/// How long the proxy waits for a client of an http/https endpoint - the protection against
/// slow clients. Resolved per endpoint from the timeout cascade (global → endpoint); see the
/// defaults in `crate::consts`.
///
/// None of them applies to `type: tcp` and `type: mcp` endpoints past the TLS handshake: those
/// forward bytes and never read an HTTP head.
#[derive(Clone, Copy, Debug)]
pub struct ClientTimeouts {
    /// The whole head of a request (http/1.1), or the first request of a connection (h2).
    pub header_read_timeout: Duration,
    /// The TLS handshake, the ClientHello included.
    pub tls_handshake_timeout: Duration,
    /// h2 PINGs to the client, and how long an answer may take.
    pub h2_keep_alive_interval: Duration,
    pub h2_keep_alive_timeout: Duration,
}

impl Default for ClientTimeouts {
    fn default() -> Self {
        Self {
            header_read_timeout: crate::consts::DEFAULT_HEADER_READ_TIMEOUT,
            tls_handshake_timeout: crate::consts::DEFAULT_TLS_HANDSHAKE_TIMEOUT,
            h2_keep_alive_interval: crate::consts::DEFAULT_CLIENT_H2_KEEP_ALIVE_INTERVAL,
            h2_keep_alive_timeout: crate::consts::DEFAULT_CLIENT_H2_KEEP_ALIVE_TIMEOUT,
        }
    }
}

impl ClientTimeouts {
    /// The longest of each. A port shared by several endpoints does not know which of them a
    /// connection is for until the ClientHello (or the first request) has been read, and until
    /// then no endpoint may be held to less than its own setting.
    pub fn longest(&self, other: &Self) -> Self {
        Self {
            header_read_timeout: self.header_read_timeout.max(other.header_read_timeout),
            tls_handshake_timeout: self.tls_handshake_timeout.max(other.tls_handshake_timeout),
            h2_keep_alive_interval: self.h2_keep_alive_interval.max(other.h2_keep_alive_interval),
            h2_keep_alive_timeout: self.h2_keep_alive_timeout.max(other.h2_keep_alive_timeout),
        }
    }
}

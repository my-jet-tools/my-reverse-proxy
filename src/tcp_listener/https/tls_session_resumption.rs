use std::sync::Arc;

use my_tls::tokio_rustls::rustls::{
    self,
    server::{ProducesTickets, ServerSessionMemoryCache, StoresServerSessions},
    ServerConfig,
};

/// Sessions the TLS 1.2 session-id cache keeps. With the ticketer on, TLS 1.3 resumes from a
/// ticket the client holds and needs no entry here; this cache serves the TLS 1.2 clients which
/// resume by session id. The oldest entries go first once it is full.
pub const TLS_SESSION_CACHE_SIZE: usize = 4096;

/// What lets a returning client resume its TLS session - an abbreviated handshake, with no
/// certificate sent and no signature made - instead of a full one on every connection.
///
/// A `ServerConfig` is built for each connection (it is picked by the SNI of the ClientHello),
/// and rustls keeps the session cache and the ticket keys inside it: built anew each time, they
/// were empty each time, and no connection ever resumed. These are made once, when the proxy
/// starts, and handed to every config that may resume.
///
/// Only an endpoint WITHOUT a client certificate may resume - see [`Self::apply_to`].
pub struct TlsSessionResumption {
    session_storage: Arc<dyn StoresServerSessions>,
    /// `None` when the ticket keys could not be made (no randomness from the system): no
    /// tickets then, and the session-id cache alone resumes what it can.
    ticketer: Option<Arc<dyn ProducesTickets>>,
}

impl TlsSessionResumption {
    pub fn new() -> Self {
        // Rotates its key every 6 hours; a ticket lives 12. The keys are in memory only, so a
        // restart costs every client one full handshake.
        let ticketer = match rustls::crypto::ring::Ticketer::new() {
            Ok(ticketer) => Some(ticketer),
            Err(err) => {
                println!(
                    "TLS session tickets are off: the ticket keys could not be made. Err: {:?}",
                    err
                );
                None
            }
        };

        Self {
            session_storage: ServerSessionMemoryCache::new(TLS_SESSION_CACHE_SIZE),
            ticketer,
        }
    }

    /// Lets connections made with `server_config` resume sessions of the other configs this was
    /// applied to, and be resumed by them.
    ///
    /// NEVER for an endpoint which requires a client certificate:
    /// * a resumed handshake skips the client certificate - `MyClientCertVerifier` is not
    ///   called, the connection's `ClientCertCell` stays empty, and the request handler would
    ///   see no certificate where the endpoint demands one;
    /// * the store is shared: a session verified against one endpoint's CA could be resumed on
    ///   an endpoint trusting a different CA, or a session which presented no certificate at
    ///   all on an endpoint requiring one.
    ///
    /// Sessions of different hosts do not mix: rustls resumes a session only under the same SNI
    /// it was made with (RFC 6066). Early data (0-RTT) stays off - `max_early_data_size` is left
    /// at 0 - since a replayed request would reach the upstream twice.
    pub fn apply_to(&self, server_config: &mut ServerConfig) {
        server_config.session_storage = self.session_storage.clone();

        if let Some(ticketer) = self.ticketer.as_ref() {
            server_config.ticketer = ticketer.clone();
        }
    }
}

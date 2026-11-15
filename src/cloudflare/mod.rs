//! `cloudflare: true` on an endpoint: its hostname is proxied by Cloudflare, and nothing else may
//! reach it.
//!
//! - A connection to it is taken only from the networks Cloudflare publishes (read at startup and
//!   then every hour - see [`CloudflareIpRanges`]).
//! - The client of each of its requests is the address of the request's `CF-Connecting-IP`, which
//!   Cloudflare always writes itself. The allow-lists, the country, the logs and
//!   `X-Forwarded-For` (`<client>, <Cloudflare server>`) are of it.
//! - Anything else - a connection from elsewhere, a request without one valid `CF-Connecting-IP`,
//!   the networks not read yet - is closed without a word, and journaled
//!   (see [`DeviationJournal`]).
//!
//! On every other endpoint the client is the peer of the connection, and `X-Forwarded-For` is its
//! address alone - what the client sent under that name, or under any other one which tells who it
//! is, never reaches the upstream (see [`RequestClient::takes_away_header`]).

mod client;
pub use client::*;
mod deviation_journal;
pub use deviation_journal::*;
mod ip_cidr;
pub use ip_cidr::*;
mod ip_ranges;
pub use ip_ranges::*;

use crate::types::ConnectionIp;

/// Writes `deviation` of a connection from `peer` to `endpoint` to the journal. `host`: what the
/// client named, by SNI or by `Host`.
pub fn journal(endpoint: &str, peer: &ConnectionIp, host: Option<&[u8]>, deviation: Deviation) {
    crate::app::APP_CTX
        .cloudflare_deviations
        .write(endpoint, peer, host, deviation);
}

/// [`peer_deviation`] against the networks the proxy read, journaled. Whether the connection goes
/// on.
pub fn connection_may_go_on(
    endpoint: &str,
    endpoint_is_cloudflare: bool,
    peer: &ConnectionIp,
    host: Option<&[u8]>,
) -> bool {
    let Some(deviation) = peer_deviation(
        endpoint_is_cloudflare,
        peer,
        &crate::app::APP_CTX.cloudflare_ip_ranges,
    ) else {
        return true;
    };

    let goes_on = !deviation.closes_connection();
    journal(endpoint, peer, host, deviation);
    goes_on
}

/// [`request_client`] against the networks the proxy read, journaled. `None`: the connection is
/// closed without a word.
pub fn client_of_request<'h>(
    endpoint: &str,
    endpoint_is_cloudflare: bool,
    peer: ConnectionIp,
    cf_connecting_ip: impl Iterator<Item = &'h [u8]>,
    host: Option<&[u8]>,
) -> Option<RequestClient> {
    match request_client(
        endpoint_is_cloudflare,
        peer,
        cf_connecting_ip,
        &crate::app::APP_CTX.cloudflare_ip_ranges,
    ) {
        Ok(client) => Some(client),
        Err(deviation) => {
            journal(endpoint, &peer, host, deviation);
            None
        }
    }
}

/// Every test connects from the loopback: in the tests it is the one network of Cloudflare. Each
/// test which needs it sets the very same list, so the tests which run at once agree on it.
#[cfg(test)]
pub fn the_loopback_is_cloudflare_in_tests() {
    crate::app::APP_CTX
        .cloudflare_ip_ranges
        .replace(vec![IpCidr::parse("127.0.0.1/32").unwrap()]);
}

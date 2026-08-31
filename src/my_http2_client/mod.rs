//! HTTP/2 client — an in-tree copy of `my_http_client::http2` (upstream commit
//! ad9855c).
//!
//! It lives here because the streaming request API the proxy needs
//! ([`MyHttp2Client::do_streamed_request`]) landed upstream after tag `0.1.2` was
//! cut, and the tag was not moved onto it. Only the h2 client itself is local:
//! everything it shares with the crate — the connector trait, the error type, the
//! metrics trait, `HyperResponse`, `from_incoming_body` — is still taken FROM
//! `my_http_client`, so this client and the h1 ones keep speaking exactly the same
//! types, and the pools and connectors did not have to change at all.
//!
//! Deliberately NOT copied: upstream's `RequestBodyStream` (a channel-fed request
//! body). The proxy streams a client's request body by forwarding hyper's own
//! `Incoming`, so it has no use for a producer side.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};

mod my_http2_client;
pub use my_http2_client::*;
mod my_http2_client_inner;
pub use my_http2_client_inner::*;
// Called by the client itself (`super::wrap_http2_endpoint::wrap_http2_endpoint`);
// nothing outside the module needs it.
mod wrap_http2_endpoint;

#[cfg(test)]
mod streaming_body_tests;

/// Body of an outgoing request as it is given to hyper. One connection serves
/// requests with different body types, so the body is erased to the
/// `hyper::body::Body` trait object — that is what lets both a buffered
/// `Full<Bytes>` and a stream of chunks travel through the very same connection.
pub type HyperRequestBody = http_body_util::combinators::BoxBody<Bytes, String>;

pub type HyperRequest = hyper::Request<HyperRequestBody>;

/// Erases a buffered request body into the trait object the connections speak in.
pub fn to_hyper_request(req: hyper::Request<Full<Bytes>>) -> HyperRequest {
    let (head, body) = req.into_parts();
    hyper::Request::from_parts(head, body.map_err(|err| err.to_string()).boxed())
}

/// The body of a request that has none (an extended CONNECT, a probe).
pub fn empty_request_body() -> HyperRequestBody {
    Full::new(Bytes::new())
        .map_err(|err| err.to_string())
        .boxed()
}

use std::io::Write;

use bytes::{Bytes, BytesMut};
use flate2::{write::GzEncoder, Compression};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, header::*, Method, Request, Uri};
// Of hyper, not the `HeaderValue` of `crate::types`, which a log takes.
use hyper::header::HeaderValue;
use hyper_tungstenite::{tungstenite::http::request::Parts, HyperWebsocket};

use crate::{configurations::*, types::*};

use super::{
    HttpProxyPass, HttpProxyPassIdentity, HttpProxyPassInner, ProxyPassError, ProxyPassLocation,
};

pub enum WebSocketUpgrade {
    H1 {
        upgrade_response: hyper::Response<Full<Bytes>>,
        server_web_socket: HyperWebsocket,
    },
    H2 {
        upgrade_response: hyper::Response<Full<Bytes>>,
        on_upgrade: hyper::upgrade::OnUpgrade,
    },
}

pub struct TransformedRequest {
    pub request: TransformedRequestBody,
    pub req_parts: Parts,
    pub web_socket_upgrade: Option<WebSocketUpgrade>,
    /// What the body held in memory takes of all request bodies held: given back once the
    /// upstream answered. Nothing for a body which is streamed, or for no body.
    pub held_body: BufferedBodyShare,
}

/// The upstream request, in the only two shapes an upstream can take it.
pub enum TransformedRequestBody {
    /// Body buffered in memory. Required whenever the body itself is handled here
    /// — gzip compression needs it whole, a websocket handshake is replayed from
    /// it — or when the upstream client only takes `Full<Bytes>` (everything that
    /// is not h2).
    Buffered(hyper::Request<Full<Bytes>>),
    /// Body forwarded frame by frame, exactly as it arrives from the client:
    /// nothing is collected, whatever size it is. h2 upstreams only.
    Streamed {
        request: hyper::Request<crate::my_http2_client::HyperRequestBody>,
        /// `Content-Length` as the client declared it, so the upstream request can
        /// announce the same size. `None` leaves it unannounced — h2 has no chunked
        /// framing, an unknown length is simply not declared.
        content_size: Option<usize>,
    },
}

/// What [`HttpRequestBuilder::build_request`] produced: the body only, so the
/// callers can still assemble the request (and clone the body for a websocket
/// handshake) themselves.
enum BuiltBody {
    Buffered(Full<Bytes>),
    Streamed {
        body: crate::my_http2_client::HyperRequestBody,
        content_size: Option<usize>,
    },
}

impl BuiltBody {
    fn into_transformed(self, parts: Parts) -> TransformedRequestBody {
        match self {
            Self::Buffered(body) => {
                TransformedRequestBody::Buffered(Request::from_parts(parts, body))
            }
            Self::Streamed { body, content_size } => TransformedRequestBody::Streamed {
                request: Request::from_parts(parts, body),
                content_size,
            },
        }
    }
}

pub struct HttpRequestBuilder {
    pub parts: Parts,
    body: Incoming,
    /// Who the request is of: its `X-Forwarded-For`, `CF-IPCountry` and `${ENDPOINT_IP}`, and
    /// the address its log lines are written with.
    client: crate::cloudflare::RequestClient,
    /// How long the client may go silent while it sends a body the proxy holds whole before it
    /// sends it on: the endpoint's `read_timeout`, set by [`Self::into_request`].
    body_idle_timeout: std::time::Duration,
    /// How much of such a body may be held: the endpoint's, set by [`Self::into_request`].
    body_limits: BufferedBodyLimits,
    /// `max_request_body` of the endpoint: the most any body may take, streamed or held.
    max_request_body: Option<usize>,
}

/// Whether the client side of this exchange is HTTP/1.x ON THE WIRE. The
/// endpoint's configured listen type cannot be used for this: an HTTP/2
/// connection opened for another vhost (browser connection coalescing,
/// RFC 7540 §9.1.1) legitimately carries requests for endpoints configured
/// as http1, so protocol-conversion decisions must follow the actual version
/// of the request itself.
pub fn client_is_http1(version: hyper::Version) -> bool {
    !matches!(version, hyper::Version::HTTP_2 | hyper::Version::HTTP_3)
}

fn is_h2_websocket_connect(parts: &Parts) -> bool {
    if parts.method != Method::CONNECT {
        return false;
    }

    let Some(protocol) = parts.extensions.get::<hyper::ext::Protocol>() else {
        return false;
    };

    protocol.as_ref().eq_ignore_ascii_case(b"websocket")
}

/// An MCP location publishes one upstream MCP server under one listen path, and
/// the whole protocol lives on that single URL — the client's path only selects
/// the location, it carries nothing the upstream can use. So every request is
/// rewritten onto the path configured in `proxy_pass_to`, exactly as the h1 byte
/// pipeline does via `H1Reader::compile_headers`. A no-op for every other
/// location type, and idempotent when the two paths are equal.
///
/// Only the path-and-query is replaced — scheme and authority are carried over
/// untouched. A request that arrived over h2 has an ABSOLUTE uri, and an h2
/// upstream request needs `:scheme` / `:authority` to be legal at all (h2 refuses
/// to send one without them, RFC 9113 §8.3.1), so overwriting the whole uri with
/// the origin-form upstream path would break every `mcp-h2` request.
fn rewrite_mcp_path(uri: &mut Uri, location: &ProxyPassLocation) {
    let Some(mcp_path) = crate::h1_remote_connection::mcp_path(&location.config.proxy_pass_to)
    else {
        return;
    };

    apply_upstream_path(uri, mcp_path, location.config.id_string.as_str());
}

/// A location with `strip_path` sends its upstream the target without the part of
/// the path which picked the location (`crate::types::strip_location_path`) - the
/// same target the h1 pipeline sends. The scheme and the authority of an absolute
/// uri stay, as they do for an MCP location.
///
/// Returns the uri as the client sent it, when the location has `strip_path`.
fn strip_location_path(uri: &mut Uri, location: &ProxyPassLocation) -> Option<Uri> {
    if !location.config.strip_path {
        return None;
    }

    let client_uri = uri.clone();

    // An authority-form target (`CONNECT host:443`) has no path, and is a request of
    // no location.
    let path_and_query = client_uri.path_and_query()?;

    let target = crate::types::strip_location_path(path_and_query.as_str(), &location.config.path);

    apply_upstream_path(uri, &target, location.config.id_string.as_str());

    Some(client_uri)
}

/// Swaps the uri's path-and-query for `upstream_path`, keeping everything else.
/// On bad input the uri is left untouched and the reason is printed — forwarding
/// the client's own path would silently 404 on the upstream (an MCP location's, or
/// the one of a location with `strip_path`), so it must not happen quietly.
fn apply_upstream_path(uri: &mut Uri, upstream_path: &str, location_id: &str) {
    let path_and_query = match upstream_path.parse::<hyper::http::uri::PathAndQuery>() {
        Ok(path_and_query) => path_and_query,
        Err(err) => {
            println!(
                "Location [{}]: upstream path '{}' is not a valid path: {:?}",
                location_id, upstream_path, err
            );
            return;
        }
    };

    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(path_and_query);

    match Uri::from_parts(parts) {
        Ok(rewritten) => *uri = rewritten,
        Err(err) => {
            println!(
                "Location [{}]: can not apply upstream path '{}' to uri '{}': {:?}",
                location_id, upstream_path, uri, err
            );
        }
    }
}

impl HttpRequestBuilder {
    pub fn new(
        src: hyper::Request<hyper::body::Incoming>,
        client: crate::cloudflare::RequestClient,
    ) -> Self {
        let (parts, body) = src.into_parts();

        Self {
            parts,
            body,
            client,
            body_idle_timeout: crate::consts::DEFAULT_READ_TIMEOUT,
            body_limits: BufferedBodyLimits::default(),
            max_request_body: None,
        }
    }

    /// The request to the upstream of `location`.
    ///
    /// `strip_path` is applied here, once, before the request takes one of its shapes
    /// below: every one of them - an upgrade included - and every content source
    /// reads the uri. `req_parts` keeps the uri the client sent: `${PATH_AND_QUERY}`
    /// in a response header is the path and query of the client's request.
    pub async fn into_request(
        mut self,
        proxy_pass: &HttpProxyPass,
        location: &ProxyPassLocation,
    ) -> Result<TransformedRequest, ProxyPassError> {
        let client_uri = strip_location_path(&mut self.parts.uri, location);

        self.body_idle_timeout = proxy_pass.endpoint_info.timeouts.read_timeout;
        self.body_limits = proxy_pass.endpoint_info.buffered_body_limits;
        self.max_request_body = proxy_pass.endpoint_info.max_request_body;

        // A body held whole is held to `max_request_body` too.
        if let Some(max_request_body) = self.max_request_body {
            self.body_limits.max_body = self.body_limits.max_body.min(max_request_body);
        }

        let mut request = self.into_upstream_request(proxy_pass, location).await?;

        if let Some(client_uri) = client_uri {
            request.req_parts.uri = client_uri;
        }

        Ok(request)
    }

    async fn into_upstream_request(
        self,
        proxy_pass: &HttpProxyPass,
        location: &ProxyPassLocation,
    ) -> Result<TransformedRequest, ProxyPassError> {
        //let location_index = inner.locations.find_location_index(self.uri())?;

        let dest_http1 = location.is_http1();
        // The client's address for log attribution.
        let ip = self.client.ip.get_ip_log();

        if is_h2_websocket_connect(&self.parts) {
            if matches!(dest_http1, Some(true)) {
                return self
                    .h2_websocket_to_h1_websocket(proxy_pass, location, ip)
                    .await;
            }
            if matches!(dest_http1, Some(false)) {
                return self
                    .h2_websocket_to_h2_websocket(proxy_pass, location, ip)
                    .await;
            }
        }

        if dest_http1.is_none() {
            let (parts, body, held_body) = self.build_request(location, ip).await?;

            return Ok(TransformedRequest {
                req_parts: parts.clone(),
                request: body.into_transformed(parts),
                web_socket_upgrade: None,
                held_body,
            });
        }

        let dest_http1 = dest_http1.unwrap();

        if !client_is_http1(self.parts.version) && dest_http1 {
            return self.http2_to_http1(location, ip).await;
        }

        let (parts, body, held_body) = self.build_request(location, ip.clone()).await?;

        let mut web_socket_upgrade = None;
        // A handshake is never streamed (see build_request), so it is always the
        // buffered body that gets replayed into the upgrade.
        if let BuiltBody::Buffered(buffered) = &body {
            if parts.headers.get("sec-websocket-key").is_some() {
                if crate::app::APP_CTX
                    .debug_flags
                    .is_location_debug(location.config.id)
                {
                    crate::app::APP_CTX.proxy_logs.write(
                        proxy_pass.endpoint_info.host_endpoint.as_str(),
                        Some(location.config.id),
                        ip.clone(),
                        "Detected Upgrade http1->http1".to_string(),
                    );
                }

                let upgrade_req = hyper::Request::from_parts(parts.clone(), buffered.clone());
                let upgrade_response = hyper_tungstenite::upgrade(upgrade_req, None)?;

                web_socket_upgrade = Some(WebSocketUpgrade::H1 {
                    upgrade_response: upgrade_response.0,
                    server_web_socket: upgrade_response.1,
                });
            }
        }

        Ok(TransformedRequest {
            req_parts: parts.clone(),
            request: body.into_transformed(parts),

            web_socket_upgrade,
            held_body,
        })
        //return Ok((location_index, ));
    }

    async fn h2_websocket_to_h2_websocket(
        mut self,
        proxy_pass: &HttpProxyPass,
        location: &ProxyPassLocation,
        ip: Option<String>,
    ) -> Result<TransformedRequest, ProxyPassError> {
        if crate::app::APP_CTX
            .debug_flags
            .is_location_debug(location.config.id)
        {
            crate::app::APP_CTX.proxy_logs.write(
                proxy_pass.endpoint_info.host_endpoint.as_str(),
                Some(location.config.id),
                ip.clone(),
                "Detected h2 extended-CONNECT WebSocket -> h2 upstream".to_string(),
            );
        }

        let on_upgrade = self
            .parts
            .extensions
            .remove::<hyper::upgrade::OnUpgrade>()
            .ok_or(ProxyPassError::NoWebSocketUpgrade)?;

        let mut builder = Request::builder()
            .uri(self.parts.uri.clone())
            .method(Method::CONNECT)
            .version(hyper::Version::HTTP_2);

        for (name, value) in self.parts.headers.iter() {
            let n = name.as_str();
            if matches!(
                n,
                "host"
                    | "connection"
                    | "upgrade"
                    | "transfer-encoding"
                    | "te"
                    | "keep-alive"
                    | "proxy-connection"
                    | "sec-websocket-version"
                    | "sec-websocket-key"
                    | "sec-websocket-accept"
            ) {
                continue;
            }
            builder = builder.header(name, value);
        }

        let mut request = builder.body(Full::new(Bytes::new())).unwrap();
        request
            .extensions_mut()
            .insert(hyper::ext::Protocol::from_static("websocket"));

        let req_parts = self.parts.clone();

        let upgrade_response = hyper::Response::builder()
            .status(hyper::StatusCode::OK)
            .body(Full::<Bytes>::new(Bytes::new()))
            .unwrap();

        if crate::app::APP_CTX
            .debug_flags
            .is_location_debug(location.config.id)
        {
            crate::app::APP_CTX.proxy_logs.write_location(
                location.config.id,
                ip.clone(),
                format!(
                    "[{}]. h2->h2 ext-CONNECT WS handshake to upstream: {:?}",
                    request.uri(),
                    crate::types::HeaderList::new(request.headers(), &[])
                ),
            );
        }

        Ok(TransformedRequest {
            req_parts,
            request: TransformedRequestBody::Buffered(request),
            web_socket_upgrade: Some(WebSocketUpgrade::H2 {
                upgrade_response,
                on_upgrade,
            }),
            held_body: BUFFERED_REQUEST_BODIES.share(),
        })
    }

    async fn h2_websocket_to_h1_websocket(
        mut self,
        proxy_pass: &HttpProxyPass,
        location: &ProxyPassLocation,
        ip: Option<String>,
    ) -> Result<TransformedRequest, ProxyPassError> {
        if crate::app::APP_CTX
            .debug_flags
            .is_location_debug(location.config.id)
        {
            crate::app::APP_CTX.proxy_logs.write(
                proxy_pass.endpoint_info.host_endpoint.as_str(),
                Some(location.config.id),
                ip.clone(),
                "Detected h2 extended-CONNECT WebSocket -> h1 upgrade".to_string(),
            );
        }

        let on_upgrade = self
            .parts
            .extensions
            .remove::<hyper::upgrade::OnUpgrade>()
            .ok_or(ProxyPassError::NoWebSocketUpgrade)?;

        let path_and_query = if let Some(path_and_query) = self.parts.uri.path_and_query() {
            path_and_query.as_str()
        } else {
            "/"
        };

        let uri: Uri = path_and_query.parse().unwrap();

        let host_header = if let Some(host) = self.parts.uri.host() {
            if let Some(port) = self.parts.uri.port() {
                format!("{}:{}", host, port)
            } else {
                host.to_string()
            }
        } else if let Some(host) = self.parts.headers.get("host") {
            host.to_str().unwrap().to_string()
        } else {
            return Err(ProxyPassError::NoWebSocketUpgrade);
        };

        let ws_key = hyper_tungstenite::tungstenite::handshake::client::generate_key();

        let mut builder = Request::builder()
            .uri(uri)
            .method(Method::GET)
            .version(hyper::Version::HTTP_11)
            .header(HOST, host_header)
            .header(CONNECTION, "Upgrade")
            .header(UPGRADE, "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", ws_key);

        for (name, value) in self.parts.headers.iter() {
            let n = name.as_str();
            if matches!(
                n,
                "host"
                    | "connection"
                    | "upgrade"
                    | "transfer-encoding"
                    | "te"
                    | "keep-alive"
                    | "proxy-connection"
                    | "sec-websocket-version"
                    | "sec-websocket-key"
                    | "sec-websocket-accept"
            ) {
                continue;
            }
            builder = builder.header(name, value);
        }

        let request = builder.body(Full::new(Bytes::new())).unwrap();
        let req_parts = self.parts.clone();

        let upgrade_response = hyper::Response::builder()
            .status(hyper::StatusCode::OK)
            .body(Full::<Bytes>::new(Bytes::new()))
            .unwrap();

        if crate::app::APP_CTX
            .debug_flags
            .is_location_debug(location.config.id)
        {
            crate::app::APP_CTX.proxy_logs.write_location(
                location.config.id,
                ip.clone(),
                format!(
                    "[{}]. h2->h1 WS handshake to upstream: {:?}",
                    request.uri(),
                    crate::types::HeaderList::new(request.headers(), &[])
                ),
            );
        }

        Ok(TransformedRequest {
            req_parts,
            request: TransformedRequestBody::Buffered(request),
            web_socket_upgrade: Some(WebSocketUpgrade::H2 {
                upgrade_response,
                on_upgrade,
            }),
            held_body: BUFFERED_REQUEST_BODIES.share(),
        })
    }

    async fn http2_to_http1(
        self,
        location: &ProxyPassLocation,
        ip: Option<String>,
    ) -> Result<TransformedRequest, ProxyPassError> {
        let path_and_query = if let Some(path_and_query) = self.parts.uri.path_and_query() {
            path_and_query.as_str()
        } else {
            "/"
        };

        let mut uri: Uri = path_and_query.parse().unwrap();
        rewrite_mcp_path(&mut uri, location);

        let host_header = if let Some(host) = self.parts.headers.get("host") {
            host.to_str().unwrap().to_string()
        } else if let Some(host) = self.parts.uri.host() {
            if let Some(port) = self.parts.uri.port() {
                format!("{}:{}", host, port)
            } else {
                host.to_string()
            }
        } else {
            return Err(ProxyPassError::NoHostHeader);
        };

        let mut builder = Request::builder()
            .uri(uri)
            .method(self.parts.method.clone())
            .header("host", host_header);

        for header in self.parts.headers.iter() {
            if header.0.as_str().eq_ignore_ascii_case("host") {
                continue;
            }
            builder = builder.header(header.0, header.1);
        }

        let (bytes, held_body) = collect_client_body(
            self.body,
            self.body_idle_timeout,
            self.body_limits,
            &BUFFERED_REQUEST_BODIES,
        )
        .await?;

        let req_parts = self.parts.clone();

        let body_len = bytes.len();
        let body = into_full_body(bytes, location.config.id, ip.clone());

        let mut request = builder.body(body).unwrap();

        // An h2 body has no length of its own on the wire: the http/1.1 upstream is told it.
        frame_whole_body(request.headers_mut(), body_len);

        if crate::app::APP_CTX
            .debug_flags
            .is_location_debug(location.config.id)
        {
            crate::app::APP_CTX.proxy_logs.write_location(
                location.config.id,
                ip.clone(),
                format!(
                    "[{}]. After Conversion Request: {:?}. ",
                    request.uri(),
                    crate::types::HeaderList::new(request.headers(), &[])
                ),
            );
        }

        Ok(TransformedRequest {
            req_parts,
            request: TransformedRequestBody::Buffered(request),
            web_socket_upgrade: None,
            held_body,
        })
    }

    pub fn uri(&self) -> &Uri {
        &self.parts.uri
    }

    /// Every `X-Api-Key` value as received, for the `api_keys_auth` gate of the location.
    pub fn get_api_key_values(&self) -> impl Iterator<Item = &[u8]> {
        self.parts
            .headers
            .get_all(crate::api_keys::API_KEY_HEADER)
            .iter()
            .map(|value| value.as_bytes())
    }

    /*
       pub fn get_from_query(&self, param: &str) -> Option<String> {
           let query = self.get_uri().query()?;

           for itm in query.split("&") {
               let mut parts = itm.split("=");

               let left = parts.next().unwrap().trim();

               if let Some(right) = parts.next() {
                   if left == param {
                       return Some(url_utils::decode_from_url_string(right.trim()).to_string());
                   }
               }
           }

           None
       }

       pub fn get_cookie(&self, cookie_name: &str) -> Option<&str> {
           let cookie_value = self.get_headers().get("Cookie")?;

           match cookie_value.to_str() {
               Ok(cookie_value) => crate::utils::get_cookie(cookie_value, cookie_name),
               Err(_) => None,
           }
       }

    pub fn get_authorization_token(&self) -> Option<&str> {
        let result = self.get_cookie(crate::consts::AUTHORIZED_COOKIE_NAME);
        result
    }
    */

    /// The parts and the body of the upstream request - and what its body, when it is held in
    /// memory, takes of all bodies held.
    async fn build_request(
        self,
        location: &ProxyPassLocation,
        ip: Option<String>,
    ) -> Result<(Parts, BuiltBody, BufferedBodyShare), ProxyPassError> {
        use http_body_util::BodyExt;

        let compress = location.compress;
        let location_id = location.config.id;

        let debug = crate::app::APP_CTX
            .debug_flags
            .is_location_debug(location_id);

        let mut parts = self.parts.clone();

        rewrite_mcp_path(&mut parts.uri, location);

        let content_size = parts
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<usize>().ok());

        // Forward the body straight through when the upstream can take it as a
        // stream: the client's frames go out as they arrive and nothing is held in
        // memory, whatever the size of the upload. Ruled out when the body itself
        // has to be handled right here — gzip needs it whole, a websocket
        // handshake is replayed from it — and when there is provably no body,
        // which keeps a bodyless request on the buffered path that still has
        // upstream failover.
        let stream_the_body = location.content_source.can_stream_request_body()
            && !compress
            && parts.headers.get("sec-websocket-key").is_none()
            && content_size != Some(0)
            && !hyper::body::Body::is_end_stream(&self.body);

        if stream_the_body {
            // `max_request_body`: a body which says it is larger goes nowhere.
            if let (Some(max_request_body), Some(content_size)) =
                (self.max_request_body, content_size)
            {
                if content_size > max_request_body {
                    return Err(ProxyPassError::ClientBodyTooLarge);
                }
            }

            // h2 carries no chunked framing: an unknown length is simply not
            // announced, and the h1 header saying otherwise must not travel.
            parts.headers.remove(TRANSFER_ENCODING);

            if debug {
                crate::app::APP_CTX.proxy_logs.write_location(
                    location_id,
                    ip.clone(),
                    format!(
                        "[{}]. Streaming request body upstream, announced size: {:?}. Headers: {:?}",
                        parts.uri,
                        content_size,
                        // What goes upstream: the headers of `request_with_header_only` are
                        // not among them any more.
                        crate::types::HeaderList::new(&parts.headers, &[])
                    ),
                );
            }

            // One which does not say, or says less than it brings, is cut as it passes the limit:
            // the upstream gets an error of the body, not the rest of it.
            let body = match self.max_request_body {
                Some(max_request_body) => http_body_util::Limited::new(self.body, max_request_body)
                    .map_err(|err| err.to_string())
                    .boxed(),
                None => self.body.map_err(|err| err.to_string()).boxed(),
            };

            return Ok((
                parts,
                BuiltBody::Streamed { body, content_size },
                BUFFERED_REQUEST_BODIES.share(),
            ));
        }

        let (bytes, held_body) = collect_client_body(
            self.body,
            self.body_idle_timeout,
            self.body_limits,
            &BUFFERED_REQUEST_BODIES,
        )
        .await?;

        let before_compress = bytes.len();

        let body = if compress && before_compress >= 2048 {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&bytes)?;
            let compressed_data = encoder.finish()?;
            let compressed_data_len = compressed_data.len();

            if debug {
                crate::app::APP_CTX.proxy_logs.write_location(
                    location_id,
                    ip.clone(),
                    format!("Compressed: {} -> {}", before_compress, compressed_data_len),
                );
            }

            parts.headers.remove(CONTENT_ENCODING);
            parts.headers.remove(CONTENT_TYPE);
            parts
                .headers
                .append(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
            parts.headers.append(
                CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );

            frame_whole_body(&mut parts.headers, compressed_data_len);

            BuiltBody::Buffered(http_body_util::Full::new(compressed_data.into()))
        } else {
            frame_whole_body(&mut parts.headers, bytes.len());

            BuiltBody::Buffered(into_full_body(bytes, location_id, ip.clone()))
        };

        if debug {
            crate::app::APP_CTX.proxy_logs.write_location(
                location_id,
                ip.clone(),
                format!(
                    "[{}]. After Conversion Request: {:?}.",
                    parts.uri,
                    crate::types::HeaderList::new(&parts.headers, &[])
                ),
            );
        }
        Ok((parts, body, held_body))
    }

    /// `identity`: who the request is of.
    pub fn process_headers(
        &mut self,
        proxy_pass: &HttpProxyPass,
        inner: &HttpProxyPassInner,
        location: &ProxyPassLocation,
        identity: Option<&HttpProxyPassIdentity>,
    ) {
        // What the client sent to tell who it is goes first: a header the settings add under
        // such a name (`X-Real-IP: ${ENDPOINT_IP}`) is the proxy's own. So do the headers of
        // `request_with_header_only`, which are the proxy's alone.
        take_away_client_ip_headers(&mut self.parts, &self.client);
        take_away_required_headers(
            &mut self.parts,
            &proxy_pass.endpoint_info.request_with_header_only,
        );

        modify_headers(
            inner,
            &mut self.parts,
            &location.config.modify_request_headers,
            identity,
            &self.client.ip,
        );

        modify_headers(
            inner,
            &mut self.parts,
            &proxy_pass.endpoint_info.modify_request_headers,
            identity,
            &self.client.ip,
        );

        apply_x_forwarded_for(&mut self.parts, &self.client);
        apply_cf_ip_country(&mut self.parts, &self.client, &proxy_pass.endpoint_info);
        apply_forwarded_user(&mut self.parts, identity);
    }
}

/// `X-Forwarded-User` and `X-Forwarded-ClientCertId`: who the request is of, or nothing - never
/// what the client sent under those names, in any spelling an upstream could read as them.
fn apply_forwarded_user(parts: &mut Parts, identity: Option<&HttpProxyPassIdentity>) {
    let sent_by_the_client: Vec<HeaderName> = parts
        .headers
        .keys()
        .filter(|name| crate::forwarded_user::is_header_name(name.as_str().as_bytes()))
        .cloned()
        .collect();

    for name in sent_by_the_client {
        parts.headers.remove(name);
    }

    let Some(identity) = identity else {
        return;
    };

    let headers = [
        (
            crate::forwarded_user::HEADER,
            crate::forwarded_user::value_of(identity),
        ),
        (
            crate::forwarded_user::CLIENT_CERT_ID_HEADER,
            crate::forwarded_user::client_cert_id_of(identity),
        ),
    ];

    for (name, value) in headers {
        let Some(Ok(value)) = value.map(HeaderValue::from_str) else {
            continue;
        };

        parts.headers.insert(HeaderName::from_static(name), value);
    }
}

/// Takes away every header the client sent which tells who it is and is not the proxy's to pass
/// on - see [`crate::cloudflare::RequestClient::takes_away_header`].
fn take_away_client_ip_headers(parts: &mut Parts, client: &crate::cloudflare::RequestClient) {
    let sent_by_the_client: Vec<HeaderName> = parts
        .headers
        .keys()
        .filter(|name| client.takes_away_header(name.as_str().as_bytes()))
        .cloned()
        .collect();

    for name in sent_by_the_client {
        parts.headers.remove(name);
    }
}

/// Takes away the headers of `request_with_header_only`, in every spelling an upstream could read
/// as one of them - see [`crate::required_headers::RequiredHeaders::covers`].
fn take_away_required_headers(
    parts: &mut Parts,
    required: &crate::required_headers::RequiredHeaders,
) {
    if required.is_empty() {
        return;
    }

    let sent_by_the_client: Vec<HeaderName> = parts
        .headers
        .keys()
        .filter(|name| required.covers(name.as_str().as_bytes()))
        .cloned()
        .collect();

    for name in sent_by_the_client {
        parts.headers.remove(name);
    }
}

/// `X-Forwarded-For` of the client - the proxy's own: what the client sent under the name is
/// taken away before. Nothing on a unix socket, where the header goes on as it came.
fn apply_x_forwarded_for(parts: &mut Parts, client: &crate::cloudflare::RequestClient) {
    let Some(value) = client.x_forwarded_for() else {
        return;
    };

    if let Ok(value) = HeaderValue::from_str(&value) {
        parts
            .headers
            .insert(HeaderName::from_static("x-forwarded-for"), value);
    }
}

fn apply_cf_ip_country(
    parts: &mut Parts,
    client: &crate::cloudflare::RequestClient,
    endpoint: &HttpEndpointInfo,
) {
    if !endpoint.inject_country {
        return;
    }
    let Some(ip) = client.ip.get_ip_addr() else {
        return;
    };
    let Some(code) = crate::ip_db::lookup_country(ip) else {
        return;
    };
    let value = HeaderValue::from_bytes(&code).unwrap();
    parts
        .headers
        .insert(HeaderName::from_static("cf-ipcountry"), value);
}

/// The framing of a body which goes upstream whole: its length, and nothing else.
///
/// The headers of the client go along with the body, and they describe it as the client sent it:
/// a `transfer-encoding: chunked` of an http/1.1 client tells of chunks which are gone once the
/// body is collected, and an h2 body comes with no length at all. An http/1.1 upstream reads from
/// these headers where the request ends - left as they are, the body, or a part of it, is read
/// as one more request (request smuggling), past the checks of the location and on a pooled
/// connection other clients share.
///
/// An empty body gets a `content-length` only if the client sent one: a request without a body
/// is framed by having none.
fn frame_whole_body(headers: &mut HeaderMap, body_len: usize) {
    // Every value of each: two `content-length`s are framing of their own.
    let had_content_length = headers.remove(CONTENT_LENGTH).is_some();
    headers.remove(TRANSFER_ENCODING);

    if body_len > 0 || had_content_length {
        headers.insert(CONTENT_LENGTH, HeaderValue::from(body_len));
    }
}

fn into_full_body(src: Bytes, location_id: i64, ip: Option<String>) -> Full<Bytes> {
    if crate::app::APP_CTX
        .debug_flags
        .is_location_debug(location_id)
    {
        crate::app::APP_CTX.proxy_logs.write_location(
            location_id,
            ip,
            format!("Body Len: {}", src.len()),
        );
    }

    http_body_util::Full::new(src)
}

fn modify_headers(
    inner: &HttpProxyPassInner,
    parts: &mut Parts,
    modify_headers: &ModifyHeadersConfig,
    identity: Option<&HttpProxyPassIdentity>,
    client_ip: &ConnectionIp,
) {
    for remove_header in modify_headers.iter_remove() {
        parts.headers.remove(remove_header.as_str());
    }

    for (header, value) in modify_headers.iter_add() {
        // A header the settings add is never taken from the client, even when there is
        // nothing to write in it: `${CLIENT_CERT_CN}` of a request with no user is empty,
        // and a client-sent header of that name would otherwise reach the upstream as a
        // user the proxy vouched for. The h1 path drops every header named in `add` the
        // same way (`has_to_be_removed`).
        parts.headers.remove(header.as_str());

        if value.as_str().is_empty() {
            continue;
        }
        let value = inner.populate_value(value, parts, identity, client_ip);
        if value.as_str().is_empty() {
            continue;
        }
        parts.headers.insert(
            HeaderName::from_bytes(header.as_bytes()).unwrap(),
            value.as_str().parse().unwrap(),
        );
    }
}

impl HttpRequestReader for Parts {
    fn get_cookie<'s>(&'s self, cookie_name: &str) -> Option<&'s str> {
        let cookie_header = self.headers.get("cookie")?;

        match cookie_header.to_str() {
            Ok(str) => crate::utils::get_cookie(str, cookie_name),
            Err(_) => None,
        }
    }

    fn get_path(&self) -> &str {
        self.uri.path()
    }

    fn get_path_and_query(&self) -> Option<&str> {
        let path_and_query = self.uri.path_and_query()?;
        Some(path_and_query.as_str())
    }

    fn get_query_string(&self) -> Option<&str> {
        let path_and_query = self.uri.path_and_query()?;
        path_and_query.query()
    }

    fn get_host(&self) -> Option<&str> {
        self.uri.host()
    }
}

/// The whole body of a client's request, for an upstream the proxy can not stream it to (an
/// http/1.1 one, a body to compress, a websocket handshake). Each frame has to come within
/// `idle_timeout` of the one before - the endpoint's `read_timeout`, as on the http/1.1 path -
/// so a client which sends its body a byte now and then can not hold the request forever. A
/// body that is streamed to an h2 upstream is not timed here: a gRPC stream may rightly be
/// silent for long, and its upstream sees every byte as it comes.
///
/// The body is held in memory until the upstream answered, so it is limited (see
/// [`BufferedBodyLimits`]). A body which says it is larger than `limits.max_body` is refused before
/// a byte of it is read, and one which comes larger as soon as it does: `413`. A body which would
/// take the bodies held all together over `limits.max_total`: `503`. What it takes of `bodies`
/// comes back with it, to be given back when that is dropped - at once, when it is refused.
///
/// The frames are copied into one buffer as they come: a frame can keep a larger buffer of hyper
/// alive than its own length, and joining the frames at the end would hold the body twice.
async fn collect_client_body<B>(
    mut body: B,
    idle_timeout: std::time::Duration,
    limits: BufferedBodyLimits,
    bodies: &'static BufferedBodies,
) -> Result<(Bytes, BufferedBodyShare), ProxyPassError>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    ProxyPassError: From<B::Error>,
{
    // `content-length`: known before anything of the body is read.
    if body.size_hint().lower() > limits.max_body as u64 {
        return Err(ProxyPassError::ClientBodyTooLarge);
    }

    let mut held = bodies.share();
    let mut collected = BytesMut::new();

    loop {
        let frame = match tokio::time::timeout(idle_timeout, body.frame()).await {
            Ok(Some(frame)) => frame?,
            Ok(None) => break,
            Err(_) => return Err(ProxyPassError::ClientBodyTimeout),
        };

        // Trailers are dropped, as `Collected::to_bytes` drops them.
        let Ok(data) = frame.into_data() else {
            continue;
        };

        if collected.len().saturating_add(data.len()) > limits.max_body {
            return Err(ProxyPassError::ClientBodyTooLarge);
        }

        if !held.take(data.len(), limits.max_total) {
            return Err(ProxyPassError::BufferedBodiesFull);
        }

        collected.extend_from_slice(&data);
    }

    Ok((collected.freeze(), held))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A request that arrived over h2 carries an ABSOLUTE uri, and an h2
    /// upstream request without `:scheme` / `:authority` is malformed — h2
    /// refuses to send it at all. So the rewrite must swap the path only.
    #[test]
    fn an_absolute_uri_keeps_its_scheme_and_authority() {
        let mut uri: Uri = "https://mcp.example.com/logs-XXX".parse().unwrap();

        apply_upstream_path(&mut uri, "/mcp", "test");

        assert_eq!(uri.to_string(), "https://mcp.example.com/mcp");
        assert!(uri.scheme().is_some());
        assert!(uri.authority().is_some());
    }

    /// A request that arrived over h1 is origin-form and must stay origin-form.
    #[test]
    fn an_origin_form_uri_stays_origin_form() {
        let mut uri: Uri = "/logs-XXX".parse().unwrap();

        apply_upstream_path(&mut uri, "/mcp", "test");

        assert_eq!(uri.to_string(), "/mcp");
    }

    /// The client's query string carries nothing an MCP upstream can use; the
    /// upstream's own query, if it has one, is what must survive.
    #[test]
    fn the_upstream_query_replaces_the_client_one() {
        let mut uri: Uri = "https://mcp.example.com/logs-XXX?session=42"
            .parse()
            .unwrap();

        apply_upstream_path(&mut uri, "/mcp?tenant=a", "test");

        assert_eq!(uri.to_string(), "https://mcp.example.com/mcp?tenant=a");
    }

    /// A path that cannot be applied leaves the request as it was, rather than
    /// producing a half-rewritten uri.
    #[test]
    fn an_invalid_upstream_path_leaves_the_uri_alone() {
        let mut uri: Uri = "https://mcp.example.com/logs-XXX".parse().unwrap();

        apply_upstream_path(&mut uri, "not a path", "test");

        assert_eq!(uri.to_string(), "https://mcp.example.com/logs-XXX");
    }

    // --- `collect_client_body`: the limits of a body held whole ---------------------------------

    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use hyper::body::{Frame, SizeHint};

    const IDLE: std::time::Duration = std::time::Duration::from_secs(5);

    type Frames = futures::stream::Iter<std::vec::IntoIter<Result<Frame<Bytes>, std::io::Error>>>;

    /// A body which comes in `frames`, saying nothing of its size - as an h2 body without a
    /// `content-length` does.
    fn frames(sizes: &[usize]) -> http_body_util::StreamBody<Frames> {
        let frames: Vec<_> = sizes
            .iter()
            .map(|size| Ok(Frame::data(Bytes::from(vec![b'x'; *size]))))
            .collect();

        http_body_util::StreamBody::new(futures::stream::iter(frames))
    }

    /// A body which says how large it is - a `content-length` - and must not be read.
    struct Announced(u64);

    impl hyper::body::Body for Announced {
        type Data = Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
            panic!("a body which says it is too large was read");
        }

        fn size_hint(&self) -> SizeHint {
            SizeHint::with_exact(self.0)
        }
    }

    fn limits(max_body: usize, max_total: usize) -> BufferedBodyLimits {
        BufferedBodyLimits {
            max_body,
            max_total,
        }
    }

    #[tokio::test]
    async fn a_body_within_the_limit_is_collected_and_counted_until_it_is_dropped() {
        static BODIES: BufferedBodies = BufferedBodies::new();

        let (bytes, held) =
            collect_client_body(frames(&[600, 0, 424]), IDLE, limits(1024, 4096), &BODIES)
                .await
                .unwrap();

        assert_eq!(bytes.len(), 1024);
        assert_eq!(held.bytes(), 1024);
        assert_eq!(BODIES.held(), 1024);

        drop(held);
        assert_eq!(BODIES.held(), 0);
    }

    #[tokio::test]
    async fn a_body_which_comes_larger_than_the_limit_is_refused_and_gives_back_what_it_took() {
        static BODIES: BufferedBodies = BufferedBodies::new();

        let result =
            collect_client_body(frames(&[600, 600]), IDLE, limits(1024, 4096), &BODIES).await;

        assert!(matches!(result, Err(ProxyPassError::ClientBodyTooLarge)));
        assert_eq!(BODIES.held(), 0);
    }

    #[tokio::test]
    async fn a_body_which_says_it_is_larger_than_the_limit_is_refused_before_it_is_read() {
        static BODIES: BufferedBodies = BufferedBodies::new();

        let result = collect_client_body(Announced(1025), IDLE, limits(1024, 4096), &BODIES).await;

        assert!(matches!(result, Err(ProxyPassError::ClientBodyTooLarge)));
    }

    #[tokio::test]
    async fn a_body_over_what_all_bodies_may_take_together_waits_for_none_and_is_refused() {
        static BODIES: BufferedBodies = BufferedBodies::new();

        let (_, first) = collect_client_body(frames(&[800]), IDLE, limits(1000, 1000), &BODIES)
            .await
            .unwrap();

        let second =
            collect_client_body(frames(&[100, 300]), IDLE, limits(1000, 1000), &BODIES).await;
        assert!(matches!(second, Err(ProxyPassError::BufferedBodiesFull)));
        assert_eq!(
            BODIES.held(),
            800,
            "the refused one gave back its first frame"
        );

        drop(first);

        let (_, third) =
            collect_client_body(frames(&[100, 300]), IDLE, limits(1000, 1000), &BODIES)
                .await
                .unwrap();
        assert_eq!(third.bytes(), 400);
    }

    #[tokio::test]
    async fn a_body_which_stops_coming_is_408_and_gives_back_what_it_took() {
        static BODIES: BufferedBodies = BufferedBodies::new();

        // One frame, and then nothing more - for ever.
        use futures::StreamExt;
        let first: Result<Frame<Bytes>, std::io::Error> =
            Ok(Frame::data(Bytes::from_static(b"some")));
        let body = http_body_util::StreamBody::new(
            futures::stream::iter(vec![first]).chain(futures::stream::pending()),
        );

        let result = collect_client_body(
            body,
            std::time::Duration::from_millis(100),
            limits(1024, 4096),
            &BODIES,
        )
        .await;

        assert!(matches!(result, Err(ProxyPassError::ClientBodyTimeout)));
        assert_eq!(BODIES.held(), 0);
    }
}

use std::io::Write;

use bytes::Bytes;
use flate2::{write::GzEncoder, Compression};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, header::*, Method, Request, Uri};
use hyper_tungstenite::{tungstenite::http::request::Parts, HyperWebsocket};

use crate::{configurations::*, types::*};

use super::{HttpProxyPass, HttpProxyPassInner, ProxyPassError, ProxyPassLocation};

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
    pub fn new(src: hyper::Request<hyper::body::Incoming>) -> Self {
        let (parts, body) = src.into_parts();

        Self { parts, body }
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
        // Client source IP for log attribution (every endpoint/location event
        // is initiated by a TCP connection, so the IP is available via inner).
        let ip = proxy_pass
            .inner
            .load_full()
            .and_then(|inner| inner.connection_ip.get_ip_log());

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
            let (parts, body) = self.build_request(location, ip).await?;

            return Ok(TransformedRequest {
                req_parts: parts.clone(),
                request: body.into_transformed(parts),
                web_socket_upgrade: None,
            });
        }

        let dest_http1 = dest_http1.unwrap();

        if !client_is_http1(self.parts.version) && dest_http1 {
            return self.http2_to_http1(location, ip).await;
        }

        let (parts, body) = self.build_request(location, ip.clone()).await?;

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
                    request.headers()
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
                    request.headers()
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

        let collected = self.body.collect().await?;
        let bytes = collected.to_bytes();

        let req_parts = self.parts.clone();

        let body = into_full_body(bytes, location.config.id, ip.clone());

        let request = builder.body(body).unwrap();

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
                    request.headers()
                ),
            );
        }

        Ok(TransformedRequest {
            req_parts,
            request: TransformedRequestBody::Buffered(request),
            web_socket_upgrade: None,
        })
    }

    pub fn uri(&self) -> &Uri {
        &self.parts.uri
    }

    /// Raw `Authorization` value as received, for the location's `auth_header`
    /// gate. `None` when the header is absent.
    pub fn get_authorization_header(&self) -> Option<&[u8]> {
        self.parts
            .headers
            .get(hyper::header::AUTHORIZATION)
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

    async fn build_request(
        self,
        location: &ProxyPassLocation,
        ip: Option<String>,
    ) -> Result<(Parts, BuiltBody), ProxyPassError> {
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
            // h2 carries no chunked framing: an unknown length is simply not
            // announced, and the h1 header saying otherwise must not travel.
            parts.headers.remove(TRANSFER_ENCODING);

            if debug {
                crate::app::APP_CTX.proxy_logs.write_location(
                    location_id,
                    ip.clone(),
                    format!(
                        "[{}]. Streaming request body upstream, announced size: {:?}. Headers: {:?}",
                        parts.uri, content_size, parts.headers
                    ),
                );
            }

            return Ok((
                parts,
                BuiltBody::Streamed {
                    body: self.body.map_err(|err| err.to_string()).boxed(),
                    content_size,
                },
            ));
        }

        let collected = self.body.collect().await?;
        let bytes = collected.to_bytes();

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

            parts.headers.remove(CONTENT_LENGTH);

            parts.headers.append(
                CONTENT_LENGTH,
                HeaderValue::from_str(compressed_data_len.to_string().as_str()).unwrap(),
            );

            BuiltBody::Buffered(http_body_util::Full::new(compressed_data.into()))
        } else {
            BuiltBody::Buffered(into_full_body(bytes, location_id, ip.clone()))
        };

        if debug {
            crate::app::APP_CTX.proxy_logs.write_location(
                location_id,
                ip.clone(),
                format!(
                    "[{}]. After Conversion Request: {:?}.",
                    parts.uri, parts.headers
                ),
            );
        }
        Ok((parts, body))
    }

    pub fn process_headers(
        &mut self,
        proxy_pass: &HttpProxyPass,
        inner: &HttpProxyPassInner,
        location: &ProxyPassLocation,
    ) {
        modify_headers(
            inner,
            &mut self.parts,
            &location.config.modify_request_headers,
        );

        modify_headers(
            inner,
            &mut self.parts,
            &proxy_pass.endpoint_info.modify_request_headers,
        );

        apply_auto_x_forwarded_for(&mut self.parts, inner);
        apply_cf_ip_country(&mut self.parts, inner, &proxy_pass.endpoint_info);
    }
}

fn apply_auto_x_forwarded_for(parts: &mut Parts, inner: &HttpProxyPassInner) {
    let Some(ip) = inner.connection_ip.get_ip_addr() else {
        return;
    };
    let ip_str = ip.to_string();

    let new_value = match parts.headers.get("x-forwarded-for") {
        Some(existing) => match existing.to_str() {
            Ok(s) => format!("{},{}", s, ip_str),
            Err(_) => ip_str,
        },
        None => ip_str,
    };

    parts.headers.insert(
        HeaderName::from_static("x-forwarded-for"),
        new_value.parse().unwrap(),
    );
}

fn apply_cf_ip_country(parts: &mut Parts, inner: &HttpProxyPassInner, endpoint: &HttpEndpointInfo) {
    if !endpoint.inject_country {
        return;
    }
    let Some(ip) = inner.connection_ip.get_ip_addr() else {
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
) {
    for remove_header in modify_headers.iter_remove() {
        parts.headers.remove(remove_header.as_str());
    }

    for (header, value) in modify_headers.iter_add() {
        if value.as_str().is_empty() {
            continue;
        }
        let value = inner.populate_value(value, parts);
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
}

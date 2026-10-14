use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper_util::rt::TokioIo;
use my_http_client::utils::into_full_body_response;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::{
    configurations::*,
    http_proxy_pass::GoogleAuthResult,
    tcp_gateway::forwarded_connection::ProxyConnectionAbort,
    tcp_listener::https::ClientCertificateData,
    types::{ConnectionIp, HttpTimeouts},
};

use super::{
    HttpListenPortInfo, HttpProxyPassIdentity, HttpProxyPassInner, HttpRequestBuilder,
    ProxyPassError, ProxyPassLocations, WebSocketPumpContext, WebSocketUpgrade,
};

pub struct HttpProxyPass {
    pub inner: ArcSwapOption<HttpProxyPassInner>,
    pub listening_port_info: HttpListenPortInfo,
    pub endpoint_info: Arc<HttpEndpointInfo>,
}

impl HttpProxyPass {
    pub async fn new(
        connection_ip: ConnectionIp,
        endpoint_info: Arc<HttpEndpointInfo>,
        listening_port_info: HttpListenPortInfo,
        client_cert: Option<Arc<ClientCertificateData>>,
    ) -> Self {
        let locations = ProxyPassLocations::new(&endpoint_info).await;
        Self {
            inner: ArcSwapOption::from(Some(Arc::new(HttpProxyPassInner::new(
                client_cert.map(HttpProxyPassIdentity::ClientCert),
                locations,
                listening_port_info.clone(),
                connection_ip,
            )))),

            listening_port_info,
            endpoint_info,
        }
    }

    pub async fn send_payload(
        &self,
        req: hyper::Request<hyper::body::Incoming>,
        connection_ip: ConnectionIp,
        _debug: bool,
    ) -> Result<hyper::Result<hyper::Response<BoxBody<Bytes, String>>>, ProxyPassError> {
        let endpoint = self.endpoint_info.host_endpoint.as_str();
        let endpoint_debug = crate::app::APP_CTX.debug_flags.is_endpoint_debug(endpoint);
        let ip = connection_ip.get_ip_log();

        if endpoint_debug {
            crate::app::APP_CTX.proxy_logs.write(
                endpoint,
                None,
                ip.clone(),
                format!("Request. Uri: [{}] Headers: {:?}", req.uri(), req.headers()),
            );
        }

        // The endpoint's IP allow-list, for every request. An `https2` connection
        // is checked when it is accepted and when its request handler resolves
        // the vhost; an `http2` one is checked nowhere else.
        if let Some(ip_list_id) = self.endpoint_info.whitelisted_ip_list_id.as_ref() {
            if let Some(client_ip) = connection_ip.get_ip_addr() {
                let is_whitelisted = crate::app::APP_CTX
                    .current_configuration
                    .get(|config| {
                        config
                            .white_list_ip_list
                            .is_white_listed(ip_list_id, &client_ip)
                    })
                    .await;

                if !is_whitelisted {
                    return Err(ProxyPassError::IpRestricted(
                        self.listening_port_info.listen_host.to_string(),
                    ));
                }
            }
        }

        // An endpoint which was given an access setting it can not apply serves
        // nobody. Everybody is refused without a word; a debug ip is told the reason.
        if let Some(reason) = self.endpoint_info.not_served_reason.as_ref() {
            let is_debug_ip = crate::app::APP_CTX.debug_ip.is_debug_ip(&connection_ip);

            return Ok(Ok(crate::error_templates::not_served_hyper_response(
                reason,
                is_debug_ip,
            )));
        }

        // A path with a `..`, a `.` or an empty segment is not matched to a
        // location - the same rule as the h1 pipeline has. Answered as an ordinary
        // response, not as an error: an error is written to the log, for every
        // scanner which comes by.
        if crate::types::has_ambiguous_segment(req.uri().path()) {
            return Ok(Ok(
                crate::http_content_source::RequestExecutorResult::bad_request().into(),
            ));
        }

        // The proxy's own OAuth 2.1 server, when this endpoint has an `oauth:`
        // block. Runs before the location is resolved because its own paths
        // (`/.well-known/…`, `/oauth/…`) match no configured location, and it
        // needs the request body intact for the token endpoint.
        let req = match super::run_oauth_gate_h2(&self.endpoint_info, &connection_ip, req).await {
            super::OAuthGateH2Outcome::Proceed(req) => req,
            super::OAuthGateH2Outcome::Answered(response) => return Ok(Ok(response)),
        };

        let mut req = HttpRequestBuilder::new(req);

        let (request, content_source, location_index, location_debug) = {
            let Some(inner) = self.inner.load_full() else {
                return Err(ProxyPassError::Disposed);
            };

            match self.handle_auth_with_g_auth(&req).await {
                GoogleAuthResult::Passed(user) => {
                    if let Some(email) = user {
                        inner
                            .identity
                            .store(Some(Arc::new(HttpProxyPassIdentity::GoogleUser(email))));
                    }
                }
                GoogleAuthResult::Content(content) => return Ok(content),
                GoogleAuthResult::DomainIsNotAuthorized => {
                    return Err(ProxyPassError::Unauthorized);
                }
            }

            if let Some(allowed_user_list_id) = self.endpoint_info.allowed_user_list_id.as_ref() {
                // No identity means NOT allowed — an anonymous request must not
                // bypass the allow-list. Same fail-closed rule as the h1 path's
                // user_is_allowed (that one answers 401, this path 403).
                let allowed = match inner.identity.load_full() {
                    Some(identity) => {
                        crate::app::APP_CTX
                            .allowed_users_list
                            .is_allowed(allowed_user_list_id, identity.as_str())
                            .await
                    }
                    None => false,
                };
                if !allowed {
                    return Err(ProxyPassError::UserIsForbidden);
                }
            }

            let location_index = inner.locations.find_location_index(
                req.uri(),
                self.endpoint_info.host_endpoint.as_str(),
                ip.clone(),
                endpoint_debug,
            )?;

            let proxy_pass_location = inner.locations.find(&location_index);

            // The location's own IP allow-list: before `auth_header`, and before
            // anything of the request body is read.
            if !proxy_pass_location
                .config
                .ip_is_allowed(&connection_ip)
                .await
            {
                return Err(ProxyPassError::IpRestricted(
                    self.listening_port_info.listen_host.to_string(),
                ));
            }

            // Per-location `auth_header` gate — same rule as the h1 pipeline's
            // `H1Reader::authorize`: refused before anything is sent upstream,
            // and an absent header is indistinguishable from a wrong one.
            if !proxy_pass_location
                .config
                .auth_header_accepts(req.get_authorization_header())
            {
                return Err(ProxyPassError::Unauthorized);
            }

            let location_debug = crate::app::APP_CTX
                .debug_flags
                .is_location_debug(location_index.id);

            req.process_headers(self, &inner, proxy_pass_location);

            let request = req.into_request(self, proxy_pass_location).await?;

            if location_debug {
                crate::app::APP_CTX.proxy_logs.write(
                    self.endpoint_info.host_endpoint.as_str(),
                    Some(location_index.id),
                    ip.clone(),
                    format!("Request parts: {:?}", request.req_parts),
                );
            }

            (
                request,
                proxy_pass_location.content_source.clone(),
                location_index,
                location_debug,
            )
        };

        // Upstream-unreachable failures are always captured per-location,
        // regardless of debug mode — debug only adds the request/response
        // detail above and below.
        let sent = match request.request {
            super::TransformedRequestBody::Buffered(req) => content_source.send_request(req).await,
            super::TransformedRequestBody::Streamed {
                request,
                content_size,
            } => {
                content_source
                    .send_streamed_request(request, content_size)
                    .await
            }
        };

        let result = match sent {
            Ok(result) => result,
            Err(err) => {
                crate::app::APP_CTX.proxy_logs.write_location(
                    location_index.id,
                    ip.clone(),
                    format!("Upstream request failed: {:?}", err),
                );
                return Err(err);
            }
        };

        let mut response = match result {
            super::content_source::HttpResponse::Response(response) => {
                if location_debug {
                    crate::app::APP_CTX.proxy_logs.write(
                        self.endpoint_info.host_endpoint.as_str(),
                        Some(location_index.id),
                        ip.clone(),
                        format!("Response headers: {:?}", response.headers()),
                    );
                }
                response
            }
            super::content_source::HttpResponse::WebSocketUpgrade {
                stream,
                response,
                disconnection,
                leftover,
            } => {
                if location_debug {
                    crate::app::APP_CTX.proxy_logs.write(
                        self.endpoint_info.host_endpoint.as_str(),
                        Some(location_index.id),
                        ip.clone(),
                        format!(
                            "Response as web-socket upgrade. Headers: {:?}",
                            response.headers()
                        ),
                    );
                }
                let request_host_for_metric: Option<String> = request
                    .req_parts
                    .headers
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
                    .or_else(|| request.req_parts.uri.host().map(|s| s.to_string()))
                    .map(|s| {
                        let host_no_port = match s.find(':') {
                            Some(idx) => &s[..idx],
                            None => s.as_str(),
                        };
                        host_no_port.trim().to_string()
                    });
                let domain: Option<String> = self
                    .endpoint_info
                    .tracked_domain(request_host_for_metric.as_deref())
                    .map(str::to_owned);
                let pump_context = WebSocketPumpContext {
                    log_scope: crate::app::ProxyLogScope::new(
                        Arc::new(self.endpoint_info.host_endpoint.as_str().to_string()),
                        location_index.id,
                        ip.clone(),
                    ),
                    disconnection,
                    trace_payload: location_debug,
                    domain,
                    timeouts: self.endpoint_info.timeouts,
                    upstream_abort: None,
                };
                match *stream {
                    super::content_source::WebSocketUpgradeStream::TcpStream(tcp_stream) => {
                        spawn_websocket_pump(
                            request.web_socket_upgrade,
                            tcp_stream,
                            leftover,
                            response,
                            pump_context,
                        )
                    }

                    super::content_source::WebSocketUpgradeStream::UnixStream(unix_stream) => {
                        spawn_websocket_pump(
                            request.web_socket_upgrade,
                            unix_stream,
                            leftover,
                            response,
                            pump_context,
                        )
                    }

                    super::content_source::WebSocketUpgradeStream::TlsStream(tls_stream) => {
                        spawn_websocket_pump(
                            request.web_socket_upgrade,
                            *tls_stream,
                            leftover,
                            response,
                            pump_context,
                        )
                    }
                    super::content_source::WebSocketUpgradeStream::SshChannel(async_channel) => {
                        spawn_websocket_pump(
                            request.web_socket_upgrade,
                            async_channel,
                            leftover,
                            response,
                            pump_context,
                        )
                    }
                    super::content_source::WebSocketUpgradeStream::GatewayStream(
                        gateway_stream,
                    ) => {
                        let pump_context = WebSocketPumpContext {
                            upstream_abort: Some(gateway_stream.abort_handle()),
                            ..pump_context
                        };
                        spawn_websocket_pump(
                            request.web_socket_upgrade,
                            gateway_stream,
                            leftover,
                            response,
                            pump_context,
                        )
                    }
                    super::content_source::WebSocketUpgradeStream::H2Upgraded(h2_upgraded) => {
                        spawn_h2_websocket_pump(
                            request.web_socket_upgrade,
                            h2_upgraded,
                            leftover,
                            response,
                            pump_context,
                        )
                    }
                }
            }
        };

        let Some(inner) = self.inner.load_full() else {
            return Err(ProxyPassError::Disposed);
        };

        super::http_response_builder::modify_resp_headers(
            self,
            &inner,
            &request.req_parts,
            response.headers_mut(),
            &location_index,
        );

        Ok(Ok(response))
    }

    pub async fn dispose(&self) {
        self.inner.store(None);
    }
}

fn spawn_websocket_pump<S>(
    web_socket_upgrade: Option<WebSocketUpgrade>,
    upstream: S,
    upstream_leftover: Vec<u8>,
    fallback_response: hyper::Response<BoxBody<Bytes, String>>,
    ctx: WebSocketPumpContext,
) -> hyper::Response<BoxBody<Bytes, String>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    let Some(web_socket_upgrade) = web_socket_upgrade else {
        return fallback_response;
    };

    match web_socket_upgrade {
        WebSocketUpgrade::H1 {
            upgrade_response,
            server_web_socket,
        } => {
            crate::app::spawn_named(
                "ws_pump_h1_start",
                super::start_web_socket_loop(server_web_socket, upstream, upstream_leftover, ctx),
            );
            into_full_body_response(upgrade_response)
        }
        WebSocketUpgrade::H2 {
            upgrade_response,
            on_upgrade,
        } => {
            crate::app::spawn_named(
                "ws_pump_h2_extended_connect_h1",
                pump_h2_extended_connect(on_upgrade, upstream, upstream_leftover, ctx),
            );
            into_full_body_response(upgrade_response)
        }
    }
}

fn spawn_h2_websocket_pump<S>(
    web_socket_upgrade: Option<WebSocketUpgrade>,
    upstream: S,
    upstream_leftover: Vec<u8>,
    fallback_response: hyper::Response<BoxBody<Bytes, String>>,
    ctx: WebSocketPumpContext,
) -> hyper::Response<BoxBody<Bytes, String>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Some(web_socket_upgrade) = web_socket_upgrade else {
        return fallback_response;
    };

    match web_socket_upgrade {
        WebSocketUpgrade::H2 {
            upgrade_response,
            on_upgrade,
        } => {
            crate::app::spawn_named(
                "ws_pump_h2_extended_connect_h2",
                pump_h2_extended_connect(on_upgrade, upstream, upstream_leftover, ctx),
            );
            into_full_body_response(upgrade_response)
        }
        WebSocketUpgrade::H1 {
            upgrade_response, ..
        } => {
            ctx.log_scope.write(
                "Unexpected h1 WebSocketUpgrade for h2 upstream — returning fallback response"
                    .to_string(),
            );
            into_full_body_response(upgrade_response)
        }
    }
}

/// A raw byte pump: it decodes no websocket frames, so `trace_payload` has nothing to trace.
pub(crate) async fn pump_h2_extended_connect<S>(
    on_upgrade: hyper::upgrade::OnUpgrade,
    upstream: S,
    upstream_leftover: Vec<u8>,
    ctx: WebSocketPumpContext,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let WebSocketPumpContext {
        log_scope,
        disconnection,
        domain,
        timeouts,
        upstream_abort,
        ..
    } = ctx;

    let upgraded = match on_upgrade.await {
        Ok(upgraded) => upgraded,
        Err(err) => {
            log_scope.write(format!("h2 extended-CONNECT upgrade failed: {:?}", err));
            super::reset_upstream(upstream_abort.as_ref());
            disconnection.web_socket_disconnect();
            return;
        }
    };

    let mut upgraded = TokioIo::new(upgraded);

    // This is a raw byte pump, not a websocket decoder, so the leftover is just
    // written out ahead of the loop — same ordering guarantee `copy_streams`
    // gives the h1 path by seeding its buffer with it.
    if !upstream_leftover.is_empty() {
        if let Some(domain) = domain.as_ref() {
            crate::app::APP_CTX
                .traffic
                .record_ws_s2c(domain, upstream_leftover.len() as u64);
        }

        if let Err(err) = upgraded.write_all(upstream_leftover.as_slice()).await {
            log_scope.write(format!(
                "h2 extended-CONNECT leftover write failed: {:?}",
                err
            ));
            super::reset_upstream(upstream_abort.as_ref());
            disconnection.web_socket_disconnect();
            return;
        }
    }

    // Reads on `client_side` are bytes coming FROM the client → upstream (c2s).
    // Reads on `upstream_side` are bytes coming FROM the upstream → client (s2c).
    // `tokio::io::copy_bidirectional` offers no idle hook, so we run a
    // per-direction copy with a write timeout (default 30s) and a session idle
    // timeout (read_timeout, default 180s, with neither direction moving bytes).
    match domain {
        Some(domain) => {
            let client_side = crate::tcp_utils::MeteredStream::new(
                upgraded,
                crate::tcp_utils::WsTrafficRecorder {
                    domain: domain.clone(),
                    direction: crate::tcp_utils::WsDirection::ClientToServer,
                },
            );
            let upstream_side = crate::tcp_utils::MeteredStream::new(
                upstream,
                crate::tcp_utils::WsTrafficRecorder {
                    domain,
                    direction: crate::tcp_utils::WsDirection::ServerToClient,
                },
            );
            pump_bidirectional_with_timeouts(
                client_side,
                upstream_side,
                timeouts,
                log_scope,
                upstream_abort.as_ref(),
            )
            .await;
        }
        None => {
            pump_bidirectional_with_timeouts(
                upgraded,
                upstream,
                timeouts,
                log_scope,
                upstream_abort.as_ref(),
            )
            .await;
        }
    };

    disconnection.web_socket_disconnect();
}

/// How one direction of [`pump_bidirectional_with_timeouts`] ended.
enum DirectionEnd {
    /// Its reader ended, or the peer of its writer is gone: the other direction goes on with
    /// what its own peer still sends.
    Finished,
    /// The session went idle: it ends.
    Idle,
    /// A write timed out or a read failed: the session ends, and the upstream connection is
    /// reset.
    Failed,
}

/// Bidirectional copy over raw tokio streams with a per-direction write timeout
/// and a session idle timeout: `read_timeout` with neither direction moving
/// bytes. A write timeout, a read error or the idle timeout end the session at
/// once - the first two reset the upstream connection. A direction which just
/// ends - its reader closed, or its writer's peer gone - leaves the other one to
/// deliver what its own peer still sends, until that ends too.
async fn pump_bidirectional_with_timeouts<A, B>(
    client_side: A,
    upstream_side: B,
    timeouts: HttpTimeouts,
    log_scope: crate::app::ProxyLogScope,
    upstream_abort: Option<&ProxyConnectionAbort>,
) where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (client_read, client_write) = tokio::io::split(client_side);
    let (upstream_read, upstream_write) = tokio::io::split(upstream_side);

    let pumps = crate::tcp_utils::ConnectionPumps::new(timeouts);

    let c2s = copy_one_direction(
        client_read,
        upstream_write,
        &pumps,
        "c2s",
        log_scope.clone(),
        upstream_abort,
    );
    let s2c = copy_one_direction(
        upstream_read,
        client_write,
        &pumps,
        "s2c",
        log_scope.clone(),
        upstream_abort,
    );

    tokio::pin!(c2s, s2c);

    // An upstream which answered and closed refuses the client's next frame while its last
    // frames, the Close among them, are still on their way to the client: c2s ends then, and s2c
    // still delivers them.
    tokio::select! {
        end = &mut c2s => {
            if let DirectionEnd::Finished = end {
                s2c.await;
            }
        }
        end = &mut s2c => {
            if let DirectionEnd::Finished = end {
                c2s.await;
            }
        }
    }

    log_scope.write("h2 ext-CONNECT WS pump finished".to_string());
}

async fn copy_one_direction<R, W>(
    mut reader: R,
    mut writer: W,
    pumps: &crate::tcp_utils::ConnectionPumps,
    dir: &'static str,
    log_scope: crate::app::ProxyLogScope,
    upstream_abort: Option<&ProxyConnectionAbort>,
) -> DirectionEnd
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = vec![0u8; 16 * 1024];
    let end = loop {
        // Idle is a property of the session, not of this direction: while the other direction
        // moves bytes, a silent reader here is a one-way stream, not a dead peer.
        let Some(time_left) = pumps.read_time_left() else {
            log_scope.write(format!(
                "h2 ext-CONNECT WS pump [{dir}] session idle for {:?}",
                pumps.read_timeout()
            ));
            break DirectionEnd::Idle;
        };

        let read_result = tokio::time::timeout(time_left, reader.read(&mut buf)).await;

        let n = match read_result {
            Err(_) => continue,
            Ok(Ok(0)) => break DirectionEnd::Finished,
            Ok(Ok(n)) => n,
            Ok(Err(err)) => {
                log_scope.write(format!(
                    "h2 ext-CONNECT WS pump [{dir}] read error: {:?}",
                    err
                ));
                break DirectionEnd::Failed;
            }
        };
        pumps.bytes_moved();

        match tokio::time::timeout(pumps.write_timeout(), writer.write_all(&buf[..n])).await {
            Err(_) => {
                log_scope.write(format!("h2 ext-CONNECT WS pump [{dir}] write timeout"));
                break DirectionEnd::Failed;
            }
            // A write which took its time still moved bytes.
            Ok(Ok(())) => pumps.bytes_moved(),
            // The peer of the writer is gone; the other direction still delivers what its own
            // peer sent before.
            Ok(Err(err)) => {
                log_scope.write(format!(
                    "h2 ext-CONNECT WS pump [{dir}] write error: {:?}",
                    err
                ));
                break DirectionEnd::Finished;
            }
        }
    };

    // A direction which just ended passes the end on to its writer's peer - within the write
    // timeout: a peer which does not read may never let a shutdown through, and that is a write
    // timeout like any other. One which failed ends the session, which drops both halves.
    let end = match end {
        DirectionEnd::Finished => {
            match tokio::time::timeout(pumps.write_timeout(), writer.shutdown()).await {
                Ok(_) => DirectionEnd::Finished,
                Err(_) => {
                    log_scope.write(format!("h2 ext-CONNECT WS pump [{dir}] shutdown timeout"));
                    DirectionEnd::Failed
                }
            }
        }
        end => end,
    };

    // While this direction still holds its half of the upstream: once both halves are dropped
    // the upstream connection is closed, cleanly.
    if let DirectionEnd::Failed = end {
        super::reset_upstream(upstream_abort);
    }

    end
}

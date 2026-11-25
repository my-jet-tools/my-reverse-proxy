use std::{sync::Arc, time::Duration};

use rust_extensions::slice_of_u8_utils::*;

use crate::{
    configurations::{
        HttpEndpointInfo, HttpListenPortConfiguration, ModifyHeadersConfig, ProxyPassLocationConfig,
    },
    h1_proxy_server::*,
    h1_utils::{Http1Headers, Http1HeadersBuilder, HttpContentLength},
    http_proxy_pass::HttpProxyPassIdentity,
    network_stream::*,
    types::HttpTimeouts,
};

pub enum H1HeadersKind<'a> {
    Request(&'a HttpEndpointInfo, &'a ProxyPassLocationConfig),
    Response(&'a HttpEndpointInfo, &'a ProxyPassLocationConfig),
}

impl<'a> H1HeadersKind<'a> {
    /// `modify_http_headers` of the endpoint and of the location - the same two the hyper path
    /// applies. A header is removed when either of them removes it, and what both add is added:
    /// the headers of the endpoint first.
    fn modify_headers(&self) -> [&'a ModifyHeadersConfig; 2] {
        match self {
            H1HeadersKind::Request(endpoint, location) => [
                &endpoint.modify_request_headers,
                &location.modify_request_headers,
            ],
            H1HeadersKind::Response(endpoint, location) => [
                &endpoint.modify_response_headers,
                &location.modify_response_headers,
            ],
        }
    }
}

use crate::tcp_utils::LoopBuffer;

pub struct H1Reader<TNetworkReadPart: NetworkStreamReadPart + Send + Sync + 'static> {
    read_part: TNetworkReadPart,
    pub loop_buffer: LoopBuffer,
    pub h1_headers_builder: Http1HeadersBuilder,
    pub timeouts: HttpTimeouts,
    /// When the head of the next request is due, if the wait for it began before this reader
    /// did: see [`ReadAhead`]. Taken by the first [`Self::read_request_headers`].
    head_deadline: Option<tokio::time::Instant>,
}

/// What was read of a client connection before the pipeline took it: the opening bytes of an
/// `http` / `http2` port, which tell http/1.1 from h2 (`tcp_listener::plain_http`).
pub struct ReadAhead {
    /// The bytes read, as the first read of the pipeline would have put them.
    pub received: LoopBuffer,
    /// When the head of the first request is due: `header_read_timeout` from the start of the
    /// connection, as if the pipeline had waited for the head from the start.
    pub head_deadline: tokio::time::Instant,
}

impl<TNetworkReadPart: NetworkStreamReadPart + Send + Sync + 'static> H1Reader<TNetworkReadPart> {
    pub fn new(read_part: TNetworkReadPart, timeouts: HttpTimeouts) -> Self {
        Self {
            read_part,
            loop_buffer: LoopBuffer::new(),
            h1_headers_builder: Http1HeadersBuilder::new(),
            timeouts,
            head_deadline: None,
        }
    }

    /// A reader of a client connection whose opening bytes were read already: they are the
    /// start of what it reads.
    pub fn with_read_ahead(
        read_part: TNetworkReadPart,
        timeouts: HttpTimeouts,
        read_ahead: ReadAhead,
    ) -> Self {
        Self {
            read_part,
            loop_buffer: read_ahead.received,
            h1_headers_builder: Http1HeadersBuilder::new(),
            timeouts,
            head_deadline: Some(read_ahead.head_deadline),
        }
    }

    pub async fn read_headers(&mut self) -> Result<Http1Headers, ProxyServerError> {
        loop {
            {
                let buf = self.loop_buffer.get_data();

                if !buf.is_empty() {
                    match Http1Headers::try_parse(buf) {
                        Ok(Some(headers)) => return Ok(headers),
                        Ok(None) => {}
                        // Reading on would not make the line a valid one.
                        Err(reason) => return Err(ProxyServerError::HeadersParseError(reason)),
                    }
                }
            }

            let Some(buffer) = self.loop_buffer.get_mut() else {
                return Err(ProxyServerError::BufferAllocationFail);
            };

            let read_size = self
                .read_part
                .read_with_timeout(buffer, self.timeouts.read_timeout)
                .await?;

            self.loop_buffer.advance(read_size);
        }
    }

    /// The head of the client's next request. The whole of it has to arrive within
    /// `header_read_timeout`, whatever pace it comes at - each read is also bounded by
    /// `read_timeout`, but that alone lets a client which sends a byte a minute hold the
    /// connection forever (slowloris).
    ///
    /// The deadline starts when the connection waits for this request with no response still
    /// going out, or at the first byte of the request, whichever comes first. So it covers the
    /// idle wait of a keep-alive connection, but not the time an answer to the request before
    /// it takes: the client sends the next request only after it got that one. The first
    /// request of a connection read ahead of the reader has the deadline of [`ReadAhead`].
    ///
    /// Only for requests: the head of an upstream's response is read with [`Self::read_headers`].
    ///
    /// A head larger than `max_head_size` - whole, or not whole yet - is
    /// [`ProxyServerError::RequestHeadTooLarge`]: `max_request_head_size`.
    pub async fn read_request_headers(
        &mut self,
        header_read_timeout: Duration,
        max_head_size: usize,
        in_flight: &crate::h1_proxy_server::pipeline::InFlightResponses,
    ) -> Result<Http1Headers, ProxyServerError> {
        let mut deadline: Option<tokio::time::Instant> = self.head_deadline.take();

        loop {
            {
                let buf = self.loop_buffer.get_data();

                if !buf.is_empty() {
                    match Http1Headers::try_parse_request(buf) {
                        Ok(Some(headers)) if headers.end > max_head_size => {
                            return Err(ProxyServerError::RequestHeadTooLarge);
                        }
                        Ok(Some(headers)) => return Ok(headers),
                        // Not whole yet, and already larger than a whole one may be.
                        Ok(None) if buf.len() > max_head_size => {
                            return Err(ProxyServerError::RequestHeadTooLarge);
                        }
                        Ok(None) => {}
                        // Reading on would not make the line a valid one.
                        Err(reason) => return Err(ProxyServerError::HeadersParseError(reason)),
                    }
                }

                if deadline.is_none() && (!buf.is_empty() || in_flight.is_idle()) {
                    deadline = Some(tokio::time::Instant::now() + header_read_timeout);
                }
            }

            let Some(buffer) = self.loop_buffer.get_mut() else {
                return Err(ProxyServerError::BufferAllocationFail);
            };

            let read_size = match deadline {
                Some(deadline) => {
                    let left = deadline.saturating_duration_since(tokio::time::Instant::now());

                    if left.is_zero() {
                        return Err(ProxyServerError::NetworkError(NetworkError::Timeout(
                            header_read_timeout,
                        )));
                    }

                    self.read_part
                        .read_with_timeout(buffer, left.min(self.timeouts.read_timeout))
                        .await?
                }
                // A response is still going out and nothing of the next request came yet.
                None => {
                    tokio::select! {
                        read = self.read_part.read_with_timeout(buffer, self.timeouts.read_timeout) => read?,
                        _ = in_flight.wait_idle() => continue,
                    }
                }
            };

            self.loop_buffer.advance(read_size);
        }
    }

    /// Resolves the vhost this request targets out of the port's configuration.
    ///
    /// `fallback_server_name` is used only when the request carries no usable
    /// `Host` header (HTTP/1.0, or an unparseable value). Passing the name this
    /// connection was accepted with — the TLS SNI — keeps such a request on its
    /// own vhost when the endpoint is looked up again after a settings reload;
    /// without it a port serving more than one vhost has no way to choose and
    /// the request would be refused. `None` reproduces the plain-HTTP behaviour:
    /// the port's single nameless endpoint, or nothing.
    pub fn try_find_endpoint_info(
        &self,
        http_headers: &Http1Headers,
        listen_config: &Arc<HttpListenPortConfiguration>,
        fallback_server_name: Option<&str>,
    ) -> Option<Arc<HttpEndpointInfo>> {
        let buffer = self.loop_buffer.get_data();

        let Some(header_position) = http_headers.host_value.as_ref() else {
            return listen_config.get_http_endpoint_info(fallback_server_name);
        };

        let Ok(host) = std::str::from_utf8(&buffer[header_position.start..header_position.end])
        else {
            return listen_config.get_http_endpoint_info(fallback_server_name);
        };

        match host.find(':') {
            Some(index) => listen_config.get_http_endpoint_info(Some(&host[..index])),
            None => listen_config.get_http_endpoint_info(Some(host)),
        }
    }

    pub async fn find_location<'s>(
        &self,
        http_headers: &Http1Headers,
        connection_info: &'s HttpConnectionInfo,
    ) -> Result<(&'s Arc<ProxyPassLocationConfig>, &'s Arc<HttpEndpointInfo>), ProxyServerError>
    {
        let Some(endpoint_info) = &connection_info.endpoint_info else {
            crate::app::APP_CTX.proxy_logs.write_port(
                connection_info
                    .listen_config
                    .listen_host
                    .get_log_key()
                    .as_str(),
                connection_info.connection_ip.get_ip_log(),
                "Rejected request: no endpoint configuration resolved for connection".to_string(),
            );
            return Err(ProxyServerError::HttpConfigurationIsNotFound);
        };

        let first_line = http_headers.get_first_line(self.loop_buffer.get_data());
        let path = first_line.get_path_and_query();

        //println!("Path: '{}'", path);

        let Some(location) = endpoint_info.find_location(path) else {
            return Err(ProxyServerError::LocationIsNotFound);
        };

        Ok((location, endpoint_info))
    }

    /// `request_target`: the target which replaces the one of the request line - the path of
    /// an MCP location, or the target without the location path (`strip_path`). `None`: the
    /// first line goes on as it came.
    pub fn compile_headers(
        &mut self,
        http_headers: Http1Headers,
        kind: H1HeadersKind<'_>,
        http_connection_info: &HttpConnectionInfo,
        identity: &Option<HttpProxyPassIdentity>,
        request_target: Option<&str>,
        dynamic_proxy_host_override: Option<&str>,
    ) -> Result<bool, ProxyServerError> {
        self.h1_headers_builder.clear();

        let web_socket_upgrade = compile_head(
            HttpHeadersReader {
                http_headers: &http_headers,
                payload: self.loop_buffer.get_data(),
            },
            &mut self.h1_headers_builder,
            kind,
            http_connection_info,
            identity,
            request_target,
            dynamic_proxy_host_override,
        )?;

        self.loop_buffer.commit_read(http_headers.end);

        Ok(web_socket_upgrade)
    }

    pub async fn transfer_body<WritePart: H1Writer + Send + Sync + 'static>(
        &mut self,
        connection_id: u64,
        write_stream: &mut WritePart,
        content_length: HttpContentLength,
    ) -> Result<usize, ProxyServerError> {
        match content_length {
            HttpContentLength::None => Ok(0),
            HttpContentLength::Known(size) => {
                if size == 0 {
                    return Ok(0);
                }

                super::transfer_body::transfer_known_size(
                    connection_id,
                    &mut self.read_part,
                    write_stream,
                    &mut self.loop_buffer,
                    size,
                    self.timeouts,
                )
                .await
            }
            HttpContentLength::Chunked => {
                super::transfer_body::transfer_chunked_body(
                    connection_id,
                    &mut self.read_part,
                    write_stream,
                    &mut self.loop_buffer,
                    self.timeouts,
                )
                .await
            }
        }
    }

    pub fn into_read_part(self) -> (TNetworkReadPart, LoopBuffer) {
        (self.read_part, self.loop_buffer)
    }
}

/// Writes `head` - parsed, in the buffer it was parsed from - to `out` the way it goes on: with
/// the `modify_http_headers` of `kind` applied, `X-Forwarded-For`, `CF-IPCountry`,
/// `X-Forwarded-User` and `X-Forwarded-ClientCertId` (of `identity`) on a request,
/// `Connection: close` and HSTS on a response.
/// Returns whether the head asks for a websocket upgrade.
///
/// The headers of a request which tell who its client is are the proxy's word: what the client
/// sent under such a name is taken away, and `X-Forwarded-For` is written anew for the client of
/// the request (see [`crate::cloudflare::RequestClient`]).
///
/// The head of an h1 upstream's response is compiled where it was read - in the loop buffer of
/// its reader. The head of an h2 upstream's response is first written as h1 and compiled from
/// there, so both get the very same rules.
pub fn compile_head(
    head: HttpHeadersReader<'_>,
    out: &mut Http1HeadersBuilder,
    kind: H1HeadersKind<'_>,
    http_connection_info: &HttpConnectionInfo,
    identity: &Option<HttpProxyPassIdentity>,
    request_target: Option<&str>,
    dynamic_proxy_host_override: Option<&str>,
) -> Result<bool, ProxyServerError> {
    let HttpHeadersReader {
        http_headers,
        payload: data,
    } = head;

    let modify_headers = kind.modify_headers();
    let request_endpoint = match &kind {
        H1HeadersKind::Request(info, _) => Some(*info),
        H1HeadersKind::Response(..) => None,
    };

    if let Some(request_target) = request_target {
        http_headers.push_first_line_with_other_path(data, request_target, out);
        out.push_cl_cr();
    } else {
        out.push_raw_payload(
            &data[..http_headers.first_line_end + crate::consts::HTTP_CR_LF.len()],
        );
    }

    let mut pos = http_headers.first_line_end + crate::consts::HTTP_CR_LF.len();

    let is_request = request_endpoint.is_some();
    // Who the request is of - and with it which of the headers telling so are the client's own
    // words, taken away, and the `X-Forwarded-For` written in their place.
    let client = is_request.then(|| http_connection_info.request_client());
    let inject_country_enabled = request_endpoint.map(|e| e.inject_country).unwrap_or(false);
    // The headers of `request_with_header_only` are the proxy's alone: never sent on.
    let required_headers = request_endpoint
        .map(|endpoint| &endpoint.request_with_header_only)
        .filter(|required| !required.is_empty());

    loop {
        let next_pos = data
            .find_sequence_pos(crate::consts::HTTP_CR_LF, pos)
            .unwrap();

        if next_pos == pos {
            break;
        }

        let header = &data[pos..next_pos];
        //println!("{:?}", std::str::from_utf8(header));

        let Some(header_name_end_pos) = header.find_byte_pos(b':', 0) else {
            return Err(ProxyServerError::HeadersParseError(
                "Header does not have end `:` symbol",
            ));
        };

        let Ok(header_name) = std::str::from_utf8(&header[..header_name_end_pos]) else {
            return Err(ProxyServerError::HeadersParseError(
                "Header name is not valid UTF-8",
            ));
        };

        let skip_for_dynamic_proxy = dynamic_proxy_host_override.is_some()
            && (header_name.eq_ignore_ascii_case("host")
                || header_name.eq_ignore_ascii_case("proxy-to"));

        let has_to_be_removed = modify_headers
            .iter()
            .any(|rules| rules.has_to_be_removed(header_name));

        // Who the request is of (`X-Forwarded-User`, `X-Forwarded-ClientCertId`) is the proxy's
        // word, written below - never the client's.
        let is_forwarded_user =
            is_request && crate::forwarded_user::is_header_name(header_name.as_bytes());

        let tells_who_the_client_is = client
            .as_ref()
            .is_some_and(|client| client.takes_away_header(header_name.as_bytes()));

        let is_required_header =
            required_headers.is_some_and(|required| required.covers(header_name.as_bytes()));

        if !skip_for_dynamic_proxy
            && !has_to_be_removed
            && !is_forwarded_user
            && !tells_who_the_client_is
            && !is_required_header
        {
            if inject_country_enabled && header_name.eq_ignore_ascii_case("cf-ipcountry") {
                // drop client-supplied value; we'll write our own below
            } else {
                out.push_raw_payload(header);
                out.push_raw_payload(crate::consts::HTTP_CR_LF);
            }
        }

        pos = next_pos + crate::consts::HTTP_CR_LF.len();
    }

    if let Some(x_forwarded_for) = client.and_then(|client| client.x_forwarded_for()) {
        out.push_header("X-Forwarded-For", &x_forwarded_for);
    }

    if inject_country_enabled {
        if let Some(ip) = http_connection_info.connection_ip.get_ip_addr() {
            if let Some(code) = crate::ip_db::lookup_country(ip) {
                let code_str = std::str::from_utf8(&code).unwrap();
                out.push_header("CF-IPCountry", code_str);
            }
        }
    }

    if let Some(identity) = identity.as_ref().filter(|_| is_request) {
        if let Some(user) = crate::forwarded_user::value_of(identity) {
            out.push_header(crate::forwarded_user::HEADER, user);
        }

        if let Some(cert_id) = crate::forwarded_user::client_cert_id_of(identity) {
            out.push_header(crate::forwarded_user::CLIENT_CERT_ID_HEADER, cert_id);
        }
    }

    if let Some(host_override) = dynamic_proxy_host_override {
        out.push_header("Host", host_override);
    }

    for add_header in modify_headers.iter().flat_map(|rules| rules.iter_add()) {
        if add_header.1.is_empty() {
            continue;
        }
        let value = crate::scripts::populate_value(
            head,
            http_connection_info,
            identity,
            add_header.1.as_str(),
        );
        if value.as_str().is_empty() {
            continue;
        }
        out.push_header(add_header.0, value.as_str());
    }

    if let H1HeadersKind::Response(info, _) = &kind {
        if !info.keep_alive {
            out.push_header("Connection", "close");
        }

        if info.hsts && info.listen_endpoint_type.is_https() {
            out.push_header("Strict-Transport-Security", crate::consts::HSTS_VALUE);
        }
    }

    out.push_cl_cr();

    let mut web_socket_upgrade = false;

    if let Some(upgrade_position) = http_headers.upgrade_value.as_ref() {
        let upgrade_value = &data[upgrade_position.start..upgrade_position.end];

        web_socket_upgrade = crate::h1_utils::compare_case_insensitive(upgrade_value, b"websocket");
    }

    Ok(web_socket_upgrade)
}

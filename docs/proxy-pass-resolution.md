# ProxyPass → Location resolution

This document traces how an incoming connection is matched to a configured
location and what happens after the match for each `ProxyPassToConfig`
variant.

## The three resolution stages

Resolution happens in three sequential stages, each narrowing what we know
about the incoming traffic:

1. **Listening port → `ListenConfiguration`** — happens at TCP `accept`.
2. **`ListenConfiguration` → `HttpEndpointInfo`** — happens after TLS
   handshake (for TLS listeners) or after the first HTTP request's `Host`
   header is read (for plain HTTP listeners).
3. **`HttpEndpointInfo` → `ProxyPassLocationConfig`** — happens per
   request, by matching the request's path prefix.

---

## Stage 1: port → `ListenConfiguration`

The proxy binds one `tokio::net::TcpListener` per configured TCP port (and
one `tokio::net::UnixListener` per unix socket). Each port carries exactly
one `ListenConfiguration` enum from
`src/configurations/app_configuration_inner.rs`:

```rust
pub enum ListenConfiguration {
    Http(Arc<HttpListenPortConfiguration>),
    Tcp(Arc<TcpEndpointHostConfig>),
    Mcp(Arc<HttpListenPortConfiguration>),
}
```

When the listener accepts a connection, `handle_accepted_connection`
(`src/tcp_listener/listen_tcp_server.rs`) looks up the port in
`AppConfigurationInner::listen_tcp_endpoints` and dispatches:

- `ListenConfiguration::Http(_)` — match on `listen_endpoint_type`:
  - `Http1` → `h1_proxy_server::kick_h1_tcp_reverse_proxy_server_from_http`
    (plain HTTP/1, no TLS).
  - `Http2` → `tcp_listener::http2::handle_connection` (h2 over plain TCP,
    legacy hyper-based).
  - `Https1` → `tcp_listener::https::handle_connection`, which terminates
    TLS and then forks on `endpoint_info.listen_endpoint_type` again
    (`Https1` → h1 server, `Https2` → hyper h2 server).
  - `Https2` → same as `Https1`.
  - `Mcp` (in this branch) → `tcp_listener::https::handle_connection` →
    after TLS handshake, the inner branch for `Mcp` calls
    `mcp::run_mcp_connection` which is a raw byte tunnel (the legacy
    `endpoint.type = mcp` mode).
- `ListenConfiguration::Tcp(_)` — pure TCP forward, no HTTP parsing.
  Branches on `remote_host` (`Gateway` / `OverSsh` / `Direct`) and forwards
  bytes to the upstream.
- `ListenConfiguration::Mcp(_)` — TLS listener for `endpoint.type = mcp`.
  Goes through `tcp_listener::https::handle_connection`, terminates TLS,
  then `mcp::run_mcp_connection` pipes bytes to a single configured
  upstream `host:port`.

The legality of multiple endpoints on one port is governed by
`ListenHttpEndpointType::can_be_under_the_same_port`
(`src/configurations/http_type.rs`):

| New type | Same-port partners allowed |
|---|---|
| `Http1` | `Http1` |
| `Http2` | `Http2` |
| `Https1` | `Https1`, `Https2`, `Mcp` |
| `Https2` | `Https1`, `Https2` |
| `Mcp` | `Https1`, `Https2`, `Mcp` |

Any mismatch is rejected at config compile time
(`src/scripts/merge_http_configuration_with_existing_port.rs`).

---

## Stage 2: `ListenConfiguration` → `HttpEndpointInfo`

For TLS listeners (`Https1` / `Https2` / `Mcp`):

1. TLS accept reads SNI from the ClientHello.
2. `HttpListenPortConfiguration::get_http_endpoint_info(Some(sni))`
   (`src/configurations/http_listen_port_configuration.rs:61`) walks
   `endpoints: Vec<Arc<HttpEndpointInfo>>` and returns the first whose
   `host_endpoint.is_my_server_name(sni)` is true.
3. The chosen `HttpEndpointInfo` carries the SSL cert id, allowed user
   list, modify-headers config, and the per-endpoint `locations`.

For plain HTTP/1 listeners (`Http1`):

1. There is no SNI, so endpoint resolution is deferred until the first
   request's `Host` header is read.
2. `H1Reader::try_find_endpoint_info`
   (`src/h1_proxy_server/h1_read_part.rs:95`) extracts the `Host` header
   value and calls the same `get_http_endpoint_info`.
3. The result is kept on `HttpConnectionInfo.endpoint_info`. A later
   request on the same connection resolves the endpoint again when its
   `Host` is not that endpoint's (`is_my_endpoint`), or after a settings
   reload (`pick_up_reload`)
   (`src/h1_proxy_server/pipeline/reader.rs:194-228`). This holds for
   h1 connections accepted over TLS as well: they start with the SNI
   endpoint.

### Special case: single-endpoint port without server name

If the port hosts exactly one endpoint and that endpoint's
`host_endpoint` was configured **without** a server name (e.g. just
`":443"`), resolution succeeds with `server_name = None` and returns that
single endpoint. Such an endpoint also matches any server name
(`is_my_server_name`), which supports configs like "all HTTPS traffic on
port 443 goes to the same backend regardless of SNI". A TLS ClientHello
with no SNI at all is refused before any endpoint is looked up
(`TlsAcceptError::UnknownServerName`,
`src/tcp_listener/https/utils.rs:141-147`), so the `None` case comes from
a request without a usable `Host`.

If multiple endpoints are configured on a port and the `Host` is missing,
resolution returns `None` → request fails with
`ProxyServerError::HttpConfigurationIsNotFound`.

### Per-endpoint settings checked at this stage

Once the endpoint is resolved, the request stream is gated by:

- `whitelisted_ip_list_id` — client IP must be in the allowed list, or
  the connection is dropped immediately
  (`tcp_listener/https/handle_connection.rs:77`). The h1 pipeline checks
  it again per request, for the endpoint the request's `Host` resolved to
  (`src/h1_proxy_server/pipeline/reader.rs:289-313`, 401).
- `g_auth` (Google login) and/or `client_certificate_id` — checked at
  request time via `must_be_authorized` and the authorize step in
  `H1Reader::authorize`. Failures return 401/redirect responses, not
  proxy errors.
- `allowed_user_list_id` — checked after authentication;
  `HttpEndpointInfo::user_is_allowed` returns false → 401.

---

## Stage 3: `HttpEndpointInfo` → `ProxyPassLocationConfig`

Per request. The endpoint's `locations: Vec<Arc<ProxyPassLocationConfig>>`
is searched by `find_location` (`src/configurations/http_endpoint_info.rs:156`):

```rust
pub fn find_location(&self, path: &str) -> Option<&Arc<ProxyPassLocationConfig>> {
    self.locations
        .iter()
        .find(|location| crate::types::is_path_of_location(path, &location.path))
}
```

The hyper path (`http2` / `https2` endpoints) matches with the same
`is_path_of_location` (`src/http_proxy_pass/proxy_pass_location.rs:30`).

Important properties:

- **First match wins, in `Vec` order.** Not longest-prefix-first.
  Locations should be ordered with the most specific paths **first** in
  the config; otherwise a generic `/` match will shadow more specific
  ones.
- **Case-insensitive** prefix match (ASCII letters only).
- **A prefix of the string, not of a segment**: the location `/a` takes
  `/ab/x` as well. A `path` meant for a subtree should end with `/`.
- Only the path is compared: `is_path_of_location`
  (`src/types/request_path.rs:65`) cuts the request target at the first
  `?` or `#`, so a query never affects routing.
- **Percent-decoded**: the path and the location's `path` are both
  decoded once before they are compared, so `/%73ecure/x` is a request
  of the location `/secure`. The path sent upstream stays as received —
  unless the location has `strip_path` (below).
- A path with a `..`, a `.` or an empty segment (an empty last segment,
  `/api/`, is fine) — written as it is or percent-encoded — is answered
  `400 Bad Request` before a location is looked for, on both HTTP paths
  (`has_ambiguous_segment`, `src/types/request_path.rs:22`;
  `src/h1_proxy_server/pipeline/reader.rs:338-358`,
  `src/http_proxy_pass/http_proxy_pass.rs:102-110`).
- A request on `/` matches a location with `path: "/"` only. On the h1
  pipeline an empty request target is refused when the request line is
  parsed (`verify_http11_first_line`); a target that does not start with
  `/` (`*`, `host:443`) matches no location whose `path` starts with `/`.

If no location matches, the request fails with
`ProxyServerError::LocationIsNotFound` and the configured "location not
found" error template is returned to the client.

### Per-location settings

After match, the request is filtered/transformed by:

- `whitelisted_ip` — additional per-location IP filter (in addition to
  endpoint-level `whitelisted_ip_list_id`).
- `modify_request_headers` / `modify_response_headers` — add/remove/
  rewrite headers on request and response.
- `domain_name` — the TLS server name (SNI) used when forwarding to an
  HTTPS upstream, instead of the host of `proxy_pass_to`
  (`connect_tls`, `src/http_client_connectors/http_tls_connector.rs:74-78`).
  The request's `Host` header is not changed. Applied on both HTTP paths;
  on the h1 pipeline it is also a part of the pool key.
- `compress` — gzips the request body sent to the upstream, when it is
  2048 bytes or more (`src/http_proxy_pass/http_request_builder.rs:664`).
  The hyper path only: the h1 pipeline does not read it. Do not enable
  for `type: mcp` — see `docs/mcp.md`.
- `trace_payload` — read from the settings, but not used: the hyper
  path's websocket pump traces payloads when the location's runtime debug
  flag is on (`src/http_proxy_pass/http_proxy_pass.rs:311`).
- `strip_path` — the upstream gets the request target without the part
  of the path the location was picked by: `strip_location_path`
  (`src/types/request_path.rs:92`) cuts the raw target where the decoded,
  case-insensitive match of `is_path_of_location` ends, and keeps the
  rest — escapes and the query — as received, after a leading `/`. Both
  HTTP paths apply it once, right where the target is decided, so every
  transport and request shape gets it:
  - h1 pipeline: the reader computes it right after the location is
    found (`src/h1_proxy_server/pipeline/reader.rs:401`) and passes it to
    `H1Reader::compile_headers` as `request_target`, in place of the MCP
    path. The worker and its replays, the WebSocket tunnel and the files
    answer all read the compiled head.
  - hyper path: `HttpRequestBuilder::into_request`
    (`src/http_proxy_pass/http_request_builder.rs:188`) rewrites the
    path-and-query of the uri before it branches; an absolute uri stays
    absolute. `req_parts` keeps the client's uri, so `${PATH_AND_QUERY}`
    in a response header is the client's path; request headers are
    filled before (`process_headers`).

  A stripped path with an ambiguous segment — the cut joined its two
  sides, as the location `/a` does with `/a..%2Fx` — is answered `400 Bad
  Request` right after the location is found
  (`src/h1_proxy_server/pipeline/reader.rs:412`,
  `src/http_proxy_pass/http_proxy_pass.rs:172`). It is refused at load
  time where it has no meaning: on `mcp` / `mcp-h2`, `static` and `drop`
  locations, on every location of a `type: mcp` endpoint, and on a
  location path which, decoded, is not UTF-8
  (`src/scripts/compile_http_configuration.rs:159`); on any location of
  a `type: tcp` endpoint (`TcpEndpointHostConfig::new`). The path of
  `proxy_pass_to` plays no part in it.

---

## What happens after location resolution: per-variant

The resolved location's `proxy_pass_to: ProxyPassToConfig` decides the
upstream behavior.

On the h1 pipeline (`http` / `https` endpoints) the reader
(`src/h1_proxy_server/pipeline/reader.rs`) closes the connection for
`Drop`, answers `Static` and `FilesPath` itself, and turns
`DynamicProxy` into a per-request `Http1` upstream built from the
`proxy-to` header. Every other request goes to a per-request worker,
`run_upstream_request` (`src/h1_proxy_server/pipeline/worker.rs`), which
takes a connection from the pool (`H1PoolHolder::acquire`,
`src/h1_remote_connection/h1_pool_holder.rs`), sends the head and the
body, and reads the response itself. A connection the pool does not have
is dialled by `Upstream::connect_owned`
(`src/h1_remote_connection/upstream.rs:48`), which builds the right
`UpstreamInner` and handles network upstreams only. See "Upstream
lifecycle per variant" below.

The hyper path (`http2` / `https2` endpoints, `src/http_proxy_pass/`)
builds a content source per location instead
(`ProxyPassLocationConfig::create_data_source`).

### `Http1(ProxyPassToModel)`

Plain HTTP/1 reverse proxy. Sub-cases by `remote_host`:

- `Direct { remote_host: http://...   }` →
  `UpstreamInner::Http1Direct` (raw `tokio::net::TcpStream`).
- `Direct { remote_host: https://... }` →
  `UpstreamInner::Https1Direct` (TLS-wrapped TCP). Uses
  `domain_name` for SNI if configured, else the URL host.
- `OverSsh { ssh_credentials, remote_host }` →
  `UpstreamInner::Http1OverSsh` (HTTP/1 over an SSH tunnel; see
  `docs/gateway-protocol.md` for unrelated gateway concept).
- `Gateway { id, remote_host }` →
  `UpstreamInner::Http1OverGateway` (HTTP/1 forwarded through a
  pre-existing MyJetTools gateway connection).

The first line is forwarded as received — for a location with
`strip_path`, with the target without the location path in it (see
"Per-location settings"); the path of `proxy_pass_to` is not used either
way. The headers go through `H1Reader::compile_headers`
(`modify_http_headers` of the endpoint and the location,
`X-Forwarded-For`); the body is streamed. The worker reads the response
and streams it to the client-writer task as `ResponseEvent`s.

### `McpHttp1(ProxyPassToModel)`

Same wire transports as `Http1` (Direct/OverSsh, http or https; MCP
through a gateway is refused at load time,
`src/scripts/compile_http_configuration.rs:122-132`), with three
differences (`ProxyPassToConfig::is_mcp`):

- on every request the first line of the HTTP request is rewritten so
  the upstream sees the path-and-query of the configured
  `proxy_pass_to`, not the path the client sent. Method, HTTP version,
  and headers are preserved;
- the response is read with the long MCP read timeout
  (`DEFAULT_MCP_READ_TIMEOUT`), since an SSE stream may idle;
- an upstream failure closes the client connection instead of sending an
  HTML error page.

The path-and-query comes from the config, per request:
`mcp_path(&proxy_pass_to)` (`src/h1_remote_connection/upstream_state.rs:5`)
is passed to `H1Reader::compile_headers` by the reader. See `docs/mcp.md`
for the full rationale.

### `Http2(ProxyPassToModel)`

HTTP/2 upstream. Served by the hyper path only
(`ProxyPassLocationConfig::create_data_source`), which runs for `http2`
endpoints (`tcp_listener::http2::handle_connection`) and `https2`
endpoints (`serve_https2` in `src/tcp_listener/https/handle_connection.rs`).
The h1 pipeline has no h2 upstream: under an `http` / `https` endpoint
`Upstream::connect_owned` returns an error for it
(`src/h1_remote_connection/upstream.rs:195-209`), and the worker answers
503 "remote resource is not available". Nothing refuses an `http2`
location under an http/1 endpoint at load time.

`McpHttp2` (`type: mcp-h2`) is the same on the wire, and is refused at
load time under an `http`, `https` or `mcp` endpoint
(`src/scripts/compile_http_configuration.rs:134-155`).

### `UnixHttp1(ProxyPassToModel)`

HTTP/1 over a unix domain socket. `Direct { remote_host }` connects to
the socket (`UpstreamInner::Http1UnixSocket`). `Gateway` is an ordinary
gateway upstream (`UpstreamInner::Http1OverGateway`): the peer connects
to the socket path itself. `OverSsh` is not supported: `connect_owned`
returns an error for it (`src/h1_remote_connection/upstream.rs:191-193`),
which the worker answers with a 503, and on the hyper path
`create_data_source` panics on it
(`src/configurations/proxy_pass_location_config.rs:431-441`).

### `UnixHttp2(ProxyPassToModel)`

HTTP/2 over a unix socket. Hyper path only, like `Http2`:
`HttpProxyPassContentSource::UnixHttp2` for `Direct`, `Http2OverGateway`
for `Gateway` (the peer connects to the socket path itself), and a panic
in `create_data_source` for `OverSsh`
(`src/configurations/proxy_pass_location_config.rs:470-479`). On the h1
pipeline `connect_owned` returns an error for it, as for `Http2`.

Both variants, and everything which carries a unix socket, are built on
unix only. On a platform without unix sockets (Windows) compiling the
settings refuses each unix socket with `unix sockets are not supported on
this platform`: a `hosts:` key which is a socket path
(`src/scripts/compile_host_configuration.rs`), a location of `type:
unix+http` / `unix+http2` - written or read from `proxy_pass_to` - and a
`unix+http://`, `http+unix://` or `unix://` upstream of any other type
(`src/scripts/compile_location_proxy_pass_to.rs`), and a `type: tcp`
endpoint to one (`src/configurations/tcp_endpoint_host_config.rs`). A
socket path behind a gateway is refused as well, although it is the peer
which would connect to it. The endpoint is not loaded, and the error is
reported as any other compile error of an endpoint.

### `FilesPath(ProxyPassFilesPathModel)`

Serves files from a folder. The folder may itself be remote:

- `Direct { remote_host }` — a folder on the proxy's local filesystem. A
  leading `~` is the home directory of the proxy.
- `OverSsh` — files are read over SFTP. The ssh session is taken from the
  pool per request, and a leading `~` is the home directory of the ssh user
  on the remote host.
- `Gateway` — files are read by the other end of a MyJetTools gateway
  connection, one `GET_FILE_REQUEST` per file, so a file is at most
  `MAX_FILE_RESPONSE_SIZE`.

All three are behind one type, `FilesContentSource`
(`src/http_content_source/files_content_source.rs`), and both serving
paths go through it:

- the h1 byte pipeline (`http` / `https` endpoints) answers in the reader
  task, without an upstream worker: the request body is drained, then
  `answer_files_request` (`src/h1_proxy_server/pipeline/files.rs`) builds
  the response;
- the hyper path (`http2` / `https2` endpoints) reaches it as
  `HttpProxyPassContentSource::Files`, through
  `FilesContentSource::execute`.

Per request:

1. The request path, without the query string — with `strip_path`,
   without the location path: `/static/` serves `/static/css/a.css` as
   `/css/a.css`, and `/static/` as the root — is checked by
   `FileRequestPath::parse`
   (`src/http_content_source/file_request_path.rs`). It has to start with
   `/`, and to hold no `..` segment and no control character — written as
   they are or percent-encoded: the check looks at the path after one pass
   of percent-decoding, with `/` and `\` both taken for separators. Nor may
   it hold a `.` segment, or an empty one which is not the last — `//x`,
   `/./x`: to the file system those are the file `/x`, while the location
   was picked by the path as it is written, so they would be served past
   the location which guards `/x`. A path which does not pass is answered
   `400 Bad Request`.
2. `FileRequestPath::in_folder` glues the path to the folder. It is the
   only function which does, and the three sources take a
   `&FileRequestPath`, so no path gets to a source unchecked. The root
   means `default_file`, and is a 404 without one. The path is glued as it
   was received: file names are not percent-decoded.
3. The source reads the file. Its content type comes from the extension
   (`WebContentType::detect_by_extension`).

A file which is not there is a 404. A gateway or an ssh host which can not
be reached is a 503 on the h1 pipeline, written to the proxy logs, and a
500 tech page on the hyper path. The h1 pipeline serves `GET` and `HEAD`
— a `HEAD` gets the head of the `GET` response and no body, any other
method is a 404 (`src/h1_proxy_server/pipeline/files.rs:83`) — and the
hyper path does not look at the method.

### `Static(Arc<StaticContentConfig>)`

Returns a configured static body (status code, content-type, body
bytes). No upstream connection at all. On the h1 pipeline the reader
builds the response itself (`Http1ResponseBuilder`, plus what
`modify_http_headers` of the endpoint and the location add to a
response), drains the request body and queues the response — no worker,
no pool (`src/h1_proxy_server/pipeline/reader.rs:600-624`). A `HEAD` gets
the head only. On the hyper path it is `HttpProxyPassContentSource::Static`.

---

## Upstream lifecycle per variant

How upstream connections are held on the h1 pipeline: in a pool per
client connection, `H1PoolHolder::new_local()`
(`src/h1_proxy_server/pipeline/reader.rs:121`), keyed by
`connection_key` (`src/h1_remote_connection/upstream_state.rs:24`) and
keeping at most one idle connection per key. A worker takes a connection
out (`acquire`) for one request and gives it back (`release`) only when
the response was self-delimiting (`Content-Length` or chunked), nothing
was left over and the socket is alive
(`src/h1_proxy_server/pipeline/worker.rs:475-493`); any other connection
is closed.

| Variant | Pool key (`connection_key`) | Reuse behavior |
|---|---|---|
| `Http1` (any sub-variant) | `h1` + scheme, `host:port` and `domain_name` (Direct) / ssh credentials and `host:port` (OverSsh) / gateway id and `host:port` (Gateway) | Reused across requests on the same client connection by every location with the same key — the path of `proxy_pass_to` is not a part of it. |
| `McpHttp1` | `mcp-h1` + the same, + the path-and-query of `proxy_pass_to` | Two MCP servers on one `host:port` under different paths get different connections. An SSE response is not self-delimiting, so its connection is never given back. |
| `UnixHttp1` | `uds-h1` + the same | Same as `Http1`. |
| `DynamicProxy` | the `h1` key of the per-request upstream built from `proxy-to` | Same as `Http1`. |
| `Http2` / `McpHttp2` / `UnixHttp2` | — | Not on this pipeline: `connect_owned` returns an error. The hyper path keeps its own per-location pools. |
| `FilesPath` / `Static` / `Drop` | — | Never reach the pool: answered (or, for `Drop`, closed) by the reader. |

While nothing has reached the client, a request is replayed once on a
fresh connection when writing it fails, or when reading the response
head fails on a reused connection (a timeout excepted) — as long as the
part of the body already sent fits `REPLAY_WINDOW`
(`run_upstream_request`, `src/h1_proxy_server/pipeline/worker.rs:163-183`).

### WebSocket upgrade

A request whose head carries `Upgrade: websocket` ends the reader loop:
the reader hands an `UpgradeContext` back to the connection entry
(`serve_reverse_proxy_pipelined`), which closes the response queue, takes
the client write half back from the writer task and runs `run_ws_tunnel`
(`src/h1_proxy_server/pipeline/ws_tunnel.rs`). The tunnel dials a fresh
upstream with `Upstream::connect_owned` — an upgrade never takes a
connection from the pool nor gives one back — and sends the head. On an
upgrade response the four halves are wired into two `copy_streams`
pumps, and from then on the WebSocket frames flow as raw bytes; a refused
upgrade is relayed to the client as an ordinary response and the
connection closed.

---

## Worked examples

### Example 1: `https://api.example.com/v1/users`

1. Port 443 → `ListenConfiguration::Http(Https1Config)`.
2. TLS handshake reads SNI `api.example.com` →
   `get_http_endpoint_info(Some("api.example.com"))` returns the matching
   `HttpEndpointInfo`.
3. After TLS termination, h1 reader reads the request `GET /v1/users HTTP/1.1`.
4. `find_location("/v1/users")` walks the endpoint's locations:
   - location 0: `path: "/v1/users"` → match, returns it.
   - (The next location, e.g. `path: "/"`, is skipped because the search
     stopped.)
5. Location's `proxy_pass_to: Http1(http://users-svc:8080/)`.
6. The reader compiles the head and spawns a worker
   (`run_upstream_request`). Its `pool.acquire` finds no idle connection
   under the key `h1|…` of `users-svc:8080` and dials one
   (`Upstream::connect_owned` → `UpstreamInner::Http1Direct`).
7. The first line is forwarded as received, the headers as compiled. The
   worker reads the response and streams it to the client-writer task →
   client; on a self-delimiting response the connection goes back to the
   pool for the next request on this client connection.

### Example 2: `https://mcp.example.com/service-a` (POST, MCP)

1. Port 443 → `ListenConfiguration::Http(Https1Config)`.
2. TLS handshake reads SNI `mcp.example.com` → endpoint resolved.
3. h1 reader reads `POST /service-a HTTP/1.1`.
4. `find_location("/service-a")` matches the location with
   `path: "/service-a"`, `proxy_pass_to: McpHttp1(http://upstream-a/mcp)`.
5. `H1Reader::compile_headers` gets `mcp_path(&proxy_pass_to)` =
   `Some("/mcp")` and rewrites the first line to `POST /mcp HTTP/1.1`.
   `Mcp-Session-Id` and the body are forwarded unchanged.
6. The worker's `pool.acquire` dials a connection under the key
   `mcp-h1|…|/mcp`.
7. Response streams back. If it's an SSE stream, the worker keeps pumping
   (with the long MCP read timeout) until the upstream closes or the
   client disconnects; that connection is not given back to the pool.

### Example 3: TLS-only endpoint without SNI

Config: port 443 has one endpoint with `host_endpoint: ":443"` (no
server name).

1. A client connecting with any SNI gets that endpoint:
   `get_http_endpoint_info(Some(sni))` matches it, because an endpoint
   without a server name matches every name (`is_my_server_name`).
2. A client connecting without SNI is refused at the ClientHello, before
   the handshake (`TlsAcceptError::UnknownServerName`,
   `src/tcp_listener/https/utils.rs:141-147`), whatever endpoints the
   port has.

### Example 4: Plain HTTP with `Host` header missing

Config: port 80 with multiple HTTP/1 endpoints.

1. `get_http_endpoint_info(None)` is called because the request had no
   `Host` header.
2. Multiple endpoints exist → returns `None`.
3. Request fails with `HttpConfigurationIsNotFound` → the connection is
   closed without a response, and the source IP is not penalised
   (`src/h1_proxy_server/rev_proxy_error.rs:72`).

If the port has exactly one endpoint without a server name, the
fallback applies and the request resolves to that single endpoint.

---

## Files involved

- `src/tcp_listener/listen_tcp_server.rs` — port-level dispatch
  (Stage 1).
- `src/tcp_listener/listen_unix_server.rs` — same for unix sockets.
- `src/tcp_listener/https/handle_connection.rs` — TLS termination and
  inner type-based dispatch.
- `src/configurations/http_listen_port_configuration.rs` —
  `get_http_endpoint_info` (Stage 2).
- `src/configurations/host_str.rs` — `EndpointHttpHostString::is_my_server_name`.
- `src/configurations/http_endpoint_info.rs` — `find_location` (Stage 3).
- `src/h1_proxy_server/h1_read_part.rs` — Stage 2/3 plumbing for h1
  (`try_find_endpoint_info`, `find_location`).
- `src/types/request_path.rs` — `is_path_of_location`,
  `has_ambiguous_segment`, `strip_location_path`.
- `src/h1_proxy_server/pipeline/reader.rs` — request loop: endpoint and
  location, `Drop` / `Static` / `FilesPath` / refused paths answered in
  place, a worker spawned for the rest; owns the connection's pool.
- `src/h1_proxy_server/pipeline/worker.rs` — `run_upstream_request`:
  pool, head and body, response.
- `src/h1_proxy_server/pipeline/ws_tunnel.rs` — WebSocket upgrade on a
  fresh upstream.
- `src/h1_proxy_server/pipeline/files.rs` — `FilesPath` on the h1
  pipeline.
- `src/h1_remote_connection/h1_pool_holder.rs` — `H1PoolHolder`, the
  upstream pool.
- `src/h1_remote_connection/upstream.rs` — `Upstream::connect_owned`,
  per-variant connect logic for network upstreams.
- `src/h1_remote_connection/upstream_state.rs` — `connection_key` (the
  pool key) and `mcp_path`.
- `src/http_proxy_pass/` — the hyper path of `http2` / `https2`
  endpoints; `http_request_builder.rs` builds the upstream request, the
  `strip_path` and MCP rewrites of its uri included.
- `src/scripts/compile_http_configuration.rs` — location combinations
  refused at load time (MCP through a gateway, `mcp-h2` under an http/1
  endpoint, `strip_path` where it has no meaning).
- `src/configurations/tcp_endpoint_host_config.rs` — a `type: tcp`
  endpoint, `strip_path` on any of its locations refused.
- `src/configurations/proxy_pass_to_config.rs` — the `ProxyPassToConfig`
  enum itself.
- `src/scripts/merge_http_configuration_with_existing_port.rs` —
  port-sharing validation.

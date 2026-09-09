# `auth_header` on h2 endpoints + live pick-up of a settings reload

Status: **complete** (2026-09-09), in the working tree. `cargo check` clean,
215 unit tests pass (11 new), verified end to end on a local harness including
counterfactual runs that prove each check discriminates. See "Verification".

## Problem

Goal: put / rotate `auth_header` on an MCP location through the dynamic
settings file (`set_dynamic_settings` → `reload_settings`) and have the gate
actually apply.

Two things stood in the way:

1. **`auth_header` is enforced only on the h1 byte pipeline**
   (`H1Reader::authorize`). The hyper path — every `http2` / `https2`
   endpoint, i.e. every `mcp-h2` location — silently ignored it. The live
   `mcp-rms.jetdev.eu:443` host is `https2` + `mcp-h2`, so adding
   `auth_header` there did nothing. (Confirmed backlog item from the Jul-2026
   coalescing review.)
2. **A connection snapshots its port configuration at accept time** —
   `HttpConnectionInfo.listen_config` on h1, `listen_port_config` inside
   `HttpRequestHandler` / `HttpsRequestsHandler` on hyper. MCP clients keep one
   h2 connection open for a long time, so after a reload the old expected
   token kept working and the new one was refused until the client
   reconnected. `sync_endpoints` does not restart listeners on a config change,
   so nothing drops those connections.

## Design

- One shared comparison: `auth_header_matches(expected, actual)` +
  `ProxyPassLocationConfig::auth_header_accepts(actual)` in
  `src/configurations/proxy_pass_location_config.rs`. Byte-for-byte after
  stripping SP/HTAB; absent == wrong; no scheme parsing. Both paths call it.
- Reload detection by a generation counter, not by the lock:
  `AppConfiguration.generation: AtomicU64`, bumped inside `write` under the
  write lock. `AppConfiguration::pick_up_reload(listen_host, current,
  seen_generation) -> (generation, Option<Arc<HttpListenPortConfiguration>>)`
  takes the read lock only when the generation moved, and returns a new Arc
  only when the port's configuration was actually replaced
  (`Arc::ptr_eq` filter — an ip-list / error-map write does not churn
  connections). Port no longer configured → keep serving the snapshot.
- `AppConfigurationInner::get_http_listen_config(&ListenHost)` — lookup for
  TCP and unix listeners, `Http` and `Mcp` variants.
- Old per-connection `HttpProxyPass` objects are **dropped, not disposed**,
  when the hyper handler swaps configuration: `dispose()` stores `None` into
  `inner`, which would fail an in-flight request at its
  `modify_resp_headers` step. Dropping lets the Arc die with the last
  in-flight request.

## Steps

| # | Step | Files | State |
|---|------|-------|-------|
| 1 | Shared `auth_header_matches` / `auth_header_accepts` + unit tests (5) | `src/configurations/proxy_pass_location_config.rs` | done |
| 2 | h1 `authorize` uses the helper; local `trim_ascii` removed | `src/h1_proxy_server/authorize.rs` | done |
| 3 | hyper path enforces the gate right after `find_location_index`, before `process_headers` → `ProxyPassError::Unauthorized` (401 tech page, upstream never contacted). `HttpRequestBuilder::get_authorization_header()` added | `src/http_proxy_pass/http_proxy_pass.rs`, `src/http_proxy_pass/http_request_builder.rs` | done |
| 4 | Generation counter + `pick_up_reload` + `get_http_listen_config`; h1 `HttpConnectionInfo::new` / `pick_up_reload`; reader forces endpoint re-resolution when the config was reloaded | `src/configurations/app_configuration.rs`, `src/configurations/app_configuration_inner.rs`, `src/h1_proxy_server/kick_of_h1_reverse_proxy_server.rs`, `src/h1_proxy_server/pipeline/reader.rs` | done |
| 5 | **hyper handlers pick up a reload.** `LiveEndpointCache` holds the connection's port configuration (`ArcSwap`) + its `seen_generation` + the per-`Host` `HttpProxyPass` cache, because the three are invalidated together. `load_current().await` is the first statement of `get_http_proxy_pass` on both handlers and returns the configuration to serve the request with; every later use of the old field reads that local instead. Both handlers lost their own `proxy_passes` map and `listen_port_config` field. | `src/tcp_listener/http_request_handler/{http.rs,https.rs,mod.rs,live_endpoint_cache.rs}` | done |
| 5b | **Regression found while wiring step 4 and fixed.** Forcing a re-resolve after a reload broke a request carrying no `Host` header: `try_find_endpoint_info` fell back to "the port's only nameless endpoint", which is `None` for a named vhost, so the connection was cut. It now takes `fallback_server_name` — the vhost the connection was accepted with (the TLS SNI) — used only when the request has no usable `Host`. `None` reproduces the old plain-HTTP behaviour. | `src/h1_proxy_server/h1_read_part.rs`, `src/h1_proxy_server/pipeline/reader.rs` | done |
| 6 | Docs: `docs/header-auth.md` — both request paths, a "Setting and rotating the value at runtime" section, the reversed check order on the hyper path, refreshed "Files involved". `docs/mcp.md` — `auth_header` works on `mcp-h2`, and reloads reach open connections. | `docs/header-auth.md`, `docs/mcp.md` | done |
| 7 | Verify — see "Verification" below. | — | done |
| 8 | Memory: `project_coalescing_hardening_backlog.md` (item closed), `project_auth_header_live_reload.md`. | memory dir | done |

## Verification

`cargo check` clean. `cargo test --bin my-reverse-proxy` → 215 passed (note:
the crate has no lib target, so `--lib` fails). 11 of those are new: 5 on
`auth_header_matches` and 6 on `pick_up_reload`'s decision table (generation
bump, no-op while the generation stands still, an unrelated write that must not
churn the connection, a genuinely replaced port, a port that disappeared, and
the non-HTTP lookup). `rustfmt` on the touched files; `cargo clippy` adds no new
warning in them — the two clippy *errors* in the repo are pre-existing, in
`src/tcp_listener/mcp/run_mcp_connection.rs` and
`src/tcp_utils/allocated_read_buffer.rs`, which this work does not touch.

End to end on a local harness (a throwaway upstream on 18100, an `http`
endpoint on 18080 → h1 byte pipeline, an `http2` endpoint on 18081 → hyper
path, control port 18000, `dynamic_configurations_file` as in production):

- **Gate**, identical on both paths and on `mcp`, `mcp-h2` and plain locations:
  absent → 401, wrong value → 401, `bearer` for a configured `Bearer` → 401,
  correct → proxied, surrounding blanks ignored, header name case-insensitive.
  On `mcp-h2` the correct token reaches the upstream stage (the harness upstream
  is h1-only, so it lands on 502 — past the gate).
- **Rotation on an already-open connection**, both paths, triggered both by
  `POST /api/configuration/ReloadPort` and by the production route
  (`reload_settings` over MCP, after `initialize`): one curl process issues
  three transfers on ONE connection — a slow request with the old token (parked
  in the upstream while the token is rotated underneath it), then the new token,
  then the old one. Result `200 / 200 / 401` with `num_connects=0` on the second
  and third, i.e. the new value applies and the old one is refused without the
  client reconnecting.
- **Counterfactuals** (temporarily neutering one function, then reverted):
  with the pick-up disabled the same sequence gives `200 / 401 / 200` — the
  connection keeps serving the pre-reload token, which is the bug. With
  `fallback_server_name` passed as `None` the Host-less request after a reload
  gets its connection cut. Both confirm the tests discriminate.
- **Host-less request on a named vhost across a reload** (raw socket, keep-alive):
  `200 / 200 / 200` — step 5b's regression does not occur.

## Out of scope / noted

- `endpoint.type = mcp` (raw TLS tunnel, `src/tcp_listener/mcp/`) parses no
  HTTP; `auth_header` cannot apply there. The MCP use case is
  `location.type = mcp` / `mcp-h2`, which is what production uses.
- Ordering divergence: h1 checks `auth_header` before endpoint-level
  google_auth; hyper checks it after g_auth + allowed_users (g_auth owns its
  own callback paths and runs before location resolution there). Irrelevant
  for MCP hosts (no google_auth) — left as is.
- One expected value per location; rotation with overlap (old+new both
  valid) is still not supported — a follow-up would make `auth_header`
  accept a list.
- The `dynamic_configurations_file` merge already handles this: hosts from
  the dynamic file are compiled like an include (`populate_settings.rs`),
  and `auth_header` goes through `apply_variables_opt`, so
  `${var}` / `${env:…}` work there too.

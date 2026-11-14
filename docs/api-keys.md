# Per-location header authentication

This document describes the `auth_header` option on a location: how it
works, what it guarantees, and the configuration patterns for the typical
use cases.

## Purpose

Some upstreams (notably MCP servers, internal admin panels, and webhook
receivers) need to be reachable only by callers that present a known
secret. Implementing this on the proxy keeps the upstream code unchanged
and stops unauthenticated traffic before any TCP connection to the
upstream is opened.

`auth_header` is an opt-in, per-location gate. The proxy validates one
header on every request to that location; on mismatch or absence the
request is refused with HTTP 401 and the upstream is never contacted.

## Configuration

Add `auth_header` to a location. The value is the **complete expected
`Authorization` header value**, scheme included:

```yaml
hosts:
  mcp.domain.com:443:
    endpoint:
      type: https
      ssl_certificate: my_ssl_cert
    locations:
    - path: /mcp
      type: mcp
      proxy_pass_to: http://internal_mcp:8100/mcp
      auth_header: "Bearer secret-token-123"
```

Any location type accepts `auth_header`: `http`, `http2`, `https`,
`mcp`, `mcp-h2`, `unix+http`, files, static. The check is applied on
both request paths — the h1 byte pipeline (`http` / `https`
endpoints) and the hyper path (`http2` / `https2` endpoints) — before
the request is dispatched to the upstream or content source, and both
compare the value the same way.

### With a variable

To keep secrets out of YAML, drive the value from a variable —
environment variable, custom variable, or a value loaded from another
file:

```yaml
variables:
  mcp_token: "Bearer ${env:MCP_TOKEN}"

hosts:
  mcp.domain.com:443:
    endpoint:
      type: https
      ssl_certificate: my_ssl_cert
    locations:
    - path: /mcp
      type: mcp
      proxy_pass_to: http://internal_mcp:8100/mcp
      auth_header: ${mcp_token}
```

`auth_header` is resolved through the same variable engine as other
string fields (see "System Variables", "Yaml variables", "Environment
variables" in the main README).

### Multiple services on one domain

Each location has its own `auth_header`, so different upstream services
can sit behind different secrets on the same hostname:

```yaml
hosts:
  api.domain.com:443:
    endpoint:
      type: https
      ssl_certificate: my_ssl_cert
    locations:
    - path: /service-a
      type: http
      proxy_pass_to: http://service-a-host:8000
      auth_header: "Bearer token-for-service-a"
    - path: /service-b
      type: http
      proxy_pass_to: http://service-b-host:8000
      auth_header: "Bearer token-for-service-b"
    - path: /public
      type: http
      proxy_pass_to: http://service-c-host:8000
      # no auth_header — anyone may hit /public
```

## Setting and rotating the value at runtime

`auth_header` can be written into the dynamic settings file and applied
without restarting the proxy:

1. `get_dynamic_settings` — read the current YAML.
2. Edit it (the file is merged like an `include:`, so a host declared
   there carries its locations and their `auth_header`) and write it
   back with `set_dynamic_settings`. It is a full-file replace, so send
   everything you want to keep.
3. `reload_settings` — compile and apply.

**Connections already open pick the new value up on their next
request.** This matters for MCP: a Streamable-HTTP client keeps one
connection open for hours, and a reload does not restart listeners or
drop sockets. Each connection notices that the port's configuration was
replaced and re-resolves its endpoint and locations before serving the
next request, so the window in which the old token still works is one
in-flight request, not the lifetime of the connection.

The same mechanism applies to everything else a location or endpoint
declares — upstream, header rules, `client_certificate_ca`. Adding an
mTLS requirement to an endpoint makes an already-open connection that
presented no certificate get 421 on its next request, so the client
re-opens one and performs mTLS: the fail-closed direction.

Only one expected value per location is supported, so a rotation is a
cut-over rather than an overlap: clients that still send the old token
are refused from the reload onwards. Roll the clients first, or publish
the new token on a second location.

## Validation rules

- **Header name**: `Authorization`, matched case-insensitively
  (`Authorization`, `AUTHORIZATION`, `authorization` all work).
- **Header value**: matched byte-for-byte after stripping surrounding
  ASCII whitespace from the request value. There is no scheme parsing
  — `"Bearer abc"` and `"bearer abc"` are different values, and only
  the first matches an `auth_header: "Bearer abc"` config.
- **No header at all** and **wrong value** produce the same outcome —
  HTTP 401 — so the proxy does not leak which condition failed.

## Failure response

On mismatch the proxy returns HTTP 401 with the body produced by the
existing `NOT_AUTHORIZED_PAGE` template (the same page the proxy uses
for any other authorization failure). The upstream is not contacted.
No `WWW-Authenticate` response header is added in this iteration.

## Header forwarding

If the request passes the check, the `Authorization` header is forwarded
to the upstream **unchanged**. The upstream may revalidate (defense in
depth) or ignore it. To strip it before forwarding, use the existing
`modify_http_headers.remove.request` block on the location:

```yaml
locations:
- path: /mcp
  type: mcp
  proxy_pass_to: http://internal_mcp:8100/mcp
  auth_header: "Bearer secret-token-123"
  modify_http_headers:
    remove:
      request:
        - authorization
```

## Combining with other auth mechanisms

`auth_header` is a per-location gate; the existing per-endpoint
`google_auth` and `client_certificate_ca` are per-endpoint identity
mechanisms. They layer cleanly:

1. The location-level header check runs **first** on the h1 pipeline.
   Failure → 401, the request stops here.
2. If the header check passes (or is not configured), the endpoint-level
   auth runs. Google OAuth may issue a redirect; client-certificate
   verification attaches a `HttpProxyPassIdentity::ClientCert` value.

On the hyper path the order is reversed — the endpoint's `oauth` gate,
`google_auth` and `allowed_users` run before the location is resolved,
so the `auth_header` check happens after them. The outcome only differs
for a location that combines `auth_header` with an endpoint-level
mechanism, which is not what either is used for: `auth_header` gates
machine endpoints, and the endpoint mechanisms identify humans. Both
paths contact the upstream only after every check has passed.

Use this layering when, for example, a public-facing UI uses Google
OAuth to identify the human user, but the same domain also exposes a
machine-to-machine endpoint that needs a static API key — set
`auth_header` only on the machine endpoint's location.

## When to use

- **MCP upstream protected by a static token.** The MCP client is
  configured with one URL plus a Bearer header; the proxy validates the
  header and forwards.
- **Internal admin endpoints not exposed to humans.** A static token
  shared between automation and the proxy is simpler than running an
  OAuth flow.
- **Webhook receivers** where the sender supports a custom
  `Authorization` value.

## When not to use

- **Per-user identity is needed.** `auth_header` does not authenticate
  individual users; it gates everyone with the same secret. Use Google
  OAuth or client certificates for user identity.
- **Multiple valid tokens are required.** Only one expected value per
  location is supported. If you need to rotate or revoke individual
  tokens, terminate auth on the upstream.
- **Browser-initiated requests.** Browsers cannot attach an
  `Authorization` header to navigations; cookie-based or OAuth flows
  fit better.

## Files involved

- `src/settings/location_settings.rs` — YAML field `auth_header`.
- `src/settings_compiled/populate_settings.rs` — variable substitution
  for `auth_header`.
- `src/scripts/compile_location_proxy_pass_to.rs` — passes the value
  from settings into the runtime config.
- `src/configurations/proxy_pass_location_config.rs` — runtime field
  carried on `ProxyPassLocationConfig`, plus `auth_header_matches` /
  `auth_header_accepts`: the one comparison both request paths use.
- `src/h1_proxy_server/authorize.rs` — the h1 check; finds the
  request's `Authorization` header in the raw byte buffer and hands it
  to `auth_header_accepts`.
- `src/h1_proxy_server/pipeline/reader.rs` — passes the resolved
  location into `authorize`.
- `src/http_proxy_pass/http_proxy_pass.rs` — the hyper check, right
  after the location is resolved and before any header processing;
  refusal is `ProxyPassError::Unauthorized` (the 401 tech page).
- `src/configurations/app_configuration.rs` — `generation` +
  `pick_up_reload`: how an open connection notices a reload.
- `src/tcp_listener/http_request_handler/live_endpoint_cache.rs` — the
  hyper connection's live port configuration and per-`Host` proxy-pass
  cache, invalidated together on a reload.

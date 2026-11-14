# API keys

This document describes `api_keys:` and `api_keys_auth:`: how a request is let through to a
location by a key it carries in `X-Api-Key`, where the keys come from, and the configuration
patterns for the typical cases. It took the place of `auth_header`, which compared the
`Authorization` header with one value per location.

## Purpose

Some upstreams - MCP servers above all, internal admin panels, webhook receivers - are to be
reachable only by callers which present a known secret. Checking it on the proxy keeps the upstream
unchanged, and stops a request without one before any connection to the upstream is opened.

A key is checked against a **set** - an id and its keys - so several clients get keys of their
own, a key is handed out or taken back without touching the others, and a key is rotated with an
overlap: the new one is added, the clients move to it, the old one is removed.

## Configuration

```yaml
variables:
  ci_mcp_key: ...                   # or an environment variable of the same name

api_keys:
  mcp_clients:                      # the id of a set, and its keys
  - 6f1c2a9e-claude-desktop
  - ${ci_mcp_key}
  admins:
  - very-secret-admin-key

hosts:
  mcp.domain.com:443:
    endpoint:
      type: https
      ssl_certificate: my_ssl_cert
      api_keys_auth: mcp_clients    # every location of the endpoint
    locations:
    - path: /mcp
      type: mcp
      proxy_pass_to: http://internal_mcp:8100/mcp
    - path: /admin
      proxy_pass_to: http://internal_mcp:8100/admin
      api_keys_auth: admins         # in place of mcp_clients
    - path: /health
      proxy_pass_to: http://internal_mcp:8100/health
      api_keys_auth: none           # open, although the endpoint is guarded
```

The client sends `X-Api-Key: 6f1c2a9e-claude-desktop`.

### Which set guards a location

1. `api_keys_auth` of the location, if it has one: a set, or `none` - the location is open.
2. Otherwise `api_keys_auth` of the endpoint: a set, or `none`.
3. Otherwise `api_keys_auth` of the endpoint's template (`endpoint_templates`).
4. Otherwise the location is open.

`none` is matched in any letter case, and can not be the id of a set.

### Where the keys of a set come from

A set is put together from every place which declares keys under its id - a key is in the set if
any of them has it:

- `api_keys:` of `~/.my-reverse-proxy`, of the files it includes, and of the dynamic settings file
  (written over MCP with `set_dynamic_settings`, applied with `reload_settings`);
- `api_keys:` of the answers of the urls of `real_time_configurations`, read every
  `refresh_interval`:

```yaml
real_time_configurations:
  urls:
  - https://keys.internal/proxy/api-keys
```

```yaml
# what https://keys.internal/proxy/api-keys answers
api_keys:
  mcp_clients:
  - tenant7-issued-key
```

A url's keys replace what it gave the read before; a url which fails to answer keeps what it gave.
They are taken as the url writes them: no variable is put into them.

### A set with no keys

A set nothing declares a key under - mistyped in `api_keys_auth`, or given by a url which has not
answered yet - lets **nobody** through. The endpoint is served and loads with the others; what the
set guards answers every request with 401 until the set has a key. `get_settings` and
`get_applied_settings` (MCP) list every set - declared, or named by an `api_keys_auth` - with how
many keys it has, from the files and from the urls, and whether it is used.

## The check

- The header name is matched case-insensitively (`X-Api-Key`, `x-api-key`, `X-API-KEY`).
- The value is compared byte for byte, letter case included, without the spaces and tabs around it.
  A key of the settings is taken without the spaces around it as well.
- A request has to carry **exactly one** `X-Api-Key`. Two are refused whatever they are - the header
  goes on to the upstream, and an upstream which reads the second one would tell the caller by a key
  nobody checked.
- Every key of the set is compared, each in a time which depends on the lengths only, so the time of
  an answer does not tell which key, or which part of one, is right.
- A missing key and a wrong one get the same answer.
- The check is the same on the h1 pipeline (`http` / `https` endpoints) and on the hyper path
  (`http2` / `https2`), for every location type: `http`, `http2`, `mcp`, `mcp-h2`, `unix+http`,
  `unix+http2`, files, static, `dynamic`.

## A refused request

- **401** with the `NOT_AUTHORIZED_PAGE` body. No `WWW-Authenticate` header. On an `http` / `https`
  endpoint the connection is closed after it.
- The upstream is not contacted.
- It is a **hard failure** of the client's address for the IP block-list: five within 15 seconds block
  the address for 5 minutes. An address of `global_settings.ip_blocklist_white_list` is never counted.
  `POST /api/IpBlocklist/Unblock` (control port) lifts a block.
- A connection which gets through to an endpoint - a TLS handshake and a `Host` are all it takes -
  forgives the soft failures of its address, never the hard ones. Before, every new connection took
  the count back, and a client which tried one wrong key after another, each on a connection of its
  own, was never blocked.

## Header forwarding

A request which passes goes to the upstream with its `X-Api-Key`: the upstream may tell its callers
apart by it, or check it again. To keep it from the upstream, take it off with `modify_http_headers`
of the location or of the endpoint - the key is checked before those are applied:

```yaml
locations:
- path: /mcp
  type: mcp
  proxy_pass_to: http://internal_mcp:8100/mcp
  api_keys_auth: mcp_clients
  modify_http_headers:
    remove:
      request:
      - x-api-key
```

`modify_http_headers` of `endpoint_templates` is not applied - not there.

## Changing the keys at runtime

- In a settings file or in the dynamic settings file: then `reload_settings` - or a reload of a port
  or of an endpoint, which take the keys of the files as they are then, too.
- By a url of `real_time_configurations`: on its next read.

Either way the connections already open check their next request against the new keys - an MCP
client which keeps one connection for hours included. A change of `api_keys_auth` itself (which set
guards what) is a change of the endpoint: it is picked up by an open connection on its next request
as well.

## What refuses the settings

- An id `none` in `api_keys:` - in a file the settings do not load; in the answer of a url that
  answer is refused, and what the url gave before stays.
- A key which is empty, has a control character, or still has `${` once the variables are put in.
  A key takes `${lower_case}` variables (from `variables:`, or an environment variable of that name).
  A `${UPPER_CASE}` name is one of the system variables, which are put into headers per request: it
  would stay in the key as the very text of the placeholder, which anyone reading the settings knows.
- `auth_header` on a location: it is removed, and a location with it left in would be open to
  everybody without a word. The error says what to use instead.

No error and no log line contains a key.

## Combining with other mechanisms

- `whitelisted_ip` of a location is checked before the key: an address which is not listed can not
  even try one.
- `google_auth` and `client_certificate_ca` of the endpoint identify a person; a key gates a machine.
  On the h1 pipeline the key is checked first, on the hyper path after the endpoint's checks; a
  request has to pass all of them either way.
- `oauth`: the proxy's own OAuth server checks the token in `Authorization`; a location which is
  also guarded by a set takes a request which carries both. The OAuth endpoints themselves
  (`/.well-known/...`, `/oauth/...`) are not guarded by `api_keys_auth`: a browser has to reach them.
- `type: mcp` and `type: tcp` endpoints read no request, so they can not check a key: an endpoint of
  either type which is given an `api_keys_auth` - of its own, of its template or of a location -
  serves nobody (see "An endpoint which can not apply an access setting" in the README). Guard an MCP
  server with `type: https` on the endpoint and a location of `type: mcp`.

## When not to use

- **Per-user identity is needed.** A key names a client, not a person. Use `google_auth` or client
  certificates.
- **Browser-initiated requests.** A browser does not add `X-Api-Key` to a navigation.

## Files involved

- `src/api_keys/` - checking a set, putting sets together, `request_has_api_key`, the block-list
  failure, and `ApiKeysStore`: the sets requests are checked against, swapped whole on a change.
- `src/settings/settings.rs`, `end_point_settings.rs`, `location_settings.rs`,
  `endpoint_template_settings.rs` - `api_keys:` and `api_keys_auth:`.
- `src/settings/real_time_configurations_settings.rs` - `api_keys:` of the answer of a url.
- `src/settings_compiled/populate_settings.rs` - the keys of the files, variables put in, checked,
  put together; `auth_header` refused.
- `src/settings_compiled/settings_compiled.rs` - `api_keys`, `dynamic_api_keys`, `get_api_keys`.
- `src/scripts/get_endpoint_api_keys_auth.rs` - the endpoint's set, from the endpoint or its template.
- `src/configurations/proxy_pass_location_config.rs` - the set which guards a location, and
  `api_keys_auth_accepts`.
- `src/h1_proxy_server/authorize.rs` - the h1 check.
- `src/http_proxy_pass/http_proxy_pass.rs` - the hyper check.
- `src/app/ip_blocklist.rs` - hard failures are not forgiven by a connection which gets through.

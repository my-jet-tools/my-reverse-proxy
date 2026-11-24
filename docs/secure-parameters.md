# Secure parameters of my-reverse-proxy

Status: draft, 2026-11-20. This document covers the proxy's own side: its keys, how it is
initialized, its store, and the operator's calls. The standard services follow to serve data to the
proxy is [encrypted-service-data.md](encrypted-service-data.md).

Built so far (`src/secure`): `/api/initialize` (over the control unix socket or the loopback), the
store with the network keys, the reading of encrypted sources, `ip_white_lists` in real-time
answers, the control port's servers decrypting encrypted calls and refusing replays, the private
keys of gateway clients (`/api/private-keys/v1/...`: installed, generated, given out;
`private_key:` of a client), the gateway server, the connections to gateways and the keys the
gateway server lets in (`/api/gateway-server/v1/...`, `/api/gateway-connections/v1/...`,
`/api/gateway-authorized-keys/v1/...`), the secure settings - hosts in the store
(`/api/secure-settings/v1/...`), the admin mode of MCP
(`/api/mcp/v1/admin-mode`), and `bin/encrypted_call` to send the calls. Body encryption is FlUrl's
and my-http-server's: the proxy has none of its own. Not built yet: the other parameters of the
store.

## Two keys

| Key | What it encrypts | Where it lives |
|---|---|---|
| files key | the store on the proxy's disk, and nothing else | nowhere: it is given to `POST /api/initialize` after every start and kept in memory until the process stops |
| network keys, one or several | every request and answer that carries secrets: the data the proxy reads from services, and the operator's calls | in the store, given in the same call |

- Every key is 32 random bytes written as standard base64, 44 characters:
  `openssl rand -base64 32`.
- The proxy never writes a key to its settings, a plain file, a log or an answer.
- If the files key is lost, the store is lost too, because nothing else opens it.

## `/api/initialize`

Served on the control port (`global_settings.http_control_port`, `127.0.0.1:8000` by default).

### `GET /api/initialize`

| Answer | |
|---|---|
| `200 True` | `POST /api/initialize` has succeeded since the proxy started. |
| `200 False` | It has not. This is the state after every start until the files key is given. |

The answer is text, exactly `True` or `False`. The call takes no key.

### `POST /api/initialize`

```
curl -X POST --unix-socket /var/run/my-reverse-proxy/control.sock http://localhost/api/initialize \
     -H 'Content-Type: application/json' \
     -d '{"key": "<files key>", "network_keys": ["<network key>", "<another network key>"]}'
```

`network_keys` is optional.

| Answer | |
|---|---|
| `200 Created` | There was no store yet. The proxy created it, encrypted with this key, and saved `network_keys` if they were given. |
| `200 Initialized` | The store opened with this key and is now in use. Also the answer when the proxy was already opened with this same key. |
| `400` | `key` or one of `network_keys` is not base64 of 32 bytes, or `network_keys` is an empty list. |
| `401 Invalid Key` | A store exists and this key does not open it, or the proxy is already initialized with another key. Nothing changed. |
| `500` | The store could not be read or written. The message names the file and the reason. |

- Once the store exists, it is the check for the key. The proxy keeps no hash of the key.
- `network_keys`, when given, replaces the whole stored list. Without it, the stored list stays.
- The first key of the list is the proxy's current key, the one it encrypts with.
- Only one initialize runs at a time. Whitespace around a key is ignored.
- The keys travel in plain text, so they are taken only over the control unix socket
  (`global_settings.control_unix_socket`) or over TCP from this host's own loopback, where nobody
  can read them on the way. A request from anywhere else, or one a proxy relayed (it carries
  `X-Forwarded-For`), gets `403`.
- The store is the file `global_settings.secure_store_file` names, `~/.my-reverse-proxy-secure`
  when it names none. In a container it has to be on a volume the proxy can write to. The file is
  `MRPS`, a version byte, a nonce and AES-256-GCM of the protobuf, under a key derived from the
  files key with HKDF-SHA-256; it is written to a file next to it first and then renamed, `0600`.
- Right after a success the urls of `real_time_configurations` are read, and every certificate and
  CA of the settings which has a source and is not loaded is loaded again: what was encrypted opens
  now.

## The store

- Protobuf records, encrypted with the files key, on the proxy's disk. It is not a settings file.
  Nobody edits it by hand: it changes only through its own set of methods.
- Parameters agreed so far:
  - a TLS certificate: an id, the certificate and its private key. An endpoint refers to it by the
    id, the way `ssl_certificate:` does today;
  - a CA for client certificates: an id and the CA certificate. Endpoints that refer to the id
    verify client certificates against it, the way `client_certificate_ca:` does today;
  - the encryption key for Google sessions, which today is the `session_key` of
    `global_settings.connection_settings`;
  - the client secret of a Google login (`g_auth.<id>.client_secret`);
  - the secrets of an `oauth:` block for MCP connectors: `client_secret`, `consent_password` and the
    key that signs the tokens. Today a generated signing key is written as plain JSON to
    `~/.my-reverse-proxy-oauth/<id>.json`;
  - API keys (`api_keys:`, sent by clients in `X-Api-Key`);
  - the secret header of `request_with_header_only` (the zone secret);
  - SSH credentials: passwords, passphrases, private keys (today these are files on disk) and the
    pass keys of `/api/SSH/InitPassKey` (today they live in memory only and are lost on restart);
  - the private key of a gateway client - built: a list of private keys by their ids, installed
    with `POST /api/private-keys/v1/set`, generated with `.../generate` (an id which has a key is
    refused), given out with `.../download` - the only answer which carries a private key - removed
    with `.../delete`, listed (public halves only) with `.../list`; a client names one with
    `private_key: <id>` and takes it at every connect;
  - connections to gateways - built: what an entry of `gateway_clients` says, with the handshake
    signed by a private key of the store, by their ids. See "Gateways" below;
  - the public keys the gateway server lets in - built: by their ids, besides the
    `authorized_keys` files. See "Gateways" below;
  - IP whitelists.
- Everything in the store survives a restart. Today, uploaded certificates and SSH pass keys are
  held in memory only.

## Reading data from services

Two places read sources, and both decrypt: `load_file` (certificates, private keys, CAs and
revocation lists from a file, `http(s)://` or ssh) and the reading of real-time configurations.
Both send `Accept-Encoding: aes128gcm`, and both decrypt with the same `BodyEncryptionKeys` the
control port has (`decrypt`: each key in turn, my-http-utils' aes128gcm).

- An answer with `Content-Encoding: aes128gcm` has to open with one of the keys. Otherwise the read
  fails, saying whether the proxy has no keys or none of them opens it.
- Anything else is decrypted if one of the keys opens it, and taken as it is if none does. The
  standard says "parse, and decrypt if that fails"; trying the keys first gives the same outcome,
  because AES-GCM never opens data that was not encrypted with the key, and it is one place
  instead of one per parser.
- A real-time answer may carry `ip_white_lists` (ip-whitelister's export). The entries of one id
  are put together from the settings files and every url. An entry that is not an IPv4 address, a
  range of them or `*` refuses the whole answer. After each read, the lists whose entries changed
  are put into the live configuration.

## The operator's calls

The methods that change the store, and the one that reads it, take an encrypted body and answer
encrypted, with the network keys. Body encryption is supported by FlUrl and my-http-server: how it
works - the body decrypted before the action runs, a replayed body refused, the answer encrypted -
is in my-http-server's `docs/http-actions/encrypted-requests.md`. What the proxy adds:

- The control port's servers get the network keys (`set_body_encryption_keys`): one list for its
  TCP address and its unix socket, replaced on each initialize.
- An action refuses with `415` a body which did not come encrypted, and answers with the key that
  decrypted the request (`HttpResultBuilder::encode(&info.key)`).
- The operator encrypts the calls with a tool kept in this repository (like `gateway_keygen`). The
  tool reads the key from a local file, so the key never appears in a chat, and sends the body with
  FlUrl's `encrypted(&key)`.

## Gateways

| Route (encrypted, `POST`) | Body | Answer |
|---|---|---|
| `/api/gateway-server/v1/set` | `{port, allowed_ip?, debug?}` | the server as kept; `409` when the port can not be had, or the settings have a gateway server |
| `/api/gateway-server/v1/delete` | `{}` | `{deleted}` |
| `/api/gateway-server/v1/get` | `{}` | `{secure_store, running: {source, listen, clients}}` |
| `/api/private-keys/v1/generate` | `{id}` | `{id, public_key}`; `409` when the id has a key |
| `/api/private-keys/v1/download` | `{id}` | `{id, private_key, public_key}`: the key in OpenSSH form; `404` when there is none |
| `/api/gateway-connections/v1/set` | `{id, remote_host, private_key, compress?, connect_timeout?, allow_incoming_forward_connections?, sync_ssl_certificates?, debug?}` | the connection as kept |
| `/api/gateway-connections/v1/delete` | `{id}` | `{id, deleted}` |
| `/api/gateway-connections/v1/list` | `{}` | `{gateway_connections: [{..., connected}]}` |
| `/api/gateway-authorized-keys/v1/set` | `{id, public_key, ip_white_list}` | `{id, public_key, ip_white_list}` |
| `/api/gateway-authorized-keys/v1/delete` | `{id}` | `{id, deleted}` |
| `/api/gateway-authorized-keys/v1/list` | `{}` | `{authorized_keys: [{id, public_key, ip_white_list}]}` |

- The gateway server of the store is `gateway_server` of the settings with no `authorized_keys`
  files - it lets in the keys of the store alone - listening at `0.0.0.0:<port>`. It is started
  when it is set and after every initialize, and stopped when it is removed. Set on another port,
  the new one listens before the one before stops, and a port which can not be had leaves the one
  before untouched; on the same port the one before stops first. While the settings have a
  `gateway_server`, the store's is refused.
- A connection of the store is a gateway client like one of the settings: started when it is set
  and after every initialize, replaced when it is set again (its gateway connection closed and
  opened anew), stopped when it is removed. The private key it names has to be in the store. The id
  of a gateway client of the settings is refused with `409`; ids are what a route names,
  `gateway:<id>->...`, so letters, digits, `-`, `_` and `.`.
- The gateway server checks every handshake against the keys of its `authorized_keys` files and the
  keys of the store as they are at that moment. `authorized_keys` may be left out: the server then
  lets in the store's keys alone - nobody before initialize.
- A key of the store is bound: its id is the gateway name the client comes in under, and its
  `ip_white_list` (at least one entry of `ip_white_lists`: an address, a range, a subnet, `*`) the
  addresses it comes from. Both are checked in the handshake, after the signature and before the
  server answers: a client under another name or from another address fails its handshake. A key
  of a file comes in under any name, from wherever `allowed_ip` lets in.
- Store fields: `gateway_connections` (tag 3), `gateway_authorized_keys` (tag 4) and
  `gateway_server` (tag 5) of the protobuf; an authorized key has its `ip_white_list` as tag 3.

## Secure settings

| Route (encrypted, `POST`) | Body | Answer |
|---|---|---|
| `/api/secure-settings/v1/get` | `{}` | the document, YAML text - nothing when there is none |
| `/api/secure-settings/v1/set` | the whole document, YAML; blank - remove it | `{bytes_kept}` |

- One YAML document of the schema of the settings file - hosts with their endpoints and locations,
  variables, lists - kept in the store (`settings_yaml`, tag 6), set and read as a whole.
- Merged with the settings files like the dynamic settings file, after it
  (`SettingsCompiled::load_settings`): a host of the document replaces one of the files with the
  same id; the variables of every file and of the document are one set.
- `set` compiles the settings with the document first (`load_settings_with_secure`) - a document
  which is not settings YAML, or with which they do not compile, is refused with `400` and nothing
  is kept, the error quoting nothing of it - then keeps it. Like the dynamic settings file, it is
  applied by a reload: the MCP tool `reload_settings`, in admin mode. The initialize which opens the
  store applies the settings with the document, as the files are applied at the start.

## MCP admin mode

- `POST /api/mcp/v1/admin-mode`, encrypted, `{"minutes": N}`: open for N minutes from now, 60 at
  most, in place of the time and the address it had; 0 closes it, from any address; `{}` is 10.
  Answer `{open, seconds_left, ip, country}`. It is closed after every start, and no MCP tool
  opens it.
- `POST /api/mcp/v1/admin-mode/get`, encrypted, `{}`: changes nothing; answer `{open, seconds_left,
  ip, country, your_ip, your_country, open_for_you}` - the address the admin commands of MCP are
  taken from, and the address of this call as the proxy sees it.
- It is open for the address of the call which opened it: the last entry of `X-Forwarded-For` when
  the call comes from the loopback (the proxy relays it so), the peer address otherwise; the unix
  socket and the bare loopback are `this host`. A middleware in front of MCP writes down where the
  requests of each MCP session come from (`McpSessionCallers`), and a tool which needs admin mode
  runs only for a session which has come from that address alone.
- While it is open, the MCP tools which change the proxy work: `reload_settings`,
  `generate_private_key`, `set_gateway_connection`, `delete_gateway_connection`,
  `set_gateway_authorized_key`, `delete_gateway_authorized_key`. Closed, they answer that it is
  closed and how it is opened.
- Reading is never gated: `get_mcp_admin_mode`, `get_public_key`, `get_gateway_connections`,
  `get_gateway_authorized_keys`. No MCP tool gives a private key.

## Until initialize

Endpoints that do not depend on the store work as usual. An endpoint that needs a parameter from
the store serves nobody until initialize, the way an endpoint waiting for a manually uploaded
certificate does today.

# Secure parameters of my-reverse-proxy

Status: draft, 2026-11-18. This document covers the proxy's own side: its keys, how it is
initialized, its store, and the operator's calls. The standard services follow to serve data to the
proxy is [encrypted-service-data.md](encrypted-service-data.md).

Built so far (`src/secure`): `/api/initialize` (over the control unix socket or the loopback), the
store with the network keys, the reading of encrypted sources, `ip_white_lists` in real-time
answers, the control port's servers decrypting encrypted calls and refusing replays, and the
private keys of gateway clients (`/api/private-keys/v1/...`, `private_key:` of a client, and
`bin/encrypted_call` to send the calls). Body encryption is FlUrl's and my-http-server's: the proxy
has none of its own. Not built yet: the other parameters of the store, the operator's calls and the tool that
encrypts them.

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
    with `POST /api/private-keys/v1/set`, removed with `.../delete`, listed (public halves only)
    with `.../list`; a client names one with `private_key: <id>` and takes it at every connect;
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

## Until initialize

Endpoints that do not depend on the store work as usual. An endpoint that needs a parameter from
the store serves nobody until initialize, the way an endpoint waiting for a manually uploaded
certificate does today.

# Secure parameters of my-reverse-proxy

Status: draft, 2026-11-18. This document covers the proxy's own side: its keys, how it is
initialized, its store, and the operator's calls. The standard services follow to serve data to the
proxy is [encrypted-service-data.md](encrypted-service-data.md).

Built so far (`src/secure`): `/api/initialize`, the store with the network keys, the reading of
encrypted sources, and `ip_white_lists` in real-time answers. Not built yet: the other parameters
of the store, the operator's calls and the tool that encrypts them.

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
curl -X POST http://127.0.0.1:8000/api/initialize \
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
- A request which came through a proxy (it carries `X-Forwarded-For`) is refused with `403`: the
  keys travel in plain text and go to the control port directly.
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
  - the private key of a gateway client;
  - IP whitelists.
- Everything in the store survives a restart. Today, uploaded certificates and SSH pass keys are
  held in memory only.

## Reading data from services

Two places read sources, and both decrypt: `load_file` (certificates, private keys, CAs and
revocation lists from a file, `http(s)://` or ssh) and the reading of real-time configurations.
Both send `Accept-Encoding: aes128gcm`.

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
encrypted, with the network keys:

```
POST <path> HTTP/1.1
Content-Type: application/json
Content-Encoding: aes128gcm

<the JSON encrypted with one of the network keys, binary>
```

- The proxy tries each of its keys until one decrypts the body. It encrypts the answer with the key
  that decrypted the request.
- The decrypted JSON carries `ts`, the sender's clock in unix seconds. The proxy accepts a body only
  when `ts` is within 5 minutes of its own clock, and accepts each body once: it remembers the
  salts of the last 5 minutes.
- `415` for a body without `Content-Encoding: aes128gcm`. `401 Invalid Key` for a body that no key
  decrypts, whose `ts` is off, or that was already accepted. `503` until initialize.
- The operator encrypts the calls with a tool kept in this repository (like `gateway_keygen`). The
  tool reads the key from a local file, so the key never appears in a chat.

## Until initialize

Endpoints that do not depend on the store work as usual. An endpoint that needs a parameter from
the store serves nobody until initialize, the way an endpoint waiting for a manually uploaded
certificate does today.

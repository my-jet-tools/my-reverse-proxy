# Encrypted data for my-reverse-proxy: the service side

This document is a prompt. Give it to the agent that builds or changes a service my-reverse-proxy
reads data from: ip-whitelister, a certificate service, a real-time configuration service. It says
what the service must serve, and how my-reverse-proxy makes the HTTP request and reads the answer.
It does not cover how my-reverse-proxy stores anything.

## The task

Make the service follow this standard:

1. The service keeps its data encrypted under a **files key** that it never stores. After every
   start it receives the files key over `POST /api/initialize`.
2. In the same call it receives the **network keys** (one or several) and keeps them in its
   encrypted store.
3. Every request and answer that carries secrets is encrypted with a network key, using the HTTP
   standard for encrypted bodies: `Content-Encoding: aes128gcm` from
   [RFC 8188](https://www.rfc-editor.org/rfc/rfc8188).

There are two keys, and each has one job. The files key encrypts the service's store and nothing
else. It is sent only to `POST /api/initialize`. The network keys cover the requests: the answers
my-reverse-proxy reads, my-reverse-proxy's own calls that carry a body, and the operator's calls to
the service.

There may be several network keys: one per pair of services, an old one and a new one while they
are being rotated, and so on. Whoever decrypts tries each key it has until one opens the body.

If the service already has its own initialize calls (ip-whitelister has `POST /api/is-initialized`
and an `initialize` that answers 409 the second time), replace them with the ones below. If the
service encrypts its admin API with the files key today (ip-whitelister does), move that API to the
network keys, as described in [Requests with a body](#requests-with-a-body).

## The keys

| Key | What it encrypts | Where it lives |
|---|---|---|
| files key | the service's own data on its disk | nowhere: it is given to `POST /api/initialize` after every start and kept in memory until the process stops |
| network keys, one or several | every request and answer that carries secrets | in the service's encrypted store. my-reverse-proxy and the operator's tool hold the keys they share with the service |

- Every key has the same format: 32 random bytes written as standard base64, 44 characters. Make
  one with `openssl rand -base64 32`.
- The service never writes a key to its settings, a plain file, a log or an answer.
- If the files key is lost, the store is lost too, because nothing else opens it.

## `/api/initialize`

### `GET /api/initialize`

Is the service initialized?

| Answer | |
|---|---|
| `200 True` | `POST /api/initialize` has succeeded since the service started. |
| `200 False` | It has not. This is the state after every start until the files key is given. |

The answer is text, exactly `True` or `False`. The call takes no key and says nothing about the
keys.

### `POST /api/initialize`

```
curl -X POST --unix-socket <socket> http://localhost/api/initialize \
     -H 'Content-Type: application/json' \
     -d '{"key": "<files key>", "network_keys": ["<network key>", "<another network key>"]}'
```

`network_keys` is optional.

| Answer | |
|---|---|
| `200 Created` | There was no store yet. The service created it, encrypted with this key, and saved `network_keys` if they were given. This is the first initialize of an installation. |
| `200 Initialized` | The store opened with this key and is now in use. Also the answer when the service was already opened with this same key. |
| `400` | `key` or one of `network_keys` is not base64 of 32 bytes, or `network_keys` is an empty list. |
| `401 Invalid Key` | A store exists and this key does not open it, or the service is already initialized with another key. Nothing changed. |
| `500` | The store could not be read or written. The message names the file and the reason. |

- The answers are text, and the words in backticks are exact.
- Once the store exists, it is the check for the key: if the store opens, the key is right. The
  service keeps no hash of the key anywhere.
- When `network_keys` is given, the service saves the list into the store, replacing the whole list
  that was there. A key listed twice is kept once. Without `network_keys`, the stored list stays.
  Call initialize again with the same files key to change the list.
- The first key of the list encrypts the answers that are not replies to an encrypted request
  (my-reverse-proxy's reads). The service tries every key on an encrypted request.
- To rotate a key: give the readers the new key next to the old one. Then put the new key first on
  the service. Once every party has it, remove the old key everywhere.
- Only one initialize runs at a time.
- Whitespace around a key is ignored.
- The keys travel here as plain text, so the call is for the inside only. Serve it on a unix socket
  or the internal network. A request relayed by my-reverse-proxy carries `X-Forwarded-For`: refuse
  it with `403`.

## Until initialize

- Every read by my-reverse-proxy answers `503` with a sentence saying what is missing. It never
  gets an empty answer. On a failed read my-reverse-proxy keeps what it read last. An empty
  whitelist would lock everybody out, and a missing certificate would break an endpoint.
- An initialized service that has no network keys yet answers `503` to a read of secret data:
  "no network keys: POST /api/initialize with network_keys".
- `GET /api/initialize`, `POST /api/initialize` and the liveness checks always answer.

## What my-reverse-proxy reads

| Where in its settings | What the answer holds, once decrypted |
|---|---|
| `real_time_configurations.urls` | A real-time configuration in YAML or JSON: `hosts`, `additional_hosts`, `api_keys`, any of them may be left out. `ip_white_lists` (ip-whitelister's `GET /api/export`) is being added on the proxy side. |
| `ssl_certificates[].certificate` and `.private_key`, as `http://` or `https://` sources | PEM: the certificate chain, and the private key. |
| `client_certificate_ca[].ca` and `.revocation_list`, as `http://` or `https://` sources | PEM: the CA certificate, and the revocation list. |

The plain text of the answer is exactly what an unencrypted answer would be.

## The request

my-reverse-proxy sends:

```
GET <the url from its settings> HTTP/1.1
Accept-Encoding: aes128gcm
```

- It is a plain GET, with no body and no key in it.
- my-reverse-proxy repeats it on its timer: `refresh_interval` for real-time configurations, the
  refresh timer for certificates.
- A service may serve several urls, one per dataset.

## The answer

```
HTTP/1.1 200 OK
Content-Type: application/yaml
Content-Encoding: aes128gcm
Cache-Control: no-store

<the body: the data encrypted as described below, binary>
```

- `Content-Type` is the type of the decrypted data: `application/yaml`, `application/json` or
  `application/x-pem-file`.
- The service encrypts every answer that carries secret data, whether or not the request asked
  with `Accept-Encoding`.
- The answer is encrypted with the first of the service's network keys.
- A fresh random salt goes into every answer, so the same data never looks the same twice.
- `200` with the data, or `503` while the service is not initialized or has no network keys. Any
  other status counts as a failed read.

## How my-reverse-proxy reads the answer

1. It takes the body.
2. With `Content-Encoding: aes128gcm`, it tries each of its network keys until one decrypts the
   body, then parses the result.
3. Without that header, it tries to parse the body as it is (YAML or JSON, or PEM). If that fails
   and it has network keys, it tries to decrypt the body as `aes128gcm` with each of them, then
   parses the result.
4. If neither works, the read fails. my-reverse-proxy keeps what it read last and logs why.

It reads sources that are not HTTP the same way. A local file, or a file over ssh, may hold the
encrypted bytes. The proxy then uses step 3.

## Requests with a body

This covers a request that carries data to a service: my-reverse-proxy's call (ip-whitelister's
`POST /api/whitelist`), or the operator's call (creating a user, adding a permanent whitelist
entry).

```
POST <path> HTTP/1.1
Content-Type: application/json
Content-Encoding: aes128gcm

<the body: the JSON encrypted with one of the network keys, binary>
```

- `Content-Type` is the type of the decrypted body.
- The service tries each of its network keys until one decrypts the body.
- The decrypted JSON carries `ts`, the sender's clock in unix seconds, next to the fields of the
  call.
- The service accepts a body only when `ts` is within 5 minutes of its own clock, and accepts each
  body once. It remembers the salts (the first 16 bytes of a body) of the last 5 minutes. A
  recorded request therefore cannot be sent again.
- The service answers:
  - `415` to a body without `Content-Encoding: aes128gcm`;
  - `401 Invalid Key` to a body that none of its keys decrypts, whose `ts` is off, or that was
    already accepted;
  - `503` while it is not initialized or has no network keys.
- The answer is encrypted with the key that decrypted the request, unless it is one of the refusals
  above.

## The encryption: `aes128gcm` (RFC 8188)

```
body   = header || record_0 || record_1 || ... || record_last
header = salt (16 random bytes) || rs (uint32, big-endian) || idlen (1 byte) || keyid (idlen bytes)
```

- `IKM` is the network key in use: its 32 bytes, decoded from base64.
- `PRK = HMAC-SHA-256(key = salt, message = IKM)`
- `CEK` is the first 16 bytes of `HMAC-SHA-256(PRK, "Content-Encoding: aes128gcm" || 0x00 || 0x01)`.
- `NONCE_BASE` is the first 12 bytes of `HMAC-SHA-256(PRK, "Content-Encoding: nonce" || 0x00 || 0x01)`.
- The nonce of record `i` (counting from 0) is `NONCE_BASE XOR i`, with `i` written as a 12-byte
  big-endian number.
- The plain text of a record is a chunk of the data, then the delimiter `0x01`, or `0x02` for the
  last record. Zero bytes (`0x00`) of padding may follow the delimiter.
- A record is `AES-128-GCM(CEK, nonce, plain text)`: the ciphertext, then the 16-byte tag. Every
  record but the last is exactly `rs` bytes long, and the last one is at most `rs`. With
  `rs = 4096`, a record carries up to 4079 bytes of data.
- `keyid` may be empty. A reader with several keys tries each one. A wrong key already fails on
  the tag of the first record, so each extra key tried costs one record, never the whole body.
- To read a record: decrypt it, check the tag, strip the trailing `0x00` padding, then take off the
  delimiter.
- If a record fails its tag, the whole body is refused: the key is wrong or the body is damaged.
  A body without a `0x02` record is cut short and is refused too. Nothing is accepted in part.

In Rust this takes about 60 lines with `aes-gcm`, `hmac` and `sha2`. In a browser, WebCrypto has
HMAC-SHA-256 and AES-GCM.

### Test vectors

Every implementation must pass these. The first two come from RFC 8188 and use base64url. The third
uses a 32-byte key in this standard's format, with standard base64.

| | Key (IKM) | rs | keyid | Body | Plain text |
|---|---|---|---|---|---|
| RFC 8188 §3.1 | `yqdlZ-tYemfogSmv7Ws5PQ` | 4096 | empty | `I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-ly8Thjg` | `I am the walrus` |
| RFC 8188 §3.2 | `BO3ZVPxUlnLORbVGMpbT1Q` | 25 | `a1` | `uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHOG8chz_gnvgOqdGYovxyjuqRyJFjEDyoF1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS_uA` | `I am the walrus` |
| This standard | `AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=` (the bytes 0 to 31) | 4096 | empty | `oKGio6SlpqeoqaqrrK2urwAAEAAAd4lQdR25LBqmiaRlRbryiJTYDikv7OAMtydV1zSRPu4Fy70/BNOmc0q8RjUIqwznMD1/D9zqlMc=` | `ip_white_lists:\n  office:\n  - 10.0.0.1\n` |

The salt is the first 16 bytes of each body. The tests must check that:

- all three bodies decrypt to their plain text;
- encrypting the first and the third plain text with the salt taken from their bodies gives the
  bodies byte for byte;
- a body decrypted with another key is refused;
- a body cut short, or with one byte changed, is refused.

## Checklist

- `GET /api/initialize` and `POST /api/initialize` answer exactly as above.
- The files key and the network keys are never on disk in plain text, and never in logs or answers.
- `network_keys` is saved in the encrypted store. Every initialize that carries it replaces the
  whole list.
- Every answer to my-reverse-proxy that carries secret data is `aes128gcm` with the first network
  key and a fresh salt, sent with `Content-Encoding: aes128gcm` and `Cache-Control: no-store`.
- Every request with a body (my-reverse-proxy's and the operator's) is `aes128gcm` with one of the
  network keys, carries `ts`, and is accepted once. The service tries each key, and answers with
  the key that decrypted the request.
- The files key encrypts only the store and is sent only to `POST /api/initialize`.
- Reads answer `503`, never an empty answer, until the service is initialized and has network keys.
- The test vectors pass.

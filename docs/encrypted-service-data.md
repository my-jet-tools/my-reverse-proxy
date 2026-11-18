# Serving data to my-reverse-proxy, encrypted

This document is a prompt. Give it to the agent that builds or changes a service my-reverse-proxy
reads data from: ip-whitelister, a certificate service, a real-time configuration service. It says
how the service answers my-reverse-proxy's request with the data encrypted, and how
my-reverse-proxy reads the answer. How a service gets its keys and where it keeps them is outside
this document.

## The task

When an answer carries secrets, the service encrypts it with a network key, using the HTTP
standard for encrypted bodies: `Content-Encoding: aes128gcm` from
[RFC 8188](https://www.rfc-editor.org/rfc/rfc8188). my-reverse-proxy holds the same key and
decrypts the answer.

## Network keys

- A network key is 32 random bytes, written as standard base64 (44 characters). Make one with
  `openssl rand -base64 32`.
- my-reverse-proxy may hold several keys: one per service, an old one and a new one while a key is
  being rotated, and so on. It tries each key until one opens the answer.
- The service encrypts its answers with one key: its current key.
- To rotate a key: give my-reverse-proxy the new key next to the old one, switch the service to the
  new key, then remove the old key from my-reverse-proxy.

## What my-reverse-proxy reads

| Where in its settings | What the answer holds, once decrypted |
|---|---|
| `real_time_configurations.urls` | A real-time configuration in YAML or JSON: `hosts`, `additional_hosts`, `api_keys` and `ip_white_lists` (ip-whitelister's `GET /api/export` answers with it), any of them may be left out. |
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
- The service does not have to authenticate it: the request carries nothing secret, and the answer
  is useless without a key.
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
- A fresh random salt goes into every answer, so the same data never looks the same twice.
- `200` with the data. A service that cannot serve the data yet (it has no key, for instance)
  answers `503` with a sentence saying why, and never an empty answer. On a failed read
  my-reverse-proxy keeps what it read last. An empty whitelist would lock everybody out, and a
  missing certificate would break an endpoint. Any other status counts as a failed read.

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

## The encryption: `aes128gcm` (RFC 8188)

```
body   = header || record_0 || record_1 || ... || record_last
header = salt (16 random bytes) || rs (uint32, big-endian) || idlen (1 byte) || keyid (idlen bytes)
```

- `IKM` is the network key: its 32 bytes, decoded from base64.
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

- Every answer to my-reverse-proxy that carries secret data is `aes128gcm` with the service's
  current key and a fresh salt, sent with `Content-Encoding: aes128gcm` and
  `Cache-Control: no-store`.
- A service that cannot serve the data answers `503`, never an empty answer.
- The test vectors pass.

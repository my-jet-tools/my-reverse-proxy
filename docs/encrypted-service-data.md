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

## The encryption

Body encryption is supported by FlUrl and my-http-server. How it works, and what goes on the wire,
is in their documentation (my-http-server: `docs/http-actions/encrypted-requests.md`,
`docs/http-actions/responses.md`). A service built on my-http-server answers with
`HttpResultBuilder::encode(&key)`, `key` being the network key.

## Checklist

- Every answer to my-reverse-proxy that carries secret data is encrypted with the service's current
  key: `HttpResultBuilder::encode(&key)`.
- A service that cannot serve the data answers `503`, never an empty answer.

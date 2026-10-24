# Running

```sh
cargo build --release
./target/release/my-reverse-proxy
```

The process takes no command-line arguments: it reads `$HOME/.my-reverse-proxy` (see below), so a second
instance on the same machine is started by pointing `HOME` somewhere else:

```sh
HOME=/srv/proxy-b ./target/release/my-reverse-proxy
```

On a settings-level error it refuses to start and prints the reason; a per-endpoint problem is reported through
the API instead (see "How a failure is reported").

On Windows, see "Running on Windows" at the end of this file.

# Configuration Example

File should be at `~/.my-reverse-proxy` location with yaml format:

```yaml
global_settings:
  http_control_port: 9000 # admin ui, REST API (/api/...), Swagger (/swagger) and MCP (/mcp) are
                          # served HERE - never on the ports under `hosts:`
  http_control_ip: 127.0.0.1 # Optional: address of the control port, IPv4 or IPv6 (in quotes: "::1"); absent = 0.0.0.0 (see "Certificates provided at runtime")
  connection_settings:
    buffer_size: 512Kb # Buffer, which is allocated twice (read/write) per connection to pass traffic by
    connect_to_remote_timeout: 5000 # ms — timeout to connect to remote host (type: tcp endpoints)
    session_key: # key to encrypt session data. Not having this field means that key is going to be randomly generated
  show_error_description_on_error_page: true # Show error description on error page
  default_h2_livness_url: /health # Optional: HTTP path used by the h2 upstream pool supervisor as an active liveness probe (see "HTTP/2 upstream pool" section)
  debug_ip: 10.0.0.5 # Optional: source ip (or a list of them) shown a detailed page instead of a bare 400 (see "Debug ip" section)
  
hosts:
  localhost:8000:
    endpoint:
      type: https
      ssl_certificate: my_ssl_cert  
      client_certificate_ca: ca_id

    locations:
    - type: http
      proxy_pass_to: ssh:username@ssh_host:22->remote_host:5123      

  localhost:8001:
    endpoint:
      type: http
    locations:      
    - type: http
      proxy_pass_to: http://remote_host:5123

  localhost:8002:
    endpoint:
      type: tcp  
    locations:        
    - proxy_pass_to: 10.0.0.5:5123    

  localhost:8003:
    endpoint:
      type: tcp
    locations:      
    - proxy_pass_to: ssh:username@ssh_host:22->10.0.0.5:5123    

  8005:
    endpoint:
      type: http2  

    locations:       
    - path: /service1
      type: http2          
      proxy_pass_to: ${my_ssh_config}->remote_host:5123
    - path: /service2
      type: http2     
      proxy_pass_to: http://remote_host:5123  

ssl_certificates:
  - id: my_ssl_cert
    certificate: ~/certs/cert.cer
    private_key: ~/certs/cert.key  

client_certificate_ca:
  - id: ca_id
    ca: ~/certs/ca.cer  
    revocation_list: ~/certs/revocation_list.crl

  # The `ca:` source is optional: an entry without it means the certificate is uploaded at
  # runtime - see "Certificates provided at runtime". Everything ELSE about the ca (its
  # revocation list, `unlimited_expiration`) is always taken from this entry, so an endpoint may
  # only reference an id declared here.
  - id: uploaded_ca
    unlimited_expiration: true   # accept client certificates whose validity dates have passed


variables:
  my_ssh_config: ssh:user@10.12.13.14:22
```

## Reaching a remote resource by ip (no A record needed)

Several settings point at a resource the proxy loads: a local path, `ssh:user@host:port->/path`, or an
`http://` / `https://` url it downloads.

| Setting | What is loaded |
| --- | --- |
| `ssl_certificates` → `certificate:`, `private_key:` | the TLS certificate and its private key |
| `client_certificate_ca` → `ca:`, `revocation_list:` | the client ca and its revocation list |
| `ssh` → `private_key_file:` | the key for ssh connections (the gateway reads it only from a local file) |
| `type: static` location → `body:` | the response body |

A url addressed by a domain only works once the domain resolves: someone has to create an A record at the
registrar (or in the DNS zone) and keep it pointed at the right server. When you already know the server's
ip, write the domain first and the ip after an `@`. Taking the service that issues certificates as the
example:

```yaml
ssl_certificates:
  - id: my_ssl_cert
    # the usual form - needs an A record for certs.example.com:
    #   https://certs.example.com:8005/api/certificates/v1/certificate?domain=x-fine.online
    certificate: https://certs.example.com@12.3.3.2:8005/api/certificates/v1/certificate?domain=x-fine.online
    private_key: https://certs.example.com@12.3.3.2:8005/api/certificates/v1/private-key?domain=x-fine.online
```

No A record is needed at all: the proxy connects to `12.3.3.2:8005` directly and never asks DNS about
`certs.example.com`. Everything else works as if the domain had been resolved:

- the TLS handshake presents `certs.example.com` as the server name (SNI), so a server that holds several
  certificates picks the right one;
- the server certificate is verified against `certs.example.com` - an ip that answers with a certificate for
  another name is refused, so pinning the ip does not weaken TLS;
- the request carries `Host: certs.example.com:8005`, so the server routes it exactly as a request made by
  the domain.

The same form reaches a server that the domain's public A record does not point to - for example an internal
instance serving the same name.

Both parts can come from variables, like any other value in the settings:

```yaml
variables:
  certs_domain: certs.example.com
  certs_ip: 12.3.3.2

ssl_certificates:
  - id: my_ssl_cert
    private_key: https://${certs_domain}@${certs_ip}:8005/api/certificates/v1/private-key?domain=x-fine.online
```

Only `${lower_case}` names are substituted in a source - from `variables:`, then from the environment. An
`${UPPER_CASE}` name is reserved for the system variables resolved per request and is not substituted here.

The part after `@` must be an ip, optionally with a port (IPv6 in brackets: `[addr]` or `[addr]:port`); a
name there is refused, not resolved. The part before `@` is the bare domain - the port always goes after the
ip. A malformed url is reported the same way as an unreachable source. The form applies to the resources in the table above when they are fetched directly - not
behind `ssh:...->`, and not to `proxy_pass_to`, whose upstreams are connected to by a different path.

## Certificates provided at runtime

A TLS server certificate and a client-certificate CA can both be **delivered while the proxy is running**,
from the admin ui or over the API, instead of being read from a file next to the configuration.

Everything below is served on the **control port** (`global_settings.http_control_port`, `9000` in these
examples) - the admin ui, `/api/...`, `/swagger` and `/mcp`. The ports under `hosts:` never serve it.

Nothing on the control port asks for a login. It listens on every IPv4 address of the host (`0.0.0.0`) unless
`global_settings.http_control_ip` names one; `127.0.0.1` keeps it to the host itself:

```yaml
global_settings:
  http_control_port: 9000
  http_control_ip: 127.0.0.1   # an IPv6 address in quotes: "::1"
```

A value that is not an ip address fails the settings load, the same way a wrong `debug_ip` does - the port does not
fall back to every address.

### 1. Declare it

```yaml
ssl_certificates:
  - id: my_ssl_cert          # no `certificate:` / `private_key:` -> uploaded at runtime
                             # (specifying only one of the two is an error)

client_certificate_ca:
  - id: partner_ca           # no `ca:` -> uploaded at runtime
    revocation_list: ~/certs/partners.crl   # optional; may be given even when the ca itself is
                                            # uploaded - it is read during an upload that sends no
                                            # `crl`, and kept refreshed from this file afterwards
    unlimited_expiration: false             # optional, see "How a client certificate is verified"

hosts:
  "partners.example.com:443":
    endpoint:
      type: https
      ssl_certificate: my_ssl_cert
      client_certificate_ca: partner_ca     # must be an id declared above
    locations:
      - proxy_pass_to: http://10.0.0.5:5123
```

The two certificate kinds differ in one important way: **a `client_certificate_ca` id must be declared**,
because its `unlimited_expiration` and its `revocation_list:` are read from that entry, while an
`ssl_certificate:` id may be referenced by an endpoint with no `ssl_certificates:` entry at all (declare one
only to give it a source).

| Configuration | Result |
| --- | --- |
| `client_certificate_ca` id on an endpoint, not declared in the `client_certificate_ca` section | **host** fails to compile |
| `client_certificate_ca` on a `type: http` / `http2` / `tcp` endpoint | **host** fails to compile - there is no TLS handshake of its own to present a client certificate in |
| the same `id` twice in `ssl_certificates` or `client_certificate_ca` | the **settings load** fails - the duplicate would be silently ignored |
| `ssl_certificate` id on an endpoint, not declared in the `ssl_certificates` section | fine - the endpoint listens and reports `ssl_cert_missing: true` until something is uploaded under that id |
| an `ssl_certificates` entry with only one of `certificate:` / `private_key:` | not caught at load time - the endpoint behaves as if the entry were manual (`ssl_cert_missing: true`) and the reason is printed to the log |

**How a failure is reported.** A *settings-level* failure means the whole file does not compile: at start-up
the process refuses to run and prints the reason (there is no control port to ask), and a reload leaves the
previous configuration in place. A *host-level* failure at start-up or after a full reload drops that one host
- it disappears from its port's `endpoints` (the port itself disappears from `ports` only if no other host on
it compiled) and the reason appears in `errors` of `GET /api/configuration/Current`. The same mistake applied
through `POST /api/configuration/ReloadEndpoint` comes back as a `400` from that call instead, with the same
message.

### 2. What happens until the material arrives

The endpoint **starts and keeps listening**, but every TLS handshake on it is cut:

- no server certificate -> the handshake is aborted (the waiting client is *not* added to the ip blocklist);
- no client-certificate CA -> the same, so an endpoint that requires mTLS **never serves anyone unverified**.

From the client side that is indistinguishable from a rejected certificate: the connection dies with no HTTP
response (`curl` reports 35/55/56 depending on timing), and the proxy deliberately tells the client nothing
about which check failed. **Diagnose from the API**, where every endpoint object carries the state:

```bash
curl -s http://127.0.0.1:9000/api/configuration/Current
```
```json
{ "host": "partners.example.com:443",
  "ssl_cert_id": "my_ssl_cert",  "ssl_cert_missing": true,
  "client_cert_id": "partner_ca", "client_cert_missing": true,
  "client_cert_unlimited_expiration": false }
```

The admin ui shows the same as a red **SSL cert not loaded** / **Client cert CA not loaded** badge on the
endpoint; clicking the badge opens a dialog that takes the PEM text and performs the upload below.

### 3. Upload

Multipart form-data (what Swagger sends; `-F 'field=<file'` makes curl send the file *content* as the field):

```bash
# TLS server certificate -> 204 No Content, no body
curl -X POST http://127.0.0.1:9000/api/SslCertificates/Init \
     -F 'cert_id=my_ssl_cert' -F 'certificate=<fullchain.pem' -F 'private_key=<privkey.pem'

# client certificate CA (+ optional revocation list) -> 200 with the json summary below
curl -X POST http://127.0.0.1:9000/api/ClientCertificates/Init \
     -F 'ca_id=partner_ca' -F 'ca=<partner-ca.crt' -F 'crl=<partners.crl'
```

The same over a json body - this is what the admin ui uses. PEM travels **base64-encoded on a SINGLE line**
(`base64 < file | tr -d '\n'`), because a json string would otherwise carry unresolved escapes:

```bash
curl -X POST http://127.0.0.1:9000/api/ClientCertificates/InitFromPem \
     -H 'Content-Type: application/json' \
     -d '{"ca_id":"partner_ca","ca":"<base64 of the PEM>","crl":"<base64, optional>",
          "replace_different_ca":false}'
```

| endpoint | fields | answer |
| --- | --- | --- |
| `POST /api/SslCertificates/Init` (form-data) | `cert_id`, `certificate`, `private_key` (PEM text) | `204`, no body |
| `POST /api/SslCertificates/InitFromPem` (json) | `cert_id`, `cert`, `private_key` (base64 of PEM) | `200` with a summary |
| `POST /api/ClientCertificates/Init` (form-data) | `ca_id`, `ca`, `crl` (optional), `replace_different_ca` (optional) | `200` with the summary below |
| `POST /api/ClientCertificates/InitFromPem` (json) | the same fields, PEM ones base64 | `200` with the summary below |

```json
{ "ca_id": "partner_ca", "cn": "Partner Issuing CA",
  "expires": "2027-09-09T08:59:52+00:00", "expired": false, "is_ca": true,
  "endpoints": ["partners.example.com:443"],
  "crl_records": 12, "crl_source": "configured_revocation_list",
  "replaced_different_authority": false, "unlimited_expiration": false }
```

`crl_source` says where the revocation list came from: `uploaded`, `configured_revocation_list` (read from the
`revocation_list:` of the entry, and kept refreshed from it afterwards), `kept_from_previous` (the list of the
ca being replaced) or `none` - **nothing can be revoked**. Only the count is reported, never the serials; to
check that a particular certificate is covered, compare `openssl crl -in <file> -noout -text` with
`openssl x509 -in <client.crt> -noout -serial` yourself.

Rotating to a **different** authority carries the previous one's list over as `kept_from_previous` (nothing is
ever silently un-revoked), but those serials were issued by the old authority and mean nothing under the new
one - upload the new authority's own `crl` in the same request, or right after.

**To add or replace the revocation list of a ca that is already loaded**, upload the same ca again together
with the new `crl`. The subject and public key are unchanged, so it counts as a renewal and needs no
`replace_different_ca`; the answer reports the new `crl_records` / `crl_source`.

### 4. Why an upload is refused

Nothing is stored unless the whole check passes, so a refusal always leaves the previous state intact.

A **server certificate** is refused when the private key does not match the certificate, when no endpoint
references `cert_id`, or when the certificate does not cover every SNI required of it - the server name of each
referencing endpoint, and the domains of the certificate it replaces (so a replacement can not quietly narrow
what is served). One consequence is worth knowing before designing around it: an endpoint whose host key has no
server name (a bare port such as `8005:`, or a unix socket) offers no SNI to validate against, so the FIRST
upload for such an id is refused - there is nothing to check the certificate belongs to. Give the endpoint a
server name, or establish the certificate from a configured source once.

Error bodies are plain text and carry a `Validation error: ` prefix, e.g.
`Validation error: The uploaded PEM contains 2 certificates. ...`.

A **client certificate CA**:

| Message | Cause | What to do |
| --- | --- | --- |
| `No https endpoint requires client certificate ca 'x'` | no endpoint in the RUNNING configuration references the id (typo, or the host failed to compile) | fix the configuration and reload first, then upload |
| `The uploaded PEM contains N certificates` | a bundle was pasted | upload the single CA that **directly issues** the client certificates (for root -> issuing-ca -> client, the issuing ca) |
| `The pasted material contains a PRIVATE KEY block` | the wrong file, or a cert+key bundle | paste only the `-----BEGIN CERTIFICATE-----` block; treat the pasted key as compromised |
| `... is currently loaded with a DIFFERENT authority` | the uploaded ca is not a renewal of the loaded one (subject + public key differ), so it changes which clients are trusted | intended rotation: repeat with `replace_different_ca=true` |
| `... declares 'revocation_list: ...' which can not be read` | the configured revocation list is unreachable | fix the source, or upload the CRL together with the ca - the proxy refuses to install a ca without the revocations it is configured to enforce |
| `Can not read the configuration to resolve the revocation list ...` | the settings files do not compile right now | fix the configuration; the upload reads it to find the ca entry |

### 5. Read back, and undo

```bash
GET    /api/SslCertificates/Current                  # every loaded server certificate
GET    /api/SslCertificates/Certificate?certId=...   # metadata: cn, expires, origin, domains
GET    /api/ClientCertificates/Ca?caId=...           # metadata: cn, expires, expired, is_ca, origin,
                                                     #           crl_records, unlimited_expiration
DELETE /api/ClientCertificates/Ca?caId=...           # drop a loaded ca (the undo for a wrong upload)
```

Reads return **metadata only** - no PEM material is ever handed out, and a private key never leaves the proxy.
Reading - or deleting - an id that is not loaded answers `404` with a plain-text message (error bodies are
text, not json).
`DELETE` answers `200` with the ca id and the endpoints it just disarmed; they go back to cutting **new**
handshakes until a ca is provided again - like a replacement, it does not drop connections that are already
open. A ca that has a `ca:` source comes back on the next `RefreshCaCertificate` or reload; a manually
uploaded one has to be uploaded again.

To apply a configuration change without restarting:

```bash
curl -X POST http://127.0.0.1:9000/api/configuration/ReloadEndpoint -F 'endpoint_id=partners.example.com:443'
curl -X POST http://127.0.0.1:9000/api/configuration/ReloadPort     -F 'port=443'
```

`endpoint_id` is the host key itself (`partners.example.com:443`), without the quotes it may carry in the yaml. Uploaded certificates survive a reload - they
live in the process, not in the configuration. **A restart does not**: see "Lifecycle".

### 6. From an agent (MCP)

The control port also serves MCP at `/mcp`. The workflow is status -> inspect -> upload:

| tool | purpose |
| --- | --- |
| `get_ssl_endpoints_status` / `get_client_ca_endpoints_status` | which endpoints are missing material, with the `cert_id` / `ca_id` to use |
| `get_ssl_certificate` / `get_client_certificate_ca` | metadata of what is loaded under an id (check before replacing) |
| `init_ssl_certificate` / `init_client_certificate_ca` | the upload, same validation as the REST endpoints |

Over plain REST the equivalent of the two status tools is `GET /api/configuration/Current`, whose endpoint
objects carry `ssl_cert_id` / `ssl_cert_missing` and `client_cert_id` / `client_cert_missing`.

### 7. How a client certificate is verified

At the TLS handshake, in this order - failing any of them rejects the connection:

1. it is inside its own validity window - **unless** the ca entry declares `unlimited_expiration: true`;
2. it is signed by the loaded ca (the signature is verified against the ca's public key);
3. its serial is not in the ca's revocation list;
4. the client proves it holds the certificate's private key (rustls hands the CertificateVerify signature to
   the proxy, which verifies it against the presented certificate - so a copy of someone else's certificate,
   or of the ca certificate itself, is not enough to authenticate).

Per request, two more things are checked, because mTLS is bound to the handshake and a connection can carry
requests for another vhost (HTTP/2 coalescing, keep-alive with a different `Host`): the ca that verified the
connection must be the ca this endpoint requires, and a certificate that was accepted **past its expiry**
under `unlimited_expiration` is refused by an endpoint that does not declare it. Both answer `421 Misdirected
Request`, so the client re-opens a dedicated connection and performs mTLS against this endpoint.

`unlimited_expiration: true` turns off **only step 1**, and only for that ca - the escape hatch for a partner
whose certificates have expired but who still has to connect. The signature, the revocation list, the proof of
possession and the per-request rules above all stay in force. It is reported by the dashboard, by
`GET /api/configuration/Current` (`client_cert_unlimited_expiration`), by `GET /api/ClientCertificates/Ca`,
by both MCP tools and by the upload result, so it can not be quietly forgotten. Because the flag is read from the
`client_certificate_ca:` entry into the endpoint's compiled configuration - not into the loaded certificate -
changing it applies on the next `ReloadEndpoint` of a host that references that ca, and the certificate does
not have to be re-uploaded.

What is deliberately **not** enforced, and worth knowing before relying on it:

- **no chain building**: exactly one certificate is the trust anchor and intermediates sent by the client are
  ignored, which is why an upload refuses a multi-certificate PEM;
- **the ca's own expiry** is not checked (an expired ca keeps verifying clients); it is reported as `expired`
  on every surface instead;
- mTLS identity is decided **during the handshake**: replacing a compromised ca, uploading a new revocation
  list or deleting the ca does not drop connections that are already open.

### 8. Lifecycle

Uploaded material is held **in memory only**. It survives reloads, but a **restart of the proxy loses it**:
every endpoint that depends on it goes back to cutting handshakes until it is uploaded again. Treat a restart
of a host with runtime-provided certificates as an outage, or give the entry a real source.

An uploaded certificate is also **manually managed**: nothing re-reads or renews it, and the renewal timer
skips it, until the configured source is re-established with `POST /api/configuration/RefreshSslCertificate` /
`RefreshCaCertificate` (both take the id as form-data - `cert_id` / `ca_id`). `RefreshCaCertificate` answers
`400` for an entry that has no `ca:` source, because there is nothing to refresh from; `RefreshSslCertificate`
answers `204` in the same situation without doing anything.

The one exception is a client ca whose entry declares a `revocation_list:` **and that was uploaded without a
`crl` field**: that list is loaded during the upload (`crl_source: configured_revocation_list`) and keeps being
refreshed from its source by the CRL timer. An uploaded `crl` is the operator's explicit list and is never
overwritten from a source.

## Http request endpoints
### Headers
By default all the headers of each request are passed to headers of each response accordingly both ways (ServerRequest->RemoteRequest and RemoteResponse->ServerResponse);

It is possible to add custom headers to request by adding yaml section:

Globally - add or remove headers to each request on each endpoint
```yaml
global_settings:
  all_http_endpoints:
    modify_http_headers:
      add:
        request:
        - name: x-real-ip
          value: '${ENDPOINT_IP}'
        response:
        - name: header-name1: 
          value: value1
        - name: header-name2: 
          value: value2
      remove:
        request:
        - header-name1
        - header-name2
        response:
        - header-name3
        - header-name4

```

On endpoint level - add header to each endpoint
```yaml
hosts:
  localhost:8000:
    endpoint:
      type: http  
      modify_http_headers:      
        add:
          request:
          - name: x-real-ip
            value: '${ENDPOINT_IP}'
          response:
          - name: header-name1
            value: value1
          - name: header-name2
            value: value2
        remove:
          request:
          - header-name1
          - header-name2
          response:
          - header-name3
          - header-name4        
```

On location level - add header to each endpoint

```yaml
hosts:
  localhost:8001:
    endpoint:
      type: http
    locations:      
    - type: http
      proxy_pass_to: http://remote_host:5123
      modify_http_headers:         
        add:
          request:
          - name: x-real-ip
            value: '${ENDPOINT_IP}'
          response:
          - name: header-name1
            value: value1
          - name: header-name2
            value: value2:
        remove:
          request:
          - header-name1
          - header-name2
          response:
          - header-name3
          - header-name4 
```

## Serving the folder with files

### Serving from the local folder
```yaml
hosts:
  localhost:8001:
    endpoint:
      type: http
    locations:      
    - proxy_pass_to: ~/web_content
      default_file: index.html
```
default_file - serves with '/' (root) path

### Serving from remote ssh folder

```yaml
hosts:
  localhost:8001:
    endpoint:
      type: http
    locations:      
    - proxy_pass_to: ssh:user@10.0.0.5:22->~/web_content
      default_file: index.html
```

### Serving from a folder behind a gateway

```yaml
hosts:
  localhost:8001:
    endpoint:
      type: http
    locations:
    - proxy_pass_to: gateway:gateway_name->/home/user/web_content
      default_file: index.html
```

The folder is one on the other end of the gateway `gateway_name`. Through a gateway a file travels as a single frame, so it can be at most about 4.9 MiB: a bigger one is answered 404.

### How a request picks a file

Whatever the folder is - local, behind ssh or behind a gateway:

- The request path is the path of the file inside the folder. The query string is not a part of it: `/index.html?v=1` serves `index.html`. To serve a folder under a prefix, give the location a `path` and `strip_path: true` (see [strip_path](#strip_path)): the request path without the prefix is then the path of the file.
- `default_file` is served for the root: `/`, and `/?utm=x` as well. Without `default_file` the root is answered 404.
- A path with a `..` segment is answered `400 Bad Request`, written as it is or percent-encoded - `/../x`, `/%2e%2e/x`, `/..%2fx`. So is a path with a control character in it - percent-encoded, or as it is where a request line can carry one. A request path does not get out of the folder.
- A path with an empty segment or a `.` segment - `//x`, `/./x` - is answered `400 Bad Request` as well. To the file system it is the file `/x`, and a location is picked by the path as it is written: served, it would get the file past the location which guards `/x` - its `drop`, its `auth_header`. A file has one path.
- On Windows a name has more spellings than these, and a path which uses one is answered `400 Bad Request` too: a segment which ends with `.` or a space (`/private./x` is `/private/x` to Windows), holds a `\` or a `:` (`/private\x`, `/private::$INDEX_ALLOCATION/x`), is a device name - `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`, `CONIN$`, `CONOUT$`, with an extension or without - or has a `~` and a digit in it, the way a short 8.3 name ends (`/PRIVAT~1/x` for `private-files`). That is wider than a short name: `report~2.html` is refused as well. The check is made by a proxy which runs on Windows, for every folder it serves; a folder on a Windows host behind ssh or a gateway is read by that host, and a proxy on Linux does not make it. And it does not cover all: letters other than `a`-`z` are told apart by case by a location and not by the file system, and short names on other file systems (an SMB share) take other forms. On Windows, do not guard a subfolder of a served folder with a location of its own - serve it from a folder of its own.
- It is the request path which is checked. A symbolic link inside the folder is followed wherever it points, a file whose name begins with a dot is served like any other, and `default_file` and the folder are taken from the settings as they are.
- A file name is not percent-decoded: `/my%20file.txt` is a file named `my%20file.txt`, not `my file.txt`.
- A file which is not there is answered 404. So is a path which is there and is not a file - a directory - and a name longer than the file system takes, behind ssh the same as in a local folder.

Two things depend on the type of the endpoint:

- On `http` and `https` endpoints only `GET` and `HEAD` are served, any other method is answered 404. A `HEAD` is answered with the head of the response the same `GET` gets, and no body. `http2` and `https2` endpoints do not look at the method.
- When the ssh host or the gateway can not be reached, the answer is 503 on `http` and `https` endpoints, and 500 on `http2` and `https2` endpoints.


### Serving static content

Example of serving static content with custom headers and body

```yaml
  7700:
    endpoint:
      type: http

    locations:
    - type: static
      status_code: 200
      content_type: text/html
      body: <h2>Body H2</h2><h3>Body H3</h3>
```


Example of serving redirect to the same url but with https schema

```yaml
  7700:
    endpoint:
      type: http

    locations:
    - type: static
      status_code: 302
      modify_http_headers:
        add:
          response:
          - name: Location
            value: https://${HOST_PORT}${PATH_AND_QUERY}
```


### System Variables which can be used to populate headers or content

* ${ENDPOINT_IP} - ip of server listen endpoint;
* ${ENDPOINT_SCHEMA} - http or https schema of listen endpoint;
* ${CLIENT_CERT_CN} - Common name of client certificate if endpoint is protected by client certificate;
* ${PATH_AND_QUERY} - path and query of request;
* ${HOST_PORT} - host and port of request;

### Environment variables

As well variables can be read from environment variables

Priory of reading is:
* System variables;
* Yaml variables
* Environment variables


### Variable tips.
* All the system variables are upper cased;
* All the environment variables are upper cased;
* All the custom variables are lower case;


Example of custom variable:
```yaml
variables:
  my_ssh_config: ssh:user@10.12.13.14:22
```

## Types of endpoints

### Http
```yaml
hosts:
  localhost:8000:
    endpoint:
      type: http
```

### Http2
```yaml
hosts:
  localhost:8000:
    endpoint:
      type: http2
```

### Https

Serves http/1.1 over TLS1.3 and TLS1.2

```yaml
hosts:
  localhost:8000:
    endpoint:
      type: https
      ssl_certificate: my_ssl_cert        
```

### Https2

Serves https/2 over TLS1.3 and TLS1.2
Fallbacks to http/1.1 if client does not support http2

```yaml
hosts:
  localhost:8000:
    endpoint:
      type: https2
      ssl_certificate: my_ssl_cert        
```

#### WebSocket support on Http2 / Https2

`Http2` and `Https2` endpoints accept WebSocket connections from the client
side. Supported endpoint × upstream combinations:

| Client endpoint | Upstream location type | Works |
|-----------------|------------------------|-------|
| `https2`        | `http`                 | yes   |
| `https2`        | `http2`                | yes   |
| `https1`        | `http`                 | yes   |
| `http2`         | `http` / `http2`       | yes (non-browser h2 clients only) |

Notes:
- Browsers do WebSocket over HTTP/2 only on TLS — use `https2` for
  browser-initiated WebSocket.
- On `https2` the client's ALPN pick decides how a WebSocket arrives: an
  RFC 8441 extended CONNECT over h2 (browsers), or a plain HTTP/1.1 `Upgrade`
  when the client negotiates `http/1.1`. Cloudflare always reaches an origin
  the second way, even with "HTTP/2 to Origin" on. Both are proxied.
- For an upstream of type `http2` (or `unix+http2`) the upstream service must
  itself support WebSocket-over-HTTP/2. Services built on `MyHttpServer`
  support it from version `0.8.3`.
- Both WebSocket pumps (H1 and H2) honor the cascade `read_timeout` /
  `write_timeout` (defaults 180000 ms / 30000 ms, resolved global → endpoint;
  see [Timeouts & connection tuning](#timeouts--connection-tuning--overview)).
  An idle connection — no traffic in either direction — is torn down after
  `read_timeout`. Traffic in one direction keeps it open: a server pushing to
  a client which sends nothing is not cut. `read_timeout` **must exceed the
  heartbeat interval** (of either side) or quiet connections will be dropped
  falsely.

### Tcp
```yaml
hosts:
  localhost:8000:
    endpoint:
      type: tcp
```

A tcp endpoint forwards bytes to its location - it has one. `whitelisted_ip`, of the endpoint and of the location, is checked by the address of the connection. `auth_header`, `google_auth` and `allowed_users` can not be checked on it: see "An endpoint which can not apply an access setting".

### Mcp (Model Context Protocol)
MCP endpoints provide TCP forwarding with enhanced debugging capabilities for Model Context Protocol connections. They forward raw TCP traffic to remote MCP servers.

**Basic Configuration:**
```yaml
hosts:
  localhost:8000:
    endpoint:
      type: mcp
      debug: true  # Optional: enables debug logging for MCP connections
    locations:
    - proxy_pass_to: remote_host:5123
```


#### MCP endpoints examples
```yaml
hosts:
  mcp.domain.com:443:
    endpoint:
      type: mcp
    locations:
    - proxy_pass_to: http://internal_mcp_server:8100
```

A `type: mcp` endpoint bridges to its **first** location and reads no request, so it does not look at a `path`: one endpoint is one MCP server. To serve several MCP servers under the paths of one host, use `type: https` on the endpoint with locations of `type: mcp` (see "Location types").

**Access settings:**

- `whitelisted_ip` - of the endpoint and of the location - is checked by the address of the connection.
- `auth_header` of a location, `google_auth` and `allowed_users` can not be checked: the bridge reads no header and no session. Settings with one of them load, and the endpoint serves nobody - see "An endpoint which can not apply an access setting". To guard an MCP server with them, use `type: https` on the endpoint with a location of `type: mcp`.
- `oauth` on a `type: mcp` endpoint is refused when the settings load.


**Remote Host Configuration:**
The `proxy_pass_to` field supports different formats:

1. **Direct TCP connection:**
```yaml
locations:
- proxy_pass_to: remote_host:5123
```

2. **With HTTP prefix (automatically stripped):**
```yaml
locations:
- proxy_pass_to: http://remote_host:5123
```

**Note:** HTTPS (`https://`), `ssh:` and `gateway:` are not supported as a remote host for MCP endpoints: the bridge opens a plain TCP connection to `host:port`. To reach an MCP server over ssh or a gateway, use `type: https` on the endpoint with a location of `type: mcp`.

**MCP Endpoint Features:**
- TLS on the listening side - with `ssl_certificate`, or a self-signed certificate when none is given - and a plain TCP connection to the MCP server, a fresh one for every client connection
- Bidirectional byte forwarding, nothing of it parsed
- Read/write timeouts and the buffer size of the connection (see "Connection Settings")

**Logging:**
Every connection is logged with its id (`MCP[id]`): the route it took, and how each direction ended - which side closed, a timeout, an error - with the bytes forwarded before that (`->To MCP Server->` for client-to-server, `<-From MCP Server<-` for server-to-client). `debug: true` adds a line for every accepted connection; the content of the messages is not logged.

**Connection Settings:**

All optional, in **milliseconds** (integer); the buffer size accepts a raw byte count or a `Kb`/`Mb` suffix (e.g. `512Kb`, `1Mb`). `read_timeout`/`write_timeout` are the generic transport timeouts from the [timeout cascade](#timeouts--connection-tuning--overview) (resolved global → endpoint) — the same keys also govern H1 transfer and TCP port-forward. `mcp_buffer_size` is endpoint-scoped only.

| Setting             | YAML key            | Default              | Description |
|---------------------|---------------------|----------------------|-------------|
| Read Timeout        | `read_timeout`      | 180000 ms (3 min)    | Max idle on either side before the tunnel is torn down. Also bounds how long a dropped upstream goes unnoticed. |
| Write Timeout       | `write_timeout`     | 30000 ms (30 sec)    | Max time to wait for write operations. |
| Buffer Size         | `mcp_buffer_size`   | 512 KB (`512Kb`)     | Per-connection read buffer. |

```yaml
hosts:
  localhost:8443:
    endpoint:
      type: mcp
      ssl_certificate: my_ssl_cert
      read_timeout: 600000       # ms — optional, default 180000 (3m)
      write_timeout: 15000       # ms — optional, default 30000 (30s)
      mcp_buffer_size: 1Mb       # optional, default 512Kb
    locations:
    - proxy_pass_to: mcp-server:5123
```

**Example: Multiple MCP Endpoints:**
```yaml
hosts:
  localhost:8443:
    endpoint:
      type: mcp
      ssl_certificate: mcp_cert  # Optional: without it the certificate is a self-signed one
      debug: true
    locations:
    - proxy_pass_to: mcp-server-1:5123

  localhost:8444:
    endpoint:
      type: mcp
      # No ssl_certificate - TLS with a self-signed certificate
      debug: false  # Disable debug for production
    locations:
    - proxy_pass_to: mcp-server-2:5123
```

**Troubleshooting:**
- If connections fail, check that the remote MCP server is accessible
- Enable `debug: true` to see detailed connection and data flow information
- Check firewall rules for both the listening port and remote host port

## Location types

None tls connections can not infer which type of HTTP protocol endpoint supports (HTTP/1.1 or HTTP2). For this reason it is possible to specify type of location explicitly.

### How a request picks a location

A request goes to the first location, in the order of the settings, whose `path` the request path starts with. The rules of that location - its `auth_header`, its `whitelisted_ip` - are the rules of the request, and the path goes on to the upstream as it was received, unless the location has `strip_path` (see [strip_path](#strip_path)).

The match is by the start of the string, not by whole segments: the location `/a` takes `/ab/x` as well as `/a/x`. A `path` meant for a subtree should end with `/` - `/a/`.

The paths are compared percent-decoded (one pass) and without the case of letters: `/%73ecure/x` is a request of the location `/secure`, the same as `/secure/x` and `/SECURE/x`. An upstream decodes a path, so a location picked by the path as it is written would let such a request past the rules of `/secure`. The query string is not a part of the path.

So a request is taken only when its path names the resource in one way. A path with a `..`, a `.` or an empty segment is answered `400 Bad Request` before a location is looked for, on every http endpoint and for every type of location:

- `/open/../secure/x`, `//secure/x`, `/./secure/x` - an upstream resolves such a segment, and would serve `/secure/x` to a request which was let in by another location;
- the same segment percent-encoded or set apart by a backslash - `%2e%2e`, `.%2e`, `%2e`, `..%2f`, `%2f` in the place of an empty segment, `..\`, `..%5c`;
- `..;` and `.;` - to an upstream which takes path parameters off first they are `..` and `.`.

The last segment may be empty (`/api/`), dots inside a name are a part of the name (`/a..b`, `/.well-known/x`), and the query string is not looked at. The request is answered as an ordinary one: its body is read, the connection goes on, nothing is counted against the source ip.

### strip_path

By default the upstream gets the path the client sent. With `strip_path: true` it gets the path without the part the location was picked by:

```yaml
hosts:
  9443:
    endpoint:
      type: https
      ssl_certificate: mt_fleet
    locations:
    - path: /mt4-direct-live-1/
      proxy_pass_to: http://127.0.0.1:8200
      strip_path: true
```

- `/mt4-direct-live-1/metrics?x=1` goes to the upstream as `/metrics?x=1`, and `/mt4-direct-live-1/` as `/`. What is left always starts with `/`.
- The query string is kept as it is.
- The part which is cut is the part which matched (see [How a request picks a location](#how-a-request-picks-a-location)): `/MT4-Direct-Live-1/metrics` and `/%6Dt4-direct-live-1/metrics` go as `/metrics` too. What is left goes on as it was received, escapes and all: `/mt4-direct-live-1/a%2Fb` goes as `/a%2Fb`.
- A `path` without a trailing `/` is cut the same way: the location `/mt4` sends `/mt4/metrics` as `/metrics` and `/mt4` as `/`, but also `/mt4x/metrics` as `/x/metrics`. End the `path` with `/`.
- The cut may join what was on its two sides into a `..`, a `.` or an empty segment which the path did not have as it came: the location `/a` would send `/a..%2Fx` as `/..%2Fx` and `/a%2Fx` as `/%2Fx`. Such a request is answered `400 Bad Request`, like a path which came so. With a `path` which ends with `/` it does not happen.
- The path of `proxy_pass_to` is not used, with or without `strip_path`: `proxy_pass_to: http://127.0.0.1:8200/base` sends `/metrics`, not `/base/metrics`. Only an `mcp` location uses that path (see [Mcp / Mcp-h2](#mcp--mcp-h2)).
- `${PATH_AND_QUERY}` in a request header of `modify_http_headers` stays the path the client sent.

It works for the location types which send the request on: `http`, `http2`, `unix+http`, `unix+http2` - direct, `ssh:...->http://...` and `gateway:<name>->http://...` - a `dynamic` location, and a folder of files. A folder is then served under a prefix: the location `/static/` serves `/static/css/a.css` from `<folder>/css/a.css`, and `/static/` is the `default_file`. It is the same on every type of http endpoint, for a WebSocket upgrade as well.

The settings are refused at load time where `strip_path: true` has no meaning:

- an `mcp` / `mcp-h2` location - every request goes to the path of its `proxy_pass_to`;
- a `static` location - it answers by itself;
- a `drop` location - it closes the connection;
- any location of a `type: tcp` or a `type: mcp` endpoint - they forward bytes, there is no request path;
- a `path` which, percent-decoded, is not UTF-8 text - the cut could fall inside a letter.

What the upstream sends back is not rewritten. A redirect (`Location: /login`) or a cookie path (`Set-Cookie: ...; Path=/`) of the upstream reaches the client as it is, without the prefix: an upstream which is published under a prefix has to know it, or use relative links.

A location with `strip_path` publishes every path of its upstream. When another location guards a part of the same upstream, the stripped one goes past it:

```yaml
    locations:
    - path: /admin/
      proxy_pass_to: http://127.0.0.1:5123
      auth_header: "Bearer secret"
    - path: /public/
      proxy_pass_to: http://127.0.0.1:5123
      strip_path: true
```

`/public/admin/x` is a request of `/public/`, which has no `auth_header`, and goes to the upstream as `/admin/x`.

### Http

Used for http/1.1 connections

```yaml
localhost:8001:
    endpoint:
      type: http
    locations:      
    - type: http
      proxy_pass_to: http://remote_host:5123
```

### Http2

Used for http/2 connections

```yaml
localhost:8001:
    endpoint:
      type: http
    locations:      
    - type: http2
      proxy_pass_to: http://remote_host:5123
```

### Unix+Http

Used for http/1.1 connections through a Unix domain socket.

Unix socket path must start with `/` or `~`. A leading `~/` is expanded to
`$HOME/…` at connect time, so configs are portable across users.

```yaml
localhost:8001:
    endpoint:
      type: http
    locations:
    - type: unix+http
      proxy_pass_to: /var/run/myapp.sock

    - type: unix+http
      proxy_pass_to: ~/sockets/myapp.sock     # expands to $HOME/sockets/myapp.sock
```

### Unix+Http2

Used for http/2 connections through a Unix domain socket. Same path rules as
`unix+http` (leading `~/` expands to `$HOME/…`).

```yaml
localhost:8001:
    endpoint:
      type: http
    locations:
    - type: unix+http2
      proxy_pass_to: /var/run/myapp.sock

    - type: unix+http2
      proxy_pass_to: ~/sockets/myapp.sock
```

### Mcp / Mcp-h2

Publishes one MCP (Model Context Protocol) server under one path. `mcp` talks
HTTP/1.1 to the upstream, `mcp-h2` talks HTTP/2 — otherwise the two are the
same location type.

`mcp` lives on an ordinary `http` / `https` endpoint:

```yaml
mcp.domain.com:443:
    endpoint:
      type: https
      ssl_certificate: my_ssl_cert
    locations:
    - path: /service-a
      type: mcp
      proxy_pass_to: http://service-a:8000/mcp

    - path: /service-b
      type: mcp
      proxy_pass_to: http://service-b:8000/mcp
```

`mcp-h2` needs an `http2` / `https2` endpoint (see the note below):

```yaml
mcp2.domain.com:443:
    endpoint:
      type: https2
      ssl_certificate: my_ssl_cert
    locations:
    - path: /service-c
      type: mcp-h2
      proxy_pass_to: http://service-c:8000/mcp
```

An MCP location differs from a plain `http` / `http2` location in exactly three
ways:

- **The request path is rewritten** onto the path in `proxy_pass_to`. The whole
  Streamable-HTTP protocol lives on one URL, so the client's path only picks the
  location and carries nothing the upstream can use — write the upstream path
  explicitly (`http://host:8000/mcp`, not `http://host:8000`, which rewrites to
  `/`).
- **The read timeout is the long MCP one** (1 hour). The listening SSE stream
  legitimately idles between server-initiated messages, and the ordinary read
  timeout would tear a healthy stream down.
- **A failed upstream drops the client connection** instead of substituting an
  HTML error page — a JSON-RPC client cannot read one, and the transport
  dropping is the one thing it does act on.

Everything else — connecting, pooling, liveness, retries — is the ordinary
`http` / `http2` upstream machinery. In particular the upstream pool is keyed by
`host:port` **plus the upstream path**, so several MCP servers published on one
`host:port` under different paths never share a connection.

Notes:

- MCP does not go through a gateway: a location of `type: mcp` / `type: mcp-h2`
  whose `proxy_pass_to` is `gateway:...` is refused at load time.

- `mcp-h2` is served by the HTTP/2 request path, so it needs an endpoint of
  `type: http2` / `type: https2`. Under an `http` / `https` endpoint the config
  is refused at load time with an explicit message.
- Do not set `compress: true` on an MCP location: it gzips the body of a
  request on its way to the upstream - the JSON-RPC messages - which an MCP
  server is not made to take, and holds every body whole in memory first.
- `type: mcp` on a **location** has nothing to do with `type: mcp` on an
  **endpoint** (the latter is a raw TCP bridge, see [Mcp
  endpoints](#mcp-model-context-protocol)).

### Drop

Silently drops the connection for any request matching this location. No
upstream connection is opened, no response template is written — on HTTP/1.1
the proxy just sends `FIN` and closes the TCP socket.

Use it on wildcard or catch-all hosts to refuse bot traffic, IP-literal
scanners, or any request that targets an unknown path you do not want to
respond to. Combine with `path:` to selectively drop a subtree.

```yaml
hosts:
  80:
    endpoint:
      type: http
    locations:
    - path: /.env
      proxy_pass_to: drop

    - path: /wp-admin
      proxy_pass_to: drop

    - proxy_pass_to: static
      status_code: 302
      modify_http_headers:
        add:
          response:
          - name: Location
            value: https://${HOST_PORT}${PATH_AND_QUERY}
```

Equivalent shorthand using the `type` field:

```yaml
locations:
- path: /.env
  type: drop
```

Behavior per protocol:

- **HTTP/1.1** — the request is parsed, the location is matched, then the TCP
  connection is closed without writing anything back to the client. The
  client sees a connection reset / EOF.
- **HTTP/2** — hyper does not allow forcing a TCP shutdown from inside a
  request handler, so the proxy returns an empty `403 Forbidden` body with
  `Connection: close`. Well-behaved h2 clients close the socket after that;
  the connection itself is not torn down by the proxy.

Drop locations:
- never resolve an upstream — there is no `proxy_pass_to: drop://...` form.
- bypass `auth_header`, `google_auth`, and `client_certificate_ca` checks —
  the request is rejected before any of them runs.
- bypass per-domain metrics (`domain_rps`, `*_traffic_*`, `ws_*_*`) when the
  endpoint also satisfies the default strict mode (`track_metrics_by_all_domains`
  unset / false on a wildcard endpoint).

### Dynamic Proxy

A `dynamic` location forwards each request to an upstream URL specified by
the client in the `proxy-to` request header. Useful when one endpoint must
fan out to many different upstreams and the choice is per-request, not
per-config.

```yaml
hosts:
  localhost:8080:
    endpoint:
      type: http
    locations:
    - path: /
      proxy_pass_to: dynamic
      connect_timeout: 5000     # ms — optional, default 5s
      request_timeout: 15000    # ms — optional, default 15s
      allowed_hosts:            # optional whitelist (case-insensitive)
      - api.example.com
      - cdn.example.com
```

Equivalent shorthand using the `type` field:

```yaml
locations:
- path: /
  type: dynamic
```

Request flow:

1. Client sends `proxy-to: https://target.example` (header name is
   case-insensitive) together with the original request.
2. The proxy parses the header value as a base URL, strips the `proxy-to`
   header, rewrites the request `Host` to the target host, and forwards the
   original path + query as-is (without the location path when the location
   has `strip_path`, see [strip_path](#strip_path)).
3. The proxy opens a **fresh HTTP/1.1 connection per request** (no pooling)
   using the parsed scheme — `http` / `ws` use plain TCP, `https` / `wss`
   use TLS with the system CA bundle.
4. The upstream response is returned to the client unchanged.

Behavior notes:

- **HTTP version to upstream is always HTTP/1.1**, regardless of the listen
  endpoint type. WebSocket upgrade is not supported in the first version.
- **`allowed_hosts` is optional**. When present, only listed hosts (matched
  case-insensitively against the parsed host) are accepted; anything else
  returns **403**. When absent, any host is allowed — the location behaves
  as an open proxy and the caller is responsible for authentication
  (combine with `auth_header` / `google_auth` / `whitelisted_ip`).
- **No connection reuse** — every request creates and tears down its own
  upstream connection. This is intentional: the target host is unbounded,
  and a per-host pool with a TTL is not worth the complexity here.

Error responses:

| Condition                                | Status |
|------------------------------------------|--------|
| `proxy-to` header missing                | 421 Misdirected Request |
| `proxy-to` value cannot be parsed as URL | 421 Misdirected Request |
| Target host not in `allowed_hosts`       | 403 Forbidden |
| Cannot connect to upstream               | 503 Upstream unavailable |

Example with auth and whitelist:

```yaml
hosts:
  proxy.example.com:443:
    endpoint:
      type: https
      ssl_certificate: my_ssl_cert
    locations:
    - path: /
      proxy_pass_to: dynamic
      auth_header: "Bearer ${env:DYNAMIC_PROXY_TOKEN}"
      allowed_hosts:
      - api.internal
      - storage.internal
```

A request like:

```
GET /v1/users?limit=10 HTTP/1.1
Host: proxy.example.com
Authorization: Bearer ...
proxy-to: https://api.internal
```

is forwarded to `https://api.internal/v1/users?limit=10` with `Host:
api.internal` and without the `proxy-to` header.



## Debugging endpoints

Adding debug flag to endpoint will print all the traffic errors to the console

```yaml
hosts:
  localhost:8000:
    endpoint:
      type: http
      debug: true
```       

### Debug ip

A request the proxy can not match to a configured host (unknown `Host` / `:authority`, or no host at
all) is answered with a bare `400 Bad Request` - it says nothing about the proxy or what it serves.

`debug_ip` in `global_settings` names the source ips that get a detailed html page instead: the host
that was looked up, the request (method, uri, headers), the listener it arrived on and the hosts
configured on that listener.

```yaml
global_settings:
  debug_ip: 10.0.0.5

# or several of them
global_settings:
  debug_ip:
  - 10.0.0.5
  - 192.168.1.20
```

- Exact addresses only (IPv4 or IPv6) - no ranges. An entry that is not an ip address fails the
  settings load.
- It is matched against the address of the tcp connection, the same way `whitelisted_ip` is - behind
  a CDN or another proxy that is the address of that proxy, not of the browser.
- Applied on start and on every full settings reload (`reload_settings`).
- Covers `http2` and `https2` endpoints - the ones that answer such a request with `400`. `http` and
  `https` endpoints close the connection silently on an unknown host, for everybody.
- A debug ip is also told why an endpoint serves nobody - see the next section.

### An endpoint which can not apply an access setting

Some access settings can not be applied by a type of endpoint:

| Endpoint type | Can not apply |
|---|---|
| `mcp` | `auth_header` of a location, `google_auth`, `allowed_users` |
| `tcp` | `auth_header` of a location, `google_auth`, `allowed_users` |
| `http`, `http2` | `google_auth` - it works on `https` and `https2` endpoints |

Settings with one of these load: an endpoint written wrong does not take the others down with it. But the endpoint **serves nobody** until the setting is removed - otherwise it would be open to everybody while its settings say it is guarded.

- Everybody is refused without a word: `403 Forbidden` on `http` and `http2` endpoints, a closed connection on `mcp` and `tcp` ones.
- A source listed in `debug_ip` is told the reason - which setting, on which endpoint, and what to do about it: on the 403 page, as an HTTP response before the connection is closed on `mcp`, as a line of text before it is closed on `tcp`.

`whitelisted_ip` is not one of them: every type of endpoint checks it, by the address of the connection - the list of the endpoint and the list of a location.

## Auto-injected request headers

Regardless of `modify_http_headers` configuration, the reverse-proxy always injects
the following headers into proxied HTTP/1.1 and HTTP/2 requests:

* **`X-Forwarded-For`** — appends the incoming client IP per RFC 7239. If the
  request already carries `X-Forwarded-For`, the client IP is appended to the
  existing value (`{existing},{client_ip}`). No header is added for Unix socket
  clients. This cannot be disabled.

* **`CF-IPCountry`** — only when `inject_country: true` is set on the endpoint.
  The 2-letter ISO country code of the client IP is looked up from the bundled
  IPv4 geolocation database and written as `CF-IPCountry: XX`. Any client-supplied
  `CF-IPCountry` header is overwritten. If the IP cannot be resolved to a
  country, the header is not added.

```yaml
hosts:
  localhost:8000:
    endpoint:
      type: http
      inject_country: true
```

The IPv4 geolocation database is compiled into the binary as a static lookup
table. IPv6 lookups use an IP2Location LITE DB1 `.BIN` file
(`ip_v6/IP2LOCATION-LITE-DB1.IPV6.BIN`) loaded via mmap at startup; the file
is shipped alongside the binary in the Docker image. If the `.BIN` file is
missing, IPv6 clients simply do not receive the header.


## Settings up SSH tunnels.

By default if there is no settings for SSH tunnel - SSH agent is used.

### To use password please specify
```yaml
ssh:
  ssh_user@10.0.0.5:
    password: password
```


### To use private key please specify
```yaml
ssh:
  ssh_user@10.0.0.5:
    private_key_file: ~/certs/private_key.key
    passphrase: passphrase
```



## Per-location header authentication

Any location can require an `Authorization` header on every incoming
request. If the header is missing or its value does not match exactly,
the proxy returns **401** with the standard `NOT_AUTHORIZED_PAGE` body
and never opens an upstream connection.

Configure with the `auth_header` field on a location. The value is the
**full expected `Authorization` header value**, scheme included
(`Bearer …`, `Basic …`, etc.):

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

Behavior:

- The header **name** is matched case-insensitively (`Authorization`,
  `AUTHORIZATION`, `authorization` all work).
- The header **value** is matched byte-for-byte exact, after stripping
  surrounding ASCII whitespace from the request value.
- If `auth_header` is absent or empty in the YAML, the check is a no-op
  and the location accepts any (or no) `Authorization` header.
- The header is **forwarded to the upstream as-is** — defense in depth,
  the upstream may revalidate.
- Missing-header and wrong-value cases both produce the same 401 — the
  proxy does not leak which one is wrong.
- The check runs **before** any endpoint-level auth (`google_auth`,
  `client_certificate_ca`). Both can be combined: header auth gates
  access, then endpoint auth attaches an identity.

The expected value can be supplied via a variable to keep secrets out of
config files:

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

## Google OAuth authentication

It is possible to use Google OAuth authentication for the endpoints.

```yaml
hosts:
  localhost:8000:
    endpoint:
      type: https
      ssl_certificate: my_ssl_cert  
      google_auth: g_auth_id

g_auth:
  g_auth_id:
    client_id: ...
    client_secret: ...
    whitelisted_domains: domain1.com;domain2.com
```

If 'whitelisted_domains' property is missing - any email from any domain passed thought google authentication is allowed.

`google_auth` works on `https` and `https2` endpoints. An endpoint of another type which names it serves nobody: see "An endpoint which can not apply an access setting".



## OAuth 2.1 authorization server

An endpoint can make the proxy act as an OAuth 2.1 authorization server, so
clients that only offer a **Client ID** and **Client Secret** — the "Add custom
connector" dialog on claude.ai is the motivating one — can reach an upstream
that does no authentication of its own.

Prefer `auth_header` (see [Per-location header authentication](#per-location-header-authentication))
whenever the client can be configured with a static token. Use `oauth` when it
cannot.

```yaml
oauth:
  claude:
    client_id: "${env:MCP_OAUTH_CLIENT_ID}"
    client_secret: "${env:MCP_OAUTH_CLIENT_SECRET}"
    consent_password: "${env:MCP_CONSENT_PASSWORD}"

hosts:
  "mcp-home.jetdev.eu:443":
    endpoint:
      type: https              # NOT `type: mcp` — see below
      ssl_certificate: my_ssl_cert
      oauth: claude
    locations:
    - path: /mt-risks
      type: mcp
      proxy_pass_to: http://127.0.0.1:8123/mt-risks
```

The user then enters `https://mcp-home.jetdev.eu/mt-risks` as the URL, the same
`client_id` / `client_secret`, and the `consent_password` on the consent screen
the proxy renders.

### `oauth` block fields

| Field | Required | Meaning |
| --- | --- | --- |
| `client_id` | yes | The pre-registered client. There is no dynamic client registration. |
| `client_secret` | yes | Checked on the token endpoint, via the form body or HTTP Basic. |
| `consent_password` | yes | What a human types on the consent screen to approve the connector. |
| `public_url` | no | Issuer override. Defaults to the request's own scheme + `Host`. Set it when something in front rewrites either. |
| `signing_key` | no | Pins the token signing key. Any sufficiently random string. |
| `signing_key_file` | no | Where a generated key is kept. Default `~/.my-reverse-proxy-oauth/{block_id}.json`. |
| `access_token_ttl_sec` | no | Default `3600`. |
| `refresh_token_ttl_sec` | no | Default `2592000` (30 days). |

All fields go through `${variable}` substitution, so the secrets can stay out of
the settings file. `oauth` can also be set on an `endpoint_templates` entry.

### Behavior

- The endpoint answers `/.well-known/oauth-authorization-server`,
  `/.well-known/openid-configuration`,
  `/.well-known/oauth-protected-resource/<location path>`, `/oauth/authorize`
  and `/oauth/token` itself. These are matched before locations, so a location
  under `/oauth` or `/.well-known` is shadowed on such an endpoint.
- Every other request on the endpoint must carry `Authorization: Bearer <token>`
  minted by this proxy; otherwise it gets **401** with a `WWW-Authenticate`
  header pointing at the resource metadata.
- Authorization Code + **PKCE S256** only. `plain` is refused.
- Accepted redirect URIs are `https://claude.ai/api/mcp/auth_callback` and RFC
  8252 loopback (`127.0.0.1`, `localhost`, `[::1]`) on any port, which is what
  Claude Code uses.
- The `Authorization` header is **stripped before proxying** — the token belongs
  to the proxy, not to the upstream, as the MCP authorization spec requires. If
  the upstream needs its own credential, add it with endpoint-level
  `modify_http_headers.add`.
- Tokens are stateless and signed; the signing key is generated once and kept on
  disk so a restart does not log the connector out.
- A wrong consent password or client secret counts as a hard failure for the IP
  block-list.
- `whitelisted_ip`, `client_certificate_ca` and `allowed_users` still apply, and
  they apply to the OAuth endpoints too. `auth_header` on a location is checked
  in addition to the OAuth gate.

### Endpoint type

`oauth` works on `type: http`, `https`, `http2` and `https2`. It does **not**
work on `type: mcp`, which is a raw TCP bridge that never parses HTTP — that
combination is rejected when the configuration is compiled and the proxy will
not start. Use `type: https` on the endpoint with `type: mcp` on the location,
as in the example above.

Full details, the request flow and troubleshooting: [docs/mcp-oauth.md](docs/mcp-oauth.md).


## IP Whitelisting

It's possible to IP whitelist and given endpoint

```yaml
hosts:
  localhost:8000:
    endpoint:
      type: http
      whitelisted_ip: id_of_ip_list
      
      
ip_white_lists:
  id_of_ip_list:
    - "10.0.0.5"
    - "10.0.0.1-10.0.0.5"
```

Same rules can be applied to any location

```yaml
hosts:
  localhost:443:
    endpoint:
      type: https

    locations:
    - proxy_pass_to: http://10.0.0.4:7702
      whitelisted_ip: id_of_ip_list 
```



## Endpoint templates 

If several endpoints have the same configuration it is possible to use templates

```yaml
hosts:
  domain.com:443:
    endpoint:
      type: https
      template_id: endpoint_template_id


endpoint_templates:
  endpoint_template_id:
    ssl_certificate: ssl_cert_id
    google_auth: google_auth_id
    whitelisted_ip: 10.0.0.0
    modify_http_headers:
      add:
        request:
        - name: x-real-ip
          value: '${ENDPOINT_IP}'
        response:
        - name: header-name1: 
          value: value1
        - name: header-name2: 
          value: value2
      remove:
        request:
        - header-name1
        - header-name2
        response:
        - header-name3
        - header-name4
```



## Allowed users list

It is possible to specify allowed users list for the endpoints which has authentication

```yaml
hosts:
  domain.com:443:
    endpoint:
      type: https
      allowed_users: list_id

allowed_users:
  list_id: 
  - email1@domain.com
  - email2@domain.com
  - email3@domain.com

```

Allowed users can be located in remote file. To specify remote file please use next example:

```yaml
hosts:
  domain.com:443:
    endpoint:
      type: https
      allowed_users: list_id

allowed_users:
  from_file: 
  - http://remote_host:5123/allowed_users_list.yaml
  - ~/allowed_users_list.yaml
  - root@127.0.0.1->~/allowed_users_list.yaml

```

In this case - allowed_users configuration with id='list_id' must be located inside of one of remote files specified in yaml.



### Compressing the http body
Sometimes if proxy pass is done to remote endpoint by ssh - it would be wise to compress http body

`compress: true` of a location gzips the body of a request on its way to the upstream - a body of 2048 bytes and more, held whole in memory for it - and the upstream has to take a gzipped body. It works on `http2` and `https2` endpoints; on `http` and `https` ones it is not applied.

```yaml


  8005:
    endpoint:
      type: http2  

    locations:       
    - path: /service1
      type: http2  
      compress: true

```




### Timeouts for Remote HTTP Endpoints
Remote HTTP endpoints have default timeouts: 5 seconds (`connect_timeout`) for establishing a connection and 15 seconds (`request_timeout`) for completing a request.

Values are in milliseconds (`1000` = 1 second). Both are part of the [timeout cascade](#timeouts--connection-tuning--overview): the example below sets them per-location, but you can also set defaults on the `endpoint:` or in `global_settings`, with the more specific level winning.

```yaml

  8989:
    endpoint:
      type: http

    locations:
      - path: /
        proxy_pass_to: http://127.0.0.1:8080
        connect_timeout: 1000  # ms — 1 second connection timeout
        request_timeout: 2000  # ms — 2 second request timeout

```

# GATEWAY

Two or more instances of reverse proxy can be connected as network and forward traffic through gateway.

Gateway authentication is based on SSH Ed25519 keys. The server holds a list of authorized public keys; each client signs the handshake with its private key. There are no shared secrets.

## Generating a key pair

A standalone helper generates an OpenSSH-format Ed25519 key pair ready to drop into the settings:

```sh
cargo run --bin gateway_keygen -- ~/gateway_keys/client_identity
```

It writes two files:

- `~/gateway_keys/client_identity` — the private key, referenced from the client's `ssh:` registry entry (`private_key_file`).
- `~/gateway_keys/client_identity.pub` — the public key, added to the server's `gateway_server.authorized_keys`.

Generate one key pair per client.

## Server side

```yaml
gateway_server:
  port: 30000
  authorized_keys:
    - ~/gateway_keys/client_identity.pub
    - ~/gateway_keys/another_client.pub
  allowed_ip:        # optional, restricts which source IPs may connect
    - 10.0.0.5
    - 10.0.1.10-10.0.1.20
  debug: false       # optional, default false
```

- `authorized_keys` - mandatory. List of paths to OpenSSH public key files (one per allowed client). Must be Ed25519.
- `allowed_ip` - optional. If present, only connections from the listed IPs are accepted; any other connection is closed right after `accept`, before the handshake. Entries are IPv4 addresses or `from-to` ranges, the same as in `ip_white_lists`. An invalid entry fails the startup.

## Client side

```yaml
ssh:
  gateway_identity:
    private_key_file: ~/gateway_keys/client_identity
    passphrase: optional_passphrase   # optional, only if the key is encrypted

gateway_clients:
  gateway_name:
    remote_host: 10.0.0.0:30000
    ssh_credentials: gateway_identity   # id of the ssh: registry entry above
    connect_timeout: 5000 # ms, optional, default 5000
    compress: 2 # compression level, optional, default 0 - no compression
    allow_incoming_forward_connections: true
    sync_ssl_certificates:
      - my_ssl_cert
      - another_ssl_cert
```

- `ssh_credentials` - mandatory. Id of an entry in the `ssh:` registry that points to the client's private key (`private_key_file`). The key must be Ed25519; password-only ssh entries are not supported for gateway.
- `compress` - is optional: the compression level of this gateway connection. `0`, the default, is no compression; `1` is LZ4, the fastest; `2`, `3`, `4` and `5` are Zstandard of its levels 1, 3, 6 and 9 - they pack better than LZ4 and slower, the higher the level the slower; `6`, `7`, `8` and `9` are the same Zstandard levels as one stream for the whole connection - every batch is packed with what went before it, so small requests and answers pack 3 to 5 times better than at `2`-`5`, at the cost of a stream kept on both ends. Everything that travels over the connection is packed with the level, in both directions: the client says it in its handshake, and the server packs what it sends to it with the same. The server has no setting of its own. What can not be made smaller - TLS, media, what is packed already - travels as it is. A level which is not in the table fails the startup. How much every level saves and how fast it is - measured on real data - and which one suits which link: [docs/gateway-compression.md](docs/gateway-compression.md).
- allow_incoming_forward_connections - is optional. Without this parameters - no Forward connections are allowed through gateway from Server side to Client side. Forward connections from Client side to Server side need no setting.
- sync_ssl_certificates - is optional. List of SSL certificate ids to pull from the remote Gateway Server. See the `SSL Certificate Sync via Gateway` section below.


To Setup location through gateway
```yaml
hosts:
  7777:
    endpoint:
      type: tcp
    locations:
    - proxy_pass_to: gateway:gateway_name->192.168.1.1:5123

  5203:
    endpoint:
      type: http
    locations:
    - proxy_pass_to: gateway:gateway_name->http://localhost:8000

  5204:
    endpoint:
      type: http2
    locations:
    - proxy_pass_to: gateway:gateway_name->http://localhost:8000   # http/1.1 upstream
    - path: /grpc
      type: http2
      proxy_pass_to: gateway:gateway_name->http://localhost:9000   # cleartext http2 (h2c) upstream
```

Gateway locations work on `http` and `http2` endpoints, for http/1.1 upstreams and, on
`http2` endpoints, for cleartext http2 (h2c) upstreams (`type: http2`). A unix socket
upstream works the same way - `gateway:gateway_name->unix+http:///var/run/app.sock` - since
the far side connects to the socket path itself. The gateway only carries the connection:
TLS to the upstream through a gateway is not supported. Neither is MCP: a location of
`type: mcp` / `type: mcp-h2`, or an endpoint of `type: mcp`, whose `proxy_pass_to` is a
gateway is refused at load time.



allow_incoming_forward_connections  - is optional. It is a setting of the gateway client (`gateway_clients`, see "Client side" above), not of a location. Without this parameters - no Forward connections are allowed through gateway from Server side to Client side.



## SSL Certificate Sync via Gateway

SSL certificates can be distributed centrally from the Gateway Server to one or more Gateway Clients. The server stores and renews certificates as usual; clients request the ones they need by id through the Gateway channel and keep them in memory.

### How it works

1. The Gateway Server holds the source of truth: certificates are loaded from `ssl_certificates:` (local files, SSH, etc.) the same way as a standalone proxy.
2. Each Gateway Client lists the certificate ids it wants in `sync_ssl_certificates`.
3. Right after the handshake, the client sends a `SyncSslCertificatesRequest` with its list. For each requested id the server replies either with a `SyncSslCertificates` packet (if it has that cert) or with `SyncSslCertificateNotFound` (if it does not). The client caches received certs in-memory, overwriting any existing entry with the same id.
4. A timer on the client wakes up every 60 seconds, checks the cached sync-origin certificates, and re-requests any id that is missing or has 1 day or less before expiry. Fresh certs on the server are therefore picked up automatically without a reconnect.
5. If the server responds with `SyncSslCertificateNotFound` for a previously cached gateway-pushed cert, the client removes it from its cache. Local (non-gateway-pushed) certificates with the same id are never touched — the client's own `ssl_certificates:` entries are safe. If the server restarts and a cert hasn't finished loading when a request arrives, the client temporarily loses it and then re-fetches it on the next 60s tick — so transient gaps self-heal in under a minute.
6. On client reconnect the full list is requested again, so transient disconnects never leave the client out of date.

The certificate with id `self_signed` is never pushed over the wire — self-signed certs are generated locally on demand.

### Server side

No extra configuration is required on the server beyond the usual `ssl_certificates:` block and a running `gateway_server`:

```yaml
gateway_server:
  port: 30000
  authorized_keys:
    - ~/gateway_keys/client_identity.pub

ssl_certificates:
  - id: my_ssl_cert
    certificate: ~/certs/cert.cer
    private_key: ~/certs/cert.key
  - id: another_ssl_cert
    certificate: ~/certs/another_cert.cer
    private_key: ~/certs/another_cert.key
```

### Client side

Add `sync_ssl_certificates` to the Gateway Client entry with the list of certificate ids that should be pulled from the server. The ids must match those defined on the server.

```yaml
ssh:
  gateway_identity:
    private_key_file: ~/gateway_keys/client_identity

gateway_clients:
  gateway_name:
    remote_host: 10.0.0.0:30000
    ssh_credentials: gateway_identity
    sync_ssl_certificates:
      - my_ssl_cert
      - another_ssl_cert

hosts:
  localhost:443:
    endpoint:
      type: https
      ssl_certificate: my_ssl_cert
    locations:
    - type: http
      proxy_pass_to: http://backend:5123
```

The client does not need its own `ssl_certificates:` entry for ids listed in `sync_ssl_certificates` — HTTPS listeners resolve the certificate from the in-memory cache that the gateway sync populates. If both a local `ssl_certificates:` entry and a pushed cert share an id, the pushed one overwrites the local one on each sync.

On the console the client prints a line for every cert it receives, e.g.:

```
received ssl_certificate 'my_ssl_cert' from gateway [gateway_name]
```

And when the server reports a cert as missing, the client removes its cached copy:

```
removed ssl_certificate 'my_ssl_cert' — not present on gateway [gateway_name]
```

### When to use it

- One or more edge proxies (clients) need to terminate TLS for domains whose certificates are managed centrally (Let's Encrypt renewals, rotation, compliance).
- You want to avoid distributing private keys via configuration management or SSH to each node.
- Certificates on the server are renewed by the existing `SslCertsRefreshTimer` — clients converge to the new cert within a minute without a restart or reconnect.



## Gateway reliability

The gateway TCP transport uses a race-free single-channel writer internally —
outgoing payloads travel through an `mpsc` channel that carries the bytes
themselves rather than separate "wake the writer" signal events. This eliminates
a class of lost-wakeup bugs that could cause a long-running gateway to silently
stall after extended uptime under heavy traffic. A frame is never dropped for
want of room in the channel; data frames instead wait for a share of a 2 MiB
write budget per gateway connection, so a fast upstream is read at the speed of
the gateway link rather than buffered in memory.

What else holds under failures, without any configuration:

- A connection closed by either end delivers everything sent before the close.
- A failure reaches the other end as a failure, not as a clean end: when the
  client of a tunnelled connection resets, a byte pump fails or a write times
  out, the target's connection is reset, and when the target resets, so is the
  client's; a gateway connection going down resets the targets behind it. A
  clean close still arrives as the end of the stream: the gateway says which
  it was (`FIN` / `RST`). A unix-socket target can not be reset - it sees the
  end of the stream.
- If any part of a tunnelled connection fails - either direction of its byte
  pumps, the write to the target, the peer - the whole connection is closed on
  both ends, and every loop working for it stops as soon as it has delivered
  what was sent before the close.
- A tunnelled connection lives as long as bytes move either way: a one-way
  stream is not cut by the silence of its other direction, a connection silent
  both ways for `read_timeout` is closed.
- A reader or target slower than the gateway link slows down only its own
  connection: each tunnelled connection holds at most 8 MiB per direction in
  memory, a connection waiting for its reader takes nothing from the others,
  and the credit which lets it go on never waits behind other connections'
  data.
- A client which leaves in the middle of a streaming response (SSE) takes the
  upstream connection with it - through a gateway or directly - instead of
  handing it back to the pool while it is still busy with that response.
- An upload the target does not take within 30 seconds of the close is given
  up on, and the target's TCP connection is reset rather than closed, so the
  target does not take a stream cut short for a complete one.
- When a gateway connection goes down, every connection tunnelled through it is
  closed at once - nothing waits for a timeout - and its target is reset.
- A gateway link too slow for its traffic is torn down rather than kept alive:
  pings get no priority, so a client whose uplink stays saturated for over 9
  seconds with nothing coming back reconnects.
- A client which vanished without closing its socket is dropped by the server
  after 30 seconds of silence; the client itself detects a dead server in 10-13
  seconds and reconnects. A handshake must complete within 10 seconds.
- After a reconnect the new connection stays registered, whenever the old one is
  finally torn down.

The exact rules are in [docs/gateway-protocol.md](docs/gateway-protocol.md).



## Timeouts & connection tuning — overview

Read this first to decide which knob you need and where to set it.

### The cascade — where a timeout wins

The **timeout set** below can be specified at three config levels. They are
layered, lowest priority first, each overriding the one before it, on top of the
compiled-in defaults:

```
HardCode  <  global_settings  <  endpoint (listen endpoint)  <  location
```

So a value set on a `location` beats the same value on its `endpoint`, which
beats `global_settings`, which beats the hardcoded default. A level that leaves
a field unset simply lets the level below show through — you only set what you
want to change, at the broadest level that makes sense.

### Units

**Every timeout is an integer number of milliseconds.** `1000` = 1 second,
`60000` = 1 minute. ⚠️ `5` means **5 milliseconds**, not 5 seconds — a common
foot-gun. The only non-millisecond knobs are the **buffer sizes**, which take a
raw byte count or a `Kb` / `Mb` suffix (e.g. `512Kb`, `1Mb`).

### The timeout set

Every key below is written the same way at any level it supports — same name,
same unit. The **Levels** column says how far down the cascade each key is read:

- **global → endpoint → location**: per-request knobs; the most specific level wins.
- **global → endpoint**: transport-level idle timeouts. They live on the connection (one reader/writer shared by all requests), so they resolve at the endpoint and a `location`-level value is ignored.

| Key | Unit | Default | Levels | Controls |
|-----|------|---------|--------|----------|
| `connect_timeout` | ms | 5000 | global→endpoint→location | TCP/TLS connect to the HTTP upstream (also the pool's connect). |
| `request_timeout` | ms | 15000 | global→endpoint→location | Time to complete a full HTTP request/response to the upstream. |
| `pool_size` | int | 5 | global→endpoint→location | Connections held in the h1/h2 upstream pool. |
| `pool_ping_timeout` | ms | 1000 | global→endpoint→location | Per-probe timeout of the h2 liveness check. **h2 + liveness URL only.** |
| `pool_hot_window` | ms | 3000 | global→endpoint→location | Idle window after a success during which the h2 probe is skipped. **h2 + liveness URL only.** |
| `read_timeout` | ms | 180000 (3m) | global→endpoint | Idle read timeout on every byte pump — H1 request/response body transfer, MCP tunnel, TCP port-forward, WebSocket. A TCP port-forward or WebSocket session is torn down only when neither direction has moved bytes for this long; a one-way stream keeps it open. Doubles as dead-peer detection. |
| `write_timeout` | ms | 30000 (30s) | global→endpoint | Idle write timeout on every byte pump (same paths as `read_timeout`). |

Keys that don't apply to a given endpoint type (e.g. `pool_size` on a `type: tcp`
endpoint) are simply ignored there.

### Outside the cascade (fixed scope)

| Setting | Where (YAML) | Unit | Default | Controls |
|---------|--------------|------|---------|----------|
| `pool_supervisor_interval` | `global_settings` | ms | 10000 (10s) | How often the single global supervisor sweeps every pool. One timer for all pools, so it can't be per-endpoint/location. |
| `default_h2_livness_url` | `global_settings` | path | (unset) | Enables the h2 active liveness probe (without it, pool recovery is reactive only). |
| `connect_to_remote_timeout` | `global_settings.connection_settings` | ms | 5000 | Connect timeout for **`type: tcp`** port-forward endpoints. |
| `buffer_size` | `global_settings.connection_settings` | bytes/`Kb`/`Mb` | `512Kb` | Pump buffer for `type: tcp` port-forward endpoints. |
| `mcp_buffer_size` | `endpoint` (`type: mcp`) | bytes/`Kb`/`Mb` | `512Kb` | Per-connection MCP read buffer (endpoint-scoped). |
| `connect_timeout` | `gateway_clients.<name>` | ms | 5000 | Connect timeout for a gateway-client link. |

### Example — defaults at global, override at endpoint and location

```yaml
global_settings:
  connect_timeout: 3000      # default connect for every upstream
  request_timeout: 20000     # default request budget for every upstream

hosts:
  8005:
    endpoint:
      type: http2
      request_timeout: 60000 # this endpoint's locations get 60s by default
    locations:
      - path: /slow
        proxy_pass_to: https2://api.internal:443
        request_timeout: 120000   # this one location overrides to 120s
      - path: /
        proxy_pass_to: https2://api.internal:443
        # inherits 60000 from the endpoint, 3000 connect from global
```

### Which knob for which symptom

- **HTTP upstream slow to fail when down** → lower `connect_timeout` (set it at the level you want it to apply).
- **Long-running HTTP request being cut off** → raise `request_timeout`.
- **Too few / too many upstream connections** → `pool_size`.
- **Dead h2 upstream detected too slowly** → set `default_h2_livness_url`, then tune `pool_supervisor_interval` (sweep rate) and `pool_hot_window`.
- **MCP tunnel / body transfer dropped on a long-idle peer** → raise `read_timeout` (on the endpoint or globally).
- **WebSocket drops while idle (no app traffic)** → raise `read_timeout`, or make either side send a heartbeat shorter than `read_timeout`.
- **`type: tcp` forward hangs connecting** → lower `connect_to_remote_timeout`.
- **Gateway link slow to fail** → `connect_timeout` on the gateway client.

Detailed sections: [Remote HTTP endpoint timeouts](#timeouts-for-remote-http-endpoints),
MCP **Connection Settings** (under the MCP endpoint docs), and
[HTTP/2 upstream pool](#http2-upstream-pool) below.



## HTTP/2 upstream pool

All HTTP/2 upstreams (`http2`, `https2`, `unix+http2`) share a single named pool
per endpoint instead of opening one connection per request or per incoming
connection. This lets the proxy multiplex tens of thousands of concurrent
requests over a fixed-size set of upstream h2 connections.

### Behavior

- **Pool key**: `(scheme, host, port)`. Two locations pointing to the same
  endpoint share the same pool — opening a second `https2://api:443` location
  does not double the upstream FD count.
- **Pool size**: **5** connections per endpoint by default, overridable
  per-location via `pool_size`.
- **Cold start**: the pool is created at config load / hot-reload, and a
  background supervisor immediately starts filling the 5 slots. If a request
  arrives before any slot is connected, the proxy returns **503**
  `Upstream unavailable`.
- **Reactive recovery**: a dead `MyHttp2Client` auto-reconnects on the next
  `do_request` (transient drops self-heal). If the upstream stays down, slots
  remain empty and the supervisor retries on every tick (10s by default).

### Active liveness check (optional)

If `default_h2_livness_url` is set in `global_settings`, the supervisor
periodically issues a `GET` to that path on each connected slot that has been
idle longer than the **hot window**. Statuses in `200..=205` keep the slot;
anything else (including a timeout or hyper error) tears the slot down on the
spot, and the supervisor reconnects it on the next tick. There is no
multi-failure counter — a single failed probe is enough.

This active probe is **HTTP/2 only**. HTTP/1 pools (`http`, `https`,
`unix+http`, `ws`, `wss`) never probe — their supervisor only refills empty
slots — so `pool_ping_timeout` and `pool_hot_window` have no effect on h1
locations (only `pool_size` does).

```yaml
global_settings:
  default_h2_livness_url: /health
```

Pool tuning parameters. Everything below is in **integer milliseconds** (except
`pool_size`). `pool_size`, `pool_ping_timeout` and `pool_hot_window` are part of
the [timeout cascade](#timeouts--connection-tuning--overview) — settable at
`global_settings`, the `endpoint:`, or the `location`, most-specific wins. The
supervisor tick is **outside** the cascade: one timer sweeps every pool, so it
lives only in `global_settings`.

| Parameter         | YAML key                  | Scope                       | Unit | Default | Effective when |
|-------------------|---------------------------|-----------------------------|------|---------|----------------|
| Pool size         | `pool_size`               | cascade (global→ep→location)| int  | 5       | always (h1 + h2) |
| Connect timeout   | `connect_timeout`         | cascade (global→ep→location)| ms   | 5000    | always (also the pool's connect) |
| Ping timeout      | `pool_ping_timeout`       | cascade (global→ep→location)| ms   | 1000    | **h2 only**, and only if `default_h2_livness_url` is set |
| Hot window        | `pool_hot_window`         | cascade (global→ep→location)| ms   | 3000    | **h2 only**, and only if `default_h2_livness_url` is set |
| Health-check tick | `pool_supervisor_interval`| `global_settings` only      | ms   | 10000   | always |

The **hot window** is how long a connection is considered "hot" after its last
successful use — within that window the supervisor skips the liveness probe.

```yaml
hosts:
  8005:
    endpoint:
      type: http2
    locations:
      - path: /
        proxy_pass_to: https2://api.internal:443
        pool_size: 10          # optional, default 5
        pool_ping_timeout: 500 # ms, optional, default 1000
        pool_hot_window: 2000  # ms, optional, default 3000

global_settings:
  default_h2_livness_url: /health
  pool_supervisor_interval: 5000  # ms, optional, default 10000
```

If `default_h2_livness_url` is not set, the supervisor only refills empty slots
and never actively probes — recovery is purely reactive on the next request.

### Settings cases

**1. Minimal — pool with reactive recovery only**

```yaml
hosts:
  8005:
    endpoint:
      type: http2
    locations:
    - type: http2
      proxy_pass_to: http://backend:5123
```

5 connections to `backend:5123` are opened at startup. No active probe; if the
upstream dies, requests fail until the supervisor refills slots on the next
10s tick.

**2. With active liveness probe**

```yaml
global_settings:
  default_h2_livness_url: /health

hosts:
  8005:
    endpoint:
      type: http2
    locations:
    - type: http2
      proxy_pass_to: http://backend:5123
```

Same as above, plus every 10s (the default `pool_supervisor_interval`) the
supervisor sends `GET /health` on each connected slot that has been idle past
the hot window. A single non-`200..=205` response (or a timeout) recreates the
slot.

**3. Two locations on the same upstream → one shared pool**

```yaml
hosts:
  8005:
    endpoint:
      type: http2
    locations:
    - path: /api/v1
      type: http2
      proxy_pass_to: http://backend:5123
    - path: /api/v2
      type: http2
      proxy_pass_to: http://backend:5123
```

`backend:5123` still gets only **5** upstream connections — both paths
multiplex over the same pool.

**4. Unix socket upstream**

```yaml
global_settings:
  default_h2_livness_url: /health

hosts:
  8005:
    endpoint:
      type: http2
    locations:
    - type: unix+http2
      proxy_pass_to: ~/sockets/myapp.sock
```

5 UDS connections to the socket; liveness probe uses `:authority = localhost`.

### Authority handling

For TCP/TLS upstreams the probe `:authority` is the canonical `host:port`. For
`unix+http2` the supervisor uses `localhost` as a placeholder (the upstream
must accept that authority — services built on `MyHttpServer >= 0.8.3` do).

### Telemetry

The `/configuration` admin endpoint exposes `remote_connections` with new keys
for the h2 pools:

- `h2://host:port`
- `h2s://host:port`
- `uds-h2://path`

Each value is the number of currently connected (ready) slots out of 5.

## Include other files

You can split config files into several config files and include them to .my_reverse_proxy file

```yaml
include:
- ~/other_config_file.yaml
- ~/other_config_file2.yaml
```

`hosts` is not required in any of the files - the main one included. The hosts may all be in
the included files, and a file may hold nothing but variables, certificates or ssh settings.
`hosts:` with nothing under it is the same as no `hosts`. A host id which is in two files is
taken from the file read last: the main file first, then the includes in their order, then the
dynamic settings file.

## Dynamic settings file

A single settings file can be designated as the **dynamic settings file** — a
config fragment that is editable at runtime over MCP and merged into the running
configuration exactly like an `include:` file.

```yaml
dynamic_configurations_file: ~/.my-reverse-proxy-dynamic
```

Behavior:

- It is merged the same way as an `include:` entry — same schema as the main
  `~/.my-reverse-proxy` file. Anything you can put in the main file (hosts,
  variables, ssl_certificates, …) can go here.
- It is **allowed to be missing**. Unlike a regular `include:`, a non-existent
  dynamic settings file is silently skipped (it may not have been written yet),
  so the proxy starts fine before the file exists.
- It is **allowed to be blank**. A file that is empty or holds nothing but
  spaces and line breaks is not parsed at all and contributes no settings.
- Leading `~/` is expanded to `$HOME/…`.

### Editing over MCP

The MCP server exposes tools to read and write this file without touching the
main config:

- **`get_dynamic_settings`** — returns the resolved path, whether the file
  exists, and its raw YAML content (empty if it does not exist yet).
- **`set_dynamic_settings`** — full-file replace. The YAML is validated against
  the settings schema before writing; on a parse error nothing is written.
  Empty or whitespace-only content is accepted as-is (no data).
- **`reload_settings`** — applies the written file to the running proxy.

The intended workflow is always: `get_dynamic_settings` → edit the returned
content → `set_dynamic_settings` (full body) → `reload_settings`. Because
`set_dynamic_settings` is a full-file replace, the content you send must already
contain everything you want to keep plus your changes.

### Inspecting what is applied

- **`get_settings`** — what the files declare *now* (a fresh compile).
- **`get_applied_settings`** — what is *currently live* (a snapshot from the
  last successful reload).

Diffing the two shows whether there are pending changes that a
`reload_settings` would apply.

# Running on Windows

On Windows the proxy is built with the MSVC toolchain and reads the same settings. This section lists what differs
from Linux.

## Build prerequisites

- Rust stable with the MSVC toolchain, `x86_64-pc-windows-msvc` - what `rustup` installs by default on Windows;
- Visual Studio Build Tools 2017 or later with the "Desktop development with C++" workload (the MSVC compiler and
  the Windows SDK) - it compiles the C code of `aws-lc-sys`, `ring`, `zstd-sys` and `lz4-sys`;
- NASM on `PATH`, for `aws-lc-sys` - or set `AWS_LC_SYS_PREBUILT_NASM=1`, and it uses the NASM objects it ships;
- Git, to get the repository.

`my-ssh` 0.1.2, the version `Cargo.toml` names, does not build on Windows yet: it binds a unix socket for a port
forward and reaches the ssh agent through a unix socket only. The Windows build needs a `my-ssh` tag with the fix for
that, named in `Cargo.toml`.

CMake is not needed: `aws-lc-sys` needs it only for its FIPS build, which is not used here.

In PowerShell, from the repository root:

```powershell
$env:AWS_LC_SYS_PREBUILT_NASM = '1'   # only when NASM is not on PATH
cargo build --release
.\target\release\my-reverse-proxy.exe
```

In cmd it is `set AWS_LC_SYS_PREBUILT_NASM=1`, then the same `cargo build --release` and
`target\release\my-reverse-proxy.exe`.

A release tag also builds it on GitHub: the release of the tag gets
`my-reverse-proxy-<tag>-x86_64-pc-windows-msvc.exe`.

## Working directory

The admin ui (`wwwroot\`) and the IPv6 country database (`ip_v6\`) are read relative to the working directory, as
in the Docker image. Start the exe from the repository root, or copy both folders into the folder you start it
from. With the exe of a release, take them from the repository at the same tag.

## Settings file location

The settings are read from `%HOME%\.my-reverse-proxy` when `HOME` is set, otherwise from
`%USERPROFILE%\.my-reverse-proxy` (`C:\Users\<name>\.my-reverse-proxy`). A leading `~` in the settings is the same
folder. When neither variable is set, the proxy does not start: it prints why and exits.

A second instance is started by pointing `HOME` somewhere else, as on Linux. In PowerShell (this sets `HOME` for
the rest of that window):

```powershell
$env:HOME = 'C:\proxy-b'; .\my-reverse-proxy.exe
```

In cmd:

```bat
set HOME=C:\proxy-b
my-reverse-proxy.exe
```

A local path in the settings - a certificate, a key, a folder of files - can be written either way:
`C:\certs\cert.pem` or `C:/certs/cert.pem`. A path behind `ssh:` or a gateway is a path of the other host, written
the way that host writes it. Write a path with
`\` without quotes or in single quotes - in double quotes YAML reads `\` as an escape.

## What is not available on Windows

Unix sockets:

- listening on a unix socket (a `hosts:` key that is a path);
- `unix+http` and `unix+http2` locations;
- `unix+http://`, `http+unix://` and `unix://` upstreams;
- a gateway target on a unix socket.

Such an endpoint is refused when the settings load, with `unix sockets are not supported on this platform`. It is
reported like any other endpoint error - in the log and in `errors` of `GET /api/configuration/Current` - and the
other endpoints run.

## Other differences

- An ssh connection with no password or key under `ssh:` uses the ssh agent (see "Settings up SSH tunnels"). On
  Windows that is the OpenSSH agent's named pipe, `\\.\pipe\openssh-ssh-agent`, or the pipe `SSH_AUTH_SOCK`
  names.
- A files location answers `400 Bad Request` to the paths Windows reads as another name - `/private./x`,
  `/private\x`, `/CON` - see "How a request picks a file".
- Ctrl+C stops the proxy. Running it as a Windows service is not covered here.

## Example: local exporters behind one https port

Prometheus scrapes exporters which listen on `127.0.0.1:8200`, `127.0.0.1:8201`, ... through one https port, one
path each. `strip_path: true` cuts the path of the location off, so `/mt4-direct-live-1/metrics` reaches the
exporter as `/metrics` (see `strip_path` under "Location types").

```yaml
global_settings:
  http_control_port: 9000
  http_control_ip: 127.0.0.1   # the admin ui and the API for this machine only

hosts:
  9443:
    endpoint:
      type: https
      ssl_certificate: mt_fleet
    locations:
    - path: /mt4-direct-live-1/
      proxy_pass_to: http://127.0.0.1:8200
      strip_path: true
    - path: /mt4-direct-live-2/
      proxy_pass_to: http://127.0.0.1:8201
      strip_path: true

ssl_certificates:
  - id: mt_fleet
    certificate: C:\certs\mt_fleet.pem
    private_key: C:\certs\mt_fleet.key
```

Prometheus then scrapes `https://<host>:9443/mt4-direct-live-1/metrics`,
`https://<host>:9443/mt4-direct-live-2/metrics` and so on.

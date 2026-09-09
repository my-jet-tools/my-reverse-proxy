# Client-CA runtime upload + mTLS hardening — handoff plan

State as of 2026-09-09, written for the session that continues the work. Everything below refers to
the working tree on top of commit `b7b2953` ("Add WASM and CSS assets…"), which captured a
mid-flight snapshot of the feature; the rest is UNCOMMITTED in the tree.

## 1. What is in the tree and its verification status

| # | Change | Files | Status |
|---|--------|-------|--------|
| A | Runtime client-CA upload (UI badge + dialog, REST `Init`/`InitFromPem`/`Ca`, MCP `init_client_certificate_ca`/`get_client_ca_endpoints_status`), non-fatal CA resolution, `ca:` optional in `client_certificate_ca` | `src/scripts/init_client_ca_manually.rs`, `client_ca_endpoints.rs`, `get_client_ca_details.rs`, `make_sure_client_ca_exists.rs`, `refresh_ca_from_sources.rs`, `src/settings/client_certificate_ca_settings.rs`, `src/http_server/controllers/client_certificates/`, `src/mcp/*client*`, `ui/src/views/client_cert_dialog.rs`, `ui/src/views/dashboard.rs` | Built, e2e-verified (see §4), mostly in `b7b2953` |
| B | Post-audit fixes: CRL resolution fail-closed (uploaded → configured `revocation_list` loaded during upload, refused if unreadable → carried over → none, reported as `crl_source`), single-certificate rule, `replace_different_ca` authority guard (subject+SPKI), check+insert under one write lock, `expired` everywhere, `parse_crl_pem` shared by upload/refresh/timer, `revocation_list`-without-`ca` and duplicate ids fail the settings load, `client_certificate_ca` on non-TLS endpoint fails the host, `RefreshCaCertificate` on source-less CA → 400 | `src/scripts/parse_crl_pem.rs`, `src/settings_compiled/populate_settings.rs`, `src/scripts/compile_http_configuration.rs`, `src/flows/refresh_ca_from_settings.rs`, README section "Certificates provided at runtime" | Built, e2e-verified (§4), partly in `b7b2953`; remainder uncommitted |
| C | **mTLS verifier hardening** — real proof of possession (`verify_tls12/13_signature` delegate to the crypto provider instead of `assertion()`), `supported_verify_schemes()` = provider's full list (was `RSA_PSS_SHA256` only), client-certificate validity window enforced against rustls' `now`, `root_hint_subjects` built from the anchor's **subject** (was issuer) | `src/tcp_listener/https/client_cert_verifier.rs`, `src/tcp_listener/https/client_certificate_ca.rs` (`verify_cert(.., now)`) | `cargo check` clean. **NOT built as a binary, NOT e2e-tested** — the session was interrupted before `cargo build`. This is the behaviour change on the live handshake for every mTLS endpoint. |
| D | Tails: pasted PRIVATE KEY block refused; `DELETE /api/ClientCertificates/Ca?caId=` (undo for a wrong upload, fail-closed: endpoints cut connections until a CA is provided again) + `ClientCertificatesCache::remove` + `CertificatesCache::write_with_result`; MCP `get_client_certificate_ca` (metadata parity with `get_ssl_certificate`); UI success note about live connections; unit tests (`init_client_ca_manually::tests`, `parse_crl_pem::tests`) | `src/http_server/controllers/client_certificates/delete_client_certificate_ca_action.rs`, `src/mcp/get_client_certificate_ca_tool_call.rs`, `src/ssl/certificates_cache.rs`, `src/ssl/client_certificates_cache.rs`, `ui/src/views/client_cert_dialog.rs` | `cargo check` clean (server + wasm). Unit tests passed (201) BEFORE the DELETE/MCP/UI-note edits; those edits do not touch tested code. **`wwwroot/` is stale**: it was rebuilt before the UI-note edit. |

`cargo fmt` has NOT been run on the files edited last: `client_cert_verifier.rs`,
`delete_client_certificate_ca_action.rs`, `get_client_certificate_ca_tool_call.rs`,
`populate_settings.rs`, `certificates_cache.rs`, `client_certificates_cache.rs`,
`init_client_ca_manually.rs`. Repo-wide `cargo fmt --check` is red at baseline
(`src/upstream_h2_pool/h2_entry.rs`) — format only your own files with `rustfmt --edition 2021 <file>`.
Clippy baseline is 311 warnings; the new files only add the same two patterns the existing
actions have (`useless conversion`, large `Err` variant) — leave them.

## 2. Do first (mechanical, no decisions)

1. `./build-ui.sh` (regenerates `wwwroot/`; dx prints a `wasm-opt … SIGABRT` error but still produces a working bundle — known), then `cargo build`, then `cargo test --bin my-reverse-proxy` (expect 201+ passing).
2. `rustfmt --edition 2021` on the files listed above; confirm `cargo fmt --check` complains only about `h2_entry.rs`.
3. Run the e2e recipe in §4 **including the five new checks** that exist only because of change C.
4. Commit in two commits, so the handshake change is revertable on its own:
   - (i) client-CA upload remainder + tails (A/B/D + README + `wwwroot/`);
   - (ii) "mTLS: enforce proof of possession, validity window, full signature schemes, subject-based CA hints" (C). Its message must say it is a behaviour change: clients that only ever "worked" because CertificateVerify was never checked (a presented-but-not-owned certificate, or the CA certificate itself) stop authenticating; ECDSA/Ed25519/RSA-PKCS1 clients that were told "RSA_PSS_SHA256 only" start working; expired client certificates stop working.

## 3. Risks in change C to reason about before shipping it

- `MyClientCertVerifier::new` takes `signature_verification_algorithms` from `CryptoProvider::get_default()`; `main` calls `my_tls::install_default_crypto_providers()` before anything listens, and there is a `ring::default_provider()` fallback, so the list can never be empty. Verify the provider is really installed by then (it is `main.rs:58`, before `http_server::start()`).
- TLS 1.2 path (`verify_tls12_signature`) has never been exercised with real verification here — test with `curl --tls-max 1.2` as well as 1.3.
- Validity check uses `x509_parser::ASN1Time::from_timestamp(now.as_secs())` with no skew tolerance. A client cert issued "now" by a CA on a clock a few seconds ahead is rejected for those seconds. Acceptable; mention in docs if it bites.
- `root_hint_subjects` now sends the anchor's subject DN. Correct per RFC 8446 §4.2.4; identical to before for a self-signed root; for an intermediate anchor clients that filter by hints will now actually find their certificate. No fail-open risk.
- The CA's OWN expiry is deliberately still not enforced (an expired CA keeps verifying). Enforcing it would turn every deployment with an expired CA into a full outage on upgrade; the `expired` flag now shows on the dashboard/status/MCP so an operator can see it first. Decide separately (§5).

## 4. e2e recipe (was run for A/B; must be re-run after C)

Fixtures via openssl (any scratch dir): a CA with `basicConstraints=critical,CA:TRUE`; `client2.crt` signed by it; `client.crt` signed by it and revoked in a CRL made with `openssl ca -gencrl`; an unrelated `other-ca.crt`; a server cert with `subjectAltName=DNS:localhost`. Additionally for C: an **expired** client cert (`openssl x509 -req … -days -1`, or `faketime`), an **ECDSA** client cert (`openssl ecparam -name prime256v1`), and a TLS 1.2 run.

Settings in `$HOME/.my-reverse-proxy` with a throw-away `HOME`:
```yaml
global_settings: { http_control_port: 18123 }
client_certificate_ca:
  - id: shared-ca            # no ca: -> manual; add revocation_list: <path> to test the fail-closed path
hosts:
  "localhost:19443":
    endpoint: { type: https, ssl_certificate: test-ssl, client_certificate_ca: shared-ca }
    locations: [ { proxy_pass_to: "http://127.0.0.1:19999" } ]
```
Then (`HOME=<dir> ./target/debug/my-reverse-proxy`):
1. `GET /api/configuration/Current` → endpoint present, `errors: {}`, `client_cert_missing: true`.
2. `POST /api/ClientCertificates/Init -F ca_id=shared-ca -F 'ca=<ca.crt'` → 200, `crl_source`; with an unreadable configured `revocation_list` → 400 naming the file.
3. Bundle (`cat ca.crt other-ca.crt`) → 400; `other-ca.crt` over a loaded CA → 400; same with `-F replace_different_ca=true` → 200 `replaced_different_authority: true`; a PEM with a PRIVATE KEY block → 400.
4. `POST /api/SslCertificates/Init -F cert_id=test-ssl -F 'certificate=<srv.crt' -F 'private_key=<srv.key'` → 204.
5. mTLS: `curl -k --cert client2.crt --key client2.key https://localhost:19443/` → **503** (handshake ok, upstream absent); no cert → TLS failure; revoked `client.crt` → TLS failure.
6. **New for C**: expired client cert → TLS failure; ECDSA client cert → 503; `--tls-max 1.2` with `client2` → 503; presenting the CA certificate as the client certificate with the *client's* key (`--cert ca.crt --key client2.key`) → TLS failure (proof of possession); `openssl s_client -cert client2.crt -key client2.key -connect localhost:19443` handshake completes.
7. `DELETE /api/ClientCertificates/Ca?caId=shared-ca` → 200 listing the endpoint; then `client2` → TLS failure again; re-upload → works.
8. UI: headless Chrome + CDP over node's built-in WebSocket (`--remote-debugging-port=9222`, `Runtime.evaluate` click on `.cert-missing-badge`, `Page.captureScreenshot`) — the previous session's `cdp.mjs`/`apply.mjs` did exactly this.

## 5. Open decisions (NOT done, need the owner's call)

1. **Enforce the CA's own validity window** in `verify_cert` (one `is_valid_at` on the issuer). Correct, but a cliff for deployments whose CA already expired — see §3.
2. **Chain building.** Today one anchor, `_intermediates` ignored; a file-sourced bundle silently trusts only its first certificate (the upload path now refuses bundles instead). Options: (a) keep several anchors and walk `_intermediates` by hand; (b) replace `MyClientCertVerifier` with rustls' `WebPkiClientVerifier` (gives chain, validity and CRL checks) and keep only the CN/`ca_id` extraction on top — a rewrite of `client_certificate_ca.rs` + `client_cert_verifier.rs` + `update_crl` semantics.
3. **Live connections on CA/CRL replacement.** Identity is decided at the handshake; replacing a compromised CA or uploading a CRL does not drop sessions already open. Options: a registry of live mTLS connections keyed by ca id, closed on `init_client_ca_manually`/`update_crl`; or a per-request re-check by serial in `connection_satisfies_client_cert`-style code. Documented in MCP text and the UI note; not implemented.
4. Minor: `RefreshSslCertificate` on a manual SSL cert still answers 204 doing nothing (the CA side now answers 400 — parity broken in the honest direction; align the SSL side the same way if wanted).

## 6. Pointers

- Audit that drove §B/§C: 26-agent workflow, 10 confirmed / 0 refuted findings; full result in the previous session's task output (`tasks/w1vixtozm.output` under that session's scratchpad). Memory file `project_manual_client_ca_init.md` summarises it.
- The SSL-certificate twin of this feature (reference for parity): `src/scripts/init_ssl_cert_manually.rs`, `src/http_server/controllers/ssl_certificates/`, `ui/src/views/ssl_cert_dialog.rs`.

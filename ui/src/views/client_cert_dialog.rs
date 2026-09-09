use dioxus::prelude::*;

use crate::models::InitClientCaResultModel;

/// What the dashboard asks the client-ca upload dialog to work on. `None` in the owning signal
/// means the dialog is closed.
#[derive(Clone, PartialEq)]
pub struct ClientCertDialogRequest {
    /// Id of the client certificate ca as the endpoint references it in the configuration.
    pub ca_id: String,
    /// `host` of the endpoint which is missing the ca, e.g. `example.com:443`.
    pub endpoint_host: String,
}

/// Outcome of the last "Apply" click.
#[derive(Clone, PartialEq)]
enum ApplyState {
    Editing,
    Applying,
    Failed(String),
    Applied(InitClientCaResultModel),
}

#[component]
pub fn ClientCertDialog(
    request: ClientCertDialogRequest,
    dialog: Signal<Option<ClientCertDialogRequest>>,
) -> Element {
    let mut ca = use_signal(String::new);
    let mut crl = use_signal(String::new);
    let mut apply_state = use_signal(|| ApplyState::Editing);

    let state = apply_state.read().clone();
    let applying = state == ApplyState::Applying;

    let ca_id = request.ca_id.clone();

    let on_apply = move |_| {
        let ca_pem = ca.read().trim().to_string();
        let crl_pem = crl.read().trim().to_string();

        if let Err(err) = validate_pem(&ca_pem, &crl_pem) {
            apply_state.set(ApplyState::Failed(err));
            return;
        }

        let ca_id = ca_id.clone();
        apply_state.set(ApplyState::Applying);

        spawn(async move {
            match crate::api::init_client_certificate_ca(&ca_id, &ca_pem, &crl_pem).await {
                Ok(result) => apply_state.set(ApplyState::Applied(result)),
                Err(err) => apply_state.set(ApplyState::Failed(err)),
            }
        });
    };

    let title = format!("Upload client certificate CA — {}", request.ca_id);

    rsx! {
        div {
            class: "modal-overlay",
            onclick: move |_| dialog.set(None),
            div {
                class: "modal-panel",
                onclick: move |evt| evt.stop_propagation(),
                div { class: "modal-header",
                    span { class: "modal-title", "{title}" }
                    button {
                        class: "modal-close",
                        onclick: move |_| dialog.set(None),
                        "✕"
                    }
                }
                div { class: "modal-body",
                    div { class: "cert-form",
                        {render_target(&request)}
                        if let ApplyState::Applied(result) = &state {
                            {render_success(result)}
                            div { class: "cert-actions",
                                button {
                                    class: "cert-apply-btn",
                                    onclick: move |_| dialog.set(None),
                                    "Close"
                                }
                            }
                        } else {
                            div { class: "cert-field",
                                label { class: "cert-label", "CA certificate — PEM" }
                                textarea {
                                    class: "cert-input",
                                    rows: 10,
                                    // Keep browser cloud spell-check / autocomplete away from the
                                    // pasted material.
                                    spellcheck: "false",
                                    autocomplete: "off",
                                    autocorrect: "off",
                                    placeholder: "-----BEGIN CERTIFICATE-----",
                                    value: "{ca}",
                                    oninput: move |evt| ca.set(evt.value()),
                                }
                            }
                            div { class: "cert-field",
                                label { class: "cert-label", "Revocation list — PEM, optional" }
                                textarea {
                                    class: "cert-input",
                                    rows: 5,
                                    spellcheck: "false",
                                    autocomplete: "off",
                                    autocorrect: "off",
                                    placeholder: "-----BEGIN X509 CRL-----",
                                    value: "{crl}",
                                    oninput: move |evt| crl.set(evt.value()),
                                }
                            }
                            if let ApplyState::Failed(err) = &state {
                                div { class: "cert-error", "{err}" }
                            }
                            div { class: "cert-actions",
                                button {
                                    class: "cert-apply-btn",
                                    disabled: applying,
                                    onclick: on_apply,
                                    if applying { "Applying..." } else { "Apply" }
                                }
                                button {
                                    class: "cert-cancel-btn",
                                    onclick: move |_| dialog.set(None),
                                    "Cancel"
                                }
                            }
                            div { class: "cert-note",
                                "This CA decides which clients the endpoint trusts: every client certificate presented to it has to be signed directly by this CA — paste exactly one certificate (for a root → issuing-CA → client chain, the issuing CA). No CA is loaded under this id yet, so if the configuration declares no 'revocation_list' for it, leaving the box empty installs the CA with NO revocation list. If it does declare one, the proxy loads it itself and refuses the upload when it can not be read."
                            }
                        }
                    }
                }
            }
        }
    }
}

/// What the CA is going to be installed for — shown before the operator pastes anything, so an
/// upload for the wrong endpoint is caught by eye.
fn render_target(request: &ClientCertDialogRequest) -> Element {
    rsx! {
        div { class: "cert-target",
            div { class: "cert-target-row",
                span { class: "cert-target-label", "Endpoint" }
                span { class: "cert-target-value", "{request.endpoint_host}" }
            }
            div { class: "cert-target-row",
                span { class: "cert-target-label", "Client-Cert id" }
                span { class: "cert-target-value", "{request.ca_id}" }
            }
        }
    }
}

fn render_success(result: &InitClientCaResultModel) -> Element {
    let endpoints = result.endpoints.join(", ");
    let crl_records = format!("{} ({})", result.crl_records, crl_source_text(result));
    let crl_note = crl_note(result);

    rsx! {
        div { class: "cert-success",
            div { class: "cert-success-title", "Client certificate CA installed" }
            div { class: "cert-target-row",
                span { class: "cert-target-label", "CN" }
                span { class: "cert-target-value", "{result.cn}" }
            }
            div { class: "cert-target-row",
                span { class: "cert-target-label", "Expires" }
                span { class: "cert-target-value", "{result.expires}" }
            }
            div { class: "cert-target-row",
                span { class: "cert-target-label", "Revoked serials" }
                span { class: "cert-target-value", "{crl_records}" }
            }
            div { class: "cert-target-row",
                span { class: "cert-target-label", "Used by" }
                span { class: "cert-target-value", "{endpoints}" }
            }
            if !result.is_ca {
                div { class: "cert-warning",
                    "The uploaded certificate is not marked as a CA (no BasicConstraints CA:TRUE). It works as a trust anchor here, but if you meant to upload an issuing CA, check that you pasted the right file."
                }
            }
            if result.expired {
                div { class: "cert-warning",
                    "This CA is already past its expiry date. Client certificate verification here does not check validity dates, so it still works — but it is almost certainly not the file you meant to upload."
                }
            }
            if result.crl_records == 0 {
                div { class: "cert-warning",
                    "No revocation list is in effect for this CA: a client certificate can not be revoked until one is uploaded."
                }
            }
            div { class: "cert-note", "{crl_note}{LIVE_CONNECTIONS_NOTE}" }
        }
    }
}

/// Where the revocation list the CA ended up with came from - mirrors `crl_source` in the proxy.
fn crl_source_text(result: &InitClientCaResultModel) -> &'static str {
    match result.crl_source.as_str() {
        "uploaded" => "from the list you pasted",
        "configured_revocation_list" => "loaded from the configured revocation_list",
        "kept_from_previous" => "kept from the CA it replaced",
        _ => "no revocation list",
    }
}

/// Every note ends with this: mTLS identity is decided during the handshake, so a replacement
/// (or a new revocation list) does not touch sessions that are already open.
const LIVE_CONNECTIONS_NOTE: &str =
    " Connections that are already open keep the CA they handshook with — replacing a compromised CA does not by itself drop the clients connected under it.";

fn crl_note(result: &InitClientCaResultModel) -> &'static str {
    match result.crl_source.as_str() {
        "configured_revocation_list" => "Used from the next TLS handshake — no reload needed. The revocation list keeps being refreshed from the source the configuration declares; the CA certificate itself is now provided by hand and is not re-read from anywhere.",
        "uploaded" => "Used from the next TLS handshake — no reload needed. Both the CA and the revocation list are now provided by hand: nothing refreshes them until the configured source is re-established.",
        _ => "Used from the next TLS handshake — no reload needed. The CA now has no configured source, so nothing refreshes it or its revocation list until the source is re-established.",
    }
}

/// Catches the obvious mistakes without a round trip. The authoritative validation — the PEM
/// parsing and the endpoint actually requiring this id — is done by the proxy.
fn validate_pem(ca: &str, crl: &str) -> Result<(), String> {
    if ca.is_empty() {
        return Err("Paste the CA certificate PEM first".to_string());
    }

    if !ca.starts_with("-----BEGIN") {
        return Err(
            "The CA does not look like PEM — it has to start with '-----BEGIN CERTIFICATE-----'"
                .to_string(),
        );
    }

    if !crl.is_empty() && !crl.starts_with("-----BEGIN") {
        return Err(
            "The revocation list does not look like PEM — it has to start with '-----BEGIN X509 CRL-----', or be left empty"
                .to_string(),
        );
    }

    Ok(())
}

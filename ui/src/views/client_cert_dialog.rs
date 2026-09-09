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
                                "This CA decides which clients the endpoint trusts: every client certificate presented to it has to be signed by this CA. Leaving the revocation list empty keeps the one the current CA was loaded with — nothing is un-revoked behind your back. Nothing is stored if the material does not parse or no endpoint requires this id."
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
    let crl_records = if result.crl_kept_from_previous {
        format!("{} (kept from the replaced CA)", result.crl_records)
    } else {
        result.crl_records.to_string()
    };

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
            div { class: "cert-note",
                "Used from the next TLS handshake — no reload needed. The CA now has no configured source, so its revocation list is no longer refreshed automatically until the source is re-established."
            }
        }
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

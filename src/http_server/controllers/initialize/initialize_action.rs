use my_http_server::{
    macros::{http_route, MyHttpInput},
    HttpContext, HttpFailResult, HttpOkResult, HttpOutput, HttpRequestHeaders, SocketAddress,
};
use serde::Deserialize;

use crate::secure::InitializeError;

/// The answer to a key which does not open the store, word for word.
const INVALID_KEY: &str = "Invalid Key";

#[http_route(
    method: "POST",
    route: "/api/initialize",
    summary: "Hand the proxy the files key, and the network keys",
    description: "Body: JSON `{\"key\": \"<files key>\", \"network_keys\": [\"<network key>\", ...]}`, each key base64 of 32 random bytes (`openssl rand -base64 32`). `network_keys` is optional: given, it replaces the whole list the secure store has. The files key encrypts the secure store on the proxy's disk and nothing else; it is written nowhere and kept in memory until the process stops. The network keys encrypt every packet of the standard (`Content-Encoding: aes128gcm`): the data the proxy reads from services, and the encrypted calls to this control port. No store yet: it is created with this key, `Created`. A store this key opens: `Initialized` - also when the proxy was already opened with this same key. Right after a success the certificates and CAs which could not be loaded are read again from their sources, and so are the urls of `real_time_configurations`.  The keys travel in plain text, so they are taken only over the control unix socket (`global_settings.control_unix_socket`) or over TCP from this host's own loopback, never from the network, and never from a proxy (`X-Forwarded-For`). See docs/secure-parameters.md.",
    controller: "Initialize",
    input_data: InitializeHttpInput,
    result:[
        {status_code: 200, description: "`Created` or `Initialized`"},
        {status_code: 400, description: "A key is not base64 of 32 bytes, `network_keys` is an empty list, or the body is not the JSON above"},
        {status_code: 401, description: "`Invalid Key` - the store is there and this key does not open it, or the proxy is already initialized with another key. Nothing changed"},
        {status_code: 403, description: "The request came over the network or through a proxy: the keys go over the control unix socket, or the host's loopback"},
        {status_code: 500, description: "The secure store can not be read or written - the message names the file and the reason"},
    ]
)]
pub struct InitializeAction;

async fn handle_request(
    _action: &InitializeAction,
    input_data: InitializeHttpInput,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let relayed = ctx
        .request
        .get_headers()
        .try_get_case_insensitive("x-forwarded-for")
        .is_some();

    if relayed || !is_local_source(&ctx.request.addr) {
        return Err(HttpFailResult::as_forbidden(Some(
            "The keys are given over the control unix socket (global_settings.control_unix_socket) \
             or over this host's loopback - never over the network, never through a proxy",
        )));
    }

    let request: InitializeRequest = serde_json::from_slice(&input_data.body)
        .map_err(|err| HttpFailResult::as_validation_error(body_refusal(&err)))?;

    let store_file = match crate::app::APP_CTX.applied_settings.load_full() {
        Some(settings) => settings.get_secure_store_file(),
        None => crate::consts::DEFAULT_SECURE_STORE_FILE.to_string(),
    };

    // Whether this call opens the store: what it keeps is applied then, as the settings files are
    // at the start.
    let opens_the_store = !crate::app::APP_CTX.secure.is_initialized();

    let outcome = crate::app::APP_CTX
        .secure
        .initialize(&store_file, &request.key, request.network_keys.as_deref())
        .await
        .map_err(|err| match err {
            InitializeError::BadRequest(reason) => HttpFailResult::as_validation_error(reason),
            InitializeError::InvalidKey => HttpFailResult::from((401u16, INVALID_KEY)),
            InitializeError::Failed(reason) => HttpFailResult::as_fatal_error(reason),
        })?;

    tokio::spawn(crate::flows::after_initialize(opens_the_store));

    HttpOutput::as_text(outcome.as_str().to_string()).into_ok_result(true)
}

/// Whether a request came from where the keys may come from: the control unix socket, or this
/// host's own loopback over TCP. Anything else crossed a network, where the keys - plain text in
/// this body - could be read on the way. An IPv4 loopback behind a dual-stack socket
/// (`::ffff:127.0.0.1`) is a loopback too.
fn is_local_source(addr: &SocketAddress) -> bool {
    match addr {
        SocketAddress::Unix(_) => true,
        SocketAddress::Tcp(addr) => addr.ip().to_canonical().is_loopback(),
    }
}

/// Why the body is refused - without a word of what it holds. serde quotes a value of the wrong
/// type ("invalid type: string \"...\""), and a value here is a key: only a field missing or
/// unknown, which names nothing but the field, is told as serde tells it.
fn body_refusal(err: &serde_json::Error) -> String {
    const EXPECTED: &str = "{\"key\": \"...\", \"network_keys\": [\"...\"]}";

    let text = err.to_string();

    if text.starts_with("missing field") || text.starts_with("unknown field") {
        return format!("The body is not {EXPECTED}: {text}");
    }

    match err.classify() {
        serde_json::error::Category::Data => format!(
            "The body is not {EXPECTED}: a value is of another type, at line {} column {}",
            err.line(),
            err.column()
        ),
        _ => format!(
            "The body is not JSON: at line {} column {}",
            err.line(),
            err.column()
        ),
    }
}

#[derive(MyHttpInput)]
pub struct InitializeHttpInput {
    #[http_body_raw(
        description = "JSON: {\"key\": \"<files key>\", \"network_keys\": [\"<network key>\"]} - network_keys is optional"
    )]
    pub body: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InitializeRequest {
    key: String,
    network_keys: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal(body: &str) -> String {
        body_refusal(
            &serde_json::from_str::<InitializeRequest>(body)
                .err()
                .unwrap(),
        )
    }

    /// A key put where another type is expected is not quoted back.
    /// The keys are taken over the unix socket and from the loopback, and from nowhere else.
    #[test]
    fn the_keys_are_taken_from_the_unix_socket_and_the_loopback_only() {
        let tcp = |addr: &str| SocketAddress::Tcp(addr.parse().unwrap());

        assert!(is_local_source(&SocketAddress::Unix(std::sync::Arc::new(
            "/var/run/control.sock".to_string()
        ))));

        for addr in [
            "127.0.0.1:50000",
            "127.10.0.1:50000",
            "[::1]:50000",
            "[::ffff:127.0.0.1]:50000",
        ] {
            assert!(is_local_source(&tcp(addr)), "{addr}");
        }

        for addr in [
            "10.0.0.5:50000",
            "172.17.0.1:50000",
            "192.168.1.2:50000",
            "[2001:db8::1]:50000",
            "[::ffff:10.0.0.5]:50000",
            "0.0.0.0:50000",
        ] {
            assert!(!is_local_source(&tcp(addr)), "{addr}");
        }
    }

    #[test]
    fn a_refused_body_is_not_quoted() {
        let secret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

        for body in [
            format!(r#"{{"key": "x", "network_keys": "{secret}"}}"#),
            format!(r#"{{"key": ["{secret}"]}}"#),
            format!(r#"{{"key": "{secret}""#),
        ] {
            let text = refusal(&body);
            assert!(!text.contains(secret), "{text}");
        }

        assert!(
            refusal(r#"{"key": "x", "network_key": "y"}"#).contains("unknown field `network_key`")
        );
        assert!(refusal(r#"{"network_keys": []}"#).contains("missing field `key`"));
        assert!(refusal("not json").starts_with("The body is not JSON"));
    }
}

//! Where does an access setting of a LOCATION (its own `whitelisted_ip` first of all) refuse a
//! request, and where does it not - for every endpoint type.
//!
//! Nothing here is mocked on the proxy side. A settings document is parsed from YAML and every
//! host of it is compiled by `scripts::compile_host_configuration`, the function
//! `flows::load_everything_from_settings` compiles a settings file with; the result is published
//! into `APP_CTX.current_configuration` the way that flow does; and the port is served by the
//! real accept loop (`start_listen_tcp_server`), so a request travels the whole way from
//! `accept` to the upstream. Only reading `~/.my-reverse-proxy` and the `${variables}`
//! substitution are skipped.
//!
//! The client always connects from 127.0.0.1, which is what `accept` reports, so "listed" and
//! "not listed" are decided by what the list holds: [`CLIENT_IS_LISTED`] or
//! [`CLIENT_IS_NOT_LISTED`].
//!
//! Every probe starts an upstream of its own, so `upstream_requests` says whether THIS request
//! was proxied, whatever the client was answered.
//!
//! No cell of the table goes against its setting: where an endpoint type can not apply one - a
//! header or a session on `mcp`, `google_auth` without TLS - the endpoint serves nobody.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use my_tls::tokio_rustls::{
    client::TlsStream,
    rustls::{
        self,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
        DigitallySignedStruct, SignatureScheme,
    },
    TlsConnector,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
};

use crate::{
    configurations::EndpointPort, settings::SettingsModel, settings_compiled::SettingsCompiled,
};

const TIMEOUT: Duration = Duration::from_secs(10);

const UPSTREAM_BODY: &str = "answered by the upstream";

/// The list of the README's "IP Whitelisting" section. The client (127.0.0.1) is not in it.
const CLIENT_IS_NOT_LISTED: &[&str] = &["10.0.0.5", "10.0.0.1-10.0.0.5"];

/// A list the client (127.0.0.1) is in.
const CLIENT_IS_LISTED: &[&str] = &["127.0.0.1"];

const LOCATION_TOKEN: &str = "Bearer location-secret";

/// The README, to take its own example from.
const README: &str = include_str!("../../README.md");

// ---------------------------------------------------------------------------------------------
// The claim itself, on the README's own example
// ---------------------------------------------------------------------------------------------

/// "Same rules can be applied to any location" - and the example under it is `type: https`.
const README_LOCATION_EXAMPLE: &str = "hosts:\n  localhost:443:\n    endpoint:\n      type: https\n\n    locations:\n    - proxy_pass_to: http://10.0.0.4:7702\n      whitelisted_ip: id_of_ip_list \n";

const README_IP_LIST: &str =
    "ip_white_lists:\n  id_of_ip_list:\n    - \"10.0.0.5\"\n    - \"10.0.0.1-10.0.0.5\"\n";

/// The README's location example, verbatim but for the port, the upstream address and the id of
/// the list, with the README's own list (10.0.0.5, 10.0.0.1-10.0.0.5): a request from 127.0.0.1
/// is refused, and the upstream does not see it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn readme_location_example_on_https_refuses_an_address_which_is_not_in_the_list() {
    assert!(README.contains(README_LOCATION_EXAMPLE));
    assert!(README.contains(README_IP_LIST));

    my_tls::install_default_crypto_providers();

    let upstream = Upstream::start().await;
    let port = free_port().await;
    let list_id = unique_id("readme");

    let yaml = format!("{README_LOCATION_EXAMPLE}\n{README_IP_LIST}")
        .replace("localhost:443", &format!("localhost:{port}"))
        .replace(
            "http://10.0.0.4:7702",
            &format!("http://127.0.0.1:{}", upstream.port),
        )
        .replace("id_of_ip_list", &list_id);

    println!("--- settings ---\n{yaml}");

    apply_settings(&yaml).await;
    serve(port);

    let host = format!("localhost:{port}");
    let reply = send(Client::TlsHttp1, port, "localhost", &host, &[]).await;
    let outcome = Outcome::new(reply, &upstream).await;

    println!("--- outcome ---\n{outcome:#?}");

    assert!(
        outcome.refused(),
        "the request was not refused: {outcome:#?}"
    );
    assert_eq!(outcome.status, Some(401));

    // The same settings with the same line moved from the location to the endpoint: the same
    // client is not let in either.
    let upstream = Upstream::start().await;
    let port = free_port().await;
    let list_id = unique_id("readme");

    let yaml = format!("{README_LOCATION_EXAMPLE}\n{README_IP_LIST}")
        .replace("      whitelisted_ip: id_of_ip_list \n", "")
        .replace(
            "      type: https\n",
            "      type: https\n      whitelisted_ip: id_of_ip_list\n",
        )
        .replace("localhost:443", &format!("localhost:{port}"))
        .replace(
            "http://10.0.0.4:7702",
            &format!("http://127.0.0.1:{}", upstream.port),
        )
        .replace("id_of_ip_list", &list_id);

    println!("--- settings, the list on the endpoint ---\n{yaml}");

    apply_settings(&yaml).await;
    serve(port);

    let host = format!("localhost:{port}");
    let reply = send(Client::TlsHttp1, port, "localhost", &host, &[]).await;
    let outcome = Outcome::new(reply, &upstream).await;

    println!("--- outcome ---\n{outcome:#?}");

    assert!(outcome.refused(), "the request was served: {outcome:#?}");
}

// ---------------------------------------------------------------------------------------------
// Every endpoint type against every setting
// ---------------------------------------------------------------------------------------------

/// One row of the table: what is configured, and what the request carries.
#[derive(Clone, Copy)]
struct Setup {
    name: &'static str,
    /// `whitelisted_ip` of the LOCATION: what the list it names holds.
    location_list: Option<&'static [&'static str]>,
    /// The location names a list which `ip_white_lists` does not declare.
    location_list_is_not_declared: bool,
    /// A second host of the same settings names the location's list as its ENDPOINT whitelist.
    /// An endpoint is the only thing which loads a list (`get_endpoint_white_listed_ip`).
    another_endpoint_uses_the_list: bool,
    /// `whitelisted_ip` of the ENDPOINT: what the list it names holds.
    endpoint_list: Option<&'static [&'static str]>,
    /// `auth_header` of the location.
    location_auth_header: bool,
    /// `google_auth` of the endpoint.
    endpoint_google_auth: bool,
    /// `allowed_users` of the endpoint.
    endpoint_allowed_users: bool,
    /// The request carries the `Authorization` the location asks for.
    request_is_authorized: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expected {
    /// Proxied, as the setting says: 200 with the upstream's body, and the upstream saw the
    /// request.
    Served,
    /// Not proxied, as the setting says: the upstream never saw the request.
    Refused,
}

impl Expected {
    fn is_served(self) -> bool {
        matches!(self, Expected::Served)
    }
}

const SERVED: Option<Expected> = Some(Expected::Served);
const REFUSED: Option<Expected> = Some(Expected::Refused);

/// The endpoint types, in the order of the columns of [`TABLE`].
const ENDPOINTS: [Endpoint; 7] = [
    Endpoint::Http,
    Endpoint::Https,
    Endpoint::Http2,
    Endpoint::Https2OverH2,
    Endpoint::Https2OverHttp1,
    Endpoint::Mcp,
    Endpoint::Tcp,
];

/// What the proxy does. The columns are [`ENDPOINTS`]:
/// http, https, http2, https2 (h2 client), https2 (http/1.1 client), mcp, tcp.
#[rustfmt::skip]
const TABLE: &[(Setup, [Option<Expected>; 7])] = &[
    (Setup { name: "nothing configured", ..NO_SETUP },
        [SERVED, SERVED, SERVED, SERVED, SERVED, SERVED, SERVED]),

    // --- the location's own whitelisted_ip ---------------------------------------------------
    //
    // A list is loaded into the live configuration by an ENDPOINT which names it
    // (`get_endpoint_white_listed_ip`) and by nothing else, and the hyper path takes a list which
    // is not loaded for one nobody is in. So "listed" needs two rows: with the list also named by
    // an endpoint somewhere in the settings, and with the location alone naming it.
    (Setup { name: "LOCATION whitelisted_ip, client NOT listed (list also used by an endpoint)",
             location_list: Some(CLIENT_IS_NOT_LISTED), another_endpoint_uses_the_list: true, ..NO_SETUP },
        [REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED]),
    (Setup { name: "LOCATION whitelisted_ip, client listed     (list also used by an endpoint)",
             location_list: Some(CLIENT_IS_LISTED), another_endpoint_uses_the_list: true, ..NO_SETUP },
        [SERVED, SERVED, SERVED, SERVED, SERVED, SERVED, SERVED]),
    (Setup { name: "LOCATION whitelisted_ip, client NOT listed (only the location names the list)",
             location_list: Some(CLIENT_IS_NOT_LISTED), ..NO_SETUP },
        [REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED]),
    (Setup { name: "LOCATION whitelisted_ip, client listed     (only the location names the list)",
             location_list: Some(CLIENT_IS_LISTED), ..NO_SETUP },
        [SERVED, SERVED, SERVED, SERVED, SERVED, SERVED, SERVED]),

    // --- the endpoint's whitelisted_ip, for comparison ---------------------------------------
    (Setup { name: "ENDPOINT whitelisted_ip, client NOT listed",
             endpoint_list: Some(CLIENT_IS_NOT_LISTED), ..NO_SETUP },
        [REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED]),
    (Setup { name: "ENDPOINT whitelisted_ip, client listed",
             endpoint_list: Some(CLIENT_IS_LISTED), ..NO_SETUP },
        [SERVED, SERVED, SERVED, SERVED, SERVED, SERVED, SERVED]),

    // --- the other access settings -----------------------------------------------------------
    //
    // `mcp` and `tcp` forward bytes: they read no request, so they can check neither a header
    // nor a session. An endpoint which was told to serves nobody - the right `Authorization`
    // does not open it. So does an `http` / `http2` endpoint with `google_auth`, which needs TLS.
    (Setup { name: "LOCATION auth_header, request without Authorization",
             location_auth_header: true, ..NO_SETUP },
        [REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED]),
    (Setup { name: "LOCATION auth_header, request with the right Authorization",
             location_auth_header: true, request_is_authorized: true, ..NO_SETUP },
        [SERVED, SERVED, SERVED, SERVED, SERVED, REFUSED, REFUSED]),
    (Setup { name: "ENDPOINT google_auth, request without a session",
             endpoint_google_auth: true, ..NO_SETUP },
        [REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED]),
    (Setup { name: "ENDPOINT allowed_users, request without an identity",
             endpoint_allowed_users: true, ..NO_SETUP },
        [REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED]),
];

const NO_SETUP: Setup = Setup {
    name: "",
    location_list: None,
    location_list_is_not_declared: false,
    another_endpoint_uses_the_list: false,
    endpoint_list: None,
    location_auth_header: false,
    endpoint_google_auth: false,
    endpoint_allowed_users: false,
    request_is_authorized: false,
};

/// A list a location names has to be declared, as one an endpoint names has to be.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_location_whitelist_which_is_not_declared_does_not_compile() {
    for endpoint in [
        Endpoint::Http,
        Endpoint::Https,
        Endpoint::Http2,
        Endpoint::Https2OverH2,
        Endpoint::Mcp,
    ] {
        let setup = Setup {
            location_list_is_not_declared: true,
            ..NO_SETUP
        };

        let yaml = settings_yaml(endpoint, &setup, free_port().await, free_port().await, 1);

        let err = try_apply_settings(&yaml)
            .await
            .expect_err("the settings compile");

        assert!(
            err.contains("Ip list with id") && err.contains("not found"),
            "{err}"
        );
    }
}

/// Probes every cell of [`TABLE`], prints what happened and then compares.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn access_settings_by_endpoint_type() {
    my_tls::install_default_crypto_providers();

    let mut mismatches = Vec::new();

    println!();
    println!("client address: 127.0.0.1");
    println!(
        "CLIENT_IS_NOT_LISTED = {CLIENT_IS_NOT_LISTED:?}   CLIENT_IS_LISTED = {CLIENT_IS_LISTED:?}"
    );

    for (setup, expected) in TABLE {
        println!();
        println!("=== {} ===", setup.name);

        for (endpoint, expected) in ENDPOINTS.iter().zip(expected.iter()) {
            let Some(expected) = expected else {
                continue;
            };

            let outcome = probe(*endpoint, setup).await;

            println!("  {:<24} {}", endpoint.column(), outcome.verdict());

            let as_expected = if expected.is_served() {
                outcome.served()
            } else {
                outcome.refused()
            };

            if !as_expected {
                mismatches.push(format!(
                    "[{}] on {}: expected {:?}, got {}\n{:#?}",
                    setup.name,
                    endpoint.column(),
                    expected,
                    outcome.verdict(),
                    outcome
                ));
            }
        }
    }

    assert!(
        mismatches.is_empty(),
        "{} cell(s) differ from the table:\n\n{}",
        mismatches.len(),
        mismatches.join("\n\n")
    );
}

// ---------------------------------------------------------------------------------------------
// Which pipeline serves a request is decided by the vhost the CONNECTION was opened for
// ---------------------------------------------------------------------------------------------

/// `https` and `https2` endpoints may share a port. A connection is handed to the pipeline of
/// the endpoint its SNI names, and that pipeline then routes every request by `Host`. So a
/// location whitelist of an `https2` endpoint - enforced when the endpoint is reached directly -
/// is not enforced for a request which arrives over a connection opened for an `https`
/// neighbour.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn https2_location_whitelist_holds_over_a_connection_opened_for_an_https_neighbour() {
    my_tls::install_default_crypto_providers();

    let upstream = Upstream::start().await;
    let neighbour_upstream = Upstream::start().await;
    let port = free_port().await;
    let other_port = free_port().await;
    let list_id = unique_id("crossvhost");

    // `list-loader` is there to have the list loaded, so that the refusals below are the list at
    // work and not a list which was never loaded.
    let yaml = format!(
        r#"hosts:
  guarded.test:{port}:
    endpoint:
      type: https2
    locations:
    - proxy_pass_to: http://127.0.0.1:{guarded_upstream}
      whitelisted_ip: {list_id}
  open.test:{port}:
    endpoint:
      type: https
    locations:
    - proxy_pass_to: http://127.0.0.1:{neighbour_upstream}
  list-loader.test:{other_port}:
    endpoint:
      type: http
      whitelisted_ip: {list_id}
    locations:
    - proxy_pass_to: http://127.0.0.1:{neighbour_upstream}
ip_white_lists:
  {list_id}:
{list}"#,
        guarded_upstream = upstream.port,
        neighbour_upstream = neighbour_upstream.port,
        list = yaml_list(CLIENT_IS_NOT_LISTED),
    );

    println!("--- settings ---\n{yaml}");

    apply_settings(&yaml).await;
    serve(port);

    let guarded_host = format!("guarded.test:{port}");

    // Reached directly, over h2 and over http/1.1: refused, the upstream is not reached.
    for client in [Client::TlsH2, Client::TlsHttp1] {
        let reply = send(client, port, "guarded.test", &guarded_host, &[]).await;
        let outcome = Outcome::new(reply, &upstream).await;
        println!("SNI guarded.test, {client:?}: {}", outcome.verdict());
        assert!(outcome.refused(), "{outcome:#?}");
        assert_eq!(outcome.status, Some(401), "{outcome:#?}");
    }

    // The same request, over a connection opened for the https neighbour: refused as well.
    let reply = send(Client::TlsHttp1, port, "open.test", &guarded_host, &[]).await;
    let outcome = Outcome::new(reply, &upstream).await;
    println!("SNI open.test, Host {guarded_host}: {}", outcome.verdict());
    assert!(outcome.refused(), "{outcome:#?}");
    assert_eq!(outcome.status, Some(401), "{outcome:#?}");
    assert_eq!(neighbour_upstream.requests().len(), 0);
}

/// The other way round: a location whitelist of an `https` endpoint, which is not enforced when
/// the endpoint is reached directly, is enforced for a request which arrives over a connection
/// opened for an `https2` neighbour - it is the hyper path which serves it then.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn https_location_whitelist_is_enforced_over_a_connection_opened_for_an_https2_neighbour() {
    my_tls::install_default_crypto_providers();

    let upstream = Upstream::start().await;
    let neighbour_upstream = Upstream::start().await;
    let port = free_port().await;
    let other_port = free_port().await;
    let list_id = unique_id("crossvhost2");

    let yaml = format!(
        r#"hosts:
  guarded.test:{port}:
    endpoint:
      type: https
    locations:
    - proxy_pass_to: http://127.0.0.1:{guarded_upstream}
      whitelisted_ip: {list_id}
  open.test:{port}:
    endpoint:
      type: https2
    locations:
    - proxy_pass_to: http://127.0.0.1:{neighbour_upstream}
  list-loader.test:{other_port}:
    endpoint:
      type: http
      whitelisted_ip: {list_id}
    locations:
    - proxy_pass_to: http://127.0.0.1:{neighbour_upstream}
ip_white_lists:
  {list_id}:
{list}"#,
        guarded_upstream = upstream.port,
        neighbour_upstream = neighbour_upstream.port,
        list = yaml_list(CLIENT_IS_NOT_LISTED),
    );

    println!("--- settings ---\n{yaml}");

    apply_settings(&yaml).await;
    serve(port);

    let guarded_host = format!("guarded.test:{port}");

    // Reached directly: refused.
    let reply = send(Client::TlsHttp1, port, "guarded.test", &guarded_host, &[]).await;
    let outcome = Outcome::new(reply, &upstream).await;
    println!("SNI guarded.test: {}", outcome.verdict());
    assert!(outcome.refused(), "{outcome:#?}");
    assert_eq!(outcome.status, Some(401), "{outcome:#?}");

    // Over a connection opened for the https2 neighbour: refused.
    let before = upstream.requests().len();
    for client in [Client::TlsH2, Client::TlsHttp1] {
        let reply = send(client, port, "open.test", &guarded_host, &[]).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        println!(
            "SNI open.test, {client:?}, Host {guarded_host}: status {:?}, upstream requests {}",
            reply.status,
            upstream.requests().len() - before
        );
        assert_eq!(reply.status, Some(401), "{reply:#?}");
        assert_eq!(upstream.requests().len(), before);
    }
}

// ---------------------------------------------------------------------------------------------
// Every kind of location
// ---------------------------------------------------------------------------------------------

/// What a location with its own whitelist serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocationKind {
    /// `proxy_pass_to: static` with a body.
    Static,
    /// A folder of local files.
    Files,
    /// `proxy_pass_to: dynamic`: the client names the upstream in `proxy-to` - the README tells to
    /// guard such a location with `auth_header` / `google_auth` / `whitelisted_ip`.
    Dynamic,
    /// An http upstream, asked for a websocket upgrade: the h1 pipeline hands that to a tunnel of
    /// its own (`run_ws_tunnel`).
    WebSocketUpgrade,
}

const STATIC_CONTENT: &str = "<p>the static content of the location</p>";
const FILE_CONTENT: &str = "the content of a file in the folder of the location";

/// A folder for a files location, with `secret.txt` in it. Removed when the test ends.
struct FolderWithAFile {
    path: std::path::PathBuf,
}

impl FolderWithAFile {
    fn create() -> Self {
        let path = std::env::temp_dir().join(unique_id("mrp-location-files"));
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("secret.txt"), FILE_CONTENT).unwrap();
        Self { path }
    }
}

impl Drop for FolderWithAFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The h1 pipeline serves static content, local files, a dynamic upstream and a websocket upgrade
/// each on a branch of its own. None of them looks at the location's whitelist either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn location_whitelist_by_location_kind() {
    my_tls::install_default_crypto_providers();

    let folder = FolderWithAFile::create();

    let mut mismatches = Vec::new();

    for kind in [
        LocationKind::Static,
        LocationKind::Files,
        LocationKind::Dynamic,
        LocationKind::WebSocketUpgrade,
    ] {
        for (list_name, list) in [
            ("client NOT listed", CLIENT_IS_NOT_LISTED),
            ("client listed    ", CLIENT_IS_LISTED),
        ] {
            println!();
            println!("=== {kind:?} location with its own whitelisted_ip, {list_name} ===");

            for endpoint in [
                Endpoint::Http,
                Endpoint::Https,
                Endpoint::Http2,
                Endpoint::Https2OverH2,
                Endpoint::Https2OverHttp1,
            ] {
                // An `Upgrade` header does not exist in h2.
                if kind == LocationKind::WebSocketUpgrade
                    && matches!(endpoint.client(), Client::PlainH2 | Client::TlsH2)
                {
                    continue;
                }

                let upstream = Upstream::start().await;
                let port = free_port().await;
                let other_port = free_port().await;
                let list_id = unique_id("kind");
                let upstream_url = format!("http://127.0.0.1:{}", upstream.port);

                let location = match kind {
                    LocationKind::Static => format!(
                        "    - proxy_pass_to: static\n      content_type: text/html\n      body: \"{STATIC_CONTENT}\"\n"
                    ),
                    LocationKind::Files => format!(
                        "    - proxy_pass_to: {}\n      default_file: secret.txt\n",
                        folder.path.to_str().unwrap()
                    ),
                    LocationKind::Dynamic => "    - proxy_pass_to: dynamic\n".to_string(),
                    LocationKind::WebSocketUpgrade => {
                        format!("    - proxy_pass_to: {upstream_url}\n")
                    }
                };

                // `list-loader` has the list loaded, so that a refusal is the list at work.
                let yaml = format!(
                    "hosts:\n  localhost:{port}:\n    endpoint:\n      type: {endpoint_type}\n    locations:\n{location}      whitelisted_ip: {list_id}\n  list-loader.test:{other_port}:\n    endpoint:\n      type: http\n      whitelisted_ip: {list_id}\n    locations:\n    - proxy_pass_to: {upstream_url}\nip_white_lists:\n  {list_id}:\n{list}",
                    endpoint_type = endpoint.type_name(),
                    list = yaml_list(list),
                );

                apply_settings(&yaml).await;
                serve(port);

                let headers: Vec<(&str, &str)> = match kind {
                    LocationKind::Static | LocationKind::Files => vec![],
                    LocationKind::Dynamic => vec![("proxy-to", upstream_url.as_str())],
                    LocationKind::WebSocketUpgrade => vec![
                        ("connection", "Upgrade"),
                        ("upgrade", "websocket"),
                        ("sec-websocket-version", "13"),
                        ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
                    ],
                };

                let reply = send(
                    endpoint.client(),
                    port,
                    "localhost",
                    &format!("localhost:{port}"),
                    &headers,
                )
                .await;

                let outcome = Outcome::new(reply, &upstream).await;

                // The upstream here is a plain http one: it answers an upgrade request with its
                // usual 200, which is all it takes to see that the request was handed to it.
                let got_the_content = match kind {
                    LocationKind::Static => {
                        outcome.status == Some(200) && outcome.body == STATIC_CONTENT
                    }
                    LocationKind::Files => {
                        outcome.status == Some(200) && outcome.body == FILE_CONTENT
                    }
                    LocationKind::Dynamic => outcome.served(),
                    LocationKind::WebSocketUpgrade => {
                        outcome.served()
                            && outcome.upstream_requests[0].contains("upgrade: websocket")
                    }
                };

                let refused = outcome.status == Some(401)
                    && outcome.upstream_requests.is_empty()
                    && !outcome.body.contains(STATIC_CONTENT)
                    && !outcome.body.contains(FILE_CONTENT);

                println!(
                    "  {:<24} {}  status {:?}, requests at the upstream: {}",
                    endpoint.column(),
                    if got_the_content {
                        "GOT THE CONTENT"
                    } else if refused {
                        "REFUSED        "
                    } else {
                        "UNCLEAR        "
                    },
                    outcome.status,
                    outcome.upstream_requests.len()
                );

                // A listed client is served everywhere, one which is not listed nowhere.
                let as_expected = if list == CLIENT_IS_LISTED {
                    got_the_content
                } else {
                    refused
                };

                if !as_expected {
                    mismatches.push(format!(
                        "{kind:?}, {list_name}, {}:\n{yaml}\n{outcome:#?}",
                        endpoint.column()
                    ));
                }
            }
        }
    }

    println!();

    assert!(
        mismatches.is_empty(),
        "{} probe(s) went another way:\n\n{}",
        mismatches.len(),
        mismatches.join("\n\n")
    );
}

// ---------------------------------------------------------------------------------------------
// A location's modify_http_headers
// ---------------------------------------------------------------------------------------------

/// Not an access setting, but the same two paths: `modify_http_headers` of a location is applied
/// by both of them - what it adds to a request and to a response, and what it removes from a
/// request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn location_modify_http_headers_by_endpoint_type() {
    my_tls::install_default_crypto_providers();

    let mut seen = Vec::new();

    for endpoint in [
        Endpoint::Http,
        Endpoint::Https,
        Endpoint::Http2,
        Endpoint::Https2OverH2,
        Endpoint::Https2OverHttp1,
    ] {
        let upstream = Upstream::start().await;
        let port = free_port().await;

        let yaml = format!(
            r#"hosts:
  localhost:{port}:
    endpoint:
      type: {endpoint_type}
    locations:
    - proxy_pass_to: http://127.0.0.1:{upstream_port}
      modify_http_headers:
        add:
          request:
          - name: x-added-by-location
            value: "yes"
          response:
          - name: x-response-added-by-location
            value: "yes"
        remove:
          request:
          - x-secret-from-client
"#,
            endpoint_type = endpoint.type_name(),
            upstream_port = upstream.port,
        );

        apply_settings(&yaml).await;
        serve(port);

        let reply = send(
            endpoint.client(),
            port,
            "localhost",
            &format!("localhost:{port}"),
            &[("x-secret-from-client", "do-not-forward")],
        )
        .await;
        let outcome = Outcome::new(reply, &upstream).await;
        assert!(outcome.served(), "{outcome:#?}");

        let request = outcome.upstream_requests[0].as_str();
        let added = request.contains("x-added-by-location: yes");
        let removed = !request.contains("x-secret-from-client");
        let response_added = outcome
            .response_headers
            .contains("x-response-added-by-location: yes");

        println!(
            "  {:<24} request header added: {:<5} request header removed: {:<5} response header added: {}",
            endpoint.column(),
            added,
            removed,
            response_added
        );

        seen.push((endpoint, added, removed, response_added));
    }

    assert_eq!(
        seen,
        vec![
            (Endpoint::Http, true, true, true),
            (Endpoint::Https, true, true, true),
            (Endpoint::Http2, true, true, true),
            (Endpoint::Https2OverH2, true, true, true),
            (Endpoint::Https2OverHttp1, true, true, true),
        ]
    );
}

/// "Example of serving redirect to the same url but with https schema" - under `hosts:`.
const README_REDIRECT_EXAMPLE: &str = "  7700:\n    endpoint:\n      type: http\n\n    locations:\n    - type: static\n      status_code: 302\n      modify_http_headers:\n        add:\n          response:\n          - name: Location\n            value: https://${HOST_PORT}${PATH_AND_QUERY}\n";

/// The README's redirect example gives its `Location` through `modify_http_headers` of the
/// location, on a `type: http` endpoint - a static location, which answers itself. The 302 has
/// its `Location` there, and under `type: http2` as well.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn readme_redirect_example_redirects() {
    assert!(README.contains(README_REDIRECT_EXAMPLE));

    let mut seen = Vec::new();

    for endpoint in [Endpoint::Http, Endpoint::Http2] {
        let port = free_port().await;

        let yaml = format!("hosts:\n{README_REDIRECT_EXAMPLE}")
            .replace("  7700:", &format!("  localhost:{port}:"))
            .replace("type: http\n", &format!("type: {}\n", endpoint.type_name()));

        apply_settings(&yaml).await;
        serve(port);

        let host = format!("localhost:{port}");
        let reply = send(endpoint.client(), port, "localhost", &host, &[]).await;

        let location = reply
            .headers
            .lines()
            .find(|line| line.starts_with("location: "))
            .map(|line| line.to_string());

        println!(
            "  {:<6} status {:?}, {}",
            endpoint.column(),
            reply.status,
            location.as_deref().unwrap_or("no Location header")
        );

        seen.push((endpoint, reply.status, location));
    }

    for (_endpoint, status, location) in &seen {
        assert_eq!(*status, Some(302), "{seen:?}");
        assert!(
            location
                .as_deref()
                .unwrap_or("")
                .starts_with("location: https://localhost"),
            "{seen:?}"
        );
    }
}

/// `domain_name` of a location is the name an https upstream is asked for, on both paths. The
/// upstream here is given by its address, so without `domain_name` the ClientHello would carry
/// no server name at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn location_domain_name_by_endpoint_type() {
    my_tls::install_default_crypto_providers();

    let mut seen = Vec::new();

    for endpoint in [
        Endpoint::Http,
        Endpoint::Https,
        Endpoint::Http2,
        Endpoint::Https2OverH2,
    ] {
        let (upstream_port, server_names) = start_server_name_recorder().await;
        let port = free_port().await;

        let yaml = format!(
            "hosts:\n  localhost:{port}:\n    endpoint:\n      type: {endpoint_type}\n    locations:\n    - proxy_pass_to: https://127.0.0.1:{upstream_port}\n      domain_name: upstream.internal\n",
            endpoint_type = endpoint.type_name(),
        );

        apply_settings(&yaml).await;
        serve(port);

        // The handshake with this upstream never completes, so the answer is an error page;
        // what matters is the ClientHello the upstream got.
        let host = format!("localhost:{port}");
        let reply = send(endpoint.client(), port, "localhost", &host, &[]).await;

        let server_name = server_names.lock().unwrap().first().cloned();

        println!(
            "  {:<24} the upstream was asked for: {:?}   (the client got {:?})",
            endpoint.column(),
            server_name,
            reply.status
        );

        seen.push((endpoint, server_name));
    }

    let asked_for = Some(Some("upstream.internal".to_string()));

    assert_eq!(
        seen,
        vec![
            (Endpoint::Http, asked_for.clone()),
            (Endpoint::Https, asked_for.clone()),
            (Endpoint::Http2, asked_for.clone()),
            (Endpoint::Https2OverH2, asked_for),
        ]
    );
}

/// A TLS upstream which notes the server name of every ClientHello and hangs up.
async fn start_server_name_recorder() -> (u16, Arc<Mutex<Vec<Option<String>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server_names = Arc::new(Mutex::new(Vec::new()));

    let seen = server_names.clone();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };

            let seen = seen.clone();

            tokio::spawn(async move {
                let acceptor = my_tls::tokio_rustls::LazyConfigAcceptor::new(
                    rustls::server::Acceptor::default(),
                    stream,
                );

                if let Ok(start) = acceptor.await {
                    let server_name = start.client_hello().server_name().map(str::to_string);
                    seen.lock().unwrap().push(server_name);
                }
            });
        }
    });

    (port, server_names)
}

/// `hsts` of an endpoint: every https endpoint sends `Strict-Transport-Security`, whichever of
/// the two paths serves it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn endpoint_hsts_by_endpoint_type() {
    my_tls::install_default_crypto_providers();

    let mut seen = Vec::new();

    for endpoint in [
        Endpoint::Https,
        Endpoint::Https2OverH2,
        Endpoint::Https2OverHttp1,
    ] {
        let upstream = Upstream::start().await;
        let port = free_port().await;

        let yaml = format!(
            "hosts:\n  localhost:{port}:\n    endpoint:\n      type: {endpoint_type}\n      hsts: true\n    locations:\n    - proxy_pass_to: http://127.0.0.1:{upstream_port}\n",
            endpoint_type = endpoint.type_name(),
            upstream_port = upstream.port,
        );

        apply_settings(&yaml).await;
        serve(port);

        let host = format!("localhost:{port}");
        let reply = send(endpoint.client(), port, "localhost", &host, &[]).await;
        let outcome = Outcome::new(reply, &upstream).await;
        assert!(outcome.served(), "{outcome:#?}");

        let has_hsts = outcome
            .response_headers
            .contains("strict-transport-security: ");

        println!(
            "  {:<24} Strict-Transport-Security in the response: {}",
            endpoint.column(),
            has_hsts
        );

        seen.push((endpoint, has_hsts));
    }

    assert_eq!(
        seen,
        vec![
            (Endpoint::Https, true),
            (Endpoint::Https2OverH2, true),
            (Endpoint::Https2OverHttp1, true),
        ]
    );
}

// ---------------------------------------------------------------------------------------------
// The proxy under test
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Endpoint {
    Http,
    Https,
    Http2,
    /// `type: https2`, the client negotiates `h2`.
    Https2OverH2,
    /// `type: https2`, the client negotiates `http/1.1` - still served by hyper.
    Https2OverHttp1,
    /// `type: mcp`: TLS, then a raw byte bridge to the first location.
    Mcp,
    /// `type: tcp`: a raw byte bridge to the first location.
    Tcp,
}

impl Endpoint {
    fn type_name(self) -> &'static str {
        match self {
            Endpoint::Http => "http",
            Endpoint::Https => "https",
            Endpoint::Http2 => "http2",
            Endpoint::Https2OverH2 | Endpoint::Https2OverHttp1 => "https2",
            Endpoint::Mcp => "mcp",
            Endpoint::Tcp => "tcp",
        }
    }

    fn column(self) -> &'static str {
        match self {
            Endpoint::Http => "http",
            Endpoint::Https => "https",
            Endpoint::Http2 => "http2",
            Endpoint::Https2OverH2 => "https2 (h2 client)",
            Endpoint::Https2OverHttp1 => "https2 (http/1.1 client)",
            Endpoint::Mcp => "mcp",
            Endpoint::Tcp => "tcp",
        }
    }

    fn client(self) -> Client {
        match self {
            Endpoint::Http | Endpoint::Tcp => Client::PlainHttp1,
            Endpoint::Http2 => Client::PlainH2,
            Endpoint::Https | Endpoint::Https2OverHttp1 | Endpoint::Mcp => Client::TlsHttp1,
            Endpoint::Https2OverH2 => Client::TlsH2,
        }
    }

    fn proxy_pass_to(self, upstream_port: u16) -> String {
        match self {
            Endpoint::Tcp => format!("127.0.0.1:{upstream_port}"),
            _ => format!("http://127.0.0.1:{upstream_port}"),
        }
    }
}

/// One request to one endpoint of `endpoint`'s type, set up as `setup` says.
async fn probe(endpoint: Endpoint, setup: &Setup) -> Outcome {
    let upstream = Upstream::start().await;
    let port = free_port().await;
    let other_port = free_port().await;

    let yaml = settings_yaml(endpoint, setup, port, other_port, upstream.port);

    apply_settings(&yaml).await;
    serve(port);

    let authorization = [("authorization", LOCATION_TOKEN)];
    let headers: &[(&str, &str)] = if setup.request_is_authorized {
        &authorization
    } else {
        &[]
    };

    let reply = send(
        endpoint.client(),
        port,
        "localhost",
        &format!("localhost:{port}"),
        headers,
    )
    .await;

    let mut outcome = Outcome::new(reply, &upstream).await;
    outcome.settings = yaml;
    outcome
}

fn settings_yaml(
    endpoint: Endpoint,
    setup: &Setup,
    port: u16,
    other_port: u16,
    upstream_port: u16,
) -> String {
    let id = unique_id("probe");
    let location_list_id = format!("{id}_location_list");
    let endpoint_list_id = format!("{id}_endpoint_list");
    let proxy_pass_to = endpoint.proxy_pass_to(upstream_port);

    let mut endpoint_lines = String::new();
    let mut location_lines = String::new();
    let mut other_hosts = String::new();
    let mut ip_white_lists = String::new();
    let mut sections = String::new();

    if let Some(list) = setup.location_list {
        location_lines.push_str(&format!("      whitelisted_ip: {location_list_id}\n"));
        ip_white_lists.push_str(&format!("  {location_list_id}:\n{}", yaml_list(list)));

        if setup.another_endpoint_uses_the_list {
            other_hosts.push_str(&format!(
                "  localhost:{other_port}:\n    endpoint:\n      type: http\n      whitelisted_ip: {location_list_id}\n    locations:\n    - proxy_pass_to: http://127.0.0.1:{upstream_port}\n"
            ));
        }
    }

    if setup.location_list_is_not_declared {
        location_lines.push_str(&format!("      whitelisted_ip: {location_list_id}\n"));
    }

    if let Some(list) = setup.endpoint_list {
        endpoint_lines.push_str(&format!("      whitelisted_ip: {endpoint_list_id}\n"));
        ip_white_lists.push_str(&format!("  {endpoint_list_id}:\n{}", yaml_list(list)));
    }

    if setup.location_auth_header {
        location_lines.push_str(&format!("      auth_header: \"{LOCATION_TOKEN}\"\n"));
    }

    if setup.endpoint_google_auth {
        endpoint_lines.push_str(&format!("      google_auth: {id}_g_auth\n"));
        sections.push_str(&format!(
            "g_auth:\n  {id}_g_auth:\n    client_id: test-client-id\n    client_secret: test-client-secret\n    whitelisted_domains: example.com\n"
        ));
    }

    if setup.endpoint_allowed_users {
        endpoint_lines.push_str(&format!("      allowed_users: {id}_users\n"));
        sections.push_str(&format!(
            "allowed_users:\n  {id}_users:\n  - someone@example.com\n"
        ));
    }

    if !ip_white_lists.is_empty() {
        sections.push_str(&format!("ip_white_lists:\n{ip_white_lists}"));
    }

    format!(
        "hosts:\n  localhost:{port}:\n    endpoint:\n      type: {endpoint_type}\n{endpoint_lines}    locations:\n    - proxy_pass_to: {proxy_pass_to}\n{location_lines}{other_hosts}{sections}",
        endpoint_type = endpoint.type_name(),
    )
}

fn yaml_list(items: &[&str]) -> String {
    items
        .iter()
        .map(|item| format!("    - \"{item}\"\n"))
        .collect()
}

fn unique_id(prefix: &str) -> String {
    format!(
        "{prefix}_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    )
}

/// What `flows::load_everything_from_settings` does with a settings file, for the settings in
/// `yaml`: every host goes through `scripts::compile_host_configuration` - `existing` being what
/// the same port got from the hosts before it - and the port configurations are published into
/// the live configuration, where the accept loop looks its port up.
///
/// Two things are left out, and neither takes part in what is tested: the file is not read from
/// `~/.my-reverse-proxy`, and `${variables}` are not substituted (the settings here have none, so
/// `SettingsCompiled::populate` would copy every field as it is). The flow swaps the whole port
/// map in; here the ports are added to it, to leave the ports of other tests alone.
async fn apply_settings(yaml: &str) {
    if let Err(err) = try_apply_settings(yaml).await {
        panic!("{err}\n{yaml}");
    }
}

async fn try_apply_settings(yaml: &str) -> Result<(), String> {
    let model: SettingsModel = my_settings_reader::serde_yaml::from_str(yaml)
        .map_err(|err| format!("the settings do not parse: {err}"))?;

    let settings = SettingsCompiled {
        hosts: model.hosts,
        ip_white_lists: model.ip_white_lists.unwrap_or_default(),
        allowed_users: model.allowed_users.unwrap_or_default(),
        g_auth: model.g_auth.unwrap_or_default(),
        ..Default::default()
    };

    for (host_id, host_settings) in &settings.hosts {
        let endpoint_host = settings.get_endpoint_host_string(host_id).unwrap();

        let EndpointPort::Tcp(port) = endpoint_host.get_port() else {
            panic!("{host_id} is not a tcp port");
        };

        let existing = crate::app::APP_CTX
            .current_configuration
            .get(|config| config.listen_tcp_endpoints.get(&port).cloned())
            .await;

        let configuration = crate::scripts::compile_host_configuration(
            &settings,
            endpoint_host,
            host_settings,
            existing,
        )
        .await
        .map_err(|err| format!("host {host_id} does not compile: {err}"))?;

        crate::app::APP_CTX
            .current_configuration
            .write(move |config| {
                config.listen_tcp_endpoints.insert(port, configuration);
            })
            .await;
    }

    Ok(())
}

/// The accept loop the proxy runs for a tcp port. `sync_endpoints` starts it on 0.0.0.0; here it
/// is on the loopback.
fn serve(port: u16) {
    super::start_listen_tcp_server(SocketAddr::from(([127, 0, 0, 1], port)));
}

async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

// ---------------------------------------------------------------------------------------------
// The upstream
// ---------------------------------------------------------------------------------------------

/// An http/1.1 upstream on a port of its own. It answers every request with [`UPSTREAM_BODY`]
/// and keeps the head of each.
struct Upstream {
    port: u16,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Upstream {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));

        let seen = requests.clone();

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };

                let seen = seen.clone();

                let service = hyper::service::service_fn(
                    move |request: hyper::Request<hyper::body::Incoming>| {
                        let seen = seen.clone();

                        async move {
                            let mut head = format!("{} {}", request.method(), request.uri());

                            for (name, value) in request.headers() {
                                head.push_str(&format!(
                                    "\n{}: {}",
                                    name,
                                    value.to_str().unwrap_or("<not text>")
                                ));
                            }

                            seen.lock().unwrap().push(head);

                            Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                                Bytes::from_static(UPSTREAM_BODY.as_bytes()),
                            )))
                        }
                    },
                );

                tokio::spawn(
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service),
                );
            }
        });

        Self { port, requests }
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

// ---------------------------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Client {
    /// http/1.1 on a plain connection.
    PlainHttp1,
    /// h2 with prior knowledge on a plain connection.
    PlainH2,
    /// TLS, offering `http/1.1` only.
    TlsHttp1,
    /// TLS, offering `h2` only.
    TlsH2,
}

/// What the client got.
#[derive(Debug, Default)]
struct Reply {
    /// `None`: the connection gave no response.
    status: Option<u16>,
    headers: String,
    body: String,
    /// Why there is no response.
    error: Option<String>,
}

impl Reply {
    fn none(error: String) -> Self {
        Self {
            error: Some(error),
            ..Default::default()
        }
    }
}

/// `GET /` to the proxy on `port`: `server_name` is the SNI of a TLS connection, `host` what the
/// request is for.
async fn send(
    client: Client,
    port: u16,
    server_name: &str,
    host: &str,
    headers: &[(&str, &str)],
) -> Reply {
    match client {
        Client::PlainHttp1 => get_over_http1(connect(port).await, host, headers).await,
        Client::PlainH2 => get_over_h2(connect(port).await, "http", host, headers).await,
        Client::TlsHttp1 => match connect_tls(port, server_name, b"http/1.1").await {
            Ok(stream) => get_over_http1(stream, host, headers).await,
            Err(err) => Reply::none(err),
        },
        Client::TlsH2 => match connect_tls(port, server_name, b"h2").await {
            Ok(stream) => get_over_h2(stream, "https", host, headers).await,
            Err(err) => Reply::none(err),
        },
    }
}

/// The accept loop binds its port in a task of its own, so the first attempts may come early.
async fn connect(port: u16) -> TcpStream {
    for _ in 0..500 {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
            assert_eq!(
                stream.local_addr().unwrap().ip().to_string(),
                "127.0.0.1",
                "the client is expected to connect from 127.0.0.1"
            );
            return stream;
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    panic!("nothing listens on 127.0.0.1:{port}");
}

async fn connect_tls(
    port: u16,
    server_name: &str,
    alpn: &[u8],
) -> Result<TlsStream<TcpStream>, String> {
    let mut client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    client_config.alpn_protocols = vec![alpn.to_vec()];

    let tcp_stream = connect(port).await;

    let connecting = TlsConnector::from(Arc::new(client_config)).connect(
        ServerName::try_from(server_name.to_string()).unwrap(),
        tcp_stream,
    );

    match tokio::time::timeout(TIMEOUT, connecting).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(err)) => Err(format!("tls handshake failed: {err:?}")),
        Err(_) => Err("tls handshake timed out".to_string()),
    }
}

async fn get_over_http1<S>(stream: S, host: &str, headers: &[(&str, &str)]) -> Reply
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) =
        match hyper::client::conn::http1::handshake(TokioIo::new(stream)).await {
            Ok(result) => result,
            Err(err) => return Reply::none(format!("http/1.1 handshake failed: {err:?}")),
        };

    tokio::spawn(connection);

    let mut request = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri("/")
        .header("host", host);

    for (name, value) in headers {
        request = request.header(*name, *value);
    }

    let request = request.body(Empty::<Bytes>::new()).unwrap();

    into_reply(tokio::time::timeout(TIMEOUT, sender.send_request(request)).await).await
}

async fn get_over_h2<S>(stream: S, scheme: &str, host: &str, headers: &[(&str, &str)]) -> Reply
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) =
        match hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
        {
            Ok(result) => result,
            Err(err) => return Reply::none(format!("h2 handshake failed: {err:?}")),
        };

    tokio::spawn(connection);

    let mut request = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(format!("{scheme}://{host}/"));

    for (name, value) in headers {
        request = request.header(*name, *value);
    }

    let request = request.body(Empty::<Bytes>::new()).unwrap();

    into_reply(tokio::time::timeout(TIMEOUT, sender.send_request(request)).await).await
}

async fn into_reply(
    result: Result<
        Result<hyper::Response<hyper::body::Incoming>, hyper::Error>,
        tokio::time::error::Elapsed,
    >,
) -> Reply {
    let response = match result {
        Ok(Ok(response)) => response,
        Ok(Err(err)) => return Reply::none(format!("no response: {err:?}")),
        Err(_) => return Reply::none("no response in time".to_string()),
    };

    let status = response.status().as_u16();

    let mut headers = String::new();
    for (name, value) in response.headers() {
        headers.push_str(&format!(
            "{}: {}\n",
            name,
            value.to_str().unwrap_or("<not text>")
        ));
    }

    let body = match tokio::time::timeout(TIMEOUT, response.into_body().collect()).await {
        Ok(Ok(body)) => String::from_utf8_lossy(&body.to_bytes()).to_string(),
        Ok(Err(err)) => format!("<the body failed: {err:?}>"),
        Err(_) => "<the body did not end in time>".to_string(),
    };

    Reply {
        status: Some(status),
        headers,
        body,
        error: None,
    }
}

/// What a probe saw, on both sides of the proxy.
#[derive(Debug)]
struct Outcome {
    /// The status the client got, `None` when the connection gave no response.
    status: Option<u16>,
    response_headers: String,
    body: String,
    error: Option<String>,
    /// The head of every request which reached the upstream.
    upstream_requests: Vec<String>,
    settings: String,
}

impl Outcome {
    async fn new(reply: Reply, upstream: &Upstream) -> Self {
        // A request which is proxied after its client was answered would still show.
        if reply.body != UPSTREAM_BODY {
            tokio::time::sleep(Duration::from_millis(150)).await;
        }

        Self {
            status: reply.status,
            response_headers: reply.headers,
            body: reply.body,
            error: reply.error,
            upstream_requests: upstream.requests(),
            settings: String::new(),
        }
    }

    /// Proxied: the client has the upstream's answer, and the upstream saw exactly this request.
    fn served(&self) -> bool {
        self.status == Some(200) && self.body == UPSTREAM_BODY && self.upstream_requests.len() == 1
    }

    /// Not proxied: the upstream saw nothing, and the client does not have its answer.
    fn refused(&self) -> bool {
        self.upstream_requests.is_empty() && self.body != UPSTREAM_BODY
    }

    fn verdict(&self) -> String {
        let client = match self.status {
            Some(status) if self.body == UPSTREAM_BODY => {
                format!("{status} with the upstream's body")
            }
            Some(status) => format!("{status} from the proxy ({})", first_words(&self.body)),
            None => format!(
                "connection closed without a response ({})",
                self.error.as_deref().unwrap_or("?")
            ),
        };

        let word = if self.served() {
            "SERVED "
        } else if self.refused() {
            "REFUSED"
        } else {
            "UNCLEAR"
        };

        format!(
            "{word}  client: {client}; requests at the upstream: {}",
            self.upstream_requests.len()
        )
    }
}

/// The text of an error page of the proxy, without its markup.
fn first_words(body: &str) -> String {
    let mut text = String::new();
    let mut in_tag = false;

    for c in body.chars() {
        match c {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                text.push(' ');
            }
            c if !in_tag => text.push(c),
            _ => {}
        }
    }

    let words: Vec<&str> = text.split_whitespace().take(6).collect();
    words.join(" ")
}

/// The endpoints serve the proxy's self-signed certificate; what is under test is what happens
/// after the handshake.
#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

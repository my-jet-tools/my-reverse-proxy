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
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
        DigitallySignedStruct, SignatureScheme,
    },
    TlsConnector,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::test_ports::free_port;
use crate::{
    configurations::EndpointPort, settings::SettingsModel, settings_compiled::SettingsCompiled,
};

const TIMEOUT: Duration = Duration::from_secs(10);

const UPSTREAM_BODY: &str = "answered by the upstream";

/// The list of the README's "IP Whitelisting" section. The client (127.0.0.1) is not in it.
const CLIENT_IS_NOT_LISTED: &[&str] = &["10.0.0.5", "10.0.0.1-10.0.0.5"];

/// A list the client (127.0.0.1) is in.
const CLIENT_IS_LISTED: &[&str] = &["127.0.0.1"];

/// Countries without the one the loopback is of in the tests
/// ([`crate::types::LOOPBACK_COUNTRY_IN_TESTS`], UA).
const CLIENT_COUNTRY_IS_NOT_LISTED: &[&str] = &["DE", "USA"];

/// The loopback's country of the tests, among others - written as a code of three letters too.
const CLIENT_COUNTRY_IS_LISTED: &[&str] = &["DE", "ukr"];

/// A list with no entry: nobody is let in.
const EMPTY_LIST: &[&str] = &[];

/// `*` among the entries: everybody is let in - the client being in none of the others.
const EVERYBODY: &[&str] = &["10.0.0.5", "*"];

/// A country list of `*` and countries the client is not of: everybody is let in.
const EVERY_COUNTRY: &[&str] = &["DE", "*"];

/// The key the location of `location_api_keys_auth` takes in `X-Api-Key`.
const LOCATION_TOKEN: &str = "location-secret-key";

/// The README, to take its own example from - with `\n` line ends, which a checkout on Windows
/// may have turned into `\r\n`.
fn readme() -> String {
    include_str!("../../README.md").replace("\r\n", "\n")
}

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
    assert!(readme().contains(README_LOCATION_EXAMPLE));
    assert!(readme().contains(README_IP_LIST));

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
    /// The endpoint names a list which `ip_white_lists` does not declare.
    endpoint_list_is_not_declared: bool,
    /// `whitelisted_country` of the LOCATION: the countries of the list it names.
    location_countries: Option<&'static [&'static str]>,
    /// The location names a list which `country_white_lists` does not declare.
    location_countries_are_not_declared: bool,
    /// `whitelisted_country` of the ENDPOINT: the countries of the list it names.
    endpoint_countries: Option<&'static [&'static str]>,
    /// The endpoint names a list which `country_white_lists` does not declare.
    endpoint_countries_are_not_declared: bool,
    /// `api_keys_auth` of the location, with a set of `api_keys:` it names.
    location_api_keys_auth: bool,
    /// `google_auth` of the endpoint.
    endpoint_google_auth: bool,
    /// `allowed_users` of the endpoint.
    endpoint_allowed_users: bool,
    /// The request carries the `X-Api-Key` the location asks for.
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

    // --- whitelisted_country: the country of the client's address ----------------------------
    (Setup { name: "LOCATION whitelisted_country, client's country NOT listed",
             location_countries: Some(CLIENT_COUNTRY_IS_NOT_LISTED), ..NO_SETUP },
        [REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED]),
    (Setup { name: "LOCATION whitelisted_country, client's country listed",
             location_countries: Some(CLIENT_COUNTRY_IS_LISTED), ..NO_SETUP },
        [SERVED, SERVED, SERVED, SERVED, SERVED, SERVED, SERVED]),
    (Setup { name: "ENDPOINT whitelisted_country, client's country NOT listed",
             endpoint_countries: Some(CLIENT_COUNTRY_IS_NOT_LISTED), ..NO_SETUP },
        [REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED]),
    (Setup { name: "ENDPOINT whitelisted_country, client's country listed",
             endpoint_countries: Some(CLIENT_COUNTRY_IS_LISTED), ..NO_SETUP },
        [SERVED, SERVED, SERVED, SERVED, SERVED, SERVED, SERVED]),

    // Both lists named: a client has to pass both - a country list never opens what an ip list
    // keeps closed, nor the other way round.
    (Setup { name: "ENDPOINT whitelisted_ip listed, whitelisted_country NOT listed",
             endpoint_list: Some(CLIENT_IS_LISTED),
             endpoint_countries: Some(CLIENT_COUNTRY_IS_NOT_LISTED), ..NO_SETUP },
        [REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED]),
    (Setup { name: "ENDPOINT whitelisted_ip NOT listed, whitelisted_country listed",
             endpoint_list: Some(CLIENT_IS_NOT_LISTED),
             endpoint_countries: Some(CLIENT_COUNTRY_IS_LISTED), ..NO_SETUP },
        [REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED]),
    (Setup { name: "ENDPOINT whitelisted_country listed, LOCATION whitelisted_country NOT listed",
             endpoint_countries: Some(CLIENT_COUNTRY_IS_LISTED),
             location_countries: Some(CLIENT_COUNTRY_IS_NOT_LISTED), ..NO_SETUP },
        [REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED]),

    // --- an empty list, `*`, a list which is not declared -------------------------------------
    //
    // An empty list lets nobody in, and so does a list which is not declared - the host loads
    // all the same. `*` among the entries lets everybody in.
    (Setup { name: "LOCATION whitelisted_ip, the list is empty",
             location_list: Some(EMPTY_LIST), ..NO_SETUP },
        [REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED]),
    (Setup { name: "LOCATION whitelisted_ip, the list is not declared",
             location_list_is_not_declared: true, ..NO_SETUP },
        [REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED]),
    (Setup { name: "LOCATION whitelisted_ip, * among the entries",
             location_list: Some(EVERYBODY), ..NO_SETUP },
        [SERVED, SERVED, SERVED, SERVED, SERVED, SERVED, SERVED]),
    (Setup { name: "ENDPOINT whitelisted_ip, the list is empty",
             endpoint_list: Some(EMPTY_LIST), ..NO_SETUP },
        [REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED]),
    (Setup { name: "ENDPOINT whitelisted_ip, the list is not declared",
             endpoint_list_is_not_declared: true, ..NO_SETUP },
        [REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED]),
    (Setup { name: "ENDPOINT whitelisted_ip, * among the entries",
             endpoint_list: Some(EVERYBODY), ..NO_SETUP },
        [SERVED, SERVED, SERVED, SERVED, SERVED, SERVED, SERVED]),
    (Setup { name: "LOCATION whitelisted_country, the list is empty",
             location_countries: Some(EMPTY_LIST), ..NO_SETUP },
        [REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED]),
    (Setup { name: "LOCATION whitelisted_country, the list is not declared",
             location_countries_are_not_declared: true, ..NO_SETUP },
        [REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED]),
    (Setup { name: "LOCATION whitelisted_country, * among the entries",
             location_countries: Some(EVERY_COUNTRY), ..NO_SETUP },
        [SERVED, SERVED, SERVED, SERVED, SERVED, SERVED, SERVED]),
    (Setup { name: "ENDPOINT whitelisted_country, the list is empty",
             endpoint_countries: Some(EMPTY_LIST), ..NO_SETUP },
        [REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED]),
    (Setup { name: "ENDPOINT whitelisted_country, the list is not declared",
             endpoint_countries_are_not_declared: true, ..NO_SETUP },
        [REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED]),
    (Setup { name: "ENDPOINT whitelisted_country, * among the entries",
             endpoint_countries: Some(EVERY_COUNTRY), ..NO_SETUP },
        [SERVED, SERVED, SERVED, SERVED, SERVED, SERVED, SERVED]),

    // --- the other access settings -----------------------------------------------------------
    //
    // `mcp` and `tcp` forward bytes: they read no request, so they can check neither a header
    // nor a session. An endpoint which was told to serves nobody - the right `X-Api-Key` does
    // not open it. So does an `http` / `http2` endpoint with `google_auth`, which needs TLS.
    (Setup { name: "LOCATION api_keys_auth, request without X-Api-Key",
             location_api_keys_auth: true, ..NO_SETUP },
        [REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED, REFUSED]),
    (Setup { name: "LOCATION api_keys_auth, request with the right X-Api-Key",
             location_api_keys_auth: true, request_is_authorized: true, ..NO_SETUP },
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
    endpoint_list_is_not_declared: false,
    location_countries: None,
    location_countries_are_not_declared: false,
    endpoint_countries: None,
    endpoint_countries_are_not_declared: false,
    location_api_keys_auth: false,
    endpoint_google_auth: false,
    endpoint_allowed_users: false,
    request_is_authorized: false,
};

/// A country list with a code which is not a country does not load: a typo must not quietly
/// keep a country out. (A list which is not declared loads, and lets nobody in: see [`TABLE`].)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_country_list_with_a_code_which_is_not_a_country_does_not_compile() {
    for endpoint in [Endpoint::Http, Endpoint::Https2OverH2, Endpoint::Tcp] {
        let port = free_port().await;
        let proxy_pass_to = endpoint.proxy_pass_to(free_port().await);
        let endpoint_type = endpoint.type_name();

        let yaml = format!(
            "hosts:\n  localhost:{port}:\n    endpoint:\n      type: {endpoint_type}\n      whitelisted_country: typo\n    locations:\n    - proxy_pass_to: {proxy_pass_to}\ncountry_white_lists:\n  typo:\n  - UA\n  - XX\n"
        );

        let err = try_apply_settings(&yaml)
            .await
            .expect_err(&format!("the settings compile:\n{yaml}"));

        assert!(
            err.contains("country_white_lists.typo: 'XX' is not a country code"),
            "{endpoint_type}: {err}\n{yaml}"
        );
    }
}

/// A list which was declared, and is not any more after a reload, lets nobody in: what it held
/// does not stay in the live configuration.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_list_taken_out_of_the_settings_lets_nobody_in_any_more() {
    let port = free_port().await;
    let list_id = unique_id("taken_out");
    let host_header = format!("localhost:{port}");

    // Each step with an upstream of its own: what one counts is of that step alone.
    let host = |upstream_port: u16| {
        format!(
            "hosts:\n  localhost:{port}:\n    endpoint:\n      type: http\n      whitelisted_ip: {list_id}\n    locations:\n    - proxy_pass_to: http://127.0.0.1:{upstream_port}\n"
        )
    };

    let upstream = Upstream::start().await;
    apply_settings(&format!(
        "{}ip_white_lists:\n  {list_id}:\n  - \"127.0.0.1\"\n",
        host(upstream.port)
    ))
    .await;
    serve(port);

    let reply = send(Client::PlainHttp1, port, "localhost", &host_header, &[]).await;
    let outcome = Outcome::new(reply, &upstream).await;
    assert!(outcome.served(), "declared: {}", outcome.verdict());

    let upstream = Upstream::start().await;
    apply_settings(&host(upstream.port)).await;

    let reply = send(Client::PlainHttp1, port, "localhost", &host_header, &[]).await;
    let outcome = Outcome::new(reply, &upstream).await;
    assert!(outcome.refused(), "taken out: {}", outcome.verdict());
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
    /// guard such a location with `api_keys_auth` / `google_auth` / `whitelisted_ip`.
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

/// A header `modify_http_headers` adds is the proxy's word, never the client's. With no client
/// certificate and no Google cookie `${CLIENT_CERT_CN}` is empty: the header is not written,
/// and the one of that name the client sent is dropped too - otherwise the upstream would read
/// a user name the client made up. A header with a value replaces the client's, not joins it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_header_the_settings_add_is_never_taken_from_the_client() {
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
          - name: x-user
            value: ${{CLIENT_CERT_CN}}
          - name: x-proxy-says
            value: "the proxy"
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
            &[("x-user", "admin"), ("x-proxy-says", "the client")],
        )
        .await;
        let outcome = Outcome::new(reply, &upstream).await;
        assert!(outcome.served(), "{outcome:#?}");

        let request = outcome.upstream_requests[0].to_ascii_lowercase();
        let user_dropped = !request.contains("x-user") && !request.contains("admin");
        let value_replaced = request.matches("x-proxy-says").count() == 1
            && request.contains("x-proxy-says: the proxy");

        println!(
            "  {:<24} client x-user dropped: {:<5} client header replaced: {}",
            endpoint.column(),
            user_dropped,
            value_replaced
        );

        seen.push((endpoint, user_dropped, value_replaced));
    }

    assert_eq!(
        seen,
        vec![
            (Endpoint::Http, true, true),
            (Endpoint::Https, true, true),
            (Endpoint::Http2, true, true),
            (Endpoint::Https2OverH2, true, true),
            (Endpoint::Https2OverHttp1, true, true),
        ]
    );
}

// ---------------------------------------------------------------------------------------------
// X-Forwarded-User
// ---------------------------------------------------------------------------------------------

/// What a client sends to pass itself off as somebody: the header, and the spelling of it a
/// CGI-style server (PHP, WSGI, Rack) reads as the same `HTTP_X_FORWARDED_USER`.
const FORGED_BY_THE_CLIENT: &[(&str, &str)] = &[
    ("x-forwarded-user", "forged-by-the-client"),
    ("x_forwarded_user", "forged-by-the-client"),
];

/// A request of nobody - no client certificate, no Google sign-in - reaches the upstream with no
/// `X-Forwarded-User`, whatever the client or the settings put under that name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x_forwarded_user_of_a_request_of_nobody_is_not_sent() {
    my_tls::install_default_crypto_providers();

    let endpoints = [
        Endpoint::Http,
        Endpoint::Https,
        Endpoint::Http2,
        Endpoint::Https2OverH2,
        Endpoint::Https2OverHttp1,
    ];

    let mut seen = Vec::new();

    for endpoint in endpoints {
        let sent = forwarded_user_probe(endpoint, "", "", &[], None).await;
        println!("  {:<24} {sent:?}", endpoint.column());
        seen.push((endpoint, sent));
    }

    assert_eq!(
        seen,
        endpoints.map(|endpoint| (endpoint, Vec::new())).to_vec()
    );
}

/// On an endpoint with `google_auth` the header is the email of the request's sign-in - the only
/// one, whatever the client or the settings put under that name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x_forwarded_user_is_the_email_of_a_google_sign_in() {
    my_tls::install_default_crypto_providers();

    const EMAIL: &str = "someone@example.com";

    let cookie = format!(
        "{}={}",
        crate::consts::AUTHORIZED_COOKIE_NAME,
        crate::google_auth::token::generate(EMAIL)
    );

    let endpoints = [
        Endpoint::Https,
        Endpoint::Https2OverH2,
        Endpoint::Https2OverHttp1,
    ];

    let mut seen = Vec::new();

    for endpoint in endpoints {
        let id = unique_id("forwarded_user");

        let sent = forwarded_user_probe(
            endpoint,
            &format!("      google_auth: {id}_g_auth\n"),
            &format!(
                "g_auth:\n  {id}_g_auth:\n    client_id: test-client-id\n    client_secret: test-client-secret\n    whitelisted_domains: example.com\n"
            ),
            &[("cookie", cookie.as_str())],
            None,
        )
        .await;

        println!("  {:<24} {sent:?}", endpoint.column());
        seen.push((endpoint, sent));
    }

    let expected = vec![format!("x-forwarded-user: {EMAIL}")];

    assert_eq!(
        seen,
        endpoints
            .map(|endpoint| (endpoint, expected.clone()))
            .to_vec()
    );
}

/// On an endpoint with `client_certificate_ca` the header is the CN of the certificate its ca
/// verified - the only one, whatever the client or the settings put under that name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x_forwarded_user_is_the_cn_of_a_client_certificate() {
    my_tls::install_default_crypto_providers();

    const CN: &str = "forwarded-user-test-client";

    let certificate = ClientCertificate::issue(CN).await;

    let endpoints = [
        Endpoint::Https,
        Endpoint::Https2OverH2,
        Endpoint::Https2OverHttp1,
    ];

    let mut seen = Vec::new();

    for endpoint in endpoints {
        let sent = forwarded_user_probe(
            endpoint,
            &format!("      client_certificate_ca: {}\n", certificate.ca_id),
            &format!("client_certificate_ca:\n- id: {}\n", certificate.ca_id),
            &[],
            Some(&certificate),
        )
        .await;

        println!("  {:<24} {sent:?}", endpoint.column());
        seen.push((endpoint, sent));
    }

    let expected = vec![format!("x-forwarded-user: {CN}")];

    assert_eq!(
        seen,
        endpoints
            .map(|endpoint| (endpoint, expected.clone()))
            .to_vec()
    );
}

/// The h1 pipeline passes a head on as the client wrote it, so a client can spell the header in
/// ways a lenient upstream still reads as it: whitespace before the colon, a folded line, `_` for
/// `-`. None of them gets through. (hyper refuses such a head itself, so only this path is
/// probed.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn x_forwarded_user_spelled_to_slip_through_does_not_reach_the_upstream() {
    let upstream = Upstream::start().await;
    let port = free_port().await;

    apply_settings(&forwarded_user_yaml(
        Endpoint::Http,
        port,
        upstream.port,
        "",
        "",
    ))
    .await;
    serve(port);

    let mut stream = connect(port).await;
    let request = format!(
        "GET / HTTP/1.1\r\nHost: localhost:{port}\r\nX-Forwarded-User : spaced\r\nX-Forwarded-User\t: tabbed\r\nX-Other: kept\r\n X-Forwarded-User: folded\r\nX_Forwarded_User: underscored\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    let read_until_the_body = async {
        let mut buffer = [0u8; 4096];
        while !String::from_utf8_lossy(&response).contains(UPSTREAM_BODY) {
            let read = stream.read(&mut buffer).await.unwrap();
            if read == 0 {
                break;
            }
            response.extend_from_slice(&buffer[..read]);
        }
    };
    let _ = tokio::time::timeout(TIMEOUT, read_until_the_body).await;

    let response = String::from_utf8_lossy(&response).to_string();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");

    let requests = upstream.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");

    for spelling in ["spaced", "tabbed", "folded", "underscored"] {
        assert!(!requests[0].contains(spelling), "{}", requests[0]);
    }
    assert_eq!(forwarded_user_lines(&requests[0]), Vec::<String>::new());
    assert!(requests[0].contains("x-other: kept"), "{}", requests[0]);
}

/// An endpoint of `endpoint`'s type in front of the upstream, with `endpoint_lines` added to it,
/// whose location tries to set `X-Forwarded-User` from the settings; `sections` go after `hosts`.
fn forwarded_user_yaml(
    endpoint: Endpoint,
    port: u16,
    upstream_port: u16,
    endpoint_lines: &str,
    sections: &str,
) -> String {
    format!(
        "hosts:\n  localhost:{port}:\n    endpoint:\n      type: {endpoint_type}\n{endpoint_lines}    locations:\n    - proxy_pass_to: http://127.0.0.1:{upstream_port}\n      modify_http_headers:\n        add:\n          request:\n          - name: X-Forwarded-User\n            value: forged-by-the-settings\n{sections}",
        endpoint_type = endpoint.type_name(),
    )
}

/// One request to an endpoint set up by [`forwarded_user_yaml`]: `headers` and
/// [`FORGED_BY_THE_CLIENT`] in it, `certificate` presented in the TLS handshake. Returns the
/// `X-Forwarded-User` headers the upstream got.
async fn forwarded_user_probe(
    endpoint: Endpoint,
    endpoint_lines: &str,
    sections: &str,
    headers: &[(&str, &str)],
    certificate: Option<&ClientCertificate>,
) -> Vec<String> {
    let upstream = Upstream::start().await;
    let port = free_port().await;

    let yaml = forwarded_user_yaml(endpoint, port, upstream.port, endpoint_lines, sections);

    apply_settings(&yaml).await;
    serve(port);

    let mut headers = headers.to_vec();
    headers.extend_from_slice(FORGED_BY_THE_CLIENT);

    let reply = send_with_certificate(
        endpoint.client(),
        port,
        "localhost",
        &format!("localhost:{port}"),
        &headers,
        certificate,
    )
    .await;

    let outcome = Outcome::new(reply, &upstream).await;
    assert!(outcome.served(), "{endpoint:?}: {outcome:#?}\n{yaml}");

    forwarded_user_lines(&outcome.upstream_requests[0])
}

/// The lines of an upstream request's head which an upstream could read as `X-Forwarded-User`.
fn forwarded_user_lines(upstream_request: &str) -> Vec<String> {
    upstream_request
        .lines()
        .skip(1)
        .filter(|line| {
            line.starts_with("x-forwarded-user:") || line.starts_with("x_forwarded_user:")
        })
        .map(str::to_string)
        .collect()
}

/// A client-certificate ca made for one test - loaded into the proxy under an id of its own,
/// since the certificate cache is shared by every test - and a certificate it issued.
struct ClientCertificate {
    ca_id: String,
    cert: CertificateDer<'static>,
    key: Vec<u8>,
}

impl ClientCertificate {
    async fn issue(cn: &str) -> Self {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
            KeyPair, KeyUsagePurpose,
        };

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "location tests ca");
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);

        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, cn);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let cert = params.signed_by(&key, &issuer).unwrap();

        let ca_id = unique_id("location_tests_ca");

        let ca = Arc::new(
            crate::tcp_listener::https::ClientCertificateCa::new(
                vec![ca_cert.der().clone()],
                None,
                vec![],
                None,
            )
            .unwrap(),
        );

        let id = ca_id.clone();
        crate::app::APP_CTX
            .ssl_certificates_cache
            .write(move |cache| {
                cache.client_ca.insert(
                    crate::configurations::SslCertificateIdRef::new(id.as_str()),
                    ca,
                );
            })
            .await;

        Self {
            ca_id,
            cert: cert.der().clone(),
            key: key.serialize_der(),
        }
    }
}

/// "Example of serving redirect to the same url but with https schema" - under `hosts:`.
const README_REDIRECT_EXAMPLE: &str = "  7700:\n    endpoint:\n      type: http\n\n    locations:\n    - type: static\n      status_code: 302\n      modify_http_headers:\n        add:\n          response:\n          - name: Location\n            value: https://${HOST_PORT}${PATH_AND_QUERY}\n";

/// The README's redirect example gives its `Location` through `modify_http_headers` of the
/// location, on a `type: http` endpoint - a static location, which answers itself. The 302 has
/// its `Location` there, and under `type: http2` as well.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn readme_redirect_example_redirects() {
    assert!(readme().contains(README_REDIRECT_EXAMPLE));

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

    let authorization = [("x-api-key", LOCATION_TOKEN)];
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
    let mut country_white_lists = String::new();
    let mut sections = String::new();

    if let Some(list) = setup.location_list {
        location_lines.push_str(&format!("      whitelisted_ip: {location_list_id}\n"));
        ip_white_lists.push_str(&format!("  {location_list_id}:{}", yaml_list_value(list)));

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
        ip_white_lists.push_str(&format!("  {endpoint_list_id}:{}", yaml_list_value(list)));
    }

    if setup.endpoint_list_is_not_declared {
        endpoint_lines.push_str(&format!("      whitelisted_ip: {endpoint_list_id}\n"));
    }

    if let Some(countries) = setup.location_countries {
        let list_id = format!("{id}_location_countries");
        location_lines.push_str(&format!("      whitelisted_country: {list_id}\n"));
        country_white_lists.push_str(&format!("  {list_id}:{}", yaml_list_value(countries)));
    }

    if setup.location_countries_are_not_declared {
        location_lines.push_str(&format!("      whitelisted_country: {id}_location_countries\n"));
    }

    if let Some(countries) = setup.endpoint_countries {
        let list_id = format!("{id}_endpoint_countries");
        endpoint_lines.push_str(&format!("      whitelisted_country: {list_id}\n"));
        country_white_lists.push_str(&format!("  {list_id}:{}", yaml_list_value(countries)));
    }

    if setup.endpoint_countries_are_not_declared {
        endpoint_lines.push_str(&format!("      whitelisted_country: {id}_endpoint_countries\n"));
    }

    if setup.location_api_keys_auth {
        location_lines.push_str(&format!("      api_keys_auth: {id}_keys\n"));
        sections.push_str(&format!(
            "api_keys:\n  {id}_keys:\n  - \"{LOCATION_TOKEN}\"\n"
        ));
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

    if !country_white_lists.is_empty() {
        sections.push_str(&format!("country_white_lists:\n{country_white_lists}"));
    }

    format!(
        "hosts:\n  localhost:{port}:\n    endpoint:\n      type: {endpoint_type}\n{endpoint_lines}    locations:\n    - proxy_pass_to: {proxy_pass_to}\n{location_lines}{other_hosts}{sections}",
        endpoint_type = endpoint.type_name(),
    )
}

/// The value of a key holding the list: on the lines after the key - or `[]` on its line, when
/// there are no items (a key with nothing under it is `null`, not a list).
fn yaml_list_value(items: &[&str]) -> String {
    if items.is_empty() {
        " []\n".to_string()
    } else {
        format!("\n{}", yaml_list(items))
    }
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
/// the same port got from the hosts of these settings before it - and the port configurations
/// are published into the live configuration, where the accept loop looks its port up. A port
/// is replaced as a whole, as the flow does.
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

    // The flow publishes the keys of the settings; here they are added next to the ones of the
    // other tests, under ids of their own.
    for (keys_id, keys) in model.api_keys.iter().flatten() {
        let keys: Vec<&str> = keys.iter().map(|key| key.as_str()).collect();
        crate::app::APP_CTX.api_keys.add_for_tests(keys_id, &keys);
    }

    let settings = SettingsCompiled {
        hosts: model.hosts,
        ip_white_lists: model.ip_white_lists.unwrap_or_default(),
        country_white_lists: model.country_white_lists.unwrap_or_default(),
        allowed_users: model.allowed_users.unwrap_or_default(),
        g_auth: model.g_auth.unwrap_or_default(),
        client_certificate_ca: model.client_certificate_ca.unwrap_or_default(),
        ..Default::default()
    };

    // Each port as these settings make it - not merged into what the live configuration has on
    // it: the tests share that configuration, and what another test put there for a port it was
    // handed stays there after that test.
    let mut ports: std::collections::HashMap<u16, crate::configurations::ListenConfiguration> =
        std::collections::HashMap::new();

    for (host_id, host_settings) in &settings.hosts {
        let endpoint_host = settings.get_endpoint_host_string(host_id).unwrap();

        let EndpointPort::Tcp(port) = endpoint_host.get_port() else {
            panic!("{host_id} is not a tcp port");
        };

        let configuration = crate::scripts::compile_host_configuration(
            &settings,
            endpoint_host,
            host_settings,
            ports.remove(&port),
        )
        .await
        .map_err(|err| format!("host {host_id} does not compile: {err}"))?;

        ports.insert(port, configuration);
    }

    crate::app::APP_CTX
        .current_configuration
        .write(move |config| {
            for (port, configuration) in ports {
                config.listen_tcp_endpoints.insert(port, configuration);
            }
        })
        .await;

    Ok(())
}

/// The accept loop the proxy runs for a tcp port. `sync_endpoints` starts it on 0.0.0.0; here it
/// is on the loopback.
fn serve(port: u16) {
    super::start_listen_tcp_server(SocketAddr::from(([127, 0, 0, 1], port)));
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
    send_with_certificate(client, port, server_name, host, headers, None).await
}

/// [`send`], presenting `certificate` in the TLS handshake.
async fn send_with_certificate(
    client: Client,
    port: u16,
    server_name: &str,
    host: &str,
    headers: &[(&str, &str)],
    certificate: Option<&ClientCertificate>,
) -> Reply {
    match client {
        Client::PlainHttp1 => get_over_http1(connect(port).await, host, headers).await,
        Client::PlainH2 => get_over_h2(connect(port).await, "http", host, headers).await,
        Client::TlsHttp1 => match connect_tls(port, server_name, b"http/1.1", certificate).await {
            Ok(stream) => get_over_http1(stream, host, headers).await,
            Err(err) => Reply::none(err),
        },
        Client::TlsH2 => match connect_tls(port, server_name, b"h2", certificate).await {
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
    certificate: Option<&ClientCertificate>,
) -> Result<TlsStream<TcpStream>, String> {
    let builder = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert));

    let mut client_config = match certificate {
        Some(certificate) => builder
            .with_client_auth_cert(
                vec![certificate.cert.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certificate.key.clone())),
            )
            .unwrap(),
        None => builder.with_no_client_auth(),
    };
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

// ---------------------------------------------------------------------------------------------
// Who the client is: `X-Forwarded-For`, and `cloudflare: true`
// ---------------------------------------------------------------------------------------------

/// The endpoint types which read the request: the ones `cloudflare: true` is served on.
const HTTP_ENDPOINTS: [Endpoint; 5] = [
    Endpoint::Http,
    Endpoint::Https,
    Endpoint::Http2,
    Endpoint::Https2OverH2,
    Endpoint::Https2OverHttp1,
];

/// What a client sends to pass itself off as another address - and the spelling of the first a
/// CGI-style server reads as the same `HTTP_X_FORWARDED_FOR`.
const CLIENT_IP_FORGED: &[(&str, &str)] = &[
    ("x-forwarded-for", "8.8.8.8"),
    ("x_forwarded_for", "8.8.8.8"),
    ("x-real-ip", "8.8.8.8"),
    ("true-client-ip", "8.8.8.8"),
];

/// An endpoint of `endpoint`'s type in front of the upstream, with `endpoint_lines` added to it,
/// whose location tells the upstream `${ENDPOINT_IP}` in `X-Client`; `sections` go after `hosts`.
fn client_ip_yaml(
    endpoint: Endpoint,
    port: u16,
    upstream_port: u16,
    endpoint_lines: &str,
    sections: &str,
) -> String {
    format!(
        "hosts:\n  localhost:{port}:\n    endpoint:\n      type: {endpoint_type}\n{endpoint_lines}    locations:\n    - proxy_pass_to: http://127.0.0.1:{upstream_port}\n      modify_http_headers:\n        add:\n          request:\n          - name: X-Client\n            value: ${{ENDPOINT_IP}}\n{sections}",
        endpoint_type = endpoint.type_name(),
    )
}

/// One request with `headers` to an endpoint set up by [`client_ip_yaml`].
async fn client_ip_probe(
    endpoint: Endpoint,
    endpoint_lines: &str,
    sections: &str,
    headers: &[(&str, &str)],
) -> Outcome {
    let upstream = Upstream::start().await;
    let port = free_port().await;

    let yaml = client_ip_yaml(endpoint, port, upstream.port, endpoint_lines, sections);

    apply_settings(&yaml).await;
    serve(port);

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

/// The lines of an upstream request's head which tell who the client is, sorted.
fn client_ip_lines(upstream_request: &str) -> Vec<String> {
    const NAMES: [&str; 8] = [
        "x-forwarded-for:",
        "x_forwarded_for:",
        "x-real-ip:",
        "true-client-ip:",
        "cf-connecting-ip:",
        "cf_connecting_ip:",
        "cf-ipcountry:",
        "x-client:",
    ];

    let mut lines: Vec<String> = upstream_request
        .lines()
        .skip(1)
        .filter(|line| NAMES.iter().any(|name| line.starts_with(name)))
        .map(str::to_string)
        .collect();

    lines.sort();
    lines
}

/// Without `cloudflare: true` the client is the peer of the connection. The upstream is told its
/// address alone - in `X-Forwarded-For` and in `${ENDPOINT_IP}` - and nothing the client sent to
/// say otherwise, Cloudflare's headers included.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_the_flag_the_upstream_is_told_the_peer_alone() {
    my_tls::install_default_crypto_providers();

    let mut headers = CLIENT_IP_FORGED.to_vec();
    headers.extend_from_slice(&[("cf-connecting-ip", "8.8.8.8"), ("cf-ipcountry", "XX")]);

    for endpoint in HTTP_ENDPOINTS {
        let outcome = client_ip_probe(endpoint, "", "", &headers).await;
        assert!(outcome.served(), "{endpoint:?}: {outcome:#?}");

        assert_eq!(
            client_ip_lines(&outcome.upstream_requests[0]),
            vec!["x-client: 127.0.0.1", "x-forwarded-for: 127.0.0.1"],
            "{endpoint:?}: {}",
            outcome.upstream_requests[0]
        );
    }
}

/// Through Cloudflare to a `cloudflare: true` endpoint the client is the address of
/// `CF-Connecting-IP`: `X-Forwarded-For` is the client, then the Cloudflare server it came
/// through, and `${ENDPOINT_IP}` is the client. What Cloudflare wrote goes on; what the client
/// forged does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn through_cloudflare_the_client_is_of_cf_connecting_ip() {
    my_tls::install_default_crypto_providers();
    crate::cloudflare::the_loopback_is_cloudflare_in_tests();

    let mut headers = CLIENT_IP_FORGED.to_vec();
    headers.extend_from_slice(&[("cf-connecting-ip", "198.51.100.4"), ("cf-ipcountry", "UA")]);

    for endpoint in HTTP_ENDPOINTS {
        let outcome = client_ip_probe(endpoint, "      cloudflare: true\n", "", &headers).await;
        assert!(outcome.served(), "{endpoint:?}: {outcome:#?}");

        assert_eq!(
            client_ip_lines(&outcome.upstream_requests[0]),
            vec![
                "cf-connecting-ip: 198.51.100.4",
                "cf-ipcountry: UA",
                "x-client: 198.51.100.4",
                "x-forwarded-for: 198.51.100.4, 127.0.0.1",
            ],
            "{endpoint:?}: {}",
            outcome.upstream_requests[0]
        );
    }
}

/// A request from Cloudflare without one `CF-Connecting-IP` which is an address can only be one
/// made to get around Cloudflare: the connection is closed without a word, and the upstream sees
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cloudflare_endpoint_closes_the_connection_without_a_word() {
    my_tls::install_default_crypto_providers();
    crate::cloudflare::the_loopback_is_cloudflare_in_tests();

    let cases: [(&str, &[(&str, &str)]); 4] = [
        ("no CF-Connecting-IP", &[]),
        (
            "two CF-Connecting-IP",
            &[
                ("cf-connecting-ip", "198.51.100.4"),
                ("cf-connecting-ip", "198.51.100.5"),
            ],
        ),
        (
            "a list in CF-Connecting-IP",
            &[("cf-connecting-ip", "198.51.100.4, 8.8.8.8")],
        ),
        (
            "a second one spelled with _",
            &[
                ("cf-connecting-ip", "198.51.100.4"),
                ("cf_connecting_ip", "8.8.8.8"),
            ],
        ),
    ];

    for (case, headers) in cases {
        for endpoint in HTTP_ENDPOINTS {
            let outcome = client_ip_probe(endpoint, "      cloudflare: true\n", "", headers).await;

            assert!(
                outcome.status.is_none() && outcome.upstream_requests.is_empty(),
                "{case}, {endpoint:?}: {outcome:#?}"
            );
        }
    }
}

/// The allow-lists of a `cloudflare: true` endpoint are of the client of `CF-Connecting-IP`, not
/// of the Cloudflare server the request came through.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_allow_list_of_a_cloudflare_endpoint_is_of_cf_connecting_ip() {
    my_tls::install_default_crypto_providers();
    crate::cloudflare::the_loopback_is_cloudflare_in_tests();

    for endpoint in HTTP_ENDPOINTS {
        let list_id = unique_id("cloudflare");
        let endpoint_lines = format!("      cloudflare: true\n      whitelisted_ip: {list_id}\n");
        let sections = format!("ip_white_lists:\n  {list_id}:\n    - \"198.51.100.4\"\n");

        let listed = client_ip_probe(
            endpoint,
            &endpoint_lines,
            &sections,
            &[("cf-connecting-ip", "198.51.100.4")],
        )
        .await;
        assert!(listed.served(), "{endpoint:?}: {listed:#?}");

        let not_listed = client_ip_probe(
            endpoint,
            &endpoint_lines,
            &sections,
            &[("cf-connecting-ip", "198.51.100.5")],
        )
        .await;
        assert!(
            not_listed.refused() && not_listed.status.is_some(),
            "{endpoint:?}: {not_listed:#?}"
        );
    }
}

/// A connection which is not from Cloudflare is closed without a word, whatever it sends: on a
/// plain connection by its request, on a TLS one right after the handshake. The loopback is
/// Cloudflare in the tests, so the stranger connects over `::1` - where there is no IPv6 loopback,
/// there is nothing to probe.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cloudflare_endpoint_takes_no_connection_from_elsewhere() {
    my_tls::install_default_crypto_providers();
    crate::cloudflare::the_loopback_is_cloudflare_in_tests();

    if std::net::TcpListener::bind("[::1]:0").is_err() {
        println!("no IPv6 loopback here - nothing to probe");
        return;
    }

    for endpoint in [Endpoint::Http, Endpoint::Https] {
        let upstream = Upstream::start().await;
        let port = free_port().await;

        apply_settings(&client_ip_yaml(
            endpoint,
            port,
            upstream.port,
            "      cloudflare: true\n",
            "",
        ))
        .await;
        super::start_listen_tcp_server(SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)));

        let mut stream = None;
        for _ in 0..500 {
            if let Ok(connected) = TcpStream::connect(("::1", port)).await {
                stream = Some(connected);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let stream = stream.expect("nothing listens on [::1]");

        let request = format!(
            "GET / HTTP/1.1\r\nHost: localhost:{port}\r\nCF-Connecting-IP: 198.51.100.4\r\n\r\n"
        );

        let answer = match endpoint {
            Endpoint::Http => read_answer(stream, request.as_bytes()).await,
            _ => {
                let mut client_config = rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
                    .with_no_client_auth();
                client_config.alpn_protocols = vec![b"http/1.1".to_vec()];

                match TlsConnector::from(Arc::new(client_config))
                    .connect(ServerName::try_from("localhost").unwrap(), stream)
                    .await
                {
                    Ok(tls_stream) => read_answer(tls_stream, request.as_bytes()).await,
                    // Closed before the handshake was over: no answer either.
                    Err(_) => Vec::new(),
                }
            }
        };

        assert!(
            answer.is_empty(),
            "{endpoint:?} answered: {}",
            String::from_utf8_lossy(&answer)
        );
        assert!(upstream.requests().is_empty(), "{endpoint:?}");
    }
}

/// Writes `request` and reads what comes back until the connection is closed.
async fn read_answer<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, request: &[u8]) -> Vec<u8> {
    let _ = stream.write_all(request).await;

    let mut answer = Vec::new();
    let _ = tokio::time::timeout(TIMEOUT, stream.read_to_end(&mut answer)).await;
    answer
}

/// An endpoint which reads no HTTP - a byte bridge - can not read `CF-Connecting-IP`: with
/// `cloudflare: true` it serves nobody, rather than check its allow-lists against Cloudflare.
#[tokio::test]
async fn a_byte_bridge_with_the_flag_serves_nobody() {
    for endpoint in [Endpoint::Mcp, Endpoint::Tcp] {
        let port = free_port().await;
        let yaml = format!(
            "hosts:\n  localhost:{port}:\n    endpoint:\n      type: {}\n      cloudflare: true\n    locations:\n    - proxy_pass_to: {}\n",
            endpoint.type_name(),
            endpoint.proxy_pass_to(9),
        );

        apply_settings(&yaml).await;

        let reason = crate::app::APP_CTX
            .current_configuration
            .get(|config| match config.listen_tcp_endpoints.get(&port) {
                Some(crate::configurations::ListenConfiguration::Mcp(config)) => config.endpoints
                    [0]
                .not_served_reason
                .as_ref()
                .map(|reason| reason.as_str().to_string()),
                Some(crate::configurations::ListenConfiguration::Tcp(config)) => config
                    .not_served_reason
                    .as_ref()
                    .map(|reason| reason.as_str().to_string()),
                _ => None,
            })
            .await;

        let reason = reason.unwrap_or_else(|| panic!("{endpoint:?} is served\n{yaml}"));
        assert!(reason.contains("'cloudflare'"), "{endpoint:?}: {reason}");
    }
}

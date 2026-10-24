//! Files locations end to end, through the entries the tcp listener uses. An `http` endpoint is
//! served by the h1 pipeline (`kick_h1_tcp_reverse_proxy_server_from_http`) and an `http2`
//! endpoint by hyper (`http2::handle_connection`); `https` and `https2` are the same two behind
//! TLS (`https::handle_connection`). The configuration is compiled from settings the same way a
//! settings file is.
//!
//! The HTTP/1.1 client is a socket written to by hand: what a test sends is what gets to the
//! wire, a `..` in the path included.

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::http2::SendRequest;
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
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::{
    app::APP_CTX,
    configurations::{EndpointHttpHostString, ListenHttpEndpointType},
    http_content_source::test_utils::*,
    settings::HostSettings,
    settings_compiled::SettingsCompiled,
};

const TIMEOUT: Duration = Duration::from_secs(5);

/// Paths which leave the folder, each in a spelling of its own. A NUL does not leave it, and is
/// refused with them.
const OUT_OF_THE_FOLDER: [&str; 10] = [
    "/../secret.txt",
    "/css/../../secret.txt",
    "/%2e%2e/secret.txt",
    "/%2E%2E/secret.txt",
    "/.%2e/secret.txt",
    "/..%2fsecret.txt",
    "/..%5csecret.txt",
    "/..\\secret.txt",
    "/../secret.txt?v=1",
    "/a%00.html",
];

#[tokio::test]
async fn http_the_query_string_is_not_a_part_of_the_file_name() {
    let site = TestSite::new();
    let endpoint = start_endpoint(ListenHttpEndpointType::Http1, "", &site.root()).await;
    let mut client = H1Client::connect(endpoint.port).await;

    let response = client.get("/index.html?v=1").await;
    assert_eq!(response.status, 200);
    assert!(response.head.contains("content-type: text/html\r\n"));
    assert_eq!(response.body, INDEX_HTML);

    // The root with a query string is the root: the default file.
    let response = client.get("/?utm=x").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, INDEX_HTML);

    // It is the path which is checked: a query string is nobody's file name.
    let response = client.get("/css/site.css?back=/../secret.txt").await;
    assert_eq!(response.status, 200);
    assert!(response.head.contains("content-type: text/css\r\n"));
    assert_eq!(response.body, SITE_CSS);

    let response = client.get("/missing.html?v=1").await;
    assert_eq!(response.status, 404);
}

#[tokio::test]
async fn http_a_path_out_of_the_folder_is_refused_and_the_connection_goes_on() {
    let site = TestSite::new();
    let endpoint = start_endpoint(ListenHttpEndpointType::Http1, "", &site.root()).await;
    let mut client = H1Client::connect(endpoint.port).await;

    // What the folder glued to the path as it is would serve.
    assert_eq!(
        std::fs::read(format!("{}/../secret.txt", site.root())).unwrap(),
        SECRET
    );

    for target in OUT_OF_THE_FOLDER {
        let response = client.get(target).await;
        assert_eq!(response.status, 400, "{target}");
        assert!(
            response.head.starts_with("HTTP/1.1 400 Bad Request\r\n"),
            "{target}: {}",
            response.head
        );
        assert!(!contains(&response.body, SECRET), "{target}");

        // An answer like any other: the next request on the connection is served.
        let response = client.get("/index.html").await;
        assert_eq!(response.status, 200, "after {target}");
        assert_eq!(response.body, INDEX_HTML, "after {target}");
    }

    // Nor is it a failure of the location: nothing of it is in the location log.
    assert!(APP_CTX
        .proxy_logs
        .get_by_location(endpoint.location_id)
        .is_empty());
}

/// The body of each request here is a request itself. Left on the connection, it would be
/// answered - with the css - in place of the request which comes next.
#[tokio::test]
async fn http_a_request_body_is_drained_whatever_the_answer_is() {
    let site = TestSite::new();
    let endpoint = start_endpoint(ListenHttpEndpointType::Http1, "", &site.root()).await;
    let mut client = H1Client::connect(endpoint.port).await;

    let body = b"GET /css/site.css HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let with_length = format!("Content-Length: {}\r\n", body.len());
    let chunked = {
        let (first, second) = body.split_at(10);
        let mut chunked = format!("{:x}\r\n", first.len()).into_bytes();
        chunked.extend_from_slice(first);
        chunked.extend_from_slice(format!("\r\n{:x}\r\n", second.len()).as_bytes());
        chunked.extend_from_slice(second);
        chunked.extend_from_slice(b"\r\n0\r\n\r\n");
        chunked
    };

    // Only GET and HEAD are served: a POST is not found. A path out of the folder is refused
    // first.
    for (target, status) in [("/index.html", 404), ("/../secret.txt", 400)] {
        let response = client.request("POST", target, &with_length, body).await;
        assert_eq!(response.status, status, "{target}, a body with a length");

        let response = client.get("/index.html").await;
        assert_eq!(response.status, 200);
        assert_eq!(response.body, INDEX_HTML);

        let response = client
            .request("POST", target, "Transfer-Encoding: chunked\r\n", &chunked)
            .await;
        assert_eq!(response.status, status, "{target}, a chunked body");

        let response = client.get("/index.html").await;
        assert_eq!(response.status, 200);
        assert_eq!(response.body, INDEX_HTML);
    }
}

/// A body which can not be read to its end can not be taken off the connection: there is no
/// telling where the next request starts. The request is answered, and the connection is closed
/// behind the answer - by a files location and by a static one alike.
#[tokio::test]
async fn http_a_request_whose_body_can_not_be_read_is_answered_and_the_connection_is_closed() {
    let site = TestSite::new();
    let locations = format!(
        "- path: /static\n  type: static\n  status_code: 200\n  content_type: text/html\n  body: <b>static-body</b>\n- proxy_pass_to: '{root}'\n  default_file: index.html\n",
        root = site.root()
    );
    let endpoint = start_host(ListenHttpEndpointType::Http1, "", &locations).await;

    for (target, body) in [
        ("/index.html", INDEX_HTML),
        ("/static", &b"<b>static-body</b>"[..]),
    ] {
        // Ends short of its length: the client says 100 bytes, sends 5 and stops.
        let mut client = H1Client::connect(endpoint.port).await;
        let request = format!(
            "GET {target} HTTP/1.1\r\nHost: localhost:{}\r\nContent-Length: 100\r\n\r\nshort",
            endpoint.port
        );
        client.stream.write_all(request.as_bytes()).await.unwrap();
        client.stream.shutdown().await.unwrap();

        let response = client.read_response().await;
        assert_eq!(response.status, 200, "{target}, a body which ends short");
        assert_eq!(response.body, body, "{target}, a body which ends short");
        client.assert_closed().await;

        // A chunk with an extension is a chunk this proxy does not read. Whatever stands
        // behind the size line stays on the connection, and is not read as a request.
        let mut client = H1Client::connect(endpoint.port).await;
        let request = format!(
            "GET {target} HTTP/1.1\r\nHost: localhost:{port}\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n0\r\n\r\nGET /css/site.css HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n",
            port = endpoint.port
        );
        client.stream.write_all(request.as_bytes()).await.unwrap();

        let response = client.read_response().await;
        assert_eq!(response.status, 200, "{target}, a chunk with an extension");
        assert_eq!(response.body, body, "{target}, a chunk with an extension");
        client.assert_closed().await;
    }
}

/// A `HEAD` is answered with the head of the response the same `GET` gets, and no body: by a
/// files location, by a static one, and by the page of a file which is not there. A body behind
/// the head would be read by the client as the start of the next response.
#[tokio::test]
async fn http_a_head_request_is_answered_without_a_body() {
    let site = TestSite::new();
    let locations = format!(
        "- path: /static\n  type: static\n  status_code: 200\n  content_type: text/html\n  body: <b>static-body</b>\n- proxy_pass_to: '{root}'\n  default_file: index.html\n",
        root = site.root()
    );
    let endpoint = start_host(ListenHttpEndpointType::Http1, "", &locations).await;
    let mut client = H1Client::connect(endpoint.port).await;

    for (target, status) in [
        ("/index.html", 200),
        ("/", 200),
        ("/css/site.css", 200),
        ("/static", 200),
        ("/missing.html", 404),
        ("/../secret.txt", 400),
    ] {
        let get = client.get(target).await;
        assert_eq!(get.status, status, "GET {target}");

        let (head_status, content_length) = client.head(target).await;
        assert_eq!(head_status, status, "HEAD {target}");
        assert_eq!(content_length, get.body.len(), "HEAD {target}");

        // The next response starts where the head ended.
        let response = client.get("/css/site.css").await;
        assert_eq!(response.status, 200, "after HEAD {target}");
        assert_eq!(response.body, SITE_CSS, "after HEAD {target}");
    }
}

#[tokio::test]
async fn http_an_endpoint_which_does_not_keep_alive_closes_after_every_answer() {
    let site = TestSite::new();
    let endpoint = start_endpoint(
        ListenHttpEndpointType::Http1,
        "  keep_alive: false\n",
        &site.root(),
    )
    .await;

    for (target, status) in [("/index.html", 200), ("/../secret.txt", 400)] {
        let mut client = H1Client::connect(endpoint.port).await;

        let response = client.get(target).await;
        assert_eq!(response.status, status, "{target}");

        client.assert_closed().await;
    }
}

/// More refused requests in a row than the block-list takes malformed ones before it blocks
/// their source: a refused path is not one of those.
#[tokio::test]
async fn http_refused_requests_are_not_counted_against_the_source_ip() {
    let site = TestSite::new();
    let endpoint = start_endpoint(ListenHttpEndpointType::Http1, "", &site.root()).await;
    let mut client = H1Client::connect(endpoint.port).await;

    let source_ip = client.stream.local_addr().unwrap().ip();

    for _ in 0..100 {
        let response = client.get("/../secret.txt").await;
        assert_eq!(response.status, 400);

        // Looked at after each one: every other connection the tests accept from this address
        // clears what the block-list has counted for it.
        assert!(!APP_CTX.ip_blocklist.is_blocked(&source_ip));
    }

    let response = client.get("/index.html").await;
    assert_eq!(response.status, 200);
}

/// No gateway is connected in the tests, so `gw` is one which can not be reached. The folder is
/// behind it all the same: the answer is not the 404 of a file missing in a local folder
/// named `gateway:gw->/srv/www`.
#[tokio::test]
async fn http_a_folder_behind_a_gateway_which_can_not_be_reached_is_a_503() {
    let endpoint = start_endpoint(ListenHttpEndpointType::Http1, "", "gateway:gw->/srv/www").await;
    let mut client = H1Client::connect(endpoint.port).await;

    let response = client.get("/index.html").await;
    assert_eq!(response.status, 503);

    // As every 5xx page the proxy returns, it is in the logs.
    let log = APP_CTX.proxy_logs.get_by_location(endpoint.location_id);
    assert_eq!(log.len(), 1);
    assert_eq!(
        log[0].message,
        "Returned 503 to client: upstream failure: can not get the file \"/index.html\": GatewayError"
    );

    // The path is checked before the gateway is asked, and the connection goes on after both.
    let response = client.get("/../secret.txt").await;
    assert_eq!(response.status, 400);

    let response = client.get("/index.html").await;
    assert_eq!(response.status, 503);
}

/// Nothing listens on the port of the ssh host. The folder is asked for there: the answer is
/// not the 404 of a file missing in a local folder.
#[tokio::test]
async fn http_a_folder_behind_ssh_which_can_not_be_reached_is_a_503() {
    let endpoint = start_endpoint(
        ListenHttpEndpointType::Http1,
        "",
        &format!("ssh:user@127.0.0.1:{}->~/web_content", closed_port().await),
    )
    .await;
    let mut client = H1Client::connect(endpoint.port).await;

    let response = client.get("/index.html").await;
    assert_eq!(response.status, 503);

    let log = APP_CTX.proxy_logs.get_by_location(endpoint.location_id);
    assert_eq!(log.len(), 1);
    assert!(
        log[0].message.starts_with(
            "Returned 503 to client: upstream failure: can not get the file \"/index.html\": SshSessionError("
        ),
        "{}",
        log[0].message
    );

    let response = client.get("/../secret.txt").await;
    assert_eq!(response.status, 400);
}

/// An `https` endpoint is the h1 pipeline behind TLS.
#[tokio::test]
async fn https_a_file_is_served_and_a_path_out_of_the_folder_is_refused() {
    let site = TestSite::new();
    let endpoint = start_endpoint(ListenHttpEndpointType::Https1, "", &site.root()).await;
    let mut client = H1Client::connect_tls(endpoint.port).await;

    assert_serves_the_folder_and_nothing_else(&mut client).await;

    let response = client.get("/../secret.txt").await;
    assert!(response.head.starts_with("HTTP/1.1 400 Bad Request\r\n"));
}

#[tokio::test]
async fn http2_a_file_is_served_and_a_path_out_of_the_folder_is_refused() {
    let site = TestSite::new();
    let endpoint = start_endpoint(ListenHttpEndpointType::Http2, "", &site.root()).await;
    let mut client = H2Client::connect(endpoint.port).await;

    assert_serves_the_folder_and_nothing_else_over_h2(&mut client).await;

    // A refused path is an answer, not a failure of the location: nothing is in its log.
    assert!(APP_CTX
        .proxy_logs
        .get_by_location(endpoint.location_id)
        .is_empty());
}

/// On this path a gateway which can not be reached is a 500 - the tech page of an error.
#[tokio::test]
async fn http2_a_folder_behind_a_gateway_which_can_not_be_reached_is_a_500() {
    let endpoint = start_endpoint(ListenHttpEndpointType::Http2, "", "gateway:gw->/srv/www").await;
    let mut client = H2Client::connect(endpoint.port).await;

    let response = client.get("/index.html").await;
    assert_eq!(response.status, 500);

    // The path is checked before the gateway is asked.
    let response = client.get("/../secret.txt").await;
    assert_eq!(response.status, 400);
}

#[tokio::test]
async fn http2_a_folder_behind_ssh_which_can_not_be_reached_is_a_500() {
    let endpoint = start_endpoint(
        ListenHttpEndpointType::Http2,
        "",
        &format!("ssh:user@127.0.0.1:{}->~/web_content", closed_port().await),
    )
    .await;
    let mut client = H2Client::connect(endpoint.port).await;

    let response = client.get("/index.html").await;
    assert_eq!(response.status, 500);

    let response = client.get("/../secret.txt").await;
    assert_eq!(response.status, 400);
}

#[tokio::test]
async fn https2_a_file_is_served_and_a_path_out_of_the_folder_is_refused() {
    let site = TestSite::new();
    let endpoint = start_endpoint(ListenHttpEndpointType::Https2, "", &site.root()).await;
    let mut client = H2Client::connect_tls(endpoint.port).await;

    assert_serves_the_folder_and_nothing_else_over_h2(&mut client).await;
}

/// An `https2` endpoint takes HTTP/1.1 too, and that is hyper as well: its HTTP/1.1 server
/// hands the path over as it came, the same as its h2 one.
#[tokio::test]
async fn https2_takes_an_http1_client_the_same_way() {
    let site = TestSite::new();
    let endpoint = start_endpoint(ListenHttpEndpointType::Https2, "", &site.root()).await;
    let mut client = H1Client::connect_tls(endpoint.port).await;

    assert_serves_the_folder_and_nothing_else(&mut client).await;

    let response = client.get("/../secret.txt").await;
    assert_eq!(response.body, b"Bad Request");
}

/// A folder which is empty in the settings - a variable which is not set - is not the root of
/// the file system: the location has no files.
#[tokio::test]
async fn an_empty_folder_serves_nothing_on_either_path() {
    // What a request would read with its path taken for the whole name of the file. Windows
    // has no /etc/hosts.
    #[cfg(unix)]
    assert!(std::fs::read("/etc/hosts").is_ok());

    let endpoint = start_endpoint(ListenHttpEndpointType::Http1, "", "").await;
    let mut client = H1Client::connect(endpoint.port).await;

    for target in ["/etc/hosts", "/"] {
        let response = client.get(target).await;
        assert_eq!(response.status, 404, "{target}");
    }

    let endpoint = start_endpoint(ListenHttpEndpointType::Http2, "", "").await;
    let mut client = H2Client::connect(endpoint.port).await;

    for target in ["/etc/hosts", "/"] {
        let response = client.get(target).await;
        assert_eq!(response.status, 404, "{target}");
    }
}

/// What a files location answers an HTTP/1.1 client, whichever of the two paths serves it.
/// A location is picked by the path of a request as it is written, and to the file system
/// `//css/site.css` and `/./css/site.css` are the file `/css/site.css`. Were they served, a
/// file would be read past the location which guards it - through the next location over the
/// same folder. A file has one path: the other spellings are refused, on both paths of the
/// proxy.
#[tokio::test]
async fn a_file_is_not_served_past_the_location_which_guards_it() {
    /// The guarded file in spellings which miss the guarded location.
    const PAST_THE_GUARD: [&str; 4] = [
        "//css/site.css",
        "/./css/site.css",
        "///css/site.css",
        "/.//css/site.css",
    ];

    let site = TestSite::new();

    // The folder of the guarded location is the folder of the open one: the file is a file of
    // both.
    let locations = format!(
        "- path: /css\n  proxy_pass_to: '{root}'\n  auth_header: 'Bearer secret'\n- proxy_pass_to: '{root}'\n  default_file: index.html\n",
        root = site.root()
    );

    // Every request on a connection of its own: a refusal of the guard closes it.
    let endpoint = start_host(ListenHttpEndpointType::Http1, "", &locations).await;

    for (target, status) in [
        ("/css/site.css", 401),
        // An empty segment is refused before a location is looked for, under the guard as
        // anywhere else.
        ("/css//site.css", 400),
        ("/index.html", 200),
    ] {
        let mut client = H1Client::connect(endpoint.port).await;
        assert_eq!(client.get(target).await.status, status, "{target}");
    }

    for target in PAST_THE_GUARD {
        let mut client = H1Client::connect(endpoint.port).await;
        let response = client.get(target).await;
        assert_eq!(response.status, 400, "{target}");
        assert!(!contains(&response.body, SITE_CSS), "{target}");
    }

    let endpoint = start_host(ListenHttpEndpointType::Http2, "", &locations).await;
    let mut client = H2Client::connect(endpoint.port).await;

    assert_eq!(client.get("/css/site.css").await.status, 401);
    assert_eq!(client.get("/css//site.css").await.status, 400);
    assert_eq!(client.get("/index.html").await.status, 200);

    for target in PAST_THE_GUARD {
        let response = client.get(target).await;
        assert_eq!(response.status, 400, "{target}");
        assert!(!contains(&response.body, SITE_CSS), "{target}");
    }
}

/// With `strip_path` a folder is served under a prefix: the request path without the path of the
/// location is the path of the file in the folder, and the root of the prefix is the default
/// file - on both paths of the proxy, and for a client of either version on hyper.
/// `${PATH_AND_QUERY}` in a header of the answer is still the path the client asked for.
#[tokio::test]
async fn a_folder_is_served_under_a_prefix_with_strip_path() {
    const SERVED: [(&str, &[u8]); 6] = [
        ("/static/css/site.css", SITE_CSS),
        ("/static/", INDEX_HTML),
        ("/static/?v=1", INDEX_HTML),
        ("/static/index.html?v=1", INDEX_HTML),
        ("/STATIC/css/site.css", SITE_CSS),
        ("/%73tatic/css/site.css", SITE_CSS),
    ];

    const NOT_SERVED: [(&str, u16); 4] = [
        ("/static/../secret.txt", 400),
        ("/static/%2e%2e/secret.txt", 400),
        // The prefix is cut once: there is no `static` in the folder.
        ("/static/static/css/site.css", 404),
        ("/static/missing.html", 404),
    ];

    let site = TestSite::new();
    let locations = format!(
        "- path: /static/\n  proxy_pass_to: '{root}'\n  default_file: index.html\n  strip_path: true\n  \
         modify_http_headers:\n    add:\n      response:\n      - name: x-client-path\n        value: ${{PATH_AND_QUERY}}\n",
        root = site.root()
    );

    let endpoint = start_host(ListenHttpEndpointType::Http1, "", &locations).await;
    let mut client = H1Client::connect(endpoint.port).await;

    for (target, body) in SERVED {
        let response = client.get(target).await;
        assert_eq!(response.status, 200, "{target}");
        assert_eq!(response.body, body, "{target}");
        assert!(
            response
                .head
                .contains(&format!("x-client-path: {target}\r\n")),
            "{target}: {}",
            response.head
        );
    }

    for (target, status) in NOT_SERVED {
        assert_eq!(client.get(target).await.status, status, "{target}");
    }

    let endpoint = start_host(ListenHttpEndpointType::Http2, "", &locations).await;
    let mut client = H2Client::connect(endpoint.port).await;

    for (target, body) in SERVED {
        let response = client.get(target).await;
        assert_eq!(response.status, 200, "{target}");
        assert_eq!(response.body, body, "{target}");
        assert_eq!(
            response.headers.get("x-client-path").unwrap(),
            target,
            "{target}"
        );
    }

    for (target, status) in NOT_SERVED {
        assert_eq!(client.get(target).await.status, status, "{target}");
    }

    // An https2 endpoint takes an HTTP/1.1 client with hyper as well, whose uri is not an
    // absolute one.
    let endpoint = start_host(ListenHttpEndpointType::Https2, "", &locations).await;
    let mut client = H1Client::connect_tls(endpoint.port).await;

    for (target, body) in SERVED {
        let response = client.get(target).await;
        assert_eq!(response.status, 200, "{target}");
        assert_eq!(response.body, body, "{target}");
        assert!(
            response
                .head
                .contains(&format!("x-client-path: {target}\r\n")),
            "{target}: {}",
            response.head
        );
    }

    for (target, status) in NOT_SERVED {
        assert_eq!(client.get(target).await.status, status, "{target}");
    }
}

async fn assert_serves_the_folder_and_nothing_else<S>(client: &mut H1Client<S>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let response = client.get("/index.html?v=1").await;
    assert_eq!(response.status, 200);
    assert!(response.head.contains("content-type: text/html\r\n"));
    assert_eq!(response.body, INDEX_HTML);

    let response = client.get("/?utm=x").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, INDEX_HTML);

    let response = client.get("/missing.html").await;
    assert_eq!(response.status, 404);

    for target in OUT_OF_THE_FOLDER {
        let response = client.get(target).await;
        assert_eq!(response.status, 400, "{target}");
        assert!(!contains(&response.body, SECRET), "{target}");

        let response = client.get("/css/site.css").await;
        assert_eq!(response.status, 200, "after {target}");
        assert_eq!(response.body, SITE_CSS, "after {target}");
    }
}

async fn assert_serves_the_folder_and_nothing_else_over_h2(client: &mut H2Client) {
    let response = client.get("/index.html?v=1").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.content_type.as_deref(), Some("text/html"));
    assert_eq!(response.body, INDEX_HTML);

    let response = client.get("/?utm=x").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, INDEX_HTML);

    let response = client.get("/css/site.css").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.content_type.as_deref(), Some("text/css"));
    assert_eq!(response.body, SITE_CSS);

    let response = client.get("/missing.html").await;
    assert_eq!(response.status, 404);

    for target in OUT_OF_THE_FOLDER {
        let response = client.get(target).await;
        assert_eq!(response.status, 400, "{target}");
        assert_eq!(
            response.content_type.as_deref(),
            Some("text/plain; charset=utf-8"),
            "{target}"
        );
        assert_eq!(response.body, b"Bad Request", "{target}");
    }

    let response = client.get("/index.html").await;
    assert_eq!(response.status, 200);
}

/// The proxy under test: one endpoint on a free port, with a single files location.
struct Endpoint {
    port: u16,
    /// What the log of the location is kept under.
    location_id: i64,
}

/// `endpoint_settings`: more lines for the `endpoint` section, indented by two spaces.
/// `files_path`: the `proxy_pass_to` of the location.
async fn start_endpoint(
    endpoint_type: ListenHttpEndpointType,
    endpoint_settings: &str,
    files_path: &str,
) -> Endpoint {
    start_host(
        endpoint_type,
        endpoint_settings,
        &format!("- proxy_pass_to: '{files_path}'\n  default_file: index.html\n"),
    )
    .await
}

/// The proxy under test with the locations given, as they are written in a settings file.
async fn start_host(
    endpoint_type: ListenHttpEndpointType,
    endpoint_settings: &str,
    locations: &str,
) -> Endpoint {
    // What main() does before anything touches TLS.
    my_tls::install_default_crypto_providers();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listening_addr = listener.local_addr().unwrap();

    let host_settings: HostSettings = my_settings_reader::serde_yaml::from_str(&format!(
        "endpoint:\n  type: {}\n{}locations:\n{}",
        endpoint_type.as_str(),
        endpoint_settings,
        locations
    ))
    .unwrap();

    let host_endpoint =
        EndpointHttpHostString::new(format!("localhost:{}", listening_addr.port())).unwrap();

    let endpoint_info = crate::scripts::compile_http_configuration(
        &SettingsCompiled::default(),
        host_endpoint,
        &host_settings,
        endpoint_type,
    )
    .await
    .unwrap();

    let location_id = endpoint_info.locations[0].id;

    let configuration =
        Arc::new(crate::scripts::merge_http_into_existing(None, endpoint_info).unwrap());

    tokio::spawn(async move {
        let mut connection_id = 0;

        loop {
            let Ok((tcp_stream, client_addr)) = listener.accept().await else {
                return;
            };

            connection_id += 1;

            match endpoint_type {
                ListenHttpEndpointType::Http1 => {
                    crate::h1_proxy_server::kick_h1_tcp_reverse_proxy_server_from_http(
                        tcp_stream,
                        client_addr,
                        configuration.clone(),
                    );
                }
                ListenHttpEndpointType::Http2 => {
                    super::http2::handle_connection(
                        (tcp_stream, client_addr).into(),
                        listening_addr.into(),
                        configuration.clone(),
                    )
                    .await;
                }
                _ => {
                    super::https::handle_connection(
                        tcp_stream,
                        client_addr,
                        listening_addr,
                        configuration.clone(),
                        connection_id,
                    );
                }
            }
        }
    });

    Endpoint {
        port: listening_addr.port(),
        location_id,
    }
}

/// A port nothing listens on: a connection to it is refused at once.
async fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

struct H1Response {
    status: u16,
    head: String,
    body: Vec<u8>,
}

struct H1Client<S> {
    stream: S,
    port: u16,
    /// What was read past the end of the last response.
    received: Vec<u8>,
}

impl H1Client<TcpStream> {
    async fn connect(port: u16) -> Self {
        Self {
            stream: TcpStream::connect(("127.0.0.1", port)).await.unwrap(),
            port,
            received: Vec::new(),
        }
    }
}

impl H1Client<TlsStream<TcpStream>> {
    async fn connect_tls(port: u16) -> Self {
        Self {
            stream: connect_tls(port, b"http/1.1").await,
            port,
            received: Vec::new(),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> H1Client<S> {
    async fn get(&mut self, target: &str) -> H1Response {
        self.request("GET", target, "", b"").await
    }

    /// `headers`: more header lines, each one with its `\r\n`.
    async fn request(
        &mut self,
        method: &str,
        target: &str,
        headers: &str,
        body: &[u8],
    ) -> H1Response {
        let mut request = format!(
            "{method} {target} HTTP/1.1\r\nHost: localhost:{}\r\n{headers}\r\n",
            self.port
        )
        .into_bytes();
        request.extend_from_slice(body);

        self.stream.write_all(&request).await.unwrap();

        self.read_response().await
    }

    /// A `HEAD`: the status and the `content-length` of the response. Its head is all there
    /// is to it, so nothing behind the head is read.
    async fn head(&mut self, target: &str) -> (u16, usize) {
        let request = format!(
            "HEAD {target} HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
            self.port
        );
        self.stream.write_all(request.as_bytes()).await.unwrap();

        let head_end = loop {
            if let Some(end) = find(&self.received, b"\r\n\r\n") {
                break end + 4;
            }

            assert!(
                self.read_more().await > 0,
                "connection closed before the response head"
            );
        };

        let head = String::from_utf8(self.received[..head_end].to_vec()).unwrap();
        self.received.drain(..head_end);

        let content_length = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .unwrap_or_else(|| panic!("no content-length in: {}", head))
            .parse()
            .unwrap();

        (head[9..12].parse().unwrap(), content_length)
    }

    /// Every response of a files location has a `content-length`.
    async fn read_response(&mut self) -> H1Response {
        let head_end = loop {
            if let Some(end) = find(&self.received, b"\r\n\r\n") {
                break end + 4;
            }

            assert!(
                self.read_more().await > 0,
                "connection closed before the response head: {:?}",
                String::from_utf8_lossy(&self.received)
            );
        };

        let head = String::from_utf8(self.received[..head_end].to_vec()).unwrap();

        let content_length: usize = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .unwrap_or_else(|| panic!("no content-length in: {}", head))
            .parse()
            .unwrap();

        while self.received.len() < head_end + content_length {
            assert!(
                self.read_more().await > 0,
                "connection closed before the end of the response body"
            );
        }

        let body = self.received[head_end..head_end + content_length].to_vec();
        self.received.drain(..head_end + content_length);

        // `HTTP/1.1 200 OK`
        let status = head[9..12].parse().unwrap();

        H1Response { status, head, body }
    }

    async fn read_more(&mut self) -> usize {
        let mut buffer = [0u8; 4096];

        let read = tokio::time::timeout(TIMEOUT, self.stream.read(&mut buffer))
            .await
            .expect("no response in time")
            .unwrap();

        self.received.extend_from_slice(&buffer[..read]);

        read
    }

    /// The server closed the connection, and sent nothing before that.
    async fn assert_closed(&mut self) {
        let mut buffer = [0u8; 4096];

        let read = match tokio::time::timeout(TIMEOUT, self.stream.read(&mut buffer))
            .await
            .expect("the connection is still open")
        {
            Ok(read) => read,
            // A connection closed with bytes of the client unread is reset, and Windows reports
            // the reset instead of the end of the stream: it is closed all the same.
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) =>
            {
                0
            }
            Err(err) => panic!("{err}"),
        };

        self.received.extend_from_slice(&buffer[..read]);

        assert!(
            self.received.is_empty(),
            "received on a connection which was to be closed: {:?}",
            String::from_utf8_lossy(&self.received)
        );
    }
}

struct H2Response {
    status: u16,
    content_type: Option<String>,
    headers: hyper::HeaderMap,
    body: Vec<u8>,
}

struct H2Client {
    sender: SendRequest<Empty<Bytes>>,
    /// Scheme and authority of the endpoint: over h2 the uri of a request is an absolute one.
    origin: String,
}

impl H2Client {
    /// h2c: an `http2` endpoint has no TLS, and takes HTTP/2 by prior knowledge.
    async fn connect(port: u16) -> Self {
        let tcp_stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

        let (sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tcp_stream))
                .await
                .unwrap();
        tokio::spawn(connection);

        Self {
            sender,
            origin: format!("http://localhost:{port}"),
        }
    }

    async fn connect_tls(port: u16) -> Self {
        let tls_stream = connect_tls(port, b"h2").await;

        let (sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls_stream))
                .await
                .unwrap();
        tokio::spawn(connection);

        Self {
            sender,
            origin: format!("https://localhost:{port}"),
        }
    }

    async fn get(&mut self, target: &str) -> H2Response {
        let request = hyper::Request::builder()
            .uri(format!("{}{}", self.origin, target))
            .body(Empty::<Bytes>::new())
            .unwrap();

        let response = tokio::time::timeout(TIMEOUT, self.sender.send_request(request))
            .await
            .expect("no response in time")
            .unwrap();

        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .map(|value| value.to_str().unwrap().to_string());
        let headers = response.headers().clone();

        let body = tokio::time::timeout(TIMEOUT, response.into_body().collect())
            .await
            .expect("no response body in time")
            .unwrap()
            .to_bytes();

        H2Response {
            status,
            content_type,
            headers,
            body: body.to_vec(),
        }
    }
}

/// The one protocol the client offers is what gets negotiated: on an `https2` endpoint that
/// picks between hyper's HTTP/1.1 server and its h2 one.
async fn connect_tls(port: u16, alpn: &[u8]) -> TlsStream<TcpStream> {
    let mut client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    client_config.alpn_protocols = vec![alpn.to_vec()];

    let tcp_stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();

    let tls_stream = TlsConnector::from(Arc::new(client_config))
        .connect(ServerName::try_from("localhost").unwrap(), tcp_stream)
        .await
        .unwrap();

    assert_eq!(tls_stream.get_ref().1.alpn_protocol(), Some(alpn));

    tls_stream
}

/// The endpoint serves the proxy's self-signed certificate; what is under test is what happens
/// after the handshake, not the certificate.
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

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find(haystack, needle).is_some()
}

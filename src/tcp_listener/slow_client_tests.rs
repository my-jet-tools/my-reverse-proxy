//! Slow clients: a connection which never finishes what it has to send must not be held open.
//!
//! Every test goes through the real accept loop (`start_listen_tcp_server`) with endpoints
//! compiled from YAML - with the timeouts cut to [`SHORT`] - and talks to it over a raw socket:
//! - an http/1.1 head that never ends, or comes a byte at a time, is cut at
//!   `header_read_timeout`, and so is a keep-alive connection that sends no next request - but
//!   not while an answer is still on its way;
//! - a connection to a TLS port that sends nothing is cut at `tls_handshake_timeout`;
//! - an `https2` connection that sends no request is cut at `header_read_timeout`, and so is a
//!   connection to an `http` / `http2` port which sends nothing to tell its protocol by, or no
//!   request after it - counted from the connect;
//! - a body the proxy waits for whole is answered `408` once it stops coming (`read_timeout`),
//!   and `413` once it is larger than `max_buffered_request_body` - or says it is;
//! - `tcp` and `mcp` endpoints, which never read a head, are not cut by any of it.
//!
//! After each refusal an ordinary request on a new connection is served.

use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full, StreamBody};
use hyper_util::rt::TokioIo;
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

use crate::test_ports::free_port;
use crate::{
    configurations::EndpointPort, settings::SettingsModel, settings_compiled::SettingsCompiled,
};

/// The timeout under test, wherever it is set.
const SHORT: Duration = Duration::from_millis(1000);

/// A connection cut by a timeout of [`SHORT`] is closed no sooner than this...
const NOT_BEFORE: Duration = Duration::from_millis(700);

/// ...and no later than this.
const NOT_AFTER: Duration = Duration::from_millis(4000);

/// How long the upstream takes on `/slow`: longer than [`SHORT`].
const SLOW_ANSWER: Duration = Duration::from_millis(2000);

// ---------------------------------------------------------------------------------------------
// http/1.1 (the proxy's own pipeline): `http` endpoint
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn http_a_head_without_its_end_is_cut_at_the_header_timeout() {
    let site = Site::start("http", "      header_read_timeout: 1000\n").await;

    let mut client = site.connect().await;
    client
        .write_all(site.head_start("GET /").as_bytes())
        .await
        .unwrap();

    assert_closed_by_timeout(&mut client).await;

    site.assert_served_on_a_new_connection().await;
}

/// The slowloris case: every byte comes well within `read_timeout`, the head never ends.
#[tokio::test]
async fn http_a_head_sent_a_byte_at_a_time_is_cut_at_the_header_timeout() {
    let site = Site::start("http", "      header_read_timeout: 1000\n").await;

    let mut client = site.connect().await;
    client
        .write_all(site.head_start("GET /").as_bytes())
        .await
        .unwrap();

    let started = Instant::now();

    while started.elapsed() < NOT_AFTER {
        if client.write_all(b"x").await.is_err() {
            break;
        }

        let mut buffer = [0u8; 64];
        match tokio::time::timeout(Duration::from_millis(200), client.read(&mut buffer)).await {
            // Still waiting for the rest of the head.
            Err(_) => {}
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(_)) => panic!("an answer to a head that never ended"),
        }
    }

    let elapsed = started.elapsed();
    assert!(
        (NOT_BEFORE..NOT_AFTER).contains(&elapsed),
        "a head sent a byte at a time was held for {elapsed:?}"
    );

    site.assert_served_on_a_new_connection().await;
}

#[tokio::test]
async fn http_a_keep_alive_connection_with_no_next_request_is_closed_at_the_header_timeout() {
    let site = Site::start("http", "      header_read_timeout: 1000\n").await;

    let mut client = site.connect().await;
    assert_eq!(site.get(&mut client, "/").await, (200, "ok".to_string()));

    assert_closed_by_timeout(&mut client).await;
}

/// The wait for the next request starts when the answer to the last one is out: an answer slower
/// than the header timeout is delivered whole, and the connection goes on.
#[tokio::test]
async fn http_an_answer_slower_than_the_header_timeout_is_delivered_and_the_connection_goes_on() {
    let site = Site::start("http", "      header_read_timeout: 1000\n").await;

    let mut client = site.connect().await;
    assert_eq!(site.get(&mut client, "/slow").await, (200, "slow".to_string()));
    assert_eq!(site.get(&mut client, "/").await, (200, "ok".to_string()));
}

// ---------------------------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------------------------

/// Set in `global_settings`: the handshake is over before any endpoint is picked.
#[tokio::test]
async fn https_a_client_which_sends_nothing_is_cut_at_the_tls_handshake_timeout() {
    let site = Site::start_with_global("https", "", "  tls_handshake_timeout: 1000\n").await;

    let mut client = site.connect().await;
    assert_closed_by_timeout(&mut client).await;

    let mut client = site.connect_tls(b"http/1.1").await;
    assert_eq!(site.get(&mut client, "/").await, (200, "ok".to_string()));
}

#[tokio::test]
async fn https_a_head_without_its_end_is_cut_at_the_header_timeout() {
    let site = Site::start("https", "      header_read_timeout: 1000\n").await;

    let mut client = site.connect_tls(b"http/1.1").await;
    client
        .write_all(site.head_start("GET /").as_bytes())
        .await
        .unwrap();

    assert_closed_by_timeout(&mut client).await;

    let mut client = site.connect_tls(b"http/1.1").await;
    assert_eq!(site.get(&mut client, "/").await, (200, "ok".to_string()));
}

// ---------------------------------------------------------------------------------------------
// hyper: `https2` and `http2` endpoints
// ---------------------------------------------------------------------------------------------

/// The auto builder reads the opening bytes to tell h2 from http/1.1 - with no limit of its own.
#[tokio::test]
async fn https2_a_client_which_sends_nothing_after_the_handshake_is_cut() {
    let site = Site::start("https2", "      header_read_timeout: 1000\n").await;

    let mut client = site.connect_tls(b"h2").await;
    assert_closed_by_timeout(&mut client).await;

    let mut client = site.connect_tls(b"http/1.1").await;
    assert_eq!(site.get(&mut client, "/").await, (200, "ok".to_string()));
}

#[tokio::test]
async fn https2_an_http1_head_without_its_end_is_cut_at_the_header_timeout() {
    let site = Site::start("https2", "      header_read_timeout: 1000\n").await;

    let mut client = site.connect_tls(b"http/1.1").await;
    client
        .write_all(site.head_start("GET /").as_bytes())
        .await
        .unwrap();

    assert_closed_by_timeout(&mut client).await;

    let mut client = site.connect_tls(b"http/1.1").await;
    assert_eq!(site.get(&mut client, "/").await, (200, "ok".to_string()));
}

#[tokio::test]
async fn https2_an_http1_keep_alive_connection_with_no_next_request_is_closed() {
    let site = Site::start("https2", "      header_read_timeout: 1000\n").await;

    let mut client = site.connect_tls(b"http/1.1").await;
    assert_eq!(site.get(&mut client, "/").await, (200, "ok".to_string()));

    assert_closed_by_timeout(&mut client).await;
}

/// To an http/1.1 upstream the body is sent whole: the proxy waits for all of it, but no longer
/// than `read_timeout` of silence.
#[tokio::test]
async fn https2_a_body_that_stops_coming_is_answered_408() {
    let site = Site::start("https2", "      read_timeout: 1000\n").await;

    let mut client = site.connect_tls(b"http/1.1").await;
    let head = format!(
        "POST /echo HTTP/1.1\r\nHost: localhost:{}\r\ncontent-length: 10\r\n\r\nab",
        site.port
    );
    client.write_all(head.as_bytes()).await.unwrap();

    let started = Instant::now();
    let (status, _) = tokio::time::timeout(NOT_AFTER, read_response(&mut client))
        .await
        .expect("no answer to a body that stopped coming");
    let elapsed = started.elapsed();

    assert_eq!(status, 408);
    assert!(
        (NOT_BEFORE..NOT_AFTER).contains(&elapsed),
        "answered after {elapsed:?}"
    );

    let mut client = site.connect_tls(b"http/1.1").await;
    assert_eq!(site.get(&mut client, "/").await, (200, "ok".to_string()));
}

/// The body held whole is held in memory: not past `max_buffered_request_body`. One which says it
/// is larger is refused before a byte of it is read.
#[tokio::test]
async fn https2_a_body_announced_over_max_buffered_request_body_is_answered_413() {
    let site = Site::start("https2", "      max_buffered_request_body: 1Kb\n").await;

    let mut client = site.connect_tls(b"http/1.1").await;
    let head = format!(
        "POST /echo HTTP/1.1\r\nHost: localhost:{}\r\ncontent-length: 1025\r\n\r\n",
        site.port
    );
    client.write_all(head.as_bytes()).await.unwrap();

    let (status, _) = tokio::time::timeout(NOT_AFTER, read_response(&mut client))
        .await
        .expect("no answer to a body announced too large");
    assert_eq!(status, 413);

    let mut client = site.connect_tls(b"http/1.1").await;
    let request = format!(
        "POST /echo HTTP/1.1\r\nHost: localhost:{}\r\ncontent-length: 1024\r\n\r\n{}",
        site.port,
        "x".repeat(1024)
    );
    client.write_all(request.as_bytes()).await.unwrap();

    let answer = tokio::time::timeout(NOT_AFTER, read_response(&mut client))
        .await
        .expect("no answer in time");
    assert_eq!(answer, (200, "1024".to_string()));
}

/// An h2 body says nothing of its size: it is counted as it comes, and refused once it is over.
#[tokio::test]
async fn https2_an_h2_body_over_max_buffered_request_body_is_answered_413() {
    let site = Site::start("https2", "      max_buffered_request_body: 1Kb\n").await;

    let response = site.h2_post("/echo", &[600, 600]).await;
    assert_eq!(response.status(), 413);

    let response = site.h2_post("/echo", &[600, 424]).await;
    assert_eq!(response.status(), 200);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"1024");
}

/// An answer the client takes nothing of - an h2 stream whose window it keeps shut - cuts the
/// connection at `write_timeout`, as nginx's `send_timeout` does: it would hold the answer and the
/// upstream connection it is read from for as long as it likes.
#[tokio::test]
async fn https2_an_answer_the_client_does_not_take_cuts_the_connection() {
    let site = Site::start("https2", "      write_timeout: 1000\n").await;
    let (mut sender, connection) = site.h2_connect().await;

    let request = hyper::Request::get(format!("https://localhost:{}/big", site.port))
        .body(Empty::<Bytes>::new().boxed())
        .unwrap();
    let response = tokio::time::timeout(NOT_AFTER, sender.send_request(request))
        .await
        .expect("no answer in time")
        .unwrap();
    assert_eq!(response.status(), 200);

    // The body is never read: the window of the stream stays shut.
    let started = Instant::now();
    tokio::time::timeout(Duration::from_secs(6), connection)
        .await
        .expect("the connection was not cut")
        .unwrap();
    assert!(
        started.elapsed() >= NOT_BEFORE,
        "cut after {:?}",
        started.elapsed()
    );

    drop(response);
    let mut client = site.connect_tls(b"http/1.1").await;
    assert_eq!(site.get(&mut client, "/").await, (200, "ok".to_string()));
}

/// An h2 connection with no request on it for `h2_idle_timeout` is closed with a GOAWAY -
/// nginx's `keepalive_timeout`. A client which answers the PINGs does not hold it any longer.
#[tokio::test]
async fn https2_an_idle_h2_connection_is_closed() {
    let site = Site::start("https2", "      h2_idle_timeout: 1000\n").await;
    let (mut sender, connection) = site.h2_connect().await;

    assert_eq!(
        h2_get(&mut sender, site.port, "/").await,
        (200, "ok".to_string())
    );

    let started = Instant::now();
    tokio::time::timeout(NOT_AFTER, connection)
        .await
        .expect("an idle h2 connection is still open")
        .unwrap();
    assert!(
        started.elapsed() >= NOT_BEFORE,
        "closed after {:?}",
        started.elapsed()
    );
}

/// After `max_requests_per_connection` requests the connection is closed with a GOAWAY, once the
/// last of them is answered - nginx's `keepalive_requests`.
#[tokio::test]
async fn https2_a_connection_is_closed_after_its_most_requests() {
    let site = Site::start_with_global("https2", "", "  max_requests_per_connection: 2\n").await;
    let (mut sender, connection) = site.h2_connect().await;

    for _ in 0..2 {
        assert_eq!(
            h2_get(&mut sender, site.port, "/").await,
            (200, "ok".to_string())
        );
    }

    tokio::time::timeout(NOT_AFTER, connection)
        .await
        .expect("the connection is still open after its most requests")
        .unwrap();
}

/// A request head larger than `max_request_head_size` is answered `431` - by the proxy's own
/// http/1.1 pipeline on `http`, and by hyper for an http/1.1 client of `https2`. One within the
/// limit is served.
#[tokio::test]
async fn a_request_head_over_max_request_head_size_is_answered_431() {
    for endpoint_type in ["http", "https2"] {
        let site =
            Site::start_with_global(endpoint_type, "", "  max_request_head_size: 8Kb\n").await;

        let head_of = |header_size: usize| {
            format!(
                "GET / HTTP/1.1\r\nHost: localhost:{}\r\nX-Big: {}\r\n\r\n",
                site.port,
                "x".repeat(header_size)
            )
        };

        for (header_size, expected) in [(10 * 1024, 431), (4 * 1024, 200)] {
            let request = head_of(header_size);

            let (status, _) = if endpoint_type == "http" {
                send_and_read(&mut site.connect().await, &request).await
            } else {
                send_and_read(&mut site.connect_tls(b"http/1.1").await, &request).await
            };

            assert_eq!(
                status, expected,
                "{endpoint_type}, a header of {header_size}"
            );
        }
    }
}

/// After `max_requests_per_connection` requests the proxy's own http/1.1 pipeline closes the
/// connection, once the last of them is answered.
#[tokio::test]
async fn http_a_connection_is_closed_after_its_most_requests() {
    let site = Site::start_with_global("http", "", "  max_requests_per_connection: 2\n").await;

    let mut client = site.connect().await;
    for _ in 0..2 {
        assert_eq!(site.get(&mut client, "/").await, (200, "ok".to_string()));
    }

    let mut buffer = [0u8; 16];
    let read = tokio::time::timeout(NOT_AFTER, client.read(&mut buffer))
        .await
        .expect("the connection is still open after its most requests")
        .unwrap_or(0);
    assert_eq!(read, 0);

    site.assert_served_on_a_new_connection().await;
}

/// `rate_limit` of an endpoint: past the requests it lets one client make, `429` with a
/// `Retry-After` - on the proxy's own http/1.1 pipeline, and on hyper's for http/1.1 and h2.
#[tokio::test]
async fn a_client_over_the_rate_limit_of_the_endpoint_is_answered_429() {
    for endpoint_type in ["http", "https2"] {
        let site = Site::start(endpoint_type, "      rate_limit: 2/m\n").await;
        let request = format!("GET / HTTP/1.1\r\nHost: localhost:{}\r\n\r\n", site.port);

        for expected in [200, 200, 429] {
            let response = if endpoint_type == "http" {
                send_and_read_raw(&mut site.connect().await, &request).await
            } else {
                send_and_read_raw(&mut site.connect_tls(b"http/1.1").await, &request).await
            };

            assert!(
                response.starts_with(&format!("HTTP/1.1 {expected}")),
                "{endpoint_type}: {response}"
            );
            if expected == 429 {
                assert!(
                    response.to_ascii_lowercase().contains("\r\nretry-after: "),
                    "{endpoint_type}: {response}"
                );
            }
        }
    }

    let site = Site::start("https2", "      rate_limit: 1/m\n").await;
    let (mut sender, _connection) = site.h2_connect().await;
    assert_eq!(h2_get(&mut sender, site.port, "/").await.0, 200);
    assert_eq!(h2_get(&mut sender, site.port, "/").await.0, 429);
}

/// `rate_limit` of a location is its own, on top of the endpoint's: the other locations are not
/// held to it.
#[tokio::test]
async fn a_client_over_the_rate_limit_of_a_location_is_answered_429() {
    let upstream = start_upstream().await;
    let port = free_port().await;

    apply_settings(&format!(
        "hosts:\n  localhost:{port}:\n    endpoint:\n      type: http\n    locations:\n    - path: /limited\n      proxy_pass_to: http://127.0.0.1:{upstream}\n      rate_limit: 1/m\n    - proxy_pass_to: http://127.0.0.1:{upstream}\n"
    ))
    .await;
    serve(port);

    let get = |path: &str| format!("GET {path} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n");

    for (path, expected) in [("/limited", 200), ("/limited", 429), ("/", 200), ("/", 200)] {
        let (status, _) = send_and_read(&mut connect_to(port).await, &get(path)).await;
        assert_eq!(status, expected, "{path}");
    }
}

/// `max_request_body` - nginx's `client_max_body_size`: a body which says it is larger is
/// answered `413` before anything goes upstream - on the proxy's own pipeline and on hyper's,
/// where it holds a body held whole to it too. One within the limit is served.
#[tokio::test]
async fn a_body_announced_over_max_request_body_is_answered_413() {
    for endpoint_type in ["http", "https2"] {
        let site = Site::start(endpoint_type, "      max_request_body: 1Kb\n").await;

        for (size, expected) in [(2048, 413), (512, 200)] {
            let request = format!(
                "POST /echo HTTP/1.1\r\nHost: localhost:{}\r\ncontent-length: {size}\r\n\r\n{}",
                site.port,
                "x".repeat(size)
            );

            let (status, body) = if endpoint_type == "http" {
                send_and_read(&mut site.connect().await, &request).await
            } else {
                send_and_read(&mut site.connect_tls(b"http/1.1").await, &request).await
            };

            assert_eq!(status, expected, "{endpoint_type}, {size} bytes");
            if expected == 200 {
                assert_eq!(body, size.to_string());
            }
        }
    }
}

/// A chunked body says nothing of its size: the proxy's own pipeline cuts it as it passes
/// `max_request_body` - the connection is closed, and it is not answered `200`.
#[tokio::test]
async fn http_a_chunked_body_over_max_request_body_is_cut() {
    let site = Site::start("http", "      max_request_body: 1Kb\n").await;

    let chunk = "x".repeat(512);
    let mut request = format!(
        "POST /echo HTTP/1.1\r\nHost: localhost:{}\r\ntransfer-encoding: chunked\r\n\r\n",
        site.port
    );
    for _ in 0..4 {
        request.push_str(&format!("200\r\n{chunk}\r\n"));
    }
    request.push_str("0\r\n\r\n");

    let response = send_and_read_raw(&mut site.connect().await, &request).await;
    assert!(!response.starts_with("HTTP/1.1 200"), "{response}");

    site.assert_served_on_a_new_connection().await;
}

/// `tls_min_version: 1.3` turns away a client of TLS 1.2 in the handshake - nginx's
/// `ssl_protocols`. Without it TLS 1.2 is taken.
#[tokio::test]
async fn https2_tls_min_version_turns_away_older_tls() {
    use my_tls::tokio_rustls::rustls::version::{TLS12, TLS13};

    let site = Site::start("https2", "      tls_min_version: 1.3\n").await;
    assert!(tls_connect_with(site.port, &[&TLS12]).await.is_err());

    let mut client = tls_connect_with(site.port, &[&TLS13]).await.unwrap();
    assert_eq!(site.get(&mut client, "/").await, (200, "ok".to_string()));

    let site = Site::start("https2", "").await;
    let mut client = tls_connect_with(site.port, &[&TLS12]).await.unwrap();
    assert_eq!(site.get(&mut client, "/").await, (200, "ok".to_string()));
}

/// `access_log`: a line for every answer - of the proxy's own pipeline and of hyper's - with the
/// request, the status and the bytes of the body.
#[tokio::test]
async fn every_answer_gets_a_line_in_the_access_log() {
    let dir = std::env::temp_dir().join(format!(
        "my-reverse-proxy-access-log-e2e-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("access.log");

    crate::app::APP_CTX
        .access_log
        .apply(Some(crate::access_log::AccessLogSettings {
            path: path.clone(),
            max_size: 100 * 1024 * 1024,
            files: 1,
        }));

    let marker = format!("/access-log-{}", free_port().await);

    for endpoint_type in ["http", "https2"] {
        let site = Site::start(endpoint_type, "").await;
        let request = format!(
            "GET {marker}-{endpoint_type} HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
            site.port
        );

        let (status, _) = if endpoint_type == "http" {
            send_and_read(&mut site.connect().await, &request).await
        } else {
            send_and_read(&mut site.connect_tls(b"http/1.1").await, &request).await
        };
        assert_eq!(status, 200);
    }

    // The lines go through the writer task: looked for a while.
    let expected = ["http", "https2"].map(|endpoint_type| {
        format!(" localhost \"GET {marker}-{endpoint_type} HTTP/1.1\" 200 2 ")
    });

    let mut log = String::new();
    for _ in 0..50 {
        log = std::fs::read_to_string(&path).unwrap_or_default();

        if expected.iter().all(|line| log.contains(line.as_str())) {
            break;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    crate::app::APP_CTX.access_log.apply(None);
    let _ = std::fs::remove_dir_all(&dir);

    for line in expected {
        assert!(log.contains(line.as_str()), "{line} is not in:\n{log}");
    }
}

// ---------------------------------------------------------------------------------------------
// The opening bytes of a plain port: `http` and `http2` endpoints
// ---------------------------------------------------------------------------------------------

/// No TLS here: the protocol is told by the first bytes of the client, so a client which sends
/// none is cut with nothing said - not even an h2 SETTINGS.
#[tokio::test]
async fn plain_a_client_which_sends_nothing_is_cut() {
    for endpoint_type in ["http", "http2"] {
        let site = Site::start(endpoint_type, "      header_read_timeout: 1000\n").await;

        let mut client = site.connect().await;
        assert_closed_by_timeout(&mut client).await;

        site.assert_served_on_a_new_connection().await;
    }
}

/// A part of the h2 preface tells neither protocol yet: cut all the same.
#[tokio::test]
async fn plain_a_part_of_the_h2_preface_is_cut() {
    for endpoint_type in ["http", "http2"] {
        let site = Site::start(endpoint_type, "      header_read_timeout: 1000\n").await;

        let mut client = site.connect().await;
        client.write_all(b"PRI * HTTP/2.0\r\n").await.unwrap();
        assert_closed_by_timeout(&mut client).await;

        site.assert_served_on_a_new_connection().await;
    }
}

/// The preface whole is h2: the server sends its SETTINGS, and cuts the connection which sends
/// no request.
#[tokio::test]
async fn plain_an_h2_preface_with_no_request_is_cut() {
    for endpoint_type in ["http", "http2"] {
        let site = Site::start(endpoint_type, "      header_read_timeout: 1000\n").await;

        let mut client = site.connect().await;
        client.write_all(H2_PREFACE).await.unwrap();
        assert_closed_by_timeout_after_the_server_preface(&mut client).await;
    }
}

/// The first request is due `header_read_timeout` after the connect, not after the first bytes:
/// a client which waits before it sends is not given the timeout again. An http/1.1 head which
/// does not end, and an h2 preface with no request after it.
#[tokio::test]
async fn plain_the_first_request_is_due_from_the_connect() {
    for endpoint_type in ["http", "http2"] {
        let site = Site::start(endpoint_type, "      header_read_timeout: 1000\n").await;

        for opening in [site.head_start("GET /").into_bytes(), H2_PREFACE.to_vec()] {
            let mut client = site.connect().await;
            let connected = Instant::now();

            tokio::time::sleep(WAIT_BEFORE_SENDING).await;
            client.write_all(&opening).await.unwrap();

            let (elapsed, answered) = wait_for_the_close(&mut client, connected).await;

            let what = format!("{endpoint_type}, {:?}", String::from_utf8_lossy(&opening));
            assert!(
                (NOT_BEFORE..SHORT + WAIT_BEFORE_SENDING / 2).contains(&elapsed),
                "{what}: closed {elapsed:?} after the connect"
            );

            // An h2 server says its SETTINGS before anything else; an http/1.1 head which did
            // not come in time is answered nothing.
            if opening.starts_with(H2_PREFACE) {
                assert_eq!(answered.get(3), Some(&4), "{what}: not a SETTINGS: {answered:?}");
            } else {
                assert!(answered.is_empty(), "{what}: answered {answered:?}");
            }
        }
    }
}

/// What an h2 client by prior knowledge sends before anything else.
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// How long [`plain_the_first_request_is_due_from_the_connect`] waits after the connect before
/// it sends. The close is expected at [`SHORT`] after the connect, and taken up to half of this
/// later; counted again from the bytes, it would come this much later.
const WAIT_BEFORE_SENDING: Duration = Duration::from_millis(700);

/// Reads until the proxy closes the connection: how long after `since` it did, and what it sent
/// before that.
async fn wait_for_the_close<S: AsyncRead + Unpin>(
    client: &mut S,
    since: Instant,
) -> (Duration, Vec<u8>) {
    let mut answered = Vec::new();
    let mut buffer = [0u8; 1024];

    loop {
        let read = tokio::time::timeout(NOT_AFTER, client.read(&mut buffer))
            .await
            .expect("the connection was not closed");

        match read {
            Ok(0) | Err(_) => return (since.elapsed(), answered),
            Ok(size) => answered.extend_from_slice(&buffer[..size]),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// No HTTP head to read: `tcp` and `mcp` endpoints
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn tcp_a_silent_connection_is_not_cut_by_the_header_timeout() {
    let echo = start_echo().await;
    let port = free_port().await;

    apply_settings(&format!(
        "global_settings:\n  header_read_timeout: 1000\n  tls_handshake_timeout: 1000\nhosts:\n  localhost:{port}:\n    endpoint:\n      type: tcp\n    locations:\n    - proxy_pass_to: '{echo}'\n"
    ))
    .await;
    serve(port);

    let mut client = connect_to(port).await;
    assert_still_open_after_the_timeouts(&mut client).await;
}

#[tokio::test]
async fn mcp_a_silent_connection_is_not_cut_by_the_header_timeout() {
    let echo = start_echo().await;
    let port = free_port().await;

    apply_settings(&format!(
        "global_settings:\n  header_read_timeout: 1000\nhosts:\n  localhost:{port}:\n    endpoint:\n      type: mcp\n    locations:\n    - proxy_pass_to: http://{echo}\n"
    ))
    .await;
    serve(port);

    let mut client = tls_connect(port, b"http/1.1").await;
    assert_still_open_after_the_timeouts(&mut client).await;
}

// ---------------------------------------------------------------------------------------------
// The checks
// ---------------------------------------------------------------------------------------------

/// The proxy closes the connection - with nothing sent - at a timeout of [`SHORT`].
async fn assert_closed_by_timeout<S: AsyncRead + Unpin>(client: &mut S) {
    let started = Instant::now();

    let mut buffer = [0u8; 1024];
    let read = tokio::time::timeout(NOT_AFTER, client.read(&mut buffer))
        .await
        .expect("the connection was not closed");

    let elapsed = started.elapsed();

    match read {
        Ok(0) | Err(_) => {}
        Ok(size) => panic!(
            "the proxy answered instead of closing: {:?}",
            String::from_utf8_lossy(&buffer[..size])
        ),
    }

    assert!(
        elapsed >= NOT_BEFORE,
        "closed after {elapsed:?}: too soon to be the timeout"
    );
}

/// The same for an h2 connection, whose server speaks first: what it sends before it closes is
/// its SETTINGS, read and dropped.
async fn assert_closed_by_timeout_after_the_server_preface<S: AsyncRead + Unpin>(client: &mut S) {
    let started = Instant::now();
    let mut buffer = [0u8; 1024];

    loop {
        let read = tokio::time::timeout(NOT_AFTER, client.read(&mut buffer))
            .await
            .expect("the connection was not closed");

        match read {
            Ok(0) | Err(_) => break,
            Ok(_) => assert!(started.elapsed() < NOT_AFTER, "the connection was not closed"),
        }
    }

    let elapsed = started.elapsed();
    assert!(
        (NOT_BEFORE..NOT_AFTER).contains(&elapsed),
        "closed after {elapsed:?}"
    );
}

/// Silent for twice the timeouts, then the bytes still go through to the echo and back.
async fn assert_still_open_after_the_timeouts<S: AsyncRead + AsyncWrite + Unpin>(client: &mut S) {
    let mut buffer = [0u8; 4];

    match tokio::time::timeout(SHORT * 2, client.read(&mut buffer)).await {
        Err(_) => {}
        Ok(read) => panic!("the connection did not stay open: {read:?}"),
    }

    client.write_all(b"ping").await.unwrap();
    tokio::time::timeout(NOT_AFTER, client.read_exact(&mut buffer))
        .await
        .expect("no echo")
        .unwrap();
    assert_eq!(&buffer, b"ping");
}

// ---------------------------------------------------------------------------------------------
// The site: one endpoint in front of an upstream
// ---------------------------------------------------------------------------------------------

struct Site {
    port: u16,
}

impl Site {
    /// `endpoint_lines`: more keys of the `endpoint` section, indented by six spaces.
    async fn start(endpoint_type: &str, endpoint_lines: &str) -> Self {
        Self::start_with_global(endpoint_type, endpoint_lines, "").await
    }

    /// `global_lines`: keys of `global_settings`, indented by two spaces.
    async fn start_with_global(endpoint_type: &str, endpoint_lines: &str, global_lines: &str) -> Self {
        let upstream = start_upstream().await;
        let port = free_port().await;

        let global = if global_lines.is_empty() {
            String::new()
        } else {
            format!("global_settings:\n{global_lines}")
        };

        apply_settings(&format!(
            "{global}hosts:\n  localhost:{port}:\n    endpoint:\n      type: {endpoint_type}\n{endpoint_lines}    locations:\n    - proxy_pass_to: http://127.0.0.1:{upstream}\n"
        ))
        .await;
        serve(port);

        Self { port }
    }

    async fn connect(&self) -> TcpStream {
        connect_to(self.port).await
    }

    async fn connect_tls(&self, alpn: &[u8]) -> TlsStream<TcpStream> {
        tls_connect(self.port, alpn).await
    }

    /// The start of a request head with no empty line to end it.
    fn head_start(&self, method_and_path: &str) -> String {
        format!("{method_and_path} HTTP/1.1\r\nHost: localhost:{}\r\nx-slow: ", self.port)
    }

    async fn get<S: AsyncRead + AsyncWrite + Unpin>(&self, client: &mut S, path: &str) -> (u16, String) {
        let request = format!("GET {path} HTTP/1.1\r\nHost: localhost:{}\r\n\r\n", self.port);
        client.write_all(request.as_bytes()).await.unwrap();

        tokio::time::timeout(NOT_AFTER, read_response(client))
            .await
            .expect("no answer in time")
    }

    /// A new h2 connection: what sends its requests, and the task which ends with it.
    async fn h2_connect(
        &self,
    ) -> (
        hyper::client::conn::http2::SendRequest<BoxBody<Bytes, Infallible>>,
        tokio::task::JoinHandle<()>,
    ) {
        let tls = self.connect_tls(b"h2").await;
        let (sender, connection) = hyper::client::conn::http2::handshake(
            hyper_util::rt::TokioExecutor::new(),
            TokioIo::new(tls),
        )
        .await
        .unwrap();

        let connection = tokio::spawn(async move {
            let _ = connection.await;
        });

        (sender, connection)
    }

    /// A `POST` over h2 on a new connection, with a body of `frames` and no `content-length`.
    async fn h2_post(
        &self,
        path: &str,
        frames: &[usize],
    ) -> hyper::Response<hyper::body::Incoming> {
        let tls = self.connect_tls(b"h2").await;
        let (mut sender, connection) = hyper::client::conn::http2::handshake(
            hyper_util::rt::TokioExecutor::new(),
            TokioIo::new(tls),
        )
        .await
        .unwrap();
        tokio::spawn(connection);

        let frames: Vec<Result<hyper::body::Frame<Bytes>, Infallible>> = frames
            .iter()
            .map(|size| Ok(hyper::body::Frame::data(Bytes::from(vec![b'x'; *size]))))
            .collect();
        let body = http_body_util::StreamBody::new(futures::stream::iter(frames));

        let request = hyper::Request::post(format!("https://localhost:{}{path}", self.port))
            .body(body)
            .unwrap();

        tokio::time::timeout(NOT_AFTER, sender.send_request(request))
            .await
            .expect("no answer in time")
            .unwrap()
    }

    async fn assert_served_on_a_new_connection(&self) {
        let mut client = self.connect().await;
        assert_eq!(self.get(&mut client, "/").await, (200, "ok".to_string()));
    }
}

/// Writes `request` and reads the answer to it: the status and the body.
async fn send_and_read<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: &str,
) -> (u16, String) {
    stream.write_all(request.as_bytes()).await.unwrap();

    tokio::time::timeout(NOT_AFTER, read_response(stream))
        .await
        .expect("no answer in time")
}

/// Writes `request` and gives back all the proxy wrote in answer: up to the close, or a second of
/// silence.
async fn send_and_read_raw<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: &str,
) -> String {
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut received = Vec::new();
    let mut buffer = [0u8; 4096];

    while let Ok(Ok(read)) =
        tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buffer)).await
    {
        if read == 0 {
            break;
        }
        received.extend_from_slice(&buffer[..read]);
    }

    String::from_utf8_lossy(&received).to_string()
}

/// A `GET` of `path` on an h2 connection: the status and the body.
async fn h2_get(
    sender: &mut hyper::client::conn::http2::SendRequest<BoxBody<Bytes, Infallible>>,
    port: u16,
    path: &str,
) -> (u16, String) {
    let request = hyper::Request::get(format!("https://localhost:{port}{path}"))
        .body(Empty::<Bytes>::new().boxed())
        .unwrap();

    let response = tokio::time::timeout(NOT_AFTER, sender.send_request(request))
        .await
        .expect("no answer in time")
        .unwrap();
    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();

    (status, String::from_utf8_lossy(&body).to_string())
}

/// The status and the body, by `content-length` or by chunks.
async fn read_response<S: AsyncRead + Unpin>(stream: &mut S) -> (u16, String) {
    let mut received = Vec::new();

    let head_end = loop {
        if let Some(end) = received.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }

        read_more(stream, &mut received).await;
    };

    let head = String::from_utf8(received[..head_end].to_vec()).unwrap();
    let status: u16 = head[9..12].parse().unwrap();
    let head_lower = head.to_ascii_lowercase();

    if let Some(length) = head_lower
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
    {
        let length: usize = length.trim().parse().unwrap();

        while received.len() < head_end + length {
            read_more(stream, &mut received).await;
        }

        let body = String::from_utf8(received[head_end..head_end + length].to_vec()).unwrap();
        return (status, body);
    }

    assert!(
        head_lower.contains("transfer-encoding: chunked"),
        "an answer with no length: {head}"
    );

    let mut body = Vec::new();
    let mut pos = head_end;

    loop {
        let size_end = loop {
            if let Some(end) = received[pos..].windows(2).position(|window| window == b"\r\n") {
                break pos + end;
            }

            read_more(stream, &mut received).await;
        };

        let size_line = std::str::from_utf8(&received[pos..size_end]).unwrap();
        let size = usize::from_str_radix(size_line.split(';').next().unwrap().trim(), 16).unwrap();
        let data_start = size_end + 2;

        while received.len() < data_start + size + 2 {
            read_more(stream, &mut received).await;
        }

        if size == 0 {
            return (status, String::from_utf8(body).unwrap());
        }

        body.extend_from_slice(&received[data_start..data_start + size]);
        pos = data_start + size + 2;
    }
}

async fn read_more<S: AsyncRead + Unpin>(stream: &mut S, received: &mut Vec<u8>) {
    let mut buffer = [0u8; 4096];
    let read = stream.read(&mut buffer).await.unwrap();

    assert!(
        read > 0,
        "the connection closed in the middle of an answer: {:?}",
        String::from_utf8_lossy(received)
    );

    received.extend_from_slice(&buffer[..read]);
}

/// An http/1.1 upstream: `ok` for `/`, `slow` for `/slow` after [`SLOW_ANSWER`], and the length
/// of the body for `/echo`.
async fn start_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };

            let service = hyper::service::service_fn(
                |request: hyper::Request<hyper::body::Incoming>| async move {
                    let body: BoxBody<Bytes, Infallible> = match request.uri().path() {
                        "/slow" => {
                            tokio::time::sleep(SLOW_ANSWER).await;
                            Full::new(Bytes::from("slow")).boxed()
                        }
                        "/echo" => {
                            let body = request.into_body().collect().await.unwrap().to_bytes();
                            Full::new(Bytes::from(body.len().to_string())).boxed()
                        }
                        // 64 MB in pieces of 64 KB: more than a client takes without reading.
                        "/big" => {
                            let pieces = (0..1024).map(|_| {
                                Ok::<_, Infallible>(hyper::body::Frame::data(Bytes::from(vec![
                                    b'x';
                                    64 * 1024
                                ])))
                            });
                            StreamBody::new(futures::stream::iter(pieces)).boxed()
                        }
                        _ => Full::new(Bytes::from("ok")).boxed(),
                    };

                    Ok::<_, Infallible>(hyper::Response::new(body))
                },
            );

            tokio::spawn(
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service),
            );
        }
    });

    port
}

/// Sends back whatever it gets.
async fn start_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };

            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });

    addr
}

// ---------------------------------------------------------------------------------------------
// The proxy
// ---------------------------------------------------------------------------------------------

/// What `flows::load_everything_from_settings` does with a settings file: every host is
/// compiled by `scripts::compile_host_configuration` and published into the live configuration,
/// where the accept loop looks its port up.
async fn apply_settings(yaml: &str) {
    // What main() does before anything touches TLS.
    my_tls::install_default_crypto_providers();

    let model: SettingsModel = my_settings_reader::serde_yaml::from_str(yaml)
        .unwrap_or_else(|err| panic!("the settings do not parse: {err}\n{yaml}"));

    let settings = SettingsCompiled {
        hosts: model.hosts,
        global_settings: model.global_settings,
        ..Default::default()
    };

    for (host_id, host_settings) in &settings.hosts {
        let endpoint_host = settings.get_endpoint_host_string(host_id).unwrap();

        let EndpointPort::Tcp(port) = endpoint_host.get_port() else {
            panic!("{host_id} is not a tcp port");
        };

        let configuration =
            crate::scripts::compile_host_configuration(&settings, endpoint_host, host_settings, None)
                .await
                .unwrap_or_else(|err| panic!("{host_id} does not compile: {err}\n{yaml}"));

        crate::app::APP_CTX
            .current_configuration
            .write(move |config| {
                config.listen_tcp_endpoints.insert(port, configuration);
            })
            .await;
    }
}

/// The accept loop the proxy runs for a tcp port, on the loopback.
fn serve(port: u16) {
    super::start_listen_tcp_server(SocketAddr::from(([127, 0, 0, 1], port)));
}

/// The accept loop is started by a spawned task: the port may not be listening yet.
async fn connect_to(port: u16) -> TcpStream {
    for _ in 0..100 {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
            return stream;
        }

        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    panic!("nothing listens on port {port}");
}

/// A finished TLS handshake with `localhost` as the server name and `alpn` as the one protocol
/// offered.
async fn tls_connect(port: u16, alpn: &[u8]) -> TlsStream<TcpStream> {
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];

    let tcp_stream = connect_to(port).await;

    tokio::time::timeout(
        NOT_AFTER,
        TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("localhost").unwrap(), tcp_stream),
    )
    .await
    .expect("no TLS handshake in time")
    .unwrap()
}

/// A TLS handshake of an http/1.1 client which speaks `versions` only.
async fn tls_connect_with(
    port: u16,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> std::io::Result<TlsStream<TcpStream>> {
    let mut config = rustls::ClientConfig::builder_with_protocol_versions(versions)
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let tcp_stream = connect_to(port).await;

    tokio::time::timeout(
        NOT_AFTER,
        TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("localhost").unwrap(), tcp_stream),
    )
    .await
    .expect("no TLS handshake in time")
}

/// The endpoint serves the proxy's self-signed certificate; what is under test is what happens
/// around the handshake, not the certificate.
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

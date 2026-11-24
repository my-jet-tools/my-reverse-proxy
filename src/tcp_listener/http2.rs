use std::sync::Arc;

use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    configurations::HttpListenPortConfiguration,
    types::{ConnectionIp, ListenHost},
};

use super::http_request_handler::http::HttpRequestHandler;

/// A connection of an `http` / `http2` endpoint - a tcp port or a unix socket - whose client
/// speaks h2 (by prior knowledge: the client preface, with no TLS to agree on it in), served to
/// its end on the task it is on. `stream` gives the preface first, as it came
/// (`plain_http::ReplayedStream`).
///
/// `first_request_deadline`: when the first request is due - `header_read_timeout` from the
/// start of the connection, the wait for the preface included.
pub async fn serve_connection<TStream: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: TStream,
    connection_ip: ConnectionIp,
    listen_host: ListenHost,
    configuration: Arc<HttpListenPortConfiguration>,
    first_request_deadline: tokio::time::Instant,
) {
    let listening_addr_str =
        listen_host.to_pretty_string(configuration.listen_endpoint_type.is_https());

    // Which endpoint of the port a connection is for is known only from its requests: until
    // then the port's client timeouts (the longest of its endpoints') apply.
    let client_timeouts = configuration.client_timeouts();
    let connection_settings = configuration.connection_settings();

    // The h2 PINGs need a timer; a client which stopped answering them is cut. What comes before
    // the first request - the rest of the client preface, the first HEADERS - is timed below.
    let mut http2_builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    http2_builder
        .enable_connect_protocol()
        .timer(TokioTimer::new())
        .keep_alive_interval(client_timeouts.h2_keep_alive_interval)
        .keep_alive_timeout(client_timeouts.h2_keep_alive_timeout)
        .max_concurrent_streams(connection_settings.h2_max_concurrent_streams)
        .max_header_list_size(connection_settings.h2_max_header_list_size);

    let port = listen_host.get_port();

    if let Some(port) = port.as_ref() {
        crate::app::APP_CTX
            .metrics
            .update(|itm| itm.connection_by_port.inc(port));
    }

    crate::app::APP_CTX
        .prometheus
        .inc_http2_server_connections(listening_addr_str.as_str());

    let http_request_handler = Arc::new(HttpRequestHandler::new(connection_ip, configuration));

    let http_request_handler_to_dispose = http_request_handler.clone();
    // A request which finds the connection must not go on cuts it: see `ConnectionCut`.
    let cut = http_request_handler.cut.clone();
    // Closes the connection once it is idle, or served enough requests: see
    // `ConnectionLifetime`.
    let lifetime = http_request_handler.lifetime.clone();

    let first_request = super::FirstRequestDeadline::new();
    let first_request_seen = first_request.clone();

    let connection = http2_builder.serve_connection(
        TokioIo::new(stream),
        service_fn(move |req| {
            first_request_seen.request_arrived();
            super::http_request_handler::http::handle_request(http_request_handler.clone(), req)
        }),
    );

    let connection = lifetime.serve(
        connection,
        |connection| connection.graceful_shutdown(),
        client_timeouts.h2_idle_timeout,
        connection_settings.max_requests_per_connection,
    );

    let result = cut
        .serve(first_request.serve_until(connection, first_request_deadline))
        .await
        .flatten();

    if let Some(Err(err)) = result {
        println!(
            "Error serving H2 connection on [{}]. Err{:?}",
            listening_addr_str, err
        );
    }

    if let Some(port) = port.as_ref() {
        crate::app::APP_CTX
            .metrics
            .update(|itm| itm.connection_by_port.dec(port));
    }

    crate::app::APP_CTX
        .prometheus
        .dec_http2_server_connections(listening_addr_str.as_str());

    http_request_handler_to_dispose.dispose().await;
}

use std::sync::Arc;

use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};

use crate::{
    configurations::HttpListenPortConfiguration,
    network_stream::*,
    types::{AcceptedServerConnection, ListenHost},
};

use super::http_request_handler::http::HttpRequestHandler;

pub async fn handle_connection(
    accepted_connection: AcceptedServerConnection,
    listen_host: ListenHost,
    configuration: Arc<HttpListenPortConfiguration>,
) {
    let listening_addr_str =
        listen_host.to_pretty_string(configuration.listen_endpoint_type.is_https());

    // Which endpoint of the port a connection is for is known only from its requests: until
    // then the port's client timeouts (the longest of its endpoints') apply.
    let client_timeouts = configuration.client_timeouts();

    // The h2 PINGs need a timer; a client which stopped answering them is cut. What comes before
    // the first request - the client preface, the first HEADERS - is timed below.
    let mut http2_builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    http2_builder
        .enable_connect_protocol()
        .timer(TokioTimer::new())
        .keep_alive_interval(client_timeouts.h2_keep_alive_interval)
        .keep_alive_timeout(client_timeouts.h2_keep_alive_timeout);
    let http2_builder = Arc::new(http2_builder);

    let builder = http2_builder.clone();

    let port = listen_host.get_port();

    if let Some(port) = port.as_ref() {
        crate::app::APP_CTX
            .metrics
            .update(|itm| itm.connection_by_port.inc(port));
    }

    let listening_addr_str = listening_addr_str.clone();

    crate::app::APP_CTX
        .prometheus
        .inc_http2_server_connections(listening_addr_str.as_str());

    let connection_addr = accepted_connection.get_addr();
    crate::app::spawn_named("http2_server_connection", async move {
        let io = match accepted_connection {
            AcceptedServerConnection::Tcp { network_stream, .. } => {
                let io = TokioIo::new(network_stream);

                TcpOrUnixSocket::Tcp(io)
            }
            #[cfg(unix)]
            AcceptedServerConnection::Unix(unix_stream) => {
                let io = TokioIo::new(unix_stream);
                TcpOrUnixSocket::Unix(io)
            }
        };

        let http_request_handler = HttpRequestHandler::new(connection_addr, configuration);

        let http_request_handler = Arc::new(http_request_handler);

        let http_request_handler_to_dispose = http_request_handler.clone();

        match io {
            TcpOrUnixSocket::Tcp(io) => {
                let first_request = super::FirstRequestDeadline::new();
                let first_request_seen = first_request.clone();

                let connection = builder.serve_connection(
                    io,
                    service_fn(move |req| {
                        first_request_seen.request_arrived();
                        super::http_request_handler::http::handle_request(
                            http_request_handler.clone(),
                            req,
                        )
                    }),
                );

                let result = first_request
                    .serve(connection, client_timeouts.header_read_timeout)
                    .await;

                if let Some(Err(err)) = result {
                    println!(
                        "Error serving H2 connection on [{}]. Err{:?}",
                        listening_addr_str, err
                    );
                }
            }
            #[cfg(unix)]
            TcpOrUnixSocket::Unix(io) => {
                let first_request = super::FirstRequestDeadline::new();
                let first_request_seen = first_request.clone();

                let connection = builder.serve_connection(
                    io,
                    service_fn(move |req| {
                        first_request_seen.request_arrived();
                        super::http_request_handler::http::handle_request(
                            http_request_handler.clone(),
                            req,
                        )
                    }),
                );

                let result = first_request
                    .serve(connection, client_timeouts.header_read_timeout)
                    .await;

                if let Some(Err(err)) = result {
                    println!(
                        "Error serving H2 connection on [{}]. Err{:?}",
                        listening_addr_str, err
                    );
                }
            }
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
    });
}

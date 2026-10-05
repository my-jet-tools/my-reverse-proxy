//! The h1 upstream pool against a real http/1.1 upstream.

use std::{sync::Arc, time::Duration};

use http_body_util::BodyExt;
use my_http_client::http1::{MyHttpRequestBuilder, MyHttpResponse};
use rust_extensions::remote_endpoint::RemoteEndpointOwned;
use tokio::net::{TcpListener, TcpStream};

use super::{H1Pool, PoolDesc, PoolParams};
use crate::{
    http_client_connectors::HttpConnector, http_proxy_pass::content_source::attach_conn_guard,
};

const TIMEOUT: Duration = Duration::from_secs(10);

/// A client which leaves in the middle of a streaming response - the normal end of an SSE session -
/// drops the body before its end. The pooled connection is still reading that response, so it must
/// not serve the next request: the request would queue behind a body which never ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_abandoned_streaming_body_takes_its_connection_out_of_service() {
    let upstream = start_upstream().await;
    let pool = H1Pool::new(
        PoolDesc {
            location_id: 1,
            name: "abandoned-body".to_string(),
            authority: "upstream".to_string(),
            id_string: "abandoned-body".to_string(),
        },
        PoolParams {
            pool_size: 1,
            ..Default::default()
        },
        Arc::new(move || {
            let connector = HttpConnector {
                remote_endpoint: Arc::new(
                    RemoteEndpointOwned::try_parse(format!("http://127.0.0.1:{upstream}")).unwrap(),
                ),
                debug: false,
            };
            let metrics: Arc<dyn my_http_client::http1::MyHttpClientMetrics + Send + Sync> =
                crate::app::APP_CTX.prometheus.clone();
            (connector, metrics)
        }),
    );

    // A body read to its end leaves the connection in service.
    let handle = pool.get_connection().await.unwrap();
    let MyHttpResponse::Response(response) =
        handle.do_request(&get("/answer"), TIMEOUT).await.unwrap()
    else {
        panic!("not an upgrade");
    };
    let response = attach_conn_guard(response, Box::new(handle));
    response.into_body().collect().await.unwrap();
    assert_eq!(pool.alive_count(), 1);

    // The same connection, now for a stream the client of the proxy leaves after the first event.
    let handle = pool.get_connection().await.unwrap();
    let MyHttpResponse::Response(response) =
        handle.do_request(&get("/stream"), TIMEOUT).await.unwrap()
    else {
        panic!("not an upgrade");
    };
    let mut response = attach_conn_guard(response, Box::new(handle));
    tokio::time::timeout(TIMEOUT, response.body_mut().frame())
        .await
        .expect("the first event did not come")
        .unwrap()
        .unwrap();
    drop(response);
    assert_eq!(pool.alive_count(), 0);

    // The next request gets a connection of its own at once instead of waiting behind the stream.
    let handle = pool.get_connection().await.unwrap();
    let MyHttpResponse::Response(response) = tokio::time::timeout(
        Duration::from_secs(3),
        handle.do_request(&get("/answer"), TIMEOUT),
    )
    .await
    .expect("the next request waits behind the abandoned stream")
    .unwrap() else {
        panic!("not an upgrade");
    };
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "answer".as_bytes()
    );
}

fn get(path: &str) -> my_http_client::http1::MyHttpRequest {
    MyHttpRequestBuilder::new(hyper::Method::GET, path)
        .append_header("Host", "upstream")
        .build()
        .unwrap()
}

/// An http/1.1 upstream: `/stream` sends one event and then stays open with nothing more, every
/// other path answers `answer`.
async fn start_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(serve(stream));
        }
    });

    port
}

async fn serve(stream: TcpStream) {
    let service = hyper::service::service_fn(
        |request: hyper::Request<hyper::body::Incoming>| async move {
            if request.uri().path() == "/stream" {
                use futures::StreamExt;

                let events = futures::stream::once(async {
                    Ok::<_, std::convert::Infallible>(hyper::body::Frame::data(
                        bytes::Bytes::from_static(b"data: first\n\n"),
                    ))
                })
                .chain(futures::stream::pending());

                return Ok::<_, std::convert::Infallible>(hyper::Response::new(BodyExt::boxed(
                    http_body_util::StreamBody::new(events),
                )));
            }

            Ok(hyper::Response::new(BodyExt::boxed(
                http_body_util::Full::new(bytes::Bytes::from_static(b"answer"))
                    .map_err(|never| match never {}),
            )))
        },
    );

    let _ = hyper::server::conn::http1::Builder::new()
        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
        .await;
}

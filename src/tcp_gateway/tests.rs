//! The gateway end to end: a gateway server and a gateway client in-process, talking over a
//! real socket, with throwaway TCP upstreams behind them.

use std::{
    future::Future,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::Poll,
    time::{Duration, Instant},
};

use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use rust_extensions::remote_endpoint::RemoteEndpointOwned;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};

use super::{
    client::{TcpGatewayClient, TcpGatewayClientParams},
    forwarded_connection::TcpGatewayProxyForwardStream,
    server::{is_ip_allowed, TcpGatewayServer},
    session::CompressionLevel,
    *,
};
use crate::{
    network_stream::{NetworkStreamReadPart, NetworkStreamWritePart},
    tcp_utils::{copy_streams, ConnectionPumps, LoopBuffer},
    types::{HttpTimeouts, WhiteListedIpList},
};

const TIMEOUT: Duration = Duration::from_secs(10);

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Short enough to hit in a test, long enough to tell a silent direction from a silent connection.
const IDLE_TIMEOUTS: HttpTimeouts = HttpTimeouts {
    read_timeout: Duration::from_secs(1),
    write_timeout: Duration::from_secs(5),
};

#[tokio::test]
async fn data_goes_through_the_tunnel_both_ways() {
    let gateway = Gateway::start("echo", false).await;
    let upstream = start_upstream(|stream| echo(stream, None)).await;

    let mut stream = gateway.connect_from_client(upstream).await;

    assert_echoes(&mut stream).await;
}

#[tokio::test]
async fn dropping_the_read_half_closes_the_whole_connection() {
    let gateway = Gateway::start("read-half-dropped", false).await;
    let (closed_tx, mut closed) = mpsc::unbounded_channel();
    let upstream = start_upstream(move |stream| echo(stream, Some(closed_tx.clone()))).await;

    let (read_half, mut write_half) = split(gateway.connect_from_client(upstream).await);
    let write_half_closed = write_half.connection_closed().unwrap();

    // The loop reading this connection ended - on an error, say. Its half goes with it.
    drop(read_half);

    tokio::time::timeout(TIMEOUT, write_half_closed.cancelled())
        .await
        .expect("the write half sees the connection's flag go down");
    assert!(write_half
        .write_to_socket(b"after the close")
        .await
        .is_err());
    tokio::time::timeout(TIMEOUT, closed.recv())
        .await
        .expect("the upstream connection behind the gateway is closed");
}

#[tokio::test]
async fn dropping_the_write_half_ends_the_read_half_with_eof() {
    let gateway = Gateway::start("write-half-dropped", false).await;
    let (closed_tx, mut closed) = mpsc::unbounded_channel();
    let upstream = start_upstream(move |stream| echo(stream, Some(closed_tx.clone()))).await;

    let (mut read_half, write_half) = split(gateway.connect_from_client(upstream).await);

    drop(write_half);

    assert_eq!(
        read_to_end(&mut read_half).await.ok(),
        Some(Vec::new()),
        "the read half ends with EOF"
    );
    tokio::time::timeout(TIMEOUT, closed.recv())
        .await
        .expect("the upstream connection behind the gateway is closed");
}

#[tokio::test]
async fn a_pump_waiting_on_an_idle_client_stops_once_the_tunnel_connection_closes() {
    let gateway = Gateway::start("idle-pump", false).await;

    // The upstream closes right after accepting.
    let upstream = start_upstream(|stream| async move { drop(stream) }).await;

    // A port forward whose client sends nothing and never closes. With a 180 s read timeout only
    // the connection's flag ends its client-to-upstream pump: it lingers for the client to close
    // once the other pump is done, a write timeout at most, and stops.
    let timeouts = HttpTimeouts {
        read_timeout: Duration::from_secs(180),
        write_timeout: Duration::from_secs(1),
    };
    let (_idle_client, pumps) =
        port_forward(gateway.connect_from_client(upstream).await, timeouts).await;

    for pump in pumps {
        tokio::time::timeout(TIMEOUT, pump)
            .await
            .expect("a pump outlived the closed tunnel connection")
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_bytes_an_upstream_sends_right_before_closing_reach_the_reader() {
    let gateway = Gateway::start("tail-of-response", false).await;
    let data = Arc::new(pseudo_random(3 * 1024 * 1024));
    let upstream = {
        let data = data.clone();
        start_upstream(move |stream| send_and_close(stream, data.clone())).await
    };

    let mut stream = gateway.connect_from_client(upstream).await;

    // Let the data and the close both arrive before the first read: the reader must still get
    // every byte, and then EOF.
    let client_side = gateway.client_side();
    wait_until(|| client_side.get_forward_proxy_connections_amount() == 0).await;

    let received = read_to_end(&mut stream)
        .await
        .unwrap_or_else(|_| panic!("a connection the upstream closed must read to EOF"));

    assert!(
        received == *data,
        "received {} of {} bytes",
        received.len(),
        data.len()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_bytes_written_right_before_closing_reach_the_upstream() {
    let gateway = Gateway::start("tail-of-request", false).await;
    let (collected_tx, mut collected) = mpsc::unbounded_channel();
    // The upstream does not read until everything - the close included - has arrived, so the
    // bytes back up behind a write to the upstream which is still in flight when the close
    // comes: the moment the tail used to get lost.
    let upstream = start_upstream(move |stream| {
        collect(stream, collected_tx.clone(), Duration::from_millis(1500))
    })
    .await;

    let mut stream = gateway.connect_from_client(upstream).await;

    // In several writes, the way a byte pump writes: frames keep queueing up behind the write
    // in flight. More than the socket buffers hold, so that write really is in flight.
    let data = pseudo_random(3 * 1024 * 1024);
    for chunk in data.chunks(256 * 1024) {
        stream.write_to_socket(chunk).await.unwrap();
    }
    stream.disconnect();

    let received = tokio::time::timeout(TIMEOUT, collected.recv())
        .await
        .expect("the upstream connection is closed")
        .unwrap();

    assert!(
        received == data,
        "received {} of {} bytes",
        received.len(),
        data.len()
    );
}

#[tokio::test]
async fn closing_a_connection_opened_from_one_end_keeps_the_connection_opened_from_the_other() {
    let gateway = Gateway::start("both-ends", false).await;
    let upstream = start_upstream(|stream| echo(stream, None)).await;

    // The first connection each end opens - before ids were allocated apart, both got id 0.
    let from_client = gateway.connect_from_client(upstream).await;
    let mut from_server = gateway.connect_from_server(upstream).await;

    from_client.disconnect();

    let server_side = gateway.server_side();
    wait_until(|| server_side.get_forward_connections_amount() == 0).await;

    assert_echoes(&mut from_server).await;
}

#[tokio::test]
async fn a_reconnect_keeps_the_new_connection_registered() {
    const NAME: &str = "reconnecting";

    let key = signing_key();
    let (server, port) = start_server(&key, None).await;

    let first = start_client(NAME, &key, port, false);
    wait_until(|| server.get_gateway_connection(NAME).is_some()).await;
    let first_on_server = server.get_gateway_connection(NAME).unwrap();

    // Stop the first client's loop, so that once its connection ends it does not come back.
    drop(first);

    // The same client connects again: the new connection displaces the old one, and the old
    // one's teardown must not unregister the new one.
    let second = start_client(NAME, &key, port, false);
    wait_until(|| !first_on_server.is_gateway_connected()).await;
    wait_until(|| second.get_gateway_connection(NAME).is_some()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let registered = server
        .get_gateway_connection(NAME)
        .expect("the new connection stays registered");
    assert!(!Arc::ptr_eq(&registered, &first_on_server));

    let upstream = start_upstream(|stream| echo(stream, None)).await;
    let mut stream = second
        .get_gateway_connection(NAME)
        .unwrap()
        .connect_to_forward_proxy_connection(
            endpoint(upstream),
            CONNECT_TIMEOUT,
            second.get_next_connection_id(),
        )
        .await
        .unwrap();

    assert_echoes(&mut stream).await;
}

#[tokio::test]
async fn a_lost_gateway_connection_closes_the_connections_tunnelled_through_it() {
    let gateway = Gateway::start("lost-gateway", false).await;
    let (closed_tx, mut closed) = mpsc::unbounded_channel();
    let upstream = start_upstream(move |stream| echo(stream, Some(closed_tx.clone()))).await;

    let mut stream = gateway.connect_from_client(upstream).await;
    assert_echoes(&mut stream).await;

    gateway.server_side().disconnect_gateway();

    tokio::time::timeout(TIMEOUT, closed.recv())
        .await
        .expect("the upstream connection behind the gateway is closed");

    assert!(
        read_to_end(&mut stream).await.is_err(),
        "a stream cut short by a lost gateway must read to an error, not to EOF"
    );
}

#[tokio::test]
async fn a_dropped_stream_closes_the_upstream_connection() {
    let gateway = Gateway::start("dropped-stream", false).await;
    let (closed_tx, mut closed) = mpsc::unbounded_channel();
    let upstream = start_upstream(move |stream| echo(stream, Some(closed_tx.clone()))).await;

    let mut stream = gateway.connect_from_client(upstream).await;
    assert_echoes(&mut stream).await;

    // Split the way the h1 pipeline splits it, and drop both halves without closing anything.
    let read_half = stream.clone();
    drop(read_half);
    drop(stream);

    tokio::time::timeout(TIMEOUT, closed.recv())
        .await
        .expect("dropping the stream closes the upstream connection behind the gateway");

    let client_side = gateway.client_side();
    let server_side = gateway.server_side();
    wait_until(|| {
        client_side.get_forward_proxy_connections_amount() == 0
            && server_side.get_forward_connections_amount() == 0
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bulk_transfer_with_compression_keeps_the_gateway_connection() {
    // Incompressible, and far more than one frame may carry.
    let data = pseudo_random(12 * 1024 * 1024);

    for compression in CompressionLevel::all().filter(|level| level.is_on()) {
        let name = format!("bulk-compressed-{}", compression.as_u8());
        let gateway = Gateway::start_at(&name, compression).await;
        let server_side = gateway.server_side();

        let (collected_tx, mut collected) = mpsc::unbounded_channel();
        let upstream =
            start_upstream(move |stream| collect(stream, collected_tx.clone(), Duration::ZERO))
                .await;

        let mut stream = gateway.connect_from_client(upstream).await;

        for chunk in data.chunks(1024 * 1024) {
            stream.write_to_socket(chunk).await.unwrap();
        }
        stream.disconnect();

        let received = tokio::time::timeout(Duration::from_secs(120), collected.recv())
            .await
            .expect("the upstream connection is closed")
            .unwrap();

        assert!(
            received == data,
            "{name}: received {} of {} bytes",
            received.len(),
            data.len()
        );
        assert!(
            Arc::ptr_eq(&gateway.server_side(), &server_side),
            "{name}: the gateway connection must survive the transfer"
        );
    }
}

#[tokio::test]
async fn a_poll_write_keeps_its_place_in_the_budget_queue_when_its_buffer_changes() {
    let gateway = Gateway::start("budget-queue", false).await;
    let upstream = start_upstream(discard).await;

    let mut first = gateway.connect_from_client(upstream).await;
    let mut second = gateway.connect_from_client(upstream).await;

    let budget = gateway.client_side().write_budget_for_tests().unwrap();
    let spent = budget.forget_permits(budget.available_permits());

    // `first` takes the credit for its 100 bytes and queues for budget, then a bulk write of
    // `second` queues behind it.
    assert!(poll_write_once(&mut first, &[1u8; 100]).is_pending());
    let bulk =
        tokio::spawn(async move { second.write_to_socket(&vec![2u8; 256 * 1024]).await.is_ok() });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The caller polls again with a longer buffer, the way the h2 client does when it adds
    // frames, and with a shorter one: the request keeps its place in the queue and its permit
    // count. The credit held caps what a longer buffer may take; nothing caps a shorter one.
    assert!(poll_write_once(&mut first, &[1u8; 101]).is_pending());
    assert!(poll_write_once(&mut first, &[1u8; 60]).is_pending());

    // Exactly what `first` asked for comes back. It goes to `first`, the head of the queue, which
    // writes what that covers.
    budget.add_permits(100 + 9);
    assert!(matches!(
        poll_write_once(&mut first, &[1u8; 101]),
        Poll::Ready(Ok(100))
    ));

    budget.add_permits(spent);
    assert!(tokio::time::timeout(TIMEOUT, bulk).await.unwrap().unwrap());
}

#[tokio::test]
async fn an_upstream_which_resets_the_connection_reads_as_an_error_not_as_eof() {
    let gateway = Gateway::start("upstream-reset", false).await;
    let upstream = start_upstream(|stream| reset_after(stream, b"the first part of a body")).await;

    // With either end of the gateway as the initiator.
    for from_server in [false, true] {
        let mut stream = connect_from(&gateway, from_server, upstream).await;

        match read_to_end(&mut stream).await {
            Err(received) => assert_eq!(received, b"the first part of a body"),
            Ok(_) => panic!("a body cut short by a reset must not read as complete"),
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn a_unix_socket_upstream_is_reachable_through_the_gateway() {
    let gateway = Gateway::start("unix-upstream", false).await;

    let path = std::env::temp_dir().join(format!("gateway-unix-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });

    let endpoint = Arc::new(
        RemoteEndpointOwned::try_parse(format!("unix+http://{}", path.display())).unwrap(),
    );
    let mut stream = gateway
        .client_side()
        .connect_to_forward_proxy_connection(
            endpoint,
            CONNECT_TIMEOUT,
            gateway.client.get_next_connection_id(),
        )
        .await
        .unwrap();

    assert_echoes(&mut stream).await;

    let _ = std::fs::remove_file(&path);
}

/// The upstream answers early and closes with the upload unread, while the initiator keeps
/// uploading: the write of the rest fails. The close must not read as a clean EOF - what the
/// initiator sent did not all arrive - even when the upstream's EOF is read before the writer
/// fails.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_upload_cut_by_an_upstream_which_answered_and_closed_reads_as_an_error() {
    let gateway = Gateway::start("early-answer", false).await;
    let answer = Arc::new(pseudo_random(64 * 1024));

    let path = std::env::temp_dir().join(format!("gateway-early-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    tokio::spawn({
        let answer = answer.clone();
        async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let answer = answer.clone();
                tokio::spawn(async move {
                    let _ = stream.read_exact(&mut [0u8; 1024]).await;
                    let _ = stream.write_all(&answer).await;
                    // Closed with the rest of the upload unread.
                });
            }
        }
    });

    let endpoint = Arc::new(
        RemoteEndpointOwned::try_parse(format!("unix+http://{}", path.display())).unwrap(),
    );
    let stream = gateway
        .client_side()
        .connect_to_forward_proxy_connection(
            endpoint,
            CONNECT_TIMEOUT,
            gateway.client.get_next_connection_id(),
        )
        .await
        .unwrap();
    let (mut reader, mut writer) = split(stream);

    let upload =
        tokio::spawn(
            async move { while writer.write_to_socket(&[1u8; 16 * 1024]).await.is_ok() {} },
        );

    let received = match read_to_end(&mut reader).await {
        Ok(received) => panic!(
            "the close reads as a clean EOF after {} bytes although the upload was cut",
            received.len()
        ),
        Err(received) => received,
    };

    // It ends on its own: with flow control it parks on credit once the dead writer took a
    // window, and the close wakes it.
    tokio::time::timeout(TIMEOUT, upload)
        .await
        .expect("the upload outlived the closed connection")
        .unwrap();

    assert!(answer.starts_with(&received), "the answer arrived mangled");

    let _ = std::fs::remove_file(&path);
}

/// An h2 websocket - an RFC 8441 extended CONNECT - to an h2c upstream on a unix socket behind the
/// gateway. The socket path is no authority, so the CONNECT has to go with a placeholder one.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_h2_websocket_reaches_a_unix_socket_upstream_through_the_gateway() {
    let gateway = Gateway::start("h2-ws-unix", false).await;

    let path = std::env::temp_dir().join(format!("gateway-h2ws-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                // Accepts the CONNECT and greets through the tunnel it opens.
                let service = hyper::service::service_fn(
                    |mut request: hyper::Request<hyper::body::Incoming>| async move {
                        let on_upgrade = hyper::upgrade::on(&mut request);
                        tokio::spawn(async move {
                            if let Ok(upgraded) = on_upgrade.await {
                                let mut upgraded = hyper_util::rt::TokioIo::new(upgraded);
                                let _ = upgraded.write_all(b"hello").await;
                                let _ = upgraded.read(&mut [0u8; 16]).await;
                            }
                        });

                        Ok::<_, std::convert::Infallible>(hyper::Response::new(
                            http_body_util::Empty::<bytes::Bytes>::new(),
                        ))
                    },
                );

                let _ =
                    hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                        .enable_connect_protocol()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
            });
        }
    });

    let endpoint = Arc::new(
        RemoteEndpointOwned::try_parse(format!("unix+http://{}", path.display())).unwrap(),
    );
    let client = crate::my_http2_client::MyHttp2Client::new(TestGatewayConnector::new(
        gateway.client_side(),
        endpoint,
    ));

    let mut headers = hyper::HeaderMap::new();
    headers.insert(
        "sec-websocket-version",
        hyper::header::HeaderValue::from_static("13"),
    );
    let mut tunnel =
        tokio::time::timeout(TIMEOUT, client.do_extended_connect("/ws", headers, TIMEOUT))
            .await
            .expect("the extended CONNECT got no answer")
            .expect("the extended CONNECT failed");

    let mut greeting = [0u8; 5];
    tokio::time::timeout(TIMEOUT, tunnel.read_exact(&mut greeting))
        .await
        .expect("no greeting through the tunnel")
        .unwrap();
    assert_eq!(&greeting, b"hello");

    let _ = std::fs::remove_file(&path);
}

/// A port forward's two pumps: the tunnel connection closes after the response, while the client
/// is still sending. The pump which stops forwarding the client must not close the client socket
/// with unread input in it - that resets the connection and loses the response tail.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_response_tail_reaches_a_client_which_keeps_sending() {
    let gateway = Gateway::start("chatty-client", false).await;

    let answer = Arc::new(pseudo_random(4 * 1024 * 1024));
    let upstream = {
        let answer = answer.clone();
        start_upstream(move |stream| answer_then_close(stream, answer.clone())).await
    };

    let (client, _pumps) = port_forward(
        gateway.connect_from_client(upstream).await,
        HttpTimeouts::default(),
    )
    .await;

    let (mut client_read, mut client_write) = client.into_split();
    let chatter = tokio::spawn(async move {
        while client_write.write_all(&[7u8; 512]).await.is_ok() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    });

    let mut received = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let read_result = tokio::time::timeout(TIMEOUT, client_read.read(&mut buf))
            .await
            .expect("the response stalled");

        match read_result {
            Ok(0) => break,
            Ok(read_size) => received.extend_from_slice(&buf[..read_size]),
            Err(err) => panic!(
                "the client lost the connection after {} of {} bytes: {err}",
                received.len(),
                answer.len()
            ),
        }
    }

    chatter.abort();
    assert!(
        received == *answer,
        "received {} of {} bytes",
        received.len(),
        answer.len()
    );
}

/// A port forward carrying a one-way stream: the client sends for three read timeouts while the
/// upstream sends nothing back. The connection is not idle - only one direction of it is - so the
/// silent direction must not end it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_one_way_stream_outlives_the_read_timeout_of_its_silent_direction() {
    let gateway = Gateway::start("one-way", false).await;
    let (collected_tx, mut collected) = mpsc::unbounded_channel();
    let upstream =
        start_upstream(move |stream| collect(stream, collected_tx.clone(), Duration::ZERO)).await;

    let (client, _pumps) =
        port_forward(gateway.connect_from_client(upstream).await, IDLE_TIMEOUTS).await;
    let (_client_read, mut client_write) = client.into_split();

    let mut sent = Vec::new();
    for step in 0..15u8 {
        tokio::time::sleep(IDLE_TIMEOUTS.read_timeout / 5).await;

        let chunk = [step; 100];
        client_write.write_all(&chunk).await.unwrap();
        sent.extend_from_slice(&chunk);
    }
    client_write.shutdown().await.unwrap();

    let received = tokio::time::timeout(TIMEOUT, collected.recv())
        .await
        .expect("the upstream did not see the close")
        .unwrap();
    assert!(
        received == sent,
        "the upstream received {} of {} bytes",
        received.len(),
        sent.len()
    );
}

/// Neither the client nor the upstream sends anything: the port forward ends once the connection
/// has been idle for the read timeout, and the upstream sees the close.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_silent_both_ways_ends_after_the_read_timeout() {
    let gateway = Gateway::start("silent", false).await;
    let (closed_tx, mut closed) = mpsc::unbounded_channel();
    let upstream = start_upstream(move |stream| echo(stream, Some(closed_tx.clone()))).await;

    let stream = gateway.connect_from_client(upstream).await;
    let started = Instant::now();
    let (_client, pumps) = port_forward(stream, IDLE_TIMEOUTS).await;

    tokio::time::timeout(TIMEOUT, closed.recv())
        .await
        .expect("the idle connection is still open")
        .unwrap();
    assert!(
        started.elapsed() >= IDLE_TIMEOUTS.read_timeout * 8 / 10,
        "closed after {:?}, before the read timeout",
        started.elapsed()
    );

    for pump in pumps {
        tokio::time::timeout(TIMEOUT, pump)
            .await
            .expect("a pump outlived the idle connection")
            .unwrap();
    }
}

/// The same, with a client which reads nothing for longer than a fixed linger would wait. The
/// client is read for as long as the tail is on its way to it, however long that takes, and until
/// it closes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_response_tail_reaches_a_slow_client_which_keeps_sending() {
    let gateway = Gateway::start("slow-chatty-client", false).await;

    let answer = Arc::new(pseudo_random(4 * 1024 * 1024));
    let upstream = {
        let answer = answer.clone();
        start_upstream(move |stream| answer_then_close(stream, answer.clone())).await
    };

    let (client, _pumps) = port_forward(
        gateway.connect_from_client(upstream).await,
        HttpTimeouts::default(),
    )
    .await;

    let (mut client_read, mut client_write) = client.into_split();
    let chatter = tokio::spawn(async move {
        while client_write.write_all(&[7u8; 512]).await.is_ok() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });

    // The tunnel connection closes meanwhile: the upstream sends it all and closes at once.
    tokio::time::sleep(Duration::from_secs(6)).await;

    let mut received = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let read_result = tokio::time::timeout(TIMEOUT, client_read.read(&mut buf))
            .await
            .expect("the response stalled");

        match read_result {
            Ok(0) => break,
            Ok(read_size) => received.extend_from_slice(&buf[..read_size]),
            Err(err) => panic!(
                "the client lost the connection after {} of {} bytes: {err}",
                received.len(),
                answer.len()
            ),
        }
    }

    chatter.abort();
    assert!(
        received == *answer,
        "received {} of {} bytes",
        received.len(),
        answer.len()
    );
}

/// The initiator uploads and closes while the upstream keeps sending. The acceptor must keep
/// reading the upstream until its writer has flushed the upload - closing the socket with unread
/// input in it resets the connection and loses the upload tail.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_upload_tail_reaches_an_upstream_which_keeps_sending() {
    let gateway = Gateway::start("chatty-upstream", false).await;
    let (collected_tx, mut collected) = mpsc::unbounded_channel();
    let upstream =
        start_upstream(move |stream| chatter_then_collect(stream, collected_tx.clone())).await;

    let mut stream = gateway.connect_from_client(upstream).await;

    let data = pseudo_random(3 * 1024 * 1024);
    for chunk in data.chunks(256 * 1024) {
        stream.write_to_socket(chunk).await.unwrap();
    }
    stream.disconnect();

    let received = tokio::time::timeout(TIMEOUT, collected.recv())
        .await
        .expect("the upstream connection is closed")
        .unwrap();

    assert!(
        received == data,
        "received {} of {} bytes",
        received.len(),
        data.len()
    );
}

#[tokio::test]
async fn a_device_file_is_not_served() {
    let gateway = Gateway::start("device-file", false).await;

    let result = tokio::time::timeout(TIMEOUT, gateway.client_side().request_file("/dev/zero"))
        .await
        .expect("a device file is refused at once, not read without end");

    assert!(matches!(result, Err(FileRequestError::FileNotFound)));
}

/// The hyper clients of the http2 endpoints drive a gateway stream through
/// `tokio::io::AsyncRead + AsyncWrite`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hyper_http1_client_works_over_a_gateway_stream() {
    let gateway = Gateway::start("hyper-h1", false).await;
    let upstream = start_hyper_upstream(false).await;

    let stream = gateway.connect_from_client(upstream).await;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(connection);

    // Bigger than the write budget, so the upload waits for room more than once.
    let upload = pseudo_random(3 * 1024 * 1024);
    assert_eq!(
        send_hyper_request(&mut sender, "/upload", upload.clone()).await,
        format!("received {} bytes", upload.len()).into_bytes()
    );

    // The same connection again, reading a big response.
    assert_eq!(
        send_hyper_request(&mut sender, "/download", Vec::new()).await,
        download_body()
    );
}

/// A websocket to an upstream behind the gateway, pumped the way the http2 endpoints pump one. The
/// upstream sends a burst and its Close, and closes; the client reads nothing for a while, then
/// sends a frame. That frame fails - the upstream is gone - but the burst and the Close it sent
/// before going must still reach the client.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_websocket_client_gets_the_upstream_tail_after_a_frame_it_sent_fails() {
    use futures::{SinkExt, StreamExt};
    use hyper_tungstenite::tungstenite::Message;

    const MESSAGES: usize = 100;

    let gateway = Gateway::start("ws-tail", false).await;
    let upstream = start_upstream(|stream| websocket_burst_then_close(stream, MESSAGES)).await;
    let port = start_websocket_pump(gateway.connect_from_client(upstream).await).await;
    let mut websocket = connect_websocket_client(port).await;

    // Long enough for the whole burst to wait in the tunnel, the upstream closed behind it.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    websocket.send(Message::text("heartbeat")).await.unwrap();

    let mut messages = 0;
    loop {
        let message = tokio::time::timeout(TIMEOUT, websocket.next())
            .await
            .expect("the websocket stalled");

        match message {
            Some(Ok(Message::Binary(_))) => messages += 1,
            Some(Ok(Message::Close(_))) => break,
            Some(Ok(_)) => {}
            other => {
                panic!("the websocket ended after {messages} messages without the Close: {other:?}")
            }
        }
    }

    assert_eq!(messages, MESSAGES);
}

/// The same over an RFC 8441 websocket - an h2 client's extended CONNECT - which the http2 endpoints
/// pump as raw bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_h2_websocket_client_gets_the_upstream_tail_after_a_frame_it_sent_fails() {
    use futures::{SinkExt, StreamExt};
    use hyper_tungstenite::tungstenite::Message;

    const MESSAGES: usize = 100;

    let gateway = Gateway::start("ws-tail-h2", false).await;
    let upstream = start_upstream(|stream| websocket_burst_then_close(stream, MESSAGES)).await;
    let port = start_h2_websocket_pump(gateway.connect_from_client(upstream).await).await;
    let mut websocket = connect_h2_websocket_client(port).await;

    // Long enough for the whole burst to wait in the tunnel, the upstream closed behind it.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    websocket.send(Message::text("heartbeat")).await.unwrap();

    let mut messages = 0;
    loop {
        let message = tokio::time::timeout(TIMEOUT, websocket.next())
            .await
            .expect("the websocket stalled");

        match message {
            Some(Ok(Message::Binary(_))) => messages += 1,
            Some(Ok(Message::Close(_))) => break,
            Some(Ok(_)) => {}
            other => {
                panic!("the websocket ended after {messages} messages without the Close: {other:?}")
            }
        }
    }

    assert_eq!(messages, MESSAGES);
}

/// A Ping in the upstream's tail: tungstenite answers it with a Pong, written into a tunnel which
/// is closed by then. That must not cost the rest of the tail.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_websocket_client_gets_the_upstream_tail_past_a_ping() {
    use futures::StreamExt;
    use hyper_tungstenite::tungstenite::Message;

    const MESSAGES: usize = 100;

    let gateway = Gateway::start("ws-tail-ping", false).await;
    let upstream = start_upstream(|stream| {
        websocket_burst_with_ping_then_close(stream, MESSAGES, Some(MESSAGES - 5))
    })
    .await;
    let port = start_websocket_pump(gateway.connect_from_client(upstream).await).await;
    let mut websocket = connect_websocket_client(port).await;

    // The burst and the upstream's close are in the tunnel before the Ping is read.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let mut messages = 0;
    loop {
        let message = tokio::time::timeout(TIMEOUT, websocket.next())
            .await
            .expect("the websocket stalled");

        match message {
            Some(Ok(Message::Binary(_))) => messages += 1,
            Some(Ok(Message::Close(_))) => break,
            Some(Ok(_)) => {}
            other => {
                panic!("the websocket ended after {messages} messages without the Close: {other:?}")
            }
        }
    }

    assert_eq!(messages, MESSAGES);
}

/// An h2 client which stops reading and half-closes while the upstream sends more than its window
/// and closes: the session still ends within the timeouts, instead of waiting on a shutdown the
/// client never lets through.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_h2_websocket_session_ends_when_its_client_stops_reading_and_half_closes() {
    let gateway = Gateway::start("ws-h2-stuck", false).await;
    let burst = Arc::new(vec![9u8; 256 * 1024]);
    let upstream = {
        let burst = burst.clone();
        start_upstream(move |stream| send_and_close(stream, burst.clone())).await
    };

    let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut ctx = websocket_pump_context();
    ctx.timeouts = HttpTimeouts {
        read_timeout: Duration::from_secs(3),
        write_timeout: Duration::from_secs(1),
    };
    ctx.disconnection = Arc::new(RecordDisconnect(ended.clone()));
    let port = start_h2_websocket_pump_with(gateway.connect_from_client(upstream).await, ctx).await;

    let mut tunnel = connect_h2_tunnel(port, 64 * 1024).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    tunnel.shutdown().await.unwrap();

    wait_until_within(Duration::from_secs(10), || ended.load(Ordering::Relaxed)).await;
    drop(tunnel);
}

/// An h2 client which stops reading while the upstream's tail is just past its window: the tail is
/// all handed over, the upstream half-closes, and the end of the stream can not reach the client.
/// That is a write timeout: the session ends then, not at the idle limit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_h2_websocket_session_ends_when_its_end_can_not_reach_the_client() {
    let gateway = Gateway::start("ws-h2-end-stuck", false).await;
    let tail = Arc::new(vec![9u8; 80 * 1024]);
    let upstream = {
        let tail = tail.clone();
        start_upstream(move |stream| answer_then_close(stream, tail.clone())).await
    };

    let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut ctx = websocket_pump_context();
    ctx.timeouts = HttpTimeouts {
        read_timeout: Duration::from_secs(30),
        write_timeout: Duration::from_secs(1),
    };
    ctx.disconnection = Arc::new(RecordDisconnect(ended.clone()));
    let port = start_h2_websocket_pump_with(gateway.connect_from_client(upstream).await, ctx).await;

    let tunnel = connect_h2_tunnel(port, 64 * 1024).await;
    let started = Instant::now();
    wait_until_within(Duration::from_secs(10), || ended.load(Ordering::Relaxed)).await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the session ended after {:?}",
        started.elapsed()
    );
    drop(tunnel);
}

/// A client which leaves in the middle of a streaming response - the normal end of an SSE session -
/// drops the body before its end. The pool client is still reading that response, so it must not go
/// back to the pool: the next request would queue behind a body which never ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_abandoned_streaming_body_keeps_its_pool_client_out_of_the_pool() {
    use http_body_util::BodyExt;
    use my_http_client::http1::{MyHttpRequestBuilder, MyHttpResponse};

    let gateway = Gateway::start("abandoned-body", false).await;
    let upstream = start_hyper_upstream(false).await;

    let pool = crate::http_client_pool::HttpClientPool::new();
    let connector = || TestGatewayConnector::new(gateway.client_side(), endpoint(upstream));
    let get = |path: &str| {
        MyHttpRequestBuilder::new(hyper::Method::GET, path)
            .append_header("Host", "upstream")
            .build()
            .unwrap()
    };

    let pooled = || {
        let mut pooled = std::collections::HashMap::new();
        pool.fill_connections_amount(&mut pooled);
        pooled.get("upstream").copied().unwrap_or(0)
    };

    // A body read to its end gives the client back.
    let client = pool.get("upstream".into(), CONNECT_TIMEOUT, None, connector);
    let MyHttpResponse::Response(response) =
        client.do_request(&get("/answer"), TIMEOUT).await.unwrap()
    else {
        panic!("not an upgrade");
    };
    let response =
        crate::http_proxy_pass::content_source::attach_conn_guard(response, Box::new(client));
    response.into_body().collect().await.unwrap();
    assert_eq!(pooled(), 1);

    // The same client, now for a stream the client of the proxy leaves after the first event.
    let client = pool.get("upstream".into(), CONNECT_TIMEOUT, None, connector);
    let MyHttpResponse::Response(response) =
        client.do_request(&get("/stream"), TIMEOUT).await.unwrap()
    else {
        panic!("not an upgrade");
    };
    let mut response =
        crate::http_proxy_pass::content_source::attach_conn_guard(response, Box::new(client));

    tokio::time::timeout(TIMEOUT, response.body_mut().frame())
        .await
        .expect("the first event did not come")
        .unwrap()
        .unwrap();
    drop(response);
    assert_eq!(pooled(), 0);

    let client = pool.get("upstream".into(), CONNECT_TIMEOUT, None, connector);
    let MyHttpResponse::Response(response) = tokio::time::timeout(
        Duration::from_secs(3),
        client.do_request(&get("/answer"), TIMEOUT),
    )
    .await
    .expect("the next request waits behind the abandoned stream")
    .unwrap() else {
        panic!("not an upgrade");
    };
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "received 0 bytes".as_bytes()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hyper_h2c_client_works_over_a_gateway_stream() {
    let gateway = Gateway::start("hyper-h2c", false).await;
    let upstream = start_hyper_upstream(true).await;

    let stream = gateway.connect_from_client(upstream).await;
    let (sender, connection) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(stream),
    )
    .await
    .unwrap();
    tokio::spawn(connection);

    // Concurrent streams over the one tunnelled connection.
    let upload = pseudo_random(3 * 1024 * 1024);
    let requests: Vec<_> = (0..4)
        .map(|index| {
            let mut sender = sender.clone();
            let upload = upload.clone();
            tokio::spawn(async move {
                if index % 2 == 0 {
                    send_h2_request(&mut sender, "/upload", upload).await
                } else {
                    send_h2_request(&mut sender, "/download", Vec::new()).await
                }
            })
        })
        .collect();

    for (index, request) in requests.into_iter().enumerate() {
        let body = request.await.unwrap();
        if index % 2 == 0 {
            assert_eq!(
                body,
                format!("received {} bytes", upload.len()).into_bytes()
            );
        } else {
            assert!(body == download_body());
        }
    }
}

#[tokio::test]
async fn a_connect_to_a_closed_port_fails_and_leaves_nothing_behind() {
    let gateway = Gateway::start("closed-port", false).await;
    let closed_port = free_port().await;

    let client_side = gateway.client_side();
    let result = client_side
        .connect_to_forward_proxy_connection(
            endpoint(closed_port),
            CONNECT_TIMEOUT,
            gateway.client.get_next_connection_id(),
        )
        .await;

    assert!(result.is_err());
    wait_until(|| client_side.get_forward_proxy_connections_amount() == 0).await;
}

#[tokio::test]
async fn a_file_too_big_for_one_frame_is_refused_without_dropping_the_gateway() {
    let gateway = Gateway::start("file-limit", false).await;
    let server_side = gateway.server_side();
    let client_side = gateway.client_side();

    let dir = std::env::temp_dir().join(format!("gateway-file-limit-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let small = dir.join("small.bin");
    std::fs::write(&small, b"small file").unwrap();
    let big = dir.join("big.bin");
    std::fs::write(&big, vec![1u8; MAX_FILE_RESPONSE_SIZE + 1]).unwrap();

    let small_path = small.to_str().unwrap();
    let big_path = big.to_str().unwrap();

    assert_eq!(
        client_side.request_file(small_path).await.ok(),
        Some(b"small file".to_vec())
    );
    assert!(matches!(
        client_side.request_file(big_path).await,
        Err(FileRequestError::FileNotFound)
    ));
    assert_eq!(
        client_side.request_file(small_path).await.ok(),
        Some(b"small file".to_vec())
    );
    assert!(Arc::ptr_eq(&gateway.server_side(), &server_side));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn more_file_requests_than_response_slots_are_all_answered() {
    let gateway = Gateway::start("many-files", false).await;
    let client_side = gateway.client_side();

    let dir = std::env::temp_dir().join(format!("gateway-many-files-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("file.bin");
    std::fs::write(&file, b"served").unwrap();
    let path = file.to_str().unwrap().to_string();

    let requests: Vec<_> = (0..20)
        .map(|_| {
            let client_side = client_side.clone();
            let path = path.clone();
            tokio::spawn(async move { client_side.request_file(&path).await.ok() })
        })
        .collect();

    for request in requests {
        assert_eq!(request.await.unwrap(), Some(b"served".to_vec()));
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn allowed_ip_lets_only_the_listed_addresses_in() {
    let key = signing_key();

    let (server, port) = start_server(&key, Some(&["10.20.30.40"])).await;
    let _client = start_client("not-listed", &key, port, false);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(server.get_gateway_connection("not-listed").is_none());

    let (server, port) = start_server(&key, Some(&["127.0.0.1"])).await;
    let _client = start_client("listed", &key, port, false);
    wait_until(|| server.get_gateway_connection("listed").is_some()).await;
}

/// A port which can not be had fails the construction of the server - `AppContext::new` unwraps
/// it, which ends the startup - instead of leaving a server which listens nowhere.
#[tokio::test]
async fn a_server_does_not_start_on_a_taken_port() {
    let key = signing_key();
    let (_first, port) = start_server(&key, None).await;

    let second = TcpGatewayServer::new(
        format!("127.0.0.1:{port}"),
        vec![key.verifying_key()],
        None,
        false,
    );

    let Err(err) = second else {
        panic!("a second server started on the port of the first");
    };
    assert!(err.contains(&format!("127.0.0.1:{port}")), "{err}");
}

/// A flush to the target which gives up resets the connection instead of shutting it down: the
/// target must not take the part of the stream it got for all of it.
#[tokio::test]
async fn a_target_connection_given_up_on_reads_as_reset_not_as_end_of_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut target = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (accepted, _) = listener.accept().await.unwrap();
    let (accepted_read, accepted_write) = accepted.into_split();

    let mut accepted_write = crate::network_stream::MyOwnedWriteHalf::Tcp(accepted_write);
    accepted_write.reset();
    drop(accepted_read);

    let read_result = tokio::time::timeout(TIMEOUT, target.read(&mut [0u8; 16]))
        .await
        .expect("the target got neither an end of stream nor a reset");
    assert!(
        read_result.is_err(),
        "the target read {read_result:?} instead of a reset"
    );
}

/// A pool client reconnects with the connect timeout it was created with, and sends it in
/// `CONNECT`: two locations with different connect timeouts must not share clients.
#[test]
fn locations_with_different_connect_timeouts_get_pool_clients_of_their_own() {
    use crate::http_proxy_pass::content_source::pool_key;

    let upstream = endpoint(8080);
    let fail_fast = pool_key("gw", &upstream, Duration::from_secs(2));

    assert_ne!(
        fail_fast,
        pool_key("gw", &upstream, Duration::from_secs(30))
    );
    assert_eq!(fail_fast, pool_key("gw", &upstream, Duration::from_secs(2)));
}

#[test]
fn allowed_ip_takes_ranges_and_ipv4_mapped_addresses() {
    let list = WhiteListedIpList::new(&["10.0.0.5-10.0.0.9".to_string()]);

    assert!(is_ip_allowed(&list, "10.0.0.7".parse().unwrap()));
    assert!(!is_ip_allowed(&list, "10.0.0.10".parse().unwrap()));
    assert!(is_ip_allowed(&list, "::ffff:10.0.0.5".parse().unwrap()));
    assert!(!is_ip_allowed(&list, "::1".parse().unwrap()));
}

#[test]
fn short_frames_are_rejected_instead_of_panicking() {
    for packet_type in 0u8..=32 {
        for len in 0..10 {
            let mut frame = vec![packet_type];
            frame.extend(std::iter::repeat_n(0u8, len));
            let _ = TcpGatewayContract::parse(&frame);
        }
    }

    assert!(TcpGatewayContract::parse(&[14]).is_err());
    assert!(TcpGatewayContract::parse(&[6, 1, 2]).is_err());
    assert!(TcpGatewayContract::parse(&[10, 1, 0, 0, 0]).is_err());
    // CONNECT: the id, the timeout and only 3 bytes of the window.
    assert!(TcpGatewayContract::parse(&[14, 1, 0, 0, 0, 5, 0, 0, 0]).is_err());
    // WINDOW_UPDATE: the id and only 3 bytes of the credit.
    assert!(TcpGatewayContract::parse(&[15, 1, 0, 0, 0, 0, 0, 0]).is_err());
}

#[test]
fn the_connect_timeout_survives_the_wire() {
    fn over_the_wire(timeout: Duration) -> Duration {
        let frame = TcpGatewayContract::Connect {
            connection_id: 1,
            timeout,
            remote_host: "localhost:80",
            receive_window: FLOW_CONTROL_WINDOW as u32,
        }
        .to_plain_frame();

        match TcpGatewayContract::parse(&frame[4..]).unwrap() {
            TcpGatewayContract::Connect { timeout, .. } => timeout,
            other => panic!("parsed as {:?}", other),
        }
    }

    assert_eq!(
        over_the_wire(Duration::from_millis(500)),
        Duration::from_secs(1)
    );
    assert_eq!(
        over_the_wire(Duration::from_millis(5500)),
        Duration::from_secs(6)
    );
    assert_eq!(
        over_the_wire(Duration::from_secs(5)),
        Duration::from_secs(5)
    );
    assert_eq!(
        over_the_wire(Duration::from_secs(600)),
        Duration::from_secs(255)
    );
}

// Flow control.

#[test]
fn ping_and_pong_are_bare_frames() {
    assert_eq!(
        TcpGatewayContract::Ping.to_plain_frame(),
        vec![1, 0, 0, 0, 0]
    );
    assert_eq!(
        TcpGatewayContract::Pong.to_plain_frame(),
        vec![1, 0, 0, 0, 1]
    );

    assert!(matches!(
        TcpGatewayContract::parse(&[0]).unwrap(),
        TcpGatewayContract::Ping
    ));
    assert!(matches!(
        TcpGatewayContract::parse(&[1]).unwrap(),
        TcpGatewayContract::Pong
    ));

    // Both are read by the type alone.
    assert!(matches!(
        TcpGatewayContract::parse(&[0, 3]).unwrap(),
        TcpGatewayContract::Ping
    ));
    assert!(matches!(
        TcpGatewayContract::parse(&[1, 1, 7, 7]).unwrap(),
        TcpGatewayContract::Pong
    ));
}

/// The frame types protocol version 1 had and version 2 has not - `HANDSHAKE`, `CONNECT` without
/// a window, `COMPRESSED_BATCH` - and one which never was.
#[test]
fn frame_types_which_are_none_any_more_are_unknown() {
    for packet_type in [2u8, 3, 18, 20, 255] {
        let err =
            TcpGatewayContract::parse(&[packet_type, 1, 0, 0, 0, 5, b'h', b':', b'1']).unwrap_err();
        assert!(
            err.starts_with("Unknown packet type"),
            "{packet_type}: {err}"
        );
    }
}

#[test]
fn a_connect_carries_the_receive_window() {
    let connect = TcpGatewayContract::Connect {
        connection_id: 5,
        timeout: Duration::from_secs(5),
        remote_host: "h:1",
        receive_window: FLOW_CONTROL_WINDOW as u32,
    }
    .to_plain_frame();

    assert_eq!(
        connect,
        vec![13, 0, 0, 0, 14, 5, 0, 0, 0, 5, 0, 0, 0x80, 0, b'h', b':', b'1']
    );

    match TcpGatewayContract::parse(&connect[4..]).unwrap() {
        TcpGatewayContract::Connect {
            connection_id: 5,
            timeout,
            remote_host: "h:1",
            receive_window,
        } => {
            assert_eq!(timeout, Duration::from_secs(5));
            assert_eq!(receive_window as usize, FLOW_CONTROL_WINDOW);
        }
        other => panic!("parsed as {:?}", other),
    }

    // CONNECT without a window - type 3 of protocol version 1 - is not a frame type any more.
    let err = TcpGatewayContract::parse(&[3, 5, 0, 0, 0, 5, b'h', b':', b'1']).unwrap_err();
    assert!(err.starts_with("Unknown packet type"), "{err}");
}

#[test]
fn a_window_update_round_trips() {
    let frame = TcpGatewayContract::WindowUpdate {
        connection_id: 0x8000_0001,
        credit: 512 * 1024,
    }
    .to_plain_frame();

    assert_eq!(frame, vec![9, 0, 0, 0, 15, 1, 0, 0, 0x80, 0, 0, 8, 0]);

    assert!(matches!(
        TcpGatewayContract::parse(&frame[4..]).unwrap(),
        TcpGatewayContract::WindowUpdate {
            connection_id: 0x8000_0001,
            credit: 524_288
        }
    ));
}

#[test]
fn every_byte_received_is_credited_once_it_is_consumed() {
    let counter = ReceiveCounter::default();
    assert!(counter.received(FLOW_CONTROL_WINDOW));
    assert!(!counter.received(1), "past the window");

    let counter = ReceiveCounter::default();
    assert!(counter.received(FLOW_CONTROL_UPDATE_THRESHOLD + 10));
    assert_eq!(counter.consumed(FLOW_CONTROL_UPDATE_THRESHOLD - 1), None);
    assert_eq!(counter.held(), 11);
    assert_eq!(
        counter.consumed(1),
        Some(FLOW_CONTROL_UPDATE_THRESHOLD as u32)
    );
    assert_eq!(counter.held(), 10);
    // Nothing owed is credited twice.
    assert_eq!(counter.consumed(10), None);
    assert_eq!(counter.held(), 0);

    assert!(initial_credit_is_enough(MIN_RECEIVE_WINDOW));
    assert!(!initial_credit_is_enough(MIN_RECEIVE_WINDOW - 1));
}

#[test]
fn credit_from_a_broken_peer_saturates_instead_of_overflowing() {
    let window = tokio::sync::Semaphore::new(0);
    add_credit(&window, u32::MAX);
    assert_eq!(window.available_permits(), MAX_SEND_CREDIT);
    add_credit(&window, 1);
    assert_eq!(window.available_permits(), MAX_SEND_CREDIT);
}

#[test]
fn the_raw_writer_coalesces_small_payloads_and_moves_big_ones() {
    let mut queue = std::collections::VecDeque::new();
    for index in 0..100_000u32 {
        super::session::push_coalesced_for_tests(&mut queue, vec![index as u8]);
    }
    assert_eq!(queue.len(), 1, "100 000 one-byte payloads fit one write");

    let big = vec![7u8; MAX_PAYLOAD_CHUNK];
    let big_at = big.as_ptr();
    super::session::push_coalesced_for_tests(&mut queue, big);
    assert_eq!(queue.len(), 2);
    assert_eq!(queue.back().unwrap().as_ptr(), big_at, "moved, not copied");

    let expected: Vec<u8> = (0..100_000u32)
        .map(|index| index as u8)
        .chain(std::iter::repeat_n(7u8, MAX_PAYLOAD_CHUNK))
        .collect();
    let written: Vec<u8> = queue.into_iter().flatten().collect();
    assert!(written == expected, "the order is kept");
}

#[tokio::test]
async fn tiny_payloads_cost_about_their_bytes() {
    // 100 000 bytes: far below the window, and below what is credited back.
    let (gateway_writer, _peer) = lone_gateway_writer().await;
    let buffer =
        super::forwarded_connection::ProxyReceiveBuffer::new(ReceiveWindow::new(1, gateway_writer));
    for index in 0..100_000u32 {
        assert!(buffer.extend_from_slice(&[index as u8]));
    }
    assert!(buffer.chunk_count() <= 2, "{} chunks", buffer.chunk_count());

    let mut read = Vec::new();
    let mut out = [0u8; 4096];
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    while let Poll::Ready(Ok(read_size)) = buffer.poll_read(&mut cx, &mut out) {
        if read_size == 0 {
            break;
        }
        read.extend_from_slice(&out[..read_size]);
        if read.len() == 100_000 {
            break;
        }
    }

    let expected: Vec<u8> = (0..100_000u32).map(|index| index as u8).collect();
    assert!(read == expected);
}

/// A connection opens with a full window, from either end: the acceptor's window comes ahead of
/// CONNECT_OK.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_opens_with_a_full_window_from_either_end() {
    let gateway = Gateway::start("fc-on", false).await;
    let upstream = start_upstream(|stream| echo(stream, None)).await;

    for mut stream in [
        gateway.connect_from_client(upstream).await,
        gateway.connect_from_server(upstream).await,
    ] {
        assert_eq!(
            stream.send_window_for_tests().available_permits(),
            FLOW_CONTROL_WINDOW
        );
        assert_echoes(&mut stream).await;
    }
}

/// Connects opened the moment the gateway connection is registered, from both ends at once -
/// pools dial exactly then, after every reconnect.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connections_opened_right_after_registration_work() {
    let gateway = Arc::new(Gateway::start("fc-early", false).await);
    let upstream = start_upstream(|stream| echo(stream, None)).await;

    let tasks: Vec<_> = (0..20)
        .map(|index| {
            let gateway = gateway.clone();
            tokio::spawn(async move {
                let mut stream = if index % 2 == 0 {
                    gateway.connect_from_client(upstream).await
                } else {
                    gateway.connect_from_server(upstream).await
                };

                assert_echoes(&mut stream).await;
            })
        })
        .collect();

    for task in tasks {
        tokio::time::timeout(TIMEOUT, task)
            .await
            .expect("a connect is stuck")
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connections_open_again_after_a_reconnect() {
    let gateway = Gateway::start("fc-reconnect", false).await;
    let (first_server_side, first_client_side) = (gateway.server_side(), gateway.client_side());

    first_server_side.disconnect_gateway();

    wait_until(|| {
        let renewed = |side: Option<Arc<TcpGatewayConnection>>,
                       first: &Arc<TcpGatewayConnection>| {
            side.is_some_and(|side| !Arc::ptr_eq(&side, first))
        };

        renewed(
            gateway.server.get_gateway_connection(&gateway.name),
            &first_server_side,
        ) && renewed(
            gateway.client.get_gateway_connection(&gateway.name),
            &first_client_side,
        )
    })
    .await;

    let upstream = start_upstream(|stream| echo(stream, None)).await;
    let mut stream = gateway.connect_from_client(upstream).await;
    assert_eq!(
        stream.send_window_for_tests().available_permits(),
        FLOW_CONTROL_WINDOW
    );
    assert_echoes(&mut stream).await;
}

/// Four windows of data: more than a window, the acceptor's read buffer and the kernel buffers of
/// both sockets together, so a sender which is held back stalls visibly.
const MORE_THAN_THE_BUFFERS: usize = 4 * FLOW_CONTROL_WINDOW;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_reader_bounds_what_the_initiator_holds() {
    let gateway = Gateway::start("fc-slow-reader", false).await;

    let data = Arc::new(pseudo_random(MORE_THAN_THE_BUFFERS));
    let progress = Arc::new(AtomicUsize::new(0));
    let upstream = {
        let (data, progress) = (data.clone(), progress.clone());
        start_upstream(move |stream| send_counting(stream, data.clone(), progress.clone())).await
    };

    let mut stream = gateway.connect_from_client(upstream).await;

    let sent = wait_for_stall(&progress).await;
    assert!(
        sent < data.len(),
        "the upstream wrote it all: nothing held it back"
    );
    assert!(
        stream.buffered_for_tests() <= FLOW_CONTROL_WINDOW,
        "the initiator holds {} bytes",
        stream.buffered_for_tests()
    );

    assert!(read_to_end(&mut stream).await.unwrap() == *data);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_target_which_stops_reading_bounds_what_the_acceptor_holds() {
    let gateway = Gateway::start("fc-slow-target", false).await;

    let (go, go_watch) = tokio::sync::watch::channel(false);
    let (collected_tx, mut collected) = mpsc::unbounded_channel();
    let upstream = start_upstream(move |mut stream| {
        let (mut go_watch, collected_tx) = (go_watch.clone(), collected_tx.clone());
        async move {
            let _ = go_watch.wait_for(|go| *go).await;
            let mut received = Vec::new();
            let _ = stream.read_to_end(&mut received).await;
            let _ = collected_tx.send(received);
        }
    })
    .await;

    let connection_id = gateway.client.get_next_connection_id();
    let stream = gateway
        .client_side()
        .connect_to_forward_proxy_connection(endpoint(upstream), CONNECT_TIMEOUT, connection_id)
        .await
        .unwrap();

    let data = Arc::new(pseudo_random(MORE_THAN_THE_BUFFERS));
    let progress = Arc::new(AtomicUsize::new(0));
    let writer = {
        let (data, progress) = (data.clone(), progress.clone());
        tokio::spawn(async move {
            let mut stream = stream;
            for piece in data.chunks(64 * 1024) {
                stream.write_to_socket(piece).await.unwrap();
                progress.fetch_add(piece.len(), Ordering::Relaxed);
            }
            stream.disconnect();
        })
    };

    let written = wait_for_stall(&progress).await;
    assert!(
        written < data.len(),
        "everything was taken: nothing held the writer back"
    );
    let held = gateway
        .server_side()
        .forward_buffered_for_tests(connection_id)
        .unwrap();
    assert!(
        held <= FLOW_CONTROL_WINDOW,
        "the acceptor holds {held} bytes"
    );

    go.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(60), writer)
        .await
        .expect("the writer is stuck")
        .unwrap();

    let received = tokio::time::timeout(Duration::from_secs(60), collected.recv())
        .await
        .expect("the upstream did not see the close")
        .unwrap();
    assert!(received == *data);
}

/// A connection whose reader - or whose target - takes nothing waits for credit holding no write
/// budget, and another connection on the same gateway connection still moves at full speed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stalled_connection_holds_no_budget_and_blocks_no_other() {
    let gateway = Gateway::start("fc-stalled", false).await;
    let echo_upstream = start_upstream(|stream| echo(stream, None)).await;

    // A reader which never reads, its upstream flooding it.
    let data = Arc::new(pseudo_random(MORE_THAN_THE_BUFFERS));
    let flood = {
        let data = data.clone();
        start_upstream(move |stream| send_and_close(stream, data.clone())).await
    };
    let not_read_id = gateway.client.get_next_connection_id();
    let not_read = gateway
        .client_side()
        .connect_to_forward_proxy_connection(endpoint(flood), CONNECT_TIMEOUT, not_read_id)
        .await
        .unwrap();

    // Once the window is spent, the acceptor waits for credit holding no budget.
    wait_until_within(Duration::from_secs(60), || {
        not_read.buffered_for_tests() + MAX_PAYLOAD_CHUNK > FLOW_CONTROL_WINDOW
    })
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let server_budget = gateway.server_side().write_budget_for_tests().unwrap();
    wait_until(|| server_budget.available_permits() == GATEWAY_WRITE_BUDGET).await;

    // A target which never reads, a writer flooding it.
    let silent = start_upstream(|stream| async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        drop(stream);
    })
    .await;
    let not_taken_id = gateway.client.get_next_connection_id();
    let mut not_taken = gateway
        .client_side()
        .connect_to_forward_proxy_connection(endpoint(silent), CONNECT_TIMEOUT, not_taken_id)
        .await
        .unwrap();
    let progress = Arc::new(AtomicUsize::new(0));
    let flooding = {
        let progress = progress.clone();
        tokio::spawn(async move {
            let piece = vec![0u8; 64 * 1024];
            while not_taken.write_to_socket(&piece).await.is_ok() {
                progress.fetch_add(piece.len(), Ordering::Relaxed);
            }
        })
    };

    // Once the window is spent, the writer waits for credit holding no budget.
    wait_for_stall(&progress).await;
    let client_budget = gateway.client_side().write_budget_for_tests().unwrap();
    wait_until(|| client_budget.available_permits() == GATEWAY_WRITE_BUDGET).await;

    // Meanwhile a window and a half echoes through another connection.
    let stream = gateway.connect_from_client(echo_upstream).await;
    tokio::time::timeout(
        Duration::from_secs(60),
        echo_round_trip(stream, 12 * 1024 * 1024),
    )
    .await
    .expect("the other connection is held up");

    // Both stalled connections are still open: their senders waited for credit, they did not
    // send past the window and get closed for it.
    let server_side = gateway.server_side();
    assert!(server_side.has_forward_connection(not_read_id));
    assert!(server_side.has_forward_connection(not_taken_id));
    assert!(not_read.buffered_for_tests() <= FLOW_CONTROL_WINDOW);
    assert!(!flooding.is_finished());

    flooding.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_poll_write_waits_for_credit_without_holding_budget() {
    let gateway = Gateway::start("fc-poll-write", false).await;
    let upstream = start_upstream(discard).await;

    let mut stream = gateway.connect_from_client(upstream).await;
    let window = stream.send_window_for_tests();
    let budget = gateway.client_side().write_budget_for_tests().unwrap();

    // No credit: Pending, and no budget asked for meanwhile.
    window.forget_permits(window.available_permits());
    assert!(poll_write_once(&mut stream, &[1u8; 1000]).is_pending());
    assert_eq!(budget.available_permits(), GATEWAY_WRITE_BUDGET);

    window.add_permits(1000);
    assert!(matches!(
        poll_write_once(&mut stream, &[1u8; 1000]),
        Poll::Ready(Ok(1000))
    ));

    // A request waits for all the credit it asks for; a smaller buffer gets what there is.
    assert!(poll_write_once(&mut stream, &[1u8; 1000]).is_pending());
    window.add_permits(100);
    assert!(poll_write_once(&mut stream, &[1u8; 1000]).is_pending());
    assert!(matches!(
        poll_write_once(&mut stream, &[1u8; 100]),
        Poll::Ready(Ok(100))
    ));

    // Credit taken for a buffer which then shrinks: the rest goes back to the window.
    window.add_permits(1024 * 1024);
    let spent = budget.forget_permits(budget.available_permits());
    assert!(poll_write_once(&mut stream, &vec![1u8; MAX_PAYLOAD_CHUNK]).is_pending());
    budget.add_permits(spent);
    assert!(matches!(
        poll_write_once(&mut stream, &[1u8; 100]),
        Poll::Ready(Ok(100))
    ));
    assert_eq!(window.available_permits(), 1024 * 1024 - 100);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bidirectional_bulk_transfer_bigger_than_the_window() {
    for (name, compress, from_server) in [
        ("fc-bidi", false, false),
        ("fc-bidi-compressed", true, false),
        ("fc-bidi-from-server", false, true),
    ] {
        let gateway = Gateway::start(name, compress).await;
        let upstream = start_upstream(|stream| echo(stream, None)).await;

        let stream = if from_server {
            gateway.connect_from_server(upstream).await
        } else {
            gateway.connect_from_client(upstream).await
        };

        tokio::time::timeout(
            Duration::from_secs(120),
            echo_round_trip(stream, 2 * FLOW_CONTROL_WINDOW),
        )
        .await
        .unwrap_or_else(|_| panic!("{name}: the transfer stalled"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hyper_bodies_bigger_than_the_window() {
    let gateway = Gateway::start("fc-hyper", false).await;
    let upload = pseudo_random(2 * FLOW_CONTROL_WINDOW);

    // http/1.1
    let upstream = start_hyper_upstream(false).await;
    let stream = gateway.connect_from_client(upstream).await;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(connection);

    assert_eq!(
        send_hyper_request(&mut sender, "/upload", upload.clone()).await,
        format!("received {} bytes", upload.len()).into_bytes()
    );
    assert!(
        send_hyper_request(&mut sender, "/download-big", Vec::new()).await == big_download_body()
    );

    // h2c, an upload and a download at once.
    let upstream = start_hyper_upstream(true).await;
    let stream = gateway.connect_from_client(upstream).await;
    let (sender, connection) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(stream),
    )
    .await
    .unwrap();
    tokio::spawn(connection);

    let uploading = {
        let (mut sender, upload) = (sender.clone(), upload.clone());
        tokio::spawn(async move { send_h2_request(&mut sender, "/upload", upload).await })
    };
    let downloading = {
        let mut sender = sender.clone();
        tokio::spawn(async move { send_h2_request(&mut sender, "/download-big", Vec::new()).await })
    };

    assert_eq!(
        uploading.await.unwrap(),
        format!("received {} bytes", upload.len()).into_bytes()
    );
    assert!(downloading.await.unwrap() == big_download_body());
}

/// A writer parked on the window wakes, with an error, however the connection ends: the target
/// going away, the gateway connection going down, another clone closing it - and every writer
/// parked on it, not one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_writer_waiting_for_credit_wakes_on_every_close() {
    let gateway = Gateway::start("fc-wake", false).await;

    // The target goes away.
    let (go, go_watch) = tokio::sync::watch::channel(false);
    let leaving = start_upstream(move |stream| {
        let mut go_watch = go_watch.clone();
        async move {
            let _ = go_watch.wait_for(|go| *go).await;
            drop(stream);
        }
    })
    .await;
    let (writer, _control) = park_a_writer(gateway.connect_from_client(leaving).await).await;
    go.send(true).unwrap();
    assert_ends_with_an_error(writer).await;

    // Another clone closes the connection.
    let silent = start_upstream(|stream| async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        drop(stream);
    })
    .await;
    let (writer, control) = park_a_writer(gateway.connect_from_client(silent).await).await;
    control.disconnect();
    assert_ends_with_an_error(writer).await;

    // Two writers on the poll_write path, both parked on an empty window.
    let stream = gateway.connect_from_client(silent).await;
    let window = stream.send_window_for_tests();
    window.forget_permits(window.available_permits());
    let writers: Vec<_> = (0..2)
        .map(|_| {
            let mut clone = stream.clone();
            tokio::spawn(async move { clone.write_all(&[1u8; 1000]).await.is_ok() })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(300)).await;
    stream.disconnect();
    for writer in writers {
        assert_ends_with_an_error(writer).await;
    }

    // The gateway connection goes down - the last: it takes the gateway with it.
    let (writer, _control) = park_a_writer(gateway.connect_from_client(silent).await).await;
    let server_side = gateway.server_side();
    server_side.disconnect_gateway();
    assert_ends_with_an_error(writer).await;
    wait_until(|| server_side.get_forward_connections_amount() == 0).await;
}

/// An acceptor whose read loop waits for credit lets its target go as soon as the initiator closes
/// the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_acceptor_waiting_for_credit_lets_go_when_the_initiator_closes() {
    let gateway = Gateway::start("fc-let-go", false).await;

    let (closed_tx, mut closed) = mpsc::unbounded_channel();
    let progress = Arc::new(AtomicUsize::new(0));
    let flood = {
        let progress = progress.clone();
        start_upstream(move |mut stream| {
            let (closed_tx, progress) = (closed_tx.clone(), progress.clone());
            async move {
                let piece = vec![0u8; 64 * 1024];
                while stream.write_all(&piece).await.is_ok() {
                    progress.fetch_add(piece.len(), Ordering::Relaxed);
                }
                let _ = closed_tx.send(());
            }
        })
        .await
    };

    // The target is held back by the acceptor, which waits for credit: once what was on the way
    // has arrived, the initiator holds a window, and no more.
    let stream = gateway.connect_from_client(flood).await;
    wait_for_stall(&progress).await;
    wait_until_within(Duration::from_secs(60), || {
        stream.buffered_for_tests() + MAX_PAYLOAD_CHUNK > FLOW_CONTROL_WINDOW
    })
    .await;
    assert!(stream.buffered_for_tests() <= FLOW_CONTROL_WINDOW);
    drop(stream);

    tokio::time::timeout(TIMEOUT, closed.recv())
        .await
        .expect("the target is still connected")
        .unwrap();
    let server_side = gateway.server_side();
    wait_until(|| server_side.get_forward_connections_amount() == 0).await;
}

/// What was sent before a close arrives in full, however much more than a window it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_tail_before_a_close_arrives_past_the_window() {
    let gateway = Gateway::start("fc-tail", false).await;
    let data = Arc::new(pseudo_random(FLOW_CONTROL_WINDOW + 4 * 1024 * 1024));

    // Downloaded by a reader taking its time.
    let upstream = {
        let data = data.clone();
        start_upstream(move |stream| send_and_close(stream, data.clone())).await
    };
    let mut stream = gateway.connect_from_client(upstream).await;
    let mut received = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let read_size = tokio::time::timeout(TIMEOUT, stream.read_from_socket(&mut buf))
            .await
            .expect("the download stalled")
            .expect("the download ended with an error");
        if read_size == 0 {
            break;
        }
        received.extend_from_slice(&buf[..read_size]);
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(received == *data);

    // Uploaded and closed at once, to a target which starts reading late.
    let (collected_tx, mut collected) = mpsc::unbounded_channel();
    let upstream =
        start_upstream(move |stream| collect(stream, collected_tx.clone(), Duration::from_secs(2)))
            .await;
    let mut stream = gateway.connect_from_client(upstream).await;
    stream.write_to_socket(&data).await.unwrap();
    stream.disconnect();
    let received = tokio::time::timeout(Duration::from_secs(60), collected.recv())
        .await
        .expect("the upload did not arrive")
        .unwrap();
    assert!(received == *data);
}

/// A failed write to the target while the initiator reads nothing: the forwarding which follows
/// waits for credit that never comes, and still ends within the drain limit, with an error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_write_ends_the_forwarding_within_the_drain_limit_without_a_reader() {
    let gateway = Gateway::start("fc-drain", false).await;

    let data = Arc::new(pseudo_random(MORE_THAN_THE_BUFFERS));
    let upstream = {
        let data = data.clone();
        start_upstream(move |stream| send_and_close(stream, data.clone())).await
    };

    let connection_id = gateway.client.get_next_connection_id();
    let stream = gateway
        .client_side()
        .connect_to_forward_proxy_connection(endpoint(upstream), CONNECT_TIMEOUT, connection_id)
        .await
        .unwrap();
    let (mut reader, mut writer) = split(stream);

    let uploading = tokio::spawn(async move {
        let piece = vec![1u8; 16 * 1024];
        while writer.write_to_socket(&piece).await.is_ok() {}
    });

    wait_until_within(Duration::from_secs(60), || {
        reader.buffered_for_tests() + MAX_PAYLOAD_CHUNK > FLOW_CONTROL_WINDOW
    })
    .await;

    let server_side = gateway.server_side();
    server_side
        .get_forward_connection(connection_id)
        .unwrap()
        .fail_writer_for_tests();

    wait_until_within(Duration::from_secs(10), || {
        server_side.get_forward_connections_amount() == 0
    })
    .await;
    tokio::time::timeout(TIMEOUT, uploading)
        .await
        .expect("the upload outlived the connection")
        .unwrap();

    let received = read_to_end(&mut reader)
        .await
        .expect_err("a connection whose write failed closes with an error");
    assert!(received.len() <= FLOW_CONTROL_WINDOW);
}

/// A peer which sends past the window loses that connection - its other connections and the
/// gateway connection go on.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_sending_past_the_window_loses_only_that_connection() {
    let gateway = Gateway::start("fc-violation", false).await;
    let (server_side, client_side) = (gateway.server_side(), gateway.client_side());

    let silent = start_upstream(|stream| async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        drop(stream);
    })
    .await;
    let chunk = vec![3u8; MAX_PAYLOAD_CHUNK];

    let echo_upstream = start_upstream(|stream| echo(stream, None)).await;
    let mut bystander = gateway.connect_from_client(echo_upstream).await;

    // Towards an initiator: opened from the server, the acceptor on the client.
    let connection_id = gateway.server.get_next_connection_id();
    let mut stream = server_side
        .connect_to_forward_proxy_connection(endpoint(silent), CONNECT_TIMEOUT, connection_id)
        .await
        .unwrap();
    for _ in 0..FLOW_CONTROL_WINDOW / MAX_PAYLOAD_CHUNK + 1 {
        client_side.send_payload(&TcpGatewayContract::BackwardPayload {
            connection_id,
            payload: chunk.as_slice().into(),
        });
    }
    // Not read before: reading would give the credit back and keep the peer within the window.
    wait_until(|| !client_side.has_forward_connection(connection_id)).await;
    let received = read_to_end(&mut stream)
        .await
        .expect_err("past the window, the connection closes with an error");
    assert!(received.len() <= FLOW_CONTROL_WINDOW);

    // Towards an acceptor whose target reads nothing: opened from the client. A unix socket takes
    // a few kilobytes before it stops taking any, so a window and a little more is past it.
    let path = std::env::temp_dir().join(format!("gateway-silent-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(60)).await;
                drop(stream);
            });
        }
    });
    let silent_unix = Arc::new(
        RemoteEndpointOwned::try_parse(format!("unix+http://{}", path.display())).unwrap(),
    );

    let connection_id = gateway.client.get_next_connection_id();
    let mut stream = client_side
        .connect_to_forward_proxy_connection(silent_unix, CONNECT_TIMEOUT, connection_id)
        .await
        .unwrap();
    for _ in 0..(FLOW_CONTROL_WINDOW + 1024 * 1024) / MAX_PAYLOAD_CHUNK {
        client_side.send_payload(&TcpGatewayContract::ForwardPayload {
            connection_id,
            payload: chunk.as_slice().into(),
        });
    }
    wait_until(|| !server_side.has_forward_connection(connection_id)).await;
    read_to_end(&mut stream)
        .await
        .expect_err("past the window, the connection closes with an error");
    let _ = std::fs::remove_file(&path);

    assert!(Arc::ptr_eq(&gateway.server_side(), &server_side));
    assert!(Arc::ptr_eq(&gateway.client_side(), &client_side));
    assert_echoes(&mut bystander).await;
    assert_echoes(&mut gateway.connect_from_client(echo_upstream).await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn credit_beyond_reason_saturates_and_credit_for_nothing_is_ignored() {
    let gateway = Gateway::start("fc-odd-credit", false).await;
    let (server_side, client_side) = (gateway.server_side(), gateway.client_side());
    let upstream = start_upstream(|stream| echo(stream, None)).await;

    // One the client opened, found among the client's own connections, and one the server
    // opened, found among those the client accepted.
    let connection_id = gateway.client.get_next_connection_id();
    let mut stream = client_side
        .connect_to_forward_proxy_connection(endpoint(upstream), CONNECT_TIMEOUT, connection_id)
        .await
        .unwrap();
    let accepted_id = gateway.server.get_next_connection_id();
    let mut accepted = server_side
        .connect_to_forward_proxy_connection(endpoint(upstream), CONNECT_TIMEOUT, accepted_id)
        .await
        .unwrap();

    // Twice the most credit there may be, for each of them, and credit for an id nobody opened.
    for target in [
        connection_id,
        connection_id,
        accepted_id,
        accepted_id,
        0x7fff_fff0,
    ] {
        server_side.send_payload(&TcpGatewayContract::WindowUpdate {
            connection_id: target,
            credit: u32::MAX,
        });
    }

    let window = stream.send_window_for_tests();
    wait_until(|| window.available_permits() == MAX_SEND_CREDIT).await;
    let accepted_on_client = client_side.get_forward_connection(accepted_id).unwrap();
    wait_until(|| accepted_on_client.send_window().available_permits() == MAX_SEND_CREDIT).await;

    assert_echoes(&mut stream).await;
    assert_echoes(&mut accepted).await;
    assert!(Arc::ptr_eq(&gateway.server_side(), &server_side));
    assert!(Arc::ptr_eq(&gateway.client_side(), &client_side));
}

/// A window under the protocol floor is refused by the acceptor, before it connects to anything;
/// at the floor the connect goes through, the acceptor's window right ahead of its CONNECT_OK.
#[tokio::test]
async fn a_connect_with_a_window_under_the_floor_is_refused() {
    const NAME: &str = "small-window";

    let key = signing_key();
    let (server, port) = start_server(&key, None).await;
    let mut client = RawClient::connect(&server, port, &key, NAME).await;

    let (accepted_tx, mut accepted) = mpsc::unbounded_channel();
    let upstream = start_upstream(move |stream| {
        let _ = accepted_tx.send(());
        echo(stream, None)
    })
    .await;
    let remote_host = format!("127.0.0.1:{upstream}");

    let connect = |connection_id, receive_window: usize| TcpGatewayContract::Connect {
        connection_id,
        timeout: CONNECT_TIMEOUT,
        remote_host: remote_host.as_str(),
        receive_window: receive_window as u32,
    };

    client.send(&connect(7, MIN_RECEIVE_WINDOW - 1)).await;
    let answer = client.read_frame().await;
    match TcpGatewayContract::parse(&answer).unwrap() {
        TcpGatewayContract::ConnectionError {
            connection_id: 7,
            error,
        } => assert!(error.contains("window out of range"), "{error}"),
        other => panic!("answered with {other:?}"),
    }
    assert!(accepted.try_recv().is_err(), "the target was connected to");

    client.send(&connect(8, MIN_RECEIVE_WINDOW)).await;
    assert!(matches!(
        TcpGatewayContract::parse(&client.read_frame().await).unwrap(),
        TcpGatewayContract::WindowUpdate {
            connection_id: 8,
            credit
        } if credit as usize == FLOW_CONTROL_WINDOW
    ));
    assert!(matches!(
        TcpGatewayContract::parse(&client.read_frame().await).unwrap(),
        TcpGatewayContract::Connected { connection_id: 8 }
    ));
}

/// The floor on the initiator's side: a CONNECT_OK which finds less credit than the floor fails
/// the connect, and the acceptor is told to close what it connected.
#[tokio::test]
async fn a_connect_answered_with_too_little_credit_fails() {
    const NAME: &str = "little-credit";

    let key = signing_key();
    let (server, port) = start_server(&key, None).await;
    let mut client = RawClient::connect(&server, port, &key, NAME).await;
    let server_side = server.get_gateway_connection(NAME).unwrap();

    let connection_id = server.get_next_connection_id();
    let connecting = {
        let server_side = server_side.clone();
        tokio::spawn(async move {
            server_side
                .connect_to_forward_proxy_connection(endpoint(1), CONNECT_TIMEOUT, connection_id)
                .await
                .map(|_| ())
        })
    };

    match TcpGatewayContract::parse(&client.read_frame().await).unwrap() {
        TcpGatewayContract::Connect {
            connection_id: id,
            receive_window,
            ..
        } => {
            assert_eq!(id, connection_id);
            assert_eq!(receive_window as usize, FLOW_CONTROL_WINDOW);
        }
        other => panic!("opened with {other:?}"),
    }

    client
        .send(&TcpGatewayContract::WindowUpdate {
            connection_id,
            credit: (MIN_RECEIVE_WINDOW - 1) as u32,
        })
        .await;
    client
        .send(&TcpGatewayContract::Connected { connection_id })
        .await;

    let err = tokio::time::timeout(TIMEOUT, connecting)
        .await
        .expect("the connect got no answer")
        .unwrap()
        .expect_err("a connect with too little credit went through");
    assert!(err.contains("window out of range"), "{err}");

    assert!(matches!(
        TcpGatewayContract::parse(&client.read_frame().await).unwrap(),
        TcpGatewayContract::Fin { connection_id: id } if id == connection_id
    ));
    assert_eq!(server_side.get_forward_proxy_connections_amount(), 0);
}

/// A frame of a type which is none any more - `CONNECT` without a window, type 3 of protocol
/// version 1 - closes the gateway connection of whichever end gets it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_type_which_is_none_any_more_closes_the_gateway_connection() {
    // The type, a connection id, a timeout and a host.
    let connect_without_a_window = [3u8, 1, 0, 0, 0, 5, b'h', b':', b'1'];

    for to_server in [true, false] {
        let gateway = Gateway::start(&format!("gone-type-{to_server}"), false).await;
        let (server_side, client_side) = (gateway.server_side(), gateway.client_side());
        let (sender, receiver) = if to_server {
            (&client_side, &server_side)
        } else {
            (&server_side, &client_side)
        };

        assert!(sender.send_raw_frame_for_tests(&connect_without_a_window));

        wait_until(|| !receiver.is_gateway_connected()).await;
    }
}

// FIN and RST.

#[test]
fn an_end_goes_as_fin_or_rst() {
    assert!(matches!(
        ConnectionEnd::Closed.to_contract(3),
        TcpGatewayContract::Fin { connection_id: 3 }
    ));
    assert!(matches!(
        ConnectionEnd::Reset("broken").to_contract(3),
        TcpGatewayContract::Rst {
            connection_id: 3,
            reason: "broken"
        }
    ));
}

/// CONNECTION_ERROR ends a connection as a reset, whatever its text says - the texts which stood
/// in for a clean close in protocol version 1 as well: at the initiator the reader gets an error,
/// at the acceptor the target connection is reset.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_error_is_a_reset_whatever_its_text_says() {
    let gateway = Gateway::start("connection-error", false).await;
    let (server_side, client_side) = (gateway.server_side(), gateway.client_side());
    let (arrived_tx, mut arrived) = mpsc::unbounded_channel();
    let (ended_tx, mut ended) = mpsc::unbounded_channel();
    let upstream = start_upstream(move |stream| {
        read_until_the_end(stream, 5, arrived_tx.clone(), ended_tx.clone())
    })
    .await;

    for text in [
        "",
        "ReadLoop. Connection to 127.0.0.1:1 with id:1 is disconnected",
        "Connection is not found",
    ] {
        let connection_id = gateway.client.get_next_connection_id();
        let mut stream = client_side
            .connect_to_forward_proxy_connection(endpoint(upstream), CONNECT_TIMEOUT, connection_id)
            .await
            .unwrap();
        stream.write_to_socket(b"hello").await.unwrap();
        tokio::time::timeout(TIMEOUT, arrived.recv())
            .await
            .expect("the data did not arrive");

        server_side.send_payload(&TcpGatewayContract::ConnectionError {
            connection_id,
            error: text,
        });
        assert!(
            read_to_end(&mut stream).await.is_err(),
            "{text:?} reached the reader as the end of the stream"
        );

        client_side.send_payload(&TcpGatewayContract::ConnectionError {
            connection_id,
            error: text,
        });
        let end = tokio::time::timeout(TIMEOUT, ended.recv())
            .await
            .expect("the target's connection did not end")
            .unwrap();
        assert_eq!(end, StreamEnd::Reset, "{text:?} at the acceptor");
    }
}

#[test]
fn fin_and_rst_round_trip() {
    let fin = TcpGatewayContract::Fin { connection_id: 7 }.to_plain_frame();
    assert_eq!(fin, vec![5, 0, 0, 0, 16, 7, 0, 0, 0]);
    assert!(matches!(
        TcpGatewayContract::parse(&fin[4..]).unwrap(),
        TcpGatewayContract::Fin { connection_id: 7 }
    ));

    for reason in ["The initiator reset the connection", ""] {
        let rst = TcpGatewayContract::Rst {
            connection_id: 7,
            reason,
        }
        .to_plain_frame();
        assert_eq!(rst[4], 17);

        match TcpGatewayContract::parse(&rst[4..]).unwrap() {
            TcpGatewayContract::Rst {
                connection_id,
                reason: parsed,
            } => {
                assert_eq!(connection_id, 7);
                assert_eq!(parsed, reason);
            }
            other => panic!("{other:?}"),
        }
    }
}

/// How the initiator ends a connection reaches the target: a close as the end of the stream, a
/// reset as a reset - with either end of the gateway as the initiator.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_target_sees_a_close_as_the_end_and_a_reset_as_a_reset() {
    let gateway = Gateway::start("initiator-ends", false).await;
    let (arrived_tx, mut arrived) = mpsc::unbounded_channel();
    let (ended_tx, mut ended) = mpsc::unbounded_channel();
    let upstream = start_upstream(move |stream| {
        read_until_the_end(stream, 5, arrived_tx.clone(), ended_tx.clone())
    })
    .await;

    for from_server in [false, true] {
        for reset in [false, true] {
            let mut stream = connect_from(&gateway, from_server, upstream).await;
            stream.write_to_socket(b"hello").await.unwrap();
            tokio::time::timeout(TIMEOUT, arrived.recv())
                .await
                .expect("the data did not arrive");

            let ending = Instant::now();
            if reset {
                stream.abort();
                assert!(
                    read_to_end(&mut stream).await.is_err(),
                    "a reset stream reads to an error"
                );
            } else {
                stream.disconnect();
            }

            let end = tokio::time::timeout(TIMEOUT, ended.recv())
                .await
                .expect("the target's connection did not end")
                .unwrap();
            let expected = if reset {
                StreamEnd::Reset
            } else {
                StreamEnd::End
            };
            assert_eq!(end, expected, "from the server: {from_server}");

            // At once: nothing lingers on a connection which is reset.
            assert!(
                ending.elapsed() < Duration::from_millis(1500),
                "the end took {:?}",
                ending.elapsed()
            );
        }
    }
}

/// A lost gateway connection cuts the streams through it short: the targets get resets.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_gateway_connection_resets_the_targets() {
    for from_server in [false, true] {
        let gateway = Gateway::start(&format!("lost-gateway-reset-{from_server}"), false).await;
        let (arrived_tx, mut arrived) = mpsc::unbounded_channel();
        let (ended_tx, mut ended) = mpsc::unbounded_channel();
        let upstream = start_upstream(move |stream| {
            read_until_the_end(stream, 5, arrived_tx.clone(), ended_tx.clone())
        })
        .await;

        let mut stream = connect_from(&gateway, from_server, upstream).await;
        stream.write_to_socket(b"hello").await.unwrap();
        tokio::time::timeout(TIMEOUT, arrived.recv())
            .await
            .expect("the data did not arrive");

        // The acceptor's end goes down.
        if from_server {
            gateway.client_side().disconnect_gateway();
        } else {
            gateway.server_side().disconnect_gateway();
        }

        let end = tokio::time::timeout(TIMEOUT, ended.recv())
            .await
            .expect("the target's connection did not end")
            .unwrap();
        assert_eq!(end, StreamEnd::Reset, "from the server: {from_server}");
    }
}

/// A reset drops what the target has not taken yet and resets its connection at once - a close
/// would hand it all over first, as slowly as the target takes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reset_drops_what_a_target_which_does_not_read_has_not_taken() {
    let gateway = Gateway::start("reset-backlog", false).await;
    let start_reading = Arc::new(tokio::sync::Notify::new());
    let (ended_tx, mut ended) = mpsc::unbounded_channel();
    let upstream = {
        let start_reading = start_reading.clone();
        start_upstream(move |mut stream| {
            let start_reading = start_reading.clone();
            let ended = ended_tx.clone();
            async move {
                start_reading.notified().await;
                let _ = ended.send(read_socket_end_probing(&mut stream).await);
            }
        })
        .await
    };

    let server_side = gateway.server_side();
    let connection_id = gateway.client.get_next_connection_id();
    let stream = gateway
        .client_side()
        .connect_to_forward_proxy_connection(endpoint(upstream), CONNECT_TIMEOUT, connection_id)
        .await
        .unwrap();

    let writer = {
        let stream = stream.clone();
        tokio::spawn(async move { stream.send_payload(&vec![1u8; MORE_THAN_THE_BUFFERS]).await })
    };

    // The target's buffers are full, and the acceptor holds what it could not write.
    wait_until_within(Duration::from_secs(30), || {
        server_side
            .forward_buffered_for_tests(connection_id)
            .is_some_and(|held| held >= FLOW_CONTROL_WINDOW / 2)
    })
    .await;

    stream.abort();
    assert!(
        !tokio::time::timeout(TIMEOUT, writer)
            .await
            .unwrap()
            .unwrap(),
        "the writer is cut short"
    );
    wait_until(|| !server_side.has_forward_connection(connection_id)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    start_reading.notify_one();
    let end = tokio::time::timeout(TIMEOUT, ended.recv())
        .await
        .expect("the target's connection did not end")
        .unwrap();
    assert_eq!(end, StreamEnd::Reset);
}

/// A port forward client which resets: the target is reset too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_port_forward_client_which_resets_resets_the_target() {
    let gateway = Gateway::start("client-reset", false).await;
    let (arrived_tx, mut arrived) = mpsc::unbounded_channel();
    let (ended_tx, mut ended) = mpsc::unbounded_channel();
    let upstream = start_upstream(move |stream| {
        read_until_the_end(stream, 5, arrived_tx.clone(), ended_tx.clone())
    })
    .await;

    for reset in [false, true] {
        let (mut client, pumps) = port_forward(
            gateway.connect_from_client(upstream).await,
            HttpTimeouts::default(),
        )
        .await;

        client.write_all(b"hello").await.unwrap();
        tokio::time::timeout(TIMEOUT, arrived.recv())
            .await
            .expect("the data did not arrive");

        if reset {
            reset_socket(client);
        } else {
            // Without half-close the client's end of the stream closes the whole connection.
            client.shutdown().await.unwrap();
        }

        let end = tokio::time::timeout(TIMEOUT, ended.recv())
            .await
            .expect("the target's connection did not end")
            .unwrap();
        let expected = if reset {
            StreamEnd::Reset
        } else {
            StreamEnd::End
        };
        assert_eq!(end, expected);

        for pump in pumps {
            tokio::time::timeout(TIMEOUT, pump)
                .await
                .expect("a pump outlived the connection")
                .unwrap();
        }
    }
}

/// A target which resets: the port forward client is reset too, after what the target sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_target_which_resets_resets_the_port_forward_client() {
    let gateway = Gateway::start("target-reset", false).await;

    for reset in [false, true] {
        let end_now = Arc::new(tokio::sync::Notify::new());
        let upstream = {
            let end_now = end_now.clone();
            start_upstream(move |mut stream| {
                let end_now = end_now.clone();
                async move {
                    stream.write_all(b"hello").await.unwrap();
                    end_now.notified().await;
                    if reset {
                        reset_socket(stream);
                    }
                }
            })
            .await
        };

        let (mut client, _pumps) = port_forward(
            gateway.connect_from_client(upstream).await,
            HttpTimeouts::default(),
        )
        .await;

        let mut hello = [0u8; 5];
        tokio::time::timeout(TIMEOUT, client.read_exact(&mut hello))
            .await
            .expect("the data did not arrive")
            .unwrap();
        assert_eq!(&hello, b"hello");

        end_now.notify_one();

        let (rest, end) = tokio::time::timeout(TIMEOUT, read_socket_end(&mut client))
            .await
            .expect("the client's connection did not end");
        assert!(rest.is_empty());
        let expected = if reset {
            StreamEnd::Reset
        } else {
            StreamEnd::End
        };
        assert_eq!(end, expected);
    }
}

/// A port forward whose target stops reading: the client's writes wait for credit, the write
/// times out, and the connection fails - both ends are reset, neither gets an end of stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_write_timeout_resets_both_ends_of_a_port_forward() {
    let gateway = Gateway::start("write-timeout-reset", false).await;
    let start_reading = Arc::new(tokio::sync::Notify::new());
    let (ended_tx, mut ended) = mpsc::unbounded_channel();
    let upstream = {
        let start_reading = start_reading.clone();
        start_upstream(move |mut stream| {
            let start_reading = start_reading.clone();
            let ended = ended_tx.clone();
            async move {
                start_reading.notified().await;
                let _ = ended.send(read_socket_end_probing(&mut stream).await);
            }
        })
        .await
    };

    let timeouts = HttpTimeouts {
        read_timeout: Duration::from_secs(60),
        write_timeout: Duration::from_secs(1),
    };
    let (client, pumps) = port_forward(gateway.connect_from_client(upstream).await, timeouts).await;
    let (mut client_read, mut client_write) = client.into_split();

    let flood = tokio::spawn(async move {
        let chunk = vec![7u8; 64 * 1024];
        while client_write.write_all(&chunk).await.is_ok() {}
    });

    for pump in pumps {
        tokio::time::timeout(Duration::from_secs(60), pump)
            .await
            .expect("the pumps did not give up on the stalled write")
            .unwrap();
    }

    let (_, client_end) = tokio::time::timeout(TIMEOUT, read_socket_end(&mut client_read))
        .await
        .expect("the client's connection did not end");
    assert_eq!(client_end, StreamEnd::Reset);
    tokio::time::timeout(TIMEOUT, flood)
        .await
        .expect("the client's writes did not fail")
        .unwrap();

    // The acceptor holds a backlog for the target, and takes its time with the frames ahead of the
    // RST in a debug build: the target reads once its connection is reset.
    let server_side = gateway.server_side();
    wait_until(|| server_side.get_forward_connections_amount() == 0).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    start_reading.notify_one();
    let target_end = tokio::time::timeout(TIMEOUT, ended.recv())
        .await
        .expect("the target's connection did not end")
        .unwrap();
    assert_eq!(target_end, StreamEnd::Reset);
}

/// A port forward client which stops reading while the target keeps sending: the write to the
/// client times out, and the connection fails - both ends are reset.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_which_stops_reading_resets_both_ends_of_a_port_forward() {
    let gateway = Gateway::start("client-stuck-reset", false).await;
    let (ended_tx, mut ended) = mpsc::unbounded_channel();
    let upstream = start_upstream(move |stream| {
        let ended = ended_tx.clone();
        async move {
            let (mut read, mut write) = stream.into_split();
            let flood = tokio::spawn(async move {
                let chunk = vec![7u8; 64 * 1024];
                while write.write_all(&chunk).await.is_ok() {}
            });

            let _ = ended.send(read_socket_end(&mut read).await.1);
            let _ = flood.await;
        }
    })
    .await;

    let timeouts = HttpTimeouts {
        read_timeout: Duration::from_secs(60),
        write_timeout: Duration::from_secs(1),
    };
    let (mut client, pumps) =
        port_forward(gateway.connect_from_client(upstream).await, timeouts).await;

    for pump in pumps {
        tokio::time::timeout(Duration::from_secs(60), pump)
            .await
            .expect("the pumps did not give up on the stalled write")
            .unwrap();
    }

    let target_end = tokio::time::timeout(TIMEOUT, ended.recv())
        .await
        .expect("the target's connection did not end")
        .unwrap();
    assert_eq!(target_end, StreamEnd::Reset);

    let (_, client_end) = tokio::time::timeout(TIMEOUT, read_socket_end(&mut client))
        .await
        .expect("the client's connection did not end");
    assert_eq!(client_end, StreamEnd::Reset);
}

/// A pump which fails resets the client even when the client's socket would close cleanly - nothing
/// unread in it: whichever pump holds which half of the client's socket, both reset it.
#[tokio::test]
async fn a_failed_pump_resets_a_client_which_left_nothing_unread() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (accepted, _) = listener.accept().await.unwrap();
    let (accepted_read, accepted_write) = accepted.into_split();

    let pumps = Arc::new(ConnectionPumps::new(HttpTimeouts {
        read_timeout: Duration::from_secs(60),
        write_timeout: Duration::from_millis(500),
    }));
    let client_to_far_side = tokio::spawn(copy_streams(
        crate::network_stream::MyOwnedReadHalf::from(accepted_read),
        StuckWriter,
        LoopBuffer::new(),
        None,
        None,
        None,
        pumps.clone(),
    ));
    let far_side_to_client = tokio::spawn(copy_streams(
        SilentReader,
        crate::network_stream::MyOwnedWriteHalf::from(accepted_write),
        LoopBuffer::new(),
        None,
        None,
        None,
        pumps,
    ));

    // Read off the socket at once, then stuck on its way on: the write times out.
    client.write_all(b"hello").await.unwrap();

    for pump in [client_to_far_side, far_side_to_client] {
        tokio::time::timeout(TIMEOUT, pump)
            .await
            .expect("a pump outlived the failed connection")
            .unwrap();
    }

    let (_, end) = tokio::time::timeout(TIMEOUT, read_socket_end(&mut client))
        .await
        .expect("the client's connection did not end");
    assert_eq!(end, StreamEnd::Reset);
}

/// A send which finds the gateway connection gone - its writer failed and closed the write budget,
/// the teardown is still to come - resets the connection: a caller which shuts the stream down
/// after the failed write, as `write_all_with_timeout` does, must not close it cleanly first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_send_which_finds_the_gateway_gone_resets_the_connection() {
    let gateway = Gateway::start("send-gateway-gone", false).await;
    let upstream = start_upstream(|stream| echo(stream, None)).await;

    let mut written = gateway.connect_from_client(upstream).await;
    let mut polled = gateway.connect_from_client(upstream).await;

    gateway
        .client_side()
        .write_budget_for_tests()
        .unwrap()
        .close();

    assert!(written.write_to_socket(b"lost").await.is_err());
    written.shutdown_socket().await;
    assert!(
        read_to_end(&mut written).await.is_err(),
        "the async write ends the connection with a reset"
    );

    assert!(matches!(
        poll_write_once(&mut polled, b"lost"),
        Poll::Ready(Err(_))
    ));
    polled.disconnect();
    assert!(
        read_to_end(&mut polled).await.is_err(),
        "poll_write ends the connection with a reset"
    );
}

/// The gateway writer of a port forward fails while the client's bytes wait for write budget: the
/// pump woken by the failure resets the client - it does not close it cleanly ahead of the
/// gateway connection's teardown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_gateway_writer_resets_a_port_forward_client() {
    let gateway = Gateway::start("writer-failed-reset", false).await;
    let upstream = start_upstream(|stream| echo(stream, None)).await;

    let timeouts = HttpTimeouts {
        read_timeout: Duration::from_secs(60),
        write_timeout: Duration::from_secs(5),
    };
    let (mut client, pumps) =
        port_forward(gateway.connect_from_client(upstream).await, timeouts).await;

    client.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    tokio::time::timeout(TIMEOUT, client.read_exact(&mut echoed))
        .await
        .expect("the echo did not come back")
        .unwrap();

    // Every byte of the write budget taken: the client's next bytes wait for it.
    let budget = gateway.client_side().write_budget_for_tests().unwrap();
    budget
        .acquire_many(GATEWAY_WRITE_BUDGET as u32)
        .await
        .unwrap()
        .forget();
    client.write_all(&[7u8; 64 * 1024]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // What the failed gateway writer does first: it closes the budget.
    budget.close();

    let (_, end) = tokio::time::timeout(TIMEOUT, read_socket_end(&mut client))
        .await
        .expect("the client's connection did not end");
    assert_eq!(end, StreamEnd::Reset);

    for pump in pumps {
        tokio::time::timeout(TIMEOUT, pump)
            .await
            .expect("a pump outlived the connection")
            .unwrap();
    }
}

/// A TLS client which closes without a close_notify - many do - reads as `UnexpectedEof`: that is
/// the end of its stream, passed on as one, not a failure.
#[tokio::test]
async fn a_tls_end_without_close_notify_passes_on_as_the_end_of_the_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (accepted, _) = listener.accept().await.unwrap();
    let (accepted_read, accepted_write) = accepted.into_split();

    let pump = tokio::spawn(copy_streams(
        TruncatedTlsReader,
        crate::network_stream::MyOwnedWriteHalf::from(accepted_write),
        LoopBuffer::new(),
        None,
        None,
        None,
        Arc::new(ConnectionPumps::new(HttpTimeouts::default())),
    ));
    tokio::time::timeout(TIMEOUT, pump)
        .await
        .expect("the pump did not end")
        .unwrap();
    drop(accepted_read);

    let (_, end) = tokio::time::timeout(TIMEOUT, read_socket_end(&mut client))
        .await
        .expect("the client's connection did not end");
    assert_eq!(end, StreamEnd::End);
}

/// A websocket client which drops its transport right after its Close went through - as a TLS
/// client without a close_notify does - ends the session cleanly: the upstream is closed when the
/// session ends, not reset.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_websocket_client_which_drops_its_transport_after_its_close_resets_nothing() {
    use futures::SinkExt;
    use hyper_tungstenite::tungstenite::Message;

    let gateway = Gateway::start("ws-close-then-drop", false).await;
    let (arrived_tx, mut arrived) = mpsc::unbounded_channel();
    let (ended_tx, mut ended) = mpsc::unbounded_channel();
    // The client's Close is a masked frame of at least 6 bytes. The upstream keeps its side open:
    // the session ends when it goes idle.
    let upstream = start_upstream(move |stream| {
        read_until_the_end(stream, 6, arrived_tx.clone(), ended_tx.clone())
    })
    .await;

    let mut ctx = websocket_pump_context();
    ctx.timeouts = HttpTimeouts {
        read_timeout: Duration::from_secs(2),
        write_timeout: Duration::from_secs(5),
    };
    let port = start_websocket_pump_with(gateway.connect_from_client(upstream).await, ctx).await;
    let mut websocket = connect_websocket_client(port).await;

    websocket.send(Message::Close(None)).await.unwrap();
    tokio::time::timeout(TIMEOUT, arrived.recv())
        .await
        .expect("the Close did not arrive");

    websocket.get_ref().set_zero_linger().unwrap();
    drop(websocket);

    let end = tokio::time::timeout(TIMEOUT, ended.recv())
        .await
        .expect("the upstream's connection did not end")
        .unwrap();
    assert_eq!(end, StreamEnd::End);
}

/// A websocket client which resets: the upstream connection through the gateway is reset too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_websocket_client_which_resets_resets_the_upstream() {
    use futures::SinkExt;
    use hyper_tungstenite::tungstenite::Message;

    let gateway = Gateway::start("ws-client-reset", false).await;
    let (arrived_tx, mut arrived) = mpsc::unbounded_channel();
    let (ended_tx, mut ended) = mpsc::unbounded_channel();
    let upstream = start_upstream(move |stream| {
        read_until_the_end(stream, 1, arrived_tx.clone(), ended_tx.clone())
    })
    .await;

    let port = start_websocket_pump(gateway.connect_from_client(upstream).await).await;
    let mut websocket = connect_websocket_client(port).await;

    websocket
        .send(Message::binary(vec![1, 2, 3]))
        .await
        .unwrap();
    tokio::time::timeout(TIMEOUT, arrived.recv())
        .await
        .expect("the message did not arrive");

    websocket.get_ref().set_zero_linger().unwrap();
    drop(websocket);

    let end = tokio::time::timeout(TIMEOUT, ended.recv())
        .await
        .expect("the upstream's connection did not end")
        .unwrap();
    assert_eq!(end, StreamEnd::Reset);
}

/// An h2 websocket whose client stops reading while the upstream keeps sending: the write to the
/// client times out, and the upstream connection is reset.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_h2_websocket_session_which_fails_resets_the_upstream() {
    let gateway = Gateway::start("ws-h2-reset", false).await;
    let (ended_tx, mut ended) = mpsc::unbounded_channel();
    let upstream = start_upstream(move |mut stream| {
        let ended = ended_tx.clone();
        async move {
            stream.write_all(&vec![9u8; 1024 * 1024]).await.unwrap();
            let _ = ended.send(read_socket_end(&mut stream).await.1);
        }
    })
    .await;

    let mut ctx = websocket_pump_context();
    ctx.timeouts = HttpTimeouts {
        read_timeout: Duration::from_secs(30),
        write_timeout: Duration::from_secs(1),
    };
    let port = start_h2_websocket_pump_with(gateway.connect_from_client(upstream).await, ctx).await;
    let tunnel = connect_h2_tunnel(port, 64 * 1024).await;

    let end = tokio::time::timeout(TIMEOUT, ended.recv())
        .await
        .expect("the upstream's connection did not end")
        .unwrap();
    assert_eq!(end, StreamEnd::Reset);
    drop(tunnel);
}

// Speed, limits and liveness.

/// The compression level is the client's setting, and it holds for both directions: the server
/// packs what it sends with the level its client asked for in its handshake. With it off neither
/// end packs. What an end counts as sent and as received is what is on the wire.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_compression_level_of_the_client_holds_for_both_directions() {
    let text = Arc::new(compressible(4 * 1024 * 1024, 1));

    // What the text went as up, at every level.
    let mut sent_up = Vec::new();

    for compression in CompressionLevel::all() {
        let name = format!("packed-{}", compression.as_u8());
        let gateway = Gateway::start_at(&name, compression).await;
        let (server_side, client_side) = (gateway.server_side(), gateway.client_side());

        assert_eq!(client_side.compression(), compression);
        assert_eq!(server_side.compression(), compression);

        let compress = compression.is_on();

        // Up: what the client sends, as it leaves and as the server gets it off the wire.
        let (collected_tx, mut collected) = mpsc::unbounded_channel();
        let upstream =
            start_upstream(move |stream| collect(stream, collected_tx.clone(), Duration::ZERO))
                .await;
        // Counted from before the connection is there: nothing of it is missed.
        client_side.out_per_second.get_per_second();
        server_side.in_per_second.get_per_second();
        let mut stream = gateway.connect_from_client(upstream).await;
        stream.write_to_socket(&text).await.unwrap();
        stream.disconnect();
        let received = tokio::time::timeout(TIMEOUT, collected.recv())
            .await
            .expect("the upstream connection is closed")
            .unwrap();
        assert!(received == *text);
        let up = [
            sent_by(&client_side, if compress { 0 } else { text.len() }).await,
            server_side.in_per_second.get_per_second(),
        ];

        // Down: what the server sends, as it leaves and as the client gets it off the wire.
        let upstream = {
            let text = text.clone();
            start_upstream(move |stream| send_and_close(stream, text.clone())).await
        };
        // The upstream sends as soon as it is connected to - before the connect is answered.
        server_side.out_per_second.get_per_second();
        client_side.in_per_second.get_per_second();
        let mut stream = gateway.connect_from_client(upstream).await;
        assert!(read_to_end(&mut stream).await.unwrap() == *text);
        let down = [
            sent_by(&server_side, if compress { 0 } else { text.len() }).await,
            client_side.in_per_second.get_per_second(),
        ];

        for on_the_wire in up.into_iter().chain(down) {
            if compress {
                assert!(
                    on_the_wire < text.len() / 2,
                    "{name}: {} bytes went as {up:?} up and {down:?} down",
                    text.len()
                );
            } else {
                assert!(
                    on_the_wire >= text.len(),
                    "{name}: {} bytes went as {up:?} up and {down:?} down",
                    text.len()
                );
            }
        }

        sent_up.push(up[1]);
    }

    // The levels are not one algorithm under several names: what Zstandard packs is smaller
    // than what LZ4 does.
    for zstd_level in 2..sent_up.len() {
        assert!(
            sent_up[zstd_level] < sent_up[1],
            "level {zstd_level} sent as much as LZ4: {sent_up:?}"
        );
    }
}

/// What `side` has counted as sent. A writer counts a write right after it is done, which may be
/// a moment after the peer has what was written: this waits for `at_least` bytes, for a second.
async fn sent_by(side: &TcpGatewayConnection, at_least: usize) -> usize {
    let mut sent = side.out_per_second.get_per_second();

    for _ in 0..200 {
        if sent >= at_least {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
        sent += side.out_per_second.get_per_second();
    }

    sent
}

/// The biggest file a response carries - one which can not be made smaller - served by either
/// end with compression on, whatever the level: the frame which carries it is within what the
/// other end accepts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_biggest_file_is_served_by_either_end_with_compression_on() {
    let dir = std::env::temp_dir().join(format!("gateway-biggest-file-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("biggest.bin");
    let content = pseudo_random(MAX_FILE_RESPONSE_SIZE);
    std::fs::write(&file, &content).unwrap();
    let path = file.to_str().unwrap();

    for compression in CompressionLevel::all().filter(|level| level.is_on()) {
        let name = format!("biggest-file-{}", compression.as_u8());
        let gateway = Gateway::start_at(&name, compression).await;
        let (server_side, client_side) = (gateway.server_side(), gateway.client_side());

        assert!(
            server_side.request_file(path).await.ok().as_deref() == Some(content.as_slice()),
            "{name}"
        );
        assert!(
            client_side.request_file(path).await.ok().as_deref() == Some(content.as_slice()),
            "{name}"
        );

        assert!(Arc::ptr_eq(&gateway.server_side(), &server_side));
        assert!(Arc::ptr_eq(&gateway.client_side(), &client_side));
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Many connections at once, opened from both ends, each echoing data of its own - in pieces of
/// its own size, some of it text and some of it noise: nothing of one connection ends up in
/// another, whatever the batches are packed with, and nothing is left registered once they are
/// done.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn many_connections_at_once_keep_their_data_apart() {
    for compression in CompressionLevel::all() {
        let name = &format!("many-{}", compression.as_u8());
        let gateway = Gateway::start_at(name, compression).await;
        let (server_side, client_side) = (gateway.server_side(), gateway.client_side());
        let upstream = start_upstream(|stream| echo(stream, None)).await;

        let mut transfers = Vec::new();
        for no in 0..120usize {
            let stream = if no % 2 == 0 {
                gateway.connect_from_client(upstream).await
            } else {
                gateway.connect_from_server(upstream).await
            };

            let size = [1, 100, 4096, 65_536, 300_000, 1_500_000, 3_000_000][no % 7] + no;
            let data = if no % 3 == 0 {
                compressible(size, no as u64)
            } else {
                pseudo_random_seeded(size, no as u64)
            };
            let piece = 1 + (no * 7919) % (300 * 1024);

            transfers.push(tokio::spawn(echo_round_trip_of(stream, data, piece)));
        }

        for transfer in transfers {
            tokio::time::timeout(Duration::from_secs(120), transfer)
                .await
                .unwrap_or_else(|_| panic!("{name}: a transfer stalled"))
                .unwrap();
        }

        assert!(Arc::ptr_eq(&gateway.server_side(), &server_side));
        wait_until(|| {
            client_side.get_forward_proxy_connections_amount() == 0
                && client_side.get_forward_connections_amount() == 0
                && server_side.get_forward_proxy_connections_amount() == 0
                && server_side.get_forward_connections_amount() == 0
        })
        .await;
    }
}

/// What a client puts on the wire first: a PING, at once, with nothing in it.
#[tokio::test]
async fn a_client_pings_as_soon_as_it_is_connected() {
    const NAME: &str = "first-ping";

    let key = signing_key();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let _client = start_client(NAME, &key, port, false);

    let (mut stream, _) = tokio::time::timeout(TIMEOUT, listener.accept())
        .await
        .expect("the client did not connect")
        .unwrap();
    let outcome = handshake::perform_server_handshake(&mut stream, &[key.verifying_key()])
        .await
        .unwrap();
    let (_sealer, mut opener) = outcome.session_keys.into_server_ends();

    let connected = Instant::now();
    let frames = tokio::time::timeout(
        TIMEOUT,
        session::read_frame_for_tests(&mut stream, &mut opener),
    )
    .await
    .expect("the client sent nothing");

    // Well before the second one is due.
    assert!(
        connected.elapsed() < Duration::from_secs(2),
        "the first frame took {:?}",
        connected.elapsed()
    );
    assert_eq!(frames, vec![vec![0u8]]);
}

/// A frame which is not what the peer sealed - a bit changed on the way - ends the gateway
/// connection: nothing of it reaches a handler.
#[tokio::test]
async fn a_frame_which_does_not_open_closes_the_gateway_connection() {
    const NAME: &str = "raw-client";

    let key = signing_key();
    let (server, port) = start_server(&key, None).await;

    let mut client = RawClient::connect(&server, port, &key, NAME).await;

    // As a client sends it: the server answers - and the PONG is the first frame it sends at all.
    client.send(&TcpGatewayContract::Ping).await;
    assert_eq!(client.read_frame().await, vec![1u8]);

    // With one bit changed on the way.
    let mut changed = client.seal(&TcpGatewayContract::Ping);
    *changed.last_mut().unwrap() ^= 1;
    client.stream.write_all(&changed).await.unwrap();

    wait_until(|| server.get_gateway_connection(NAME).is_none()).await;

    let mut rest = Vec::new();
    let closed = tokio::time::timeout(TIMEOUT, client.stream.read_to_end(&mut rest)).await;
    assert!(closed.is_ok(), "the server did not close the socket");
    assert!(rest.is_empty(), "the frame which did not open was answered");
}

/// What a peer may not send ends the gateway connection, whichever of the two read-side tasks
/// finds it - and the socket is closed for good, its reading side too: a peer which goes on
/// writing gets an error instead of a socket which takes its bytes and handles none.
#[tokio::test]
async fn what_a_peer_may_not_send_closes_the_gateway_connection() {
    type Bad = Box<dyn Fn(&mut RawClient) -> Vec<u8>>;

    let sealed = |batch: Vec<u8>| -> Bad { Box::new(move |client| client.seal_batch(&batch)) };

    let cases: Vec<(&str, Bad)> = vec![
        (
            "a frame bigger than the limit",
            Box::new(|_| ((MAX_PAYLOAD_SIZE + 1) as u32).to_le_bytes().to_vec()),
        ),
        (
            "a frame which is a tag and nothing else",
            Box::new(|_| {
                let mut wire = (session::FRAME_TAG_LEN as u32).to_le_bytes().to_vec();
                wire.extend_from_slice(&[0u8; session::FRAME_TAG_LEN]);
                wire
            }),
        ),
        (
            "a batch of a kind which is none",
            sealed(vec![7, 1, 0, 0, 0, 0]),
        ),
        (
            "a packed batch which says it unpacks to more than the limit",
            {
                let mut batch = vec![session::BATCH_LZ4];
                batch.extend_from_slice(&(MAX_DECOMPRESSED_BATCH_SIZE as u32 + 1).to_le_bytes());
                batch.extend_from_slice(&[0u8; 32]);
                sealed(batch)
            },
        ),
        (
            "a batch packed with zstd which says it unpacks to more than the limit",
            {
                let mut batch = vec![session::BATCH_ZSTD];
                batch.extend_from_slice(&(MAX_DECOMPRESSED_BATCH_SIZE as u32 + 1).to_le_bytes());
                batch.extend_from_slice(&[0u8; 32]);
                sealed(batch)
            },
        ),
        ("a batch said to be packed with lz4 which is not", {
            let mut batch = vec![session::BATCH_LZ4];
            batch.extend_from_slice(&1000u32.to_le_bytes());
            batch.extend_from_slice(&pseudo_random(300));
            sealed(batch)
        }),
        ("a batch said to be packed with zstd which is not", {
            let mut batch = vec![session::BATCH_ZSTD];
            batch.extend_from_slice(&1000u32.to_le_bytes());
            batch.extend_from_slice(&pseudo_random(300));
            sealed(batch)
        }),
        (
            "an inner frame cut short",
            sealed(vec![session::BATCH_STORED, 9, 0, 0, 0, 0]),
        ),
        (
            "bytes behind the last inner frame",
            sealed(vec![session::BATCH_STORED, 1, 0, 0, 0, 0, 0xff, 0xff]),
        ),
        (
            "an inner frame with nothing in it",
            sealed(vec![session::BATCH_STORED, 0, 0, 0, 0]),
        ),
        (
            "an inner frame of a type which is none",
            sealed(vec![session::BATCH_STORED, 1, 0, 0, 0, 99]),
        ),
    ];

    for (index, (what, bad)) in cases.iter().enumerate() {
        let name = format!("may-not-send-{index}");
        let key = signing_key();
        let (server, port) = start_server(&key, None).await;
        let mut client = RawClient::connect(&server, port, &key, &name).await;

        // It speaks the protocol: until the frame under test the server answers it.
        client.send(&TcpGatewayContract::Ping).await;
        assert_eq!(client.read_frame().await, vec![1u8], "{what}");

        let wire = bad(&mut client);
        client.stream.write_all(&wire).await.unwrap();

        tokio::time::timeout(TIMEOUT, async {
            while server.get_gateway_connection(&name).is_some() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{what}: the gateway connection is still there"));

        let mut refused = false;
        for _ in 0..100 {
            if client.stream.write_all(&[0u8; 1024]).await.is_err() {
                refused = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            refused,
            "{what}: the socket still takes what is written to it"
        );
    }
}

/// A healthy link is not given up: an idle gateway held past the client's dead-peer check - 9
/// seconds of silence, looked at every 3 - is still the same pair of connected objects. The
/// client records what comes in, and the server answers every PING.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_idle_healthy_gateway_outlives_the_dead_peer_check() {
    let gateway = Gateway::start("idle-healthy", false).await;
    let (server_side, client_side) = (gateway.server_side(), gateway.client_side());

    tokio::time::sleep(Duration::from_secs(15)).await;

    assert!(client_side.is_gateway_connected() && server_side.is_gateway_connected());
    assert!(Arc::ptr_eq(&gateway.client_side(), &client_side));
    assert!(Arc::ptr_eq(&gateway.server_side(), &server_side));

    // And it works.
    let upstream = start_upstream(|stream| echo(stream, None)).await;
    let mut stream = gateway.connect_from_client(upstream).await;
    assert_echoes(&mut stream).await;
}

/// A client whose key the server does not list is not let in, whatever it signs.
#[tokio::test]
async fn a_client_with_a_key_which_is_not_authorized_is_not_let_in() {
    let key = signing_key();
    let (server, port) = start_server(&key, None).await;

    let _stranger = start_client("stranger", &signing_key(), port, false);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(server.get_gateway_connection("stranger").is_none());

    let _known = start_client("known", &key, port, false);
    wait_until(|| server.get_gateway_connection("known").is_some()).await;
    assert!(server.get_gateway_connection("stranger").is_none());
}

/// A link which goes silent without closing anything - a route which died. The client gives the
/// connection up within its dead-peer check, what waits on it fails, and once the link passes
/// bytes again the gateway is back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silent_link_is_given_up_and_the_gateway_comes_back() {
    const NAME: &str = "silent-link";

    let key = signing_key();
    let (server, server_port) = start_server(&key, None).await;
    let link = Link::start(server_port).await;
    let client = start_client(NAME, &key, link.port, false);

    wait_until(|| {
        server.get_gateway_connection(NAME).is_some()
            && client.get_gateway_connection(NAME).is_some()
    })
    .await;
    let client_before = client.get_gateway_connection(NAME).unwrap();
    let server_before = server.get_gateway_connection(NAME).unwrap();

    let upstream = start_upstream(|stream| echo(stream, None)).await;
    let mut stream = client_before
        .connect_to_forward_proxy_connection(
            endpoint(upstream),
            CONNECT_TIMEOUT,
            client.get_next_connection_id(),
        )
        .await
        .unwrap();
    assert_echoes(&mut stream).await;

    let went_silent = Instant::now();
    link.go_silent();

    // A request in flight when the link dies.
    let in_flight = tokio::spawn(async move {
        let _ = stream.write_to_socket(b"into the void").await;
        let mut buf = [0u8; 64];
        stream.read_from_socket(&mut buf).await
    });

    // 9 seconds of silence, looked at every 3.
    wait_until_within(Duration::from_secs(20), || {
        !client_before.is_gateway_connected()
    })
    .await;
    assert!(went_silent.elapsed() >= Duration::from_secs(9));

    let answer = tokio::time::timeout(TIMEOUT, in_flight)
        .await
        .expect("what waited on the dead link was left waiting")
        .unwrap();
    assert!(
        answer.is_err(),
        "a request cut by a dead link must read as an error"
    );

    // The link passes new connections again: the client is back, and the server lets its side
    // of the dead connection go for the new one.
    wait_until_within(Duration::from_secs(20), || {
        client
            .get_gateway_connection(NAME)
            .is_some_and(|connection| !Arc::ptr_eq(&connection, &client_before))
            && server
                .get_gateway_connection(NAME)
                .is_some_and(|connection| !Arc::ptr_eq(&connection, &server_before))
    })
    .await;
    assert!(!server_before.is_gateway_connected());

    let mut stream = client
        .get_gateway_connection(NAME)
        .unwrap()
        .connect_to_forward_proxy_connection(
            endpoint(upstream),
            CONNECT_TIMEOUT,
            client.get_next_connection_id(),
        )
        .await
        .unwrap();
    assert_echoes(&mut stream).await;
}

/// A client which vanished and can not come back. Nothing tells the server: it finds out by the
/// silence, and stops routing to the client once that has lasted for the read timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_server_drops_a_client_silent_for_the_read_timeout() {
    const NAME: &str = "vanished-client";

    let key = signing_key();
    let (server, server_port) = start_server(&key, None).await;
    let link = Link::start(server_port).await;
    let _client = start_client(NAME, &key, link.port, false);

    wait_until(|| server.get_gateway_connection(NAME).is_some()).await;
    let server_side = server.get_gateway_connection(NAME).unwrap();

    let went_silent = Instant::now();
    link.go_silent_for_good();

    wait_until_within(Duration::from_secs(45), || {
        !server_side.is_gateway_connected()
    })
    .await;
    assert!(went_silent.elapsed() >= Duration::from_secs(25));
    wait_until(|| server.get_gateway_connection(NAME).is_none()).await;
}

/// What the tunnel moves per second at every compression level, and how much smaller the data
/// is on the wire for it: one connection, both directions. For a release build:
/// `cargo test --release --bin my-reverse-proxy throughput -- --ignored --nocapture`
///
/// It prints what the tables of docs/gateway-compression.md are made of: the best of
/// `GATEWAY_BENCH_ROUNDS` runs (3, when it is not set) of every level. The data is rows of an API
/// answer, HTTP requests with their answers, and bytes nothing packs.
/// `GATEWAY_BENCH_FILES=/a/sample.json,/b/sample.html` measures samples of the real traffic
/// instead.
///
/// The data is megabytes which do not repeat, sent over and over: a block which comes round
/// again within moments is packed far faster than data ever is - the processor has learned its
/// way through it - and the figure would be of that. So a sample is to be megabytes as well.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn throughput() {
    /// How long one end sends for, in one run.
    const SENDING: Duration = Duration::from_millis(1500);
    const MIB: f64 = 1024.0 * 1024.0;

    let rounds: usize = std::env::var("GATEWAY_BENCH_ROUNDS")
        .ok()
        .and_then(|rounds| rounds.parse().ok())
        .unwrap_or(3);

    println!("| data | level | packed with | ratio | up, MiB/s | down, MiB/s |");
    println!("|---|---|---|---|---|---|");

    for (sample_no, (sample_name, sample)) in bench_samples().into_iter().enumerate() {
        for compression in CompressionLevel::all() {
            let (mut ratio, mut best_up, mut best_down) = (0f64, 0f64, 0f64);

            for round in 0..rounds {
                let name = format!("throughput-{sample_no}-{}-{round}", compression.as_u8());
                let gateway = Gateway::start_at(&name, compression).await;
                let client_side = gateway.client_side();

                // Up: the client writes, an upstream behind the server takes it.
                let (taken_tx, mut taken) = mpsc::unbounded_channel();
                let upstream = start_upstream(move |mut stream| {
                    let taken_tx = taken_tx.clone();
                    async move {
                        let mut buf = vec![0u8; 1024 * 1024];
                        let mut total = 0usize;
                        while let Ok(read_size) = stream.read(&mut buf).await {
                            if read_size == 0 {
                                break;
                            }
                            total += read_size;
                        }
                        let _ = taken_tx.send(total);
                    }
                })
                .await;

                let mut stream = gateway.connect_from_client(upstream).await;
                client_side.out_per_second.get_per_second();
                let started = Instant::now();
                let mut sent = 0usize;
                'sending: loop {
                    for piece in sample.chunks(MAX_PAYLOAD_CHUNK) {
                        stream.write_to_socket(piece).await.unwrap();
                        sent += piece.len();
                        if started.elapsed() >= SENDING {
                            break 'sending;
                        }
                    }
                }
                stream.disconnect();
                let received = tokio::time::timeout(Duration::from_secs(300), taken.recv())
                    .await
                    .expect("the upload did not end")
                    .unwrap();
                assert_eq!(received, sent);
                let up = sent as f64 / MIB / started.elapsed().as_secs_f64();
                ratio = sent as f64 / sent_by(&client_side, 1).await as f64;

                // Down: an upstream behind the server writes, the client reads.
                let upstream = {
                    let sample = sample.clone();
                    start_upstream(move |mut stream| {
                        let sample = sample.clone();
                        async move {
                            let started = Instant::now();
                            loop {
                                for piece in sample.chunks(MAX_PAYLOAD_CHUNK) {
                                    if stream.write_all(piece).await.is_err()
                                        || started.elapsed() >= SENDING
                                    {
                                        return;
                                    }
                                }
                            }
                        }
                    })
                    .await
                };

                let mut stream = gateway.connect_from_client(upstream).await;
                let started = Instant::now();
                let mut buf = vec![0u8; 1024 * 1024];
                let mut received = 0usize;
                loop {
                    match stream.read_from_socket(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(read_size) => received += read_size,
                    }
                }
                let down = received as f64 / MIB / started.elapsed().as_secs_f64();

                best_up = best_up.max(up);
                best_down = best_down.max(down);
            }

            println!(
                "| {sample_name} | {} | {compression} | {ratio:.2} | {best_up:.0} | {best_down:.0} |",
                compression.as_u8()
            );
        }
    }
}

/// What a small request and its answer cost through the tunnel at a compression level: 100
/// bytes there, 100 bytes back, over one connection and over many at once. For a release build:
/// `cargo test --release --bin my-reverse-proxy round_trips -- --ignored --nocapture`
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn round_trips() {
    println!(
        "| level | packed with | connections | round trips a second | of one connection, us |"
    );
    println!("|---|---|---|---|---|");

    for compression in CompressionLevel::all() {
        for (connections, per_connection) in [(1usize, 30_000usize), (64, 5_000)] {
            let name = format!("round-trips-{}-{connections}", compression.as_u8());
            let gateway = Gateway::start_at(&name, compression).await;
            let upstream = start_upstream(|stream| echo(stream, None)).await;

            let mut streams = Vec::new();
            for _ in 0..connections {
                streams.push(gateway.connect_from_client(upstream).await);
            }

            let started = Instant::now();

            let tasks: Vec<_> = streams
                .into_iter()
                .enumerate()
                .map(|(no, mut stream)| {
                    tokio::spawn(async move {
                        // A request of its own for every connection: text, as requests are.
                        let request = compressible(100, no as u64);
                        let mut buf = [0u8; 256];

                        for _ in 0..per_connection {
                            stream.write_to_socket(&request).await.unwrap();

                            let mut answered = 0;
                            while answered < request.len() {
                                answered += stream.read_from_socket(&mut buf).await.unwrap();
                            }
                        }
                    })
                })
                .collect();

            for task in tasks {
                task.await.unwrap();
            }

            let elapsed = started.elapsed();
            let total = connections * per_connection;

            println!(
                "| {} | {compression} | {connections} | {:.0} | {:.1} |",
                compression.as_u8(),
                total as f64 / elapsed.as_secs_f64(),
                elapsed.as_secs_f64() * 1_000_000.0 / per_connection as f64,
            );
        }
    }
}

/// How much a level saves by the size of a batch: the bytes the batches take on the wire
/// without compression for a byte they take with it, the sealing of a frame counted in both. A
/// batch is packed on its own, so the frames of a busy connection - they travel in big batches -
/// pack better than the same frames sent one by one. The data is the first megabytes of what
/// [`throughput`] sends, cut into batches of every size:
/// `cargo test --release --bin my-reverse-proxy batch_sizes -- --ignored --nocapture`
#[test]
#[ignore]
fn batch_sizes() {
    const SIZES: [usize; 6] = [256, 1024, 4096, 16 * 1024, 64 * 1024, 256 * 1024];

    /// What a frame adds to the batch it carries.
    const SEALING: usize = session::FRAME_LEN_SIZE + session::FRAME_TAG_LEN;

    println!("| data | level | packed with | 256 B | 1 KiB | 4 KiB | 16 KiB | 64 KiB | 256 KiB |");
    println!("|---|---|---|---|---|---|---|---|---|");

    for (sample_name, sample) in bench_samples() {
        let sample = &sample[..sample.len().min(2 * 1024 * 1024)];

        for compression in CompressionLevel::all().filter(|level| level.is_on()) {
            let mut packer = session::BatchPacker::new(compression);
            let mut wire = Vec::new();
            let mut ratios = String::new();

            for size in SIZES {
                let (mut packed, mut not_packed) = (0usize, 0usize);

                for batch in sample.chunks(size) {
                    wire.clear();
                    packer.write_batch(batch, &mut wire);
                    packed += wire.len() + SEALING;
                    not_packed += 1 + batch.len() + SEALING;
                }

                ratios += &format!(" {:.2} |", not_packed as f64 / packed as f64);
            }

            println!(
                "| {sample_name} | {} | {compression} |{ratios}",
                compression.as_u8()
            );
        }
    }
}

/// What [`throughput`] sends: the samples named by `GATEWAY_BENCH_FILES`, or the data made here.
fn bench_samples() -> Vec<(String, Arc<Vec<u8>>)> {
    /// Far beyond what a packer looks back at, and enough for what repeats to be forgotten.
    const SAMPLE_SIZE: usize = 8 * 1024 * 1024;

    if let Ok(files) = std::env::var("GATEWAY_BENCH_FILES") {
        return files
            .split(',')
            .map(|file| {
                let mut sample = std::fs::read(file.trim())
                    .unwrap_or_else(|err| panic!("GATEWAY_BENCH_FILES: {file}: {err}"));
                sample.truncate(8 * SAMPLE_SIZE);

                let name = std::path::Path::new(file.trim())
                    .file_name()
                    .map(|name| name.to_string_lossy().to_string())
                    .unwrap_or_else(|| file.to_string());

                (name, Arc::new(sample))
            })
            .collect();
    }

    vec![
        ("API rows".to_string(), Arc::new(api_rows(SAMPLE_SIZE))),
        (
            "HTTP messages".to_string(),
            Arc::new(http_messages(SAMPLE_SIZE)),
        ),
        (
            "packed already".to_string(),
            Arc::new(pseudo_random(SAMPLE_SIZE)),
        ),
    ]
}

/// Requests of an API with their answers, as they travel through a proxy: the headers of a
/// browser, a token, an id of its own in every one - and a small JSON body in the answer.
fn http_messages(size: usize) -> Vec<u8> {
    let mut state = 0x0FED_CBA9_8765_4321u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    let mut out = Vec::with_capacity(size + 2048);

    while out.len() < size {
        let (a, b, c, d) = (next(), next(), next(), next());
        let account = a % 900_000 + 100_000;

        out.extend_from_slice(
            format!(
                "GET /api/v1/accounts/{account}/positions?limit=50&offset={} HTTP/1.1\r\n\
                 host: api.example.com\r\n\
                 user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36\r\n\
                 accept: application/json, text/plain, */*\r\n\
                 accept-encoding: gzip, deflate, br, zstd\r\n\
                 accept-language: en-US,en;q=0.9\r\n\
                 authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{b:016x}{c:016x}.{d:016x}\r\n\
                 x-request-id: {c:016x}\r\n\
                 cookie: session={d:x}; theme=dark\r\n\r\n",
                b % 13 * 50,
            )
            .as_bytes(),
        );

        let body = format!(
            "{{\"account\":{account},\"balance\":{}.{:02},\"currency\":\"USD\",\"positions\":[{{\"symbol\":\"EURUSD\",\"volume\":{}.{:02},\"profit\":{}.{:02}}}]}}",
            b % 100_000,
            c % 100,
            d % 50,
            a % 100,
            (c % 10_000) as i64 - 5_000,
            b % 100,
        );

        out.extend_from_slice(
            format!(
                "HTTP/1.1 200 OK\r\n\
                 content-type: application/json; charset=utf-8\r\n\
                 content-length: {}\r\n\
                 date: Tue, 13 Oct 2026 12:{:02}:{:02} GMT\r\n\
                 cache-control: no-store\r\n\
                 x-request-id: {c:016x}\r\n\
                 strict-transport-security: max-age=31536000\r\n\r\n{body}",
                body.len(),
                a % 60,
                b % 60,
            )
            .as_bytes(),
        );
    }

    out.truncate(size);
    out
}

/// Rows of an API answer: the names repeat from row to row, the values do not.
fn api_rows(size: usize) -> Vec<u8> {
    const SYMBOLS: [&str; 8] = [
        "EURUSD", "GBPUSD", "USDJPY", "XAUUSD", "BTCUSD", "US500", "GER40", "AUDCAD",
    ];

    let mut state = 0x1234_5678_9ABC_DEF1u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    let mut out = Vec::with_capacity(size + 256);

    while out.len() < size {
        let (a, b, c) = (next(), next(), next());

        out.extend_from_slice(
            format!(
                "{{\"id\":\"{a:016x}\",\"account\":{},\"symbol\":\"{}\",\"volume\":{}.{:02},\"open_price\":{}.{:05},\"profit\":{}.{:02},\"comment\":\"{:x}\",\"open_time\":\"2026-10-{:02}T{:02}:{:02}:{:02}Z\"}},\n",
                b % 900_000 + 100_000,
                SYMBOLS[(c % 8) as usize],
                c % 50,
                a % 100,
                b % 2000,
                c % 100_000,
                (a % 20_000) as i64 - 10_000,
                b % 100,
                c >> 40,
                a % 28 + 1,
                b % 24,
                c % 60,
                a % 60,
            )
            .as_bytes(),
        );
    }

    out.truncate(size);
    out
}

struct Gateway {
    server: TcpGatewayServer,
    client: TcpGatewayClient,
    name: String,
}

impl Gateway {
    /// Both ends registered. `compress`: at the first level of the table - LZ4.
    async fn start(name: &str, compress: bool) -> Self {
        Self::start_at(name, first_level_if(compress)).await
    }

    /// Both ends registered, the batches packed with what `compression` says.
    async fn start_at(name: &str, compression: CompressionLevel) -> Self {
        let key = signing_key();
        let (server, port) = start_server(&key, None).await;
        let client = start_client_at(name, &key, port, compression);

        wait_until(|| {
            server.get_gateway_connection(name).is_some()
                && client.get_gateway_connection(name).is_some()
        })
        .await;

        Self {
            server,
            client,
            name: name.to_string(),
        }
    }

    fn server_side(&self) -> Arc<TcpGatewayConnection> {
        self.server
            .get_gateway_connection(&self.name)
            .expect("the server side is connected")
    }

    fn client_side(&self) -> Arc<TcpGatewayConnection> {
        self.client
            .get_gateway_connection(&self.name)
            .expect("the client side is connected")
    }

    /// A connection from the client end to `upstream_port`, reached behind the server.
    async fn connect_from_client(&self, upstream_port: u16) -> TcpGatewayProxyForwardStream {
        self.client_side()
            .connect_to_forward_proxy_connection(
                endpoint(upstream_port),
                CONNECT_TIMEOUT,
                self.client.get_next_connection_id(),
            )
            .await
            .unwrap()
    }

    /// A connection from the server end to `upstream_port`, reached behind the client.
    async fn connect_from_server(&self, upstream_port: u16) -> TcpGatewayProxyForwardStream {
        self.server_side()
            .connect_to_forward_proxy_connection(
                endpoint(upstream_port),
                CONNECT_TIMEOUT,
                self.server.get_next_connection_id(),
            )
            .await
            .unwrap()
    }
}

async fn start_server(key: &SigningKey, allowed_ip: Option<&[&str]>) -> (TcpGatewayServer, u16) {
    let port = free_port().await;

    let allowed_ip = allowed_ip.map(|list| {
        let list: Vec<String> = list.iter().map(|itm| itm.to_string()).collect();
        WhiteListedIpList::new(&list)
    });

    // It listens once it is constructed: a client may connect at once.
    let server = TcpGatewayServer::new(
        format!("127.0.0.1:{port}"),
        vec![key.verifying_key()],
        allowed_ip,
        false,
    )
    .expect("the gateway server starts");

    (server, port)
}

/// The first level of the table - LZ4 - or no compression.
fn first_level_if(compress: bool) -> CompressionLevel {
    CompressionLevel::new(compress as u8).unwrap()
}

fn start_client(name: &str, key: &SigningKey, port: u16, compress: bool) -> TcpGatewayClient {
    start_client_at(name, key, port, first_level_if(compress))
}

fn start_client_at(
    name: &str,
    key: &SigningKey,
    port: u16,
    compression: CompressionLevel,
) -> TcpGatewayClient {
    TcpGatewayClient::new(TcpGatewayClientParams {
        id: name.to_string(),
        remote_endpoint: format!("127.0.0.1:{port}"),
        signing_key: key.clone(),
        compression,
        allow_incoming_forward_connections: true,
        connect_timeout: CONNECT_TIMEOUT,
        debug: false,
        sync_ssl_certificates: Vec::new(),
    })
}

/// A gateway client driven by hand: the frames it sends and the frames it gets, one by one.
struct RawClient {
    stream: TcpStream,
    sealer: session::FrameSealer,
    opener: session::FrameOpener,
    received: std::collections::VecDeque<Vec<u8>>,
}

impl RawClient {
    /// Connected and past the handshake, registered on `server` as `name`.
    async fn connect(server: &TcpGatewayServer, port: u16, key: &SigningKey, name: &str) -> Self {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let session_keys =
            handshake::perform_client_handshake(&mut stream, key, name, CompressionLevel::OFF)
                .await
                .unwrap();
        let (sealer, opener) = session_keys.into_client_ends();
        wait_until(|| server.get_gateway_connection(name).is_some()).await;

        Self {
            stream,
            sealer,
            opener,
            received: Default::default(),
        }
    }

    /// `contract` as a sealed frame of its own, ready for the wire.
    fn seal(&mut self, contract: &TcpGatewayContract<'_>) -> Vec<u8> {
        let mut wire = vec![0u8; session::FRAME_LEN_SIZE];
        wire.push(session::BATCH_STORED);
        wire.extend_from_slice(&contract.to_plain_frame());
        self.sealer.seal(&mut wire).unwrap();
        wire
    }

    /// `batch` - whatever it is - as a sealed frame: one which opens, and is refused for what it
    /// carries.
    fn seal_batch(&mut self, batch: &[u8]) -> Vec<u8> {
        let mut wire = vec![0u8; session::FRAME_LEN_SIZE];
        wire.extend_from_slice(batch);
        self.sealer.seal(&mut wire).unwrap();
        wire
    }

    async fn send(&mut self, contract: &TcpGatewayContract<'_>) {
        let wire = self.seal(contract);
        self.stream.write_all(&wire).await.unwrap();
    }

    /// The next inner frame the server sent, `[u8 TYPE][PAYLOAD]`.
    async fn read_frame(&mut self) -> Vec<u8> {
        while self.received.is_empty() {
            let frames = tokio::time::timeout(
                TIMEOUT,
                session::read_frame_for_tests(&mut self.stream, &mut self.opener),
            )
            .await
            .expect("the server sent nothing");
            self.received.extend(frames);
        }

        self.received.pop_front().unwrap()
    }
}

fn signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

fn endpoint(port: u16) -> Arc<RemoteEndpointOwned> {
    Arc::new(RemoteEndpointOwned::try_parse(format!("127.0.0.1:{port}")).unwrap())
}

/// An upstream which hands every accepted connection to `behaviour`.
async fn start_upstream<F, Fut>(behaviour: F) -> u16
where
    F: Fn(TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(behaviour(stream));
        }
    });

    port
}

/// Echoes until EOF, then reports the close on `closed`.
async fn echo(mut stream: TcpStream, closed: Option<mpsc::UnboundedSender<()>>) {
    let (mut read, mut write) = stream.split();
    let _ = tokio::io::copy(&mut read, &mut write).await;

    if let Some(closed) = closed {
        let _ = closed.send(());
    }
}

async fn send_and_close(mut stream: TcpStream, data: Arc<Vec<u8>>) {
    let _ = stream.write_all(&data).await;
}

/// Starts reading after `delay`, reads until EOF, then sends what it got.
async fn collect(
    mut stream: TcpStream,
    collected: mpsc::UnboundedSender<Vec<u8>>,
    delay: Duration,
) {
    tokio::time::sleep(delay).await;

    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf).await;
    let _ = collected.send(buf);
}

async fn assert_echoes(stream: &mut TcpGatewayProxyForwardStream) {
    let message = b"ping through the gateway";
    stream.write_to_socket(message).await.unwrap();

    let mut received = Vec::new();
    let mut buf = [0u8; 64];
    while received.len() < message.len() {
        let read_size = tokio::time::timeout(TIMEOUT, stream.read_from_socket(&mut buf))
            .await
            .expect("the echo did not come back")
            .expect("the stream is open");
        assert!(read_size > 0, "the stream closed before the echo came back");
        received.extend_from_slice(&buf[..read_size]);
    }

    assert_eq!(received, message);
}

/// Splits a gateway stream the way the byte pumps get it.
fn split(
    stream: TcpGatewayProxyForwardStream,
) -> (TcpGatewayProxyForwardStream, TcpGatewayProxyForwardStream) {
    crate::network_stream::NetworkStream::split(stream)
}

/// A port forward over `stream`: a client socket linked to it by the two byte pumps, which share
/// the connection's pump state - the way a tcp port forward links an accepted connection.
async fn port_forward(
    stream: TcpGatewayProxyForwardStream,
    timeouts: HttpTimeouts,
) -> (TcpStream, [tokio::task::JoinHandle<()>; 2]) {
    let (gateway_read, gateway_write) = split(stream);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (accepted, _) = listener.accept().await.unwrap();
    let (accepted_read, accepted_write) = accepted.into_split();
    let accepted_read = crate::network_stream::MyOwnedReadHalf::from(accepted_read);
    let accepted_write = crate::network_stream::MyOwnedWriteHalf::from(accepted_write);

    let pumps = Arc::new(ConnectionPumps::new(timeouts));

    let client_to_upstream = tokio::spawn(copy_streams(
        accepted_read,
        gateway_write,
        LoopBuffer::new(),
        None,
        None,
        None,
        pumps.clone(),
    ));
    let upstream_to_client = tokio::spawn(copy_streams(
        gateway_read,
        accepted_write,
        LoopBuffer::new(),
        None,
        None,
        None,
        pumps,
    ));

    (client, [client_to_upstream, upstream_to_client])
}

/// How a stream ended for its reader.
#[derive(Debug, PartialEq, Eq)]
enum StreamEnd {
    /// The end of the stream - a FIN.
    End,
    /// An error - a reset.
    Reset,
}

/// Reads `stream` until it ends: what arrived, and how it ended.
async fn read_socket_end(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> (Vec<u8>, StreamEnd) {
    let mut received = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];

    loop {
        match stream.read(&mut buf).await {
            Ok(0) => return (received, StreamEnd::End),
            Ok(read_size) => received.extend_from_slice(&buf[..read_size]),
            Err(_) => return (received, StreamEnd::Reset),
        }
    }
}

/// [`read_socket_end`] for a target which only reads, and so would never learn of a reset which got
/// lost: the OS may drop the reset of a connection closed in the middle of a transfer (macOS does,
/// on loopback, and rate-limits the reset it would answer the next segment with). After a second
/// without data it writes a byte, as a live peer would sooner or later: a connection reset on the
/// other side answers it with a reset. An end of stream still reads as one first.
async fn read_socket_end_probing(stream: &mut TcpStream) -> StreamEnd {
    let mut buf = vec![0u8; 64 * 1024];

    loop {
        match tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buf)).await {
            Ok(Ok(0)) => return StreamEnd::End,
            Ok(Ok(_)) => {}
            Ok(Err(_)) => return StreamEnd::Reset,
            Err(_) => {
                if stream.write_all(b"?").await.is_err() {
                    return StreamEnd::Reset;
                }
            }
        }
    }
}

/// A target which reads its connection until it ends: reports once `expected` bytes arrived, then
/// how the stream ended.
async fn read_until_the_end(
    mut stream: TcpStream,
    expected: usize,
    arrived: mpsc::UnboundedSender<()>,
    ended: mpsc::UnboundedSender<StreamEnd>,
) {
    let mut buf = vec![0u8; 64 * 1024];
    let mut received = 0;

    let end = loop {
        match stream.read(&mut buf).await {
            Ok(0) => break StreamEnd::End,
            Ok(read_size) => {
                if received < expected && received + read_size >= expected {
                    let _ = arrived.send(());
                }
                received += read_size;
            }
            Err(_) => break StreamEnd::Reset,
        }
    };

    let _ = ended.send(end);
}

/// A far side which never takes a byte: every write to it runs into the write timeout.
struct StuckWriter;

#[async_trait::async_trait]
impl NetworkStreamWritePart for StuckWriter {
    async fn shutdown_socket(&mut self) {}

    async fn write_to_socket(&mut self, _buffer: &[u8]) -> Result<(), std::io::Error> {
        std::future::pending().await
    }

    async fn flush_it(&mut self) -> Result<(), crate::network_stream::NetworkError> {
        Ok(())
    }
}

/// A TLS client which closed without a close_notify, as tokio-rustls reports it.
struct TruncatedTlsReader;

#[async_trait::async_trait]
impl NetworkStreamReadPart for TruncatedTlsReader {
    async fn read_from_socket(&mut self, _buf: &mut [u8]) -> Result<usize, std::io::Error> {
        Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "peer closed connection without sending TLS close_notify",
        ))
    }
}

/// A far side which never sends a byte.
struct SilentReader;

#[async_trait::async_trait]
impl NetworkStreamReadPart for SilentReader {
    async fn read_from_socket(&mut self, _buf: &mut [u8]) -> Result<usize, std::io::Error> {
        std::future::pending().await
    }
}

/// Closes `stream` with a reset instead of a FIN.
fn reset_socket(stream: TcpStream) {
    stream.set_zero_linger().unwrap();
    drop(stream);
}

/// A target which sends `data` and resets the connection.
async fn reset_after(mut stream: TcpStream, data: &'static [u8]) {
    stream.write_all(data).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    reset_socket(stream);
}

/// A connection to `port` from the server end of `gateway` or from its client end.
async fn connect_from(
    gateway: &Gateway,
    from_server: bool,
    port: u16,
) -> TcpGatewayProxyForwardStream {
    if from_server {
        gateway.connect_from_server(port).await
    } else {
        gateway.connect_from_client(port).await
    }
}

/// A websocket upstream past its handshake: sends `messages` binary messages of 64 KiB and a Close,
/// closes its write side and reads until the other side closes too.
async fn websocket_burst_then_close(stream: TcpStream, messages: usize) {
    websocket_burst_with_ping_then_close(stream, messages, None).await
}

/// The same, with a Ping after message `ping_after`.
async fn websocket_burst_with_ping_then_close(
    mut stream: TcpStream,
    messages: usize,
    ping_after: Option<usize>,
) {
    const MESSAGE_SIZE: usize = 64 * 1024;

    let mut frames = Vec::with_capacity(messages * (MESSAGE_SIZE + 10) + 16);
    for index in 0..messages {
        frames.extend_from_slice(&[0x82, 127]);
        frames.extend_from_slice(&(MESSAGE_SIZE as u64).to_be_bytes());
        frames.extend(std::iter::repeat_n(index as u8, MESSAGE_SIZE));

        if ping_after == Some(index) {
            frames.extend_from_slice(&[0x89, 0]);
        }
    }
    frames.extend_from_slice(&[0x88, 2]);
    frames.extend_from_slice(&1000u16.to_be_bytes());

    let _ = stream.write_all(&frames).await;
    let _ = stream.shutdown().await;
    discard(stream).await;
}

/// Records the end of the websocket session it is told about.
struct RecordDisconnect(Arc<std::sync::atomic::AtomicBool>);

impl my_http_client::MyHttpClientDisconnect for RecordDisconnect {
    fn disconnect(&self) {}
    fn web_socket_disconnect(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
    fn get_connection_id(&self) -> u64 {
        0
    }
}

struct NoDisconnect;

impl my_http_client::MyHttpClientDisconnect for NoDisconnect {
    fn disconnect(&self) {}
    fn web_socket_disconnect(&self) {}
    fn get_connection_id(&self) -> u64 {
        0
    }
}

fn websocket_pump_context() -> crate::http_proxy_pass::WebSocketPumpContext {
    crate::http_proxy_pass::WebSocketPumpContext {
        log_scope: crate::app::ProxyLogScope::new(Arc::new("ws-test".to_string()), 0, None),
        disconnection: Arc::new(NoDisconnect),
        trace_payload: false,
        domain: None,
        timeouts: HttpTimeouts::default(),
        upstream_abort: None,
    }
}

/// `ctx` for a pump into `upstream`, as HttpProxyPass makes it for a gateway stream: a failed
/// session resets the tunnelled connection.
fn for_gateway_upstream(
    ctx: crate::http_proxy_pass::WebSocketPumpContext,
    upstream: &TcpGatewayProxyForwardStream,
) -> crate::http_proxy_pass::WebSocketPumpContext {
    crate::http_proxy_pass::WebSocketPumpContext {
        upstream_abort: Some(upstream.abort_handle()),
        ..ctx
    }
}

/// A local h2c endpoint which accepts one websocket opened with an extended CONNECT and pumps it
/// into `upstream`, as HttpProxyPass does for an h2 client.
async fn start_h2_websocket_pump(upstream: TcpGatewayProxyForwardStream) -> u16 {
    start_h2_websocket_pump_with(upstream, websocket_pump_context()).await
}

async fn start_h2_websocket_pump_with(
    upstream: TcpGatewayProxyForwardStream,
    ctx: crate::http_proxy_pass::WebSocketPumpContext,
) -> u16 {
    let ctx = Arc::new(parking_lot::Mutex::new(Some(for_gateway_upstream(
        ctx, &upstream,
    ))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let upstream = Arc::new(parking_lot::Mutex::new(Some(upstream)));

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();

        let service = hyper::service::service_fn(
            move |mut request: hyper::Request<hyper::body::Incoming>| {
                let upstream = upstream.lock().take().unwrap();
                let ctx = ctx.lock().take().unwrap();
                let on_upgrade = hyper::upgrade::on(&mut request);

                async move {
                    tokio::spawn(crate::http_proxy_pass::pump_h2_extended_connect(
                        on_upgrade,
                        upstream,
                        Vec::new(),
                        ctx,
                    ));

                    Ok::<_, std::convert::Infallible>(hyper::Response::new(
                        http_body_util::Empty::<bytes::Bytes>::new(),
                    ))
                }
            },
        );

        let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .enable_connect_protocol()
            .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
            .await;
    });

    port
}

/// Opens a tunnel to `port` with an RFC 8441 extended CONNECT over h2c, from a client whose
/// windows are `window` bytes.
async fn connect_h2_tunnel(
    port: u16,
    window: u32,
) -> hyper_util::rt::TokioIo<hyper::upgrade::Upgraded> {
    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (mut sender, connection) =
        hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .initial_stream_window_size(window)
            .initial_connection_window_size(window)
            .handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(connection);

    let mut request = hyper::Request::builder()
        .method(hyper::Method::CONNECT)
        .uri(format!("http://127.0.0.1:{port}/ws"))
        .header("sec-websocket-version", "13")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    request
        .extensions_mut()
        .insert(hyper::ext::Protocol::from_static("websocket"));

    let response = tokio::time::timeout(TIMEOUT, sender.send_request(request))
        .await
        .expect("no answer to the extended CONNECT")
        .unwrap();
    assert_eq!(response.status(), hyper::StatusCode::OK);

    hyper_util::rt::TokioIo::new(hyper::upgrade::on(response).await.unwrap())
}

/// Opens a websocket to `port` with an RFC 8441 extended CONNECT over h2c.
async fn connect_h2_websocket_client(
    port: u16,
) -> hyper_tungstenite::WebSocketStream<hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>> {
    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(stream),
    )
    .await
    .unwrap();
    tokio::spawn(connection);

    let mut request = hyper::Request::builder()
        .method(hyper::Method::CONNECT)
        .uri(format!("http://127.0.0.1:{port}/ws"))
        .header("sec-websocket-version", "13")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    request
        .extensions_mut()
        .insert(hyper::ext::Protocol::from_static("websocket"));

    let response = tokio::time::timeout(TIMEOUT, sender.send_request(request))
        .await
        .expect("no answer to the extended CONNECT")
        .unwrap();
    assert_eq!(response.status(), hyper::StatusCode::OK);

    let upgraded = hyper::upgrade::on(response).await.unwrap();

    hyper_tungstenite::WebSocketStream::from_raw_socket(
        hyper_util::rt::TokioIo::new(upgraded),
        hyper_tungstenite::tungstenite::protocol::Role::Client,
        None,
    )
    .await
}

/// A local http/1.1 endpoint which upgrades one websocket and pumps it into `upstream`, as
/// HttpProxyPass does for a location behind a gateway.
async fn start_websocket_pump(upstream: TcpGatewayProxyForwardStream) -> u16 {
    start_websocket_pump_with(upstream, websocket_pump_context()).await
}

async fn start_websocket_pump_with(
    upstream: TcpGatewayProxyForwardStream,
    ctx: crate::http_proxy_pass::WebSocketPumpContext,
) -> u16 {
    let ctx = Arc::new(parking_lot::Mutex::new(Some(for_gateway_upstream(
        ctx, &upstream,
    ))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let upstream = Arc::new(parking_lot::Mutex::new(Some(upstream)));

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();

        let service = hyper::service::service_fn(
            move |mut request: hyper::Request<hyper::body::Incoming>| {
                let upstream = upstream.lock().take().unwrap();
                let ctx = ctx.lock().take().unwrap();

                async move {
                    let (response, websocket) =
                        hyper_tungstenite::upgrade(&mut request, None).unwrap();

                    tokio::spawn(crate::http_proxy_pass::start_web_socket_loop(
                        websocket,
                        upstream,
                        Vec::new(),
                        ctx,
                    ));

                    Ok::<_, std::convert::Infallible>(response)
                }
            },
        );

        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
            .with_upgrades()
            .await;
    });

    port
}

/// Opens a websocket to `port` with a plain http/1.1 upgrade.
async fn connect_websocket_client(port: u16) -> hyper_tungstenite::WebSocketStream<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let request = format!(
        "GET /ws HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let mut received = Vec::new();
    let mut buf = [0u8; 1024];
    let leftover = loop {
        if let Some(end) = received.windows(4).position(|window| window == b"\r\n\r\n") {
            let leftover = received.split_off(end + 4);
            let head = String::from_utf8_lossy(&received);
            assert!(head.starts_with("HTTP/1.1 101"), "not upgraded: {head}");
            break leftover;
        }

        let read_size = tokio::time::timeout(TIMEOUT, stream.read(&mut buf))
            .await
            .expect("no upgrade response")
            .unwrap();
        assert!(read_size > 0, "closed before the upgrade response");
        received.extend_from_slice(&buf[..read_size]);
    };

    hyper_tungstenite::WebSocketStream::from_partially_read(
        stream,
        leftover,
        hyper_tungstenite::tungstenite::protocol::Role::Client,
        None,
    )
    .await
}

/// Opens connections through the client end of a test gateway, the way HttpOverGatewayConnector
/// opens them through a registered gateway.
struct TestGatewayConnector {
    gateway_connection: Arc<TcpGatewayConnection>,
    remote_endpoint: Arc<RemoteEndpointOwned>,
}

impl TestGatewayConnector {
    fn new(
        gateway_connection: Arc<TcpGatewayConnection>,
        remote_endpoint: Arc<RemoteEndpointOwned>,
    ) -> Self {
        Self {
            gateway_connection,
            remote_endpoint,
        }
    }
}

#[async_trait::async_trait]
impl my_http_client::MyHttpClientConnector<TcpGatewayProxyForwardStream> for TestGatewayConnector {
    async fn connect(
        &self,
    ) -> Result<TcpGatewayProxyForwardStream, my_http_client::MyHttpClientError> {
        // Ids of their own, apart from those the test gateway's client hands out.
        static NEXT_CONNECTION_ID: std::sync::atomic::AtomicU32 =
            std::sync::atomic::AtomicU32::new(0x4000_0000);
        let connection_id = NEXT_CONNECTION_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        self.gateway_connection
            .connect_to_forward_proxy_connection(
                self.remote_endpoint.clone(),
                CONNECT_TIMEOUT,
                connection_id,
            )
            .await
            .map_err(my_http_client::MyHttpClientError::CanNotConnectToRemoteHost)
    }

    fn get_remote_endpoint<'s>(&'s self) -> rust_extensions::remote_endpoint::RemoteEndpoint<'s> {
        self.remote_endpoint.to_ref()
    }

    fn is_debug(&self) -> bool {
        false
    }

    fn reunite(
        read: tokio::io::ReadHalf<TcpGatewayProxyForwardStream>,
        write: tokio::io::WriteHalf<TcpGatewayProxyForwardStream>,
    ) -> TcpGatewayProxyForwardStream {
        read.unsplit(write)
    }
}

/// Reads to the end: `Ok` on EOF, `Err` with what was read before an error.
async fn read_to_end(stream: &mut TcpGatewayProxyForwardStream) -> Result<Vec<u8>, Vec<u8>> {
    let mut result = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];

    loop {
        let read_result = tokio::time::timeout(TIMEOUT, stream.read_from_socket(&mut buf))
            .await
            .expect("the stream neither delivered data nor closed");

        match read_result {
            Ok(0) => return Ok(result),
            Ok(read_size) => result.extend_from_slice(&buf[..read_size]),
            Err(_) => return Err(result),
        }
    }
}

async fn wait_until(mut condition: impl FnMut() -> bool) {
    let started = Instant::now();
    while !condition() {
        assert!(
            started.elapsed() < TIMEOUT,
            "the condition is not met within {TIMEOUT:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The writer of a gateway connection over a socket nobody speaks the protocol on - the peer half
/// is returned to keep the socket open - for what needs a gateway writer and no peer.
async fn lone_gateway_writer() -> (Arc<TcpConnectionInner>, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (accepted, _) = listener.accept().await.unwrap();
    let (_read, write) = accepted.into_split();

    let writer = TcpConnectionInner::new_gateway_peer(
        write.into(),
        session::FrameSealer::for_tests([7u8; 32]),
        CompressionLevel::OFF,
        Default::default(),
    );

    (writer, peer)
}

async fn wait_until_within(limit: Duration, mut condition: impl FnMut() -> bool) {
    let started = Instant::now();
    while !condition() {
        assert!(
            started.elapsed() < limit,
            "the condition is not met within {limit:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Samples `progress` until it stops moving for a second: what is held back stays held back.
/// Returns where it stopped.
async fn wait_for_stall(progress: &AtomicUsize) -> usize {
    let started = Instant::now();
    let mut last = progress.load(Ordering::Relaxed);
    let mut still = 0;

    loop {
        tokio::time::sleep(Duration::from_millis(250)).await;

        let now = progress.load(Ordering::Relaxed);
        if now == last && now > 0 {
            still += 1;
            if still == 4 {
                return now;
            }
        } else {
            still = 0;
            last = now;
        }

        assert!(
            started.elapsed() < Duration::from_secs(60),
            "the transfer never stalled, at {now} bytes"
        );
    }
}

/// Writes `data` in pieces of 64 KiB, counting what the socket took, then closes.
async fn send_counting(mut stream: TcpStream, data: Arc<Vec<u8>>, progress: Arc<AtomicUsize>) {
    for piece in data.chunks(64 * 1024) {
        if stream.write_all(piece).await.is_err() {
            return;
        }
        progress.fetch_add(piece.len(), Ordering::Relaxed);
    }
}

/// Sends `size` bytes through an echoing upstream while reading the echo at the same time.
async fn echo_round_trip(stream: TcpGatewayProxyForwardStream, size: usize) {
    let data = Arc::new(pseudo_random(size));
    let (mut reader, mut writer) = split(stream);

    let writing = {
        let data = data.clone();
        tokio::spawn(async move {
            for piece in data.chunks(64 * 1024) {
                writer.write_to_socket(piece).await.unwrap();
            }
            writer
        })
    };

    let mut received = Vec::with_capacity(size);
    let mut buf = vec![0u8; 64 * 1024];
    while received.len() < size {
        let read_size = reader.read_from_socket(&mut buf).await.unwrap();
        assert!(
            read_size > 0,
            "closed after {} of {size} bytes",
            received.len()
        );
        received.extend_from_slice(&buf[..read_size]);
    }

    let _writer = writing.await.unwrap();
    assert!(received == *data);
}

/// Starts writing to `stream` in pieces and returns once the writer is parked on the window - the
/// writer's task, and a clone of the stream to close it with.
async fn park_a_writer(
    stream: TcpGatewayProxyForwardStream,
) -> (tokio::task::JoinHandle<bool>, TcpGatewayProxyForwardStream) {
    let control = stream.clone();
    let progress = Arc::new(AtomicUsize::new(0));

    let writer = {
        let progress = progress.clone();
        tokio::spawn(async move {
            let mut stream = stream;
            let piece = vec![0u8; 64 * 1024];
            loop {
                if stream.write_to_socket(&piece).await.is_err() {
                    return false;
                }
                progress.fetch_add(piece.len(), Ordering::Relaxed);
            }
        })
    };

    wait_for_stall(&progress).await;
    assert!(!writer.is_finished(), "the writer is not parked");

    (writer, control)
}

async fn assert_ends_with_an_error(writer: tokio::task::JoinHandle<bool>) {
    let succeeded = tokio::time::timeout(TIMEOUT, writer)
        .await
        .expect("a writer parked on the window did not wake")
        .unwrap();
    assert!(!succeeded, "the write succeeded on a closed connection");
}

/// Bytes which do not pack: a batch of them travels as it is.
fn pseudo_random(size: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    (0..size)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

/// [`pseudo_random`], another run of bytes for every `seed`.
fn pseudo_random_seeded(size: usize, seed: u64) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15u64 ^ (seed.wrapping_mul(0xA24B_AED4_963E_E407) | 1);
    (0..size)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

/// Text which packs well - rows of an API answer - and differs for every `seed`.
fn compressible(size: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(size + 128);
    let mut row = 0u64;

    while out.len() < size {
        row += 1;
        out.extend_from_slice(
            format!(
                "{{\"connection\":{seed},\"row\":{row},\"symbol\":\"EURUSD\",\"bid\":1.0{},\"ask\":1.0{}}},\n",
                row % 977,
                row % 983
            )
            .as_bytes(),
        );
    }

    out.truncate(size);
    out
}

/// Sends `data` through an echoing upstream, `piece` bytes a write, while reading the echo at
/// the same time.
async fn echo_round_trip_of(stream: TcpGatewayProxyForwardStream, data: Vec<u8>, piece: usize) {
    let data = Arc::new(data);
    let (mut reader, mut writer) = split(stream);

    let writing = {
        let data = data.clone();
        tokio::spawn(async move {
            for piece in data.chunks(piece) {
                writer.write_to_socket(piece).await.unwrap();
            }
            writer
        })
    };

    let mut received = Vec::with_capacity(data.len());
    let mut buf = vec![0u8; 64 * 1024];
    while received.len() < data.len() {
        let read_size = reader.read_from_socket(&mut buf).await.unwrap();
        assert!(
            read_size > 0,
            "closed after {} of {} bytes",
            received.len(),
            data.len()
        );
        received.extend_from_slice(&buf[..read_size]);
    }

    let _writer = writing.await.unwrap();
    assert!(received == *data, "the echo is not what was sent");
}

/// The link between a gateway client and its server: passes the bytes both ways until it is
/// told to go silent - and then keeps every socket open and passes nothing, the way a route
/// which died does.
struct Link {
    port: u16,
    silent: Arc<std::sync::atomic::AtomicBool>,
    silent_for_good: Arc<std::sync::atomic::AtomicBool>,
}

impl Link {
    async fn start(server_port: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let silent = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let silent_for_good = Arc::new(std::sync::atomic::AtomicBool::new(false));

        {
            let (silent, silent_for_good) = (silent.clone(), silent_for_good.clone());

            tokio::spawn(async move {
                while let Ok((client_side, _)) = listener.accept().await {
                    let passes = {
                        let (silent, silent_for_good) = (silent.clone(), silent_for_good.clone());
                        // A connection accepted after `go_silent` is of a link which works again.
                        let of_the_link_which_is_back = silent.load(Ordering::Relaxed);
                        move || {
                            !silent_for_good.load(Ordering::Relaxed)
                                && (of_the_link_which_is_back || !silent.load(Ordering::Relaxed))
                        }
                    };

                    tokio::spawn(async move {
                        let Ok(server_side) = TcpStream::connect(("127.0.0.1", server_port)).await
                        else {
                            return;
                        };

                        let (client_read, client_write) = client_side.into_split();
                        let (server_read, server_write) = server_side.into_split();

                        let up =
                            tokio::spawn(pass_bytes(client_read, server_write, passes.clone()));
                        let down = tokio::spawn(pass_bytes(server_read, client_write, passes));
                        let _ = up.await;
                        let _ = down.await;
                    });
                }
            });
        }

        Self {
            port,
            silent,
            silent_for_good,
        }
    }

    /// The connections which are there pass nothing from now on; new ones work.
    fn go_silent(&self) {
        self.silent.store(true, Ordering::Relaxed);
    }

    /// Nothing passes from now on, on any connection.
    fn go_silent_for_good(&self) {
        self.silent_for_good.store(true, Ordering::Relaxed);
    }
}

/// Passes bytes one way while `passes` says so, then holds both halves open and passes nothing.
async fn pass_bytes(
    mut read: tokio::net::tcp::OwnedReadHalf,
    mut write: tokio::net::tcp::OwnedWriteHalf,
    passes: impl Fn() -> bool,
) {
    let mut buf = vec![0u8; 64 * 1024];

    loop {
        let read_size = tokio::select! {
            read_size = read.read(&mut buf) => read_size,
            // Looks at `passes` again: a silent socket would not say that the link went silent.
            _ = tokio::time::sleep(Duration::from_millis(20)) => {
                if passes() {
                    continue;
                }
                break;
            }
        };

        if !passes() {
            break;
        }

        match read_size {
            Ok(read_size) if read_size > 0 => {
                if write.write_all(&buf[..read_size]).await.is_err() {
                    return;
                }
            }
            _ => return,
        }
    }

    std::future::pending::<()>().await;
}

/// A hyper upstream: `/upload` answers with the size of the request body, `/download` with
/// [`download_body`].
async fn start_hyper_upstream(http2: bool) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let service = hyper::service::service_fn(
                    |request: hyper::Request<hyper::body::Incoming>| async move {
                        use http_body_util::BodyExt;

                        let path = request.uri().path().to_string();
                        let body = request.into_body().collect().await.unwrap().to_bytes();

                        // An SSE-like stream: one event, then it stays open with nothing more.
                        if path == "/stream" {
                            use futures::StreamExt;

                            let events = futures::stream::once(async {
                                Ok::<_, std::convert::Infallible>(hyper::body::Frame::data(
                                    bytes::Bytes::from_static(b"data: first\n\n"),
                                ))
                            })
                            .chain(futures::stream::pending());

                            return Ok::<_, std::convert::Infallible>(hyper::Response::new(
                                BodyExt::boxed(http_body_util::StreamBody::new(events)),
                            ));
                        }

                        let response = if path == "/download" {
                            download_body()
                        } else if path == "/download-big" {
                            big_download_body()
                        } else {
                            format!("received {} bytes", body.len()).into_bytes()
                        };

                        Ok(hyper::Response::new(
                            http_body_util::Full::new(bytes::Bytes::from(response))
                                .map_err(|never| match never {})
                                .boxed(),
                        ))
                    },
                );

                let io = hyper_util::rt::TokioIo::new(stream);

                if http2 {
                    let _ = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(io, service)
                    .await;
                } else {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await;
                }
            });
        }
    });

    port
}

fn download_body() -> Vec<u8> {
    pseudo_random(3 * 1024 * 1024)
}

/// Twice the flow-control window.
fn big_download_body() -> Vec<u8> {
    pseudo_random(2 * FLOW_CONTROL_WINDOW)
}

async fn send_hyper_request(
    sender: &mut hyper::client::conn::http1::SendRequest<http_body_util::Full<bytes::Bytes>>,
    path: &str,
    body: Vec<u8>,
) -> Vec<u8> {
    use http_body_util::BodyExt;

    let request = hyper::Request::post(path)
        .header("host", "upstream")
        .body(http_body_util::Full::new(bytes::Bytes::from(body)))
        .unwrap();

    // The head of an /upload answer comes only once the whole body is up.
    let response = tokio::time::timeout(Duration::from_secs(60), sender.send_request(request))
        .await
        .expect("the response head did not come")
        .unwrap();

    tokio::time::timeout(Duration::from_secs(60), response.into_body().collect())
        .await
        .expect("the response body did not come")
        .unwrap()
        .to_bytes()
        .to_vec()
}

async fn send_h2_request(
    sender: &mut hyper::client::conn::http2::SendRequest<http_body_util::Full<bytes::Bytes>>,
    path: &str,
    body: Vec<u8>,
) -> Vec<u8> {
    use http_body_util::BodyExt;

    let request = hyper::Request::post(format!("http://upstream{path}"))
        .body(http_body_util::Full::new(bytes::Bytes::from(body)))
        .unwrap();

    // The head of an /upload answer comes only once the whole body is up.
    let response = tokio::time::timeout(Duration::from_secs(60), sender.send_request(request))
        .await
        .expect("the response head did not come")
        .unwrap();

    tokio::time::timeout(Duration::from_secs(60), response.into_body().collect())
        .await
        .expect("the response body did not come")
        .unwrap()
        .to_bytes()
        .to_vec()
}

/// Reads and drops everything until EOF.
async fn discard(mut stream: TcpStream) {
    let mut buf = vec![0u8; 64 * 1024];
    while let Ok(read_size) = stream.read(&mut buf).await {
        if read_size == 0 {
            break;
        }
    }
}

/// Sends `answer` and closes its write side, reading and dropping the client's input all along.
async fn answer_then_close(stream: TcpStream, answer: Arc<Vec<u8>>) {
    let (mut read, mut write) = stream.into_split();

    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        while let Ok(read_size) = read.read(&mut buf).await {
            if read_size == 0 {
                break;
            }
        }
    });

    let _ = write.write_all(&answer).await;
    let _ = write.shutdown().await;
    let _ = reader.await;
}

/// Keeps writing, and starts reading - slowly - only after 1.5 s; sends what it read once the
/// connection is closed.
async fn chatter_then_collect(stream: TcpStream, collected: mpsc::UnboundedSender<Vec<u8>>) {
    let (mut read, mut write) = stream.into_split();

    let chatter = tokio::spawn(async move {
        while write.write_all(&[9u8; 1024]).await.is_ok() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    });

    tokio::time::sleep(Duration::from_millis(1500)).await;

    // A slow reader: when the acceptor closes its side, much of the upload is still unread here.
    let mut received = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    while let Ok(read_size) = read.read(&mut buf).await {
        if read_size == 0 {
            break;
        }
        received.extend_from_slice(&buf[..read_size]);
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    chatter.abort();
    let _ = collected.send(received);
}

/// One `poll_write`, the way an executor polls it - the waker is not needed, the test polls again
/// itself.
fn poll_write_once(
    stream: &mut TcpGatewayProxyForwardStream,
    buf: &[u8],
) -> Poll<std::io::Result<usize>> {
    use tokio::io::AsyncWrite;

    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    std::pin::Pin::new(stream).poll_write(&mut cx, buf)
}

/// A files location whose folder is behind the gateway: the requesting end puts the folder and
/// the checked request path together, and either end serves the file.
#[tokio::test]
async fn a_file_of_a_folder_behind_the_gateway_is_served_by_either_end() {
    use crate::http_content_source::FileRequestPath;
    use crate::http_proxy_pass::{executors::get_file_from_gateway_connection, ProxyPassError};

    let gateway = Gateway::start("files-location", false).await;

    let dir = std::env::temp_dir().join(format!("gateway-files-location-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("css")).unwrap();
    std::fs::write(dir.join("index.html"), b"<h1>index</h1>").unwrap();
    std::fs::write(dir.join("css").join("site.css"), b"body {}").unwrap();
    let folder = dir.to_str().unwrap();

    let root = FileRequestPath::parse("/").unwrap();
    let css = FileRequestPath::parse("/css/site.css").unwrap();
    let missing = FileRequestPath::parse("/missing.html").unwrap();

    for side in [gateway.client_side(), gateway.server_side()] {
        let file = get_file_from_gateway_connection(&side, folder, Some("index.html"), &css)
            .await
            .unwrap();
        assert_eq!(file.status_code, 200);
        assert_eq!(file.content_type.unwrap().as_str(), "text/css");
        assert_eq!(file.body, b"body {}");

        // The default file is the answer to the root.
        let file = get_file_from_gateway_connection(&side, folder, Some("index.html"), &root)
            .await
            .unwrap();
        assert_eq!(file.status_code, 200);
        assert_eq!(file.content_type.unwrap().as_str(), "text/html");
        assert_eq!(file.body, b"<h1>index</h1>");

        // Without one the root is no file: it is not asked for.
        let file = get_file_from_gateway_connection(&side, folder, None, &root)
            .await
            .unwrap();
        assert_eq!(file.status_code, 404);

        let result =
            get_file_from_gateway_connection(&side, folder, Some("index.html"), &missing).await;
        assert!(matches!(result, Err(ProxyPassError::NoLocationFound)));
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// The serving end reads the path it is sent as it is, `..` included: it does not know the
/// folder. So the path is checked on the requesting end, where a path which leaves the folder
/// never gets to be a request.
#[tokio::test]
async fn the_serving_end_reads_the_path_it_is_sent_as_it_is() {
    use crate::http_content_source::FileRequestPath;

    let gateway = Gateway::start("files-parent-segment", false).await;

    let dir = std::env::temp_dir().join(format!("gateway-parent-segment-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("root")).unwrap();
    std::fs::write(dir.join("secret.txt"), b"secret").unwrap();
    let folder = dir.join("root");
    let folder = folder.to_str().unwrap();

    let out_of_the_folder = format!("{folder}/../secret.txt");
    assert_eq!(
        gateway
            .client_side()
            .request_file(&out_of_the_folder)
            .await
            .ok(),
        Some(b"secret".to_vec())
    );

    for path in ["/../secret.txt", "/%2e%2e/secret.txt", "/..%2fsecret.txt"] {
        assert!(FileRequestPath::parse(path).is_err(), "{path}");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

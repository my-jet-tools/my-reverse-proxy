//! `http` and `http2` endpoints: plain HTTP - a tcp port or a unix socket with no TLS, so no
//! ALPN to agree on a protocol in. A connection says which one it speaks by its first bytes: an
//! h2 client by prior knowledge sends the connection preface before anything else (RFC 9113
//! §3.4), an http/1.1 client its request line. So either type serves both, and the two names are
//! of one thing: an h2 client is served by hyper ([`super::http2::serve_connection`]), an
//! http/1.1 one by the proxy's own pipeline ([`crate::h1_proxy_server`]).

use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use crate::{
    configurations::HttpListenPortConfiguration,
    h1_proxy_server::ReadAhead,
    network_stream::NetworkStream,
    tcp_utils::LoopBuffer,
    types::{ConnectionIp, ListenHost},
};

/// What an h2 client sends before anything else.
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlainHttpProtocol {
    Http1,
    Http2,
}

/// Serves a connection of an `http` / `http2` endpoint on a task of its own, in the protocol its
/// first bytes are of. `slot`: the connection's place among the ones held (`max_connections`),
/// given back with it.
pub fn kick_connection<TStream>(
    stream: TStream,
    connection_ip: ConnectionIp,
    listen_host: ListenHost,
    configuration: Arc<HttpListenPortConfiguration>,
    slot: crate::app::ConnectionSlot,
) where
    TStream: NetworkStream + AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    crate::app::spawn_named("plain_http_connection", async move {
        let _slot = slot;
        serve_connection(stream, connection_ip, listen_host, configuration).await;
    });
}

async fn serve_connection<TStream>(
    mut stream: TStream,
    connection_ip: ConnectionIp,
    listen_host: ListenHost,
    configuration: Arc<HttpListenPortConfiguration>,
) where
    TStream: NetworkStream + AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    // Which endpoint of the port the connection is for is known only from its first request:
    // until then the port's `header_read_timeout` applies (the longest of its endpoints'). The
    // first request is due by it whatever the protocol - the wait for the opening bytes counts.
    let deadline =
        tokio::time::Instant::now() + configuration.client_timeouts().header_read_timeout;

    let mut received = LoopBuffer::new();

    // Nothing to tell the protocol by - the connection closed, failed, or sent too little in
    // time: it is closed without a word, as a request head which did not come in time is.
    let Some(protocol) = read_protocol(&mut stream, &mut received, deadline).await else {
        return;
    };

    match protocol {
        PlainHttpProtocol::Http1 => {
            crate::h1_proxy_server::serve_h1_plain_connection(
                stream,
                connection_ip,
                configuration,
                ReadAhead {
                    received,
                    head_deadline: deadline,
                },
            )
            .await;
        }
        PlainHttpProtocol::Http2 => {
            let stream = ReplayedStream::new(Bytes::copy_from_slice(received.get_data()), stream);
            drop(received);

            super::http2::serve_connection(
                stream,
                connection_ip,
                listen_host,
                configuration,
                deadline,
            )
            .await;
        }
    }
}

/// Reads the opening bytes of a connection into `received` until they tell its protocol: the h2
/// preface whole, or a byte which is not the one of the preface. A read takes all there is, up
/// to the room the buffer gives a first read - for http/1.1 that is the head, mostly whole, read
/// once into the buffer the pipeline parses it from.
///
/// `None`: the connection closed or failed first, or did not tell by `deadline`.
async fn read_protocol<TStream: AsyncRead + Unpin>(
    stream: &mut TStream,
    received: &mut LoopBuffer,
    deadline: tokio::time::Instant,
) -> Option<PlainHttpProtocol> {
    loop {
        if let Some(protocol) = protocol_of(received.get_data()) {
            return Some(protocol);
        }

        // There is room: the buffer holds less than the preface.
        let room = received.get_mut()?;

        match tokio::time::timeout_at(deadline, stream.read(room)).await {
            Ok(Ok(read)) if read > 0 => received.advance(read),
            _ => return None,
        }
    }
}

/// The protocol of a connection whose opening bytes are `received`, if they tell it yet.
fn protocol_of(received: &[u8]) -> Option<PlainHttpProtocol> {
    let compared = received.len().min(H2_PREFACE.len());

    if received[..compared] != H2_PREFACE[..compared] {
        return Some(PlainHttpProtocol::Http1);
    }

    if compared == H2_PREFACE.len() {
        return Some(PlainHttpProtocol::Http2);
    }

    None
}

/// A stream which gives `received` - what was read of it already - before what it reads on.
/// Writes go to it as they are.
struct ReplayedStream<TStream> {
    received: Bytes,
    stream: TStream,
}

impl<TStream> ReplayedStream<TStream> {
    fn new(received: Bytes, stream: TStream) -> Self {
        Self { received, stream }
    }
}

impl<TStream: AsyncRead + Unpin> AsyncRead for ReplayedStream<TStream> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if this.received.has_remaining() {
            let size = this.received.len().min(buf.remaining());
            buf.put_slice(&this.received[..size]);
            this.received.advance(size);
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut this.stream).poll_read(cx, buf)
    }
}

impl<TStream: AsyncWrite + Unpin> AsyncWrite for ReplayedStream<TStream> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    const DEADLINE: Duration = Duration::from_secs(5);

    /// What `read_protocol` tells of a connection which sends `pieces`, one write after another,
    /// and then nothing - and what it read.
    async fn protocol_of_pieces(
        pieces: &[&[u8]],
        close_after: bool,
    ) -> (Option<PlainHttpProtocol>, Vec<u8>) {
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);

        let pieces: Vec<Vec<u8>> = pieces.iter().map(|piece| piece.to_vec()).collect();
        let writer = tokio::spawn(async move {
            for piece in pieces {
                client.write_all(&piece).await.unwrap();
                client.flush().await.unwrap();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }

            if !close_after {
                // Kept open, silent: the reader has to give up by its deadline.
                tokio::time::sleep(DEADLINE * 2).await;
            }
        });

        let mut received = LoopBuffer::new();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
        let protocol = read_protocol(&mut server, &mut received, deadline).await;
        writer.abort();

        (protocol, received.get_data().to_vec())
    }

    #[tokio::test]
    async fn an_http1_request_is_told_by_its_first_byte_and_read_whole() {
        let request: &[u8] = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let (protocol, received) = protocol_of_pieces(&[request], false).await;

        assert_eq!(protocol, Some(PlainHttpProtocol::Http1));
        assert_eq!(received, request, "what one read gave is kept whole");
    }

    /// The methods which start as the preface does are http/1.1 all the same - told at the first
    /// byte which differs, however few came at a time.
    #[tokio::test]
    async fn a_request_which_starts_as_the_preface_does_is_http1() {
        for request in [
            &b"POST / HTTP/1.1\r\n\r\n"[..],
            b"PUT / HTTP/1.1\r\n\r\n",
            b"PATCH / HTTP/1.1\r\n\r\n",
            b"PROPFIND / HTTP/1.1\r\n\r\n",
            // An http/1.1 request line of the preface's method.
            b"PRI * HTTP/1.1\r\n\r\n",
        ] {
            let pieces: Vec<&[u8]> = request.chunks(1).collect();
            let (protocol, received) = protocol_of_pieces(&pieces, false).await;

            let text = String::from_utf8_lossy(request);
            assert_eq!(protocol, Some(PlainHttpProtocol::Http1), "{text}");
            assert!(request.starts_with(&received), "{text}");
        }
    }

    #[tokio::test]
    async fn the_preface_is_h2_and_what_came_with_it_is_kept() {
        // The preface, and the SETTINGS frame a client sends right after it.
        let mut sent = H2_PREFACE.to_vec();
        sent.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);

        let (protocol, received) = protocol_of_pieces(&[sent.as_slice()], false).await;
        assert_eq!(protocol, Some(PlainHttpProtocol::Http2));
        assert_eq!(received, sent);

        // In pieces: told once the last byte of the preface came, not before.
        let (protocol, received) =
            protocol_of_pieces(&[&H2_PREFACE[..3], &H2_PREFACE[3..17], &H2_PREFACE[17..]], false)
                .await;
        assert_eq!(protocol, Some(PlainHttpProtocol::Http2));
        assert_eq!(received, H2_PREFACE);
    }

    #[tokio::test]
    async fn a_connection_which_does_not_tell_is_given_up() {
        // Closed with nothing sent, or with a part of the preface.
        assert_eq!(protocol_of_pieces(&[], true).await.0, None);
        assert_eq!(protocol_of_pieces(&[&b"PRI * HT"[..]], true).await.0, None);

        // Silent, or silent after a part of the preface: given up at the deadline.
        let started = tokio::time::Instant::now();
        assert_eq!(protocol_of_pieces(&[], false).await.0, None);
        assert_eq!(
            protocol_of_pieces(&[&b"PRI * HTTP/2.0\r\n"[..]], false).await.0,
            None
        );
        assert!(started.elapsed() < DEADLINE, "the deadline was not kept");
    }

    #[tokio::test]
    async fn a_replayed_stream_gives_what_was_read_then_the_rest_and_writes_through() {
        let (mut client, server) = tokio::io::duplex(1024);
        let mut stream = ReplayedStream::new(Bytes::from_static(b"first "), server);

        client.write_all(b"second").await.unwrap();

        // A small buffer: what was read is given in as many reads as it takes.
        let mut received = Vec::new();
        let mut buffer = [0u8; 4];
        while received.len() < b"first second".len() {
            let read = stream.read(&mut buffer).await.unwrap();
            assert!(read > 0);
            received.extend_from_slice(&buffer[..read]);
        }
        assert_eq!(received, b"first second");

        stream.write_all(b"answer").await.unwrap();
        let mut answer = [0u8; 6];
        client.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"answer");
    }
}

use tokio::net::{TcpStream, ToSocketAddrs};

/// A tcp connection to an upstream or a remote, with TCP_NODELAY on.
///
/// Whatever the proxy relays it writes as it comes - a request body piece by piece as the
/// client sends it, a tunnel's bytes as they arrive. With Nagle's algorithm on, a small piece
/// which follows another waits for the peer to acknowledge the first, and a peer which delays
/// its ACKs makes that tens to hundreds of milliseconds. For a TLS upstream this is set before
/// the handshake, so its flights are not held back either.
///
/// A failed `set_nodelay` is not an error: the connection works, only slower.
pub async fn connect_tcp(addr: impl ToSocketAddrs) -> std::io::Result<TcpStream> {
    let tcp_stream = TcpStream::connect(addr).await?;
    let _ = tcp_stream.set_nodelay(true);
    Ok(tcp_stream)
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn the_connection_sends_without_delay() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();

        let stream = super::connect_tcp(listener.local_addr().unwrap())
            .await
            .unwrap();

        assert!(stream.nodelay().unwrap());
    }
}

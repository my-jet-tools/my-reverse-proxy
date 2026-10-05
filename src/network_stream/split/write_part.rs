use std::time::Duration;

use my_ssh::SshAsyncChannel;
use tokio_util::sync::CancellationToken;

use crate::network_stream::*;

#[async_trait::async_trait]
pub trait NetworkStreamWritePart {
    async fn shutdown_socket(&mut self);

    async fn write_to_socket(&mut self, buffer: &[u8]) -> Result<(), std::io::Error>;

    async fn flush_it(&mut self) -> Result<(), NetworkError>;

    /// Ends the connection as broken: its other end gets an error - a TCP reset, an `RST` through
    /// a gateway tunnel - instead of the end of the stream, which would pass a stream cut short
    /// for a whole one. A stream which can not tell the two apart is shut down.
    async fn abort_socket(&mut self) {
        self.shutdown_socket().await
    }

    /// Cancelled once the connection behind this half is gone, for a stream which learns that
    /// without a read or a write of its own - a gateway tunnel connection. `None` for sockets.
    fn connection_closed(&self) -> Option<CancellationToken> {
        None
    }

    async fn write_all_with_timeout(
        &mut self,
        buffer: &[u8],
        timeout: Duration,
    ) -> Result<(), NetworkError> {
        let future = self.write_to_socket(buffer);

        let result = tokio::time::timeout(timeout, future).await;

        let Ok(result) = result else {
            // The socket is deliberately not shut down here: a peer which stopped reading
            // would stall the shutdown as well. The caller tears the connection down.
            return Err(NetworkError::Timeout(timeout));
        };

        if let Err(err) = result {
            let _ = self.shutdown_socket().await;
            return Err(NetworkError::IoError(err));
        }

        self.flush_it().await?;

        Ok(())
    }
}

pub enum MyOwnedWriteHalf {
    Tcp(tokio::net::tcp::OwnedWriteHalf),
    Unix(tokio::net::unix::OwnedWriteHalf),
    Ssh(tokio::io::WriteHalf<SshAsyncChannel>),
    /// Given up by [`MyOwnedWriteHalf::reset`]: writes fail, a shutdown does nothing.
    Reset,
}

impl MyOwnedWriteHalf {
    /// Gives the write half up without shutting the write side down, and has the connection
    /// closed with a reset once the read half is dropped too: the other end gets an error, not
    /// the end of a stream cut short. A unix socket or an ssh channel can not be reset - its write
    /// side is shut down, and its other end sees the end of the stream.
    pub fn reset(&mut self) {
        match std::mem::replace(self, MyOwnedWriteHalf::Reset) {
            MyOwnedWriteHalf::Tcp(write_half) => {
                let _ = write_half.as_ref().set_zero_linger();
                write_half.forget();
            }
            // Dropped: an owned unix write half shuts its side down on drop.
            other => drop(other),
        }
    }
}

impl From<tokio::net::tcp::OwnedWriteHalf> for MyOwnedWriteHalf {
    fn from(val: tokio::net::tcp::OwnedWriteHalf) -> Self {
        MyOwnedWriteHalf::Tcp(val)
    }
}

impl From<tokio::net::unix::OwnedWriteHalf> for MyOwnedWriteHalf {
    fn from(val: tokio::net::unix::OwnedWriteHalf) -> Self {
        MyOwnedWriteHalf::Unix(val)
    }
}

impl From<tokio::io::WriteHalf<SshAsyncChannel>> for MyOwnedWriteHalf {
    fn from(val: tokio::io::WriteHalf<SshAsyncChannel>) -> Self {
        MyOwnedWriteHalf::Ssh(val)
    }
}

#[async_trait::async_trait]
impl NetworkStreamWritePart for MyOwnedWriteHalf {
    async fn shutdown_socket(&mut self) {
        match self {
            MyOwnedWriteHalf::Tcp(owned_write_half) => {
                use tokio::io::AsyncWriteExt;
                let _ = owned_write_half.shutdown().await;
            }
            MyOwnedWriteHalf::Unix(owned_write_half) => {
                use tokio::io::AsyncWriteExt;
                let _ = owned_write_half.shutdown().await;
            }
            MyOwnedWriteHalf::Ssh(ssh) => {
                use tokio::io::AsyncWriteExt;
                let _ = ssh.shutdown().await;
            }
            MyOwnedWriteHalf::Reset => {}
        }
    }

    async fn abort_socket(&mut self) {
        self.reset();
    }

    async fn write_to_socket(&mut self, buffer: &[u8]) -> Result<(), std::io::Error> {
        match self {
            MyOwnedWriteHalf::Tcp(owned_write_half) => {
                use tokio::io::AsyncWriteExt;
                owned_write_half.write_all(buffer).await
            }
            MyOwnedWriteHalf::Unix(owned_write_half) => {
                use tokio::io::AsyncWriteExt;
                owned_write_half.write_all(buffer).await
            }
            MyOwnedWriteHalf::Ssh(owned_write_half) => {
                use tokio::io::AsyncWriteExt;
                owned_write_half.write_all(buffer).await
            }
            MyOwnedWriteHalf::Reset => Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "The connection is reset",
            )),
        }
    }

    async fn flush_it(&mut self) -> Result<(), NetworkError> {
        match self {
            MyOwnedWriteHalf::Tcp(owned_write_half) => {
                use tokio::io::AsyncWriteExt;
                owned_write_half.flush().await?;
            }
            MyOwnedWriteHalf::Unix(owned_write_half) => {
                use tokio::io::AsyncWriteExt;
                owned_write_half.flush().await?;
            }
            MyOwnedWriteHalf::Ssh(write_half) => {
                use tokio::io::AsyncWriteExt;
                write_half.flush().await?;
            }
            MyOwnedWriteHalf::Reset => {}
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl NetworkStreamWritePart
    for tokio::io::WriteHalf<my_tls::tokio_rustls::client::TlsStream<tokio::net::TcpStream>>
{
    async fn shutdown_socket(&mut self) {
        use tokio::io::AsyncWriteExt;
        let _ = self.shutdown().await;
    }

    async fn write_to_socket(&mut self, buffer: &[u8]) -> Result<(), std::io::Error> {
        use tokio::io::AsyncWriteExt;

        self.write_all(buffer).await
    }

    async fn flush_it(&mut self) -> Result<(), NetworkError> {
        use tokio::io::AsyncWriteExt;
        self.flush().await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl NetworkStreamWritePart
    for tokio::io::WriteHalf<my_tls::tokio_rustls::server::TlsStream<tokio::net::TcpStream>>
{
    async fn shutdown_socket(&mut self) {
        use tokio::io::AsyncWriteExt;
        let _ = self.shutdown().await;
    }

    async fn write_to_socket(&mut self, buffer: &[u8]) -> Result<(), std::io::Error> {
        use tokio::io::AsyncWriteExt;
        let result = self.write_all(buffer).await;
        result
    }

    async fn flush_it(&mut self) -> Result<(), NetworkError> {
        use tokio::io::AsyncWriteExt;
        self.flush().await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl NetworkStreamWritePart for tokio::io::WriteHalf<tokio::net::TcpStream> {
    async fn shutdown_socket(&mut self) {
        use tokio::io::AsyncWriteExt;
        let _ = self.shutdown().await;
    }

    async fn write_to_socket(&mut self, buffer: &[u8]) -> Result<(), std::io::Error> {
        use tokio::io::AsyncWriteExt;
        self.write_all(buffer).await
    }

    async fn flush_it(&mut self) -> Result<(), NetworkError> {
        use tokio::io::AsyncWriteExt;
        self.flush().await?;
        Ok(())
    }
}

#[cfg(unix)]
#[async_trait::async_trait]
impl NetworkStreamWritePart for tokio::io::WriteHalf<tokio::net::UnixStream> {
    async fn shutdown_socket(&mut self) {
        use tokio::io::AsyncWriteExt;
        let _ = self.shutdown().await;
    }

    async fn write_to_socket(&mut self, buffer: &[u8]) -> Result<(), std::io::Error> {
        use tokio::io::AsyncWriteExt;
        self.write_all(buffer).await
    }

    async fn flush_it(&mut self) -> Result<(), NetworkError> {
        use tokio::io::AsyncWriteExt;
        self.flush().await?;
        Ok(())
    }
}

#[cfg(unix)]
#[async_trait::async_trait]
impl NetworkStreamWritePart for tokio::io::WriteHalf<my_ssh::SshAsyncChannel> {
    async fn shutdown_socket(&mut self) {
        use tokio::io::AsyncWriteExt;
        let _ = self.shutdown().await;
    }

    async fn write_to_socket(&mut self, buffer: &[u8]) -> Result<(), std::io::Error> {
        use tokio::io::AsyncWriteExt;
        self.write_all(buffer).await
    }

    async fn flush_it(&mut self) -> Result<(), NetworkError> {
        use tokio::io::AsyncWriteExt;
        self.flush().await?;
        Ok(())
    }
}

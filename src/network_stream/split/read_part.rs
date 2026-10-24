use std::time::Duration;

use my_ssh::SshAsyncChannel;
use tokio::io::AsyncReadExt;

use crate::network_stream::NetworkError;
#[async_trait::async_trait]
pub trait NetworkStreamReadPart {
    async fn read_from_socket(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error>;

    /// Has the connection end as broken however it is closed - see
    /// [`super::NetworkStreamWritePart::abort_socket`]: a byte pump which failed resets the
    /// connections of both its halves. A gateway tunnel connection is reset at once, a socket
    /// closes with a reset once both its halves are gone. Nothing for a stream which can not tell
    /// the two apart.
    fn abort_connection(&mut self) {}

    async fn read_with_timeout(
        &mut self,
        buf: &mut [u8],
        timeout: Duration,
    ) -> Result<usize, NetworkError> {
        let future = self.read_from_socket(buf);

        let result = tokio::time::timeout(timeout, future).await;

        let Ok(result) = result else {
            return Err(NetworkError::Timeout(timeout));
        };

        match result {
            Ok(result) => {
                if result == 0 {
                    return Err(NetworkError::Disconnected);
                }

                return Ok(result);
            }
            Err(err) => Err(NetworkError::IoError(err)),
        }
    }
}

/// Lets a boxed read half (the type-erased upstream read half handed out by
/// `Upstream::connect_owned`, where the 5 transports have 5 concrete read-half
/// types) be driven through the same `NetworkStreamReadPart` API — e.g. wrapped
/// in `H1Reader<Box<dyn NetworkStreamReadPart + Send + Sync>>` so a worker can
/// read the upstream response uniformly.
#[async_trait::async_trait]
impl NetworkStreamReadPart for Box<dyn NetworkStreamReadPart + Send + Sync> {
    async fn read_from_socket(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        (**self).read_from_socket(buf).await
    }

    fn abort_connection(&mut self) {
        (**self).abort_connection()
    }
}

pub enum MyOwnedReadHalf {
    Tcp(tokio::net::tcp::OwnedReadHalf),
    #[cfg(unix)]
    Unix(tokio::net::unix::OwnedReadHalf),
    Ssh(tokio::io::ReadHalf<SshAsyncChannel>),
}

impl MyOwnedReadHalf {
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        match self {
            MyOwnedReadHalf::Tcp(owned_read_half) => {
                use tokio::io::AsyncReadExt;
                owned_read_half.read(buf).await
            }
            #[cfg(unix)]
            MyOwnedReadHalf::Unix(owned_read_half) => {
                use tokio::io::AsyncReadExt;
                owned_read_half.read(buf).await
            }
            MyOwnedReadHalf::Ssh(owned_read_half) => {
                use tokio::io::AsyncReadExt;
                owned_read_half.read(buf).await
            }
        }
    }

    /// Has the connection closed with a reset once both halves are gone - its other end gets an
    /// error, not the end of the stream - however the write half is given up. A unix socket or
    /// an ssh channel can not be reset.
    pub fn reset_on_close(&self) {
        if let MyOwnedReadHalf::Tcp(read_half) = self {
            let _ = read_half.as_ref().set_zero_linger();
        }
    }

    /// Reads into the spare capacity of `buf` and appends what was read - the buffer
    /// does not have to be initialized up front.
    pub async fn read_buf(&mut self, buf: &mut Vec<u8>) -> Result<usize, std::io::Error> {
        use tokio::io::AsyncReadExt;

        match self {
            MyOwnedReadHalf::Tcp(owned_read_half) => owned_read_half.read_buf(buf).await,
            #[cfg(unix)]
            MyOwnedReadHalf::Unix(owned_read_half) => owned_read_half.read_buf(buf).await,
            MyOwnedReadHalf::Ssh(owned_read_half) => owned_read_half.read_buf(buf).await,
        }
    }
}

impl From<tokio::net::tcp::OwnedReadHalf> for MyOwnedReadHalf {
    fn from(val: tokio::net::tcp::OwnedReadHalf) -> Self {
        MyOwnedReadHalf::Tcp(val)
    }
}

#[cfg(unix)]
impl From<tokio::net::unix::OwnedReadHalf> for MyOwnedReadHalf {
    fn from(val: tokio::net::unix::OwnedReadHalf) -> Self {
        MyOwnedReadHalf::Unix(val)
    }
}

impl From<tokio::io::ReadHalf<SshAsyncChannel>> for MyOwnedReadHalf {
    fn from(val: tokio::io::ReadHalf<SshAsyncChannel>) -> Self {
        MyOwnedReadHalf::Ssh(val)
    }
}

#[async_trait::async_trait]
impl NetworkStreamReadPart for MyOwnedReadHalf {
    async fn read_from_socket(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        self.read(buf).await
    }

    fn abort_connection(&mut self) {
        self.reset_on_close();
    }
}

#[async_trait::async_trait]
impl NetworkStreamReadPart
    for tokio::io::ReadHalf<my_tls::tokio_rustls::client::TlsStream<tokio::net::TcpStream>>
{
    async fn read_from_socket(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        self.read(buf).await
    }
}

#[async_trait::async_trait]
impl NetworkStreamReadPart
    for tokio::io::ReadHalf<my_tls::tokio_rustls::server::TlsStream<tokio::net::TcpStream>>
{
    async fn read_from_socket(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        self.read(buf).await
    }
}

#[async_trait::async_trait]
impl NetworkStreamReadPart for tokio::io::ReadHalf<tokio::net::TcpStream> {
    async fn read_from_socket(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        self.read(buf).await
    }
}

#[cfg(unix)]
#[async_trait::async_trait]
impl NetworkStreamReadPart for tokio::io::ReadHalf<tokio::net::UnixStream> {
    async fn read_from_socket(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        self.read(buf).await
    }
}

#[async_trait::async_trait]
impl NetworkStreamReadPart for tokio::io::ReadHalf<my_ssh::SshAsyncChannel> {
    async fn read_from_socket(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        self.read(buf).await
    }
}

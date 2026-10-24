use std::net::SocketAddr;

use tokio::io::AsyncWriteExt;

use crate::types::ConnectionIp;

pub enum AcceptedServerConnection {
    Tcp {
        network_stream: tokio::net::TcpStream,
        addr: SocketAddr,
    },

    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
}

impl From<(tokio::net::TcpStream, SocketAddr)> for AcceptedServerConnection {
    fn from(val: (tokio::net::TcpStream, SocketAddr)) -> Self {
        AcceptedServerConnection::Tcp {
            network_stream: val.0,
            addr: val.1,
        }
    }
}

#[cfg(unix)]
impl From<tokio::net::UnixStream> for AcceptedServerConnection {
    fn from(val: tokio::net::UnixStream) -> Self {
        AcceptedServerConnection::Unix(val)
    }
}

impl AcceptedServerConnection {
    pub async fn shutdown(&mut self) {
        match self {
            AcceptedServerConnection::Tcp {
                network_stream,
                addr: _,
            } => {
                let _ = network_stream.shutdown().await;
            }
            #[cfg(unix)]
            AcceptedServerConnection::Unix(network_stream) => {
                let _ = network_stream.shutdown().await;
            }
        }
    }

    pub fn get_addr(&self) -> ConnectionIp {
        match self {
            AcceptedServerConnection::Tcp { addr, .. } => ConnectionIp::Tcp(*addr),
            #[cfg(unix)]
            AcceptedServerConnection::Unix(_) => ConnectionIp::UnixSocket,
        }
    }
}

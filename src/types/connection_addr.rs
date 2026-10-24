use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Copy)]
pub enum ConnectionIp {
    Tcp(SocketAddr),
    #[cfg(unix)]
    UnixSocket,
}

impl ConnectionIp {
    pub fn get_ip_addr(&self) -> Option<IpAddr> {
        match self {
            ConnectionIp::Tcp(addr) => Some(addr.ip()),
            #[cfg(unix)]
            ConnectionIp::UnixSocket => None,
        }
    }

    /// Source IP as a string for the in-memory logs IP field; `None` for unix
    /// sockets (no IP to resolve).
    pub fn get_ip_log(&self) -> Option<String> {
        self.get_ip_addr().map(|ip| ip.to_string())
    }
}

impl From<SocketAddr> for ConnectionIp {
    fn from(val: SocketAddr) -> Self {
        ConnectionIp::Tcp(val)
    }
}

impl std::fmt::Debug for ConnectionIp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(ip) => f.debug_tuple("Tcp:").field(ip).finish(),
            #[cfg(unix)]
            Self::UnixSocket => write!(f, "UnixSocket"),
        }
    }
}

use std::{net::SocketAddr, sync::Arc};

#[derive(Clone)]
pub enum ListenHost {
    Tcp(SocketAddr),
    Unix(Arc<String>),
}

impl Into<ListenHost> for Arc<String> {
    fn into(self) -> ListenHost {
        ListenHost::Unix(self)
    }
}

impl ListenHost {
    pub fn to_pretty_string(&self, is_https: bool) -> String {
        match self {
            ListenHost::Tcp(socket_addr) => {
                if is_https {
                    format!("https://{}", socket_addr)
                } else {
                    format!("http://{}", socket_addr)
                }
            }
            ListenHost::Unix(socket) => socket.to_string(),
        }
    }

    /// Key used to group in-memory port-level logs: the TCP port number for
    /// TCP listeners, the socket path for unix listeners. Matches the key the
    /// TCP/unix accept loops use when writing port-level rejections.
    pub fn get_log_key(&self) -> String {
        match self {
            ListenHost::Tcp(socket_addr) => socket_addr.port().to_string(),
            ListenHost::Unix(socket) => socket.to_string(),
        }
    }

    pub fn get_port(&self) -> Option<u16> {
        match self {
            ListenHost::Tcp(socket_addr) => Some(socket_addr.port()),
            ListenHost::Unix(_) => None,
        }
    }
}

impl std::fmt::Display for ListenHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ListenHost::Tcp(socket_addr) => write!(f, "{}", socket_addr),
            ListenHost::Unix(socket) => f.write_str(socket.as_str()),
        }
    }
}

impl From<SocketAddr> for ListenHost {
    fn from(val: SocketAddr) -> Self {
        ListenHost::Tcp(val)
    }
}

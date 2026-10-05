mod client_handshake;
mod protocol;
mod server_handshake;

pub use client_handshake::perform_client_handshake;
pub use server_handshake::perform_server_handshake;

/// How long either side waits for the other to complete the handshake. A peer which accepted
/// the TCP connection but never answers must not hold the client back from reconnecting, nor
/// keep a server task and its socket forever.
pub const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

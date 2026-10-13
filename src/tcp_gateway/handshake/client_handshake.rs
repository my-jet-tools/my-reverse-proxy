use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tokio::net::TcpStream;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroize;

use crate::tcp_gateway::session::{CompressionLevel, SessionKeys};

use super::protocol::{
    build_client_handshake, derive_session_keys, read_handshake_frame, write_handshake_frame,
    ServerHandshakeFrame,
};

/// `compression`: what the batches of this gateway connection are packed with, in both
/// directions - the server packs what it sends with the level its client asks for here.
pub async fn perform_client_handshake(
    stream: &mut TcpStream,
    signing_key: &SigningKey,
    gateway_name: &str,
    compression: CompressionLevel,
) -> Result<SessionKeys, String> {
    let eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph_secret);
    let eph_pub_bytes = eph_pub.to_bytes();

    let frame = build_client_handshake(eph_pub_bytes, signing_key, gateway_name, compression);
    write_handshake_frame(stream, &frame.encode()).await?;

    let server_body = read_handshake_frame(stream).await?;
    // Refuses a server of another protocol version.
    let server = ServerHandshakeFrame::decode(&server_body)?;

    let server_eph = PublicKey::from(server.server_eph_pub);
    let shared = eph_secret.diffie_hellman(&server_eph);
    let keys = derive_session_keys(&eph_pub, &server_eph, &shared);

    let mut shared_bytes = shared.as_bytes().to_owned();
    shared_bytes.zeroize();

    Ok(keys)
}

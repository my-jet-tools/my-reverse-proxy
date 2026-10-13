use ed25519_dalek::VerifyingKey;
use rand_core::OsRng;
use tokio::net::TcpStream;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroize;

use crate::tcp_gateway::session::{CompressionLevel, SessionKeys};

use super::protocol::{
    derive_session_keys, read_handshake_frame, validate_timestamp, write_handshake_frame,
    ClientHandshakeFrame, ServerHandshakeFrame,
};

pub struct ServerHandshakeOutcome {
    pub session_keys: SessionKeys,
    pub gateway_name: String,
    pub timestamp_us: i64,
    /// What the client has asked the batches to be packed with: this side packs what it sends
    /// to it the same way.
    pub compression: CompressionLevel,
}

pub async fn perform_server_handshake(
    stream: &mut TcpStream,
    authorized_keys: &[VerifyingKey],
) -> Result<ServerHandshakeOutcome, String> {
    let body = read_handshake_frame(stream).await?;
    // Refuses a client of another protocol version, and one which asks for a compression level
    // this side does not know.
    let client = ClientHandshakeFrame::decode(&body)?;

    validate_timestamp(client.timestamp_us)?;

    let verifying_key = VerifyingKey::from_bytes(&client.client_id_pub)
        .map_err(|err| format!("ClientHandshake: invalid Ed25519 public key bytes: {err}"))?;

    let authorized = authorized_keys
        .iter()
        .any(|k| k.to_bytes() == verifying_key.to_bytes());
    if !authorized {
        return Err("ClientHandshake: client_id_pub is not in authorized_keys".to_string());
    }

    client.verify_signature(&verifying_key)?;

    let server_secret = EphemeralSecret::random_from_rng(OsRng);
    let server_pub = PublicKey::from(&server_secret);

    let server_frame = ServerHandshakeFrame::new(server_pub.to_bytes());
    write_handshake_frame(stream, &server_frame.encode()).await?;

    let client_pub = PublicKey::from(client.client_eph_pub);
    let shared = server_secret.diffie_hellman(&client_pub);
    let session_keys = derive_session_keys(&client_pub, &server_pub, &shared);

    let mut shared_bytes = shared.as_bytes().to_owned();
    shared_bytes.zeroize();

    Ok(ServerHandshakeOutcome {
        session_keys,
        compression: client.compression,
        gateway_name: client.gateway_name,
        timestamp_us: client.timestamp_us,
    })
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::RngCore;
    use rust_extensions::date_time::DateTimeAsMicroseconds;
    use tokio::net::TcpListener;

    use super::super::protocol::{build_client_handshake, signed_transcript, PROTOCOL_VERSION};
    use super::*;

    fn signing_key() -> SigningKey {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        SigningKey::from_bytes(&seed)
    }

    /// The frame `key` signs `seconds_ago` seconds ago, as it goes to the wire.
    fn client_frame(key: &SigningKey, seconds_ago: i64) -> ClientHandshakeFrame {
        let client_eph_pub = [3u8; 32];
        let timestamp_us =
            DateTimeAsMicroseconds::now().unix_microseconds - seconds_ago * 1_000_000;
        let signature = key.sign(&signed_transcript(
            &client_eph_pub,
            timestamp_us,
            CompressionLevel::OFF,
            "london",
        ));

        ClientHandshakeFrame {
            protocol_version: PROTOCOL_VERSION,
            compression: CompressionLevel::OFF,
            client_eph_pub,
            client_id_pub: key.verifying_key().to_bytes(),
            timestamp_us,
            gateway_name: "london".to_string(),
            signature: signature.to_bytes(),
        }
    }

    /// What the server makes of `frame`, sent to it by a client.
    async fn outcome_of(
        frame: Vec<u8>,
        authorized: &[VerifyingKey],
    ) -> Result<ServerHandshakeOutcome, String> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut accepted, _) = listener.accept().await.unwrap();

        write_handshake_frame(&mut client, &frame).await.unwrap();

        perform_server_handshake(&mut accepted, authorized).await
    }

    /// The name the server lets `frame` in under.
    async fn answer_to(frame: Vec<u8>, authorized: &[VerifyingKey]) -> Result<String, String> {
        outcome_of(frame, authorized)
            .await
            .map(|outcome| outcome.gateway_name)
    }

    #[tokio::test]
    async fn only_a_fresh_frame_signed_with_an_authorized_key_is_let_in() {
        let key = signing_key();
        let authorized = [key.verifying_key()];

        assert_eq!(
            answer_to(client_frame(&key, 0).encode(), &authorized).await,
            Ok("london".to_string())
        );

        // A key the server does not list.
        let err = answer_to(client_frame(&signing_key(), 0).encode(), &authorized)
            .await
            .unwrap_err();
        assert!(err.contains("not in authorized_keys"), "{err}");

        // A listed key under a frame somebody else signed.
        let mut forged = client_frame(&signing_key(), 0);
        forged.client_id_pub = key.verifying_key().to_bytes();
        let err = answer_to(forged.encode(), &authorized).await.unwrap_err();
        assert!(err.contains("Signature verification failed"), "{err}");

        // A signed frame with something changed in it afterwards.
        let mut renamed = client_frame(&key, 0);
        renamed.gateway_name = "paris!".to_string();
        let err = answer_to(renamed.encode(), &authorized).await.unwrap_err();
        assert!(err.contains("Signature verification failed"), "{err}");

        // A frame signed too long ago, or too far ahead - whatever the distance. The one ahead
        // is well past the limit: the time this test takes to get it to the server brings it
        // closer.
        for seconds_ago in [61, -120] {
            let err = answer_to(client_frame(&key, seconds_ago).encode(), &authorized)
                .await
                .unwrap_err();
            assert!(err.contains("timestamp drifted"), "{err}");
        }

        let mut out_of_range = client_frame(&key, 0);
        out_of_range.timestamp_us = i64::MIN;
        let err = answer_to(out_of_range.encode(), &authorized)
            .await
            .unwrap_err();
        assert!(err.contains("timestamp drifted"), "{err}");
    }

    /// The level a client asks for is the level its server packs with, and a level the server
    /// has no row for is not let in - by the number, before anything else is looked at.
    #[tokio::test]
    async fn the_server_takes_the_compression_level_its_client_asks_for() {
        const HANDSHAKE_FRAME_HEADER_LEN: usize = 4;

        let key = signing_key();
        let authorized = [key.verifying_key()];

        for compression in CompressionLevel::all() {
            let frame = build_client_handshake([3u8; 32], &key, "london", compression);
            let outcome = outcome_of(frame.encode(), &authorized).await;

            assert_eq!(outcome.map(|outcome| outcome.compression), Ok(compression));
        }

        let mut frame = client_frame(&key, 0).encode();
        frame[HANDSHAKE_FRAME_HEADER_LEN + 1] = CompressionLevel::MAX + 1;

        let err = answer_to(frame, &authorized).await.unwrap_err();
        assert!(err.contains("is not known"), "{err}");
    }
}

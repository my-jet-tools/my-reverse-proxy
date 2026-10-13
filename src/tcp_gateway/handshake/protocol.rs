use std::io;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey, SIGNATURE_LENGTH};
use rust_extensions::date_time::DateTimeAsMicroseconds;
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use x25519_dalek::PublicKey;

use crate::tcp_gateway::session::{CompressionLevel, SessionKeys, FRAME_KEY_LEN};

/// Version 2: the frames are sealed with AES-256-GCM under a key per direction, a frame carries
/// a batch, and the client says in its handshake what the batches are packed with. The two ends
/// of a gateway connection are the same version: a peer of another one is refused here.
pub const PROTOCOL_VERSION: u8 = 2;
pub const HANDSHAKE_TIMESTAMP_TOLERANCE_SECS: i64 = 60;
const HKDF_INFO: &[u8] = b"gateway-session-v2";
const SESSION_KEY_LEN: usize = 2 * FRAME_KEY_LEN;
const HANDSHAKE_FRAME_HEADER_LEN: usize = 4;
const MAX_HANDSHAKE_FRAME_LEN: usize = 4096;
const MAX_GATEWAY_NAME_LEN: usize = 256;
const SIGNED_TRANSCRIPT_PREFIX: &[u8] = b"gateway-handshake-v2:";

const X25519_PUB_LEN: usize = 32;
const ED25519_PUB_LEN: usize = 32;

pub struct ClientHandshakeFrame {
    pub protocol_version: u8,
    /// What the batches of this gateway connection are packed with - in both directions: the
    /// server packs what it sends with the level its client asks for. One byte on the wire.
    pub compression: CompressionLevel,
    pub client_eph_pub: [u8; X25519_PUB_LEN],
    pub client_id_pub: [u8; ED25519_PUB_LEN],
    pub timestamp_us: i64,
    pub gateway_name: String,
    pub signature: [u8; SIGNATURE_LENGTH],
}

pub struct ServerHandshakeFrame {
    pub protocol_version: u8,
    pub server_eph_pub: [u8; X25519_PUB_LEN],
}

pub fn signed_transcript(
    client_eph_pub: &[u8; X25519_PUB_LEN],
    timestamp_us: i64,
    compression: CompressionLevel,
    gateway_name: &str,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        SIGNED_TRANSCRIPT_PREFIX.len() + X25519_PUB_LEN + 8 + 1 + gateway_name.len(),
    );
    buf.extend_from_slice(SIGNED_TRANSCRIPT_PREFIX);
    buf.extend_from_slice(client_eph_pub);
    buf.extend_from_slice(&timestamp_us.to_le_bytes());
    buf.push(compression.as_u8());
    buf.extend_from_slice(gateway_name.as_bytes());
    buf
}

pub fn build_client_handshake(
    client_eph_pub: [u8; X25519_PUB_LEN],
    signing_key: &SigningKey,
    gateway_name: &str,
    compression: CompressionLevel,
) -> ClientHandshakeFrame {
    let timestamp_us = DateTimeAsMicroseconds::now().unix_microseconds;
    let transcript = signed_transcript(&client_eph_pub, timestamp_us, compression, gateway_name);
    let signature = signing_key.sign(&transcript);
    ClientHandshakeFrame {
        protocol_version: PROTOCOL_VERSION,
        compression,
        client_eph_pub,
        client_id_pub: signing_key.verifying_key().to_bytes(),
        timestamp_us,
        gateway_name: gateway_name.to_string(),
        signature: signature.to_bytes(),
    }
}

impl ClientHandshakeFrame {
    pub fn encode(&self) -> Vec<u8> {
        let name_bytes = self.gateway_name.as_bytes();
        let mut body = Vec::with_capacity(
            2 + X25519_PUB_LEN + ED25519_PUB_LEN + 8 + 4 + name_bytes.len() + SIGNATURE_LENGTH,
        );
        body.push(self.protocol_version);
        body.push(self.compression.as_u8());
        body.extend_from_slice(&self.client_eph_pub);
        body.extend_from_slice(&self.client_id_pub);
        body.extend_from_slice(&self.timestamp_us.to_le_bytes());
        body.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        body.extend_from_slice(name_bytes);
        body.extend_from_slice(&self.signature);
        prepend_length(body)
    }

    pub fn decode(body: &[u8]) -> Result<Self, String> {
        let mut cursor = 0usize;
        let protocol_version = read_u8(body, &mut cursor)?;

        // First of all: the frame of another version is laid out another way, and read as this
        // one it would only say that something in it is cut short.
        if protocol_version != PROTOCOL_VERSION {
            return Err(format!(
                "ClientHandshake: unsupported protocol_version {protocol_version}, this side speaks {PROTOCOL_VERSION}"
            ));
        }

        // A level this side has no row for: the client is of a build with a longer table.
        let compression = CompressionLevel::new(read_u8(body, &mut cursor)?)
            .map_err(|err| format!("ClientHandshake: {err}"))?;

        let client_eph_pub = read_array::<X25519_PUB_LEN>(body, &mut cursor)?;
        let client_id_pub = read_array::<ED25519_PUB_LEN>(body, &mut cursor)?;
        let timestamp_us = read_i64(body, &mut cursor)?;
        let name_len = read_u32(body, &mut cursor)? as usize;
        if name_len > MAX_GATEWAY_NAME_LEN {
            return Err(format!(
                "ClientHandshake: gateway_name too long ({name_len})"
            ));
        }
        if body.len() < cursor + name_len {
            return Err("ClientHandshake: truncated gateway_name".to_string());
        }
        let gateway_name = std::str::from_utf8(&body[cursor..cursor + name_len])
            .map_err(|_| "ClientHandshake: gateway_name is not valid UTF-8".to_string())?
            .to_string();
        cursor += name_len;
        let signature = read_array::<SIGNATURE_LENGTH>(body, &mut cursor)?;
        if cursor != body.len() {
            return Err("ClientHandshake: trailing bytes".to_string());
        }
        Ok(Self {
            protocol_version,
            compression,
            client_eph_pub,
            client_id_pub,
            timestamp_us,
            gateway_name,
            signature,
        })
    }

    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> Result<(), String> {
        let transcript = signed_transcript(
            &self.client_eph_pub,
            self.timestamp_us,
            self.compression,
            &self.gateway_name,
        );
        let signature = Signature::from_bytes(&self.signature);
        verifying_key
            .verify(&transcript, &signature)
            .map_err(|err| format!("Signature verification failed: {err}"))
    }
}

impl ServerHandshakeFrame {
    pub fn new(server_eph_pub: [u8; X25519_PUB_LEN]) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            server_eph_pub,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(1 + X25519_PUB_LEN);
        body.push(self.protocol_version);
        body.extend_from_slice(&self.server_eph_pub);
        prepend_length(body)
    }

    pub fn decode(body: &[u8]) -> Result<Self, String> {
        // First of all, as in the frame of the client: another version may be another layout.
        if let Some(&protocol_version) = body.first() {
            if protocol_version != PROTOCOL_VERSION {
                return Err(format!(
                    "ServerHandshake: unsupported protocol_version {protocol_version}, this side speaks {PROTOCOL_VERSION}"
                ));
            }
        }

        if body.len() != 1 + X25519_PUB_LEN {
            return Err(format!(
                "ServerHandshake: unexpected length {} (want {})",
                body.len(),
                1 + X25519_PUB_LEN
            ));
        }
        let protocol_version = body[0];
        let mut server_eph_pub = [0u8; X25519_PUB_LEN];
        server_eph_pub.copy_from_slice(&body[1..]);
        Ok(Self {
            protocol_version,
            server_eph_pub,
        })
    }
}

/// The keys of the gateway connection: one for what the client sends, one for what the server
/// sends.
pub fn derive_session_keys(
    client_eph_pub: &PublicKey,
    server_eph_pub: &PublicKey,
    shared: &x25519_dalek::SharedSecret,
) -> SessionKeys {
    let mut salt = [0u8; X25519_PUB_LEN * 2];
    salt[..X25519_PUB_LEN].copy_from_slice(client_eph_pub.as_bytes());
    salt[X25519_PUB_LEN..].copy_from_slice(server_eph_pub.as_bytes());
    let hk = hkdf::Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
    let mut okm = zeroize::Zeroizing::new([0u8; SESSION_KEY_LEN]);
    hk.expand(HKDF_INFO, okm.as_mut())
        .expect("HKDF: 64 bytes is within Sha256 output limit");
    SessionKeys::new(&okm)
}

pub fn validate_timestamp(timestamp_us: i64) -> Result<(), String> {
    let now = DateTimeAsMicroseconds::now().unix_microseconds;
    // The timestamp is whatever the peer sent: any distance has to fit.
    let diff_us = now.abs_diff(timestamp_us);
    let tolerance_us = HANDSHAKE_TIMESTAMP_TOLERANCE_SECS as u64 * 1_000_000;
    if diff_us > tolerance_us {
        return Err(format!(
            "Handshake timestamp drifted {diff_us} us (max {tolerance_us})"
        ));
    }
    Ok(())
}

pub async fn write_handshake_frame(stream: &mut TcpStream, framed: &[u8]) -> Result<(), String> {
    stream
        .write_all(framed)
        .await
        .map_err(|err| format!("Handshake write error: {err}"))
}

pub async fn read_handshake_frame(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; HANDSHAKE_FRAME_HEADER_LEN];
    read_exact_or_eof(stream, &mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > MAX_HANDSHAKE_FRAME_LEN {
        return Err(format!("Handshake frame size {len} out of range"));
    }
    let mut body = vec![0u8; len];
    read_exact_or_eof(stream, &mut body).await?;
    Ok(body)
}

async fn read_exact_or_eof(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(), String> {
    match stream.read_exact(buf).await {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
            Err("Peer closed during handshake".to_string())
        }
        Err(err) => Err(format!("Handshake read error: {err}")),
    }
}

fn prepend_length(body: Vec<u8>) -> Vec<u8> {
    let len = body.len() as u32;
    let mut out = Vec::with_capacity(HANDSHAKE_FRAME_HEADER_LEN + body.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&body);
    out
}

fn read_u8(buf: &[u8], cursor: &mut usize) -> Result<u8, String> {
    if *cursor + 1 > buf.len() {
        return Err("ClientHandshake: truncated u8".to_string());
    }
    let value = buf[*cursor];
    *cursor += 1;
    Ok(value)
}

fn read_array<const N: usize>(buf: &[u8], cursor: &mut usize) -> Result<[u8; N], String> {
    if *cursor + N > buf.len() {
        return Err(format!("ClientHandshake: truncated [u8; {N}]"));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&buf[*cursor..*cursor + N]);
    *cursor += N;
    Ok(out)
}

fn read_i64(buf: &[u8], cursor: &mut usize) -> Result<i64, String> {
    let arr = read_array::<8>(buf, cursor)?;
    Ok(i64::from_le_bytes(arr))
}

fn read_u32(buf: &[u8], cursor: &mut usize) -> Result<u32, String> {
    let arr = read_array::<4>(buf, cursor)?;
    Ok(u32::from_le_bytes(arr))
}

#[cfg(test)]
mod tests {
    use rand_core::{OsRng, RngCore};

    use super::*;

    fn signing_key() -> SigningKey {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        SigningKey::from_bytes(&seed)
    }

    /// The body of the frame, without the length it travels behind.
    fn body_of(frame: &ClientHandshakeFrame) -> Vec<u8> {
        frame.encode()[HANDSHAKE_FRAME_HEADER_LEN..].to_vec()
    }

    #[test]
    fn the_client_frame_carries_the_compression_level() {
        let key = signing_key();

        for compression in CompressionLevel::all() {
            let frame = build_client_handshake([3u8; X25519_PUB_LEN], &key, "london", compression);

            let body = body_of(&frame);
            assert_eq!(body[1], compression.as_u8());

            let decoded = ClientHandshakeFrame::decode(&body).unwrap();

            assert_eq!(decoded.compression, compression);
            assert_eq!(decoded.gateway_name, "london");
            assert_eq!(decoded.client_eph_pub, [3u8; X25519_PUB_LEN]);
            decoded.verify_signature(&key.verifying_key()).unwrap();
        }
    }

    /// The level is under the signature: a link which changed it on the way would leave the
    /// two ends packing differently.
    #[test]
    fn the_compression_level_is_signed() {
        let key = signing_key();

        for (signed, changed_to) in [(0, 1), (1, 0), (1, 2), (CompressionLevel::MAX, 1)] {
            let frame = build_client_handshake(
                [3u8; X25519_PUB_LEN],
                &key,
                "london",
                CompressionLevel::new(signed).unwrap(),
            );

            let mut body = body_of(&frame);
            assert_eq!(body[1], signed);
            body[1] = changed_to;

            let changed = ClientHandshakeFrame::decode(&body).unwrap();
            assert_eq!(changed.compression.as_u8(), changed_to);
            assert!(changed.verify_signature(&key.verifying_key()).is_err());
        }
    }

    #[test]
    fn a_frame_of_another_protocol_version_is_refused_by_its_version() {
        let key = signing_key();
        let frame = build_client_handshake(
            [3u8; X25519_PUB_LEN],
            &key,
            "london",
            CompressionLevel::new(1).unwrap(),
        );

        let mut body = body_of(&frame);
        body[0] = 1;
        let err = ClientHandshakeFrame::decode(&body).err().unwrap();
        assert!(err.contains("unsupported protocol_version 1"), "{err}");

        // The frame of version 1 as it was: no compression level, so everything behind the
        // version is shifted - it is still the version which is reported.
        body.remove(1);
        let err = ClientHandshakeFrame::decode(&body).err().unwrap();
        assert!(err.contains("unsupported protocol_version 1"), "{err}");

        let mut server = ServerHandshakeFrame::new([5u8; X25519_PUB_LEN]).encode()
            [HANDSHAKE_FRAME_HEADER_LEN..]
            .to_vec();
        assert!(ServerHandshakeFrame::decode(&server).is_ok());
        server[0] = 1;
        let err = ServerHandshakeFrame::decode(&server).err().unwrap();
        assert!(err.contains("unsupported protocol_version 1"), "{err}");
    }

    /// A client of a build whose table is longer: the level it asks for is refused, and by
    /// its number.
    #[test]
    fn a_compression_level_this_side_does_not_know_is_refused() {
        let key = signing_key();
        let frame =
            build_client_handshake([3u8; X25519_PUB_LEN], &key, "london", CompressionLevel::OFF);

        for level in [CompressionLevel::MAX + 1, 0x80, 0xff] {
            let mut body = body_of(&frame);
            body[1] = level;

            let err = ClientHandshakeFrame::decode(&body).err().unwrap();
            assert!(
                err.contains(&format!("compression level {level} is not known")),
                "{err}"
            );
        }
    }
}

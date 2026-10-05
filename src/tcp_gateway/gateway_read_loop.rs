use std::{io::Read, sync::Arc, time::Duration};

use encryption::AesEncryptedDataRef;
use rust_extensions::date_time::DateTimeAsMicroseconds;
use tokio::{io::AsyncReadExt, net::tcp::OwnedReadHalf};

use super::*;

/// A live peer is never silent this long: the client pings every 3 seconds and the server
/// answers every ping. Bytes trickling in through a big frame count as activity, so a slow link
/// is not mistaken for a dead one. This is what finds a peer which vanished without closing
/// the socket - nothing else on the server side would.
const READ_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn gateway_read_loop(
    tcp_gateway: Arc<TcpGatewayInner>,
    mut read: OwnedReadHalf,
    gateway_connection: Arc<TcpGatewayConnection>,
    packet_handler: impl TcpGatewayPacketHandler,
    debug: bool,
) {
    // Tears the connection down however the loop ends - a closed socket, a bad frame, a
    // disconnect requested from outside, or a panic in a packet handler.
    let _teardown = ReadLoopTeardown {
        tcp_gateway: tcp_gateway.clone(),
        gateway_connection: gateway_connection.clone(),
    };

    let disconnected = gateway_connection.disconnected_token();

    tokio::select! {
        _ = disconnected.cancelled() => {
            if debug {
                println!(
                    "TCP Gateway connection [{}] at {} is disconnected",
                    gateway_connection.get_gateway_id(),
                    tcp_gateway.gateway_host.as_str()
                );
            }
        }
        _ = read_frames(&tcp_gateway, &mut read, &gateway_connection, &packet_handler, debug) => {}
    }
}

struct ReadLoopTeardown {
    tcp_gateway: Arc<TcpGatewayInner>,
    gateway_connection: Arc<TcpGatewayConnection>,
}

impl Drop for ReadLoopTeardown {
    fn drop(&mut self) {
        let gateway_id = self.gateway_connection.get_gateway_id();
        self.tcp_gateway
            .remove_gateway_connection(gateway_id.as_str(), &self.gateway_connection);
        self.gateway_connection.disconnect_gateway();
    }
}

async fn read_frames(
    tcp_gateway: &Arc<TcpGatewayInner>,
    read: &mut OwnedReadHalf,
    gateway_connection: &Arc<TcpGatewayConnection>,
    packet_handler: &impl TcpGatewayPacketHandler,
    debug: bool,
) {
    let mut buf = crate::tcp_utils::allocated_read_buffer(None);
    let mut payload_no: u64 = 0;
    let aes_key = gateway_connection.get_aes_key().clone();

    loop {
        payload_no += 1;
        let mut payload_size = [0u8; 4];

        if let Err(err) = read_exact(read, &mut payload_size, gateway_connection).await {
            if debug {
                println!(
                    "[1] Failed to read payload size from TCP Gateway at {}. Err: {}",
                    tcp_gateway.gateway_host.as_str(),
                    err
                );
            }
            return;
        }

        let payload_size = u32::from_le_bytes(payload_size) as usize;

        if payload_size > MAX_PAYLOAD_SIZE {
            println!(
                "[1] Failed to read payload size from TCP Gateway at {}. Payload no: {payload_no}. Max payload size is overflown, PayloadSize: {payload_size}",
                tcp_gateway.gateway_host.as_str(),
            );
            return;
        }

        let mut dynamic_buffer: Vec<u8>;
        let frame: &mut [u8] = if payload_size > buf.len() {
            dynamic_buffer = crate::tcp_utils::allocated_read_buffer(Some(payload_size));
            &mut dynamic_buffer[..]
        } else {
            &mut buf[..payload_size]
        };

        if let Err(err) = read_exact(read, frame, gateway_connection).await {
            if debug {
                println!(
                    "[2] Failed to read payload from TCP Gateway at {}. Err: {}",
                    tcp_gateway.gateway_host.as_str(),
                    err
                );
            }
            return;
        }

        let decrypted = match aes_key.decrypt(&AesEncryptedDataRef::new(frame)) {
            Ok(decrypted) => decrypted,
            Err(_) => {
                println!("TcpGateway is closing connection: decryption failed");
                return;
            }
        };

        let decrypted_bytes = decrypted.as_slice();

        if decrypted_bytes.is_empty() {
            println!("TcpGateway received empty frame body");
            return;
        }

        if decrypted_bytes[0] == COMPRESSED_BATCH_PACKET_ID {
            if let Err(err) = handle_compressed_batch(
                decrypted_bytes,
                tcp_gateway,
                gateway_connection,
                packet_handler,
            )
            .await
            {
                println!(
                    "TcpGateway compressed batch from {} failed: {err}",
                    tcp_gateway.gateway_host.as_str()
                );
                return;
            }
            continue;
        }

        match TcpGatewayContract::parse_with_capabilities(
            decrypted_bytes,
            gateway_connection.own_capabilities(),
        ) {
            Ok(packet) => {
                if let Err(err) = packet_handler
                    .handle_packet(packet, tcp_gateway, gateway_connection)
                    .await
                {
                    println!(
                        "Failed to handle packet from TCP Gateway at {}. Err: {}",
                        tcp_gateway.gateway_host.as_str(),
                        err
                    );
                    return;
                }
            }
            Err(err) => {
                println!(
                    "Failed to parse packet from TCP Gateway at {}. Err: {:?}",
                    tcp_gateway.gateway_host.as_str(),
                    err
                );
                return;
            }
        }
    }
}

/// `read_exact` which gives up on a peer silent for [`READ_IDLE_TIMEOUT`] and records every
/// chunk as incoming activity - the client's dead-peer check is based on it.
async fn read_exact(
    read: &mut OwnedReadHalf,
    buf: &mut [u8],
    gateway_connection: &TcpGatewayConnection,
) -> Result<(), String> {
    let mut filled = 0;

    while filled < buf.len() {
        let read_size =
            match tokio::time::timeout(READ_IDLE_TIMEOUT, read.read(&mut buf[filled..])).await {
                Ok(Ok(0)) => return Err("Disconnected".to_string()),
                Ok(Ok(read_size)) => read_size,
                Ok(Err(err)) => return Err(format!("{:?}", err)),
                Err(_) => return Err(format!("No incoming data for {:?}", READ_IDLE_TIMEOUT)),
            };

        filled += read_size;
        gateway_connection.in_per_second.add(read_size);
        gateway_connection.set_last_incoming_payload_time(DateTimeAsMicroseconds::now());
    }

    Ok(())
}

async fn handle_compressed_batch(
    decrypted: &[u8],
    tcp_gateway: &Arc<TcpGatewayInner>,
    gateway_connection: &Arc<TcpGatewayConnection>,
    packet_handler: &impl TcpGatewayPacketHandler,
) -> Result<(), String> {
    if decrypted.len() < 2 {
        return Err("COMPRESSED_BATCH: missing algo byte".to_string());
    }
    let algo = decrypted[1];
    if algo != COMPRESSION_ALGO_ZSTD {
        return Err(format!("COMPRESSED_BATCH: unknown algo byte {algo}"));
    }

    let decompressed = decompress_batch(&decrypted[2..])?;

    let mut offset = 0usize;
    while offset + 4 <= decompressed.len() {
        let inner_len = u32::from_le_bytes([
            decompressed[offset],
            decompressed[offset + 1],
            decompressed[offset + 2],
            decompressed[offset + 3],
        ]) as usize;
        offset += 4;
        if offset + inner_len > decompressed.len() {
            return Err("COMPRESSED_BATCH: truncated inner frame".to_string());
        }
        let body = &decompressed[offset..offset + inner_len];
        offset += inner_len;

        if body.is_empty() {
            return Err("COMPRESSED_BATCH: empty inner frame".to_string());
        }
        if body[0] == COMPRESSED_BATCH_PACKET_ID {
            return Err("COMPRESSED_BATCH: nested batch is not allowed".to_string());
        }

        let packet = TcpGatewayContract::parse_with_capabilities(
            body,
            gateway_connection.own_capabilities(),
        )
        .map_err(|err| format!("COMPRESSED_BATCH: failed to parse inner frame: {err}"))?;
        packet_handler
            .handle_packet(packet, tcp_gateway, gateway_connection)
            .await
            .map_err(|err| format!("COMPRESSED_BATCH: handler failed: {err}"))?;
    }

    if offset != decompressed.len() {
        return Err("COMPRESSED_BATCH: trailing bytes after last inner frame".to_string());
    }

    Ok(())
}

/// Decompresses no further than one byte past [`MAX_DECOMPRESSED_BATCH_SIZE`]: checking the
/// size of a fully decompressed batch would come after the memory is already spent.
pub(crate) fn decompress_batch(compressed: &[u8]) -> Result<Vec<u8>, String> {
    let decoder = zstd::stream::read::Decoder::new(compressed)
        .map_err(|err| format!("COMPRESSED_BATCH: zstd decompress failed: {err}"))?;

    let mut decompressed = Vec::new();
    decoder
        .take(MAX_DECOMPRESSED_BATCH_SIZE as u64 + 1)
        .read_to_end(&mut decompressed)
        .map_err(|err| format!("COMPRESSED_BATCH: zstd decompress failed: {err}"))?;

    if decompressed.len() > MAX_DECOMPRESSED_BATCH_SIZE {
        return Err(format!(
            "COMPRESSED_BATCH: decompressed size exceeds {} limit",
            MAX_DECOMPRESSED_BATCH_SIZE
        ));
    }

    Ok(decompressed)
}

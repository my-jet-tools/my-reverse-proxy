use std::{sync::Arc, time::Duration};

use rust_extensions::{
    date_time::DateTimeAsMicroseconds, DoubleBuffer, DoubleBufferReader, DoubleBufferWriter,
};
use tokio::{io::AsyncReadExt, net::tcp::OwnedReadHalf};

use super::session::{BatchUnpacker, FrameOpener, FRAME_LEN_SIZE, FRAME_TAG_LEN};
use super::*;

/// A live peer is never silent this long: the client pings every 3 seconds and the server
/// answers every ping. Bytes trickling in through a big frame count as activity, so a slow link
/// is not mistaken for a dead one. This is what finds a peer which vanished without closing
/// the socket - nothing else on the server side would.
const READ_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Reads the gateway connection until it ends, and tears it down then.
///
/// The work is split between two tasks, with the two buffers of a [`DoubleBuffer`] between
/// them: the socket reader reads a frame into a buffer and opens it there, and this task unpacks
/// the batch the frame carries and handles its inner frames, in the order they came. The next
/// frame may be read and opened there - into the other buffer - while a batch is handled here;
/// how much the two overlap is up to the scheduler.
pub async fn gateway_read_loop(
    tcp_gateway: Arc<TcpGatewayInner>,
    read: OwnedReadHalf,
    opener: FrameOpener,
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

    // Each buffer takes a frame of any size a peer may send, and is allocated when it is first
    // read into.
    let (buffers, batches) = DoubleBuffer::new(MAX_PAYLOAD_SIZE);

    // The socket reader goes together with this loop, however the loop ends - also while it
    // waits on a silent socket.
    let _socket_reader = AbortOnDrop(crate::app::spawn_named(
        "tcp_gateway_socket_reader",
        read_socket(
            read,
            buffers,
            opener,
            gateway_connection.clone(),
            tcp_gateway.gateway_host.clone(),
            debug,
        ),
    ));

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
        _ = handle_batches(&tcp_gateway, &batches, &gateway_connection, &packet_handler) => {}
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

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The socket reader: reads the frames off the socket, each into one of the two buffers, opens
/// it in place and hands the batch it carried over to the read loop. It waits while both
/// buffers are still being handled - the socket is left alone meanwhile, and the peer's writer
/// slows down to the speed of this side.
///
/// It ends when the socket does, on a frame which is too big or does not open, or with the read
/// loop. Its end of the buffers is dropped then: the read loop handles what was handed over
/// before, and ends.
async fn read_socket(
    mut read: OwnedReadHalf,
    buffers: DoubleBufferWriter,
    mut opener: FrameOpener,
    gateway_connection: Arc<TcpGatewayConnection>,
    gateway_host: Arc<String>,
    debug: bool,
) {
    let mut frame_no: u64 = 0;

    loop {
        frame_no += 1;
        let mut frame_len = [0u8; FRAME_LEN_SIZE];

        if let Err(err) = read_exact(&mut read, &mut frame_len, &gateway_connection).await {
            if debug {
                println!(
                    "[1] Failed to read frame length from TCP Gateway at {}. Err: {}",
                    gateway_host.as_str(),
                    err
                );
            }
            return;
        }

        let frame_len = u32::from_le_bytes(frame_len) as usize;

        if frame_len > MAX_PAYLOAD_SIZE {
            println!(
                "[1] Failed to read frame from TCP Gateway at {}. Frame no: {frame_no}. Max frame size is overflown, FrameSize: {frame_len}",
                gateway_host.as_str(),
            );
            return;
        }

        // A frame is a batch - its kind at least - and the tag.
        if frame_len <= FRAME_TAG_LEN {
            println!(
                "[1] Failed to read frame from TCP Gateway at {}. Frame no: {frame_no}. A frame of {frame_len} bytes carries nothing",
                gateway_host.as_str(),
            );
            return;
        }

        // The read loop is gone.
        let Ok(mut buffer) = buffers.get_buffer_to_read().await else {
            return;
        };

        if let Err(err) = read_exact(&mut read, &mut buffer[..frame_len], &gateway_connection).await
        {
            if debug {
                println!(
                    "[2] Failed to read frame from TCP Gateway at {}. Err: {}",
                    gateway_host.as_str(),
                    err
                );
            }
            return;
        }

        let batch_len = match opener.open(&mut buffer[..frame_len]) {
            Ok(batch_len) => batch_len,
            Err(err) => {
                println!(
                    "TcpGateway is closing connection to {}. Frame no: {frame_no}. {err}",
                    gateway_host.as_str()
                );
                return;
            }
        };

        buffer.send(batch_len);
    }
}

/// Handles the batches the socket reader hands over, until it ends or a batch can not be
/// handled.
async fn handle_batches(
    tcp_gateway: &Arc<TcpGatewayInner>,
    batches: &DoubleBufferReader,
    gateway_connection: &Arc<TcpGatewayConnection>,
    packet_handler: &impl TcpGatewayPacketHandler,
) {
    // Unpacks the packed batches; what it needs for that is kept from batch to batch.
    let mut unpacker = BatchUnpacker::new();

    // Until the socket reader ends: the socket did, or a frame was not what a peer may send.
    while let Ok(Some(batch)) = batches.get_next().await {
        let handled = handle_batch(
            &batch,
            &mut unpacker,
            tcp_gateway,
            gateway_connection,
            packet_handler,
        )
        .await;

        if let Err(err) = handled {
            println!(
                "Failed to handle batch from TCP Gateway at {}. Err: {err}",
                tcp_gateway.gateway_host.as_str()
            );
            return;
        }

        unpacker.release_buffer();

        // `batch` is dropped here: handled, and its buffer is free for a frame again.
    }
}

/// Handles the inner frames `[u32 LEN][u8 TYPE][PAYLOAD]` of one batch, one after another.
async fn handle_batch(
    batch: &[u8],
    unpacker: &mut BatchUnpacker,
    tcp_gateway: &Arc<TcpGatewayInner>,
    gateway_connection: &Arc<TcpGatewayConnection>,
    packet_handler: &impl TcpGatewayPacketHandler,
) -> Result<(), String> {
    let mut frames = unpacker.read_batch(batch)?;

    while !frames.is_empty() {
        let Some((frame_len, rest)) = frames.split_first_chunk::<4>() else {
            return Err("Batch: trailing bytes after last inner frame".to_string());
        };

        let frame_len = u32::from_le_bytes(*frame_len) as usize;

        if frame_len > rest.len() {
            return Err("Batch: truncated inner frame".to_string());
        }

        let (frame, rest) = rest.split_at(frame_len);
        frames = rest;

        let packet = TcpGatewayContract::parse(frame)
            .map_err(|err| format!("Batch: failed to parse inner frame: {err}"))?;

        packet_handler
            .handle_packet(packet, tcp_gateway, gateway_connection)
            .await
            .map_err(|err| format!("Batch: handler failed: {err}"))?;
    }

    Ok(())
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

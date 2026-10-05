use std::{collections::VecDeque, future::Future, pin::Pin, sync::Arc, time::Duration};

use encryption::aes::AesKey;
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::network_stream::{MyOwnedWriteHalf, NetworkStreamWritePart};
use crate::tcp_gateway::{
    encrypt_frame, OutgoingFrame, COMPRESSED_BATCH_PACKET_ID, COMPRESSION_ALGO_ZSTD,
};

const ZSTD_LEVEL: i32 = 3;

/// Plaintext handed to the socket in one write. Small enough that a `COMPRESSED_BATCH` stays far
/// below the receiver's frame limits, and that write budget comes back in steady steps on a slow
/// link.
const MAX_WRITE_BATCH: usize = 256 * 1024;

/// `WINDOW_UPDATE` bytes one batch carries at most ahead of its data - 315 of them. Keeps a batch
/// with a near-limit `GET_FILE_RESPONSE` within the frame limit; the rest go with the next batch.
const MAX_CREDIT_PER_BATCH: usize = 4 * 1024;

/// How long a closing writer may spend on shutting its socket down.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

type WriteFuture =
    Pin<Box<dyn Future<Output = (MyOwnedWriteHalf, Result<(), std::io::Error>)> + Send>>;

/// Writer task for a gateway TCP connection.
///
/// Producers push **plaintext** inner frames `[u32 LEN][u8 TYPE][PAYLOAD]`
/// into `rx`. The writer queues them while the previous `write_all` is still
/// in flight. On every flush boundary it takes up to [`MAX_WRITE_BATCH`] of
/// queued frames and either:
///
/// - encrypts them frame-by-frame and writes them as concatenated wire frames
///   (`compress_outbound = false`), or
/// - zstd-compresses them as a whole, wraps them as a single `COMPRESSED_BATCH`
///   frame, then encrypts and writes that (`compress_outbound = true`).
///
/// The write budget held by the frames of a batch goes back to `write_budget`
/// once the batch is on the socket.
///
/// The queue is FIFO but for `WINDOW_UPDATE` frames, which go out with the next
/// batch, ahead of the queued ones: one connection's credit must not wait behind
/// another connection's data. An expedited frame never goes out after a frame
/// queued after it: a batch which leaves credit behind carries nothing else.
/// Overtaking frames queued before it is harmless: credit is additive, it is
/// sent only for a connection the peer opened already, and the peer drops
/// credit for an id it no longer knows.
pub async fn gateway_write_loop(
    write_half: MyOwnedWriteHalf,
    mut rx: mpsc::UnboundedReceiver<OutgoingFrame>,
    aes_key: Arc<AesKey>,
    compress_outbound: bool,
    disconnected: CancellationToken,
    write_budget: Arc<Semaphore>,
) {
    let mut queue: VecDeque<OutgoingFrame> = VecDeque::new();
    let mut credits: VecDeque<OutgoingFrame> = VecDeque::new();
    let mut write_fut: Option<WriteFuture> = None;
    let mut in_flight_budget: usize = 0;
    let mut write_half_holder: Option<MyOwnedWriteHalf> = Some(write_half);

    loop {
        if write_fut.is_none() && !(queue.is_empty() && credits.is_empty()) {
            let (plaintext, budget) = take_batch(&mut credits, &mut queue);
            in_flight_budget = budget;
            let wire = build_wire(&plaintext, &aes_key, compress_outbound);
            let mut owned_write_half = write_half_holder.take().expect("write_half was borrowed");
            write_fut = Some(Box::pin(async move {
                let res = owned_write_half.write_to_socket(&wire).await;
                (owned_write_half, res)
            }));
        }

        tokio::select! {
            _ = disconnected.cancelled() => break,

            msg = rx.recv() => {
                match msg {
                    Some(frame) if frame.expedite => credits.push_back(frame),
                    Some(frame) => queue.push_back(frame),
                    None => break,
                }
            }

            res = async { write_fut.as_mut().unwrap().as_mut().await }, if write_fut.is_some() => {
                let (returned_half, io_res) = res;
                write_half_holder = Some(returned_half);
                write_fut = None;
                write_budget.add_permits(std::mem::take(&mut in_flight_budget));
                if let Err(err) = io_res {
                    eprintln!("gateway_write_loop: write failure: {:?}", err);
                    break;
                }
            }
        }
    }

    // A writer which stops takes the whole connection down with it: the read loop sees the
    // cancellation and tears the connection down, and producers waiting for budget are released
    // instead of waiting forever.
    disconnected.cancel();
    write_budget.close();

    // What is still queued goes down with the connection. A write in flight may be stuck on a
    // peer which stopped reading, so it is dropped rather than awaited - dropping the write half
    // it owns shuts the socket down.
    drop(write_fut);
    if let Some(mut half) = write_half_holder.take() {
        let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, half.shutdown_socket()).await;
    }
}

/// Takes the queued `WINDOW_UPDATE`s first - up to [`MAX_CREDIT_PER_BATCH`] of them - then whole
/// frames off the front of `queue`: at least one, then more while their bytes stay within
/// [`MAX_WRITE_BATCH`]. Credit does not count against that limit, so it never puts a big frame
/// off. A batch which leaves credit behind takes no frames off `queue`: those may have been
/// queued after the credit left behind. Returns the concatenated plaintext and the write budget
/// the frames hold.
fn take_batch(
    credits: &mut VecDeque<OutgoingFrame>,
    queue: &mut VecDeque<OutgoingFrame>,
) -> (Vec<u8>, usize) {
    let mut plaintext = Vec::new();

    while let Some(credit) = credits.front() {
        if !plaintext.is_empty() && plaintext.len() + credit.payload.len() > MAX_CREDIT_PER_BATCH {
            break;
        }

        plaintext.extend_from_slice(&credits.pop_front().unwrap().payload);
    }

    let credit_len = plaintext.len();
    let mut budget = 0usize;

    if !credits.is_empty() {
        return (plaintext, budget);
    }

    while let Some(frame) = queue.front() {
        let data_len = plaintext.len() - credit_len;
        if data_len > 0 && data_len + frame.payload.len() > MAX_WRITE_BATCH {
            break;
        }

        let frame = queue.pop_front().unwrap();
        plaintext.extend_from_slice(&frame.payload);
        budget += frame.budget as usize;
    }

    (plaintext, budget)
}

fn build_wire(plaintext: &[u8], aes: &AesKey, compress_outbound: bool) -> Vec<u8> {
    if compress_outbound {
        encode_compressed_batch(plaintext, aes)
    } else {
        encode_individual_frames(plaintext, aes)
    }
}

fn encode_individual_frames(plaintext: &[u8], aes: &AesKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(plaintext.len() + 64);
    let mut offset = 0usize;
    while offset + 4 <= plaintext.len() {
        let inner_len = u32::from_le_bytes([
            plaintext[offset],
            plaintext[offset + 1],
            plaintext[offset + 2],
            plaintext[offset + 3],
        ]) as usize;
        offset += 4;
        if offset + inner_len > plaintext.len() {
            eprintln!(
                "gateway_write_loop: truncated inner frame in accumulator (need {inner_len}, have {})",
                plaintext.len() - offset
            );
            return out;
        }
        let body = &plaintext[offset..offset + inner_len];
        offset += inner_len;
        out.extend_from_slice(&encrypt_frame(body, aes));
    }
    out
}

fn encode_compressed_batch(plaintext: &[u8], aes: &AesKey) -> Vec<u8> {
    let compressed = match zstd::stream::encode_all(plaintext, ZSTD_LEVEL) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("gateway_write_loop: zstd compression failed: {err}");
            return encode_individual_frames(plaintext, aes);
        }
    };

    let mut body = Vec::with_capacity(2 + compressed.len());
    body.push(COMPRESSED_BATCH_PACKET_ID);
    body.push(COMPRESSION_ALGO_ZSTD);
    body.extend_from_slice(&compressed);
    encrypt_frame(&body, aes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(len: usize, budget: u32, expedite: bool) -> OutgoingFrame {
        OutgoingFrame {
            payload: vec![0; len],
            budget,
            expedite,
        }
    }

    #[test]
    fn credit_goes_first_and_never_puts_a_big_frame_off() {
        let mut credits: VecDeque<_> = (0..3).map(|_| frame(13, 0, true)).collect();
        let mut queue: VecDeque<_> =
            [frame(MAX_WRITE_BATCH + 9, 100, false), frame(100, 7, false)].into();

        let (plaintext, budget) = take_batch(&mut credits, &mut queue);
        assert_eq!(plaintext.len(), 3 * 13 + MAX_WRITE_BATCH + 9);
        assert_eq!(budget, 100);
        assert!(credits.is_empty());
        assert_eq!(queue.len(), 1, "the small frame waits for the next batch");

        let mut credits: VecDeque<_> = (0..400).map(|_| frame(13, 0, true)).collect();
        let mut queue = VecDeque::new();

        let (plaintext, budget) = take_batch(&mut credits, &mut queue);
        assert_eq!(plaintext.len(), 315 * 13);
        assert_eq!(budget, 0);
        assert_eq!(credits.len(), 85, "the rest go with the next batch");
    }

    /// A connection's credit does not wait behind data queued before it: with the writer blocked
    /// on a write the peer does not take, it goes out with the very next batch, ahead of the data.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn credit_goes_out_ahead_of_the_data_queued_before_it() {
        use tokio::io::AsyncReadExt;

        use crate::tcp_gateway::{
            ReceiveWindow, TcpConnectionInner, TcpGatewayContract, FLOW_CONTROL_UPDATE_THRESHOLD,
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut peer = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        let (_read, write) = accepted.into_split();

        let aes = Arc::new(AesKey::new(&[7u8; 48]));
        let inner = TcpConnectionInner::new_gateway_peer(write.into(), aes.clone(), false);
        let window = ReceiveWindow::new(1, inner.clone());

        let data = |connection_id: u32, len: usize| {
            TcpGatewayContract::ForwardPayload {
                connection_id,
                payload: vec![0u8; len].into(),
            }
            .to_plain_frame()
        };

        // More than the socket buffers take: the writer blocks on it until the peer reads.
        inner.send_payload(data(2, 16 * 1024 * 1024));
        tokio::time::sleep(Duration::from_millis(300)).await;
        for _ in 0..3 {
            inner.send_payload(data(3, 1000));
        }
        assert!(window.received(FLOW_CONTROL_UPDATE_THRESHOLD));
        window.consumed(FLOW_CONTROL_UPDATE_THRESHOLD);

        let mut types = Vec::new();
        while types.len() < 5 {
            let mut len = [0u8; 4];
            peer.read_exact(&mut len).await.unwrap();
            let mut frame = vec![0u8; u32::from_le_bytes(len) as usize];
            peer.read_exact(&mut frame).await.unwrap();

            let decrypted = aes
                .decrypt(&encryption::AesEncryptedDataRef::new(&frame))
                .unwrap();
            types.push(decrypted.as_slice()[0]);
        }

        // The blocked frame, the credit, then the data queued before the credit.
        assert_eq!(types, vec![6, 15, 6, 6, 6]);
    }

    /// More credit than one batch carries, and frames queued after it - a CONNECT_OK behind an
    /// acceptor's credit: no frame goes out ahead of credit queued before it.
    #[test]
    fn a_frame_never_overtakes_credit_left_for_the_next_batch() {
        let mut credits: VecDeque<_> = (0..400).map(|_| frame(13, 0, true)).collect();
        let mut queue: VecDeque<_> = [frame(9, 0, false), frame(100, 7, false)].into();

        let (plaintext, budget) = take_batch(&mut credits, &mut queue);
        assert_eq!(plaintext.len(), 315 * 13, "credit alone");
        assert_eq!(budget, 0);
        assert_eq!(queue.len(), 2);

        let (plaintext, budget) = take_batch(&mut credits, &mut queue);
        assert_eq!(plaintext.len(), 85 * 13 + 9 + 100);
        assert_eq!(budget, 7);
        assert!(credits.is_empty() && queue.is_empty());
    }
}

use std::{collections::VecDeque, future::Future, pin::Pin, sync::Arc, time::Duration};

use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::metrics::PerSecondAccumulator;
use crate::network_stream::{MyOwnedWriteHalf, NetworkStreamWritePart};
use crate::tcp_gateway::{OutgoingFrame, MAX_FILE_RESPONSE_SIZE, MAX_PAYLOAD_SIZE};

use super::{BatchPacker, FrameSealer, BATCH_STORED, FRAME_LEN_SIZE, FRAME_TAG_LEN};

/// Inner frames one batch carries at most. Small enough that a frame stays far below the
/// receiver's frame limits, and that write budget comes back in steady steps on a slow link. One
/// frame of a full payload chunk and its header fits, with room for the small frames queued
/// behind it.
const MAX_WRITE_BATCH: usize = 256 * 1024 + 4 * 1024;

/// `WINDOW_UPDATE` bytes one write carries at most ahead of its data - 315 of them; the rest go
/// with the next write.
const MAX_CREDIT_PER_BATCH: usize = 4 * 1024;

/// An inner frame bigger than this begins a sealed frame of its own. A frame is handled only
/// once all of it is off the wire, so what is queued ahead of a big inner frame - credit, a pong,
/// the answer to a connect - goes in a frame of its own ahead of it, and does not wait for the
/// big one to arrive.
const BIG_INNER_FRAME: usize = 4 * 1024;

// The biggest frames a writer builds are within what a reader takes. A file response of the
// limit begins a frame, with nothing behind it: the header of its inner frame, the kind of the
// batch and the tag are all that is added.
const _: () = assert!(1 + 10 + MAX_FILE_RESPONSE_SIZE + FRAME_TAG_LEN <= MAX_PAYLOAD_SIZE);
// Credit and small frames: what one batch takes of each.
const _: () = assert!(
    1 + MAX_CREDIT_PER_BATCH + MAX_WRITE_BATCH + BIG_INNER_FRAME + FRAME_TAG_LEN
        <= MAX_PAYLOAD_SIZE
);

/// How long a closing writer may spend on shutting its socket down.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// A wire buffer bigger than this is not kept for the next batch: it carried a file response.
const WIRE_BUFFER_TO_KEEP: usize = 1024 * 1024;

type WriteFuture =
    Pin<Box<dyn Future<Output = (MyOwnedWriteHalf, Vec<u8>, Result<(), std::io::Error>)> + Send>>;

/// Writer task for a gateway TCP connection.
///
/// Producers push **plaintext** inner frames `[u32 LEN][u8 TYPE][PAYLOAD]`
/// into `rx`. The writer queues them while the previous `write_all` is still
/// in flight. On every flush boundary it takes up to [`MAX_WRITE_BATCH`] of
/// queued frames as a batch - packed by `packer` when compression is on and
/// packing makes it smaller - seals it as a frame and writes that.
/// What is queued ahead of a big inner frame is a batch of its own, and both
/// frames go in the same write: see [`BIG_INNER_FRAME`].
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
    mut sealer: FrameSealer,
    mut packer: BatchPacker,
    disconnected: CancellationToken,
    write_budget: Arc<Semaphore>,
    written_bytes: Arc<PerSecondAccumulator>,
) {
    let mut queue: VecDeque<OutgoingFrame> = VecDeque::new();
    let mut credits: VecDeque<OutgoingFrame> = VecDeque::new();
    let mut write_fut: Option<WriteFuture> = None;
    let mut in_flight_budget: usize = 0;
    let mut write_half_holder: Option<MyOwnedWriteHalf> = Some(write_half);

    // Both are kept from batch to batch: a batch costs no allocation of its size.
    let mut wire: Vec<u8> = Vec::new();
    let mut frames: Vec<u8> = Vec::new();

    loop {
        if write_fut.is_none() && !(queue.is_empty() && credits.is_empty()) {
            // What is in the channel already goes into the same batch: frames sent one right
            // after another - a `WINDOW_UPDATE` and the `CONNECT_OK` behind it - are one write.
            while let Ok(frame) = rx.try_recv() {
                enqueue(&mut credits, &mut queue, frame);
            }

            let mut frame = std::mem::take(&mut wire);
            in_flight_budget = match build_write(
                &mut credits,
                &mut queue,
                &mut frames,
                &mut packer,
                &mut sealer,
                &mut frame,
            ) {
                Ok(budget) => budget,
                Err(err) => {
                    eprintln!("gateway_write_loop: {err}");
                    break;
                }
            };

            let mut owned_write_half = write_half_holder.take().expect("write_half was borrowed");
            write_fut = Some(Box::pin(async move {
                let res = owned_write_half.write_to_socket(&frame).await;
                (owned_write_half, frame, res)
            }));
        }

        tokio::select! {
            _ = disconnected.cancelled() => break,

            msg = rx.recv() => {
                match msg {
                    Some(frame) => enqueue(&mut credits, &mut queue, frame),
                    None => break,
                }
            }

            res = async { write_fut.as_mut().unwrap().as_mut().await }, if write_fut.is_some() => {
                let (returned_half, written, io_res) = res;
                write_half_holder = Some(returned_half);
                write_fut = None;
                write_budget.add_permits(std::mem::take(&mut in_flight_budget));
                if let Err(err) = io_res {
                    eprintln!("gateway_write_loop: write failure: {:?}", err);
                    break;
                }

                // What went to the socket: sealed, and packed if it is.
                written_bytes.add(written.len());

                if written.capacity() <= WIRE_BUFFER_TO_KEEP {
                    wire = written;
                }
                if frames.capacity() > WIRE_BUFFER_TO_KEEP {
                    frames = Vec::new();
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

fn enqueue(
    credits: &mut VecDeque<OutgoingFrame>,
    queue: &mut VecDeque<OutgoingFrame>,
    frame: OutgoingFrame,
) {
    if frame.expedite {
        credits.push_back(frame);
    } else {
        queue.push_back(frame);
    }
}

/// Takes what the next write carries off the queues and puts it into `wire`, sealed: one frame,
/// or two when something is queued ahead of a big inner frame - see [`BIG_INNER_FRAME`].
/// `frames` is where a batch is put together to be packed; a batch which is not packed is put
/// together in `wire` itself. Returns the write budget the inner frames hold.
fn build_write(
    credits: &mut VecDeque<OutgoingFrame>,
    queue: &mut VecDeque<OutgoingFrame>,
    frames: &mut Vec<u8>,
    packer: &mut BatchPacker,
    sealer: &mut FrameSealer,
    wire: &mut Vec<u8>,
) -> Result<usize, String> {
    wire.clear();

    let mut budget = seal_batch(wire, frames, packer, sealer, |out| {
        take_small_frames(credits, queue, out)
    })?;

    // A write which leaves credit behind takes nothing else: no frame overtakes credit queued
    // before it. Small frames left behind did not fit, and wait for the next write as well.
    let big_frame_is_next = queue
        .front()
        .is_some_and(|frame| frame.payload.len() > BIG_INNER_FRAME);

    if credits.is_empty() && big_frame_is_next {
        budget += seal_batch(wire, frames, packer, sealer, |out| {
            take_from_a_big_frame(queue, out)
        })?;
    }

    Ok(budget)
}

/// Appends to `wire` the sealed frame of the batch `take` puts together - nothing, when it takes
/// nothing. Returns what `take` does: the write budget of the inner frames it took.
fn seal_batch(
    wire: &mut Vec<u8>,
    frames: &mut Vec<u8>,
    packer: &mut BatchPacker,
    sealer: &mut FrameSealer,
    take: impl FnOnce(&mut Vec<u8>) -> usize,
) -> Result<usize, String> {
    let frame_at = wire.len();
    wire.extend_from_slice(&[0u8; FRAME_LEN_SIZE]);

    let budget = if packer.is_on() {
        frames.clear();
        let budget = take(frames);

        if frames.is_empty() {
            wire.truncate(frame_at);
            return Ok(budget);
        }

        if frames.len() > MAX_WRITE_BATCH {
            pack_apart(|| packer.write_batch(frames, wire));
        } else {
            packer.write_batch(frames, wire);
        }

        budget
    } else {
        wire.push(BATCH_STORED);
        let batch_at = wire.len();
        let budget = take(wire);

        if wire.len() == batch_at {
            wire.truncate(frame_at);
            return Ok(budget);
        }

        budget
    };

    sealer.seal_last(wire, frame_at)?;

    Ok(budget)
}

/// Runs `pack` for a batch bigger than a writer puts together itself - a file response:
/// megabytes, which take a strong level tens of milliseconds. Where the runtime has other
/// threads, the tasks which wait for this one are handed over to them for that long.
fn pack_apart(pack: impl FnOnce()) {
    use tokio::runtime::{Handle, RuntimeFlavor};

    match Handle::try_current() {
        Ok(runtime) if runtime.runtime_flavor() == RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(pack)
        }
        _ => pack(),
    }
}

/// Appends to `out` the queued `WINDOW_UPDATE`s - up to [`MAX_CREDIT_PER_BATCH`] of them - and
/// then the frames off the front of `queue` up to the first big one, while their bytes stay
/// within [`MAX_WRITE_BATCH`]. With credit left behind it takes no frames off `queue`: those may
/// have been queued after the credit left behind. Returns the write budget the frames hold.
fn take_small_frames(
    credits: &mut VecDeque<OutgoingFrame>,
    queue: &mut VecDeque<OutgoingFrame>,
    out: &mut Vec<u8>,
) -> usize {
    let batch_at = out.len();

    while let Some(credit) = credits.front() {
        let credit_len = out.len() - batch_at;
        if credit_len > 0 && credit_len + credit.payload.len() > MAX_CREDIT_PER_BATCH {
            break;
        }

        out.extend_from_slice(&credits.pop_front().unwrap().payload);
    }

    let data_at = out.len();
    let mut budget = 0usize;

    if !credits.is_empty() {
        return budget;
    }

    while let Some(frame) = queue.front() {
        if frame.payload.len() > BIG_INNER_FRAME
            || out.len() - data_at + frame.payload.len() > MAX_WRITE_BATCH
        {
            break;
        }

        let frame = queue.pop_front().unwrap();
        out.extend_from_slice(&frame.payload);
        budget += frame.budget as usize;
    }

    budget
}

/// Appends to `out` the frame at the front of `queue` - a big one - and then more frames, of any
/// size, while their bytes stay within [`MAX_WRITE_BATCH`]: what is behind a big frame arrives
/// behind it anyway. Returns the write budget the frames hold.
fn take_from_a_big_frame(queue: &mut VecDeque<OutgoingFrame>, out: &mut Vec<u8>) -> usize {
    let data_at = out.len();
    let mut budget = 0usize;

    while let Some(frame) = queue.front() {
        let data_len = out.len() - data_at;
        if data_len > 0 && data_len + frame.payload.len() > MAX_WRITE_BATCH {
            break;
        }

        let frame = queue.pop_front().unwrap();
        out.extend_from_slice(&frame.payload);
        budget += frame.budget as usize;
    }

    budget
}

/// Reads one frame off `peer` the way a gateway peer does - opens it, unpacks its batch - and
/// returns the inner frames it carried, each as `[u8 TYPE][PAYLOAD]`.
#[cfg(test)]
pub(crate) async fn read_frame_for_tests(
    peer: &mut tokio::net::TcpStream,
    opener: &mut super::FrameOpener,
) -> Vec<Vec<u8>> {
    use tokio::io::AsyncReadExt;

    let mut len = [0u8; FRAME_LEN_SIZE];
    peer.read_exact(&mut len).await.unwrap();
    let mut frame = vec![0u8; u32::from_le_bytes(len) as usize];
    peer.read_exact(&mut frame).await.unwrap();

    let plain_len = opener.open(&mut frame).unwrap();

    let mut unpacker = super::BatchUnpacker::new();
    let mut batch = unpacker.read_batch(&frame[..plain_len]).unwrap();

    let mut inner_frames = Vec::new();
    while !batch.is_empty() {
        let (len, rest) = batch.split_first_chunk::<4>().unwrap();
        let (inner_frame, rest) = rest.split_at(u32::from_le_bytes(*len) as usize);
        inner_frames.push(inner_frame.to_vec());
        batch = rest;
    }

    inner_frames
}

#[cfg(test)]
mod tests {
    use super::super::{
        BatchUnpacker, CompressionLevel, FrameOpener, BATCH_LZ4, BATCH_ZSTD, BATCH_ZSTD_STREAM,
        FRAME_TAG_LEN,
    };
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];

    const OFF: CompressionLevel = CompressionLevel::OFF;

    fn level(level: u8) -> CompressionLevel {
        CompressionLevel::new(level).unwrap()
    }

    fn frame(len: usize, budget: u32, expedite: bool) -> OutgoingFrame {
        OutgoingFrame {
            payload: vec![0; len],
            budget,
            expedite,
        }
    }

    /// What one write carries: the size of the inner frames of each sealed frame, the kind of
    /// each batch, and the write budget they hold.
    struct Write {
        batches: Vec<usize>,
        kinds: Vec<u8>,
        budget: usize,
        wire_len: usize,
        /// What every sealed frame says its length is.
        frame_lens: Vec<usize>,
    }

    fn build(
        credits: &mut VecDeque<OutgoingFrame>,
        queue: &mut VecDeque<OutgoingFrame>,
        level: CompressionLevel,
    ) -> Write {
        let mut sealer = FrameSealer::for_tests(KEY);
        let mut opener = FrameOpener::for_tests(KEY);

        let mut wire = Vec::new();
        let budget = build_write(
            credits,
            queue,
            &mut Vec::new(),
            &mut BatchPacker::new(level),
            &mut sealer,
            &mut wire,
        )
        .unwrap();

        // One unpacker for the write, as a connection has one: at a level of one stream the
        // batch of the second frame is read with what the first one left.
        let mut unpacker = BatchUnpacker::new();

        let mut batches = Vec::new();
        let mut kinds = Vec::new();
        let mut frame_lens = Vec::new();
        let mut rest = wire.as_slice();
        while !rest.is_empty() {
            let (len, behind) = rest.split_first_chunk::<FRAME_LEN_SIZE>().unwrap();
            let (sealed, behind) = behind.split_at(u32::from_le_bytes(*len) as usize);
            rest = behind;
            frame_lens.push(sealed.len());

            let mut sealed = sealed.to_vec();
            let batch_len = opener.open(&mut sealed).unwrap();
            kinds.push(sealed[0]);
            batches.push(unpacker.read_batch(&sealed[..batch_len]).unwrap().len());
        }

        Write {
            batches,
            kinds,
            budget,
            wire_len: wire.len(),
            frame_lens,
        }
    }

    #[test]
    fn credit_goes_first_in_a_frame_of_its_own_and_never_puts_a_big_frame_off() {
        let mut credits: VecDeque<_> = (0..3).map(|_| frame(13, 0, true)).collect();
        let mut queue: VecDeque<_> =
            [frame(MAX_WRITE_BATCH + 9, 100, false), frame(100, 7, false)].into();

        let write = build(&mut credits, &mut queue, OFF);
        assert_eq!(write.batches, vec![3 * 13, MAX_WRITE_BATCH + 9]);
        assert_eq!(write.budget, 100);
        assert!(credits.is_empty());
        assert_eq!(queue.len(), 1, "the small frame waits for the next write");

        let mut credits: VecDeque<_> = (0..400).map(|_| frame(13, 0, true)).collect();
        let mut queue = VecDeque::new();

        let write = build(&mut credits, &mut queue, OFF);
        assert_eq!(write.batches, vec![315 * 13]);
        assert_eq!(write.budget, 0);
        assert_eq!(credits.len(), 85, "the rest go with the next write");
    }

    /// What is queued ahead of a big inner frame is a frame of its own - the peer handles it
    /// once it is there, not once the big one behind it is - and what is queued behind the big
    /// one shares its frame.
    #[test]
    fn small_frames_ahead_of_a_big_one_do_not_wait_for_it() {
        use crate::tcp_gateway::MAX_PAYLOAD_CHUNK;

        let chunk = MAX_PAYLOAD_CHUNK + 9;

        let mut credits: VecDeque<_> = [frame(13, 0, true)].into();
        let mut queue: VecDeque<_> = [
            frame(9, 3, false),
            frame(chunk, 100, false),
            frame(100, 7, false),
            frame(chunk, 100, false),
        ]
        .into();

        // The budget of the write is the budget of both its frames: what the first one holds
        // comes back with the write as well.
        let write = build(&mut credits, &mut queue, OFF);
        assert_eq!(write.batches, vec![13 + 9, chunk + 100]);
        assert_eq!(write.budget, 3 + 100 + 7);
        assert_eq!(queue.len(), 1, "the next chunk is a write of its own");

        let write = build(&mut credits, &mut queue, OFF);
        assert_eq!(write.batches, vec![chunk]);
        assert_eq!(write.budget, 100);
        assert!(queue.is_empty());

        // Small frames alone are one frame, whatever their number - up to the limit of a batch.
        let mut queue: VecDeque<_> = (0..100).map(|_| frame(BIG_INNER_FRAME, 1, false)).collect();
        let write = build(&mut credits, &mut queue, OFF);
        assert_eq!(
            write.batches,
            vec![(MAX_WRITE_BATCH / BIG_INNER_FRAME) * BIG_INNER_FRAME]
        );
        assert_eq!(queue.len(), 100 - MAX_WRITE_BATCH / BIG_INNER_FRAME);

        // And frames just over the mark go on sharing a frame with one another.
        let mut queue: VecDeque<_> = (0..3)
            .map(|_| frame(BIG_INNER_FRAME + 1, 1, false))
            .collect();
        let write = build(&mut credits, &mut queue, OFF);
        assert_eq!(write.batches, vec![3 * (BIG_INNER_FRAME + 1)]);
    }

    /// The frame which carries a batch: as it is with compression off, packed with what the
    /// level says with it on - and with it on, as it is all the same when there is nothing to
    /// save.
    #[test]
    fn a_batch_is_packed_only_when_that_makes_it_smaller() {
        let text = b"{\"symbol\":\"EURUSD\",\"bid\":1.08412,\"ask\":1.08419},".repeat(100);
        let noise: Vec<u8> = {
            let mut state = 0x9E37_79B9_7F4A_7C15u64;
            (0..5000)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    (state >> 24) as u8
                })
                .collect()
        };

        for (payload, level, kind) in [
            (text.clone(), OFF, BATCH_STORED),
            (text.clone(), level(1), BATCH_LZ4),
            (text.clone(), level(2), BATCH_ZSTD),
            (text.clone(), level(5), BATCH_ZSTD),
            (noise.clone(), level(1), BATCH_STORED),
            (noise.clone(), level(2), BATCH_STORED),
            // One stream: a batch is a piece of it whether it packs or not.
            (text.clone(), level(6), BATCH_ZSTD_STREAM),
            (
                text.clone(),
                level(CompressionLevel::MAX),
                BATCH_ZSTD_STREAM,
            ),
            (noise, level(6), BATCH_ZSTD_STREAM),
        ] {
            let mut credits = VecDeque::new();
            let mut queue: VecDeque<_> = [OutgoingFrame {
                payload: payload.clone(),
                budget: 5,
                expedite: false,
            }]
            .into();

            let write = build(&mut credits, &mut queue, level);

            assert_eq!(write.budget, 5);
            assert_eq!(write.kinds, vec![kind]);
            assert_eq!(write.batches, vec![payload.len()]);
            // Never bigger than its inner frames, the kind of the batch and the tag - and, for
            // a piece of a stream, its size and the heads of the stream and of a block.
            let head = if kind == BATCH_ZSTD_STREAM { 32 } else { 1 };
            assert!(write.wire_len <= FRAME_LEN_SIZE + head + payload.len() + FRAME_TAG_LEN);
        }
    }

    /// The biggest frames a writer builds - a file response of the limit behind as much credit
    /// as a write carries - are frames a reader takes.
    #[test]
    fn the_biggest_write_is_made_of_frames_within_the_limit() {
        for level in CompressionLevel::all() {
            let mut credits: VecDeque<_> = (0..400).map(|_| frame(13, 0, true)).collect();
            let mut queue: VecDeque<_> = [OutgoingFrame {
                // Noise: packing does not make it smaller.
                payload: {
                    let mut state = 0x9E37_79B9_7F4A_7C15u64;
                    (0..10 + MAX_FILE_RESPONSE_SIZE)
                        .map(|_| {
                            state ^= state << 13;
                            state ^= state >> 7;
                            state ^= state << 17;
                            (state >> 24) as u8
                        })
                        .collect()
                },
                budget: 1,
                expedite: false,
            }]
            .into();

            // Credit is left behind: the file response waits for the next write.
            let write = build(&mut credits, &mut queue, level);
            assert_eq!(write.batches, vec![315 * 13]);
            assert_eq!(queue.len(), 1);

            let write = build(&mut credits, &mut queue, level);
            assert_eq!(write.batches, vec![85 * 13, 10 + MAX_FILE_RESPONSE_SIZE]);

            // The file response is alone in its frame: its inner frame, the kind of the
            // batch and the tag - and that is a frame a reader takes. The credit ahead of it
            // is a frame of its own, packed or not.
            assert_eq!(write.frame_lens.len(), 2);
            assert!(write.frame_lens[0] <= 1 + 85 * 13 + FRAME_TAG_LEN);

            let as_it_is = 1 + 10 + MAX_FILE_RESPONSE_SIZE + FRAME_TAG_LEN;

            if matches!(
                level.packing(),
                Some(super::super::Packing::ZstdStream { .. })
            ) {
                // A piece of the stream all the same: what does not pack costs the size of
                // the piece and the head of every block of it - 3 bytes for 128 KiB.
                assert!(write.frame_lens[1] > as_it_is);
                assert!(write.frame_lens[1] <= as_it_is + 256, "level {level}");
            } else {
                assert_eq!(write.frame_lens[1], as_it_is);
            }

            assert!(write.frame_lens.iter().all(|len| *len <= MAX_PAYLOAD_SIZE));
        }
    }

    /// Frames sent one right after another - what an acceptor sends once it is connected - go to
    /// the socket as one frame.
    #[tokio::test]
    async fn frames_queued_together_go_out_as_one_frame() {
        use crate::tcp_gateway::{TcpConnectionInner, TcpGatewayContract, FLOW_CONTROL_WINDOW};

        for level in CompressionLevel::all() {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut peer = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (accepted, _) = listener.accept().await.unwrap();
            let (_read, write) = accepted.into_split();

            let mut opener = FrameOpener::for_tests(KEY);
            let inner = TcpConnectionInner::new_gateway_peer(
                write.into(),
                FrameSealer::for_tests(KEY),
                level,
                Default::default(),
            );

            // On the one thread of this test the writer does not run until the test waits: all
            // three are in its channel by then.
            inner.send_payload(
                TcpGatewayContract::WindowUpdate {
                    connection_id: 1,
                    credit: FLOW_CONTROL_WINDOW as u32,
                }
                .to_plain_frame(),
            );
            inner.send_payload(TcpGatewayContract::Connected { connection_id: 1 }.to_plain_frame());
            inner.send_payload(TcpGatewayContract::Pong.to_plain_frame());

            let mut types = Vec::new();
            let mut frames = 0;
            while types.len() < 3 {
                for inner_frame in read_frame_for_tests(&mut peer, &mut opener).await {
                    types.push(inner_frame[0]);
                }
                frames += 1;
            }

            assert_eq!(types, vec![15, 4, 1]);
            assert_eq!(frames, 1);
        }
    }

    /// A batch bigger than a writer puts together itself - a file response - is packed on a
    /// runtime of one thread and on one of many, at the strongest level there is.
    #[test]
    fn a_batch_of_megabytes_is_packed_whatever_the_runtime() {
        use crate::tcp_gateway::{TcpConnectionInner, TcpGatewayContract};

        let one_thread = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let many_threads = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();

        let text = b"{\"symbol\":\"EURUSD\",\"bid\":1.08412,\"ask\":1.08419},".repeat(40_000);
        assert!(text.len() > MAX_WRITE_BATCH);

        for runtime in [one_thread, many_threads] {
            runtime.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let mut peer = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                    .await
                    .unwrap();
                let (accepted, _) = listener.accept().await.unwrap();
                let (_read, write) = accepted.into_split();

                let written = Arc::new(PerSecondAccumulator::new());
                let mut opener = FrameOpener::for_tests(KEY);
                let inner = TcpConnectionInner::new_gateway_peer(
                    write.into(),
                    FrameSealer::for_tests(KEY),
                    level(CompressionLevel::MAX),
                    written.clone(),
                );

                inner.send_payload(
                    TcpGatewayContract::ForwardPayload {
                        connection_id: 1,
                        payload: text.as_slice().into(),
                    }
                    .to_plain_frame(),
                );

                let inner_frames = read_frame_for_tests(&mut peer, &mut opener).await;
                assert_eq!(inner_frames.len(), 1);
                assert!(inner_frames[0].ends_with(&text));

                // Packed: a small part of it went to the socket.
                let mut on_the_wire = 0;
                for _ in 0..200 {
                    on_the_wire += written.get_per_second();
                    if on_the_wire > 0 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                assert!(
                    on_the_wire > 0 && on_the_wire < text.len() / 10,
                    "{on_the_wire} bytes"
                );
            });
        }
    }

    /// What went to the socket is what is counted as sent: the frames as they are on the wire.
    #[tokio::test]
    async fn what_is_written_is_counted_as_it_is_on_the_wire() {
        use tokio::io::AsyncReadExt;

        use crate::tcp_gateway::{TcpConnectionInner, TcpGatewayContract};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut peer = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        let (_read, write) = accepted.into_split();

        let written = Arc::new(PerSecondAccumulator::new());
        let inner = TcpConnectionInner::new_gateway_peer(
            write.into(),
            FrameSealer::for_tests(KEY),
            level(1),
            written.clone(),
        );

        let text = b"0123456789".repeat(1000);
        inner.send_payload(
            TcpGatewayContract::ForwardPayload {
                connection_id: 1,
                payload: text.as_slice().into(),
            }
            .to_plain_frame(),
        );

        let mut len = [0u8; FRAME_LEN_SIZE];
        peer.read_exact(&mut len).await.unwrap();
        let mut sealed = vec![0u8; u32::from_le_bytes(len) as usize];
        peer.read_exact(&mut sealed).await.unwrap();

        // The writer counts a write once it is done, which is right behind the peer's read.
        let on_the_wire = FRAME_LEN_SIZE + sealed.len();
        let mut counted = 0;
        for _ in 0..200 {
            counted += written.get_per_second();
            if counted >= on_the_wire {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        assert_eq!(counted, on_the_wire);
        assert!(on_the_wire < text.len() / 10, "packed: {on_the_wire} bytes");
    }

    /// A connection's credit does not wait behind data queued before it: with the writer blocked
    /// on a write the peer does not take, it goes out with the very next write, ahead of the data.
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

        let mut opener = FrameOpener::for_tests(KEY);
        let inner = TcpConnectionInner::new_gateway_peer(
            write.into(),
            FrameSealer::for_tests(KEY),
            OFF,
            Default::default(),
        );
        let window = ReceiveWindow::new(1, inner.clone());

        let data = |connection_id: u32, len: usize| {
            TcpGatewayContract::ForwardPayload {
                connection_id,
                payload: vec![0u8; len].into(),
            }
            .to_plain_frame()
        };

        // More than the socket buffers take: the writer blocks on it until the peer reads.
        const BLOCKING: usize = 16 * 1024 * 1024;
        inner.send_payload(data(2, BLOCKING));

        // Its length is on the wire only once the writer is in that write - and the rest is
        // queued behind a writer which is blocked, whatever the machine is busy with.
        let mut len = [0u8; FRAME_LEN_SIZE];
        peer.read_exact(&mut len).await.unwrap();
        let blocking_frame_len = u32::from_le_bytes(len) as usize;
        assert!(blocking_frame_len > BLOCKING);

        for _ in 0..3 {
            inner.send_payload(data(3, 1000));
        }
        assert!(window.received(FLOW_CONTROL_UPDATE_THRESHOLD));
        window.consumed(FLOW_CONTROL_UPDATE_THRESHOLD);

        let mut sealed = vec![0u8; blocking_frame_len];
        peer.read_exact(&mut sealed).await.unwrap();
        let batch_len = opener.open(&mut sealed).unwrap();
        let mut types = vec![sealed[..batch_len][1 + FRAME_LEN_SIZE]];

        while types.len() < 5 {
            for inner_frame in read_frame_for_tests(&mut peer, &mut opener).await {
                types.push(inner_frame[0]);
            }
        }

        // The blocked frame, the credit, then the data queued before the credit.
        assert_eq!(types, vec![6, 15, 6, 6, 6]);
    }

    /// More credit than one write carries, and frames queued after it - a CONNECT_OK behind an
    /// acceptor's credit: no frame goes out ahead of credit queued before it.
    #[test]
    fn a_frame_never_overtakes_credit_left_for_the_next_write() {
        let mut credits: VecDeque<_> = (0..400).map(|_| frame(13, 0, true)).collect();
        let mut queue: VecDeque<_> = [frame(9, 0, false), frame(100, 7, false)].into();

        let write = build(&mut credits, &mut queue, OFF);
        assert_eq!(write.batches, vec![315 * 13], "credit alone");
        assert_eq!(write.budget, 0);
        assert_eq!(queue.len(), 2);

        let write = build(&mut credits, &mut queue, OFF);
        assert_eq!(write.batches, vec![85 * 13 + 9 + 100]);
        assert_eq!(write.budget, 7);
        assert!(credits.is_empty() && queue.is_empty());

        // Neither does a big one: it waits for the write behind the last of the credit.
        let mut credits: VecDeque<_> = (0..400).map(|_| frame(13, 0, true)).collect();
        let mut queue: VecDeque<_> = [frame(BIG_INNER_FRAME + 1, 7, false)].into();

        let write = build(&mut credits, &mut queue, OFF);
        assert_eq!(write.batches, vec![315 * 13]);
        assert_eq!(queue.len(), 1);

        let write = build(&mut credits, &mut queue, OFF);
        assert_eq!(write.batches, vec![85 * 13, BIG_INNER_FRAME + 1]);
        assert_eq!(write.budget, 7);
    }
}

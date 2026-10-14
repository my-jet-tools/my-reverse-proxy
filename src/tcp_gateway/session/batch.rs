//! A batch is what one frame carries: inner frames `[u32 LEN][u8 TYPE][PAYLOAD]` one after
//! another, as they are or packed. See "Batches" in docs/gateway-protocol.md.

use crate::tcp_gateway::MAX_DECOMPRESSED_BATCH_SIZE;

use super::{CompressionLevel, Packing};

/// The inner frames follow as they are.
pub const BATCH_STORED: u8 = 0;

/// `[u32 RAW_LEN][LZ4 block]`: the inner frames, `RAW_LEN` bytes of them, packed.
pub const BATCH_LZ4: u8 = 1;

/// `[u32 RAW_LEN][Zstandard frame]`: the inner frames, `RAW_LEN` bytes of them, packed.
pub const BATCH_ZSTD: u8 = 2;

/// `[u32 RAW_LEN][a piece of the Zstandard stream of this direction]`: the inner frames,
/// `RAW_LEN` bytes of them, packed with every batch of this kind sent before them for a
/// history. The piece ends where the stream was flushed: it unpacks to the whole batch, and to
/// nothing but it. It can be unpacked only after the pieces before it, in their order - which
/// is the order of the frames, and a frame out of its order does not open.
pub const BATCH_ZSTD_STREAM: u8 = 3;

/// The window of the stream is at most 2 to this power: 4 MiB, what the Zstandard levels of
/// the table ask for at the most. The unpacking end takes no stream which asks for more - a
/// stream says the size of its window itself, and the memory for it is taken by the one who
/// reads it.
const STREAM_WINDOW_LOG_MAX: u32 = 22;

/// What the end of a piece - a flush of the stream - may add to the bound of a packed batch.
const STREAM_FLUSH_MARGIN: usize = 64;

/// A batch under this size does not go into the stream: a ping, a window update. A piece costs
/// 8 bytes before its first packed one - the kind, the size, the head of a block - and such a
/// batch has less than that to save, and nothing the batches after it would be packed with.
const MIN_SIZE_TO_PACK_STREAM: usize = 32;

/// Under this size a batch is not worth packing: LZ4 finds nothing to save in so few bytes.
const MIN_SIZE_TO_PACK_LZ4: usize = 64;

/// The same for Zstandard, whose frame costs more bytes to begin with - and an attempt on a
/// batch this small takes it ten times as long as LZ4.
const MIN_SIZE_TO_PACK_ZSTD: usize = 128;

/// An unpack buffer bigger than this is not kept for the next batch: a batch that big is a
/// file response, and the batches around it are a small part of it.
const UNPACK_BUFFER_TO_KEEP: usize = 1024 * 1024;

/// Packs the batches one end of a gateway connection sends, with what its compression level
/// says.
pub struct BatchPacker {
    packing: Option<Packing>,
    /// Made for the first batch Zstandard packs and kept for the rest: making one costs more
    /// than packing a small batch.
    zstd: Option<zstd::bulk::Compressor<'static>>,
    /// The stream of a `ZstdStream` level: one for the life of the connection.
    stream: Option<zstd::stream::raw::Encoder<'static>>,
    /// The stream could not take a batch and is left where it was: what it holds now is not
    /// what the other end has. Every batch from then on goes as it is - such a batch is no
    /// part of the stream, so the other end reads it whatever state the stream is in.
    stream_is_broken: bool,
}

impl BatchPacker {
    pub fn new(level: CompressionLevel) -> Self {
        Self {
            packing: level.packing(),
            zstd: None,
            stream: None,
            stream_is_broken: false,
        }
    }

    /// Compression is on: a batch may go out packed.
    pub fn is_on(&self) -> bool {
        self.packing.is_some()
    }

    /// Appends the batch of `frames` to `wire`. Packed when compression is on and packing makes
    /// it smaller; otherwise as it is - a batch never goes out bigger than its frames and a byte.
    pub fn write_batch(&mut self, frames: &[u8], wire: &mut Vec<u8>) {
        if self.write_packed(frames, wire) {
            return;
        }

        wire.push(BATCH_STORED);
        wire.extend_from_slice(frames);
    }

    /// `false`: nothing packs it, or packing saves nothing - `wire` is left as it was.
    fn write_packed(&mut self, frames: &[u8], wire: &mut Vec<u8>) -> bool {
        let Some(packing) = self.packing else {
            return false;
        };

        let Ok(raw_len) = u32::try_from(frames.len()) else {
            return false;
        };

        if let Packing::ZstdStream { level } = packing {
            return self.write_to_stream(level, frames, raw_len, wire);
        }

        let (kind, min_size, bound) = match packing {
            Packing::Lz4 { .. } => {
                let Ok(bound) = lz4::block::compress_bound(frames.len()) else {
                    return false;
                };
                (BATCH_LZ4, MIN_SIZE_TO_PACK_LZ4, bound)
            }
            Packing::Zstd { .. } => (
                BATCH_ZSTD,
                MIN_SIZE_TO_PACK_ZSTD,
                zstd::zstd_safe::compress_bound(frames.len()),
            ),
            Packing::ZstdStream { .. } => return false,
        };

        if frames.len() < min_size {
            return false;
        }

        let batch_at = wire.len();

        wire.push(kind);
        wire.extend_from_slice(&raw_len.to_le_bytes());

        let packed_at = wire.len();
        wire.resize(packed_at + bound, 0);

        let packed = &mut wire[packed_at..];

        let packed_len = match packing {
            Packing::Lz4 { acceleration } => {
                let mode = lz4::block::CompressionMode::FAST(acceleration);
                lz4::block::compress_to_buffer(frames, Some(mode), false, packed).ok()
            }
            Packing::Zstd { level } => self
                .zstd_compressor(level)
                .and_then(|zstd| zstd.compress_to_buffer(frames, packed).ok()),
            Packing::ZstdStream { .. } => None,
        };

        match packed_len {
            // Smaller together with the size it has to carry.
            Some(packed_len) if packed_len + 4 < frames.len() => {
                wire.truncate(packed_at + packed_len);
                true
            }
            _ => {
                wire.truncate(batch_at);
                false
            }
        }
    }

    /// Packs `frames` as the next piece of the stream. A batch goes this way whether it packs
    /// or not: it is what the next ones are packed with, and what does not pack Zstandard puts
    /// into the stream as it is, at a few bytes for it. So a piece can be bigger than its
    /// frames - by its 5 bytes and 3 more for every 128 KiB.
    ///
    /// `false`: the batch is too small to be a piece, or the stream is broken, now or before -
    /// `wire` is left as it was, and the batch goes as it is. That is no part of the stream:
    /// the other end reads it and leaves its stream where it is.
    fn write_to_stream(
        &mut self,
        level: i32,
        frames: &[u8],
        raw_len: u32,
        wire: &mut Vec<u8>,
    ) -> bool {
        use zstd::stream::raw::{InBuffer, Operation, OutBuffer};

        if self.stream_is_broken || frames.len() < MIN_SIZE_TO_PACK_STREAM {
            return false;
        }

        let stream = match &mut self.stream {
            Some(stream) => stream,
            None => match zstd::stream::raw::Encoder::new(level) {
                Ok(stream) => self.stream.insert(stream),
                // No memory for a stream: nothing was sent of it, and nothing will be.
                Err(_) => {
                    self.stream_is_broken = true;
                    return false;
                }
            },
        };

        let batch_at = wire.len();

        wire.push(BATCH_ZSTD_STREAM);
        wire.extend_from_slice(&raw_len.to_le_bytes());

        let packed_at = wire.len();
        let bound = zstd::zstd_safe::compress_bound(frames.len()) + STREAM_FLUSH_MARGIN;
        wire.resize(packed_at + bound, 0);

        let packed_len = {
            let mut input = InBuffer::around(frames);
            let mut output = OutBuffer::around(&mut wire[packed_at..]);

            let mut packed = || -> std::io::Result<Option<usize>> {
                while input.pos() < frames.len() {
                    stream.run(&mut input, &mut output)?;

                    // The room is the bound of a whole batch: it does not run out before the
                    // batch does.
                    if output.pos() == bound && input.pos() < frames.len() {
                        return Ok(None);
                    }
                }

                // The end of the piece: all of the batch is in `wire`, and can be unpacked.
                if stream.flush(&mut output)? > 0 {
                    return Ok(None);
                }

                Ok(Some(output.pos()))
            };

            packed().ok().flatten()
        };

        match packed_len {
            Some(packed_len) => {
                wire.truncate(packed_at + packed_len);
                true
            }
            // A part of the batch is in the stream and is not in `wire`: the stream is not
            // what the other end has any more.
            None => {
                self.stream_is_broken = true;
                self.stream = None;
                wire.truncate(batch_at);
                false
            }
        }
    }

    /// The Zstandard compressor of this packer. `None`: there is no memory for one, and the
    /// batch goes as it is.
    fn zstd_compressor(&mut self, level: i32) -> Option<&mut zstd::bulk::Compressor<'static>> {
        if self.zstd.is_none() {
            let mut zstd = zstd::bulk::Compressor::new(level).ok()?;

            // A batch carries its size itself: the frame need not say it again in every batch.
            zstd.set_parameter(zstd::zstd_safe::CParameter::ContentSizeFlag(false))
                .ok()?;

            self.zstd = Some(zstd);
        }

        self.zstd.as_mut()
    }
}

/// Unpacks the batches a peer sends. A batch says itself what it is packed with, so this takes
/// any kind there is, whatever the compression level of the gateway connection.
#[derive(Default)]
pub struct BatchUnpacker {
    /// Where a packed batch is unpacked; kept from batch to batch.
    unpacked: Vec<u8>,
    /// Made for the first batch packed with Zstandard, and kept for the rest.
    zstd: Option<zstd::bulk::Decompressor<'static>>,
    /// The stream the pieces of the peer are a stream of: made for the first of them, and one
    /// for the life of the connection.
    stream: Option<zstd::stream::raw::Decoder<'static>>,
}

impl BatchUnpacker {
    pub fn new() -> Self {
        Self::default()
    }

    /// The inner frames of `batch`: a part of it, or unpacked into the buffer kept here.
    ///
    /// A packed batch says how big it is unpacked, and one which says more than
    /// [`MAX_DECOMPRESSED_BATCH_SIZE`] is refused before any memory is taken for it. What it
    /// unpacks to is never more than it says: both algorithms stop at the end of the buffer.
    pub fn read_batch<'s>(&'s mut self, batch: &'s [u8]) -> Result<&'s [u8], String> {
        let Some((&kind, body)) = batch.split_first() else {
            return Err("Batch: empty frame".to_string());
        };

        if kind == BATCH_STORED {
            return Ok(body);
        }

        if kind != BATCH_LZ4 && kind != BATCH_ZSTD && kind != BATCH_ZSTD_STREAM {
            return Err(format!("Batch: unknown kind {kind}"));
        }

        let Some((raw_len, packed)) = body.split_first_chunk::<4>() else {
            return Err("Batch: a packed batch without its size".to_string());
        };

        let raw_len = u32::from_le_bytes(*raw_len) as usize;

        if raw_len == 0 || raw_len > MAX_DECOMPRESSED_BATCH_SIZE {
            return Err(format!(
                "Batch: unpacked size {raw_len} is out of range, the limit is {MAX_DECOMPRESSED_BATCH_SIZE}"
            ));
        }

        // Never shrunk here, and so not cleared before every batch either.
        if self.unpacked.len() < raw_len {
            self.unpacked.resize(raw_len, 0);
        }

        let unpacked = &mut self.unpacked[..raw_len];

        let unpacked_len = if kind == BATCH_LZ4 {
            lz4::block::decompress_to_buffer(packed, Some(raw_len as i32), unpacked)
                .map_err(|err| format!("Batch: lz4 can not unpack it: {err}"))?
        } else if kind == BATCH_ZSTD_STREAM {
            let stream = match &mut self.stream {
                Some(stream) => stream,
                None => self.stream.insert(new_stream_decoder()?),
            };

            read_from_stream(stream, packed, unpacked)?
        } else {
            let zstd = match &mut self.zstd {
                Some(zstd) => zstd,
                None => self.zstd.insert(
                    zstd::bulk::Decompressor::new()
                        .map_err(|err| format!("Batch: no zstd decompressor: {err}"))?,
                ),
            };

            zstd.decompress_to_buffer(packed, unpacked)
                .map_err(|err| format!("Batch: zstd can not unpack it: {err}"))?
        };

        if unpacked_len != raw_len {
            return Err(format!(
                "Batch: unpacked to {unpacked_len} bytes, {raw_len} were announced"
            ));
        }

        Ok(&self.unpacked[..raw_len])
    }

    /// Lets the unpack buffer go after a batch too big to keep a buffer for.
    ///
    /// The stream is not let go with it: its window is what the next pieces are unpacked with.
    pub fn release_buffer(&mut self) {
        if self.unpacked.len() > UNPACK_BUFFER_TO_KEEP {
            self.unpacked = Vec::new();
        }
    }
}

fn new_stream_decoder() -> Result<zstd::stream::raw::Decoder<'static>, String> {
    let mut stream = zstd::stream::raw::Decoder::new()
        .map_err(|err| format!("Batch: no zstd stream decoder: {err}"))?;

    stream
        .set_parameter(zstd::zstd_safe::DParameter::WindowLogMax(
            STREAM_WINDOW_LOG_MAX,
        ))
        .map_err(|err| format!("Batch: no zstd stream decoder: {err}"))?;

    Ok(stream)
}

/// Unpacks `packed`, the next piece of the stream, into `unpacked` - a buffer of the size the
/// batch announced - and returns how much of it was filled. All of the piece has to go in, and
/// nothing may be left of it for which the buffer has no room: then the batch is bigger than
/// it said, and the rest of it would come out in front of the next one.
///
/// An error leaves the stream wherever it stopped. It is not used again: the connection is
/// closed for a batch which does not unpack, as for any frame which is not what a peer sends.
fn read_from_stream(
    stream: &mut zstd::stream::raw::Decoder<'static>,
    packed: &[u8],
    unpacked: &mut [u8],
) -> Result<usize, String> {
    use zstd::stream::raw::{InBuffer, Operation, OutBuffer};

    let can_not = |err: std::io::Error| format!("Batch: the zstd stream can not unpack it: {err}");

    let room = unpacked.len();

    let mut input = InBuffer::around(packed);
    let mut output = OutBuffer::around(unpacked);

    while input.pos() < packed.len() {
        if output.pos() == room {
            return Err(format!(
                "Batch: a piece of the zstd stream unpacks to more than the {room} bytes announced"
            ));
        }

        stream.run(&mut input, &mut output).map_err(can_not)?;
    }

    let unpacked_len = output.pos();

    // The buffer is full and the piece is read: what is unpacked and did not fit would still
    // be inside the stream. A byte of room shows it.
    if unpacked_len == room {
        let mut spare = [0u8; 1];
        let mut nothing = InBuffer::around(&[][..]);
        let mut output = OutBuffer::around(&mut spare[..]);

        stream.run(&mut nothing, &mut output).map_err(can_not)?;

        if output.pos() > 0 {
            return Err(format!(
                "Batch: a piece of the zstd stream unpacks to more than the {room} bytes announced"
            ));
        }
    }

    Ok(unpacked_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn level(level: u8) -> CompressionLevel {
        CompressionLevel::new(level).unwrap()
    }

    /// The kind of the batches a level packs into.
    fn kind_of(level: CompressionLevel) -> u8 {
        match level.packing() {
            None => BATCH_STORED,
            Some(Packing::Lz4 { .. }) => BATCH_LZ4,
            Some(Packing::Zstd { .. }) => BATCH_ZSTD,
            Some(Packing::ZstdStream { .. }) => BATCH_ZSTD_STREAM,
        }
    }

    fn is_stream(level: CompressionLevel) -> bool {
        matches!(level.packing(), Some(Packing::ZstdStream { .. }))
    }

    fn batch_of(frames: &[u8], level: CompressionLevel) -> Vec<u8> {
        let mut wire = Vec::new();
        BatchPacker::new(level).write_batch(frames, &mut wire);
        wire
    }

    /// Bytes nothing can make smaller.
    fn noise(size: usize) -> Vec<u8> {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        (0..size)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn a_batch_reads_back_whatever_level_it_is_packed_with() {
        let text = b"GET /api/accounts HTTP/1.1\r\nhost: example.com\r\n\r\n".repeat(200);

        for level in CompressionLevel::all() {
            let is_stream = matches!(level.packing(), Some(Packing::ZstdStream { .. }));

            for (frames, kind) in [
                (text.clone(), kind_of(level)),
                // Nothing to save: it goes as it is - but into a stream, where it is what the
                // next batches are packed with.
                (
                    noise(100_000),
                    if is_stream {
                        BATCH_ZSTD_STREAM
                    } else {
                        BATCH_STORED
                    },
                ),
                (b"ping".to_vec(), BATCH_STORED),
                (Vec::new(), BATCH_STORED),
            ] {
                let batch = batch_of(&frames, level);
                assert_eq!(batch[0], kind, "level {level}");

                if is_stream {
                    // The kind, the size, the head of the stream and of its blocks.
                    assert!(batch.len() <= frames.len() + 32, "level {level}");
                } else {
                    assert!(batch.len() <= frames.len() + 1);
                }

                assert_eq!(BatchUnpacker::new().read_batch(&batch).unwrap(), frames);
            }

            if level.is_on() {
                assert!(
                    batch_of(&text, level).len() < text.len() / 10,
                    "level {level}"
                );
            }
        }
    }

    /// One packer and one unpacker carry all the batches of a connection: what one batch
    /// leaves behind in them does not get into the next.
    #[test]
    fn a_packer_and_an_unpacker_carry_batch_after_batch() {
        let batches: Vec<Vec<u8>> = (0..40usize)
            .map(|no| match no % 4 {
                0 => format!("{{\"row\":{no},\"symbol\":\"EURUSD\"}},")
                    .repeat(1 + no * 37)
                    .into_bytes(),
                1 => noise(1 + no * 211),
                2 => vec![no as u8; 1 + no * 1009],
                _ => b"pong".to_vec(),
            })
            .collect();

        for level in CompressionLevel::all() {
            let mut packer = BatchPacker::new(level);
            let mut unpacker = BatchUnpacker::new();
            assert_eq!(packer.is_on(), level.is_on());

            for frames in &batches {
                let mut wire = Vec::new();
                packer.write_batch(frames, &mut wire);
                assert_eq!(unpacker.read_batch(&wire).unwrap(), frames, "level {level}");
            }
        }
    }

    /// A batch says what it is packed with: one unpacker reads the batches of every level which
    /// packs a batch on its own. (A piece of a stream is read by the unpacker which read the
    /// pieces before it: [`a_piece_of_a_stream_is_read_after_the_pieces_before_it`].)
    #[test]
    fn an_unpacker_reads_the_batches_of_any_level() {
        let frames = b"a batch of frames ".repeat(500);
        let mut unpacker = BatchUnpacker::new();

        for _ in 0..2 {
            for level in CompressionLevel::all().filter(|level| !is_stream(*level)) {
                let batch = batch_of(&frames, level);
                assert_eq!(
                    unpacker.read_batch(&batch).unwrap(),
                    frames,
                    "level {level}"
                );
            }
        }
    }

    /// Every level which is on makes text smaller - Zstandard smaller than LZ4 does - and
    /// every one of them in a way of its own.
    #[test]
    fn the_levels_differ_in_how_much_they_save() {
        let text: Vec<u8> = (0..3000u32)
            .flat_map(|row| {
                format!(
                    "{{\"id\":{},\"symbol\":\"EURUSD\",\"bid\":1.0{},\"ask\":1.0{}}},\n",
                    row.wrapping_mul(2_654_435_761),
                    row % 977,
                    row % 983
                )
                .into_bytes()
            })
            .collect();

        let size_at = |no: u8| batch_of(&text, level(no)).len();

        assert_eq!(size_at(0), text.len() + 1);
        for no in 1..=CompressionLevel::MAX {
            assert!(size_at(no) < text.len() / 2, "level {no}: {}", size_at(no));
        }
        assert!(size_at(2) < size_at(1), "zstd 1 against lz4");

        // And no two rows are one packer under two numbers: the level of a row is what its
        // packer is given. A row of one stream packs a single batch the way the row of its
        // level does, so the two kinds of rows are compared apart.
        for rows in [
            (0..=CompressionLevel::MAX)
                .filter(|no| !is_stream(level(*no)))
                .collect::<Vec<u8>>(),
            (0..=CompressionLevel::MAX)
                .filter(|no| is_stream(level(*no)))
                .collect(),
        ] {
            let sizes: std::collections::BTreeSet<usize> =
                rows.iter().map(|no| size_at(*no)).collect();
            assert_eq!(sizes.len(), rows.len(), "{rows:?}: {sizes:?}");
        }
    }

    /// The point of the one stream: a small batch - a request, an answer - is packed with the
    /// batches before it. On its own it has next to nothing to be packed with.
    #[test]
    fn a_small_batch_in_a_stream_is_packed_with_the_batches_before_it() {
        let requests: Vec<Vec<u8>> = (0..400u32)
            .map(|no| {
                format!(
                    "GET /api/accounts/{}/orders?page={} HTTP/1.1\r\nhost: api.example.com\r\n\
                     user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)\r\n\
                     accept: application/json\r\nauthorization: Bearer {:x}\r\n\r\n",
                    no.wrapping_mul(2_654_435_761) % 100_000,
                    no % 7,
                    u64::from(no).wrapping_mul(0x9E37_79B9_7F4A_7C15)
                )
                .into_bytes()
            })
            .collect();

        let on_the_wire = |no: u8| {
            let mut packer = BatchPacker::new(level(no));
            let mut unpacker = BatchUnpacker::new();
            let mut total = 0;

            for request in &requests {
                let mut wire = Vec::new();
                packer.write_batch(request, &mut wire);
                assert_eq!(unpacker.read_batch(&wire).unwrap(), request, "level {no}");
                total += wire.len();
            }

            total
        };

        let not_packed = on_the_wire(0);

        // The same Zstandard level, a batch on its own and in the stream.
        for (alone, in_the_stream) in [(2, 6), (3, 7), (4, 8), (5, 9)] {
            let (alone, in_the_stream) = (on_the_wire(alone), on_the_wire(in_the_stream));

            assert!(alone > not_packed / 2, "{alone} of {not_packed}");
            assert!(
                in_the_stream < not_packed / 3,
                "{in_the_stream} of {not_packed}"
            );
            assert!(in_the_stream * 2 < alone, "{in_the_stream} against {alone}");
        }
    }

    /// Thousands of batches of every size in a row through one stream - far more than its
    /// window holds: what packs, what does not, and the small ones which stay out of it.
    #[test]
    fn a_stream_carries_thousands_of_batches_of_any_size() {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        let batches: Vec<Vec<u8>> = (0..3000usize)
            .map(|no| {
                // Mostly small, and a big one now and then: 1 byte to 300 KiB.
                let size = match next() % 100 {
                    0 => 1 + (next() % 300_000) as usize,
                    1..=9 => 1 + (next() % 20_000) as usize,
                    10..=29 => 1 + (next() % 40) as usize,
                    _ => 1 + (next() % 2_000) as usize,
                };

                match no % 3 {
                    0 => (0..size).map(|_| (next() >> 24) as u8).collect(),
                    1 => format!(
                        "{{\"row\":{no},\"symbol\":\"EURUSD\",\"bid\":1.0{}}},",
                        no % 977
                    )
                    .into_bytes()
                    .into_iter()
                    .cycle()
                    .take(size)
                    .collect(),
                    _ => vec![no as u8; size],
                }
            })
            .collect();

        let total: usize = batches.iter().map(Vec::len).sum();
        assert!(total > 8 * 1024 * 1024, "{total}");

        for level in CompressionLevel::all().filter(|level| is_stream(*level)) {
            let mut packer = BatchPacker::new(level);
            let mut unpacker = BatchUnpacker::new();
            let mut wire = Vec::new();
            let (mut pieces, mut stored) = (0, 0);

            for frames in &batches {
                wire.clear();
                packer.write_batch(frames, &mut wire);

                match wire[0] {
                    BATCH_ZSTD_STREAM => pieces += 1,
                    BATCH_STORED => {
                        assert!(frames.len() < MIN_SIZE_TO_PACK_STREAM);
                        stored += 1;
                    }
                    kind => panic!("level {level}: a batch of the kind {kind}"),
                }

                // What does not pack costs the head of a piece and of its blocks.
                assert!(wire.len() <= frames.len() + 32, "level {level}");

                assert_eq!(unpacker.read_batch(&wire).unwrap(), frames, "level {level}");
                unpacker.release_buffer();
            }

            assert!(pieces > 2000 && stored > 100, "{pieces} and {stored}");
        }
    }

    /// A batch of the biggest size a connection carries - megabytes nothing packs - goes into
    /// the stream whole, and comes out of it.
    #[test]
    fn a_stream_carries_the_biggest_batch() {
        let frames = noise(crate::tcp_gateway::MAX_PAYLOAD_SIZE);

        for level in CompressionLevel::all().filter(|level| is_stream(*level)) {
            let mut packer = BatchPacker::new(level);
            let mut unpacker = BatchUnpacker::new();
            let mut wire = Vec::new();

            for _ in 0..2 {
                wire.clear();
                packer.write_batch(&frames, &mut wire);

                assert_eq!(wire[0], BATCH_ZSTD_STREAM);
                assert!(wire.len() <= frames.len() + 256, "level {level}");
                assert!(
                    unpacker.read_batch(&wire).unwrap() == frames,
                    "level {level}"
                );
            }
        }
    }

    /// The pieces are one stream: a piece is read by the unpacker which read every piece
    /// before it, and by no other. On a connection the frames open in their order or not at
    /// all, so a piece does not get to an unpacker out of its turn.
    #[test]
    fn a_piece_of_a_stream_is_read_after_the_pieces_before_it() {
        let batches: Vec<Vec<u8>> = (0..4u32)
            .map(|no| {
                format!("{{\"row\":{no},\"symbol\":\"EURUSD\"}},")
                    .repeat(50)
                    .into_bytes()
            })
            .collect();

        for level in CompressionLevel::all().filter(|level| is_stream(*level)) {
            let mut packer = BatchPacker::new(level);
            let pieces: Vec<Vec<u8>> = batches
                .iter()
                .map(|frames| {
                    let mut wire = Vec::new();
                    packer.write_batch(frames, &mut wire);
                    assert_eq!(wire[0], BATCH_ZSTD_STREAM);
                    wire
                })
                .collect();

            // In their order.
            let mut unpacker = BatchUnpacker::new();
            for (piece, frames) in pieces.iter().zip(&batches) {
                assert_eq!(unpacker.read_batch(piece).unwrap(), frames);
            }

            // Without the first one.
            let err = BatchUnpacker::new().read_batch(&pieces[1]).unwrap_err();
            assert!(err.contains("the zstd stream can not unpack it"), "{err}");
        }
    }

    #[test]
    fn a_piece_of_a_stream_which_is_not_what_it_says_is_refused() {
        let frames = b"a batch of frames ".repeat(500);
        let piece = batch_of(&frames, level(6));
        assert_eq!(piece[0], BATCH_ZSTD_STREAM);

        let with_size = |size: usize| {
            let mut piece = piece.clone();
            piece[1..5].copy_from_slice(&(size as u32).to_le_bytes());
            piece
        };

        // Unpacks to more than it says.
        for size in [1, frames.len() - 1] {
            let err = BatchUnpacker::new()
                .read_batch(&with_size(size))
                .unwrap_err();
            assert!(err.contains("unpacks to more than"), "{size}: {err}");
        }

        // Unpacks to less than it says.
        let err = BatchUnpacker::new()
            .read_batch(&with_size(frames.len() + 1))
            .unwrap_err();
        assert!(err.contains("bytes, 9001 were announced"), "{err}");

        // Says more than a batch may be: refused before any memory is taken for it.
        let err = BatchUnpacker::new()
            .read_batch(&with_size(MAX_DECOMPRESSED_BATCH_SIZE + 1))
            .unwrap_err();
        assert!(err.contains("is out of range"), "{err}");

        // Cut short.
        let err = BatchUnpacker::new()
            .read_batch(&piece[..piece.len() - 3])
            .unwrap_err();
        assert!(err.contains("were announced"), "{err}");

        // Not a stream at all.
        let mut garbage = with_size(frames.len());
        garbage.truncate(5);
        garbage.extend_from_slice(&noise(200));
        let err = BatchUnpacker::new().read_batch(&garbage).unwrap_err();
        assert!(err.contains("the zstd stream can not unpack it"), "{err}");
    }

    /// A stream says the size of its window, and the memory for it is taken by the end which
    /// reads it. One which asks for more than the levels of the table do is not read.
    #[test]
    fn a_stream_with_a_window_beyond_the_limit_is_refused() {
        use zstd::stream::raw::{Encoder, InBuffer, Operation, OutBuffer};

        let frames = b"a batch of frames ".repeat(500);

        let piece_with_window = |window_log: u32| {
            let mut stream = Encoder::new(1).unwrap();
            stream
                .set_parameter(zstd::zstd_safe::CParameter::WindowLog(window_log))
                .unwrap();

            let mut packed = vec![0u8; frames.len() + 256];
            let packed_len = {
                let mut input = InBuffer::around(&frames[..]);
                let mut output = OutBuffer::around(&mut packed[..]);
                stream.run(&mut input, &mut output).unwrap();
                assert_eq!(stream.flush(&mut output).unwrap(), 0);
                output.pos()
            };

            let mut piece = vec![BATCH_ZSTD_STREAM];
            piece.extend_from_slice(&(frames.len() as u32).to_le_bytes());
            piece.extend_from_slice(&packed[..packed_len]);
            piece
        };

        assert_eq!(
            BatchUnpacker::new()
                .read_batch(&piece_with_window(STREAM_WINDOW_LOG_MAX))
                .unwrap(),
            frames
        );

        let err = BatchUnpacker::new()
            .read_batch(&piece_with_window(STREAM_WINDOW_LOG_MAX + 1))
            .unwrap_err();
        assert!(err.contains("the zstd stream can not unpack it"), "{err}");
    }

    /// A batch which goes as it is - too small for a piece - is no part of the stream: the
    /// pieces around it are read as if it were not there.
    #[test]
    fn a_batch_which_is_not_a_piece_leaves_the_stream_where_it_is() {
        let text = b"GET /api/accounts HTTP/1.1\r\nhost: example.com\r\n\r\n".repeat(20);

        let mut packer = BatchPacker::new(level(7));
        let mut unpacker = BatchUnpacker::new();

        for round in 0..50 {
            for frames in [&text[..], &b"ping"[..], &text[..round + 40], &[7u8; 31][..]] {
                let mut wire = Vec::new();
                packer.write_batch(frames, &mut wire);

                let kind = if frames.len() < MIN_SIZE_TO_PACK_STREAM {
                    BATCH_STORED
                } else {
                    BATCH_ZSTD_STREAM
                };
                assert_eq!(wire[0], kind);
                assert_eq!(unpacker.read_batch(&wire).unwrap(), frames);
            }
        }
    }

    #[test]
    fn a_small_batch_is_not_packed() {
        let text = [b'a'; 2 * MIN_SIZE_TO_PACK_ZSTD];

        for (no, min_size) in [(1, MIN_SIZE_TO_PACK_LZ4), (2, MIN_SIZE_TO_PACK_ZSTD)] {
            assert_eq!(batch_of(&text[..min_size - 1], level(no))[0], BATCH_STORED);
            assert_ne!(batch_of(&text[..min_size], level(no))[0], BATCH_STORED);
        }
    }

    #[test]
    fn the_unpack_buffer_is_reused_and_a_small_batch_reads_right_after_a_big_one() {
        for no in [1, 2] {
            let mut unpacker = BatchUnpacker::new();

            let big = b"0123456789".repeat(10_000);
            assert_eq!(
                unpacker.read_batch(&batch_of(&big, level(no))).unwrap(),
                big
            );

            let small = b"abcdefgh".repeat(20);
            assert_eq!(
                unpacker.read_batch(&batch_of(&small, level(no))).unwrap(),
                small
            );
            assert_eq!(unpacker.unpacked.len(), big.len());

            unpacker.release_buffer();
            assert_eq!(unpacker.unpacked.len(), big.len(), "small enough to keep");

            let file = vec![7u8; 2 * UNPACK_BUFFER_TO_KEEP];
            assert_eq!(
                unpacker.read_batch(&batch_of(&file, level(no))).unwrap(),
                file
            );
            unpacker.release_buffer();
            assert!(unpacker.unpacked.is_empty());
        }
    }

    #[test]
    fn a_batch_which_lies_about_itself_is_refused() {
        let mut unpacker = BatchUnpacker::new();

        assert!(unpacker.read_batch(&[]).is_err());
        assert!(unpacker.read_batch(&[7, 1, 2, 3]).is_err());

        for no in [1, 2] {
            let kind = kind_of(level(no));
            assert!(unpacker.read_batch(&[kind, 1, 0]).is_err());

            let frames = b"a batch of frames ".repeat(100);
            let batch = batch_of(&frames, level(no));
            assert_eq!(batch[0], kind);

            let with_raw_len = |raw_len: u32| {
                let mut batch = batch.clone();
                batch[1..5].copy_from_slice(&raw_len.to_le_bytes());
                batch
            };

            // More than there is, less than there is, nothing at all.
            for raw_len in [frames.len() as u32 + 1, frames.len() as u32 - 1, 0] {
                assert!(unpacker.read_batch(&with_raw_len(raw_len)).is_err());
            }

            // Cut short, with something behind it, and not packed at all.
            assert!(unpacker.read_batch(&batch[..batch.len() - 3]).is_err());

            let mut longer = batch.clone();
            longer.extend_from_slice(b"more");
            assert!(unpacker.read_batch(&longer).is_err());

            let mut garbage = vec![kind];
            garbage.extend_from_slice(&1000u32.to_le_bytes());
            garbage.extend_from_slice(&noise(300));
            assert!(unpacker.read_batch(&garbage).is_err());

            // Packed with one, said to be packed with the other.
            let mut mislabeled = batch.clone();
            mislabeled[0] = if kind == BATCH_LZ4 {
                BATCH_ZSTD
            } else {
                BATCH_LZ4
            };
            assert!(unpacker.read_batch(&mislabeled).is_err());

            // And the unpacker is as good as new after all of that.
            assert_eq!(unpacker.read_batch(&batch).unwrap(), frames);
        }
    }

    /// A batch which announces more than the limit is refused by its size alone: no buffer is
    /// taken for it.
    #[test]
    fn unpacking_stops_at_the_limit() {
        for no in [1, 2] {
            let mut bomb = vec![kind_of(level(no))];
            bomb.extend_from_slice(&(MAX_DECOMPRESSED_BATCH_SIZE as u32 + 1).to_le_bytes());
            bomb.extend_from_slice(&[0u8; 64]);

            let mut unpacker = BatchUnpacker::new();
            assert!(unpacker.read_batch(&bomb).is_err());
            assert!(unpacker.unpacked.is_empty());

            // At the limit it is unpacked.
            let frames = vec![0u8; MAX_DECOMPRESSED_BATCH_SIZE];
            let batch = batch_of(&frames, level(no));
            assert!(unpacker.read_batch(&batch).unwrap() == frames);
        }
    }

    /// A batch which unpacks to more than it says: what is unpacked stops where it said.
    #[test]
    fn a_batch_never_unpacks_to_more_than_it_announces() {
        let frames = vec![0u8; 4 * 1024 * 1024];

        for no in [1, 2] {
            let mut batch = batch_of(&frames, level(no));
            assert_ne!(batch[0], BATCH_STORED);
            batch[1..5].copy_from_slice(&1024u32.to_le_bytes());

            let mut unpacker = BatchUnpacker::new();
            assert!(unpacker.read_batch(&batch).is_err());
            assert_eq!(unpacker.unpacked.len(), 1024);
        }
    }
}

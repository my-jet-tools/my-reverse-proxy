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
}

impl BatchPacker {
    pub fn new(level: CompressionLevel) -> Self {
        Self {
            packing: level.packing(),
            zstd: None,
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

        if kind != BATCH_LZ4 && kind != BATCH_ZSTD {
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
    pub fn release_buffer(&mut self) {
        if self.unpacked.len() > UNPACK_BUFFER_TO_KEEP {
            self.unpacked = Vec::new();
        }
    }
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
        }
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
            for (frames, kind) in [
                (text.clone(), kind_of(level)),
                // Nothing to save: it goes as it is.
                (noise(100_000), BATCH_STORED),
                (b"ping".to_vec(), BATCH_STORED),
                (Vec::new(), BATCH_STORED),
            ] {
                let batch = batch_of(&frames, level);
                assert_eq!(batch[0], kind, "level {level}");
                assert!(batch.len() <= frames.len() + 1);

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

    /// A batch says what it is packed with: one unpacker reads the batches of every level.
    #[test]
    fn an_unpacker_reads_the_batches_of_any_level() {
        let frames = b"a batch of frames ".repeat(500);
        let mut unpacker = BatchUnpacker::new();

        for _ in 0..2 {
            for level in CompressionLevel::all() {
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
        // packer is given.
        let sizes: std::collections::BTreeSet<usize> =
            (0..=CompressionLevel::MAX).map(size_at).collect();
        assert_eq!(sizes.len(), CompressionLevel::MAX as usize + 1, "{sizes:?}");
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

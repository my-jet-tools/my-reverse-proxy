//! The compression levels of a gateway connection: the number a client is set up with
//! (`compress`) and carries in its handshake, and what the batches are packed with for it.
//! docs/gateway-compression.md has the table, with what every level gives on real data.

use std::fmt;

/// What a batch is packed with: an algorithm and its own level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Packing {
    /// An LZ4 block. `acceleration` is LZ4's own: 1 is its default, more packs faster and worse.
    Lz4 { acceleration: i32 },
    /// A Zstandard frame, of the Zstandard level.
    Zstd { level: i32 },
    /// One Zstandard stream for the whole direction, of the Zstandard level: a batch is a piece
    /// of it, packed with everything sent before it for a history. A batch of a few hundred
    /// bytes - a request, an answer - has nothing in itself to be packed with; in the stream
    /// it has the requests and the answers before it.
    ZstdStream { level: i32 },
}

/// The table: what the levels from 1 on pack with. Level 0 is no compression.
///
/// A new row goes to the end: a level means the same on both ends of a gateway connection, and
/// goes on meaning what it means in the settings which are deployed. It goes into the table of
/// the document and of the README as well, with what it gives.
///
/// The rows are what packs fast enough to be done by the writer of the connection between two
/// writes: see "What is not in the table" in the document.
const LEVELS: [Packing; 9] = [
    /* 1 */ Packing::Lz4 { acceleration: 1 },
    /* 2 */ Packing::Zstd { level: 1 },
    /* 3 */ Packing::Zstd { level: 3 },
    /* 4 */ Packing::Zstd { level: 6 },
    /* 5 */ Packing::Zstd { level: 9 },
    /* 6 */ Packing::ZstdStream { level: 1 },
    /* 7 */ Packing::ZstdStream { level: 3 },
    /* 8 */ Packing::ZstdStream { level: 6 },
    /* 9 */ Packing::ZstdStream { level: 9 },
];

/// A level of the table, or 0: no compression.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CompressionLevel(u8);

impl CompressionLevel {
    pub const OFF: Self = Self(0);

    /// The last level of the table.
    pub const MAX: u8 = LEVELS.len() as u8;

    /// `level` as it is in the settings and in a handshake. A level this side has no row for is
    /// refused: the two ends would pack differently from what was asked for.
    pub fn new(level: u8) -> Result<Self, String> {
        if level > Self::MAX {
            return Err(format!(
                "compression level {level} is not known, the levels are 0 (off) to {}",
                Self::MAX
            ));
        }

        Ok(Self(level))
    }

    pub fn as_u8(self) -> u8 {
        self.0
    }

    pub fn is_on(self) -> bool {
        self.0 > 0
    }

    /// What the batches are packed with: `None` with compression off.
    pub fn packing(self) -> Option<Packing> {
        let row = (self.0 as usize).checked_sub(1)?;
        LEVELS.get(row).copied()
    }

    /// Every level there is, from 0.
    #[cfg(test)]
    pub fn all() -> impl Iterator<Item = Self> {
        (0..=Self::MAX).map(Self)
    }
}

/// The algorithm and its level in a word or two: what the status of a connection and the logs
/// call it.
impl fmt::Display for CompressionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.packing() {
            None => f.write_str("off"),
            Some(Packing::Lz4 { acceleration: 1 }) => f.write_str("lz4"),
            Some(Packing::Lz4 { acceleration }) => write!(f, "lz4, acceleration {acceleration}"),
            Some(Packing::Zstd { level }) => write!(f, "zstd {level}"),
            Some(Packing::ZstdStream { level }) => write!(f, "zstd {level}, one stream"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_level_is_a_row_of_the_table_or_no_compression() {
        assert_eq!(CompressionLevel::default(), CompressionLevel::OFF);
        assert_eq!(CompressionLevel::OFF.packing(), None);
        assert!(!CompressionLevel::OFF.is_on());
        assert_eq!(CompressionLevel::OFF.to_string(), "off");

        for (row, packing) in LEVELS.iter().enumerate() {
            let level = CompressionLevel::new(row as u8 + 1).unwrap();
            assert!(level.is_on());
            assert_eq!(level.as_u8(), row as u8 + 1);
            assert_eq!(level.packing(), Some(*packing));
        }

        assert_eq!(CompressionLevel::all().count(), LEVELS.len() + 1);
    }

    #[test]
    fn a_level_with_no_row_is_refused() {
        for level in [CompressionLevel::MAX + 1, 100, u8::MAX] {
            let err = CompressionLevel::new(level).unwrap_err();
            assert!(
                err.contains(&format!("level {level} is not known")),
                "{err}"
            );
        }
    }

    /// The numbers are in the settings of the deployed clients: a row keeps its place.
    #[test]
    fn the_rows_keep_their_numbers() {
        let named = |level: u8| CompressionLevel::new(level).unwrap().to_string();

        assert_eq!(named(1), "lz4");
        assert_eq!(named(2), "zstd 1");
        assert_eq!(named(3), "zstd 3");
        assert_eq!(named(4), "zstd 6");
        assert_eq!(named(5), "zstd 9");
        assert_eq!(named(6), "zstd 1, one stream");
        assert_eq!(named(7), "zstd 3, one stream");
        assert_eq!(named(8), "zstd 6, one stream");
        assert_eq!(named(9), "zstd 9, one stream");
    }
}

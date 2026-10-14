use super::super::*;
pub struct ChunkHeader {
    pub len: usize,
    pub chunk_size: usize,
}

impl ChunkHeader {
    pub fn new(len: usize, src: &[u8]) -> Result<Self, ProxyServerError> {
        let chunk_size = get_chunk_size(src, len)?;
        Ok(Self { len, chunk_size })
    }
}

/// 16 hex digits are a `u64`: a longer size line is not a size.
const MAX_CHUNK_SIZE_DIGITS: usize = 16;

fn get_chunk_size(chunk: &[u8], len: usize) -> Result<usize, ProxyServerError> {
    let digits = &chunk[..len];

    // The line comes straight off the wire. Without the limit and the checked steps a long
    // one overflows the size: a panic in a debug build, and in a release build a size which
    // is not the one that was sent - the body would be cut at the wrong byte.
    if digits.is_empty() || digits.len() > MAX_CHUNK_SIZE_DIGITS {
        return Err(ProxyServerError::ChunkHeaderParseError);
    }

    let mut result: usize = 0;

    for c in digits {
        let Some(digit) = parse_hex_digit(*c) else {
            return Err(ProxyServerError::ChunkHeaderParseError);
        };

        result = result
            .checked_mul(16)
            .and_then(|result| result.checked_add(digit))
            .ok_or(ProxyServerError::ChunkHeaderParseError)?;
    }

    // A chunk is relayed whole - the size line, the data and both line ends: that has to be
    // a number as well.
    if result
        .checked_add(len + crate::consts::HTTP_CR_LF.len() * 2)
        .is_none()
    {
        return Err(ProxyServerError::ChunkHeaderParseError);
    }

    Ok(result)
}

fn parse_hex_digit(c: u8) -> Option<usize> {
    const C_ZERO: usize = b'0' as usize;
    const C_NINE: usize = b'9' as usize;

    const C_A_LC: usize = b'a' as usize;
    const C_F_LC: usize = b'f' as usize;

    const C_A_UC: usize = b'A' as usize;
    const C_F_UC: usize = b'F' as usize;

    let c = c as usize;

    if (C_ZERO..=C_NINE).contains(&c) {
        return Some(c - C_ZERO);
    }

    if (C_A_LC..=C_F_LC).contains(&c) {
        return Some(c - C_A_LC + 10);
    }

    if (C_A_UC..=C_F_UC).contains(&c) {
        return Some(c - C_A_UC + 10);
    }

    None
}

#[cfg(test)]
mod test {

    use crate::h1_proxy_server::transfer_body::ChunkHeader;

    #[test]
    fn test_211b() {
        let chunk = b"211B";

        let header = ChunkHeader::new(chunk.len(), chunk).unwrap();

        assert_eq!(8475, header.chunk_size);
    }

    #[test]
    fn test_211b_lc() {
        let chunk = b"211b";

        let header = ChunkHeader::new(chunk.len(), chunk).unwrap();

        assert_eq!(8475, header.chunk_size);
    }

    #[test]
    fn the_biggest_size_which_fits_is_read() {
        let chunk = b"0000000000001000";
        assert_eq!(
            ChunkHeader::new(chunk.len(), chunk).unwrap().chunk_size,
            4096
        );

        let chunk = b"0";
        assert_eq!(ChunkHeader::new(chunk.len(), chunk).unwrap().chunk_size, 0);
    }

    #[test]
    fn a_size_which_does_not_fit_is_refused() {
        for chunk in [
            // 17 digits: one more than a u64 has.
            &b"10000000000000000"[..],
            b"00000000000000001",
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            // Fits a u64, and the chunk around it does not.
            b"FFFFFFFFFFFFFFFF",
            b"FFFFFFFFFFFFFFF0",
        ] {
            assert!(
                ChunkHeader::new(chunk.len(), chunk).is_err(),
                "{}",
                String::from_utf8_lossy(chunk)
            );
        }
    }

    #[test]
    fn a_line_which_is_not_hex_digits_is_refused() {
        for chunk in [&b""[..], b"5;ext=1", b" 5", b"5 ", b"0x5", b"-5", b"5g"] {
            assert!(
                ChunkHeader::new(chunk.len(), chunk).is_err(),
                "{:?}",
                String::from_utf8_lossy(chunk)
            );
        }
    }

    #[test]
    fn test_211b_ff() {
        let chunk = b"Ff";

        let header = ChunkHeader::new(chunk.len(), chunk).unwrap();

        assert_eq!(255, header.chunk_size);
    }
}

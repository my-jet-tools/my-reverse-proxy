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

fn get_chunk_size(chunk: &[u8], len: usize) -> Result<usize, ProxyServerError> {
    let my_chunk = &chunk[..len];

    let mut result: usize = 0;
    let mut multiplier: usize = 1;
    for c in my_chunk.iter().rev() {
        let Some(digit) = parse_hex_digit(*c) else {
            return Err(ProxyServerError::ChunkHeaderParseError);
        };

        result += digit * multiplier;
        multiplier *= 16;
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
    fn test_211b_ff() {
        let chunk = b"Ff";

        let header = ChunkHeader::new(chunk.len(), chunk).unwrap();

        assert_eq!(255, header.chunk_size);
    }
}

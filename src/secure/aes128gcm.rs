//! `Content-Encoding: aes128gcm` - RFC 8188, "Encrypted Content-Encoding for HTTP".
//!
//! A body is a header - a random salt, the record size, the id of the key - and AES-128-GCM
//! records after it. The key and the nonces of the records come from the key and the salt through
//! HKDF-SHA-256. docs/encrypted-service-data.md has the layout byte by byte, and the test vectors
//! every service checks its own implementation with: the tests below are the same ones.

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use sha2::Sha256;
use zeroize::Zeroizing;

/// The value of `Content-Encoding` which says a body is encrypted this way.
pub const CONTENT_ENCODING: &str = "aes128gcm";

/// The record size the proxy encrypts with.
pub const DEFAULT_RECORD_SIZE: u32 = 4096;

const SALT_LEN: usize = 16;
const CONTENT_KEY_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// The salt, the record size and the length of the key id.
const HEADER_LEN: usize = SALT_LEN + 4 + 1;

/// What a record adds to the data it carries: the tag and the delimiter.
const RECORD_OVERHEAD: usize = TAG_LEN + 1;

const DELIMITER: u8 = 0x01;
const LAST_DELIMITER: u8 = 0x02;

const CONTENT_KEY_INFO: &[u8] = b"Content-Encoding: aes128gcm\0";
const NONCE_INFO: &[u8] = b"Content-Encoding: nonce\0";

/// Why a body does not open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    /// Too short, or a header no body of this encoding has: it is not encrypted this way.
    NotEncrypted,
    /// A record does not open: the key is another one, or the body is damaged.
    WrongKeyOrDamaged,
    /// The body ends without its last record: it is cut short.
    CutShort,
    /// Something follows the last record, or a record has no delimiter.
    Malformed,
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::NotEncrypted => "not an aes128gcm body",
            Self::WrongKeyOrDamaged => {
                "a record does not open: the key is wrong or the body is damaged"
            }
            Self::CutShort => "the body ends without its last record: it is cut short",
            Self::Malformed => "the records are not laid out as aes128gcm lays them out",
        };

        f.write_str(text)
    }
}

/// The body, decrypted with `ikm`. Either all of it opens or nothing is given: a record which
/// fails its tag, a body cut short and anything after the last record refuse the whole body.
pub fn decrypt(ikm: &[u8], body: &[u8]) -> Result<Vec<u8>, OpenError> {
    let header = Header::read(body).ok_or(OpenError::NotEncrypted)?;

    let mut records = &body[header.len..];

    if records.is_empty() {
        return Err(OpenError::CutShort);
    }

    let keys = RecordKeys::derive(ikm, header.salt);

    let mut result = Vec::with_capacity(records.len());
    let mut sequence = 0u64;

    loop {
        let (record, rest) = records.split_at(records.len().min(header.record_size));

        if record.len() < RECORD_OVERHEAD {
            return Err(OpenError::WrongKeyOrDamaged);
        }

        let mut buffer = record.to_vec();

        let plain = keys
            .key
            .open_in_place(keys.nonce(sequence), Aad::empty(), &mut buffer)
            .map_err(|_| OpenError::WrongKeyOrDamaged)?;

        // The padding is zero bytes after the delimiter.
        let Some(delimiter_at) = plain.iter().rposition(|byte| *byte != 0) else {
            return Err(OpenError::Malformed);
        };

        let is_last = rest.is_empty();

        match (plain[delimiter_at], is_last) {
            (LAST_DELIMITER, true) | (DELIMITER, false) => {}
            (DELIMITER, true) => return Err(OpenError::CutShort),
            _ => return Err(OpenError::Malformed),
        }

        result.extend_from_slice(&plain[..delimiter_at]);

        if is_last {
            return Ok(result);
        }

        records = rest;
        sequence += 1;
    }
}

/// `plain`, encrypted with `ikm` under a fresh random salt, in records of
/// [`DEFAULT_RECORD_SIZE`], with no key id.
pub fn encrypt(ikm: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut salt = [0u8; SALT_LEN];

    SystemRandom::new()
        .fill(&mut salt)
        .expect("the system random generator gives no salt");

    encrypt_with(ikm, &salt, DEFAULT_RECORD_SIZE, &[], plain)
}

/// `plain`, encrypted with `ikm` under `salt`, in records of `record_size` bytes, with `key_id`
/// in the header. A salt is never to be used twice with one key: [`encrypt`] makes a fresh one.
pub fn encrypt_with(
    ikm: &[u8],
    salt: &[u8; SALT_LEN],
    record_size: u32,
    key_id: &[u8],
    plain: &[u8],
) -> Vec<u8> {
    assert!(
        record_size as usize > RECORD_OVERHEAD,
        "a record of {record_size} bytes carries no data"
    );
    assert!(
        key_id.len() <= u8::MAX as usize,
        "a key id is at most 255 bytes"
    );

    let chunk_len = record_size as usize - RECORD_OVERHEAD;
    let keys = RecordKeys::derive(ikm, salt);

    let mut chunks: Vec<&[u8]> = plain.chunks(chunk_len).collect();

    // Empty data is still a record: the last one, with nothing but its delimiter.
    if chunks.is_empty() {
        chunks.push(&[]);
    }

    let mut result = Vec::with_capacity(
        HEADER_LEN + key_id.len() + plain.len() + chunks.len() * RECORD_OVERHEAD,
    );

    result.extend_from_slice(salt);
    result.extend_from_slice(&record_size.to_be_bytes());
    result.push(key_id.len() as u8);
    result.extend_from_slice(key_id);

    let last = chunks.len() - 1;

    for (sequence, chunk) in chunks.into_iter().enumerate() {
        let mut record = Vec::with_capacity(chunk.len() + RECORD_OVERHEAD);
        record.extend_from_slice(chunk);
        record.push(if sequence == last {
            LAST_DELIMITER
        } else {
            DELIMITER
        });

        keys.key
            .seal_in_place_append_tag(keys.nonce(sequence as u64), Aad::empty(), &mut record)
            .expect("AES-128-GCM seals any record");

        result.extend_from_slice(&record);
    }

    result
}

struct Header<'s> {
    salt: &'s [u8; SALT_LEN],
    record_size: usize,
    /// The header with its key id: where the records start.
    len: usize,
}

impl<'s> Header<'s> {
    fn read(body: &'s [u8]) -> Option<Self> {
        if body.len() < HEADER_LEN {
            return None;
        }

        let salt: &[u8; SALT_LEN] = body[..SALT_LEN].try_into().ok()?;

        let record_size =
            u32::from_be_bytes(body[SALT_LEN..SALT_LEN + 4].try_into().ok()?) as usize;

        if record_size <= RECORD_OVERHEAD {
            return None;
        }

        let len = HEADER_LEN + body[HEADER_LEN - 1] as usize;

        if body.len() < len {
            return None;
        }

        Some(Self {
            salt,
            record_size,
            len,
        })
    }
}

struct RecordKeys {
    key: LessSafeKey,
    nonce_base: [u8; NONCE_LEN],
}

impl RecordKeys {
    /// `CEK` and `NONCE` of RFC 8188: HKDF-Extract with the salt, HKDF-Expand with the two infos.
    fn derive(ikm: &[u8], salt: &[u8; SALT_LEN]) -> Self {
        let hkdf = hkdf::Hkdf::<Sha256>::new(Some(salt), ikm);

        let mut content_key = Zeroizing::new([0u8; CONTENT_KEY_LEN]);
        hkdf.expand(CONTENT_KEY_INFO, &mut content_key[..])
            .expect("16 bytes is a length HKDF-SHA-256 gives");

        let mut nonce_base = [0u8; NONCE_LEN];
        hkdf.expand(NONCE_INFO, &mut nonce_base)
            .expect("12 bytes is a length HKDF-SHA-256 gives");

        let key = LessSafeKey::new(
            UnboundKey::new(&AES_128_GCM, &content_key[..]).expect("16 bytes is an AES-128 key"),
        );

        Self { key, nonce_base }
    }

    /// The nonce of the record `sequence`: the base, with the number XORed into its end.
    fn nonce(&self, sequence: u64) -> Nonce {
        let mut nonce = self.nonce_base;

        for (byte, sequence_byte) in nonce[NONCE_LEN - 8..]
            .iter_mut()
            .zip(sequence.to_be_bytes())
        {
            *byte ^= sequence_byte;
        }

        Nonce::assume_unique_for_key(nonce)
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::*;

    fn base64url(text: &str) -> Vec<u8> {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(text)
            .unwrap()
    }

    fn base64(text: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .unwrap()
    }

    fn salt_of(body: &[u8]) -> [u8; SALT_LEN] {
        body[..SALT_LEN].try_into().unwrap()
    }

    /// RFC 8188, 3.1: one record, no key id.
    const RFC_3_1_KEY: &str = "yqdlZ-tYemfogSmv7Ws5PQ";
    const RFC_3_1_BODY: &str =
        "I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-ly8Thjg";

    /// RFC 8188, 3.2: records of 25 bytes, the key id `a1`.
    const RFC_3_2_KEY: &str = "BO3ZVPxUlnLORbVGMpbT1Q";
    const RFC_3_2_BODY: &str = "uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHOG8chz_gnvgOqdGYovxyjuqRyJFjEDyoF1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS_uA";

    /// The vector of docs/encrypted-service-data.md: a key of 32 bytes, in standard base64.
    const OUR_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    const OUR_BODY: &str = "oKGio6SlpqeoqaqrrK2urwAAEAAAd4lQdR25LBqmiaRlRbryiJTYDikv7OAMtydV1zSRPu4Fy70/BNOmc0q8RjUIqwznMD1/D9zqlMc=";
    const OUR_PLAIN: &[u8] = b"ip_white_lists:\n  office:\n  - 10.0.0.1\n";

    #[test]
    fn the_vectors_decrypt_to_their_plain_text() {
        assert_eq!(
            decrypt(&base64url(RFC_3_1_KEY), &base64url(RFC_3_1_BODY)).unwrap(),
            b"I am the walrus"
        );
        assert_eq!(
            decrypt(&base64url(RFC_3_2_KEY), &base64url(RFC_3_2_BODY)).unwrap(),
            b"I am the walrus"
        );
        assert_eq!(
            decrypt(&base64(OUR_KEY), &base64(OUR_BODY)).unwrap(),
            OUR_PLAIN
        );
    }

    #[test]
    fn the_vectors_are_encrypted_byte_for_byte() {
        let body = base64url(RFC_3_1_BODY);
        assert_eq!(
            encrypt_with(
                &base64url(RFC_3_1_KEY),
                &salt_of(&body),
                4096,
                b"",
                b"I am the walrus"
            ),
            body
        );

        let body = base64(OUR_BODY);
        assert_eq!(
            encrypt_with(&base64(OUR_KEY), &salt_of(&body), 4096, b"", OUR_PLAIN),
            body
        );
    }

    #[test]
    fn another_key_does_not_open_a_body() {
        assert_eq!(
            decrypt(&base64(OUR_KEY), &base64url(RFC_3_1_BODY)),
            Err(OpenError::WrongKeyOrDamaged)
        );
    }

    #[test]
    fn a_damaged_body_does_not_open() {
        let key = base64(OUR_KEY);
        let body = base64(OUR_BODY);

        for index in [0, 20, body.len() / 2, body.len() - 1] {
            let mut damaged = body.clone();
            damaged[index] ^= 0x01;
            assert!(decrypt(&key, &damaged).is_err(), "byte {index}");
        }

        assert!(decrypt(&key, &body[..body.len() - 1]).is_err());
    }

    /// A body of several records which lost its last one ends with a record that says more is
    /// coming.
    #[test]
    fn a_body_cut_short_does_not_open() {
        let key = base64(OUR_KEY);
        let body = encrypt_with(
            &key,
            &[7u8; SALT_LEN],
            25,
            b"",
            b"more than one record of data",
        );

        let header_len = HEADER_LEN;
        let records = &body[header_len..];
        assert!(records.len() > 25);

        let cut = &body[..header_len + 25];
        assert_eq!(decrypt(&key, cut), Err(OpenError::CutShort));
    }

    #[test]
    fn what_is_encrypted_opens_whatever_its_length() {
        let key = base64(OUR_KEY);

        for len in [0, 1, 7, 8, 9, 16, 17, 100, 4079, 4080, 10_000] {
            let plain: Vec<u8> = (0..len).map(|index| (index % 251) as u8).collect();

            for record_size in [25, 4096] {
                let body = encrypt_with(&key, &[3u8; SALT_LEN], record_size, b"id", &plain);
                assert_eq!(
                    decrypt(&key, &body).unwrap(),
                    plain,
                    "{len} in {record_size}"
                );
            }

            let body = encrypt(&key, &plain);
            assert_eq!(decrypt(&key, &body).unwrap(), plain, "{len}");
        }
    }

    #[test]
    fn a_fresh_salt_goes_into_every_body() {
        let key = base64(OUR_KEY);

        assert_ne!(encrypt(&key, b"same"), encrypt(&key, b"same"));
    }

    /// What is not encrypted is told from what is encrypted with another key only as far as the
    /// header goes: either way it does not open.
    #[test]
    fn plain_data_does_not_open() {
        let key = base64(OUR_KEY);

        for plain in [
            &b""[..],
            b"hosts: {}\n",
            b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        ] {
            assert!(decrypt(&key, plain).is_err(), "{plain:?}");
        }
    }
}

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use sha2::Sha256;
use zeroize::Zeroizing;

/// The size of the key of one direction.
pub const FRAME_KEY_LEN: usize = 32;

/// The frame length which goes ahead of every frame on the wire.
pub const FRAME_LEN_SIZE: usize = 4;

/// What sealing adds to a frame: the tag which tells a frame changed on the way - or sealed with
/// another key, or out of its turn - from the one which was sent.
pub const FRAME_TAG_LEN: usize = 16;

/// Bytes sealed with one key before the next one is derived from it. Both ends count the same
/// frames, so they change the key behind the same frame and nothing travels to say so.
const REKEY_AFTER_BYTES: u64 = 64 * 1024 * 1024 * 1024;

const REKEY_INFO: &[u8] = b"gateway-rekey-v2";

/// The keys of a gateway connection, one per direction. The nonce of a frame is its number in
/// its direction - with a key of its own each direction counts from zero, and a nonce never
/// repeats under a key.
pub struct SessionKeys {
    client_to_server: Zeroizing<[u8; FRAME_KEY_LEN]>,
    server_to_client: Zeroizing<[u8; FRAME_KEY_LEN]>,
}

impl SessionKeys {
    pub fn new(key_material: &[u8; 2 * FRAME_KEY_LEN]) -> Self {
        let mut client_to_server = Zeroizing::new([0u8; FRAME_KEY_LEN]);
        let mut server_to_client = Zeroizing::new([0u8; FRAME_KEY_LEN]);
        client_to_server.copy_from_slice(&key_material[..FRAME_KEY_LEN]);
        server_to_client.copy_from_slice(&key_material[FRAME_KEY_LEN..]);

        Self {
            client_to_server,
            server_to_client,
        }
    }

    /// What the client seals its frames with, and what it opens the server's frames with.
    pub fn into_client_ends(self) -> (FrameSealer, FrameOpener) {
        (
            FrameSealer::new(self.client_to_server),
            FrameOpener::new(self.server_to_client),
        )
    }

    /// What the server seals its frames with, and what it opens the client's frames with.
    pub fn into_server_ends(self) -> (FrameSealer, FrameOpener) {
        (
            FrameSealer::new(self.server_to_client),
            FrameOpener::new(self.client_to_server),
        )
    }
}

/// The key of one direction, and how far the direction has got under it. The sealing end and
/// the opening end keep one each and move them in step.
struct DirectionKey {
    key_bytes: Zeroizing<[u8; FRAME_KEY_LEN]>,
    key: LessSafeKey,
    /// The number of the next frame under this key - its nonce.
    frame_no: u64,
    /// Bytes of the frames which went under this key.
    bytes: u64,
    rekey_after: u64,
}

impl DirectionKey {
    fn new(key_bytes: Zeroizing<[u8; FRAME_KEY_LEN]>, rekey_after: u64) -> Self {
        let key = UnboundKey::new(&AES_256_GCM, key_bytes.as_ref())
            .expect("an AES-256-GCM key is 32 bytes");

        Self {
            key_bytes,
            key: LessSafeKey::new(key),
            frame_no: 0,
            bytes: 0,
            rekey_after,
        }
    }

    fn nonce(&self) -> Nonce {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[NONCE_LEN - 8..].copy_from_slice(&self.frame_no.to_be_bytes());
        Nonce::assume_unique_for_key(nonce)
    }

    /// A frame of `frame_len` bytes went under the key.
    fn frame_done(&mut self, frame_len: usize) {
        self.frame_no += 1;
        self.bytes += frame_len as u64;

        if self.bytes >= self.rekey_after {
            let mut next = Zeroizing::new([0u8; FRAME_KEY_LEN]);
            hkdf::Hkdf::<Sha256>::new(None, self.key_bytes.as_ref())
                .expand(REKEY_INFO, next.as_mut())
                .expect("HKDF: 32 bytes is within Sha256 output limit");

            *self = Self::new(next, self.rekey_after);
        }
    }
}

/// Seals the frames of one direction, in the order they go to the socket.
pub struct FrameSealer {
    direction: DirectionKey,
}

impl FrameSealer {
    pub fn new(key: Zeroizing<[u8; FRAME_KEY_LEN]>) -> Self {
        Self {
            direction: DirectionKey::new(key, REKEY_AFTER_BYTES),
        }
    }

    /// Seals the last frame of `wire` in place - the one which begins at `frame_at`, behind the
    /// frames sealed before it: `[4 bytes for the length][plaintext]` becomes
    /// `[u32 LEN][ciphertext][tag]`.
    pub fn seal_last(&mut self, wire: &mut Vec<u8>, frame_at: usize) -> Result<(), String> {
        let plaintext_at = frame_at + FRAME_LEN_SIZE;
        debug_assert!(wire.len() >= plaintext_at);

        let tag = self
            .direction
            .key
            .seal_in_place_separate_tag(
                self.direction.nonce(),
                Aad::empty(),
                &mut wire[plaintext_at..],
            )
            .map_err(|_| "A gateway frame can not be sealed".to_string())?;

        wire.extend_from_slice(tag.as_ref());

        let frame_len = wire.len() - plaintext_at;
        let frame_len_on_the_wire = u32::try_from(frame_len)
            .map_err(|_| format!("A gateway frame of {frame_len} bytes has no length to send"))?;
        wire[frame_at..plaintext_at].copy_from_slice(&frame_len_on_the_wire.to_le_bytes());

        self.direction.frame_done(frame_len);

        Ok(())
    }
}

/// Opens the frames of one direction, in the order they come off the socket. A frame which is
/// not the next one the other end sealed - changed, replayed, out of its turn - does not open.
pub struct FrameOpener {
    direction: DirectionKey,
}

impl FrameOpener {
    pub fn new(key: Zeroizing<[u8; FRAME_KEY_LEN]>) -> Self {
        Self {
            direction: DirectionKey::new(key, REKEY_AFTER_BYTES),
        }
    }

    /// Opens a frame in place - what came behind its length: `[ciphertext][tag]`. The plaintext
    /// is the beginning of `frame`; its size is returned.
    pub fn open(&mut self, frame: &mut [u8]) -> Result<usize, String> {
        let frame_len = frame.len();

        let plain_len = self
            .direction
            .key
            .open_in_place(self.direction.nonce(), Aad::empty(), frame)
            .map_err(|_| {
                "A gateway frame does not open: it is not what the peer sealed".to_string()
            })?
            .len();

        self.direction.frame_done(frame_len);

        Ok(plain_len)
    }
}

#[cfg(test)]
impl FrameSealer {
    pub(crate) fn for_tests(key: [u8; FRAME_KEY_LEN]) -> Self {
        Self::new(Zeroizing::new(key))
    }

    /// Seals `wire`, which holds one frame: `[4 bytes for the length][plaintext]`.
    pub(crate) fn seal(&mut self, wire: &mut Vec<u8>) -> Result<(), String> {
        self.seal_last(wire, 0)
    }

    fn with_rekey_after(key: [u8; FRAME_KEY_LEN], rekey_after: u64) -> Self {
        Self {
            direction: DirectionKey::new(Zeroizing::new(key), rekey_after),
        }
    }
}

#[cfg(test)]
impl FrameOpener {
    pub(crate) fn for_tests(key: [u8; FRAME_KEY_LEN]) -> Self {
        Self::new(Zeroizing::new(key))
    }

    fn with_rekey_after(key: [u8; FRAME_KEY_LEN], rekey_after: u64) -> Self {
        Self {
            direction: DirectionKey::new(Zeroizing::new(key), rekey_after),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; FRAME_KEY_LEN] = [7u8; FRAME_KEY_LEN];

    fn sealed(sealer: &mut FrameSealer, plaintext: &[u8]) -> Vec<u8> {
        let mut wire = vec![0u8; FRAME_LEN_SIZE];
        wire.extend_from_slice(plaintext);
        sealer.seal(&mut wire).unwrap();
        wire
    }

    fn opened(opener: &mut FrameOpener, wire: &[u8]) -> Result<Vec<u8>, String> {
        let mut frame = wire[FRAME_LEN_SIZE..].to_vec();
        let plain_len = opener.open(&mut frame)?;
        frame.truncate(plain_len);
        Ok(frame)
    }

    #[test]
    fn a_sealed_frame_opens_to_what_was_sealed() {
        let mut sealer = FrameSealer::for_tests(KEY);
        let mut opener = FrameOpener::for_tests(KEY);

        for plaintext in [&b"x"[..], b"a frame", &[9u8; 300_000]] {
            let wire = sealed(&mut sealer, plaintext);

            let frame_len = u32::from_le_bytes(wire[..FRAME_LEN_SIZE].try_into().unwrap()) as usize;
            assert_eq!(frame_len, plaintext.len() + FRAME_TAG_LEN);
            assert_eq!(wire.len(), FRAME_LEN_SIZE + frame_len);

            assert_eq!(opened(&mut opener, &wire).unwrap(), plaintext);
        }
    }

    #[test]
    fn the_same_frame_never_looks_the_same_on_the_wire() {
        let mut sealer = FrameSealer::for_tests(KEY);

        let first = sealed(&mut sealer, b"ping");
        let second = sealed(&mut sealer, b"ping");

        assert_ne!(first, second);
    }

    #[test]
    fn a_changed_frame_does_not_open() {
        let mut sealer = FrameSealer::for_tests(KEY);

        let wire = sealed(&mut sealer, &[5u8; 1000]);

        for changed_at in [FRAME_LEN_SIZE, FRAME_LEN_SIZE + 500, wire.len() - 1] {
            let mut changed = wire.clone();
            changed[changed_at] ^= 1;

            let mut opener = FrameOpener::for_tests(KEY);
            assert!(opened(&mut opener, &changed).is_err());
        }

        // Cut short: the tag is not where it was.
        let mut opener = FrameOpener::for_tests(KEY);
        assert!(opened(&mut opener, &wire[..wire.len() - 1]).is_err());

        // Too short to hold a tag at all.
        let mut opener = FrameOpener::for_tests(KEY);
        assert!(opener.open(&mut [0u8; FRAME_TAG_LEN - 1]).is_err());
    }

    #[test]
    fn a_frame_opens_only_in_its_turn() {
        let mut sealer = FrameSealer::for_tests(KEY);
        let first = sealed(&mut sealer, b"first");
        let second = sealed(&mut sealer, b"second");

        // Out of its turn.
        let mut opener = FrameOpener::for_tests(KEY);
        assert!(opened(&mut opener, &second).is_err());

        // Replayed.
        let mut opener = FrameOpener::for_tests(KEY);
        assert_eq!(opened(&mut opener, &first).unwrap(), b"first");
        assert!(opened(&mut opener, &first).is_err());
    }

    #[test]
    fn a_frame_of_the_other_direction_does_not_open() {
        let mut material = [0u8; 2 * FRAME_KEY_LEN];
        material[..FRAME_KEY_LEN].fill(1);
        material[FRAME_KEY_LEN..].fill(2);

        let (mut client_sealer, mut client_opener) = SessionKeys::new(&material).into_client_ends();
        let (mut server_sealer, mut server_opener) = SessionKeys::new(&material).into_server_ends();

        let from_client = sealed(&mut client_sealer, b"from the client");
        let from_server = sealed(&mut server_sealer, b"from the server");

        // Sent back to where it came from.
        assert!(opened(&mut client_opener, &from_client).is_err());

        assert_eq!(
            opened(&mut server_opener, &from_client).unwrap(),
            b"from the client"
        );
        assert_eq!(
            opened(&mut client_opener, &from_server).unwrap(),
            b"from the server"
        );
    }

    #[test]
    fn both_ends_change_the_key_behind_the_same_frame() {
        // Every third frame of 100 bytes goes past the limit.
        const REKEY_AFTER: u64 = 300;

        let mut sealer = FrameSealer::with_rekey_after(KEY, REKEY_AFTER);
        let mut opener = FrameOpener::with_rekey_after(KEY, REKEY_AFTER);

        // An end which never changes the key loses the stream at the first frame behind the change.
        let mut stale = FrameOpener::for_tests(KEY);
        let mut stale_failed_at = None;

        for frame_no in 0..20u8 {
            let plaintext = [frame_no; 100 - FRAME_TAG_LEN];
            let wire = sealed(&mut sealer, &plaintext);

            assert_eq!(opened(&mut opener, &wire).unwrap(), plaintext);

            if stale_failed_at.is_none() && opened(&mut stale, &wire).is_err() {
                stale_failed_at = Some(frame_no);
            }
        }

        assert_eq!(stale_failed_at, Some(3));
    }

    /// The key itself changes - to what the document says - and not only the count of the frames:
    /// the same plaintext under the same nonce looks different on the wire only under another key.
    #[test]
    fn the_next_key_is_derived_from_the_current_one() {
        const REKEY_AFTER: u64 = 300;

        let mut sealer = FrameSealer::with_rekey_after(KEY, REKEY_AFTER);
        let plaintext = [1u8; 100 - FRAME_TAG_LEN];

        let first = sealed(&mut sealer, &plaintext);
        sealed(&mut sealer, &plaintext);
        sealed(&mut sealer, &plaintext);
        // The first frame behind the change: its nonce is 0 again.
        let behind = sealed(&mut sealer, &plaintext);

        assert_ne!(first, behind);
        assert!(opened(&mut FrameOpener::for_tests(KEY), &behind).is_err());

        // docs/gateway-protocol.md: HKDF-SHA256(ikm = key, info = "gateway-rekey-v2"), 32 bytes.
        let mut next = [0u8; FRAME_KEY_LEN];
        hkdf::Hkdf::<Sha256>::new(None, &KEY)
            .expand(b"gateway-rekey-v2", &mut next)
            .unwrap();

        assert_eq!(
            opened(&mut FrameOpener::for_tests(next), &behind).unwrap(),
            plaintext
        );
    }

    /// Frames of every size against a limit which falls inside a frame: both ends count the same
    /// bytes - the frame as it is on the wire behind its length - and stay in step over many
    /// changes of the key.
    #[test]
    fn frames_of_any_size_keep_both_ends_in_step() {
        const REKEY_AFTER: u64 = 1000;

        let mut sealer = FrameSealer::with_rekey_after(KEY, REKEY_AFTER);
        let mut opener = FrameOpener::with_rekey_after(KEY, REKEY_AFTER);

        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        for frame_no in 0..3000u32 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let plaintext = vec![frame_no as u8; 1 + (state % 700) as usize];

            let wire = sealed(&mut sealer, &plaintext);
            assert_eq!(
                opened(&mut opener, &wire).unwrap(),
                plaintext,
                "frame {frame_no}"
            );
        }
    }

    /// Over several changes of the key no frame looks like one before it: neither a key nor a
    /// nonce under it comes back.
    #[test]
    fn nothing_repeats_on_the_wire_across_the_changes_of_the_key() {
        const REKEY_AFTER: u64 = 300;

        let mut sealer = FrameSealer::with_rekey_after(KEY, REKEY_AFTER);
        let plaintext = [1u8; 100 - FRAME_TAG_LEN];

        let mut seen = std::collections::HashSet::new();
        for frame_no in 0..30 {
            assert!(
                seen.insert(sealed(&mut sealer, &plaintext)),
                "frame {frame_no} repeats an earlier one"
            );
        }
    }

    #[test]
    fn frames_are_sealed_one_behind_another_in_one_buffer() {
        let mut sealer = FrameSealer::for_tests(KEY);
        let mut opener = FrameOpener::for_tests(KEY);

        let mut wire = vec![0u8; FRAME_LEN_SIZE];
        wire.extend_from_slice(b"first");
        sealer.seal_last(&mut wire, 0).unwrap();

        let second_at = wire.len();
        wire.extend_from_slice(&[0u8; FRAME_LEN_SIZE]);
        wire.extend_from_slice(b"the second one");
        sealer.seal_last(&mut wire, second_at).unwrap();

        assert_eq!(opened(&mut opener, &wire[..second_at]).unwrap(), b"first");
        assert_eq!(
            opened(&mut opener, &wire[second_at..]).unwrap(),
            b"the second one"
        );
    }
}

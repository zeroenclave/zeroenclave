//! Object files (vault-format §4) with a per-object data key (crypto §8.1).

use std::io::{Read, Seek, SeekFrom, Write};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::kdf::labels;
use crate::keys::{Dek, VaultKey};
use crate::rng::{self, OsRandom, RandomSource};
use crate::stream::{StreamDecryptor, StreamEncryptor, CHUNK_SIZE, NONCE_PREFIX_LEN};

const MAGIC: &[u8; 4] = b"ZENO";
const VERSION: u16 = 1;
const PREFIX_LEN: usize = 51;
const NONCE_LEN: usize = 12;
const WRAPPED_DEK_LEN: usize = 48;
const HEADER_LEN: usize = 111;

/// Object kind byte. `0x03` (snapshot) is reserved and rejected for now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    Blob = 0x01,
    Journal = 0x02,
}

impl ObjectKind {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Blob),
            0x02 => Some(Self::Journal),
            _ => None,
        }
    }
}

fn vault_cipher(vk: &VaultKey) -> Aes256Gcm {
    Aes256Gcm::new(&Key::<Aes256Gcm>::from(*vk.as_bytes()))
}

/// `LABEL("dek") || header[0..51]`.
fn dek_aad(prefix: &[u8]) -> Vec<u8> {
    let mut aad = labels::DEK.to_vec();
    aad.extend_from_slice(prefix);
    aad
}

/// Writes a new object; the header is written immediately.
pub fn write_object<W: Write>(
    w: W,
    vk: &VaultKey,
    vault_id: [u8; 16],
    object_id: [u8; 16],
    kind: ObjectKind,
) -> Result<ObjectWriter<W>> {
    write_object_with(w, vk, vault_id, object_id, kind, &mut OsRandom)
}

/// Random draw order: dek, dek_nonce, nonce_prefix.
pub fn write_object_with<W: Write>(
    mut w: W,
    vk: &VaultKey,
    vault_id: [u8; 16],
    object_id: [u8; 16],
    kind: ObjectKind,
    rng: &mut impl RandomSource,
) -> Result<ObjectWriter<W>> {
    let dek = Dek::from_bytes(rng::array::<32>(rng)?);
    let dek_nonce = rng::array::<NONCE_LEN>(rng)?;
    let nonce_prefix = rng::array::<NONCE_PREFIX_LEN>(rng)?;

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&VERSION.to_be_bytes());
    header.push(kind as u8);
    header.push(0);
    header.extend_from_slice(&vault_id);
    header.extend_from_slice(&object_id);
    header.extend_from_slice(&(CHUNK_SIZE as u32).to_be_bytes());
    header.extend_from_slice(&nonce_prefix);
    debug_assert_eq!(header.len(), PREFIX_LEN);

    let wrapped = vault_cipher(vk)
        .encrypt(
            &Nonce::from(dek_nonce),
            Payload {
                msg: dek.as_bytes(),
                aad: &dek_aad(&header),
            },
        )
        .map_err(|_| Error::Crypto)?;
    debug_assert_eq!(wrapped.len(), WRAPPED_DEK_LEN);
    header.extend_from_slice(&dek_nonce);
    header.extend_from_slice(&wrapped);
    debug_assert_eq!(header.len(), HEADER_LEN);

    let header_hash: [u8; 32] = Sha256::digest(&header).into();
    w.write_all(&header).map_err(|_| Error::Io)?;
    Ok(ObjectWriter {
        enc: StreamEncryptor::new(w, &dek, nonce_prefix, header_hash),
    })
}

pub struct ObjectWriter<W: Write> {
    enc: StreamEncryptor<W>,
}

impl<W: Write> ObjectWriter<W> {
    pub fn write_all(&mut self, data: &[u8]) -> Result<()> {
        self.enc.write_all(data)
    }

    /// Seals the final chunk and returns the writer.
    pub fn finish(self) -> Result<W> {
        self.enc.finish()
    }
}

/// Parses and validates the header, unwraps the data key and opens the body.
///
/// The reader is rewound to the start. `expected_object_id` is `None` for
/// objects whose id is not bound to a file name.
pub fn open_object<R: Read + Seek>(
    mut r: R,
    vk: &VaultKey,
    expected_vault_id: [u8; 16],
    expected_object_id: Option<[u8; 16]>,
) -> Result<ObjectReader<R>> {
    let file_len = r.seek(SeekFrom::End(0)).map_err(|_| Error::Io)?;
    if file_len < HEADER_LEN as u64 {
        return Err(Error::ObjectFormat);
    }
    r.seek(SeekFrom::Start(0)).map_err(|_| Error::Io)?;
    let mut h = [0u8; HEADER_LEN];
    r.read_exact(&mut h).map_err(|_| Error::Io)?;

    if &h[0..4] != MAGIC || u16::from_be_bytes([h[4], h[5]]) != VERSION {
        return Err(Error::ObjectFormat);
    }
    let kind = ObjectKind::from_byte(h[6]).ok_or(Error::ObjectFormat)?;
    if h[7] != 0 {
        return Err(Error::ObjectFormat);
    }
    if u32::from_be_bytes([h[40], h[41], h[42], h[43]]) as usize != CHUNK_SIZE {
        return Err(Error::ObjectFormat);
    }
    let vault_id: [u8; 16] = h[8..24].try_into().unwrap();
    let object_id: [u8; 16] = h[24..40].try_into().unwrap();
    if vault_id != expected_vault_id || expected_object_id.is_some_and(|e| e != object_id) {
        return Err(Error::ObjectMismatch);
    }
    let nonce_prefix: [u8; NONCE_PREFIX_LEN] = h[44..51].try_into().unwrap();
    let dek_nonce: [u8; NONCE_LEN] = h[51..63].try_into().unwrap();

    let pt = Zeroizing::new(
        vault_cipher(vk)
            .decrypt(
                &Nonce::from(dek_nonce),
                Payload {
                    msg: &h[63..],
                    aad: &dek_aad(&h[..PREFIX_LEN]),
                },
            )
            .map_err(|_| Error::Corrupt)?,
    );
    let dek = Dek::from_bytes(pt.as_slice().try_into().map_err(|_| Error::Corrupt)?);

    let header_hash: [u8; 32] = Sha256::digest(h).into();
    let body_len = file_len - HEADER_LEN as u64;
    let dec = StreamDecryptor::new(
        r,
        &dek,
        nonce_prefix,
        header_hash,
        HEADER_LEN as u64,
        body_len,
    )?;
    Ok(ObjectReader {
        dec,
        kind,
        object_id,
    })
}

pub struct ObjectReader<R: Read + Seek> {
    dec: StreamDecryptor<R>,
    kind: ObjectKind,
    object_id: [u8; 16],
}

impl<R: Read + Seek> ObjectReader<R> {
    pub fn kind(&self) -> ObjectKind {
        self.kind
    }

    pub fn object_id(&self) -> [u8; 16] {
        self.object_id
    }

    pub fn plaintext_len(&self) -> u64 {
        self.dec.plaintext_len()
    }

    pub fn read_chunk(&mut self, i: u64) -> Result<Zeroizing<Vec<u8>>> {
        self.dec.read_chunk(i)
    }

    pub fn read_range(&mut self, offset: u64, len: u64) -> Result<Vec<u8>> {
        self.dec.read_range(offset, len)
    }

    pub fn read_all(&mut self) -> Result<Vec<u8>> {
        self.dec.read_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const VID: [u8; 16] = [0x11; 16];
    const OID: [u8; 16] = [0x22; 16];
    const CS: usize = CHUNK_SIZE;

    /// Deterministic non-cryptographic source for tests.
    struct Counter(u8);

    impl RandomSource for Counter {
        fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
            for b in buf {
                self.0 = self.0.wrapping_mul(31).wrapping_add(7);
                *b = self.0;
            }
            Ok(())
        }
    }

    fn vk(b: u8) -> VaultKey {
        VaultKey::from_bytes([b; 32])
    }

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn make(seed: u8, object_id: [u8; 16], kind: ObjectKind, pt: &[u8]) -> Vec<u8> {
        let mut w = write_object_with(Vec::new(), &vk(1), VID, object_id, kind, &mut Counter(seed))
            .unwrap();
        w.write_all(pt).unwrap();
        w.finish().unwrap()
    }

    fn open_with(file: Vec<u8>, key: u8, vid: [u8; 16], oid: Option<[u8; 16]>) -> Result<Vec<u8>> {
        open_object(Cursor::new(file), &vk(key), vid, oid)?.read_all()
    }

    fn open_ok(file: Vec<u8>) -> Result<Vec<u8>> {
        open_with(file, 1, VID, Some(OID))
    }

    #[test]
    fn round_trip_lengths() {
        for len in [0, 1, CS - 1, CS, CS + 1, 2 * CS + 17] {
            let pt = data(len);
            let file = make(3, OID, ObjectKind::Blob, &pt);
            assert_eq!(file[..4], *b"ZENO");
            let mut r = open_object(Cursor::new(file), &vk(1), VID, Some(OID)).unwrap();
            assert_eq!(r.kind(), ObjectKind::Blob);
            assert_eq!(r.object_id(), OID);
            assert_eq!(r.plaintext_len(), len as u64);
            assert_eq!(r.read_all().unwrap(), pt, "len {len}");
        }
    }

    #[test]
    fn empty_object_size() {
        assert_eq!(make(3, OID, ObjectKind::Blob, &[]).len(), HEADER_LEN + 16);
    }

    #[test]
    fn journal_kind_and_no_object_id_check() {
        let file = make(3, OID, ObjectKind::Journal, b"abc");
        let mut r = open_object(Cursor::new(file), &vk(1), VID, None).unwrap();
        assert_eq!(r.kind(), ObjectKind::Journal);
        assert_eq!(r.read_all().unwrap(), b"abc");
    }

    #[test]
    fn read_range_and_chunk() {
        let pt = data(CS + 100);
        let file = make(3, OID, ObjectKind::Blob, &pt);
        let mut r = open_object(Cursor::new(file), &vk(1), VID, Some(OID)).unwrap();
        let off = CS - 4;
        assert_eq!(r.read_range(off as u64, 8).unwrap(), pt[off..off + 8]);
        assert_eq!(
            r.read_range(pt.len() as u64 - 3, 3).unwrap(),
            pt[pt.len() - 3..]
        );
        assert_eq!(r.read_range(pt.len() as u64 - 3, 4), Err(Error::OutOfRange));
        assert_eq!(*r.read_chunk(1).unwrap(), pt[CS..]);
    }

    #[test]
    fn writes_are_randomised() {
        let a = make(3, OID, ObjectKind::Blob, b"x");
        let b = make(4, OID, ObjectKind::Blob, b"x");
        assert_ne!(a[44..], b[44..]);
    }

    #[test]
    fn wrong_vault_key_fails() {
        let file = make(3, OID, ObjectKind::Blob, b"abc");
        assert_eq!(open_with(file, 2, VID, Some(OID)), Err(Error::Corrupt));
    }

    #[test]
    fn id_mismatch_is_rejected() {
        let file = make(3, OID, ObjectKind::Blob, b"abc");
        assert_eq!(
            open_with(file.clone(), 1, [0x33; 16], Some(OID)),
            Err(Error::ObjectMismatch)
        );
        assert_eq!(
            open_with(file, 1, VID, Some([0x33; 16])),
            Err(Error::ObjectMismatch)
        );
    }

    #[test]
    fn rewritten_ids_fail_dek_binding() {
        // Patching the ids to match the caller still breaks the wrapped key.
        let mut file = make(3, OID, ObjectKind::Blob, b"abc");
        file[24..40].copy_from_slice(&[0x33; 16]);
        assert_eq!(
            open_with(file, 1, VID, Some([0x33; 16])),
            Err(Error::Corrupt)
        );
    }

    #[test]
    fn header_reject_paths() {
        let good = make(3, OID, ObjectKind::Blob, b"abc");
        let patch = |off: usize, val: &[u8]| {
            let mut f = good.clone();
            f[off..off + val.len()].copy_from_slice(val);
            f
        };
        let cases = [
            ("magic", patch(0, b"ZENX")),
            ("version", patch(4, &[0, 2])),
            ("kind 0", patch(6, &[0])),
            ("kind snapshot", patch(6, &[3])),
            ("kind other", patch(6, &[0x7F])),
            ("reserved", patch(7, &[1])),
            ("chunk size", patch(40, &(CS as u32 / 2).to_be_bytes())),
            ("short", good[..HEADER_LEN - 1].to_vec()),
            ("empty", Vec::new()),
        ];
        for (name, f) in cases {
            assert_eq!(open_ok(f), Err(Error::ObjectFormat), "{name}");
        }
        // Header only: no chunk at all.
        assert_eq!(open_ok(good[..HEADER_LEN].to_vec()), Err(Error::Corrupt));
    }

    #[test]
    fn bit_flips_fail() {
        let file = make(3, OID, ObjectKind::Blob, &data(CS + 5));
        let positions = [
            0,
            5,
            6,
            7,
            12,
            30,
            41,
            46,
            55,
            80,
            HEADER_LEN - 1,
            HEADER_LEN,
            HEADER_LEN + 500,
            HEADER_LEN + CS + 16,
            file.len() - 1,
        ];
        for pos in positions {
            let mut bad = file.clone();
            bad[pos] ^= 0x01;
            assert!(open_ok(bad).is_err(), "pos {pos}");
        }
    }

    #[test]
    fn structural_attacks_fail() {
        let file = make(3, OID, ObjectKind::Blob, &data(CS + 5));
        let sealed = CS + 16;
        let first = file[HEADER_LEN..HEADER_LEN + sealed].to_vec();

        let truncated = file[..HEADER_LEN + sealed].to_vec();
        assert_eq!(open_ok(truncated), Err(Error::Corrupt));

        let mut appended = file.clone();
        appended.extend_from_slice(&first);
        assert_eq!(open_ok(appended), Err(Error::Corrupt));

        let mut dropped_first = file[..HEADER_LEN].to_vec();
        dropped_first.extend_from_slice(&file[HEADER_LEN + sealed..]);
        assert_eq!(open_ok(dropped_first), Err(Error::Corrupt));
    }

    #[test]
    fn swapped_chunks_fail() {
        let mut file = make(3, OID, ObjectKind::Blob, &data(2 * CS + 17));
        let sealed = CS + 16;
        let a = file[HEADER_LEN..HEADER_LEN + sealed].to_vec();
        let b = file[HEADER_LEN + sealed..HEADER_LEN + 2 * sealed].to_vec();
        file[HEADER_LEN..HEADER_LEN + sealed].copy_from_slice(&b);
        file[HEADER_LEN + sealed..HEADER_LEN + 2 * sealed].copy_from_slice(&a);
        assert_eq!(open_ok(file), Err(Error::Corrupt));
    }

    #[test]
    fn chunk_from_other_object_fails() {
        let pt = data(CS + 5);
        let mut file = make(3, OID, ObjectKind::Blob, &pt);
        let other = make(4, OID, ObjectKind::Blob, &pt);
        let sealed = CS + 16;
        file[HEADER_LEN..HEADER_LEN + sealed]
            .copy_from_slice(&other[HEADER_LEN..HEADER_LEN + sealed]);
        assert_eq!(open_ok(file), Err(Error::Corrupt));
    }

    #[test]
    fn header_swap_between_objects_fails() {
        let pt = data(40);
        let mut file = make(3, OID, ObjectKind::Blob, &pt);
        let other = make(4, OID, ObjectKind::Blob, &pt);
        file[..HEADER_LEN].copy_from_slice(&other[..HEADER_LEN]);
        assert_eq!(open_ok(file), Err(Error::Corrupt));
    }
}

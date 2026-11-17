//! STREAM chunked AES-256-GCM (crypto §8.2, §8.3).

use std::io::{Read, Seek, SeekFrom, Write};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::keys::Dek;

pub const CHUNK_SIZE: usize = 1_048_576;
pub const TAG_LEN: usize = 16;
pub(crate) const NONCE_PREFIX_LEN: usize = 7;
const SEALED_CHUNK: u64 = (CHUNK_SIZE + TAG_LEN) as u64;
/// Chunk indices are u32, so at most 2^32 chunks.
const MAX_CHUNKS: u64 = 1 << 32;

fn cipher(dek: &Dek) -> Aes256Gcm {
    Aes256Gcm::new(&Key::<Aes256Gcm>::from(*dek.as_bytes()))
}

fn nonce(prefix: &[u8; NONCE_PREFIX_LEN], index: u64, last: bool) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    n[NONCE_PREFIX_LEN..11].copy_from_slice(&(index as u32).to_be_bytes());
    n[11] = u8::from(last);
    n
}

/// Encrypts a byte stream into sealed chunks (`ciphertext || tag`).
pub struct StreamEncryptor<W: Write> {
    writer: W,
    cipher: Aes256Gcm,
    prefix: [u8; NONCE_PREFIX_LEN],
    aad: [u8; 32],
    buf: Zeroizing<Vec<u8>>,
    index: u64,
}

impl<W: Write> StreamEncryptor<W> {
    pub fn new(
        writer: W,
        dek: &Dek,
        nonce_prefix: [u8; NONCE_PREFIX_LEN],
        header_hash: [u8; 32],
    ) -> Self {
        Self {
            writer,
            cipher: cipher(dek),
            prefix: nonce_prefix,
            aad: header_hash,
            buf: Zeroizing::new(Vec::with_capacity(CHUNK_SIZE)),
            index: 0,
        }
    }

    fn seal(&mut self, last: bool) -> Result<()> {
        // A non-last chunk needs a successor, so it must not take the last index.
        if self.index + u64::from(!last) >= MAX_CHUNKS {
            return Err(Error::TooLarge);
        }
        let ct = self
            .cipher
            .encrypt(
                &Nonce::from(nonce(&self.prefix, self.index, last)),
                Payload {
                    msg: &self.buf,
                    aad: &self.aad,
                },
            )
            .map_err(|_| Error::Crypto)?;
        self.writer.write_all(&ct).map_err(|_| Error::Io)?;
        self.index += 1;
        self.buf.clear();
        Ok(())
    }

    /// Buffers one chunk; a full chunk is sealed as non-last only once more data arrives.
    pub fn write_all(&mut self, mut data: &[u8]) -> Result<()> {
        while !data.is_empty() {
            if self.buf.len() == CHUNK_SIZE {
                self.seal(false)?;
            }
            let take = (CHUNK_SIZE - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
        }
        Ok(())
    }

    /// Seals the final chunk (possibly empty) and returns the writer.
    pub fn finish(mut self) -> Result<W> {
        self.seal(true)?;
        self.writer.flush().map_err(|_| Error::Io)?;
        Ok(self.writer)
    }
}

/// Random-access decryptor over a sealed body of `body_len` bytes at `body_offset`.
pub struct StreamDecryptor<R: Read + Seek> {
    reader: R,
    cipher: Aes256Gcm,
    prefix: [u8; NONCE_PREFIX_LEN],
    aad: [u8; 32],
    body_offset: u64,
    body_len: u64,
    chunks: u64,
}

impl<R: Read + Seek> StreamDecryptor<R> {
    pub fn new(
        reader: R,
        dek: &Dek,
        nonce_prefix: [u8; NONCE_PREFIX_LEN],
        header_hash: [u8; 32],
        body_offset: u64,
        body_len: u64,
    ) -> Result<Self> {
        let chunks = body_len.div_ceil(SEALED_CHUNK);
        if chunks == 0 || chunks > MAX_CHUNKS {
            return Err(Error::Corrupt);
        }
        let last_len = body_len - (chunks - 1) * SEALED_CHUNK;
        if last_len < TAG_LEN as u64 || (chunks > 1 && last_len == TAG_LEN as u64) {
            return Err(Error::Corrupt);
        }
        if body_offset.checked_add(body_len).is_none() {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            reader,
            cipher: cipher(dek),
            prefix: nonce_prefix,
            aad: header_hash,
            body_offset,
            body_len,
            chunks,
        })
    }

    pub fn plaintext_len(&self) -> u64 {
        self.body_len - self.chunks * TAG_LEN as u64
    }

    /// Decrypts and authenticates chunk `i`.
    pub fn read_chunk(&mut self, i: u64) -> Result<Zeroizing<Vec<u8>>> {
        if i >= self.chunks {
            return Err(Error::OutOfRange);
        }
        let start = i * SEALED_CHUNK;
        let len = (self.body_len - start).min(SEALED_CHUNK) as usize;
        self.reader
            .seek(SeekFrom::Start(self.body_offset + start))
            .map_err(|_| Error::Io)?;
        let mut ct = vec![0u8; len];
        self.reader.read_exact(&mut ct).map_err(|_| Error::Io)?;
        self.cipher
            .decrypt(
                &Nonce::from(nonce(&self.prefix, i, i == self.chunks - 1)),
                Payload {
                    msg: &ct,
                    aad: &self.aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| Error::Corrupt)
    }

    /// Reads `len` plaintext bytes at `offset`, spanning chunks as needed.
    pub fn read_range(&mut self, offset: u64, len: u64) -> Result<Vec<u8>> {
        let end = offset.checked_add(len).ok_or(Error::OutOfRange)?;
        if end > self.plaintext_len() {
            return Err(Error::OutOfRange);
        }
        let mut out = Vec::with_capacity(len as usize);
        let mut pos = offset;
        while pos < end {
            let chunk = self.read_chunk(pos / CHUNK_SIZE as u64)?;
            let from = (pos % CHUNK_SIZE as u64) as usize;
            let take = (chunk.len() - from).min((end - pos) as usize);
            out.extend_from_slice(&chunk[from..from + take]);
            pos += take as u64;
        }
        Ok(out)
    }

    /// Reads and authenticates the whole plaintext.
    pub fn read_all(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.plaintext_len() as usize);
        for i in 0..self.chunks {
            out.extend_from_slice(&self.read_chunk(i)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_key_schedule_is_wiped_on_drop() {
        fn wiped<T: zeroize::ZeroizeOnDrop>() {}
        wiped::<aes::Aes256>();
    }
    use std::io::Cursor;

    const PREFIX: [u8; 7] = [1, 2, 3, 4, 5, 6, 7];
    const HASH: [u8; 32] = [9; 32];
    const CS: usize = CHUNK_SIZE;
    const SEALED: usize = CS + TAG_LEN;

    fn dek(b: u8) -> Dek {
        Dek::from_bytes([b; 32])
    }

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn seal_with(d: &Dek, hash: [u8; 32], pt: &[u8]) -> Vec<u8> {
        let mut e = StreamEncryptor::new(Vec::new(), d, PREFIX, hash);
        // Uneven writes exercise the buffering.
        for part in pt.chunks(300_001) {
            e.write_all(part).unwrap();
        }
        e.finish().unwrap()
    }

    fn seal(pt: &[u8]) -> Vec<u8> {
        seal_with(&dek(1), HASH, pt)
    }

    fn open(ct: Vec<u8>) -> Result<StreamDecryptor<Cursor<Vec<u8>>>> {
        let len = ct.len() as u64;
        StreamDecryptor::new(Cursor::new(ct), &dek(1), PREFIX, HASH, 0, len)
    }

    fn open_all(ct: Vec<u8>) -> Result<Vec<u8>> {
        open(ct)?.read_all()
    }

    #[test]
    fn round_trip_lengths() {
        for len in [0, 1, CS - 1, CS, CS + 1, 2 * CS + 17] {
            let pt = data(len);
            let ct = seal(&pt);
            let chunks = len.div_ceil(CS).max(1);
            assert_eq!(ct.len(), len + chunks * TAG_LEN, "len {len}");
            let mut d = open(ct).unwrap();
            assert_eq!(d.plaintext_len(), len as u64);
            assert_eq!(d.read_all().unwrap(), pt, "len {len}");
        }
    }

    #[test]
    fn empty_plaintext_is_one_tag() {
        assert_eq!(seal(&[]).len(), TAG_LEN);
    }

    #[test]
    fn body_offset_is_honoured() {
        let pt = data(CS + 3);
        let mut file = vec![0xEE; 111];
        file.extend_from_slice(&seal(&pt));
        let len = file.len() as u64 - 111;
        let mut d =
            StreamDecryptor::new(Cursor::new(file), &dek(1), PREFIX, HASH, 111, len).unwrap();
        assert_eq!(d.read_all().unwrap(), pt);
    }

    #[test]
    fn read_range_spans_chunks() {
        let pt = data(2 * CS + 17);
        let mut d = open(seal(&pt)).unwrap();
        let cases = [
            (0u64, 0u64),
            (0, 10),
            (CS as u64 - 5, 10),
            (CS as u64, 1),
            (CS as u64 - 1, CS as u64 + 2),
            (2 * CS as u64 + 10, 7),
            (0, pt.len() as u64),
        ];
        for (off, len) in cases {
            let got = d.read_range(off, len).unwrap();
            assert_eq!(got, pt[off as usize..(off + len) as usize], "{off}+{len}");
        }
        assert_eq!(d.read_range(pt.len() as u64, 0).unwrap(), Vec::<u8>::new());
        assert_eq!(d.read_range(pt.len() as u64 - 3, 4), Err(Error::OutOfRange));
        assert_eq!(d.read_range(u64::MAX, 2), Err(Error::OutOfRange));
        assert_eq!(d.read_chunk(3).unwrap_err(), Error::OutOfRange);
    }

    #[test]
    fn truncation_at_chunk_boundary_fails() {
        let ct = seal(&data(2 * CS + 17));
        assert_eq!(open_all(ct[..SEALED].to_vec()), Err(Error::Corrupt));
        assert_eq!(open_all(ct[..2 * SEALED].to_vec()), Err(Error::Corrupt));
    }

    #[test]
    fn dropping_last_chunk_fails() {
        let ct = seal(&data(CS + 5));
        assert_eq!(open_all(ct[..SEALED].to_vec()), Err(Error::Corrupt));
    }

    #[test]
    fn truncation_inside_chunk_fails() {
        let ct = seal(&data(40));
        assert_eq!(open_all(ct[..ct.len() - 1].to_vec()), Err(Error::Corrupt));
        assert_eq!(open_all(ct[..TAG_LEN - 1].to_vec()), Err(Error::Corrupt));
        assert_eq!(open_all(Vec::new()), Err(Error::Corrupt));
    }

    #[test]
    fn appended_chunk_fails() {
        let mut ct = seal(&data(CS));
        let extra = ct.clone();
        ct.extend_from_slice(&extra);
        assert_eq!(open_all(ct), Err(Error::Corrupt));
    }

    #[test]
    fn appended_empty_chunk_is_rejected() {
        let mut ct = seal(&data(CS));
        ct.extend_from_slice(&[0u8; TAG_LEN]);
        assert_eq!(open(ct).err(), Some(Error::Corrupt));
    }

    #[test]
    fn swapped_chunks_fail() {
        let mut ct = seal(&data(2 * CS + 17));
        let (a, b) = (ct[..SEALED].to_vec(), ct[SEALED..2 * SEALED].to_vec());
        ct[..SEALED].copy_from_slice(&b);
        ct[SEALED..2 * SEALED].copy_from_slice(&a);
        let mut d = open(ct).unwrap();
        assert_eq!(d.read_chunk(0).unwrap_err(), Error::Corrupt);
        assert_eq!(d.read_chunk(1).unwrap_err(), Error::Corrupt);
        assert_eq!(d.read_all(), Err(Error::Corrupt));
    }

    #[test]
    fn chunk_from_other_stream_fails() {
        let pt = data(CS + 5);
        let mut ct = seal(&pt);
        let other_key = seal_with(&dek(2), HASH, &pt);
        let other_hash = seal_with(&dek(1), [8; 32], &pt);
        for other in [other_key, other_hash] {
            let mut forged = ct.clone();
            forged[..SEALED].copy_from_slice(&other[..SEALED]);
            assert_eq!(open_all(forged), Err(Error::Corrupt));
        }
        ct[0] ^= 1;
        assert_eq!(open_all(ct), Err(Error::Corrupt));
    }

    #[test]
    fn bit_flips_fail() {
        let ct = seal(&data(CS + 5));
        for pos in [
            0,
            1,
            100,
            CS - 1,
            CS,
            CS + 15,
            SEALED,
            SEALED + 3,
            ct.len() - 1,
        ] {
            let mut bad = ct.clone();
            bad[pos] ^= 0x40;
            assert_eq!(open_all(bad), Err(Error::Corrupt), "pos {pos}");
        }
    }

    #[test]
    fn wrong_key_prefix_or_hash_fails() {
        let ct = seal(&data(100));
        let len = ct.len() as u64;
        let args = [
            (dek(2), PREFIX, HASH),
            (dek(1), [0; 7], HASH),
            (dek(1), PREFIX, [0; 32]),
        ];
        for (k, p, h) in args {
            let mut d = StreamDecryptor::new(Cursor::new(ct.clone()), &k, p, h, 0, len).unwrap();
            assert_eq!(d.read_all(), Err(Error::Corrupt));
        }
    }

    #[test]
    fn chunk_limit_is_enforced() {
        let mut e = StreamEncryptor::new(Vec::new(), &dek(1), PREFIX, HASH);
        e.index = MAX_CHUNKS - 1;
        e.write_all(&[0; 10]).unwrap();
        // The last allowed index can still be sealed as the final chunk.
        let mut full = StreamEncryptor::new(Vec::new(), &dek(1), PREFIX, HASH);
        full.index = MAX_CHUNKS - 1;
        full.write_all(&vec![0; CS]).unwrap();
        assert_eq!(full.write_all(&[1]), Err(Error::TooLarge));
        e.index = MAX_CHUNKS;
        assert_eq!(e.finish().err(), Some(Error::TooLarge));
    }

    #[test]
    fn write_errors_map_to_io() {
        struct Fail;
        impl Write for Fail {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::Other.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let e = StreamEncryptor::new(Fail, &dek(1), PREFIX, HASH);
        assert_eq!(e.finish().err(), Some(Error::Io));
    }
}

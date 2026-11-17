use crate::error::{Error, Result};

/// Source of random bytes; injectable so tests and vectors can be deterministic.
pub trait RandomSource {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()>;
}

/// OS CSPRNG.
pub(crate) struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        fill(buf)
    }
}

pub(crate) fn fill(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| Error::Rng)
}

pub(crate) fn array<const N: usize>(rng: &mut impl RandomSource) -> Result<[u8; N]> {
    let mut out = [0u8; N];
    rng.fill(&mut out)?;
    Ok(out)
}

/// Deterministic stream for test vectors. Never use outside tests.
///
/// The stream is the concatenation of `SHA-256(seed || u64_be(counter))` for
/// `counter = 0, 1, 2, ...`. Every `fill` consumes the next bytes of that
/// stream; unused bytes of a block are kept for the following call.
#[cfg(feature = "test-vectors")]
pub struct SeededRandom {
    seed: Vec<u8>,
    counter: u64,
    block: [u8; 32],
    pos: usize,
}

#[cfg(feature = "test-vectors")]
impl SeededRandom {
    pub fn new(seed: &[u8]) -> Self {
        Self {
            seed: seed.to_vec(),
            counter: 0,
            block: [0; 32],
            pos: 32,
        }
    }
}

#[cfg(feature = "test-vectors")]
impl RandomSource for SeededRandom {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        use sha2::{Digest, Sha256};
        for b in buf.iter_mut() {
            if self.pos == 32 {
                let mut h = Sha256::new();
                h.update(&self.seed);
                h.update(self.counter.to_be_bytes());
                self.block = h.finalize().into();
                self.counter += 1;
                self.pos = 0;
            }
            *b = self.block[self.pos];
            self.pos += 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arrays_differ() {
        let a = array::<32>(&mut OsRandom).unwrap();
        let b = array::<32>(&mut OsRandom).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn fill_overwrites_buffer() {
        let mut buf = [0u8; 64];
        fill(&mut buf).unwrap();
        assert_ne!(buf, [0u8; 64]);
    }

    #[cfg(feature = "test-vectors")]
    #[test]
    fn seeded_stream_is_block_concatenation() {
        use sha2::{Digest, Sha256};
        let mut r = SeededRandom::new(b"seed");
        let mut got = [0u8; 70];
        // Split reads must not change the stream.
        r.fill(&mut got[..5]).unwrap();
        r.fill(&mut got[5..]).unwrap();
        let mut want = Vec::new();
        for c in 0u64..3 {
            let mut h = Sha256::new();
            h.update(b"seed");
            h.update(c.to_be_bytes());
            want.extend_from_slice(&h.finalize());
        }
        assert_eq!(&got[..], &want[..70]);
    }
}

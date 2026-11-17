use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::kdf::{hkdf32, labels};
use crate::keys::{key_type, Kek};
use crate::rng::{self, OsRandom, RandomSource};

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const KEY_LEN: usize = 32;
const CHECKSUM_LEN: usize = 3;
const PAYLOAD_LEN: usize = KEY_LEN + CHECKSUM_LEN;
const SYMBOLS: usize = PAYLOAD_LEN * 8 / 5;
const GROUP: usize = 4;

key_type!(
    /// 256-bit recovery key (spec §6.2).
    RecoveryKey
);

fn checksum(key: &[u8; KEY_LEN]) -> [u8; CHECKSUM_LEN] {
    let mut h = Sha256::new();
    h.update(labels::RECOVERY_CHECKSUM);
    h.update(key);
    let digest = h.finalize();
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&digest[..CHECKSUM_LEN]);
    out
}

/// Value of one Crockford symbol; accepts lowercase and maps I/L to 1, O to 0.
fn symbol_value(c: char) -> Result<u8> {
    let c = match c.to_ascii_uppercase() {
        'I' | 'L' => '1',
        'O' => '0',
        other => other,
    };
    if !c.is_ascii() {
        return Err(Error::RecoveryKeyFormat);
    }
    ALPHABET
        .iter()
        .position(|&a| a as char == c)
        .map(|i| i as u8)
        .ok_or(Error::RecoveryKeyFormat)
}

impl RecoveryKey {
    pub fn generate() -> Result<Self> {
        Self::generate_with(&mut OsRandom)
    }

    pub(crate) fn generate_with(rng: &mut impl RandomSource) -> Result<Self> {
        Ok(Self::from_bytes(rng::array::<KEY_LEN>(rng)?))
    }

    /// Crockford Base32 of `key || checksum`, 14 groups of 4 joined by `-`.
    pub fn encode(&self) -> Zeroizing<String> {
        let mut payload = Zeroizing::new([0u8; PAYLOAD_LEN]);
        payload[..KEY_LEN].copy_from_slice(self.as_bytes());
        payload[KEY_LEN..].copy_from_slice(&checksum(self.as_bytes()));

        let mut out = Zeroizing::new(String::with_capacity(SYMBOLS + SYMBOLS / GROUP - 1));
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        let mut in_group = 0usize;
        for &b in payload.iter() {
            acc = (acc << 8) | u32::from(b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                if in_group == GROUP {
                    out.push('-');
                    in_group = 0;
                }
                out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
                in_group += 1;
            }
            acc &= (1 << bits) - 1;
        }
        out
    }

    /// Parses the display format and verifies the checksum.
    pub fn decode(s: &str) -> Result<Self> {
        let mut syms = Zeroizing::new(Vec::<u8>::with_capacity(SYMBOLS));
        for c in s.chars() {
            if c == ' ' || c == '-' {
                continue;
            }
            if syms.len() == SYMBOLS {
                return Err(Error::RecoveryKeyFormat);
            }
            syms.push(symbol_value(c)?);
        }
        if syms.len() != SYMBOLS {
            return Err(Error::RecoveryKeyFormat);
        }

        let mut payload = Zeroizing::new([0u8; PAYLOAD_LEN]);
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        let mut n = 0usize;
        for &v in syms.iter() {
            acc = (acc << 5) | u32::from(v);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                payload[n] = (acc >> bits) as u8;
                n += 1;
                acc &= (1 << bits) - 1;
            }
        }

        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        key.copy_from_slice(&payload[..KEY_LEN]);
        let expected = checksum(&key);
        if !bool::from(payload[KEY_LEN..].ct_eq(&expected[..])) {
            return Err(Error::RecoveryKeyChecksum);
        }
        Ok(Self::from_bytes(*key))
    }
}

pub fn recovery_kek(rk: &RecoveryKey, vault_id: &[u8; 16]) -> Kek {
    Kek::from_bytes(*hkdf32(rk.as_bytes(), vault_id, labels::RECOVERY_KEK))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> RecoveryKey {
        RecoveryKey::from_bytes([b; 32])
    }

    #[test]
    fn encoded_shape() {
        let s = key(0x5A).encode();
        assert_eq!(s.len(), 56 + 13);
        let groups: Vec<&str> = s.split('-').collect();
        assert_eq!(groups.len(), 14);
        assert!(groups.iter().all(|g| g.len() == 4));
        assert!(s.bytes().all(|b| b == b'-' || ALPHABET.contains(&b)));
    }

    #[test]
    fn all_zero_key_starts_with_zeros() {
        let s = key(0).encode();
        assert!(s.starts_with("0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-"));
    }

    #[test]
    fn round_trip() {
        for b in [0u8, 0xFF, 0x5A, 0x01] {
            let k = key(b);
            let back = RecoveryKey::decode(&k.encode()).unwrap();
            assert_eq!(back.expose_for_test_vectors(), k.expose_for_test_vectors());
        }
        let k = RecoveryKey::generate().unwrap();
        let back = RecoveryKey::decode(&k.encode()).unwrap();
        assert_eq!(back.expose_for_test_vectors(), k.expose_for_test_vectors());
    }

    #[test]
    fn lenient_decoding() {
        let mut zero_subs = 0;
        let mut one_subs = 0;
        for b in 0..=255u8 {
            let k = key(b);
            let enc = k.encode();
            zero_subs += enc.matches('0').count();
            one_subs += enc.matches('1').count();
            let lower = enc.to_lowercase().replace('-', " ");
            let variants = [
                lower.clone(),
                lower.replace('0', "o"),
                enc.replace('0', "O"),
                lower.replace('1', "l"),
                enc.replace('1', "I"),
                enc.replace('-', ""),
                format!("  {}  ", *enc),
            ];
            for v in variants {
                let back = RecoveryKey::decode(&v).unwrap();
                assert_eq!(back.expose_for_test_vectors(), k.expose_for_test_vectors());
            }
        }
        assert!(zero_subs > 0 && one_subs > 0);
    }

    #[test]
    fn single_char_typo_is_checksum_error() {
        let enc = key(0x5A).encode();
        let chars: Vec<char> = enc.chars().collect();
        for i in (0..chars.len()).filter(|&i| chars[i] != '-') {
            let mut c = chars.clone();
            c[i] = if c[i] == '2' { '3' } else { '2' };
            let s: String = c.into_iter().collect();
            assert_eq!(
                RecoveryKey::decode(&s).unwrap_err(),
                Error::RecoveryKeyChecksum,
                "position {i}"
            );
        }
    }

    #[test]
    fn wrong_length_is_format_error() {
        let enc = key(0x5A).encode();
        assert_eq!(
            RecoveryKey::decode("").unwrap_err(),
            Error::RecoveryKeyFormat
        );
        assert_eq!(
            RecoveryKey::decode(&enc[..enc.len() - 1]).unwrap_err(),
            Error::RecoveryKeyFormat
        );
        assert_eq!(
            RecoveryKey::decode(&format!("{}2", *enc)).unwrap_err(),
            Error::RecoveryKeyFormat
        );
    }

    #[test]
    fn invalid_chars_are_format_errors() {
        let enc = key(0x5A).encode();
        for bad in ["U", "u", "#", "\u{e9}", "\u{ff21}", "\0"] {
            let s = format!("{bad}{}", &enc[1..]);
            assert_eq!(
                RecoveryKey::decode(&s).unwrap_err(),
                Error::RecoveryKeyFormat,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn debug_is_redacted() {
        let k = key(0xAB);
        let s = format!("{k:?}");
        assert_eq!(s, "RecoveryKey(redacted)");
        assert!(!s.to_lowercase().contains("abab"));
    }

    #[test]
    fn recovery_kek_depends_on_key_and_vault() {
        let a = recovery_kek(&key(1), &[1; 16]);
        let b = recovery_kek(&key(2), &[1; 16]);
        let c = recovery_kek(&key(1), &[2; 16]);
        assert_ne!(a.expose_for_test_vectors(), b.expose_for_test_vectors());
        assert_ne!(a.expose_for_test_vectors(), c.expose_for_test_vectors());
    }
}

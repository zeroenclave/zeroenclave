use subtle::ConstantTimeEq;

macro_rules! key_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(::zeroize::Zeroize, ::zeroize::ZeroizeOnDrop)]
        pub struct $name([u8; 32]);

        impl $name {
            #[allow(dead_code)]
            pub(crate) fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            pub(crate) fn from_bytes(b: [u8; 32]) -> Self {
                Self(b)
            }

            /// Test-only access to the raw key bytes.
            #[cfg(any(test, feature = "test-vectors"))]
            #[allow(dead_code)]
            pub fn expose_for_test_vectors(&self) -> &[u8; 32] {
                &self.0
            }

            /// Test-only constructor for fixed vector inputs.
            #[cfg(feature = "test-vectors")]
            #[allow(dead_code)]
            pub fn from_bytes_for_test_vectors(b: [u8; 32]) -> Self {
                Self(b)
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), "(redacted)"))
            }
        }
    };
}

pub(crate) use key_type;

key_type!(
    /// Argon2id output; never stored.
    MasterKey
);
key_type!(
    /// Key-encryption key derived from a secret; wraps the vault key in a slot.
    Kek
);
key_type!(
    /// Reserved, unused in v1.
    AuthKey
);
key_type!(
    /// 256-bit vault key; only stored wrapped in header slots.
    VaultKey
);
key_type!(
    /// HMAC key for the vault header.
    MacKey
);
key_type!(
    /// Per-object data key; only stored wrapped in the object header.
    Dek
);
key_type!(
    /// Device-bound random key that wraps the vault key in the biometric slot.
    BioKey
);
key_type!(
    /// Verifier for the duress password.
    DuressTag
);

impl BioKey {
    /// Takes ownership of `bytes` (wiped on drop); fails with `InvalidInput` unless it is 32 bytes.
    pub fn from_vec(bytes: Vec<u8>) -> crate::error::Result<Self> {
        let bytes = zeroize::Zeroizing::new(bytes);
        let key: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| crate::error::Error::InvalidInput)?;
        Ok(Self::from_bytes(key))
    }
}

impl DuressTag {
    /// Constant-time comparison.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let k = MasterKey::from_bytes([0xAB; 32]);
        let s = format!("{k:?}");
        assert_eq!(s, "MasterKey(redacted)");
        assert!(!s.to_lowercase().contains("abab"));
    }

    #[test]
    fn duress_tag_ct_eq() {
        let a = DuressTag::from_bytes([1; 32]);
        let b = DuressTag::from_bytes([1; 32]);
        let mut raw = [1u8; 32];
        raw[31] = 2;
        let c = DuressTag::from_bytes(raw);
        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
    }

    #[test]
    fn bio_key_requires_32_bytes() {
        assert!(BioKey::from_vec(vec![1; 32]).is_ok());
        assert!(BioKey::from_vec(vec![1; 31]).is_err());
        assert!(BioKey::from_vec(vec![1; 33]).is_err());
        assert!(BioKey::from_vec(Vec::new()).is_err());
    }

    #[test]
    fn as_bytes_roundtrip() {
        let k = Kek::from_bytes([7; 32]);
        assert_eq!(k.as_bytes(), &[7u8; 32]);
        assert_eq!(k.expose_for_test_vectors(), &[7u8; 32]);
    }
}

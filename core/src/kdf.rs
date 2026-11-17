use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::keys::{AuthKey, BioKey, DuressTag, Kek, MacKey, MasterKey, VaultKey};

/// HKDF info labels (spec §3, `LABEL(x)`).
pub(crate) mod labels {
    pub const PASSWORD_KEK: &[u8] = b"zeroenclave v1 password-kek";
    pub const DURESS_TAG: &[u8] = b"zeroenclave v1 duress-tag";
    pub const AUTH: &[u8] = b"zeroenclave v1 auth";
    pub const RECOVERY_KEK: &[u8] = b"zeroenclave v1 recovery-kek";
    pub const RECOVERY_CHECKSUM: &[u8] = b"zeroenclave v1 recovery-checksum";
    pub const SLOT: &[u8] = b"zeroenclave v1 slot";
    pub const HEADER_MAC: &[u8] = b"zeroenclave v1 header-mac";
    pub const DEK: &[u8] = b"zeroenclave v1 dek";
    pub const EXPORT_MAC: &[u8] = b"zeroenclave v1 export-mac";
    pub const BIOMETRIC_KEK: &[u8] = b"zeroenclave v1 biometric-kek";
    pub const BIOMETRIC: &[u8] = b"zeroenclave v1 biometric";
    pub const BIOMETRIC_POLICY: &[u8] = b"zeroenclave v1 biometric-policy";
    pub const PIN_KEY: &[u8] = b"zeroenclave v1 pin-key";
    pub const PIN_KEK: &[u8] = b"zeroenclave v1 pin-kek";
    pub const PIN: &[u8] = b"zeroenclave v1 pin";
    pub const PIN_POLICY: &[u8] = b"zeroenclave v1 pin-policy";
    pub const ALBUM_PIN: &[u8] = b"zeroenclave v1 album-pin";
}

const M_KIB_RANGE: core::ops::RangeInclusive<u32> = 65_536..=1_048_576;
const T_RANGE: core::ops::RangeInclusive<u32> = 3..=32;
const P_RANGE: core::ops::RangeInclusive<u8> = 1..=16;

/// Argon2id parameters (spec §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u8,
}

impl KdfParams {
    pub const DEFAULT: KdfParams = KdfParams {
        m_kib: 65_536,
        t: 3,
        p: 4,
    };

    /// Rejects parameters outside the accepted ranges.
    pub fn validate(&self) -> Result<()> {
        if M_KIB_RANGE.contains(&self.m_kib)
            && T_RANGE.contains(&self.t)
            && P_RANGE.contains(&self.p)
        {
            Ok(())
        } else {
            Err(Error::InvalidKdfParams)
        }
    }
}

/// Argon2id over the NFC-normalized password (spec §5.1, §5.2).
pub fn derive_master_key(password: &str, salt: &[u8; 16], params: &KdfParams) -> Result<MasterKey> {
    params.validate()?;
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }

    // Reserve up front so the buffer is not reallocated (and left unzeroized) while growing.
    let mut normalized = Zeroizing::new(String::with_capacity(password.len().saturating_mul(4)));
    normalized.extend(password.nfc());

    let argon_params = Params::new(params.m_kib, params.t, u32::from(params.p), Some(32))
        .map_err(|_| Error::InvalidKdfParams)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(normalized.as_bytes(), salt, &mut *out)
        .map_err(|_| Error::Kdf)?;
    Ok(MasterKey::from_bytes(*out))
}

/// HKDF-SHA256 with salt = vault_id, 32 bytes of output.
pub(crate) fn hkdf32(ikm: &[u8; 32], vault_id: &[u8; 16], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(vault_id), ikm)
        .expand(info, &mut *out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// Digest of an album view-lock code: HKDF-SHA256(ikm = code, salt, info = label || album id).
/// Four digits give only 10^4 candidates, so this is a view lock and no protection
/// against anyone who can read the (encrypted) journal.
pub(crate) fn album_pin_digest(
    code: &[u8],
    salt: &[u8; 16],
    album: &[u8; 16],
) -> Zeroizing<[u8; 32]> {
    let mut info = labels::ALBUM_PIN.to_vec();
    info.extend_from_slice(album);
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), code)
        .expand(&info, &mut *out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

pub fn password_kek(mk: &MasterKey, vault_id: &[u8; 16]) -> Kek {
    Kek::from_bytes(*hkdf32(mk.as_bytes(), vault_id, labels::PASSWORD_KEK))
}

pub fn duress_tag(mk: &MasterKey, vault_id: &[u8; 16]) -> DuressTag {
    DuressTag::from_bytes(*hkdf32(mk.as_bytes(), vault_id, labels::DURESS_TAG))
}

pub fn auth_key(mk: &MasterKey, vault_id: &[u8; 16]) -> AuthKey {
    AuthKey::from_bytes(*hkdf32(mk.as_bytes(), vault_id, labels::AUTH))
}

pub(crate) fn mac_key(vk: &VaultKey, vault_id: &[u8; 16]) -> MacKey {
    MacKey::from_bytes(*hkdf32(vk.as_bytes(), vault_id, labels::HEADER_MAC))
}

pub(crate) fn export_mac_key(vk: &VaultKey, vault_id: &[u8; 16]) -> MacKey {
    MacKey::from_bytes(*hkdf32(vk.as_bytes(), vault_id, labels::EXPORT_MAC))
}

/// Number of digits in an unlock PIN.
pub const PIN_LEN: usize = 6;

/// Key for the PIN slot (crypto §12): `HKDF(se_secret || Argon2id(pin, vault_id), vault_id,
/// LABEL("pin-key"))`. The device-bound `se_secret` keeps a copied vault safe from PIN guessing.
pub fn pin_key(se_secret: &BioKey, pin: &str, vault_id: &[u8; 16]) -> Result<BioKey> {
    if pin.len() != PIN_LEN || !pin.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::InvalidInput);
    }
    let p = KdfParams::DEFAULT;
    let argon_params =
        Params::new(p.m_kib, p.t, u32::from(p.p), Some(32)).map_err(|_| Error::InvalidKdfParams)?;
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(se_secret.as_bytes());
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params)
        .hash_password_into(pin.as_bytes(), vault_id, &mut ikm[32..])
        .map_err(|_| Error::Kdf)?;
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(vault_id), &*ikm)
        .expand(labels::PIN_KEY, &mut *out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Ok(BioKey::from_bytes(*out))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; 16] = [9; 16];
    const VAULT_ID: [u8; 16] = [5; 16];

    fn with(f: impl FnOnce(&mut KdfParams)) -> KdfParams {
        let mut p = KdfParams::DEFAULT;
        f(&mut p);
        p
    }

    #[test]
    fn default_params_are_valid() {
        assert!(KdfParams::DEFAULT.validate().is_ok());
    }

    #[test]
    fn param_bounds() {
        let ok = [
            with(|p| p.m_kib = 65_536),
            with(|p| p.m_kib = 1_048_576),
            with(|p| p.t = 3),
            with(|p| p.t = 32),
            with(|p| p.p = 1),
            with(|p| p.p = 16),
        ];
        for p in ok {
            assert!(p.validate().is_ok(), "{p:?}");
        }
        let bad = [
            with(|p| p.m_kib = 65_535),
            with(|p| p.m_kib = 1_048_577),
            with(|p| p.t = 2),
            with(|p| p.t = 33),
            with(|p| p.p = 0),
            with(|p| p.p = 17),
        ];
        for p in bad {
            assert_eq!(p.validate(), Err(Error::InvalidKdfParams), "{p:?}");
        }
    }

    #[test]
    fn invalid_params_rejected_before_kdf() {
        let p = with(|p| p.m_kib = 1_048_577);
        assert_eq!(
            derive_master_key("pw", &SALT, &p).unwrap_err(),
            Error::InvalidKdfParams
        );
        // Params are checked before the password.
        assert_eq!(
            derive_master_key("", &SALT, &p).unwrap_err(),
            Error::InvalidKdfParams
        );
    }

    #[test]
    fn empty_password_rejected() {
        assert_eq!(
            derive_master_key("", &SALT, &KdfParams::DEFAULT).unwrap_err(),
            Error::EmptyPassword
        );
    }

    #[test]
    fn nfc_and_nfd_give_same_key() {
        let nfc = derive_master_key("caf\u{e9}", &SALT, &KdfParams::DEFAULT).unwrap();
        let nfd = derive_master_key("cafe\u{301}", &SALT, &KdfParams::DEFAULT).unwrap();
        assert_eq!(nfc.expose_for_test_vectors(), nfd.expose_for_test_vectors());
    }

    #[test]
    fn salt_and_password_change_key() {
        let a = derive_master_key("password-one", &SALT, &KdfParams::DEFAULT).unwrap();
        let b = derive_master_key("password-two", &SALT, &KdfParams::DEFAULT).unwrap();
        let c = derive_master_key("password-one", &[1; 16], &KdfParams::DEFAULT).unwrap();
        assert_ne!(a.expose_for_test_vectors(), b.expose_for_test_vectors());
        assert_ne!(a.expose_for_test_vectors(), c.expose_for_test_vectors());
    }

    #[test]
    fn derived_keys_are_separated() {
        let mk = MasterKey::from_bytes([3; 32]);
        let k = password_kek(&mk, &VAULT_ID);
        let d = duress_tag(&mk, &VAULT_ID);
        let a = auth_key(&mk, &VAULT_ID);
        assert_ne!(k.expose_for_test_vectors(), d.expose_for_test_vectors());
        assert_ne!(k.expose_for_test_vectors(), a.expose_for_test_vectors());
        assert_ne!(d.expose_for_test_vectors(), a.expose_for_test_vectors());
        let other = password_kek(&mk, &[6; 16]);
        assert_ne!(k.expose_for_test_vectors(), other.expose_for_test_vectors());
    }

    #[test]
    fn labels_are_exact() {
        assert_eq!(labels::PASSWORD_KEK, b"zeroenclave v1 password-kek");
        assert_eq!(labels::DURESS_TAG, b"zeroenclave v1 duress-tag");
        assert_eq!(labels::AUTH, b"zeroenclave v1 auth");
        assert_eq!(labels::RECOVERY_KEK, b"zeroenclave v1 recovery-kek");
        assert_eq!(
            labels::RECOVERY_CHECKSUM,
            b"zeroenclave v1 recovery-checksum"
        );
        assert_eq!(labels::SLOT, b"zeroenclave v1 slot");
        assert_eq!(labels::HEADER_MAC, b"zeroenclave v1 header-mac");
        assert_eq!(labels::EXPORT_MAC, b"zeroenclave v1 export-mac");
    }
}

//! Vault header (vault-format §3) with key slots (crypto §6).

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::kdf::{derive_master_key, duress_tag, labels, mac_key, password_kek, KdfParams};
use crate::keys::{DuressTag, Kek, VaultKey};
use crate::recovery::{recovery_kek, RecoveryKey};
use crate::rng::{self, OsRandom, RandomSource};

const MAGIC: &[u8; 4] = b"ZENV";
const VERSION: u16 = 1;
const KDF_ALG_ARGON2ID: u8 = 1;
const SLOT_PASSWORD: u8 = 0x01;
const SLOT_RECOVERY: u8 = 0x02;
const SLOT_DURESS: u8 = 0x03;
const NONCE_LEN: usize = 12;
const WRAPPED_LEN: usize = 60;
const DURESS_LEN: usize = 32;
const MAC_LEN: usize = 32;
const KDF_START: usize = 24;
const KDF_END: usize = 50;
const SLOT_COUNT: u8 = 3;
const HEADER_LEN: usize = 51 + (3 + WRAPPED_LEN) * 2 + (3 + DURESS_LEN) + MAC_LEN;

/// Parsed v1 header. Holds only public data and wrapped keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHeader {
    vault_id: [u8; 16],
    params: KdfParams,
    salt: [u8; 16],
    slot_password: [u8; WRAPPED_LEN],
    slot_recovery: [u8; WRAPPED_LEN],
    slot_duress: [u8; DURESS_LEN],
    mac: [u8; MAC_LEN],
}

/// Result of a password unlock attempt (crypto §6.4).
#[derive(Debug)]
pub enum UnlockOutcome {
    Open(VaultKey),
    Duress,
    WrongPassword,
}

/// Duress handling when the master password changes (crypto §6.5).
pub enum DuressUpdate {
    Disable,
    Set(String),
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        s
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        self.take(N).try_into().expect("length checked by take")
    }

    fn u8(&mut self) -> u8 {
        self.array::<1>()[0]
    }

    fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.array())
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.array())
    }
}

impl VaultHeader {
    /// Strict parser; rejects anything that is not exactly a v1 header.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HEADER_LEN {
            return Err(Error::HeaderFormat);
        }
        let mut r = Reader { buf: bytes, pos: 0 };
        if r.take(4) != MAGIC {
            return Err(Error::HeaderFormat);
        }
        if r.u16() != VERSION || r.u16() != 0 {
            return Err(Error::HeaderFormat);
        }
        let vault_id = r.array::<16>();
        if r.u8() != KDF_ALG_ARGON2ID {
            return Err(Error::HeaderFormat);
        }
        let params = KdfParams {
            m_kib: r.u32(),
            t: r.u32(),
            p: r.u8(),
        };
        params.validate()?;
        let salt = r.array::<16>();
        if r.u8() != SLOT_COUNT {
            return Err(Error::HeaderFormat);
        }
        for (ty, len) in [
            (SLOT_PASSWORD, WRAPPED_LEN),
            (SLOT_RECOVERY, WRAPPED_LEN),
            (SLOT_DURESS, DURESS_LEN),
        ] {
            // Fixed order and lengths also rule out duplicate, unknown and unsorted types.
            if r.u8() != ty || usize::from(r.u16()) != len {
                return Err(Error::HeaderFormat);
            }
            r.take(len);
        }
        let mac = r.array::<MAC_LEN>();
        debug_assert_eq!(r.pos, HEADER_LEN);

        let mut slots = Reader {
            buf: bytes,
            pos: 54,
        };
        let slot_password = slots.array::<WRAPPED_LEN>();
        slots.take(3);
        let slot_recovery = slots.array::<WRAPPED_LEN>();
        slots.take(3);
        let slot_duress = slots.array::<DURESS_LEN>();
        Ok(Self {
            vault_id,
            params,
            salt,
            slot_password,
            slot_recovery,
            slot_duress,
            mac,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.body_bytes();
        out.extend_from_slice(&self.mac);
        out
    }

    pub fn vault_id(&self) -> &[u8; 16] {
        &self.vault_id
    }

    pub fn kdf_params(&self) -> KdfParams {
        self.params
    }

    /// All bytes covered by the header MAC.
    fn body_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&self.vault_id);
        out.extend_from_slice(&self.kdf_block());
        out.push(SLOT_COUNT);
        for (ty, body) in [
            (SLOT_PASSWORD, &self.slot_password[..]),
            (SLOT_RECOVERY, &self.slot_recovery[..]),
            (SLOT_DURESS, &self.slot_duress[..]),
        ] {
            out.push(ty);
            out.extend_from_slice(&(body.len() as u16).to_be_bytes());
            out.extend_from_slice(body);
        }
        out
    }

    /// Bytes 24..50 of the header.
    fn kdf_block(&self) -> [u8; KDF_END - KDF_START] {
        let mut out = [0u8; KDF_END - KDF_START];
        out[0] = KDF_ALG_ARGON2ID;
        out[1..5].copy_from_slice(&self.params.m_kib.to_be_bytes());
        out[5..9].copy_from_slice(&self.params.t.to_be_bytes());
        out[9] = self.params.p;
        out[10..].copy_from_slice(&self.salt);
        out
    }

    fn mac_over_body(&self, vk: &VaultKey) -> Hmac<Sha256> {
        let key = mac_key(vk, &self.vault_id);
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes())
            .expect("HMAC accepts any key length");
        mac.update(&self.body_bytes());
        mac
    }

    fn seal(&mut self, vk: &VaultKey) {
        self.mac = self.mac_over_body(vk).finalize().into_bytes().into();
    }

    /// Constant-time MAC check.
    pub(crate) fn verify_mac(&self, vk: &VaultKey) -> Result<()> {
        self.mac_over_body(vk)
            .verify_slice(&self.mac)
            .map_err(|_| Error::HeaderTampered)
    }

    fn slot_aad(&self, slot_type: u8) -> Vec<u8> {
        slot_aad(slot_type, &self.vault_id, &self.kdf_block())
    }
}

/// aad = LABEL("slot") || slot_type || vault_id [|| kdf_block].
/// The recovery slot omits kdf_block so a password change can leave it untouched.
fn slot_aad(slot_type: u8, vault_id: &[u8; 16], kdf_block: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(labels::SLOT.len() + 1 + 16 + kdf_block.len());
    aad.extend_from_slice(labels::SLOT);
    aad.push(slot_type);
    aad.extend_from_slice(vault_id);
    if slot_type != SLOT_RECOVERY {
        aad.extend_from_slice(kdf_block);
    }
    aad
}

fn cipher(kek: &Kek) -> Aes256Gcm {
    Aes256Gcm::new(&Key::<Aes256Gcm>::from(*kek.as_bytes()))
}

/// Returns `nonce || ciphertext || tag`.
fn wrap(
    kek: &Kek,
    vk: &VaultKey,
    aad: &[u8],
    rng: &mut impl RandomSource,
) -> Result<[u8; WRAPPED_LEN]> {
    let nonce = rng::array::<NONCE_LEN>(rng)?;
    let ct = cipher(kek)
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: vk.as_bytes(),
                aad,
            },
        )
        .map_err(|_| Error::Crypto)?;
    let mut out = [0u8; WRAPPED_LEN];
    out[..NONCE_LEN].copy_from_slice(&nonce);
    out[NONCE_LEN..].copy_from_slice(&ct);
    Ok(out)
}

fn unwrap(kek: &Kek, slot: &[u8; WRAPPED_LEN], aad: &[u8]) -> Option<VaultKey> {
    let (nonce, ct) = slot.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().ok()?;
    let pt = Zeroizing::new(
        cipher(kek)
            .decrypt(&Nonce::from(nonce), Payload { msg: ct, aad })
            .ok()?,
    );
    let key: [u8; 32] = pt.as_slice().try_into().ok()?;
    Some(VaultKey::from_bytes(key))
}

fn nfc_eq(a: &str, b: &str) -> bool {
    a.nfc().eq(b.nfc())
}

/// Creates a new vault header; returns it with the vault key and recovery key.
pub fn create(password: &str, params: KdfParams) -> Result<(VaultHeader, VaultKey, RecoveryKey)> {
    create_with(password, params, &mut OsRandom)
}

/// Random draw order: vault_id, salt, vk, recovery key, slot 0x01 nonce,
/// slot 0x02 nonce, slot 0x03 bytes.
pub fn create_with(
    password: &str,
    params: KdfParams,
    rng: &mut impl RandomSource,
) -> Result<(VaultHeader, VaultKey, RecoveryKey)> {
    let vault_id = rng::array::<16>(rng)?;
    let salt = rng::array::<16>(rng)?;
    let vk = VaultKey::from_bytes(rng::array::<32>(rng)?);
    let rk = RecoveryKey::generate_with(rng)?;

    let mut header = VaultHeader {
        vault_id,
        params,
        salt,
        slot_password: [0; WRAPPED_LEN],
        slot_recovery: [0; WRAPPED_LEN],
        slot_duress: [0; DURESS_LEN],
        mac: [0; MAC_LEN],
    };
    let mk = derive_master_key(password, &salt, &params)?;
    header.slot_password = wrap(
        &password_kek(&mk, &vault_id),
        &vk,
        &header.slot_aad(SLOT_PASSWORD),
        rng,
    )?;
    header.slot_recovery = wrap(
        &recovery_kek(&rk, &vault_id),
        &vk,
        &header.slot_aad(SLOT_RECOVERY),
        rng,
    )?;
    rng.fill(&mut header.slot_duress)?;
    header.seal(&vk);
    Ok((header, vk, rk))
}

/// One Argon2id run per attempt (crypto §6.4).
pub fn unlock(header: &VaultHeader, password: &str) -> Result<UnlockOutcome> {
    let mk = derive_master_key(password, &header.salt, &header.params)?;
    let kek = password_kek(&mk, &header.vault_id);
    if let Some(vk) = unwrap(&kek, &header.slot_password, &header.slot_aad(SLOT_PASSWORD)) {
        header.verify_mac(&vk)?;
        return Ok(UnlockOutcome::Open(vk));
    }
    let tag = duress_tag(&mk, &header.vault_id);
    if tag.ct_eq(&DuressTag::from_bytes(header.slot_duress)) {
        return Ok(UnlockOutcome::Duress);
    }
    Ok(UnlockOutcome::WrongPassword)
}

pub fn unlock_recovery(header: &VaultHeader, rk: &RecoveryKey) -> Result<VaultKey> {
    let kek = recovery_kek(rk, &header.vault_id);
    let vk = unwrap(&kek, &header.slot_recovery, &header.slot_aad(SLOT_RECOVERY))
        .ok_or(Error::WrongRecoveryKey)?;
    header
        .verify_mac(&vk)
        .map_err(|_| Error::WrongRecoveryKey)?;
    Ok(vk)
}

/// Re-wraps the password slot under a new salt; the recovery slot stays untouched.
pub fn change_password(
    header: &VaultHeader,
    vk: &VaultKey,
    new_password: &str,
    new_params: KdfParams,
    duress: DuressUpdate,
) -> Result<VaultHeader> {
    change_password_with(header, vk, new_password, new_params, duress, &mut OsRandom)
}

/// Random draw order: salt, slot 0x01 nonce, slot 0x03 bytes (only when disabling).
pub fn change_password_with(
    header: &VaultHeader,
    vk: &VaultKey,
    new_password: &str,
    new_params: KdfParams,
    duress: DuressUpdate,
    rng: &mut impl RandomSource,
) -> Result<VaultHeader> {
    header.verify_mac(vk)?;
    if let DuressUpdate::Set(d) = &duress {
        if nfc_eq(d, new_password) {
            return Err(Error::DuressEqualsPassword);
        }
    }
    new_params.validate()?;

    let mut h = header.clone();
    h.salt = rng::array::<16>(rng)?;
    h.params = new_params;
    let mk = derive_master_key(new_password, &h.salt, &h.params)?;
    h.slot_password = wrap(
        &password_kek(&mk, &h.vault_id),
        vk,
        &h.slot_aad(SLOT_PASSWORD),
        rng,
    )?;
    match duress {
        DuressUpdate::Disable => rng.fill(&mut h.slot_duress)?,
        DuressUpdate::Set(d) => {
            let dmk = derive_master_key(&d, &h.salt, &h.params)?;
            h.slot_duress = *duress_tag(&dmk, &h.vault_id).as_bytes();
        }
    }
    h.seal(vk);
    Ok(h)
}

/// Stores the duress tag under the current salt and parameters (crypto §7).
/// Rejects a duress password that unwraps the password slot (i.e. equals the master password).
pub fn set_duress(
    header: &VaultHeader,
    vk: &VaultKey,
    duress_password: &str,
) -> Result<VaultHeader> {
    header.verify_mac(vk)?;
    let dmk = derive_master_key(duress_password, &header.salt, &header.params)?;
    let kek = password_kek(&dmk, &header.vault_id);
    if unwrap(&kek, &header.slot_password, &header.slot_aad(SLOT_PASSWORD)).is_some() {
        return Err(Error::DuressEqualsPassword);
    }
    let mut h = header.clone();
    h.slot_duress = *duress_tag(&dmk, &h.vault_id).as_bytes();
    h.seal(vk);
    Ok(h)
}

/// Replaces the duress slot with random bytes (crypto §7).
pub(crate) fn disable_duress(header: &VaultHeader, vk: &VaultKey) -> Result<VaultHeader> {
    header.verify_mac(vk)?;
    let mut h = header.clone();
    rng::fill(&mut h.slot_duress)?;
    h.seal(vk);
    Ok(h)
}

pub fn rotate_recovery(header: &VaultHeader, vk: &VaultKey) -> Result<(VaultHeader, RecoveryKey)> {
    rotate_recovery_with(header, vk, &mut OsRandom)
}

/// Random draw order: recovery key, slot 0x02 nonce.
pub fn rotate_recovery_with(
    header: &VaultHeader,
    vk: &VaultKey,
    rng: &mut impl RandomSource,
) -> Result<(VaultHeader, RecoveryKey)> {
    header.verify_mac(vk)?;
    let rk = RecoveryKey::generate_with(rng)?;
    let mut h = header.clone();
    h.slot_recovery = wrap(
        &recovery_kek(&rk, &h.vault_id),
        vk,
        &h.slot_aad(SLOT_RECOVERY),
        rng,
    )?;
    h.seal(vk);
    Ok((h, rk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    const PW: &str = "correct horse battery staple";
    const DURESS: &str = "another password entirely";

    struct Fixture {
        header: VaultHeader,
        vk: [u8; 32],
        rk: String,
    }

    fn fixture() -> &'static Fixture {
        static F: OnceLock<Fixture> = OnceLock::new();
        F.get_or_init(|| {
            let (header, vk, rk) = create(PW, KdfParams::DEFAULT).unwrap();
            Fixture {
                header,
                vk: *vk.expose_for_test_vectors(),
                rk: rk.encode().to_string(),
            }
        })
    }

    fn vk() -> VaultKey {
        VaultKey::from_bytes(fixture().vk)
    }

    fn rk() -> RecoveryKey {
        RecoveryKey::decode(&fixture().rk).unwrap()
    }

    fn bytes() -> Vec<u8> {
        fixture().header.to_bytes()
    }

    fn assert_format(b: &[u8]) {
        assert_eq!(VaultHeader::parse(b).unwrap_err(), Error::HeaderFormat);
    }

    fn open_vk(h: &VaultHeader, pw: &str) -> [u8; 32] {
        match unlock(h, pw).unwrap() {
            UnlockOutcome::Open(k) => *k.expose_for_test_vectors(),
            other => panic!("expected Open, got {other:?}"),
        }
    }

    #[test]
    fn layout_and_roundtrip() {
        let b = bytes();
        assert_eq!(b.len(), 244);
        assert_eq!(&b[..4], b"ZENV");
        assert_eq!(&b[4..8], &[0, 1, 0, 0]);
        assert_eq!(b[24], 1);
        assert_eq!(b[50], 3);
        assert_eq!(&b[51..54], &[1, 0, 60]);
        assert_eq!(&b[114..117], &[2, 0, 60]);
        assert_eq!(&b[177..180], &[3, 0, 32]);
        let parsed = VaultHeader::parse(&b).unwrap();
        assert_eq!(parsed, fixture().header);
        assert_eq!(parsed.to_bytes(), b);
    }

    #[test]
    fn reject_wrong_magic() {
        let mut b = bytes();
        b[0] ^= 1;
        assert_format(&b);
    }

    #[test]
    fn reject_unknown_version() {
        let mut b = bytes();
        b[5] = 2;
        assert_format(&b);
        b[5] = 1;
        b[4] = 1;
        assert_format(&b);
    }

    #[test]
    fn reject_nonzero_reserved() {
        for i in [6, 7] {
            let mut b = bytes();
            b[i] = 1;
            assert_format(&b);
        }
    }

    #[test]
    fn reject_unknown_kdf_alg() {
        let mut b = bytes();
        b[24] = 2;
        assert_format(&b);
    }

    #[test]
    fn reject_kdf_params_out_of_range() {
        let mut b = bytes();
        b[25..29].copy_from_slice(&65_535u32.to_be_bytes());
        assert_eq!(VaultHeader::parse(&b).unwrap_err(), Error::InvalidKdfParams);
        let mut b = bytes();
        b[29..33].copy_from_slice(&2u32.to_be_bytes());
        assert_eq!(VaultHeader::parse(&b).unwrap_err(), Error::InvalidKdfParams);
        let mut b = bytes();
        b[33] = 0;
        assert_eq!(VaultHeader::parse(&b).unwrap_err(), Error::InvalidKdfParams);
    }

    #[test]
    fn reject_wrong_slot_count() {
        for n in [0u8, 2, 4] {
            let mut b = bytes();
            b[50] = n;
            assert_format(&b);
        }
    }

    #[test]
    fn reject_wrong_duplicate_unknown_unsorted_slot_type() {
        for (off, ty) in [(51, 4u8), (51, 0), (114, 1), (177, 2), (177, 0xFF)] {
            let mut b = bytes();
            b[off] = ty;
            assert_format(&b);
        }
        // Unsorted: swap the types of slots 0x01 and 0x02.
        let mut b = bytes();
        b[51] = 2;
        b[114] = 1;
        assert_format(&b);
    }

    #[test]
    fn reject_wrong_slot_length() {
        for (off, len) in [(52, 59u16), (52, 61), (115, 0), (178, 60), (178, 31)] {
            let mut b = bytes();
            b[off..off + 2].copy_from_slice(&len.to_be_bytes());
            assert_format(&b);
        }
    }

    #[test]
    fn reject_wrong_total_length() {
        let b = bytes();
        assert_format(&[]);
        assert_format(&b[..243]);
        let mut long = b.clone();
        long.push(0);
        assert_format(&long);
    }

    #[test]
    fn create_then_unlock_opens() {
        assert_eq!(open_vk(&fixture().header, PW), fixture().vk);
    }

    #[test]
    fn wrong_password() {
        assert!(matches!(
            unlock(&fixture().header, "not the password").unwrap(),
            UnlockOutcome::WrongPassword
        ));
    }

    #[test]
    fn empty_password_is_error() {
        assert_eq!(
            unlock(&fixture().header, "").unwrap_err(),
            Error::EmptyPassword
        );
    }

    #[test]
    fn duress_password_yields_duress() {
        let h = set_duress(&fixture().header, &vk(), DURESS).unwrap();
        assert!(matches!(unlock(&h, DURESS).unwrap(), UnlockOutcome::Duress));
        assert_eq!(open_vk(&h, PW), fixture().vk);
        assert!(matches!(
            unlock(&h, "unrelated").unwrap(),
            UnlockOutcome::WrongPassword
        ));
        // The MAC covers slot 0x03, so the duress change is authenticated.
        assert_ne!(h.to_bytes(), bytes());
        assert!(h.verify_mac(&vk()).is_ok());
    }

    #[test]
    fn real_password_wins_over_equal_duress_slot() {
        let f = fixture();
        let mk = derive_master_key(PW, &f.header.salt, &f.header.params).unwrap();
        let mut h = f.header.clone();
        h.slot_duress = *duress_tag(&mk, &h.vault_id).as_bytes();
        h.seal(&vk());
        assert_eq!(open_vk(&h, PW), f.vk);
    }

    #[test]
    fn duress_must_differ_from_master() {
        let (h, vk, _) = create("caf\u{e9}", KdfParams::DEFAULT).unwrap();
        for d in ["caf\u{e9}", "cafe\u{301}"] {
            assert_eq!(
                set_duress(&h, &vk, d).unwrap_err(),
                Error::DuressEqualsPassword
            );
        }
        assert_eq!(
            change_password(
                &h,
                &vk,
                "caf\u{e9}",
                KdfParams::DEFAULT,
                DuressUpdate::Set("cafe\u{301}".into())
            )
            .unwrap_err(),
            Error::DuressEqualsPassword
        );
    }

    #[test]
    fn recovery_unlock() {
        let k = unlock_recovery(&fixture().header, &rk()).unwrap();
        assert_eq!(k.expose_for_test_vectors(), &fixture().vk);
        let wrong = RecoveryKey::from_bytes([7; 32]);
        assert_eq!(
            unlock_recovery(&fixture().header, &wrong).unwrap_err(),
            Error::WrongRecoveryKey
        );
    }

    #[test]
    fn change_password_keeps_recovery_and_replaces_old_password() {
        let f = fixture();
        let h = change_password(
            &f.header,
            &vk(),
            "new password 123",
            KdfParams::DEFAULT,
            DuressUpdate::Disable,
        )
        .unwrap();
        assert_ne!(h.salt, f.header.salt);
        assert_eq!(h.slot_recovery, f.header.slot_recovery);
        assert_eq!(open_vk(&h, "new password 123"), f.vk);
        assert!(matches!(
            unlock(&h, PW).unwrap(),
            UnlockOutcome::WrongPassword
        ));
        let k = unlock_recovery(&h, &rk()).unwrap();
        assert_eq!(k.expose_for_test_vectors(), &f.vk);
        // Parsing round trip stays valid.
        assert_eq!(VaultHeader::parse(&h.to_bytes()).unwrap(), h);
    }

    #[test]
    fn change_password_recomputes_duress_under_new_salt() {
        let h = change_password(
            &fixture().header,
            &vk(),
            "new password 123",
            KdfParams::DEFAULT,
            DuressUpdate::Set(DURESS.into()),
        )
        .unwrap();
        assert!(matches!(unlock(&h, DURESS).unwrap(), UnlockOutcome::Duress));
        assert_eq!(open_vk(&h, "new password 123"), fixture().vk);
    }

    #[test]
    fn rotate_recovery_replaces_old_key() {
        let (h, new_rk) = rotate_recovery(&fixture().header, &vk()).unwrap();
        assert_eq!(
            unlock_recovery(&h, &rk()).unwrap_err(),
            Error::WrongRecoveryKey
        );
        let k = unlock_recovery(&h, &new_rk).unwrap();
        assert_eq!(k.expose_for_test_vectors(), &fixture().vk);
        assert_eq!(h.slot_password, fixture().header.slot_password);
    }

    #[test]
    fn management_requires_matching_vault_key() {
        let other = VaultKey::from_bytes([9; 32]);
        assert_eq!(
            rotate_recovery(&fixture().header, &other).unwrap_err(),
            Error::HeaderTampered
        );
    }

    #[test]
    fn tampering_never_opens() {
        // One byte per region: vault_id, kdf params, salt, each slot, MAC.
        for off in [8, 30, 40, 60, 100, 120, 170, 190, 200, 243] {
            let mut b = bytes();
            b[off] ^= 0x01;
            // Rejected at parse time (e.g. KDF params out of range) is also fine.
            let Ok(h) = VaultHeader::parse(&b) else {
                continue;
            };
            match unlock(&h, PW) {
                Ok(UnlockOutcome::Open(_)) => panic!("tampered header opened at {off}"),
                Ok(UnlockOutcome::Duress) => panic!("tampered header gave duress at {off}"),
                Ok(UnlockOutcome::WrongPassword) | Err(_) => {}
            }
        }
    }

    #[test]
    fn tampered_recovery_and_duress_slots_are_detected() {
        for off in [120, 170, 190, 200] {
            let mut b = bytes();
            b[off] ^= 0x01;
            let h = VaultHeader::parse(&b).unwrap();
            assert_eq!(unlock(&h, PW).unwrap_err(), Error::HeaderTampered);
            assert_eq!(
                unlock_recovery(&h, &rk()).unwrap_err(),
                Error::WrongRecoveryKey
            );
        }
    }

    #[test]
    fn foreign_password_slot_fails() {
        let (other, _, _) = create(PW, KdfParams::DEFAULT).unwrap();
        let mut h = fixture().header.clone();
        h.slot_password = other.slot_password;
        assert!(matches!(
            unlock(&h, PW).unwrap(),
            UnlockOutcome::WrongPassword
        ));
    }
}

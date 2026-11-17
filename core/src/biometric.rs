//! Quick-unlock slots (crypto §12): `local/biometric.zes` for Face ID and `local/pin.zes`
//! for the PIN. Each holds the vault key wrapped under a device-bound key plus a
//! MAC-protected expiry policy. Local only, never exported.
//!
//! Layout (big-endian): `magic ("ZENB" / "ZENP") || version u16 || nonce (12) || wrapped_vk (48) ||
//! boot_time u64 || expires_at u64 || policy_mac (32)`. `boot_time` and `now` are Unix
//! seconds supplied by the caller, so the core stays free of clock access.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::kdf::{hkdf32, labels};
use crate::keys::{BioKey, Kek, MacKey, VaultKey};
use crate::rng::{self, RandomSource};
use crate::store::Store;

const VERSION: u16 = 1;
const NONCE_LEN: usize = 12;
const WRAPPED_LEN: usize = 48;
const MAC_LEN: usize = 32;
const BODY_LEN: usize = 4 + 2 + NONCE_LEN + WRAPPED_LEN + 8 + 8;
const SLOT_LEN: usize = BODY_LEN + MAC_LEN;

/// Validity of the slot after a password or recovery unlock.
pub(crate) const VALIDITY_SECS: u64 = 7 * 24 * 60 * 60;

/// Which quick-unlock slot; both share the layout and differ in magic, file and labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Biometric,
    Pin,
}

impl Kind {
    fn magic(self) -> &'static [u8; 4] {
        match self {
            Kind::Biometric => b"ZENB",
            Kind::Pin => b"ZENP",
        }
    }

    fn file_name(self) -> &'static str {
        match self {
            Kind::Biometric => "biometric.zes",
            Kind::Pin => "pin.zes",
        }
    }

    /// Error for a slot that does not parse, unwrap or verify.
    pub(crate) fn invalid(self) -> Error {
        match self {
            Kind::Biometric => Error::BiometricInvalid,
            Kind::Pin => Error::PinInvalid,
        }
    }

    pub(crate) fn expired(self) -> Error {
        match self {
            Kind::Biometric => Error::BiometricExpired,
            Kind::Pin => Error::PinExpired,
        }
    }

    fn kek(self, key: &BioKey, vault_id: &[u8; 16]) -> Kek {
        let label = match self {
            Kind::Biometric => labels::BIOMETRIC_KEK,
            Kind::Pin => labels::PIN_KEK,
        };
        Kek::from_bytes(*hkdf32(key.as_bytes(), vault_id, label))
    }

    fn policy_key(self, vk: &VaultKey, vault_id: &[u8; 16]) -> MacKey {
        let label = match self {
            Kind::Biometric => labels::BIOMETRIC_POLICY,
            Kind::Pin => labels::PIN_POLICY,
        };
        MacKey::from_bytes(*hkdf32(vk.as_bytes(), vault_id, label))
    }

    /// aad = LABEL("biometric" / "pin") || vault_id.
    fn aad(self, vault_id: &[u8; 16]) -> Vec<u8> {
        let label = match self {
            Kind::Biometric => labels::BIOMETRIC,
            Kind::Pin => labels::PIN,
        };
        let mut out = Vec::with_capacity(label.len() + 16);
        out.extend_from_slice(label);
        out.extend_from_slice(vault_id);
        out
    }
}

pub(crate) fn slot_path(store: &Store, kind: Kind) -> std::path::PathBuf {
    store.local_dir().join(kind.file_name())
}

/// Parsed slot; `mac` covers every byte before it.
pub(crate) struct Slot {
    kind: Kind,
    nonce: [u8; NONCE_LEN],
    wrapped: [u8; WRAPPED_LEN],
    pub(crate) boot_time: u64,
    pub(crate) expires_at: u64,
    mac: [u8; MAC_LEN],
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(b[at..at + 8].try_into().expect("slice of length 8"))
}

impl Slot {
    /// Strict parse: exact length, magic and version.
    pub(crate) fn parse(kind: Kind, b: &[u8]) -> Result<Self> {
        if b.len() != SLOT_LEN || &b[..4] != kind.magic() || b[4..6] != VERSION.to_be_bytes() {
            return Err(kind.invalid());
        }
        let n = 6;
        let w = n + NONCE_LEN;
        let t = w + WRAPPED_LEN;
        Ok(Self {
            kind,
            nonce: b[n..w].try_into().expect("fixed length"),
            wrapped: b[w..t].try_into().expect("fixed length"),
            boot_time: u64_at(b, t),
            expires_at: u64_at(b, t + 8),
            mac: b[BODY_LEN..].try_into().expect("fixed length"),
        })
    }

    fn body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SLOT_LEN);
        out.extend_from_slice(self.kind.magic());
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.wrapped);
        out.extend_from_slice(&self.boot_time.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.body();
        out.extend_from_slice(&self.mac);
        out
    }

    fn policy_mac(&self, vk: &VaultKey, vault_id: &[u8; 16]) -> Hmac<Sha256> {
        let key = self.kind.policy_key(vk, vault_id);
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes())
            .expect("HMAC accepts any key length");
        mac.update(&self.body());
        mac
    }

    fn seal(&mut self, vk: &VaultKey, vault_id: &[u8; 16]) {
        self.mac = self.policy_mac(vk, vault_id).finalize().into_bytes().into();
    }

    /// Constant-time policy MAC check.
    pub(crate) fn verify_policy(&self, vk: &VaultKey, vault_id: &[u8; 16]) -> Result<()> {
        self.policy_mac(vk, vault_id)
            .verify_slice(&self.mac)
            .map_err(|_| self.kind.invalid())
    }

    /// Unwraps the vault key; any failure is the kind's `invalid` error.
    pub(crate) fn unwrap_vk(&self, key: &BioKey, vault_id: &[u8; 16]) -> Result<VaultKey> {
        let pt = Zeroizing::new(
            cipher(self.kind, key, vault_id)
                .decrypt(
                    &Nonce::from(self.nonce),
                    Payload {
                        msg: &self.wrapped,
                        aad: &self.kind.aad(vault_id),
                    },
                )
                .map_err(|_| self.kind.invalid())?,
        );
        let key: [u8; 32] = pt.as_slice().try_into().map_err(|_| self.kind.invalid())?;
        Ok(VaultKey::from_bytes(key))
    }

    /// Replaces the policy block and MAC; the wrapped key stays as is.
    pub(crate) fn refreshed(
        &self,
        vk: &VaultKey,
        vault_id: &[u8; 16],
        boot_time: u64,
        now: u64,
    ) -> Self {
        let mut s = Self {
            kind: self.kind,
            nonce: self.nonce,
            wrapped: self.wrapped,
            boot_time,
            expires_at: now.saturating_add(VALIDITY_SECS),
            mac: [0; MAC_LEN],
        };
        s.seal(vk, vault_id);
        s
    }
}

fn cipher(kind: Kind, key: &BioKey, vault_id: &[u8; 16]) -> Aes256Gcm {
    let kek = kind.kek(key, vault_id);
    Aes256Gcm::new(&Key::<Aes256Gcm>::from(*kek.as_bytes()))
}

/// Builds a fresh slot. Random draw: nonce.
pub(crate) fn create(
    kind: Kind,
    vk: &VaultKey,
    bio_key: &BioKey,
    vault_id: &[u8; 16],
    boot_time: u64,
    now: u64,
    rng: &mut impl RandomSource,
) -> Result<Slot> {
    let nonce = rng::array::<NONCE_LEN>(rng)?;
    let ct = cipher(kind, bio_key, vault_id)
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: vk.as_bytes(),
                aad: &kind.aad(vault_id),
            },
        )
        .map_err(|_| Error::Crypto)?;
    let mut s = Slot {
        kind,
        nonce,
        wrapped: ct.try_into().map_err(|_| Error::Crypto)?,
        boot_time,
        expires_at: now.saturating_add(VALIDITY_SECS),
        mac: [0; MAC_LEN],
    };
    s.seal(vk, vault_id);
    Ok(s)
}

/// Reads the slot file; `None` if it does not exist.
pub(crate) fn read(store: &Store, kind: Kind) -> Result<Option<Vec<u8>>> {
    match std::fs::read(slot_path(store, kind)) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(Error::Io),
    }
}

pub(crate) fn write(store: &Store, slot: &Slot) -> Result<()> {
    write_bytes(store, slot.kind, &slot.to_bytes())
}

/// Writes raw slot bytes, e.g. to restore a PIN slot after a successful attempt.
pub(crate) fn write_bytes(store: &Store, kind: Kind, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    store.write_atomic(&slot_path(store, kind), |f| {
        f.write_all(bytes).map_err(|_| Error::Io)
    })
}

/// Removes the slot; a missing file is fine.
pub(crate) fn remove(store: &Store, kind: Kind) -> Result<()> {
    match std::fs::remove_file(slot_path(store, kind)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(Error::Io),
    }
}

/// Paused PIN slot (crypto §12): the same bytes under another name. Only a right PIN or a
/// password or recovery unlock makes it active again.
pub(crate) fn paused_pin_path(store: &Store) -> std::path::PathBuf {
    store.local_dir().join("pin.paused")
}

fn rename_durable(from: &std::path::Path, to: &std::path::Path, store: &Store) -> Result<bool> {
    match std::fs::rename(from, to) {
        Ok(()) => {
            // The pause must be on disk before the PIN is tried.
            if let Ok(dir) = std::fs::File::open(store.local_dir()) {
                dir.sync_all().map_err(|_| Error::Io)?;
            }
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(Error::Io),
    }
}

/// Reads the paused PIN slot; `None` if it does not exist.
pub(crate) fn read_paused_pin(store: &Store) -> Result<Option<Vec<u8>>> {
    match std::fs::read(paused_pin_path(store)) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(Error::Io),
    }
}

/// Moves an active PIN slot aside; `false` if there was none.
pub(crate) fn pause_pin(store: &Store) -> Result<bool> {
    rename_durable(&slot_path(store, Kind::Pin), &paused_pin_path(store), store)
}

/// Makes a paused PIN slot active again; a missing one is fine.
pub(crate) fn resume_pin(store: &Store) -> Result<()> {
    rename_durable(&paused_pin_path(store), &slot_path(store, Kind::Pin), store).map(|_| ())
}

/// Removes the PIN slot, active or paused.
pub(crate) fn remove_pin(store: &Store) -> Result<()> {
    remove(store, Kind::Pin)?;
    match std::fs::remove_file(paused_pin_path(store)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(Error::Io),
    }
}

/// After a password or recovery unlock: rewrites policy block and MAC of an existing slot.
/// A slot that does not parse or fails its MAC is unusable and removed.
pub(crate) fn refresh(
    store: &Store,
    kind: Kind,
    vk: &VaultKey,
    vault_id: &[u8; 16],
    boot_time: u64,
    now: u64,
) -> Result<()> {
    let Some(bytes) = read(store, kind)? else {
        return Ok(());
    };
    match Slot::parse(kind, &bytes).and_then(|s| s.verify_policy(vk, vault_id).map(|()| s)) {
        Ok(s) => write(store, &s.refreshed(vk, vault_id, boot_time, now)),
        Err(_) => remove(store, kind),
    }
}

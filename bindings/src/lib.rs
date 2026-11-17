//! UniFFI wrapper around `zeroenclave-core`. Thin by design: no crypto logic lives here.
//!
//! Every handle checks the vault state in the core before each call and fails with
//! `Locked` after `VaultHandle::lock`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use zeroenclave_core as zc;
use zeroize::Zeroizing;

mod error;
mod types;

pub use error::ZeError;
pub use types::*;

uniffi::setup_scaffolding!();

type Result<T> = core::result::Result<T, ZeError>;

/// Upper bound for one `read_range` call.
const MAX_READ_LEN: u64 = 4 * 1024 * 1024;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn parse_items(ids: &[String]) -> Result<Vec<zc::ItemId>> {
    ids.iter()
        .map(|s| types::parse_id(s).map(zc::ItemId))
        .collect()
}

/// Takes ownership of a secret from Swift so the Rust copy is wiped on drop (crypto §11).
fn secret(s: String) -> Zeroizing<String> {
    Zeroizing::new(s)
}

fn path(s: &str) -> Result<PathBuf> {
    if s.is_empty() {
        return Err(ZeError::InvalidInput);
    }
    Ok(Path::new(s).to_path_buf())
}

#[derive(uniffi::Record)]
pub struct CreatedVault {
    pub handle: Arc<VaultHandle>,
    /// Shown once at setup.
    pub recovery_key: String,
}

#[derive(uniffi::Enum)]
pub enum UnlockResult {
    Open {
        handle: Arc<VaultHandle>,
    },
    /// The old vault was destroyed; this one is fresh and empty.
    Duress {
        handle: Arc<VaultHandle>,
    },
    WrongPassword,
}

#[uniffi::export(callback_interface)]
pub trait ProgressCallback: Send + Sync {
    fn progress(&self, done: u64, total: u64);
}

#[uniffi::export]
pub fn vault_create(root: String, password: String, params: KdfParams) -> Result<CreatedVault> {
    let password = secret(password);
    let (vault, rk) = zc::Vault::create(&path(&root)?, &password, params.into())?;
    Ok(CreatedVault {
        handle: VaultHandle::new(vault),
        recovery_key: rk.to_string(),
    })
}

/// `boot_time` (kernel boot) and `now` are Unix seconds; they refresh the biometric slot.
#[uniffi::export]
pub fn vault_unlock(
    root: String,
    password: String,
    boot_time: u64,
    now: u64,
) -> Result<UnlockResult> {
    let password = secret(password);
    Ok(
        match zc::Vault::unlock(&path(&root)?, &password, boot_time, now)? {
            zc::UnlockResult::Open(v) => UnlockResult::Open {
                handle: VaultHandle::new(v),
            },
            zc::UnlockResult::Duress(v) => UnlockResult::Duress {
                handle: VaultHandle::new(v),
            },
            zc::UnlockResult::WrongPassword => UnlockResult::WrongPassword,
        },
    )
}

#[uniffi::export]
pub fn vault_unlock_recovery(
    root: String,
    recovery_key: String,
    boot_time: u64,
    now: u64,
) -> Result<Arc<VaultHandle>> {
    let recovery_key = secret(recovery_key);
    let v = zc::Vault::unlock_recovery(&path(&root)?, &recovery_key, boot_time, now)?;
    Ok(VaultHandle::new(v))
}

/// Unlocks with the 32-byte device-bound key. Fails with `BiometricExpired` after a reboot
/// or 7 days without a password unlock, and with `BiometricInvalid` on any mismatch.
#[uniffi::export]
pub fn vault_unlock_biometric(
    root: String,
    bio_key: Vec<u8>,
    boot_time: u64,
    now: u64,
) -> Result<Arc<VaultHandle>> {
    let key = zc::BioKey::from_vec(bio_key)?;
    let v = zc::Vault::unlock_biometric(&path(&root)?, &key, boot_time, now)?;
    Ok(VaultHandle::new(v))
}

/// True if a biometric slot exists; works while the vault is locked.
#[uniffi::export]
pub fn vault_is_biometric_enabled(root: String) -> bool {
    path(&root).is_ok_and(|p| zc::Vault::biometric_slot_exists(&p))
}

/// Deletes the biometric slot without opening the vault.
#[uniffi::export]
pub fn vault_remove_biometric(root: String) -> Result<()> {
    Ok(zc::Vault::remove_biometric_slot(&path(&root)?)?)
}

/// Unlocks with the 6-digit PIN and the 32-byte device-bound `se_secret`. One attempt: a
/// wrong PIN pauses the slot until the next password or recovery unlock (`PinInvalid`);
/// a malformed PIN is `InvalidInput` and leaves the slot untouched.
#[uniffi::export]
pub fn vault_unlock_pin(
    root: String,
    se_secret: Vec<u8>,
    pin: String,
    boot_time: u64,
    now: u64,
) -> Result<Arc<VaultHandle>> {
    let pin = secret(pin);
    let se_secret = zc::BioKey::from_vec(se_secret)?;
    let v = zc::Vault::unlock_pin(&path(&root)?, &se_secret, &pin, boot_time, now)?;
    Ok(VaultHandle::new(v))
}

/// True if a PIN slot exists, active or paused; works while the vault is locked.
#[uniffi::export]
pub fn vault_is_pin_enabled(root: String) -> bool {
    path(&root).is_ok_and(|p| zc::Vault::pin_slot_exists(&p))
}

/// True if PIN unlock is paused until the next password or recovery unlock.
#[uniffi::export]
pub fn vault_is_pin_paused(root: String) -> bool {
    path(&root).is_ok_and(|p| zc::Vault::pin_slot_paused(&p))
}

/// Pauses PIN unlock until the next password or recovery unlock (manual lock).
#[uniffi::export]
pub fn vault_pause_pin(root: String) -> Result<()> {
    Ok(zc::Vault::pause_pin_slot(&path(&root)?)?)
}

/// Deletes the PIN slot without opening the vault.
#[uniffi::export]
pub fn vault_remove_pin(root: String) -> Result<()> {
    Ok(zc::Vault::remove_pin_slot(&path(&root)?)?)
}

#[uniffi::export]
pub fn vault_import_from(
    root: String,
    export_path: String,
    secret: ImportSecret,
) -> Result<ImportOutcome> {
    let outcome = zc::Vault::import_from(&path(&root)?, &path(&export_path)?, secret.into())?;
    Ok(outcome.into())
}

/// Calibrates `t` so that one derivation takes at least `target_ms`; blocks while measuring.
#[uniffi::export]
pub fn kdf_calibrate(target_ms: u32) -> KdfParams {
    zc::kdf_calibrate(target_ms).into()
}

/// Password strength, 0 (weak) to 4 (strong).
#[uniffi::export]
pub fn password_strength(pw: String) -> u8 {
    zc::password_strength(&secret(pw))
}

#[uniffi::export]
pub fn kdf_default() -> KdfParams {
    zc::KdfParams::DEFAULT.into()
}

#[derive(uniffi::Object)]
pub struct VaultHandle {
    vault: Arc<zc::Vault>,
}

impl VaultHandle {
    fn new(vault: zc::Vault) -> Arc<Self> {
        Arc::new(Self {
            vault: Arc::new(vault),
        })
    }
}

#[uniffi::export]
impl VaultHandle {
    /// Drops all keys; every handle derived from this vault fails with `Locked` afterwards.
    pub fn lock(&self) {
        self.vault.lock();
    }

    pub fn is_locked(&self) -> bool {
        self.vault.items().err() == Some(zc::Error::Locked)
    }

    /// True after a detected rollback (vault-format §6): viewing and export work, changes fail
    /// with `ReadOnly` until `accept_current_state`.
    pub fn is_read_only(&self) -> bool {
        self.vault.is_read_only()
    }

    /// Ends read-only mode after the owner confirmed the current files with the master password.
    pub fn accept_current_state(&self, password: String) -> Result<()> {
        Ok(self.vault.accept_current_state(&secret(password))?)
    }

    pub fn items(&self) -> Result<Vec<ItemSummary>> {
        Ok(self.vault.items()?.into_iter().map(Into::into).collect())
    }

    pub fn begin_import(&self, kind: ItemKind, meta: ItemMeta) -> Result<Arc<ImportSession>> {
        let s = self.vault.begin_import(kind.into(), meta.into())?;
        Ok(Arc::new(ImportSession {
            session: Mutex::new(Some(s)),
        }))
    }

    pub fn delete_items(&self, ids: Vec<String>) -> Result<()> {
        Ok(self.vault.delete_items(&parse_items(&ids)?)?)
    }

    /// Moves items to the trash; already trashed items keep their date.
    pub fn trash_items(&self, ids: Vec<String>, now_ms: u64) -> Result<()> {
        Ok(self.vault.trash_items(&parse_items(&ids)?, now_ms)?)
    }

    pub fn restore_items(&self, ids: Vec<String>) -> Result<()> {
        Ok(self.vault.restore_items(&parse_items(&ids)?)?)
    }

    /// Permanently deletes trashed items past the retention period; returns their number.
    pub fn purge_expired(&self, now_ms: u64) -> Result<u64> {
        Ok(self.vault.purge_expired(now_ms)?)
    }

    pub fn create_album(&self, name: String) -> Result<String> {
        Ok(types::hex_id(&self.vault.create_album(&name)?.0))
    }

    pub fn rename_album(&self, album_id: String, name: String) -> Result<()> {
        let id = zc::AlbumId(types::parse_id(&album_id)?);
        Ok(self.vault.rename_album(id, &name)?)
    }

    /// Sets (`Some`) or removes (`None`) the four-digit view-lock code of an album.
    pub fn set_album_pin(&self, album_id: String, code: Option<String>) -> Result<()> {
        let id = zc::AlbumId(types::parse_id(&album_id)?);
        Ok(self.vault.set_album_pin(id, code.as_deref())?)
    }

    /// True if the code matches; false if wrong or the album has no code.
    pub fn verify_album_pin(&self, album_id: String, code: String) -> Result<bool> {
        let id = zc::AlbumId(types::parse_id(&album_id)?);
        Ok(self.vault.verify_album_pin(id, &code)?)
    }

    pub fn set_album_show_in_all(&self, album_id: String, show: bool) -> Result<()> {
        let id = zc::AlbumId(types::parse_id(&album_id)?);
        Ok(self.vault.set_album_show_in_all(id, show)?)
    }

    pub fn delete_album(&self, album_id: String) -> Result<()> {
        let id = zc::AlbumId(types::parse_id(&album_id)?);
        Ok(self.vault.delete_album(id)?)
    }

    pub fn add_to_album(&self, album_id: String, item_ids: Vec<String>) -> Result<()> {
        let id = zc::AlbumId(types::parse_id(&album_id)?);
        Ok(self.vault.add_to_album(id, &parse_items(&item_ids)?)?)
    }

    pub fn remove_from_album(&self, album_id: String, item_ids: Vec<String>) -> Result<()> {
        let id = zc::AlbumId(types::parse_id(&album_id)?);
        Ok(self.vault.remove_from_album(id, &parse_items(&item_ids)?)?)
    }

    pub fn albums(&self) -> Result<Vec<AlbumSummary>> {
        Ok(self.vault.albums()?.into_iter().map(Into::into).collect())
    }

    pub fn album_items(&self, album_id: String) -> Result<Vec<String>> {
        let id = zc::AlbumId(types::parse_id(&album_id)?);
        Ok(self
            .vault
            .album_items(id)?
            .iter()
            .map(|i| types::hex_id(&i.0))
            .collect())
    }

    pub fn set_meta(&self, item_id: String, field: String, value: MetaValue) -> Result<()> {
        let id = zc::ItemId(types::parse_id(&item_id)?);
        Ok(self.vault.set_meta(id, &field, value.into())?)
    }

    pub fn open_object(&self, object_id: String) -> Result<Arc<ObjectReaderHandle>> {
        let r = self.vault.open_object(types::parse_id(&object_id)?)?;
        Ok(Arc::new(ObjectReaderHandle {
            len: r.plaintext_len(),
            reader: Mutex::new(r),
        }))
    }

    /// Also removes Face ID and PIN unlock; the caller deletes their device keys.
    pub fn change_password(&self, old: String, new: String, params: KdfParams) -> Result<()> {
        let (old, new) = (secret(old), secret(new));
        Ok(self.vault.change_password(&old, &new, params.into())?)
    }

    /// Verifies the master `password` first.
    pub fn set_duress(&self, password: String, duress_password: String) -> Result<()> {
        let (password, duress_password) = (secret(password), secret(duress_password));
        Ok(self.vault.set_duress(&password, &duress_password)?)
    }

    /// Verifies the master `password` first.
    pub fn disable_duress(&self, password: String) -> Result<()> {
        Ok(self.vault.disable_duress(&secret(password))?)
    }

    /// False while locked.
    pub fn is_duress_enabled(&self) -> bool {
        self.vault.is_duress_enabled()
    }

    /// Checks the master password; `WrongPassword` also for the duress password.
    pub fn verify_password(&self, password: String) -> Result<()> {
        Ok(self.vault.verify_password(&secret(password))?)
    }

    /// Verifies the master `password` first. `bio_key` must be 32 bytes. `boot_time` and
    /// `now` are Unix seconds.
    pub fn enable_biometric(
        &self,
        password: String,
        bio_key: Vec<u8>,
        boot_time: u64,
        now: u64,
    ) -> Result<()> {
        let password = secret(password);
        let key = zc::BioKey::from_vec(bio_key)?;
        Ok(self
            .vault
            .enable_biometric(&password, &key, boot_time, now)?)
    }

    pub fn disable_biometric(&self) -> Result<()> {
        Ok(self.vault.disable_biometric()?)
    }

    /// False while locked.
    pub fn is_biometric_enabled(&self) -> bool {
        self.vault.is_biometric_enabled()
    }

    /// Verifies the master `password` first. `se_secret` must be 32 bytes, `pin` 6 ASCII
    /// digits. `boot_time` and `now` are Unix seconds.
    pub fn enable_pin(
        &self,
        password: String,
        se_secret: Vec<u8>,
        pin: String,
        boot_time: u64,
        now: u64,
    ) -> Result<()> {
        let (password, pin) = (secret(password), secret(pin));
        let se_secret = zc::BioKey::from_vec(se_secret)?;
        Ok(self
            .vault
            .enable_pin(&password, &se_secret, &pin, boot_time, now)?)
    }

    pub fn disable_pin(&self) -> Result<()> {
        Ok(self.vault.disable_pin()?)
    }

    /// False while locked.
    pub fn is_pin_enabled(&self) -> bool {
        self.vault.is_pin_enabled()
    }

    /// Verifies the master password, then destroys the vault on this device and locks
    /// the handle. Nothing is deleted on a wrong password.
    pub fn erase(&self, password: String) -> Result<()> {
        Ok(self.vault.erase(&secret(password))?)
    }

    /// Verifies the master password, then replaces the recovery key.
    pub fn rotate_recovery(&self, password: String) -> Result<String> {
        Ok(self.vault.rotate_recovery(&secret(password))?.to_string())
    }

    pub fn export_to(&self, path: String, progress: Box<dyn ProgressCallback>) -> Result<()> {
        let path = self::path(&path)?;
        Ok(self
            .vault
            .export_to(&path, |done, total| progress.progress(done, total))?)
    }

    pub fn import_into(&self, path: String, secret: ImportSecret) -> Result<ImportOutcome> {
        let path = self::path(&path)?;
        Ok(self.vault.import_into(&path, secret.into())?.into())
    }

    /// Replaces this vault with the backup after verifying `current_password` and the
    /// backup completely. The handle is locked afterwards.
    pub fn replace_from_backup(
        &self,
        current_password: String,
        path: String,
        secret: ImportSecret,
    ) -> Result<()> {
        let path = self::path(&path)?;
        Ok(self
            .vault
            .replace_from_backup(&self::secret(current_password), &path, secret.into())?)
    }
}

/// One item under construction. `commit` and `abort` consume the session.
#[derive(uniffi::Object)]
pub struct ImportSession {
    session: Mutex<Option<zc::ImportSession>>,
}

#[uniffi::export]
impl ImportSession {
    pub fn add_object(&self, role: ObjectRole) -> Result<Arc<ObjectWriterHandle>> {
        let mut g = lock(&self.session);
        let w = g
            .as_mut()
            .ok_or(ZeError::InvalidInput)?
            .add_object(role.into())?;
        Ok(Arc::new(ObjectWriterHandle {
            writer: Mutex::new(Some(w)),
        }))
    }

    /// Returns the new item id (32-char hex).
    pub fn commit(&self) -> Result<String> {
        let s = lock(&self.session).take().ok_or(ZeError::InvalidInput)?;
        Ok(types::hex_id(&s.commit()?.0))
    }

    pub fn abort(&self) {
        if let Some(s) = lock(&self.session).take() {
            s.abort();
        }
    }
}

/// Streaming writer for one object; `finish` consumes it.
#[derive(uniffi::Object)]
pub struct ObjectWriterHandle {
    writer: Mutex<Option<zc::ImportWriter>>,
}

#[uniffi::export]
impl ObjectWriterHandle {
    pub fn write(&self, data: Vec<u8>) -> Result<()> {
        let mut g = lock(&self.writer);
        Ok(g.as_mut().ok_or(ZeError::InvalidInput)?.write(&data)?)
    }

    pub fn finish(&self) -> Result<()> {
        let w = lock(&self.writer).take().ok_or(ZeError::InvalidInput)?;
        w.finish()?;
        Ok(())
    }
}

#[derive(uniffi::Object)]
pub struct ObjectReaderHandle {
    len: u64,
    reader: Mutex<zc::GuardedReader>,
}

#[uniffi::export]
impl ObjectReaderHandle {
    pub fn plaintext_len(&self) -> u64 {
        self.len
    }

    /// `len` is capped at 4 MiB; a range beyond the end of the object fails with `OutOfRange`.
    pub fn read_range(&self, offset: u64, len: u32) -> Result<Vec<u8>> {
        let len = u64::from(len).min(MAX_READ_LEN);
        Ok(lock(&self.reader).read_range(offset, len)?)
    }

    pub fn read_all(&self) -> Result<Vec<u8>> {
        Ok(lock(&self.reader).read_all()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "correct horse";

    #[test]
    fn create_import_read_lock_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap().to_owned();
        let created = vault_create(root.clone(), PW.into(), kdf_default()).unwrap();
        let h = created.handle;
        assert!(!created.recovery_key.is_empty());
        assert!(!h.is_locked() && !h.is_read_only());

        let meta = ItemMeta {
            filename: Some("a.jpg".into()),
            imported: 1,
            ..ItemMeta::default()
        };
        let s = h.begin_import(ItemKind::Photo, meta).unwrap();
        let w = s.add_object(ObjectRole::Original).unwrap();
        w.write(b"original ".to_vec()).unwrap();
        w.write(b"bytes".to_vec()).unwrap();
        w.finish().unwrap();
        assert_eq!(w.write(vec![1]), Err(ZeError::InvalidInput));
        let id = s.commit().unwrap();
        assert_eq!(s.commit(), Err(ZeError::InvalidInput));

        let items = h.items().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, id);
        assert_eq!(items[0].id.len(), 32);
        let oid = items[0].objects[0].object_id.clone();
        let r = h.open_object(oid.clone()).unwrap();
        assert_eq!(r.plaintext_len(), 14);
        assert_eq!(r.read_range(9, 5).unwrap(), b"bytes");
        assert_eq!(r.read_all().unwrap(), b"original bytes");
        assert_eq!(
            h.open_object("xyz".into()).err(),
            Some(ZeError::InvalidInput)
        );

        h.lock();
        assert!(h.is_locked());
        assert_eq!(r.read_all(), Err(ZeError::Locked));
        assert_eq!(r.read_range(0, 1), Err(ZeError::Locked));
        assert_eq!(h.items().err(), Some(ZeError::Locked));

        assert!(matches!(
            vault_unlock(root.clone(), "nope".into(), 1, 2).unwrap(),
            UnlockResult::WrongPassword
        ));
        let UnlockResult::Open { handle } = vault_unlock(root, PW.into(), 1, 2).unwrap() else {
            panic!("expected Open");
        };
        let r = handle.open_object(oid).unwrap();
        assert_eq!(r.read_all().unwrap(), b"original bytes");
        let album = handle.create_album("Trip".into()).unwrap();
        handle
            .add_to_album(album.clone(), vec![id.clone()])
            .unwrap();
        assert_eq!(handle.items().unwrap()[0].albums, vec![album.clone()]);
        assert_eq!(handle.album_items(album.clone()).unwrap(), vec![id.clone()]);
        let list = handle.albums().unwrap();
        assert_eq!(list[0].name, "Trip");
        assert_eq!(list[0].cover_item.as_deref(), Some(id.as_str()));
        handle.rename_album(album.clone(), "Berge".into()).unwrap();
        handle
            .remove_from_album(album.clone(), vec![id.clone()])
            .unwrap();
        assert!(handle.album_items(album.clone()).unwrap().is_empty());
        assert_eq!(
            handle.add_to_album("zz".into(), vec![id.clone()]),
            Err(ZeError::InvalidInput)
        );
        handle
            .set_album_pin(album.clone(), Some("4321".into()))
            .unwrap();
        assert!(handle
            .verify_album_pin(album.clone(), "4321".into())
            .unwrap());
        assert!(!handle
            .verify_album_pin(album.clone(), "0000".into())
            .unwrap());
        assert_eq!(
            handle.set_album_pin(album.clone(), Some("abcd".into())),
            Err(ZeError::InvalidInput)
        );
        let a = handle.albums().unwrap().remove(0);
        assert!(a.locked && !a.show_in_all);
        handle.set_album_show_in_all(album.clone(), true).unwrap();
        assert!(handle.albums().unwrap()[0].show_in_all);
        handle.set_album_pin(album.clone(), None).unwrap();
        assert!(!handle.albums().unwrap()[0].locked);
        handle.delete_album(album.clone()).unwrap();
        assert_eq!(handle.album_items(album), Err(ZeError::NotFound));
        handle.delete_items(vec![id]).unwrap();
        assert!(handle.items().unwrap().is_empty());
    }

    #[test]
    fn writer_and_session_fail_after_lock() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap().to_owned();
        let h = vault_create(root, PW.into(), kdf_default()).unwrap().handle;
        let s = h
            .begin_import(ItemKind::Photo, ItemMeta::default())
            .unwrap();
        let w = s.add_object(ObjectRole::Original).unwrap();
        w.write(b"x".to_vec()).unwrap();
        h.lock();
        assert_eq!(w.write(b"y".to_vec()), Err(ZeError::Locked));
        assert_eq!(w.finish(), Err(ZeError::Locked));
        assert_eq!(s.commit(), Err(ZeError::Locked));
        assert_eq!(
            h.begin_import(ItemKind::Photo, ItemMeta::default()).err(),
            Some(ZeError::Locked)
        );
    }

    #[test]
    fn pin_single_attempt() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap().to_owned();
        let h = vault_create(root.clone(), PW.into(), kdf_default())
            .unwrap()
            .handle;
        assert_eq!(
            h.enable_pin(PW.into(), vec![7; 31], "123456".into(), 1, 2),
            Err(ZeError::InvalidInput)
        );
        h.enable_pin(PW.into(), vec![7; 32], "123456".into(), 1, 2)
            .unwrap();
        assert!(h.is_pin_enabled() && vault_is_pin_enabled(root.clone()));
        h.lock();
        assert_eq!(
            vault_unlock_pin(root.clone(), vec![7; 32], "12345".into(), 1, 2).err(),
            Some(ZeError::InvalidInput)
        );
        let h = vault_unlock_pin(root.clone(), vec![7; 32], "123456".into(), 1, 3).unwrap();
        h.lock();
        assert_eq!(
            vault_unlock_pin(root.clone(), vec![7; 32], "654321".into(), 1, 3).err(),
            Some(ZeError::PinInvalid)
        );
        assert!(vault_is_pin_enabled(root.clone()) && vault_is_pin_paused(root.clone()));
        let UnlockResult::Open { handle } = vault_unlock(root.clone(), PW.into(), 1, 3).unwrap()
        else {
            panic!("expected Open");
        };
        handle.lock();
        assert!(!vault_is_pin_paused(root.clone()));
        vault_pause_pin(root.clone()).unwrap();
        assert!(vault_is_pin_paused(root.clone()));
        vault_remove_pin(root.clone()).unwrap();
        assert!(!vault_is_pin_enabled(root));
    }

    #[test]
    fn biometric_duress_and_erase() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap().to_owned();
        let h = vault_create(root.clone(), PW.into(), kdf_default())
            .unwrap()
            .handle;
        assert!(!h.is_duress_enabled() && !h.is_biometric_enabled());
        h.set_duress(PW.into(), "duress pw".into()).unwrap();
        assert!(h.is_duress_enabled());
        assert_eq!(
            h.verify_password("nope".into()),
            Err(ZeError::WrongPassword)
        );
        h.verify_password(PW.into()).unwrap();

        assert_eq!(
            h.enable_biometric(PW.into(), vec![7; 31], 1, 2),
            Err(ZeError::InvalidInput)
        );
        h.enable_biometric(PW.into(), vec![7; 32], 1, 2).unwrap();
        assert!(h.is_biometric_enabled() && vault_is_biometric_enabled(root.clone()));
        h.lock();
        assert!(!h.is_biometric_enabled() && !h.is_duress_enabled());
        assert_eq!(
            vault_unlock_biometric(root.clone(), vec![7; 5], 1, 2).err(),
            Some(ZeError::InvalidInput)
        );
        assert_eq!(
            vault_unlock_biometric(root.clone(), vec![8; 32], 1, 2).err(),
            Some(ZeError::BiometricInvalid)
        );
        assert_eq!(
            vault_unlock_biometric(root.clone(), vec![7; 32], 2, 2).err(),
            Some(ZeError::BiometricExpired)
        );
        let h = vault_unlock_biometric(root.clone(), vec![7; 32], 1, 3).unwrap();
        assert!(h.is_duress_enabled());
        h.disable_biometric().unwrap();
        assert!(!vault_is_biometric_enabled(root.clone()));

        assert_eq!(h.erase("nope".into()), Err(ZeError::WrongPassword));
        h.erase(PW.into()).unwrap();
        assert!(h.is_locked());
        assert_eq!(
            vault_unlock(root, PW.into(), 1, 2).err(),
            Some(ZeError::NotAVault)
        );
    }
}

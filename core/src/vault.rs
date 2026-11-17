//! Public vault API: lifecycle, import, delete and key management.
//!
//! The vault handle keeps its state behind a `Mutex<Option<Inner>>`; `lock()` drops
//! the inner state (and with it all keys) and every method fails with `Locked` afterwards.
//! Sessions, writers and readers hold a weak reference to that state and check it before
//! every operation; on `Locked` they drop their own key material.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, Instant};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::biometric::{self, Kind};
use crate::cbor::Value;
use crate::error::{Error, Result};
use crate::export::{self, ImportOutcome, ImportSecret};
use crate::header::{self, DuressUpdate, UnlockOutcome, VaultHeader};
use crate::journal::{
    clean_album_name, next_t, read_all_chains, sweep, write_segment, AlbumId, Chains, DeviceId,
    ItemId, ItemKind, ItemMeta, Op, Segment, State, ALBUM_PIN_LEN, TRASH_RETENTION_MS,
};
use crate::kdf::{self, album_pin_digest, derive_master_key, export_mac_key, KdfParams, PIN_LEN};
use crate::keys::{BioKey, VaultKey};
use crate::local::{check_rollback, device_id, read_local_state, write_local_state, LocalState};
use crate::object::{self, open_object, write_object, ObjectKind, ObjectReader};
use crate::recovery::RecoveryKey;
use crate::rng::{self, OsRandom};
use crate::store::Store;

/// Unreferenced objects younger than this survive the sweep (vault-format §5.4).
const SWEEP_AGE: Duration = Duration::from_secs(24 * 60 * 60);
const CALIBRATION_MAX_T: u32 = 32;

pub type ObjectId = [u8; 16];

/// Encoded recovery key; shown once at setup.
pub type RecoveryKeyString = Zeroizing<String>;

/// Role of an object within an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ObjectRole {
    Original,
    ThumbSmall,
    ThumbLarge,
    PairedVideo,
}

impl ObjectRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Original => "original",
            Self::ThumbSmall => "thumb_small",
            Self::ThumbLarge => "thumb_large",
            Self::PairedVideo => "paired_video",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "original" => Some(Self::Original),
            "thumb_small" => Some(Self::ThumbSmall),
            "thumb_large" => Some(Self::ThumbLarge),
            "paired_video" => Some(Self::PairedVideo),
            _ => None,
        }
    }
}

/// A live item as shown to the app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemSummary {
    pub id: ItemId,
    pub kind: ItemKind,
    pub meta: ItemMeta,
    pub objects: BTreeMap<ObjectRole, ObjectId>,
    /// Live albums containing the item, ordered by id (trashed items keep memberships).
    pub albums: Vec<AlbumId>,
    /// In at least one album that is not shown in All Photos; clients leave such items
    /// out of the All Photos grid (they stay visible inside their albums).
    pub hidden_in_all: bool,
}

/// A live album as shown to the app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlbumSummary {
    pub id: AlbumId,
    pub name: String,
    pub item_count: u64,
    /// Newest member by capture (else import) time.
    pub cover_item: Option<ItemId>,
    /// A view-lock code is set.
    pub locked: bool,
    /// Items of this album appear in All Photos.
    pub show_in_all: bool,
}

/// Number of digits of an album view-lock code.
pub const ALBUM_CODE_LEN: usize = 4;

fn valid_album_code(code: &str) -> bool {
    code.len() == ALBUM_CODE_LEN && code.bytes().all(|b| b.is_ascii_digit())
}

/// Outcome of a password unlock.
pub enum UnlockResult {
    Open(Vault),
    /// Duress password entered: the old vault is destroyed, this one is fresh and empty.
    Duress(Vault),
    WrongPassword,
}

struct Inner {
    store: Store,
    vk: VaultKey,
    header: VaultHeader,
    device: DeviceId,
    chains: Chains,
    state: State,
    read_only: bool,
    duress_enabled: bool,
    handles: Vec<OpenHandle>,
}

/// Lock, erase and replace all drop `Inner`; open readers and writers lose their keys here.
impl Drop for Inner {
    fn drop(&mut self) {
        for h in &self.handles {
            h.revoke();
        }
    }
}

impl Inner {
    fn track(&mut self, handle: OpenHandle) {
        self.handles.retain(OpenHandle::is_alive);
        self.handles.push(handle);
    }

    fn vault_id(&self) -> [u8; 16] {
        *self.header.vault_id()
    }

    /// `password` must open the on-disk header with the key of this open vault.
    /// Wrong and duress passwords both fail with `WrongPassword`.
    fn check_password(&self, password: &str) -> Result<()> {
        let on_disk = read_header(&self.store)?;
        match header::unlock(&on_disk, password)? {
            UnlockOutcome::Open(vk) if bool::from(vk.as_bytes().ct_eq(self.vk.as_bytes())) => {
                Ok(())
            }
            _ => Err(Error::WrongPassword),
        }
    }

    /// Commits one segment with `ops` to the own chain and updates the cached state.
    fn append(&mut self, ops: Vec<Op>) -> Result<()> {
        let chain = self.chains.entry(self.device).or_default();
        let seq = chain.len() as u64;
        let prev = chain.last().map_or([0; 32], |s| s.hash);
        let hash = write_segment(
            &self.store,
            &self.vk,
            *self.header.vault_id(),
            self.device,
            seq,
            prev,
            ops.clone(),
        )?;
        for op in &ops {
            self.state.apply(op);
        }
        chain.push(Segment {
            device: self.device,
            seq,
            prev,
            ops,
            hash,
        });
        self.persist_local();
        Ok(())
    }

    /// Commits the tombstones first, then deletes the referenced objects.
    fn delete_items(&mut self, ids: &[ItemId]) -> Result<()> {
        let ids: BTreeSet<_> = ids.iter().copied().collect();
        let mut objects = Vec::new();
        for id in &ids {
            let it = self.state.item(id).ok_or(Error::NotFound)?;
            objects.extend(it.objects.values().copied());
        }
        if ids.is_empty() {
            return Ok(());
        }
        let t = next_t(&self.state);
        let ops = (t..)
            .zip(&ids)
            .map(|(t, item)| Op::ItemDel { t, item: *item })
            .collect();
        self.append(ops)?;
        for o in objects {
            // Best effort; leftovers are removed by the sweep.
            let _ = self.store.delete_object(&o);
        }
        Ok(())
    }

    /// The local state is a cache; the journal segment is the commit point.
    fn persist_local(&self) {
        let _ = self.try_persist_local();
    }

    fn try_persist_local(&self) -> Result<()> {
        let mut local = LocalState::build(&self.chains, self.state.clone());
        local.duress_enabled = self.duress_enabled;
        write_local_state(&self.store, &self.vk, self.vault_id(), &local)
    }

    /// Records the duress state in the encrypted local state; errors are reported.
    fn set_duress_flag(&mut self, enabled: bool) -> Result<()> {
        self.duress_enabled = enabled;
        self.try_persist_local()
    }

    fn write_header(&mut self, h: VaultHeader) -> Result<()> {
        self.store.write_atomic(&self.store.header_path(), |f| {
            f.write_all(&h.to_bytes()).map_err(|_| Error::Io)
        })?;
        self.header = h;
        Ok(())
    }
}

type Shared = Mutex<Option<Inner>>;

fn lock_shared(m: &Shared) -> MutexGuard<'_, Option<Inner>> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn with_shared<R>(m: &Shared, f: impl FnOnce(&mut Inner) -> Result<R>) -> Result<R> {
    let mut g = lock_shared(m);
    f(g.as_mut().ok_or(Error::Locked)?)
}

fn with_shared_mut<R>(m: &Shared, f: impl FnOnce(&mut Inner) -> Result<R>) -> Result<R> {
    with_shared(m, |i| {
        if i.read_only {
            Err(Error::ReadOnly)
        } else {
            f(i)
        }
    })
}

/// Like `with_shared_mut` through a weak reference; a dropped vault counts as locked.
fn with_weak_mut<R>(w: &Weak<Shared>, f: impl FnOnce(&mut Inner) -> Result<R>) -> Result<R> {
    let shared = w.upgrade().ok_or(Error::Locked)?;
    with_shared_mut(&shared, f)
}

/// Runs `f` while holding the vault guard, so `lock()` waits for it and nothing runs after.
/// Fails with `Locked` once the vault was locked or dropped.
fn while_open<R>(w: &Weak<Shared>, f: impl FnOnce() -> Result<R>) -> Result<R> {
    let shared = w.upgrade().ok_or(Error::Locked)?;
    with_shared(&shared, |_| f())
}

/// Handle to an open vault. `Send + Sync`; usable until `lock()`.
pub struct Vault {
    inner: Arc<Shared>,
}

pub(crate) fn read_header(store: &Store) -> Result<VaultHeader> {
    match fs::read(store.header_path()) {
        Ok(b) => VaultHeader::parse(&b),
        Err(e) if e.kind() == ErrorKind::NotFound => Err(Error::NotAVault),
        Err(_) => Err(Error::Io),
    }
}

fn remove_dir(path: &Path) -> Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(_) => Err(Error::Io),
    }
}

/// Crypto-shredding (crypto §7): the header goes first, so the rest is unrecoverable.
fn shred(store: &Store) -> Result<()> {
    let path = store.header_path();
    let len = fs::metadata(&path).map_err(|_| Error::Io)?.len();
    let mut junk = vec![0u8; usize::try_from(len).map_err(|_| Error::Io)?];
    rng::fill(&mut junk)?;
    let mut f = File::options()
        .write(true)
        .open(&path)
        .map_err(|_| Error::Io)?;
    f.write_all(&junk).map_err(|_| Error::Io)?;
    f.sync_all().map_err(|_| Error::Io)?;
    drop(f);
    fs::remove_file(&path).map_err(|_| Error::Io)?;
    if let Ok(dir) = File::open(store.root()) {
        let _ = dir.sync_all();
    }
    remove_dir(&store.local_dir())?;
    remove_dir(&store.root().join("objects"))?;
    remove_dir(&store.root().join("journal"))
}

impl Vault {
    fn from_inner(inner: Inner) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(inner))),
        }
    }

    /// Creates a new vault; fails with `Exists` if `vault.zev` is present.
    pub fn create(
        root: &Path,
        password: &str,
        params: KdfParams,
    ) -> Result<(Vault, RecoveryKeyString)> {
        let store = Store::new(root);
        if store.header_path().exists() {
            return Err(Error::Exists);
        }
        let (header, vk, rk) = header::create(password, params)?;
        fs::create_dir_all(root).map_err(|_| Error::Io)?;
        store.write_atomic(&store.header_path(), |f| {
            f.write_all(&header.to_bytes()).map_err(|_| Error::Io)
        })?;
        let device = device_id(&store)?;
        write_local_state(&store, &vk, *header.vault_id(), &LocalState::empty())?;
        let vault = Vault::from_inner(Inner {
            store,
            vk,
            header,
            device,
            chains: Chains::new(),
            state: State::new(),
            read_only: false,
            duress_enabled: false,
            handles: Vec::new(),
        });
        Ok((vault, rk.encode()))
    }

    /// One Argon2id run; on the duress password the vault is destroyed and replaced.
    /// `boot_time` (kernel boot, Unix seconds) and `now` (Unix seconds) come from the caller;
    /// they refresh the biometric slot, if any (crypto §12).
    pub fn unlock(root: &Path, password: &str, boot_time: u64, now: u64) -> Result<UnlockResult> {
        Self::unlock_with(root, password, boot_time, now, SWEEP_AGE)
    }

    pub(crate) fn unlock_with(
        root: &Path,
        password: &str,
        boot_time: u64,
        now: u64,
        sweep_age: Duration,
    ) -> Result<UnlockResult> {
        let store = Store::new(root);
        let header = read_header(&store)?;
        match header::unlock(&header, password)? {
            UnlockOutcome::Open(vk) => Ok(UnlockResult::Open(Self::open_with_key(
                store,
                header,
                vk,
                sweep_age,
                Some((boot_time, now)),
            )?)),
            UnlockOutcome::Duress => {
                let params = header.kdf_params();
                shred(&store)?;
                // The recovery key of the fresh vault is discarded.
                let (vault, _) = Vault::create(root, password, params)?;
                Ok(UnlockResult::Duress(vault))
            }
            UnlockOutcome::WrongPassword => Ok(UnlockResult::WrongPassword),
        }
    }

    /// Like `unlock`, with the recovery key; see there for `boot_time` and `now`.
    pub fn unlock_recovery(
        root: &Path,
        recovery_key: &str,
        boot_time: u64,
        now: u64,
    ) -> Result<Vault> {
        let rk = RecoveryKey::decode(recovery_key)?;
        let store = Store::new(root);
        let header = read_header(&store)?;
        let vk = header::unlock_recovery(&header, &rk)?;
        Self::open_with_key(store, header, vk, SWEEP_AGE, Some((boot_time, now)))
    }

    /// Unlocks with the device-bound `bio_key` (crypto §12). Never triggers duress and does
    /// not extend the slot's validity. Fails with `BiometricInvalid` if the slot, the key or
    /// the header do not match, and with `BiometricExpired` after a reboot or once
    /// `now >= expires_at`.
    pub fn unlock_biometric(
        root: &Path,
        bio_key: &BioKey,
        boot_time: u64,
        now: u64,
    ) -> Result<Vault> {
        let store = Store::new(root);
        let header = read_header(&store)?;
        let bytes = biometric::read(&store, Kind::Biometric)?.ok_or(Error::BiometricInvalid)?;
        let vk = Self::open_slot(Kind::Biometric, &bytes, &header, bio_key, boot_time, now)?;
        Self::open_with_key(store, header, vk, SWEEP_AGE, None)
    }

    /// Unlocks with the PIN and the device-bound `se_secret` (crypto §12). One attempt: the
    /// slot is removed before the PIN is tried and written back only if the PIN was right, so
    /// a wrong PIN or an interrupted attempt leaves only the master password. Fails with
    /// `InvalidInput` for a malformed PIN (slot kept), `PinInvalid` (slot gone) and
    /// `PinExpired` (slot kept until a password unlock refreshes it).
    pub fn unlock_pin(
        root: &Path,
        se_secret: &BioKey,
        pin: &str,
        boot_time: u64,
        now: u64,
    ) -> Result<Vault> {
        if pin.len() != PIN_LEN || !pin.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::InvalidInput);
        }
        let store = Store::new(root);
        let header = read_header(&store)?;
        // Take the slot before reading it: a concurrent attempt finds nothing to take.
        if !biometric::pause_pin(&store)? {
            return Err(Error::PinInvalid);
        }
        let bytes = biometric::read_paused_pin(&store)?.ok_or(Error::PinInvalid)?;
        let key = kdf::pin_key(se_secret, pin, header.vault_id())?;
        match Self::open_slot(Kind::Pin, &bytes, &header, &key, boot_time, now) {
            Ok(vk) => {
                biometric::resume_pin(&store)?;
                Self::open_with_key(store, header, vk, SWEEP_AGE, None)
            }
            // The PIN was right (the slot unwrapped); only the policy has run out. The next
            // password unlock refreshes it, so the slot stays active.
            Err(Error::PinExpired) => {
                biometric::resume_pin(&store)?;
                Err(Error::PinExpired)
            }
            Err(e) => Err(e),
        }
    }

    /// Unwraps and checks a quick-unlock slot: key, header MAC, policy MAC, boot and expiry.
    fn open_slot(
        kind: Kind,
        bytes: &[u8],
        header: &VaultHeader,
        key: &BioKey,
        boot_time: u64,
        now: u64,
    ) -> Result<VaultKey> {
        let slot = biometric::Slot::parse(kind, bytes)?;
        let vault_id = *header.vault_id();
        let vk = slot.unwrap_vk(key, &vault_id)?;
        header.verify_mac(&vk).map_err(|_| kind.invalid())?;
        slot.verify_policy(&vk, &vault_id)?;
        if slot.boot_time != boot_time || now >= slot.expires_at {
            // `vk` is zeroized on drop.
            return Err(kind.expired());
        }
        Ok(vk)
    }

    /// True if a biometric slot exists at `root`; usable while the vault is locked.
    pub fn biometric_slot_exists(root: &Path) -> bool {
        biometric::slot_path(&Store::new(root), Kind::Biometric).exists()
    }

    /// Deletes the biometric slot without opening the vault; a missing slot is fine.
    pub fn remove_biometric_slot(root: &Path) -> Result<()> {
        biometric::remove(&Store::new(root), Kind::Biometric)
    }

    /// True if a PIN slot exists at `root`, active or paused; usable while the vault is locked.
    pub fn pin_slot_exists(root: &Path) -> bool {
        let store = Store::new(root);
        biometric::slot_path(&store, Kind::Pin).exists()
            || biometric::paused_pin_path(&store).exists()
    }

    /// True if the PIN slot is paused: the next unlock needs the master password.
    pub fn pin_slot_paused(root: &Path) -> bool {
        let store = Store::new(root);
        !biometric::slot_path(&store, Kind::Pin).exists()
            && biometric::paused_pin_path(&store).exists()
    }

    /// Pauses the PIN slot until the next password or recovery unlock, e.g. on a manual lock.
    pub fn pause_pin_slot(root: &Path) -> Result<()> {
        biometric::pause_pin(&Store::new(root)).map(|_| ())
    }

    /// Deletes the PIN slot, active or paused, without opening the vault.
    pub fn remove_pin_slot(root: &Path) -> Result<()> {
        biometric::remove_pin(&Store::new(root))
    }

    /// `clock` is `(boot_time, now)` for refreshing the quick-unlock slots.
    fn open_with_key(
        store: Store,
        header: VaultHeader,
        vk: VaultKey,
        sweep_age: Duration,
        clock: Option<(u64, u64)>,
    ) -> Result<Vault> {
        let vault_id = *header.vault_id();
        store.cleanup_tmp()?;
        let device = device_id(&store)?;
        let chains = read_all_chains(&store, &vk, vault_id)?;
        let state = State::fold(chains.values().flatten());
        let local = read_local_state(&store, &vk, vault_id);
        let duress_enabled = matches!(&local, Ok(Some(l)) if l.duress_enabled);
        // A missing or unreadable state next to a non-empty journal counts as rollback
        // (vault-format §6): deleting the file must not switch detection off.
        let read_only = match local {
            Ok(Some(l)) => match check_rollback(&l, &chains) {
                Ok(()) => false,
                Err(Error::RollbackDetected) => true,
                Err(e) => return Err(e),
            },
            Ok(None) | Err(_) => !chains.is_empty(),
        };
        let inner = Inner {
            store,
            vk,
            header,
            device,
            chains,
            state,
            read_only,
            duress_enabled,
            handles: Vec::new(),
        };
        if !read_only {
            if let Some((boot_time, now)) = clock {
                // Best effort: an unrefreshed slot only means quick unlock asks for the password.
                // The password also ends a PIN pause.
                let _ = biometric::resume_pin(&inner.store);
                for kind in [Kind::Biometric, Kind::Pin] {
                    let _ = biometric::refresh(
                        &inner.store,
                        kind,
                        &inner.vk,
                        &vault_id,
                        boot_time,
                        now,
                    );
                }
            }
            inner.persist_local();
            inner.store.cleanup_staging()?;
            sweep(&inner.store, &inner.state, sweep_age)?;
        }
        Ok(Vault::from_inner(inner))
    }

    fn guard(&self) -> MutexGuard<'_, Option<Inner>> {
        lock_shared(&self.inner)
    }

    fn with<R>(&self, f: impl FnOnce(&mut Inner) -> Result<R>) -> Result<R> {
        with_shared(&self.inner, f)
    }

    fn with_mut<R>(&self, f: impl FnOnce(&mut Inner) -> Result<R>) -> Result<R> {
        with_shared_mut(&self.inner, f)
    }

    /// Writes the encrypted export (vault-format §7) atomically to `path`.
    /// `progress` receives `(bytes done, bytes total)` of the entry data.
    pub fn export_to(&self, path: &Path, progress: impl FnMut(u64, u64)) -> Result<()> {
        let (store, header, key, files) = self.with(|i| {
            Ok((
                i.store.clone(),
                i.header.to_bytes(),
                export_mac_key(&i.vk, &i.vault_id()),
                export::plan(&i.store, &i.state)?,
            ))
        })?;
        export::write_export(&store, &header, &key, &files, path, progress)
    }

    /// Restores an export into `root` or merges it into the vault with the same id.
    /// A different vault at `root` is never overwritten (`DifferentVault`).
    pub fn import_from(
        root: &Path,
        export_path: &Path,
        secret: ImportSecret,
    ) -> Result<ImportOutcome> {
        export::import(
            root,
            export_path,
            |h| export::unlock_secret(h, &secret),
            None,
        )
    }

    /// Merges an export of this vault into the open vault and refreshes the state.
    /// Duress is disabled afterwards, as for a restore.
    pub fn import_into(&self, export_path: &Path, secret: ImportSecret) -> Result<ImportOutcome> {
        self.with_mut(|i| {
            let outcome = export::import(
                i.store.root(),
                export_path,
                |h| export::unlock_secret(h, &secret),
                Some(&i.vk),
            )?;
            i.header = read_header(&i.store)?;
            i.duress_enabled = false;
            i.chains = read_all_chains(&i.store, &i.vk, i.vault_id())?;
            i.state = State::fold(i.chains.values().flatten());
            i.persist_local();
            Ok(outcome)
        })
    }

    /// Replaces this vault with the export at `export_path`. `current_password` is checked
    /// against the on-disk header. The export is unlocked, verified and staged completely
    /// before anything is erased; any failure up to then leaves this vault untouched.
    /// The handle is locked afterwards; the restored vault opens with the export's secret
    /// and has duress disabled.
    pub fn replace_from_backup(
        &self,
        current_password: &str,
        export_path: &Path,
        secret: ImportSecret,
    ) -> Result<()> {
        let mut g = self.guard();
        let i = g.as_mut().ok_or(Error::Locked)?;
        if i.read_only {
            return Err(Error::ReadOnly);
        }
        let on_disk = read_header(&i.store)?;
        match header::unlock(&on_disk, current_password)? {
            UnlockOutcome::Open(vk) if bool::from(vk.as_bytes().ct_eq(i.vk.as_bytes())) => {}
            _ => return Err(Error::WrongPassword),
        }
        let store = i.store.clone();
        let staged = export::stage_export(
            store.root(),
            export_path,
            |h| export::unlock_secret(h, &secret),
            |_, _| Ok(()),
        )?;
        *g = None;
        shred(&store)?;
        staged.commit_restore(&store)
    }

    /// Drops all keys. Readers, writers and sessions obtained earlier fail with `Locked`
    /// on their next call and drop their own data key.
    pub fn lock(&self) {
        *self.guard() = None;
    }

    /// Ends read-only mode after a detected rollback: the owner confirms the files as they
    /// are with the master password, and a fresh local state is written (vault-format §6).
    pub fn accept_current_state(&self, password: &str) -> Result<()> {
        self.with(|i| {
            i.check_password(password)?;
            i.try_persist_local()?;
            i.read_only = false;
            Ok(())
        })
    }

    /// True after a rollback was detected at unlock, and once locked.
    pub fn is_read_only(&self) -> bool {
        self.guard().as_ref().is_none_or(|i| i.read_only)
    }

    pub fn items(&self) -> Result<Vec<ItemSummary>> {
        self.with(|i| {
            Ok(i.state
                .items()
                .map(|it| ItemSummary {
                    id: it.id,
                    kind: it.kind,
                    meta: it.meta.clone(),
                    objects: it
                        .objects
                        .iter()
                        .filter_map(|(r, o)| Some((ObjectRole::parse(r)?, *o)))
                        .collect(),
                    albums: i
                        .state
                        .albums()
                        .filter(|a| {
                            i.state
                                .album_members(&a.id)
                                .is_some_and(|m| m.contains(&it.id))
                        })
                        .map(|a| a.id)
                        .collect(),
                    hidden_in_all: i.state.is_hidden_in_all(&it.id),
                })
                .collect())
        })
    }

    /// Creates an album (`album.add`); the name is trimmed and NFC-normalized.
    pub fn create_album(&self, name: &str) -> Result<AlbumId> {
        let name = clean_album_name(name).ok_or(Error::InvalidInput)?;
        self.with_mut(|i| {
            let album = AlbumId(rng::array::<16>(&mut OsRandom)?);
            let t = next_t(&i.state);
            i.append(vec![Op::AlbumAdd { t, album, name }])?;
            Ok(album)
        })
    }

    pub fn rename_album(&self, id: AlbumId, name: &str) -> Result<()> {
        let name = clean_album_name(name).ok_or(Error::InvalidInput)?;
        self.with_mut(|i| {
            if i.state.album(&id).is_none() {
                return Err(Error::NotFound);
            }
            let t = next_t(&i.state);
            i.append(vec![Op::AlbumSet {
                t,
                album: id,
                field: "name".to_owned(),
                value: Value::text(&name),
            }])
        })
    }

    /// Sets (`Some`) or removes (`None`) the view-lock code of an album. The code must be
    /// four ASCII digits. It is a view lock only: the digest is stored in the encrypted
    /// journal and adds no encryption of its own.
    pub fn set_album_pin(&self, id: AlbumId, code: Option<&str>) -> Result<()> {
        let value = match code {
            None => Value::Null,
            Some(c) if valid_album_code(c) => {
                let salt = rng::array::<16>(&mut OsRandom)?;
                let digest = album_pin_digest(c.as_bytes(), &salt, &id.0);
                let mut pin = salt.to_vec();
                pin.extend_from_slice(&*digest);
                Value::Bytes(pin)
            }
            Some(_) => return Err(Error::InvalidInput),
        };
        self.set_album_field(id, "pin", value)
    }

    /// Checks a view-lock code in constant time; false if the album has no code.
    pub fn verify_album_pin(&self, id: AlbumId, code: &str) -> Result<bool> {
        self.with(|i| {
            let album = i.state.album(&id).ok_or(Error::NotFound)?;
            let Some(pin) = &album.pin else {
                return Ok(false);
            };
            if !valid_album_code(code) || pin.len() != ALBUM_PIN_LEN {
                return Ok(false);
            }
            let (salt, want) = pin.split_at(16);
            let salt: [u8; 16] = salt.try_into().map_err(|_| Error::Cbor)?;
            let got = album_pin_digest(code.as_bytes(), &salt, &id.0);
            Ok(bool::from(got.as_slice().ct_eq(want)))
        })
    }

    /// Sets whether the album's items appear in All Photos.
    pub fn set_album_show_in_all(&self, id: AlbumId, show: bool) -> Result<()> {
        self.set_album_field(id, "show_in_all", Value::Bool(show))
    }

    fn set_album_field(&self, id: AlbumId, field: &str, value: Value) -> Result<()> {
        self.with_mut(|i| {
            if i.state.album(&id).is_none() {
                return Err(Error::NotFound);
            }
            let t = next_t(&i.state);
            i.append(vec![Op::AlbumSet {
                t,
                album: id,
                field: field.to_owned(),
                value,
            }])
        })
    }

    /// Tombstones the album (`album.del`); items are untouched.
    pub fn delete_album(&self, id: AlbumId) -> Result<()> {
        self.with_mut(|i| {
            if i.state.album(&id).is_none() {
                return Err(Error::NotFound);
            }
            let t = next_t(&i.state);
            i.append(vec![Op::AlbumDel { t, album: id }])
        })
    }

    /// Adds items to an album in one segment (`album.put`); adding a member again is a no-op.
    pub fn add_to_album(&self, id: AlbumId, items: &[ItemId]) -> Result<()> {
        self.album_membership(id, items, true)
    }

    /// Removes items from an album in one segment (`album.pop`).
    pub fn remove_from_album(&self, id: AlbumId, items: &[ItemId]) -> Result<()> {
        self.album_membership(id, items, false)
    }

    fn album_membership(&self, id: AlbumId, items: &[ItemId], add: bool) -> Result<()> {
        self.with_mut(|i| {
            let members = i.state.album_members(&id).ok_or(Error::NotFound)?;
            let items: BTreeSet<_> = items.iter().copied().collect();
            if items.iter().any(|it| i.state.item(it).is_none()) {
                return Err(Error::NotFound);
            }
            let ops: Vec<_> = items
                .iter()
                .filter(|it| members.contains(it) != add)
                .zip(next_t(&i.state)..)
                .map(|(&item, t)| {
                    if add {
                        Op::AlbumPut { t, album: id, item }
                    } else {
                        Op::AlbumPop { t, album: id, item }
                    }
                })
                .collect();
            if ops.is_empty() {
                return Ok(());
            }
            i.append(ops)
        })
    }

    /// Live albums, ordered by name (then id).
    pub fn albums(&self) -> Result<Vec<AlbumSummary>> {
        self.with(|i| {
            let mut out: Vec<_> = i
                .state
                .albums()
                .map(|a| {
                    let members = i.state.album_members(&a.id);
                    // Trashed items are not part of album views.
                    let visible = || {
                        members
                            .into_iter()
                            .flatten()
                            .filter_map(|id| i.state.item(id))
                            .filter(|it| it.meta.trashed.is_none())
                    };
                    let cover = visible()
                        .max_by_key(|it| (it.meta.created.unwrap_or(it.meta.imported), it.id))
                        .map(|it| it.id);
                    AlbumSummary {
                        id: a.id,
                        name: a.name.clone(),
                        item_count: visible().count() as u64,
                        cover_item: cover,
                        locked: a.locked(),
                        show_in_all: a.shows_in_all(),
                    }
                })
                .collect();
            out.sort_by(|a, b| (&a.name, a.id).cmp(&(&b.name, b.id)));
            Ok(out)
        })
    }

    /// Members of a live album without trashed items, ordered by id.
    pub fn album_items(&self, id: AlbumId) -> Result<Vec<ItemId>> {
        self.with(|i| {
            let m = i.state.album_members(&id).ok_or(Error::NotFound)?;
            Ok(m.iter()
                .copied()
                .filter(|it| !i.state.is_trashed(it))
                .collect())
        })
    }

    pub fn begin_import(&self, kind: ItemKind, meta: ItemMeta) -> Result<ImportSession> {
        let store = self.with_mut(|i| Ok(i.store.clone()))?;
        Ok(ImportSession {
            vault: Arc::downgrade(&self.inner),
            store,
            kind,
            meta,
            objects: Arc::default(),
        })
    }

    /// Opens an object referenced by a live item.
    pub fn open_object(&self, id: ObjectId) -> Result<GuardedReader> {
        self.with(|i| {
            if !i
                .state
                .items()
                .any(|it| it.objects.values().any(|o| *o == id))
            {
                return Err(Error::NotFound);
            }
            let f = File::open(i.store.object_path(&id)).map_err(|e| match e.kind() {
                ErrorKind::NotFound => Error::NotFound,
                _ => Error::Io,
            })?;
            let reader = open_object(f, &i.vk, i.vault_id(), Some(id))?;
            let len = reader.plaintext_len();
            let slot = Arc::new(Mutex::new(Some(reader)));
            i.track(OpenHandle::Reader(Arc::downgrade(&slot)));
            Ok(GuardedReader {
                len,
                reader: slot,
                vault: Arc::downgrade(&self.inner),
            })
        })
    }

    /// Commits the tombstones first, then deletes the referenced objects.
    pub fn delete_items(&self, ids: &[ItemId]) -> Result<()> {
        self.with_mut(|i| i.delete_items(ids))
    }

    /// Moves items to the trash in one segment (`item.set trashed`); items already in the
    /// trash keep their date.
    pub fn trash_items(&self, ids: &[ItemId], now_ms: u64) -> Result<()> {
        self.set_trashed(ids, Some(now_ms))
    }

    /// Takes items out of the trash in one segment; items not in the trash are skipped.
    pub fn restore_items(&self, ids: &[ItemId]) -> Result<()> {
        self.set_trashed(ids, None)
    }

    fn set_trashed(&self, ids: &[ItemId], at: Option<u64>) -> Result<()> {
        self.with_mut(|i| {
            let ids: BTreeSet<_> = ids.iter().copied().collect();
            if ids.iter().any(|id| i.state.item(id).is_none()) {
                return Err(Error::NotFound);
            }
            let value = at.map_or(Value::Null, Value::Uint);
            let ops: Vec<_> = ids
                .iter()
                .filter(|id| i.state.is_trashed(id) == at.is_none())
                .zip(next_t(&i.state)..)
                .map(|(&item, t)| Op::ItemSet {
                    t,
                    item,
                    field: "trashed".to_owned(),
                    value: value.clone(),
                })
                .collect();
            if ops.is_empty() {
                return Ok(());
            }
            i.append(ops)
        })
    }

    /// Permanently deletes items trashed at least `TRASH_RETENTION_MS` ago (tombstones
    /// first, then blobs); returns the number of deleted items.
    pub fn purge_expired(&self, now_ms: u64) -> Result<u64> {
        self.with_mut(|i| {
            let expired: Vec<ItemId> = i
                .state
                .items()
                .filter(|it| {
                    it.meta
                        .trashed
                        .is_some_and(|t| t.saturating_add(TRASH_RETENTION_MS) <= now_ms)
                })
                .map(|it| it.id)
                .collect();
            i.delete_items(&expired)?;
            Ok(expired.len() as u64)
        })
    }

    /// Sets a metadata field (`item.set`); `Value::Null` clears optional fields.
    pub fn set_meta(&self, item: ItemId, field: &str, value: Value) -> Result<()> {
        let valid = match field {
            "filename" | "mime" => matches!(value, Value::Null) || value.as_str().is_some(),
            "created" => matches!(value, Value::Null) || value.as_i64().is_some(),
            "imported" => value.as_i64().is_some(),
            "width" | "height" | "duration" | "size" | "trashed" => {
                matches!(value, Value::Null) || value.as_u64().is_some()
            }
            _ => false,
        };
        if !valid {
            return Err(Error::InvalidInput);
        }
        self.with_mut(|i| {
            if i.state.item(&item).is_none() {
                return Err(Error::NotFound);
            }
            let t = next_t(&i.state);
            i.append(vec![Op::ItemSet {
                t,
                item,
                field: field.to_owned(),
                value,
            }])
        })
    }

    /// Verifies `old` against the on-disk header and re-wraps the vault key under `new`.
    /// Duress is disabled by this change and must be set again with `set_duress`.
    /// Also removes Face ID and PIN unlock (crypto §6.5); the app deletes their device keys.
    pub fn change_password(&self, old: &str, new: &str, params: KdfParams) -> Result<()> {
        self.with_mut(|i| {
            i.check_password(old)?;
            let h = header::change_password(&i.header, &i.vk, new, params, DuressUpdate::Disable)?;
            i.write_header(h)?;
            i.set_duress_flag(false)?;
            biometric::remove(&i.store, Kind::Biometric)?;
            biometric::remove_pin(&i.store)
        })
    }

    /// Checks `password` against the on-disk header and the open vault key.
    /// The duress password and wrong passwords both fail with `WrongPassword`.
    pub fn verify_password(&self, password: &str) -> Result<()> {
        self.with(|i| i.check_password(password))
    }

    /// Needs the master password (crypto §6.6).
    pub fn set_duress(&self, password: &str, duress_password: &str) -> Result<()> {
        self.with_mut(|i| {
            i.check_password(password)?;
            let h = header::set_duress(&i.header, &i.vk, duress_password)?;
            i.write_header(h)?;
            i.set_duress_flag(true)
        })
    }

    /// Needs the master password (crypto §6.6).
    pub fn disable_duress(&self, password: &str) -> Result<()> {
        self.with_mut(|i| {
            i.check_password(password)?;
            let h = header::disable_duress(&i.header, &i.vk)?;
            i.write_header(h)?;
            i.set_duress_flag(false)
        })
    }

    /// Permanently destroys the vault on this device after verifying `password` against the
    /// on-disk header (same procedure as duress shredding, but no new vault is created).
    /// The handle is locked afterwards. A wrong password deletes nothing.
    pub fn erase(&self, password: &str) -> Result<()> {
        let mut g = self.guard();
        let i = g.as_mut().ok_or(Error::Locked)?;
        if i.read_only {
            return Err(Error::ReadOnly);
        }
        i.check_password(password)?;
        let store = i.store.clone();
        // Drop the keys first so nothing stays usable even if shredding fails midway.
        *g = None;
        shred(&store)
    }

    /// Whether a duress password is set; false once locked.
    pub fn is_duress_enabled(&self) -> bool {
        self.guard().as_ref().is_some_and(|i| i.duress_enabled)
    }

    /// Creates or replaces the biometric slot for `bio_key`. `boot_time` and `now` are
    /// Unix seconds supplied by the caller; the slot is valid for 7 days from `now`.
    /// Needs the master password (crypto §6.6).
    pub fn enable_biometric(
        &self,
        password: &str,
        bio_key: &BioKey,
        boot_time: u64,
        now: u64,
    ) -> Result<()> {
        self.with_mut(|i| {
            i.check_password(password)?;
            let slot = biometric::create(
                Kind::Biometric,
                &i.vk,
                bio_key,
                &i.vault_id(),
                boot_time,
                now,
                &mut OsRandom,
            )?;
            biometric::write(&i.store, &slot)
        })
    }

    pub fn disable_biometric(&self) -> Result<()> {
        self.with_mut(|i| biometric::remove(&i.store, Kind::Biometric))
    }

    /// True if the slot file exists; false once locked.
    pub fn is_biometric_enabled(&self) -> bool {
        self.guard()
            .as_ref()
            .is_some_and(|i| biometric::slot_path(&i.store, Kind::Biometric).exists())
    }

    /// Creates or replaces the PIN slot (crypto §12). `se_secret` is the device-bound secret
    /// released by the Secure Enclave; the slot is valid for 7 days from `now`.
    /// Needs the master password (crypto §6.6).
    pub fn enable_pin(
        &self,
        password: &str,
        se_secret: &BioKey,
        pin: &str,
        boot_time: u64,
        now: u64,
    ) -> Result<()> {
        self.with_mut(|i| {
            i.check_password(password)?;
            let vault_id = i.vault_id();
            let key = kdf::pin_key(se_secret, pin, &vault_id)?;
            let slot = biometric::create(
                Kind::Pin,
                &i.vk,
                &key,
                &vault_id,
                boot_time,
                now,
                &mut OsRandom,
            )?;
            biometric::remove_pin(&i.store)?;
            biometric::write(&i.store, &slot)
        })
    }

    pub fn disable_pin(&self) -> Result<()> {
        self.with_mut(|i| biometric::remove_pin(&i.store))
    }

    /// True if a PIN slot exists, active or paused; false once locked.
    pub fn is_pin_enabled(&self) -> bool {
        self.guard()
            .as_ref()
            .is_some_and(|i| Self::pin_slot_exists(i.store.root()))
    }

    /// Verifies the master password, then replaces the recovery key (crypto §6.6).
    /// The previous recovery key stops working immediately.
    pub fn rotate_recovery(&self, password: &str) -> Result<RecoveryKeyString> {
        self.with_mut(|i| {
            i.check_password(password)?;
            let (h, rk) = header::rotate_recovery(&i.header, &i.vk)?;
            i.write_header(h)?;
            Ok(rk.encode())
        })
    }
}

/// Keeps `m` and `p` of the default parameters and picks `t` (from 3, capped at 32) so that
/// one derivation takes about `target_ms`. Argon2id time grows linearly with `t`, so one
/// measurement at the default `t` is enough.
pub fn kdf_calibrate(target_ms: u32) -> KdfParams {
    let mut params = KdfParams::DEFAULT;
    let start = Instant::now();
    if derive_master_key("calibration", &[0; 16], &params).is_err() {
        return params;
    }
    let per_pass = start.elapsed().as_secs_f64() / f64::from(params.t);
    if per_pass > 0.0 {
        let t = (f64::from(target_ms) / 1000.0 / per_pass).ceil();
        // Float to int saturates; the clamp keeps the result inside the accepted range.
        params.t = (t as u32).clamp(KdfParams::DEFAULT.t, CALIBRATION_MAX_T);
    }
    params
}

/// Longest prefix (in chars) that is scored; bounds the estimator's running time.
const STRENGTH_MAX_CHARS: usize = 128;

/// Password strength on the zxcvbn scale, 0 (weak) to 4 (strong). Only a prefix is scored.
pub fn password_strength(pw: &str) -> u8 {
    let end = pw
        .char_indices()
        .nth(STRENGTH_MAX_CHARS)
        .map_or(pw.len(), |(i, _)| i);
    zxcvbn::zxcvbn(&pw[..end], &[]).score().into()
}

/// One item under construction: objects are written first, `commit` makes the item visible.
/// Dropping the session without `commit` leaves unreferenced objects for the sweep.
pub struct ImportSession {
    vault: Weak<Shared>,
    store: Store,
    kind: ItemKind,
    meta: ItemMeta,
    objects: Arc<Mutex<Vec<(ObjectRole, ObjectId)>>>,
}

type Finished = Arc<Mutex<Vec<(ObjectRole, ObjectId)>>>;

fn lock_finished(f: &Finished) -> MutexGuard<'_, Vec<(ObjectRole, ObjectId)>> {
    f.lock().unwrap_or_else(PoisonError::into_inner)
}

impl ImportSession {
    /// Starts a new object; it becomes visible on disk only when `finish` succeeds.
    pub fn add_object(&mut self, role: ObjectRole) -> Result<ImportWriter> {
        if lock_finished(&self.objects).iter().any(|(r, _)| *r == role) {
            return Err(Error::Exists);
        }
        let id = rng::array::<16>(&mut OsRandom)?;
        let (slot, dest) = with_weak_mut(&self.vault, |i| {
            let dest = i.store.object_path(&id);
            let (file, tmp) = i.store.create_tmp(&dest)?;
            match write_object(file, &i.vk, i.vault_id(), id, ObjectKind::Blob) {
                Ok(enc) => {
                    let slot = Arc::new(Mutex::new(WriterSlot {
                        enc: Some(enc),
                        tmp,
                    }));
                    i.track(OpenHandle::Writer(Arc::downgrade(&slot)));
                    Ok((slot, dest))
                }
                Err(e) => {
                    let _ = fs::remove_file(&tmp);
                    Err(e)
                }
            }
        })?;
        Ok(ImportWriter {
            slot,
            dest,
            store: self.store.clone(),
            role,
            id,
            done: Arc::clone(&self.objects),
            vault: self.vault.clone(),
        })
    }

    /// Writes one journal segment with `item.add`. Requires an `original` object.
    pub fn commit(self) -> Result<ItemId> {
        let finished = lock_finished(&self.objects).clone();
        with_weak_mut(&self.vault, |i| {
            if !finished.iter().any(|(r, _)| *r == ObjectRole::Original) {
                return Err(Error::InvalidInput);
            }
            let item = ItemId(rng::array::<16>(&mut OsRandom)?);
            let objects = finished
                .iter()
                .map(|(r, o)| (r.as_str().to_owned(), *o))
                .collect();
            let t = next_t(&i.state);
            i.append(vec![Op::ItemAdd {
                t,
                item,
                kind: self.kind,
                objects,
                meta: self.meta.clone(),
            }])?;
            Ok(item)
        })
    }

    /// Deletes the objects finished so far.
    pub fn abort(self) {
        for (_, id) in lock_finished(&self.objects).iter() {
            let _ = self.store.delete_object(id);
        }
    }
}

type ReaderSlot = Mutex<Option<ObjectReader<File>>>;

/// Encryptor and temporary file of an unfinished import object.
struct WriterSlot {
    enc: Option<object::ObjectWriter<File>>,
    tmp: PathBuf,
}

impl WriterSlot {
    /// Drops the data key and removes the temporary file.
    fn discard(&mut self) {
        if self.enc.take().is_some() {
            let _ = fs::remove_file(&self.tmp);
        }
    }
}

/// Open handle that holds a data key; `lock()` revokes it (crypto §11).
enum OpenHandle {
    Reader(Weak<ReaderSlot>),
    Writer(Weak<Mutex<WriterSlot>>),
}

impl OpenHandle {
    fn is_alive(&self) -> bool {
        match self {
            Self::Reader(w) => w.strong_count() > 0,
            Self::Writer(w) => w.strong_count() > 0,
        }
    }

    /// Called with the vault guard held; handles take the same order (vault, then slot).
    fn revoke(&self) {
        match self {
            Self::Reader(w) => {
                if let Some(slot) = w.upgrade() {
                    *slot.lock().unwrap_or_else(PoisonError::into_inner) = None;
                }
            }
            Self::Writer(w) => {
                if let Some(slot) = w.upgrade() {
                    slot.lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .discard();
                }
            }
        }
    }
}

/// Reader for one object. Checks the vault state before every call; `lock()` drops its
/// data key at once, and every later call fails with `Locked`.
pub struct GuardedReader {
    reader: Arc<ReaderSlot>,
    len: u64,
    vault: Weak<Shared>,
}

impl GuardedReader {
    pub fn plaintext_len(&self) -> u64 {
        self.len
    }

    /// Runs one read while holding the vault guard.
    fn read<R>(&mut self, f: impl FnOnce(&mut ObjectReader<File>) -> Result<R>) -> Result<R> {
        let r = while_open(&self.vault, || {
            let mut g = self.reader.lock().unwrap_or_else(PoisonError::into_inner);
            f(g.as_mut().ok_or(Error::Locked)?)
        });
        if matches!(r, Err(Error::Locked)) {
            *self.reader.lock().unwrap_or_else(PoisonError::into_inner) = None;
        }
        r
    }

    pub fn read_range(&mut self, offset: u64, len: u64) -> Result<Vec<u8>> {
        self.read(|r| r.read_range(offset, len))
    }

    pub fn read_all(&mut self) -> Result<Vec<u8>> {
        self.read(ObjectReader::read_all)
    }
}

/// Streaming writer for one object. Dropping it unfinished leaves no visible file.
pub struct ImportWriter {
    slot: Arc<Mutex<WriterSlot>>,
    dest: PathBuf,
    store: Store,
    role: ObjectRole,
    id: ObjectId,
    done: Finished,
    vault: Weak<Shared>,
}

impl ImportWriter {
    /// On `Locked` the data key is dropped and the temporary file removed.
    fn slot(&self) -> MutexGuard<'_, WriterSlot> {
        self.slot.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn discard_if_locked<R>(&mut self, r: Result<R>) -> Result<R> {
        if matches!(r, Err(Error::Locked)) {
            self.slot().discard();
        }
        r
    }

    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        let r = while_open(&self.vault, || {
            self.slot()
                .enc
                .as_mut()
                .ok_or(Error::InvalidInput)?
                .write_all(data)
        });
        self.discard_if_locked(r)
    }

    /// Seals the object and moves it into place atomically.
    pub fn finish(mut self) -> Result<ObjectId> {
        let r = while_open(&self.vault, || {
            let mut slot = self.slot();
            let enc = slot.enc.take().ok_or(Error::InvalidInput)?;
            let file = enc.finish()?;
            self.store.commit_tmp(file, &slot.tmp, &self.dest)
        });
        self.discard_if_locked(r)?;
        lock_finished(&self.done).push((self.role, self.id));
        Ok(self.id)
    }
}

impl Drop for ImportWriter {
    fn drop(&mut self) {
        self.slot().discard();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn password_strength_scale() {
        assert_eq!(password_strength(""), 0);
        assert!(password_strength("password1") <= 1);
        assert!(password_strength("correct horse battery staple glacier") >= 3);
        assert!(password_strength(&"é".repeat(500)) <= 4);
    }

    use super::*;

    const PW: &str = "correct horse";
    const BOOT: u64 = 1_000;
    const NOW: u64 = 2_000_000;

    fn meta() -> ItemMeta {
        ItemMeta {
            filename: Some("a.jpg".into()),
            imported: 1,
            ..ItemMeta::default()
        }
    }

    fn new_vault() -> (tempfile::TempDir, Vault, RecoveryKeyString) {
        let dir = tempfile::tempdir().unwrap();
        let (v, rk) = Vault::create(dir.path(), PW, KdfParams::DEFAULT).unwrap();
        (dir, v, rk)
    }

    fn put(role: ObjectRole, data: &[u8], s: &mut ImportSession) -> ObjectId {
        let mut w = s.add_object(role).unwrap();
        w.write(data).unwrap();
        w.finish().unwrap()
    }

    fn import(v: &Vault, orig: &[u8], thumb: &[u8]) -> ItemId {
        let mut s = v.begin_import(ItemKind::Photo, meta()).unwrap();
        put(ObjectRole::Original, orig, &mut s);
        put(ObjectRole::ThumbSmall, thumb, &mut s);
        s.commit().unwrap()
    }

    fn open(dir: &Path, pw: &str) -> Vault {
        match Vault::unlock(dir, pw, BOOT, NOW).unwrap() {
            UnlockResult::Open(v) => v,
            _ => panic!("expected Open"),
        }
    }

    fn files_under(dir: &Path) -> usize {
        let Ok(rd) = fs::read_dir(dir) else { return 0 };
        rd.map(|e| e.unwrap().path())
            .map(|p| if p.is_dir() { files_under(&p) } else { 1 })
            .sum()
    }

    #[test]
    fn import_read_delete() {
        let (dir, v, _rk) = new_vault();
        assert_eq!(
            Vault::create(dir.path(), PW, KdfParams::DEFAULT).err(),
            Some(Error::Exists)
        );
        drop(v);
        let v = open(dir.path(), PW);
        assert!(v.items().unwrap().is_empty());

        let id = import(&v, b"original bytes", b"thumb bytes");
        let items = v.items().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, id);
        assert_eq!(items[0].meta.filename.as_deref(), Some("a.jpg"));
        let o = items[0].objects[&ObjectRole::Original];
        let t = items[0].objects[&ObjectRole::ThumbSmall];
        assert_eq!(
            v.open_object(o).unwrap().read_all().unwrap(),
            b"original bytes"
        );
        assert_eq!(
            v.open_object(t).unwrap().read_all().unwrap(),
            b"thumb bytes"
        );
        assert_eq!(v.open_object([9; 16]).err(), Some(Error::NotFound));

        v.set_meta(id, "filename", Value::text("b.jpg")).unwrap();
        assert_eq!(
            v.items().unwrap()[0].meta.filename.as_deref(),
            Some("b.jpg")
        );
        assert_eq!(
            v.set_meta(id, "bogus", Value::Null),
            Err(Error::InvalidInput)
        );
        assert_eq!(
            v.set_meta(id, "width", Value::text("x")),
            Err(Error::InvalidInput)
        );

        v.delete_items(&[id]).unwrap();
        assert!(v.items().unwrap().is_empty());
        assert_eq!(v.open_object(o).err(), Some(Error::NotFound));
        assert_eq!(files_under(&dir.path().join("objects")), 0);
        assert_eq!(v.delete_items(&[id]), Err(Error::NotFound));
    }

    #[test]
    fn unfinished_writer_and_abort_leave_nothing() {
        let (dir, v, _rk) = new_vault();
        let mut s = v.begin_import(ItemKind::Photo, meta()).unwrap();
        let mut w = s.add_object(ObjectRole::Original).unwrap();
        w.write(b"partial").unwrap();
        drop(w);
        assert_eq!(files_under(&dir.path().join("objects")), 0);
        put(ObjectRole::Original, b"x", &mut s);
        assert_eq!(files_under(&dir.path().join("objects")), 1);
        assert_eq!(
            s.add_object(ObjectRole::Original).err(),
            Some(Error::Exists)
        );
        s.abort();
        assert_eq!(files_under(&dir.path().join("objects")), 0);
        let s = v.begin_import(ItemKind::Photo, meta()).unwrap();
        assert_eq!(s.commit(), Err(Error::InvalidInput));
    }

    #[test]
    fn wrong_password_and_recovery() {
        let (dir, v, rk) = new_vault();
        let id = import(&v, b"data", b"t");
        drop(v);
        assert!(matches!(
            Vault::unlock(dir.path(), "nope", BOOT, NOW).unwrap(),
            UnlockResult::WrongPassword
        ));
        let v = Vault::unlock_recovery(dir.path(), &rk, BOOT, NOW).unwrap();
        assert_eq!(v.items().unwrap()[0].id, id);
        assert_eq!(
            Vault::unlock_recovery(dir.path(), "garbage", BOOT, NOW).err(),
            Some(Error::RecoveryKeyFormat)
        );
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(
            Vault::unlock(empty.path(), PW, BOOT, NOW).err(),
            Some(Error::NotAVault)
        );
    }

    #[test]
    fn duress_replaces_vault() {
        let (dir, v, _rk) = new_vault();
        import(&v, b"secret", b"t");
        v.set_duress(PW, "duress pw").unwrap();
        assert_eq!(v.set_duress(PW, PW), Err(Error::DuressEqualsPassword));
        drop(v);
        let before = fs::metadata(dir.path().join("vault.zev")).unwrap().len();

        let UnlockResult::Duress(d) = Vault::unlock(dir.path(), "duress pw", BOOT, NOW).unwrap()
        else {
            panic!("expected Duress");
        };
        assert!(d.items().unwrap().is_empty());
        assert_eq!(files_under(&dir.path().join("objects")), 0);
        assert_eq!(files_under(&dir.path().join("journal")), 0);
        assert_eq!(
            fs::metadata(dir.path().join("vault.zev")).unwrap().len(),
            before
        );
        drop(d);

        let v = open(dir.path(), "duress pw");
        assert!(v.items().unwrap().is_empty());
        drop(v);
        assert!(matches!(
            Vault::unlock(dir.path(), PW, BOOT, NOW).unwrap(),
            UnlockResult::WrongPassword
        ));
    }

    #[test]
    fn disable_duress_and_rotate_recovery() {
        let (dir, v, old_rk) = new_vault();
        v.set_duress(PW, "duress pw").unwrap();
        v.disable_duress(PW).unwrap();
        assert_eq!(v.rotate_recovery("nope").err(), Some(Error::WrongPassword));
        let rk = v.rotate_recovery(PW).unwrap();
        drop(v);
        assert!(Vault::unlock_recovery(dir.path(), &old_rk, BOOT, NOW).is_err());
        assert!(Vault::unlock_recovery(dir.path(), &rk, BOOT, NOW).is_ok());
        assert!(matches!(
            Vault::unlock(dir.path(), "duress pw", BOOT, NOW).unwrap(),
            UnlockResult::WrongPassword
        ));
    }

    #[test]
    fn locked_handle_rejects_everything() {
        let (_dir, v, _rk) = new_vault();
        let id = import(&v, b"d", b"t");
        let mut s = v.begin_import(ItemKind::Photo, meta()).unwrap();
        put(ObjectRole::Original, b"x", &mut s);
        v.lock();
        assert!(v.is_read_only());
        assert_eq!(s.commit(), Err(Error::Locked));
        assert_eq!(v.items().err(), Some(Error::Locked));
        assert_eq!(
            v.begin_import(ItemKind::Photo, meta()).err(),
            Some(Error::Locked)
        );
        assert_eq!(v.open_object([0; 16]).err(), Some(Error::Locked));
        assert_eq!(v.delete_items(&[id]), Err(Error::Locked));
        assert_eq!(v.set_meta(id, "mime", Value::Null), Err(Error::Locked));
        assert_eq!(
            v.change_password(PW, "x", KdfParams::DEFAULT),
            Err(Error::Locked)
        );
        assert_eq!(v.set_duress(PW, "d"), Err(Error::Locked));
        assert_eq!(v.disable_duress(PW), Err(Error::Locked));
        assert_eq!(v.rotate_recovery(PW).err(), Some(Error::Locked));
        v.lock();
    }

    #[test]
    fn reader_fails_after_lock() {
        let (_dir, v, _rk) = new_vault();
        import(&v, b"original bytes", b"t");
        let o = v.items().unwrap()[0].objects[&ObjectRole::Original];
        let mut r = v.open_object(o).unwrap();
        assert_eq!(r.read_range(0, 4).unwrap(), b"orig");
        v.lock();
        assert_eq!(r.plaintext_len(), 14);
        assert_eq!(r.read_range(0, 4), Err(Error::Locked));
        assert_eq!(r.read_all(), Err(Error::Locked));
        assert!(r.reader.lock().unwrap().is_none());
    }

    #[test]
    fn lock_revokes_open_handles_without_further_calls() {
        let (_dir, v, _rk) = new_vault();
        import(&v, b"original bytes", b"t");
        let o = v.items().unwrap()[0].objects[&ObjectRole::Original];
        let r = v.open_object(o).unwrap();
        let mut s = v.begin_import(ItemKind::Photo, meta()).unwrap();
        let mut w = s.add_object(ObjectRole::Original).unwrap();
        w.write(b"partial").unwrap();
        let tmp = w.slot().tmp.clone();
        assert!(tmp.exists());
        v.lock();
        // Keys and buffers are gone at lock time, not at the next call or drop.
        assert!(r.reader.lock().unwrap().is_none());
        assert!(w.slot().enc.is_none());
        assert!(!tmp.exists());
    }

    #[test]
    fn writer_fails_after_lock() {
        let (dir, v, _rk) = new_vault();
        let mut s = v.begin_import(ItemKind::Photo, meta()).unwrap();
        let mut w = s.add_object(ObjectRole::Original).unwrap();
        w.write(b"partial").unwrap();
        v.lock();
        assert_eq!(w.write(b"more"), Err(Error::Locked));
        assert!(w.slot().enc.is_none());
        assert_eq!(w.finish(), Err(Error::Locked));
        assert_eq!(files_under(&dir.path().join("objects")), 0);

        let (_dir, v, _rk) = new_vault();
        let mut s = v.begin_import(ItemKind::Photo, meta()).unwrap();
        let w = s.add_object(ObjectRole::Original).unwrap();
        v.lock();
        assert_eq!(w.finish(), Err(Error::Locked));
        assert_eq!(
            s.add_object(ObjectRole::ThumbSmall).err(),
            Some(Error::Locked)
        );
    }

    #[test]
    fn session_commit_fails_after_lock() {
        let (_dir, v, _rk) = new_vault();
        let mut s = v.begin_import(ItemKind::Photo, meta()).unwrap();
        put(ObjectRole::Original, b"x", &mut s);
        v.lock();
        assert_eq!(s.commit(), Err(Error::Locked));
    }

    #[test]
    fn lock_waits_for_in_flight_operation() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let (_dir, v, _rk) = new_vault();
        let weak = Arc::downgrade(&v.inner);
        let done = AtomicBool::new(false);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::scope(|sc| {
            sc.spawn(|| {
                while_open(&weak, || {
                    tx.send(()).unwrap();
                    std::thread::sleep(Duration::from_millis(200));
                    done.store(true, Ordering::SeqCst);
                    Ok(())
                })
                .unwrap();
            });
            rx.recv().unwrap();
            v.lock();
            assert!(done.load(Ordering::SeqCst));
            assert_eq!(while_open(&weak, || Ok(())), Err(Error::Locked));
        });
    }

    #[test]
    fn dropped_vault_counts_as_locked() {
        let (_dir, v, _rk) = new_vault();
        let id = import(&v, b"d", b"t");
        let o = v
            .items()
            .unwrap()
            .into_iter()
            .find(|i| i.id == id)
            .unwrap()
            .objects[&ObjectRole::Original];
        let mut r = v.open_object(o).unwrap();
        let mut s = v.begin_import(ItemKind::Photo, meta()).unwrap();
        put(ObjectRole::Original, b"x", &mut s);
        drop(v);
        assert_eq!(r.read_all(), Err(Error::Locked));
        assert_eq!(s.commit(), Err(Error::Locked));
    }

    #[test]
    fn crash_leftovers_are_recovered() {
        let (dir, v, _rk) = new_vault();
        let keep = import(&v, b"kept", b"t");
        // Crash before commit: objects written, no segment.
        let mut s = v.begin_import(ItemKind::Photo, meta()).unwrap();
        put(ObjectRole::Original, b"orphan", &mut s);
        drop(s);
        drop(v);
        // Crash during an atomic write.
        fs::write(dir.path().join(".vault.zev.tmp-0123456789abcdef"), b"x").unwrap();
        let shard = dir.path().join("objects/ab");
        fs::create_dir_all(&shard).unwrap();
        let tmp = shard.join(".x.zeo.tmp-0123456789abcdef");
        fs::write(&tmp, b"x").unwrap();
        assert_eq!(files_under(&dir.path().join("objects")), 4);

        let v = open(dir.path(), PW);
        assert!(!tmp.exists());
        assert!(!dir.path().join(".vault.zev.tmp-0123456789abcdef").exists());
        assert_eq!(files_under(&dir.path().join("objects")), 3);
        assert_eq!(v.items().unwrap()[0].id, keep);
        drop(v);

        let UnlockResult::Open(v) =
            Vault::unlock_with(dir.path(), PW, BOOT, NOW, Duration::ZERO).unwrap()
        else {
            panic!("expected Open");
        };
        assert_eq!(files_under(&dir.path().join("objects")), 2);
        assert_eq!(v.items().unwrap().len(), 1);
    }

    #[test]
    fn deleted_newest_segment_opens_read_only() {
        let (dir, v, _rk) = new_vault();
        let first = import(&v, b"one", b"t");
        import(&v, b"two", b"t");
        let store = Store::new(dir.path());
        let dev = store.list_devices().unwrap()[0];
        drop(v);
        fs::remove_file(store.segment_path(&dev, 1)).unwrap();

        let v = open(dir.path(), PW);
        assert!(v.is_read_only());
        let items = v.items().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, first);
        assert_eq!(v.delete_items(&[first]), Err(Error::ReadOnly));
        assert_eq!(
            v.begin_import(ItemKind::Photo, meta()).err(),
            Some(Error::ReadOnly)
        );
        assert_eq!(v.rotate_recovery(PW).err(), Some(Error::ReadOnly));
    }

    #[test]
    fn deleted_or_swapped_local_state_opens_read_only() {
        let (dir, v, _rk) = new_vault();
        let id = import(&v, b"one", b"t");
        drop(v);
        let state = dir.path().join("local").join("state.zeo");

        fs::remove_file(&state).unwrap();
        let v = open(dir.path(), PW);
        assert!(v.is_read_only());
        drop(v);

        // Another blob of this vault in place of the state does not parse as state.
        let o = Store::new(dir.path()).list_objects().unwrap()[0];
        fs::copy(Store::new(dir.path()).object_path(&o), &state).unwrap();
        let v = open(dir.path(), PW);
        assert!(v.is_read_only());
        assert_eq!(v.items().unwrap()[0].id, id);

        // Only the master password ends read-only mode.
        assert_eq!(v.accept_current_state("wrong"), Err(Error::WrongPassword));
        assert!(v.is_read_only());
        v.accept_current_state(PW).unwrap();
        assert!(!v.is_read_only());
        drop(v);
        assert!(!open(dir.path(), PW).is_read_only());
    }

    #[test]
    fn empty_vault_without_state_is_writable() {
        let (dir, v, _rk) = new_vault();
        drop(v);
        fs::remove_file(dir.path().join("local").join("state.zeo")).unwrap();
        assert!(!open(dir.path(), PW).is_read_only());
    }

    #[test]
    fn unlock_path_changes_need_the_master_password() {
        let (dir, v, _rk) = new_vault();
        let header = fs::read(dir.path().join("vault.zev")).unwrap();
        for r in [
            v.set_duress("wrong", "duress password 1"),
            v.disable_duress("wrong"),
            v.enable_pin("wrong", &bio(2), "482916", BOOT, NOW),
            v.enable_biometric("wrong", &bio(1), BOOT, NOW),
        ] {
            assert_eq!(r, Err(Error::WrongPassword));
        }
        assert_eq!(fs::read(dir.path().join("vault.zev")).unwrap(), header);
        assert!(!v.is_pin_enabled());
        assert!(!v.is_biometric_enabled());
        assert!(!v.is_duress_enabled());
        v.set_duress(PW, "duress password 1").unwrap();
        assert_eq!(
            v.disable_duress("duress password 1"),
            Err(Error::WrongPassword)
        );
        assert!(v.is_duress_enabled());
        v.disable_duress(PW).unwrap();
        assert!(!v.is_duress_enabled());
    }

    #[test]
    fn change_password_removes_quick_unlock() {
        let (dir, v, _rk) = new_vault();
        v.enable_biometric(PW, &bio(1), BOOT, NOW).unwrap();
        v.enable_pin(PW, &bio(2), "482916", BOOT, NOW).unwrap();
        Vault::pause_pin_slot(dir.path()).unwrap();
        v.change_password(PW, "new pw", KdfParams::DEFAULT).unwrap();
        assert!(!v.is_biometric_enabled());
        assert!(!v.is_pin_enabled());
        assert!(!Vault::pin_slot_exists(dir.path()));
    }

    #[test]
    fn change_password_keeps_data() {
        let (dir, v, rk) = new_vault();
        let id = import(&v, b"data", b"t");
        assert_eq!(
            v.change_password("wrong", "new pw", KdfParams::DEFAULT),
            Err(Error::WrongPassword)
        );
        v.change_password(PW, "new pw", KdfParams::DEFAULT).unwrap();
        drop(v);
        let v = open(dir.path(), "new pw");
        let o = v.items().unwrap()[0].objects[&ObjectRole::Original];
        assert_eq!(v.items().unwrap()[0].id, id);
        assert_eq!(v.open_object(o).unwrap().read_all().unwrap(), b"data");
        drop(v);
        assert!(matches!(
            Vault::unlock(dir.path(), PW, BOOT, NOW).unwrap(),
            UnlockResult::WrongPassword
        ));
        assert!(Vault::unlock_recovery(dir.path(), &rk, BOOT, NOW).is_ok());
    }

    #[test]
    fn calibrate_returns_valid_params() {
        let p = kdf_calibrate(0);
        assert_eq!((p.m_kib, p.t, p.p), (65_536, 3, 4));
        let p = kdf_calibrate(u32::MAX);
        assert_eq!((p.m_kib, p.t, p.p), (65_536, 32, 4));
        assert!(kdf_calibrate(800).validate().is_ok());
    }

    fn bio(b: u8) -> BioKey {
        BioKey::from_bytes([b; 32])
    }

    fn slot_file(dir: &Path) -> PathBuf {
        dir.join("local").join("biometric.zes")
    }

    #[test]
    fn biometric_enable_and_unlock() {
        let (dir, v, _rk) = new_vault();
        let id = import(&v, b"data", b"t");
        assert!(!v.is_biometric_enabled());
        assert!(!Vault::biometric_slot_exists(dir.path()));
        v.enable_biometric(PW, &bio(1), BOOT, NOW).unwrap();
        assert!(v.is_biometric_enabled());
        assert!(Vault::biometric_slot_exists(dir.path()));
        drop(v);

        let v = Vault::unlock_biometric(dir.path(), &bio(1), BOOT, NOW + 10).unwrap();
        assert_eq!(v.items().unwrap()[0].id, id);
        assert!(!v.is_read_only());
        // Slot validity is not extended by a biometric unlock.
        let slot =
            biometric::Slot::parse(Kind::Biometric, &fs::read(slot_file(dir.path())).unwrap())
                .unwrap();
        assert_eq!(slot.expires_at, NOW + biometric::VALIDITY_SECS);
    }

    #[test]
    fn biometric_rejects_wrong_key_and_missing_slot() {
        let (dir, v, _rk) = new_vault();
        assert_eq!(
            Vault::unlock_biometric(dir.path(), &bio(1), BOOT, NOW).err(),
            Some(Error::BiometricInvalid)
        );
        v.enable_biometric(PW, &bio(1), BOOT, NOW).unwrap();
        assert_eq!(
            Vault::unlock_biometric(dir.path(), &bio(2), BOOT, NOW).err(),
            Some(Error::BiometricInvalid)
        );
    }

    #[test]
    fn biometric_rejects_tampered_slot() {
        let (dir, v, _rk) = new_vault();
        v.enable_biometric(PW, &bio(1), BOOT, NOW).unwrap();
        let path = slot_file(dir.path());
        let good = fs::read(&path).unwrap();
        assert_eq!(good.len(), 114);
        // Every byte matters: magic, version, nonce, wrapped key, policy block, MAC.
        for at in [0, 5, 8, 30, 66, 74, 82, 113] {
            let mut bad = good.clone();
            bad[at] ^= 1;
            fs::write(&path, &bad).unwrap();
            assert_eq!(
                Vault::unlock_biometric(dir.path(), &bio(1), BOOT, NOW).err(),
                Some(Error::BiometricInvalid),
                "byte {at}"
            );
        }
        // Extended policy (later expiry) with the old MAC.
        let mut bad = good.clone();
        bad[74..82].copy_from_slice(&u64::MAX.to_be_bytes());
        fs::write(&path, &bad).unwrap();
        assert_eq!(
            Vault::unlock_biometric(dir.path(), &bio(1), BOOT, NOW).err(),
            Some(Error::BiometricInvalid)
        );
        // Truncated and extended files.
        fs::write(&path, &good[..113]).unwrap();
        assert!(Vault::unlock_biometric(dir.path(), &bio(1), BOOT, NOW).is_err());
        let mut long = good.clone();
        long.push(0);
        fs::write(&path, &long).unwrap();
        assert!(Vault::unlock_biometric(dir.path(), &bio(1), BOOT, NOW).is_err());
        fs::write(&path, &good).unwrap();
        assert!(Vault::unlock_biometric(dir.path(), &bio(1), BOOT, NOW).is_ok());
    }

    #[test]
    fn biometric_expires_by_time_and_boot() {
        let (dir, v, _rk) = new_vault();
        v.enable_biometric(PW, &bio(1), BOOT, NOW).unwrap();
        let exp = NOW + biometric::VALIDITY_SECS;
        assert!(Vault::unlock_biometric(dir.path(), &bio(1), BOOT, exp - 1).is_ok());
        assert_eq!(
            Vault::unlock_biometric(dir.path(), &bio(1), BOOT, exp).err(),
            Some(Error::BiometricExpired)
        );
        assert_eq!(
            Vault::unlock_biometric(dir.path(), &bio(1), BOOT + 1, NOW).err(),
            Some(Error::BiometricExpired)
        );
    }

    #[test]
    fn password_and_recovery_unlock_refresh_the_slot() {
        let (dir, v, rk) = new_vault();
        v.enable_biometric(PW, &bio(1), BOOT, NOW).unwrap();
        drop(v);
        let later = NOW + biometric::VALIDITY_SECS + 5;
        assert_eq!(
            Vault::unlock_biometric(dir.path(), &bio(1), BOOT, later).err(),
            Some(Error::BiometricExpired)
        );
        drop(Vault::unlock(dir.path(), PW, BOOT, later).unwrap());
        assert!(Vault::unlock_biometric(dir.path(), &bio(1), BOOT, later + 1).is_ok());

        // New boot: expired until the next password unlock, recovery works too.
        assert_eq!(
            Vault::unlock_biometric(dir.path(), &bio(1), BOOT + 7, later).err(),
            Some(Error::BiometricExpired)
        );
        drop(Vault::unlock_recovery(dir.path(), &rk, BOOT + 7, later).unwrap());
        assert!(Vault::unlock_biometric(dir.path(), &bio(1), BOOT + 7, later).is_ok());
    }

    #[test]
    fn password_unlock_removes_a_corrupt_slot() {
        let (dir, v, _rk) = new_vault();
        v.enable_biometric(PW, &bio(1), BOOT, NOW).unwrap();
        drop(v);
        fs::write(slot_file(dir.path()), b"junk").unwrap();
        drop(open(dir.path(), PW));
        assert!(!Vault::biometric_slot_exists(dir.path()));
    }

    #[test]
    fn biometric_disable_removes_slot() {
        let (dir, v, _rk) = new_vault();
        v.enable_biometric(PW, &bio(1), BOOT, NOW).unwrap();
        v.disable_biometric().unwrap();
        v.disable_biometric().unwrap();
        assert!(!v.is_biometric_enabled());
        assert_eq!(
            Vault::unlock_biometric(dir.path(), &bio(1), BOOT, NOW).err(),
            Some(Error::BiometricInvalid)
        );
        v.enable_biometric(PW, &bio(1), BOOT, NOW).unwrap();
        Vault::remove_biometric_slot(dir.path()).unwrap();
        assert!(!v.is_biometric_enabled());
        v.lock();
        assert!(!v.is_biometric_enabled());
        assert_eq!(
            v.enable_biometric(PW, &bio(1), BOOT, NOW),
            Err(Error::Locked)
        );
    }

    #[test]
    fn duress_unlock_removes_biometric_slot() {
        let (dir, v, _rk) = new_vault();
        v.set_duress(PW, "duress pw").unwrap();
        v.enable_biometric(PW, &bio(1), BOOT, NOW).unwrap();
        drop(v);
        let UnlockResult::Duress(d) = Vault::unlock(dir.path(), "duress pw", BOOT, NOW).unwrap()
        else {
            panic!("expected Duress");
        };
        assert!(!Vault::biometric_slot_exists(dir.path()));
        assert!(!d.is_duress_enabled());
        assert_eq!(
            Vault::unlock_biometric(dir.path(), &bio(1), BOOT, NOW).err(),
            Some(Error::BiometricInvalid)
        );
    }

    const PIN: &str = "482916";

    fn pin_file(dir: &Path) -> PathBuf {
        dir.join("local").join("pin.zes")
    }

    #[test]
    fn pin_enable_and_unlock() {
        let (dir, v, _rk) = new_vault();
        assert!(!v.is_pin_enabled());
        v.enable_pin(PW, &bio(2), PIN, BOOT, NOW).unwrap();
        assert!(v.is_pin_enabled());
        drop(v);
        assert!(Vault::pin_slot_exists(dir.path()));
        let v = Vault::unlock_pin(dir.path(), &bio(2), PIN, BOOT, NOW).unwrap();
        assert!(v.is_pin_enabled());
        drop(v);
        // A successful attempt keeps the slot for the next unlock.
        assert!(Vault::unlock_pin(dir.path(), &bio(2), PIN, BOOT, NOW).is_ok());
    }

    #[test]
    fn wrong_pin_pauses_until_the_master_password() {
        let (dir, v, _rk) = new_vault();
        v.enable_pin(PW, &bio(2), PIN, BOOT, NOW).unwrap();
        drop(v);
        assert_eq!(
            Vault::unlock_pin(dir.path(), &bio(2), "000000", BOOT, NOW).err(),
            Some(Error::PinInvalid)
        );
        assert!(Vault::pin_slot_exists(dir.path()));
        assert!(Vault::pin_slot_paused(dir.path()));
        // Paused: even the right PIN gets no second attempt.
        assert_eq!(
            Vault::unlock_pin(dir.path(), &bio(2), PIN, BOOT, NOW).err(),
            Some(Error::PinInvalid)
        );
        let UnlockResult::Open(v) = Vault::unlock(dir.path(), PW, BOOT, NOW).unwrap() else {
            panic!("expected Open");
        };
        assert!(v.is_pin_enabled());
        drop(v);
        assert!(!Vault::pin_slot_paused(dir.path()));
        assert!(Vault::unlock_pin(dir.path(), &bio(2), PIN, BOOT, NOW).is_ok());
    }

    #[test]
    fn concurrent_pin_attempts_get_one_guess() {
        let (dir, v, _rk) = new_vault();
        v.enable_pin(PW, &bio(2), PIN, BOOT, NOW).unwrap();
        drop(v);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let evaluated = ["111111", "222222"]
            .map(|pin| {
                let (root, barrier) = (dir.path().to_path_buf(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    let t = Instant::now();
                    let r = Vault::unlock_pin(&root, &bio(2), pin, BOOT, NOW);
                    // Only an evaluated PIN runs Argon2id; a refused attempt returns at once.
                    (r.err(), t.elapsed())
                })
            })
            .map(|h| h.join().unwrap())
            .into_iter()
            .filter(|(e, took)| *e == Some(Error::PinInvalid) && *took > Duration::from_millis(50))
            .count();
        assert_eq!(evaluated, 1);
        assert!(Vault::pin_slot_paused(dir.path()));
    }

    #[test]
    fn manual_pause_and_recovery_unlock_resume() {
        let (dir, v, rk) = new_vault();
        v.enable_pin(PW, &bio(2), PIN, BOOT, NOW).unwrap();
        drop(v);
        Vault::pause_pin_slot(dir.path()).unwrap();
        assert!(Vault::pin_slot_paused(dir.path()));
        assert_eq!(
            Vault::unlock_pin(dir.path(), &bio(2), PIN, BOOT, NOW).err(),
            Some(Error::PinInvalid)
        );
        drop(Vault::unlock_recovery(dir.path(), &rk, BOOT, NOW).unwrap());
        assert!(Vault::unlock_pin(dir.path(), &bio(2), PIN, BOOT, NOW).is_ok());
        Vault::remove_pin_slot(dir.path()).unwrap();
        assert!(!Vault::pin_slot_exists(dir.path()));
    }

    #[test]
    fn wrong_se_secret_pauses_the_pin_slot() {
        let (dir, v, _rk) = new_vault();
        v.enable_pin(PW, &bio(2), PIN, BOOT, NOW).unwrap();
        drop(v);
        assert_eq!(
            Vault::unlock_pin(dir.path(), &bio(3), PIN, BOOT, NOW).err(),
            Some(Error::PinInvalid)
        );
        assert!(Vault::pin_slot_paused(dir.path()));
    }

    #[test]
    fn malformed_pin_is_rejected_without_using_the_attempt() {
        let (dir, v, _rk) = new_vault();
        assert_eq!(
            v.enable_pin(PW, &bio(2), "12345", BOOT, NOW).err(),
            Some(Error::InvalidInput)
        );
        v.enable_pin(PW, &bio(2), PIN, BOOT, NOW).unwrap();
        drop(v);
        for bad in ["12345", "1234567", "12345a", "١٢٣٤٥٦", ""] {
            assert_eq!(
                Vault::unlock_pin(dir.path(), &bio(2), bad, BOOT, NOW).err(),
                Some(Error::InvalidInput)
            );
        }
        assert!(Vault::unlock_pin(dir.path(), &bio(2), PIN, BOOT, NOW).is_ok());
    }

    #[test]
    fn pin_expires_by_time_and_boot_and_password_unlock_refreshes() {
        let (dir, v, _rk) = new_vault();
        v.enable_pin(PW, &bio(2), PIN, BOOT, NOW).unwrap();
        drop(v);
        let exp = NOW + biometric::VALIDITY_SECS;
        assert_eq!(
            Vault::unlock_pin(dir.path(), &bio(2), PIN, BOOT + 1, NOW).err(),
            Some(Error::PinExpired)
        );
        // The right PIN after a reboot keeps the slot for after the next password unlock.
        assert!(Vault::pin_slot_exists(dir.path()));
        assert_eq!(
            Vault::unlock_pin(dir.path(), &bio(2), PIN, BOOT, exp).err(),
            Some(Error::PinExpired)
        );
        assert!(Vault::pin_slot_exists(dir.path()));
        // A wrong PIN on an expired slot still pauses it.
        let (dir2, v2, _rk2) = new_vault();
        v2.enable_pin(PW, &bio(2), PIN, BOOT, NOW).unwrap();
        drop(v2);
        assert_eq!(
            Vault::unlock_pin(dir2.path(), &bio(2), "111111", BOOT + 1, NOW).err(),
            Some(Error::PinInvalid)
        );
        assert!(Vault::pin_slot_paused(dir2.path()));

        let later = exp - 10;
        assert!(matches!(
            Vault::unlock(dir.path(), PW, BOOT, later),
            Ok(UnlockResult::Open(_))
        ));
        assert!(Vault::unlock_pin(dir.path(), &bio(2), PIN, BOOT, exp + 1).is_ok());
    }

    #[test]
    fn pin_and_biometric_are_independent() {
        let (dir, v, _rk) = new_vault();
        v.enable_biometric(PW, &bio(1), BOOT, NOW).unwrap();
        v.enable_pin(PW, &bio(2), PIN, BOOT, NOW).unwrap();
        v.disable_pin().unwrap();
        assert!(v.is_biometric_enabled());
        assert!(!v.is_pin_enabled());
        drop(v);
        assert!(Vault::unlock_biometric(dir.path(), &bio(1), BOOT, NOW).is_ok());
    }

    #[test]
    fn biometric_slot_bytes_do_not_open_as_pin_slot() {
        let (dir, v, _rk) = new_vault();
        v.enable_biometric(PW, &bio(1), BOOT, NOW).unwrap();
        drop(v);
        fs::copy(slot_file(dir.path()), pin_file(dir.path())).unwrap();
        assert_eq!(
            Vault::unlock_pin(dir.path(), &bio(1), PIN, BOOT, NOW).err(),
            Some(Error::PinInvalid)
        );
    }

    #[test]
    fn duress_unlock_removes_pin_slot() {
        let (dir, v, _rk) = new_vault();
        v.set_duress(PW, "duress pw").unwrap();
        v.enable_pin(PW, &bio(2), PIN, BOOT, NOW).unwrap();
        drop(v);
        let UnlockResult::Duress(_) = Vault::unlock(dir.path(), "duress pw", BOOT, NOW).unwrap()
        else {
            panic!("expected Duress");
        };
        assert!(!Vault::pin_slot_exists(dir.path()));
    }

    #[test]
    fn biometric_needs_matching_header() {
        let (dir, v, _rk) = new_vault();
        v.enable_biometric(PW, &bio(1), BOOT, NOW).unwrap();
        drop(v);
        let other = tempfile::tempdir().unwrap();
        Vault::create(other.path(), PW, KdfParams::DEFAULT).unwrap();
        fs::create_dir_all(other.path().join("local")).unwrap();
        fs::copy(slot_file(dir.path()), slot_file(other.path())).unwrap();
        assert_eq!(
            Vault::unlock_biometric(other.path(), &bio(1), BOOT, NOW).err(),
            Some(Error::BiometricInvalid)
        );
    }

    #[test]
    fn biometric_enable_needs_writable_vault() {
        let (_dir, v, _rk) = new_vault();
        v.lock();
        assert_eq!(
            v.enable_biometric(PW, &bio(1), BOOT, NOW),
            Err(Error::Locked)
        );
    }

    #[test]
    fn duress_state_is_tracked_and_persisted() {
        let (dir, v, _rk) = new_vault();
        assert!(!v.is_duress_enabled());
        v.set_duress(PW, "duress pw").unwrap();
        assert!(v.is_duress_enabled());
        drop(v);
        let v = open(dir.path(), PW);
        assert!(v.is_duress_enabled());
        // An import (state rewrite) keeps the flag.
        import(&v, b"a", b"t");
        drop(v);
        let v = open(dir.path(), PW);
        assert!(v.is_duress_enabled());
        v.disable_duress(PW).unwrap();
        assert!(!v.is_duress_enabled());
        drop(v);
        let v = open(dir.path(), PW);
        assert!(!v.is_duress_enabled());
        v.set_duress(PW, "duress pw").unwrap();
        v.change_password(PW, "new pw", KdfParams::DEFAULT).unwrap();
        assert!(!v.is_duress_enabled());
        drop(v);
        assert!(!open(dir.path(), "new pw").is_duress_enabled());
        let v = open(dir.path(), "new pw");
        v.lock();
        assert!(!v.is_duress_enabled());
    }

    #[test]
    fn rotate_recovery_requires_master_password() {
        let (dir, v, old_rk) = new_vault();
        v.set_duress(PW, "duress pw").unwrap();
        assert_eq!(v.rotate_recovery("nope").err(), Some(Error::WrongPassword));
        assert_eq!(
            v.rotate_recovery("duress pw").err(),
            Some(Error::WrongPassword)
        );
        assert_eq!(v.rotate_recovery("").err(), Some(Error::EmptyPassword));
        drop(v);
        assert!(Vault::unlock_recovery(dir.path(), &old_rk, BOOT, NOW).is_ok());
    }

    #[test]
    fn verify_password_checks_master_only() {
        let (_dir, v, _rk) = new_vault();
        v.set_duress(PW, "duress pw").unwrap();
        assert_eq!(v.verify_password(PW), Ok(()));
        assert_eq!(v.verify_password("nope"), Err(Error::WrongPassword));
        assert_eq!(v.verify_password("duress pw"), Err(Error::WrongPassword));
        assert_eq!(v.verify_password(""), Err(Error::EmptyPassword));
    }

    #[test]
    fn erase_requires_master_password() {
        let (dir, v, _rk) = new_vault();
        import(&v, b"data", b"t");
        v.set_duress(PW, "duress pw").unwrap();
        v.enable_biometric(PW, &bio(1), BOOT, NOW).unwrap();
        let before = files_under(dir.path());
        assert_eq!(v.erase("nope"), Err(Error::WrongPassword));
        assert_eq!(v.erase("duress pw"), Err(Error::WrongPassword));
        assert_eq!(v.erase(""), Err(Error::EmptyPassword));
        assert_eq!(files_under(dir.path()), before);
        assert!(v.items().is_ok());

        v.erase(PW).unwrap();
        assert_eq!(files_under(dir.path()), 0);
        assert_eq!(v.items().err(), Some(Error::Locked));
        assert_eq!(v.erase(PW), Err(Error::Locked));
        assert_eq!(
            Vault::unlock(dir.path(), PW, BOOT, NOW).err(),
            Some(Error::NotAVault)
        );
    }

    #[test]
    fn albums_round_trip() {
        let (dir, v, _rk) = new_vault();
        let a = import(&v, b"a", b"ta");
        let b = import(&v, b"b", b"tb");
        let album = v.create_album("  Trip ").unwrap();
        assert_eq!(v.create_album(" "), Err(Error::InvalidInput));
        assert_eq!(v.create_album(&"x".repeat(101)), Err(Error::InvalidInput));
        let list = v.albums().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "Trip");
        assert_eq!((list[0].item_count, list[0].cover_item), (0, None));

        v.add_to_album(album, &[a, b]).unwrap();
        v.add_to_album(album, &[a]).unwrap();
        assert_eq!(v.album_items(album).unwrap().len(), 2);
        assert_eq!(v.albums().unwrap()[0].item_count, 2);
        assert!(v.items().unwrap().iter().all(|it| it.albums == vec![album]));
        // Unknown ids are rejected and nothing is written.
        assert_eq!(
            v.add_to_album(album, &[a, ItemId([7; 16])]),
            Err(Error::NotFound)
        );
        assert_eq!(v.add_to_album(AlbumId([7; 16]), &[a]), Err(Error::NotFound));

        v.remove_from_album(album, &[a]).unwrap();
        v.rename_album(album, "Berge").unwrap();
        assert_eq!(v.album_items(album).unwrap(), vec![b]);
        assert_eq!(v.albums().unwrap()[0].cover_item, Some(b));

        // Persists across unlock; deleting an item drops it from the album.
        drop(v);
        let v = open(dir.path(), PW);
        assert_eq!(v.albums().unwrap()[0].name, "Berge");
        v.delete_items(&[b]).unwrap();
        assert!(v.album_items(album).unwrap().is_empty());
        assert_eq!(v.items().unwrap().len(), 1);
        assert!(v.items().unwrap()[0].albums.is_empty());

        // Deleting the album keeps the photos.
        v.add_to_album(album, &[a]).unwrap();
        v.delete_album(album).unwrap();
        assert!(v.albums().unwrap().is_empty());
        assert_eq!(v.album_items(album), Err(Error::NotFound));
        assert_eq!(v.delete_album(album), Err(Error::NotFound));
        assert_eq!(v.items().unwrap().len(), 1);
        assert!(v.items().unwrap()[0].albums.is_empty());
        drop(v);
        let v = open(dir.path(), PW);
        assert!(v.albums().unwrap().is_empty());
    }

    #[test]
    fn album_pin_and_visibility() {
        let (dir, v, _rk) = new_vault();
        let a = import(&v, b"a", b"ta");
        let b = import(&v, b"b", b"tb");
        let c = import(&v, b"c", b"tc");
        let open_album = v.create_album("Open").unwrap();
        let locked = v.create_album("Locked").unwrap();
        v.add_to_album(open_album, &[a]).unwrap();
        v.add_to_album(locked, &[a, b]).unwrap();

        let summary = |v: &Vault, id| {
            v.albums()
                .unwrap()
                .into_iter()
                .find(|s| s.id == id)
                .unwrap()
        };
        let hidden = |v: &Vault, id| {
            v.items()
                .unwrap()
                .into_iter()
                .find(|i| i.id == id)
                .unwrap()
                .hidden_in_all
        };
        assert!(!summary(&v, locked).locked && summary(&v, locked).show_in_all);
        assert_eq!(v.verify_album_pin(locked, "1234"), Ok(false));
        assert!(!hidden(&v, a) && !hidden(&v, b) && !hidden(&v, c));

        for bad in ["", "123", "12345", "12a4", "١٢٣٤"] {
            assert_eq!(v.set_album_pin(locked, Some(bad)), Err(Error::InvalidInput));
        }
        let unknown = AlbumId([7; 16]);
        assert_eq!(v.set_album_pin(unknown, Some("1234")), Err(Error::NotFound));
        assert_eq!(v.verify_album_pin(unknown, "1234"), Err(Error::NotFound));
        v.set_album_pin(locked, Some("1234")).unwrap();
        assert_eq!(v.verify_album_pin(locked, "1234"), Ok(true));
        assert_eq!(v.verify_album_pin(locked, "1235"), Ok(false));
        assert_eq!(v.verify_album_pin(locked, "123"), Ok(false));
        assert_eq!(v.verify_album_pin(open_album, "1234"), Ok(false));

        // Locking defaults to hidden; an item in a shown and a hidden album is hidden.
        let s = summary(&v, locked);
        assert!(s.locked && !s.show_in_all);
        assert!(hidden(&v, a) && hidden(&v, b) && !hidden(&v, c));

        // Explicit show wins and persists across unlock.
        v.set_album_show_in_all(locked, true).unwrap();
        assert!(!hidden(&v, a) && !hidden(&v, b));
        v.set_album_show_in_all(locked, false).unwrap();
        drop(v);
        let v = open(dir.path(), PW);
        assert_eq!(v.verify_album_pin(locked, "1234"), Ok(true));
        assert!(!summary(&v, locked).show_in_all && hidden(&v, a));

        // Removing the code keeps the explicit choice; the album is open again.
        v.set_album_pin(locked, None).unwrap();
        assert!(!summary(&v, locked).locked && !summary(&v, locked).show_in_all);
        assert_eq!(v.verify_album_pin(locked, "1234"), Ok(false));
        assert!(hidden(&v, b));

        // Deleting the hidden album un-hides its items.
        v.delete_album(locked).unwrap();
        assert!(!hidden(&v, a) && !hidden(&v, b));
    }

    #[test]
    fn trash_restore_and_album_views() {
        let (dir, v, _rk) = new_vault();
        let a = import(&v, b"a", b"ta");
        let b = import(&v, b"b", b"tb");
        let album = v.create_album("Trip").unwrap();
        v.add_to_album(album, &[a, b]).unwrap();
        let trashed = |v: &Vault, id: ItemId| {
            v.items()
                .unwrap()
                .iter()
                .find(|it| it.id == id)
                .unwrap()
                .meta
                .trashed
        };

        v.trash_items(&[a], 1000).unwrap();
        assert_eq!(trashed(&v, a), Some(1000));
        assert_eq!(trashed(&v, b), None);
        // Already trashed items keep their date.
        v.trash_items(&[a, b], 2000).unwrap();
        assert_eq!((trashed(&v, a), trashed(&v, b)), (Some(1000), Some(2000)));
        // Trashed items are out of album views but keep their membership.
        assert_eq!(v.album_items(album).unwrap(), Vec::<ItemId>::new());
        let s = &v.albums().unwrap()[0];
        assert_eq!((s.item_count, s.cover_item), (0, None));
        assert!(v.items().unwrap().iter().all(|it| it.albums == vec![album]));
        assert_eq!(
            v.trash_items(&[a, ItemId([7; 16])], 1),
            Err(Error::NotFound)
        );

        v.restore_items(&[a]).unwrap();
        v.restore_items(&[a]).unwrap();
        assert_eq!(v.album_items(album).unwrap(), vec![a]);
        let s = &v.albums().unwrap()[0];
        assert_eq!((s.item_count, s.cover_item), (1, Some(a)));

        // Persists across unlock.
        drop(v);
        let v = open(dir.path(), PW);
        assert_eq!((trashed(&v, a), trashed(&v, b)), (None, Some(2000)));
        // Permanent delete of a trashed item.
        let blobs = files_under(dir.path());
        v.delete_items(&[b]).unwrap();
        assert!(files_under(dir.path()) < blobs);
        assert_eq!(v.restore_items(&[b]), Err(Error::NotFound));
    }

    #[test]
    fn purge_expired_boundary() {
        let (_dir, v, _rk) = new_vault();
        let a = import(&v, b"a", b"ta");
        let b = import(&v, b"b", b"tb");
        let c = import(&v, b"c", b"tc");
        let t0 = 1_000_000;
        v.trash_items(&[a], t0).unwrap();
        v.trash_items(&[b], t0 + 1).unwrap();
        let ids =
            |v: &Vault| -> Vec<ItemId> { v.items().unwrap().iter().map(|it| it.id).collect() };

        // One ms before the retention ends nothing is purged.
        assert_eq!(v.purge_expired(t0 + TRASH_RETENTION_MS - 1), Ok(0));
        assert_eq!(ids(&v).len(), 3);
        // Exactly at the boundary the first item goes, the later one stays.
        assert_eq!(v.purge_expired(t0 + TRASH_RETENTION_MS), Ok(1));
        assert!(!ids(&v).contains(&a) && ids(&v).contains(&b) && ids(&v).contains(&c));
        assert_eq!(v.purge_expired(t0 + TRASH_RETENTION_MS), Ok(0));
        assert_eq!(v.purge_expired(t0 + TRASH_RETENTION_MS + 1), Ok(1));
        assert_eq!(ids(&v), vec![c]);
    }
}

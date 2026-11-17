//! Encrypted export file and its import (vault-format §7, crypto §10).
//!
//! Files are copied as stored; nothing is decrypted. Import stages everything in
//! `<root>/.import-<hex>/` and touches the vault only after the MAC has verified.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
use crate::header::VaultHeader;
use crate::journal::{read_all_chains, referenced_objects, Chains, State};
use crate::kdf::export_mac_key;
use crate::keys::{MacKey, VaultKey};
use crate::local::{read_local_state, write_local_state, LocalState};
use crate::recovery::RecoveryKey;
use crate::rng::{self, OsRandom};
use crate::store::{hex_id, is_lower_hex, parse_id, parse_seq, Store, STAGING_PREFIX};
use crate::{header, vault};

const MAGIC: &[u8; 4] = b"ZENX";
const VERSION: u16 = 1;
const TYPE_END: u8 = 0x00;
const TYPE_OBJECT: u8 = 0x01;
const TYPE_SEGMENT: u8 = 0x02;
const MAX_PATH_LEN: usize = 128;
const MAX_HEADER_LEN: u32 = 4096;
const MAC_LEN: usize = 32;
const BLOCK: usize = 64 * 1024;

/// Secret used to unlock the vault header inside an export.
#[derive(Zeroize, ZeroizeOnDrop)]
pub enum ImportSecret {
    Password(String),
    RecoveryKey(String),
}

/// Result of a successful import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportOutcome {
    /// No vault existed at the target; the export became the vault.
    Restored,
    /// Same vault: only missing files were added.
    Merged {
        added_objects: usize,
        added_segments: usize,
    },
}

/// Unlocks the header of an export. A duress password never shreds anything here.
pub(crate) fn unlock_secret(header: &VaultHeader, secret: &ImportSecret) -> Result<VaultKey> {
    match secret {
        ImportSecret::Password(pw) => match header::unlock(header, pw)? {
            header::UnlockOutcome::Open(vk) => Ok(vk),
            _ => Err(Error::WrongPassword),
        },
        ImportSecret::RecoveryKey(rk) => header::unlock_recovery(header, &RecoveryKey::decode(rk)?),
    }
}

fn io_err(e: io::Error) -> Error {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        Error::ExportFormat
    } else {
        Error::Io
    }
}

fn new_mac(key: &MacKey) -> Hmac<Sha256> {
    <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length")
}

// ---------------------------------------------------------------- paths

/// A file of the store, identified by its position in the layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Entry {
    Object([u8; 16]),
    Segment([u8; 16], u64),
}

impl Entry {
    fn type_byte(self) -> u8 {
        match self {
            Self::Object(_) => TYPE_OBJECT,
            Self::Segment(..) => TYPE_SEGMENT,
        }
    }

    fn rel_path(self) -> String {
        match self {
            Self::Object(id) => {
                let h = hex_id(&id);
                format!("objects/{}/{h}.zeo", &h[..2])
            }
            Self::Segment(dev, seq) => format!("journal/{}/{seq:020}.zeo", hex_id(&dev)),
        }
    }

    fn path_in(self, store: &Store) -> PathBuf {
        match self {
            Self::Object(id) => store.object_path(&id),
            Self::Segment(dev, seq) => store.segment_path(&dev, seq),
        }
    }

    /// Strict inverse of `rel_path`: only canonical store paths are accepted.
    fn parse(path: &str) -> Option<Self> {
        if !path.is_ascii() {
            return None;
        }
        let parts: Vec<&str> = path.split('/').collect();
        let entry = match parts.as_slice() {
            ["objects", shard, name] => {
                let id = parse_id(name.strip_suffix(".zeo")?)?;
                if !is_lower_hex(shard, 2) || hex_id(&id)[..2] != **shard {
                    return None;
                }
                Self::Object(id)
            }
            ["journal", dev, name] => Self::Segment(parse_id(dev)?, parse_seq(name)?),
            _ => return None,
        };
        (entry.rel_path() == path).then_some(entry)
    }
}

// ---------------------------------------------------------------- export

/// Files to export: live objects, then all journal segments, in path order.
pub(crate) fn plan(store: &Store, state: &State) -> Result<Vec<(Entry, u64)>> {
    let mut entries: Vec<Entry> = referenced_objects(state)
        .into_iter()
        .map(Entry::Object)
        .collect();
    for dev in store.list_devices()? {
        for seq in store.list_segments(&dev)? {
            entries.push(Entry::Segment(dev, seq));
        }
    }
    entries
        .into_iter()
        .map(|e| {
            let len = fs::metadata(e.path_in(store)).map_err(|err| match err.kind() {
                io::ErrorKind::NotFound => Error::NotFound,
                _ => Error::Io,
            })?;
            Ok((e, len.len()))
        })
        .collect()
}

struct MacWriter<W: Write> {
    w: W,
    mac: Hmac<Sha256>,
}

impl<W: Write> MacWriter<W> {
    fn put(&mut self, data: &[u8]) -> Result<()> {
        self.mac.update(data);
        self.w.write_all(data).map_err(|_| Error::Io)
    }
}

/// Streams the export to `path` (atomic); memory use is one block.
pub(crate) fn write_export(
    store: &Store,
    header_bytes: &[u8],
    mac_key: &MacKey,
    files: &[(Entry, u64)],
    path: &Path,
    mut progress: impl FnMut(u64, u64),
) -> Result<()> {
    let total: u64 = files.iter().map(|(_, n)| n).sum();
    let (file, tmp) = store.create_tmp(path)?;
    let res = (|| {
        let mut w = MacWriter {
            w: BufWriter::new(file),
            mac: new_mac(mac_key),
        };
        let header_len = u32::try_from(header_bytes.len()).map_err(|_| Error::Io)?;
        w.put(MAGIC)?;
        w.put(&VERSION.to_be_bytes())?;
        w.put(&0u16.to_be_bytes())?;
        w.put(&header_len.to_be_bytes())?;
        w.put(header_bytes)?;
        let mut buf = vec![0u8; BLOCK];
        let mut done = 0u64;
        progress(0, total);
        for (entry, len) in files {
            let rel = entry.rel_path();
            let path_len = u16::try_from(rel.len()).map_err(|_| Error::Io)?;
            w.put(&[entry.type_byte()])?;
            w.put(&path_len.to_be_bytes())?;
            w.put(rel.as_bytes())?;
            w.put(&len.to_be_bytes())?;
            let mut src = File::open(entry.path_in(store)).map_err(|_| Error::Io)?;
            let mut left = *len;
            while left > 0 {
                let want = usize::try_from(left).unwrap_or(BLOCK).min(BLOCK);
                // The file changing size after planning is an error.
                src.read_exact(&mut buf[..want]).map_err(|_| Error::Io)?;
                w.put(&buf[..want])?;
                left -= want as u64;
                done += want as u64;
                progress(done, total);
            }
        }
        w.put(&[TYPE_END])?;
        let tag = w.mac.clone().finalize().into_bytes();
        w.w.write_all(&tag).map_err(|_| Error::Io)?;
        w.w.into_inner().map_err(|_| Error::Io)
    })();
    match res {
        Ok(file) => store.commit_tmp(file, &tmp, path),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

// ---------------------------------------------------------------- import

/// Removes the staging directory on every exit path.
struct Staging(PathBuf);

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Reader that feeds everything it reads into the MAC.
struct Tee<R: Read> {
    r: R,
    mac: Hmac<Sha256>,
    pos: u64,
}

impl<R: Read> Tee<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<()> {
        self.r.read_exact(buf).map_err(io_err)?;
        self.mac.update(buf);
        self.pos += buf.len() as u64;
        Ok(())
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut b = [0u8; N];
        self.read(&mut b)?;
        Ok(b)
    }
}

/// Streams all entries into `stage`; returns them sorted. The end marker is consumed.
fn stage_entries<R: Read>(t: &mut Tee<R>, file_len: u64, stage: &Store) -> Result<Vec<Entry>> {
    let mut seen = BTreeSet::new();
    let mut buf = vec![0u8; BLOCK];
    loop {
        let ty = t.array::<1>()?[0];
        if ty == TYPE_END {
            break;
        }
        let path_len = usize::from(u16::from_be_bytes(t.array()?));
        if path_len == 0 || path_len > MAX_PATH_LEN {
            return Err(Error::ExportFormat);
        }
        let mut path = vec![0u8; path_len];
        t.read(&mut path)?;
        let path = String::from_utf8(path).map_err(|_| Error::ExportFormat)?;
        let entry = Entry::parse(&path).ok_or(Error::ExportFormat)?;
        if entry.type_byte() != ty || !seen.insert(entry) {
            return Err(Error::ExportFormat);
        }
        let mut left = u64::from_be_bytes(t.array()?);
        // Data must fit into the rest of the file (end marker and MAC follow).
        if left > file_len.saturating_sub(t.pos + 1 + MAC_LEN as u64) {
            return Err(Error::ExportFormat);
        }
        let dest = entry.path_in(stage);
        fs::create_dir_all(dest.parent().ok_or(Error::Io)?).map_err(|_| Error::Io)?;
        let mut f = File::options()
            .write(true)
            .create_new(true)
            .open(&dest)
            .map_err(|_| Error::Io)?;
        while left > 0 {
            let want = usize::try_from(left).unwrap_or(BLOCK).min(BLOCK);
            t.read(&mut buf[..want])?;
            f.write_all(&buf[..want]).map_err(|_| Error::Io)?;
            left -= want as u64;
        }
        f.sync_all().map_err(|_| Error::Io)?;
    }
    Ok(seen.into_iter().collect())
}

fn same_file(a: &Path, b: &Path) -> Result<bool> {
    let (mut fa, mut fb) = (
        File::open(a).map_err(|_| Error::Io)?,
        File::open(b).map_err(|_| Error::Io)?,
    );
    let len = fa.metadata().map_err(|_| Error::Io)?.len();
    if len != fb.metadata().map_err(|_| Error::Io)?.len() {
        return Ok(false);
    }
    let (mut ba, mut bb) = (vec![0u8; BLOCK], vec![0u8; BLOCK]);
    let mut left = len;
    while left > 0 {
        let n = usize::try_from(left).unwrap_or(BLOCK).min(BLOCK);
        fa.read_exact(&mut ba[..n]).map_err(|_| Error::Io)?;
        fb.read_exact(&mut bb[..n]).map_err(|_| Error::Io)?;
        if ba[..n] != bb[..n] {
            return Ok(false);
        }
        left -= n as u64;
    }
    Ok(true)
}

fn move_into(src: &Path, dest: &Path) -> Result<()> {
    fs::create_dir_all(dest.parent().ok_or(Error::Io)?).map_err(|_| Error::Io)?;
    fs::rename(src, dest).map_err(|_| Error::Io)
}

/// Longest chain per device; overlapping segments are identical (checked beforehand).
fn merge_chains(mut base: Chains, other: Chains) -> Chains {
    for (dev, chain) in other {
        let cur = base.entry(dev).or_default();
        if chain.len() > cur.len() {
            *cur = chain;
        }
    }
    base
}

/// A fully verified export, staged next to the vault. Nothing in the target is touched yet.
pub(crate) struct Staged {
    _staging: Staging,
    stage: Store,
    header: VaultHeader,
    vk: VaultKey,
    entries: Vec<Entry>,
    local: LocalState,
}

/// Parses, unlocks and stages `export_path` in `root`, and verifies the MAC.
/// `check` runs right after unlocking, before anything is staged.
pub(crate) fn stage_export(
    root: &Path,
    export_path: &Path,
    unlock: impl FnOnce(&VaultHeader) -> Result<VaultKey>,
    check: impl FnOnce(&VaultHeader, &VaultKey) -> Result<()>,
) -> Result<Staged> {
    let file = File::open(export_path).map_err(|_| Error::Io)?;
    let file_len = file.metadata().map_err(|_| Error::Io)?.len();
    let mut r = BufReader::new(file);

    let mut prefix = vec![0u8; 12];
    r.read_exact(&mut prefix).map_err(io_err)?;
    let version = u16::from_be_bytes([prefix[4], prefix[5]]);
    let reserved = u16::from_be_bytes([prefix[6], prefix[7]]);
    let header_len = u32::from_be_bytes([prefix[8], prefix[9], prefix[10], prefix[11]]);
    if &prefix[..4] != MAGIC || version != VERSION || reserved != 0 || header_len > MAX_HEADER_LEN {
        return Err(Error::ExportFormat);
    }
    let mut header_bytes = vec![0u8; header_len as usize];
    r.read_exact(&mut header_bytes).map_err(io_err)?;
    prefix.extend_from_slice(&header_bytes);
    let header = VaultHeader::parse(&header_bytes).map_err(|_| Error::ExportFormat)?;
    let vk = unlock(&header)?;
    check(&header, &vk)?;
    let vault_id = *header.vault_id();

    fs::create_dir_all(root).map_err(|_| Error::Io)?;
    let rand = rng::array::<8>(&mut OsRandom)?;
    let staging = Staging(root.join(format!("{STAGING_PREFIX}{}", hex_id(&rand))));
    fs::create_dir(&staging.0).map_err(|_| Error::Io)?;
    let stage = Store::new(&staging.0);

    let mut mac = new_mac(&export_mac_key(&vk, &vault_id));
    mac.update(&prefix);
    let mut tee = Tee {
        r,
        mac,
        pos: prefix.len() as u64,
    };
    let entries = stage_entries(&mut tee, file_len, &stage)?;
    let mut tag = [0u8; MAC_LEN];
    tee.r.read_exact(&mut tag).map_err(io_err)?;
    if tee.r.read(&mut [0u8; 1]).map_err(|_| Error::Io)? != 0 {
        return Err(Error::ExportFormat);
    }
    // Constant-time comparison.
    tee.mac
        .verify_slice(&tag)
        .map_err(|_| Error::ExportFormat)?;
    // A journal that does not open fails here, before any caller touches the vault.
    let chains = read_all_chains(&stage, &vk, vault_id)?;
    let local = LocalState::build(&chains, State::fold(chains.values().flatten()));
    Ok(Staged {
        local,
        _staging: staging,
        stage,
        header,
        vk,
        entries,
    })
}

impl Staged {
    /// Moves the staged export into `target`, which holds no vault. The header goes last:
    /// it is what makes the directory a vault. Duress is disabled in the written header,
    /// because the flag is not part of the export (crypto §7).
    pub(crate) fn commit_restore(&self, target: &Store) -> Result<()> {
        let header = header::disable_duress(&self.header, &self.vk)?.to_bytes();
        for e in &self.entries {
            move_into(&e.path_in(&self.stage), &e.path_in(target))?;
        }
        target.write_atomic(&target.header_path(), |f| {
            f.write_all(&header).map_err(|_| Error::Io)
        })?;
        // Without a local state the restored vault would open read-only (vault-format §6).
        write_local_state(target, &self.vk, *self.header.vault_id(), &self.local)
    }
}

/// Disables duress in the on-disk header and the local flag of the vault at `target`.
fn reset_duress(target: &Store, vk: &VaultKey, vault_id: [u8; 16]) -> Result<()> {
    let h = header::disable_duress(&vault::read_header(target)?, vk)?.to_bytes();
    target.write_atomic(&target.header_path(), |f| {
        f.write_all(&h).map_err(|_| Error::Io)
    })?;
    if let Some(mut local) = read_local_state(target, vk, vault_id).ok().flatten() {
        if local.duress_enabled {
            local.duress_enabled = false;
            write_local_state(target, vk, vault_id, &local)?;
        }
    }
    Ok(())
}

/// Imports `export_path` into `root`. `unlock` opens the export header; `expect_vk`
/// (open vault) additionally requires the same vault key. Duress is disabled on the
/// resulting vault (restore and merge).
pub(crate) fn import(
    root: &Path,
    export_path: &Path,
    unlock: impl FnOnce(&VaultHeader) -> Result<VaultKey>,
    expect_vk: Option<&VaultKey>,
) -> Result<ImportOutcome> {
    let target = Store::new(root);
    let mut existing = false;
    let staged = stage_export(root, export_path, unlock, |header, vk| {
        if let Some(want) = expect_vk {
            if !bool::from(want.as_bytes().ct_eq(vk.as_bytes())) {
                return Err(Error::DifferentVault);
            }
        }
        match vault::read_header(&target) {
            Ok(h) if h.vault_id() != header.vault_id() => return Err(Error::DifferentVault),
            Ok(_) => existing = true,
            Err(Error::NotAVault) => {}
            Err(e) => return Err(e),
        }
        Ok(())
    })?;
    let Staged {
        stage,
        entries,
        vk,
        header,
        ..
    } = &staged;
    let vault_id = *header.vault_id();

    if !existing {
        staged.commit_restore(&target)?;
        return Ok(ImportOutcome::Restored);
    }

    for e in entries {
        let dest = e.path_in(&target);
        if dest.exists() && !same_file(&e.path_in(stage), &dest)? {
            return Err(Error::ExportConflict);
        }
    }
    // Only objects referenced by the merged journal are copied, so deleted
    // items do not come back.
    let merged = merge_chains(
        read_all_chains(&target, vk, vault_id)?,
        read_all_chains(stage, vk, vault_id)?,
    );
    let live = referenced_objects(&State::fold(merged.values().flatten()));
    let (mut added_objects, mut added_segments) = (0, 0);
    // Objects first, so a segment never references a missing object.
    for e in entries {
        let dest = e.path_in(&target);
        let wanted = match e {
            Entry::Object(id) => live.contains(id),
            Entry::Segment(..) => false,
        };
        if wanted && !dest.exists() {
            move_into(&e.path_in(stage), &dest)?;
            added_objects += 1;
        }
    }
    for e in entries {
        let dest = e.path_in(&target);
        if matches!(e, Entry::Segment(..)) && !dest.exists() {
            move_into(&e.path_in(stage), &dest)?;
            added_segments += 1;
        }
    }
    reset_duress(&target, vk, vault_id)?;
    Ok(ImportOutcome::Merged {
        added_objects,
        added_segments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{ItemId, ItemKind, ItemMeta};
    use crate::kdf::KdfParams;
    use crate::vault::{ObjectRole, UnlockResult, Vault};

    const PW: &str = "correct horse";

    fn put(v: &Vault, data: &[u8]) -> ItemId {
        let meta = ItemMeta {
            filename: Some("a.jpg".into()),
            imported: 1,
            ..ItemMeta::default()
        };
        let mut s = v.begin_import(ItemKind::Photo, meta).unwrap();
        let mut w = s.add_object(ObjectRole::Original).unwrap();
        w.write(data).unwrap();
        w.finish().unwrap();
        s.commit().unwrap()
    }

    /// Items sorted by id with their original bytes.
    fn dump(v: &Vault) -> Vec<(ItemId, Option<String>, Vec<u8>)> {
        let mut out: Vec<_> = v
            .items()
            .unwrap()
            .into_iter()
            .map(|it| {
                let o = it.objects[&ObjectRole::Original];
                let bytes = v.open_object(o).unwrap().read_all().unwrap();
                (it.id, it.meta.filename, bytes)
            })
            .collect();
        out.sort_by_key(|x| x.0 .0);
        out
    }

    fn open(dir: &Path, pw: &str) -> Vault {
        match Vault::unlock(dir, pw, 0, 0).unwrap() {
            UnlockResult::Open(v) => v,
            _ => panic!("expected Open"),
        }
    }

    fn pw(s: &str) -> ImportSecret {
        ImportSecret::Password(s.into())
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn export_restore_roundtrip() {
        let a = tempfile::tempdir().unwrap();
        let (va, _rk) = Vault::create(a.path(), PW, KdfParams::DEFAULT).unwrap();
        put(&va, b"first original");
        put(&va, &vec![7u8; 200_000]);
        let out = tempfile::tempdir().unwrap();
        let file = out.path().join("e.zenx");
        let mut calls = Vec::new();
        va.export_to(&file, |d, t| calls.push((d, t))).unwrap();
        assert_eq!(names(out.path()), ["e.zenx"]);
        let (d, t) = *calls.last().unwrap();
        assert!(t > 0 && d == t);
        assert!(calls.windows(2).all(|w| w[0].0 <= w[1].0));

        let bytes = fs::read(&file).unwrap();
        assert_eq!(&bytes[..4], b"ZENX");
        assert!(!bytes.windows(6).any(|w| w == b"local/"));

        let b = tempfile::tempdir().unwrap();
        let outcome = Vault::import_from(b.path(), &file, pw(PW)).unwrap();
        assert_eq!(outcome, ImportOutcome::Restored);
        assert!(!names(b.path()).iter().any(|n| n.starts_with(".import-")));
        assert!(b.path().join("local").join("state.zeo").is_file());
        let vb = open(b.path(), PW);
        assert!(!vb.is_read_only());
        assert_eq!(dump(&vb).len(), 2);
        assert_eq!(dump(&vb), dump(&va));

        va.lock();
        assert_eq!(va.export_to(&file, |_, _| {}), Err(Error::Locked));
    }

    #[test]
    fn merge_keeps_tombstones() {
        let a = tempfile::tempdir().unwrap();
        let (va, _rk) = Vault::create(a.path(), PW, KdfParams::DEFAULT).unwrap();
        let one = put(&va, b"one");
        let out = tempfile::tempdir().unwrap();
        let e1 = out.path().join("e1.zenx");
        va.export_to(&e1, |_, _| {}).unwrap();

        // Second device: restore, add an item, export.
        let b = tempfile::tempdir().unwrap();
        Vault::import_from(b.path(), &e1, pw(PW)).unwrap();
        let vb = open(b.path(), PW);
        let two = put(&vb, b"two");
        let e2 = out.path().join("e2.zenx");
        vb.export_to(&e2, |_, _| {}).unwrap();

        va.delete_items(&[one]).unwrap();
        let outcome = va.import_into(&e2, pw(PW)).unwrap();
        assert_eq!(
            outcome,
            ImportOutcome::Merged {
                added_objects: 1,
                added_segments: 1
            }
        );
        let items = dump(&va);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].0, two);
        assert_eq!(items[0].2, b"two");
        assert!(va.items().unwrap().iter().all(|i| i.id != one));
        assert!(!names(a.path()).iter().any(|n| n.starts_with(".import-")));
    }

    fn craft(header: &[u8], vk: &[u8; 32], entries: &[(u8, &str, &[u8])]) -> Vec<u8> {
        let id = *VaultHeader::parse(header).unwrap().vault_id();
        let mut out = b"ZENX".to_vec();
        out.extend_from_slice(&[0, 1, 0, 0]);
        out.extend_from_slice(&(header.len() as u32).to_be_bytes());
        out.extend_from_slice(header);
        for (ty, path, data) in entries {
            out.push(*ty);
            out.extend_from_slice(&(path.len() as u16).to_be_bytes());
            out.extend_from_slice(path.as_bytes());
            out.extend_from_slice(&(data.len() as u64).to_be_bytes());
            out.extend_from_slice(data);
        }
        out.push(TYPE_END);
        let key = export_mac_key(&VaultKey::from_bytes(*vk), &id);
        let mut mac = new_mac(&key);
        mac.update(&out);
        out.extend_from_slice(&mac.finalize().into_bytes());
        out
    }

    fn run(root: &Path, file: &Path, vk: &[u8; 32]) -> Result<ImportOutcome> {
        import(root, file, |_| Ok(VaultKey::from_bytes(*vk)), None)
    }

    #[test]
    fn tampered_and_malformed_files_are_rejected() {
        let (h, vk, _rk) = header::create(PW, KdfParams::DEFAULT).unwrap();
        let (header_bytes, vkb) = (h.to_bytes(), *vk.as_bytes());
        let obj = Entry::Object([1; 16]).rel_path();
        let seg = Entry::Segment([2; 16], 0).rel_path();
        let good = craft(&header_bytes, &vkb, &[(1, &obj, b"object bytes")]);
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("x.zenx");
        let target = tempfile::tempdir().unwrap();

        fs::write(&file, &good).unwrap();
        // Sanity: the unmodified file is accepted (and the target is reset below).
        let ok = tempfile::tempdir().unwrap();
        assert_eq!(run(ok.path(), &file, &vkb), Ok(ImportOutcome::Restored));
        assert!(ok.path().join(&obj).is_file());
        assert!(ok.path().join("vault.zev").is_file());
        assert_eq!(names(ok.path()), ["local", "objects", "vault.zev"]);

        // A correct MAC over a segment that does not open: rejected before the target is touched.
        let broken = craft(&header_bytes, &vkb, &[(2, &seg, b"segment bytes")]);
        fs::write(&file, broken).unwrap();
        assert_eq!(run(target.path(), &file, &vkb), Err(Error::JournalCorrupt));
        assert!(names(target.path()).is_empty());

        let entry_data = 12 + header_bytes.len() + 1 + 2 + obj.len() + 8;
        let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
        let flip = |at: usize| {
            let mut b = good.clone();
            b[at] ^= 1;
            b
        };
        cases.push(("entry", flip(entry_data + 3)));
        cases.push(("mac", flip(good.len() - 1)));
        cases.push(("magic", flip(0)));
        cases.push(("truncated", good[..good.len() - 1].to_vec()));
        cases.push(("truncated entry", good[..entry_data + 4].to_vec()));
        cases.push(("empty", Vec::new()));
        let mut appended = good.clone();
        appended.push(0);
        cases.push(("appended", appended));
        for (name, bytes) in cases {
            fs::write(&file, bytes).unwrap();
            assert_eq!(
                run(target.path(), &file, &vkb),
                Err(Error::ExportFormat),
                "{name}"
            );
            assert!(names(target.path()).is_empty(), "{name}");
        }

        // A flipped header byte fails during unlock (real password path).
        let mut bytes = good.clone();
        bytes[12 + 40] ^= 1;
        fs::write(&file, bytes).unwrap();
        assert!(Vault::import_from(target.path(), &file, pw(PW)).is_err());
        assert!(names(target.path()).is_empty());

        // Invalid entries with a correct MAC are caught by validation.
        let long = format!("objects/{}", "a".repeat(200));
        let upper = obj.replace("01", "0A");
        let bad: Vec<Vec<(u8, &str, &[u8])>> = vec![
            vec![(1, "../x", b"x")],
            vec![(1, "/etc/x", b"x")],
            vec![(1, "objects/zz/../../a.zeo", b"x")],
            vec![(1, &long, b"x")],
            vec![(1, "", b"x")],
            vec![(1, &upper, b"x")],
            vec![(1, "objects/02/01010101010101010101010101010101.zeo", b"x")],
            vec![(2, &obj, b"x")],
            vec![(1, &seg, b"x")],
            vec![(1, &obj, b"x"), (1, &obj, b"y")],
        ];
        for (i, entries) in bad.iter().enumerate() {
            fs::write(&file, craft(&header_bytes, &vkb, entries)).unwrap();
            assert_eq!(
                run(target.path(), &file, &vkb),
                Err(Error::ExportFormat),
                "case {i}"
            );
            assert!(names(target.path()).is_empty(), "case {i}");
        }
    }

    #[test]
    fn secrets_and_vault_identity() {
        let a = tempfile::tempdir().unwrap();
        let (va, rk) = Vault::create(a.path(), PW, KdfParams::DEFAULT).unwrap();
        va.set_duress(PW, "duress pw").unwrap();
        put(&va, b"data");
        let out = tempfile::tempdir().unwrap();
        let file = out.path().join("e.zenx");
        va.export_to(&file, |_, _| {}).unwrap();

        let c = tempfile::tempdir().unwrap();
        assert_eq!(
            Vault::import_from(c.path(), &file, pw("nope")),
            Err(Error::WrongPassword)
        );
        // Duress is just a wrong password here; nothing is shredded.
        assert_eq!(
            Vault::import_from(c.path(), &file, pw("duress pw")),
            Err(Error::WrongPassword)
        );
        assert!(names(c.path()).is_empty());
        assert_eq!(
            Vault::import_from(c.path(), &file, ImportSecret::RecoveryKey("garbage".into())),
            Err(Error::RecoveryKeyFormat)
        );

        let outcome =
            Vault::import_from(c.path(), &file, ImportSecret::RecoveryKey(rk.to_string()));
        assert_eq!(outcome, Ok(ImportOutcome::Restored));
        let vc = Vault::unlock_recovery(c.path(), &rk, 0, 0).unwrap();
        assert_eq!(dump(&vc), dump(&va));

        let x = tempfile::tempdir().unwrap();
        let (_vx, _) = Vault::create(x.path(), "other pw", KdfParams::DEFAULT).unwrap();
        let before = names(x.path());
        assert_eq!(
            Vault::import_from(x.path(), &file, pw(PW)),
            Err(Error::DifferentVault)
        );
        assert_eq!(names(x.path()), before);
    }

    fn export_of(v: &Vault, dir: &Path) -> PathBuf {
        let file = dir.join("e.zenx");
        v.export_to(&file, |_, _| {}).unwrap();
        file
    }

    #[test]
    fn restore_and_merge_disable_duress() {
        let a = tempfile::tempdir().unwrap();
        let (va, _rk) = Vault::create(a.path(), PW, KdfParams::DEFAULT).unwrap();
        va.set_duress(PW, "duress pw").unwrap();
        put(&va, b"data");
        let out = tempfile::tempdir().unwrap();
        let file = export_of(&va, out.path());

        // Restore into an empty directory.
        let b = tempfile::tempdir().unwrap();
        Vault::import_from(b.path(), &file, pw(PW)).unwrap();
        assert!(matches!(
            Vault::unlock(b.path(), "duress pw", 0, 0).unwrap(),
            UnlockResult::WrongPassword
        ));
        let vb = open(b.path(), PW);
        assert!(!vb.is_duress_enabled());
        assert_eq!(dump(&vb), dump(&va));

        // Merge via an open vault: duress was enabled there and is turned off.
        vb.set_duress(PW, "duress pw").unwrap();
        assert!(vb.is_duress_enabled());
        vb.import_into(&file, pw(PW)).unwrap();
        assert!(!vb.is_duress_enabled());
        vb.lock();
        assert!(matches!(
            Vault::unlock(b.path(), "duress pw", 0, 0).unwrap(),
            UnlockResult::WrongPassword
        ));
        assert!(!open(b.path(), PW).is_duress_enabled());

        // The source vault itself is unaffected.
        va.lock();
        assert!(matches!(
            Vault::unlock(a.path(), "duress pw", 0, 0).unwrap(),
            UnlockResult::Duress(_)
        ));
    }

    #[test]
    fn import_from_into_existing_vault_disables_duress() {
        let a = tempfile::tempdir().unwrap();
        let (va, _rk) = Vault::create(a.path(), PW, KdfParams::DEFAULT).unwrap();
        va.set_duress(PW, "duress pw").unwrap();
        let out = tempfile::tempdir().unwrap();
        let file = export_of(&va, out.path());
        va.lock();
        assert_eq!(
            Vault::import_from(a.path(), &file, pw(PW)),
            Ok(ImportOutcome::Merged {
                added_objects: 0,
                added_segments: 0
            })
        );
        assert!(matches!(
            Vault::unlock(a.path(), "duress pw", 0, 0).unwrap(),
            UnlockResult::WrongPassword
        ));
        assert!(!open(a.path(), PW).is_duress_enabled());
    }

    #[test]
    fn replace_with_a_broken_journal_keeps_the_vault() {
        let (h, vk, _rk) = header::create("backup pw", KdfParams::DEFAULT).unwrap();
        let seg = Entry::Segment([2; 16], 0).rel_path();
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("x.zenx");
        fs::write(
            &file,
            craft(&h.to_bytes(), vk.as_bytes(), &[(2, &seg, b"junk")]),
        )
        .unwrap();

        let a = tempfile::tempdir().unwrap();
        let (va, _) = Vault::create(a.path(), PW, KdfParams::DEFAULT).unwrap();
        let id = put(&va, b"keep me");
        assert_eq!(
            va.replace_from_backup(PW, &file, pw("backup pw")),
            Err(Error::JournalCorrupt)
        );
        assert_eq!(va.items().unwrap()[0].id, id);
        drop(va);
        assert_eq!(open(a.path(), PW).items().unwrap()[0].id, id);
    }

    #[test]
    fn replace_from_backup_swaps_the_vault() {
        let a = tempfile::tempdir().unwrap();
        let (va, rk) = Vault::create(a.path(), PW, KdfParams::DEFAULT).unwrap();
        va.set_duress(PW, "duress pw").unwrap();
        put(&va, b"backup item");
        let out = tempfile::tempdir().unwrap();
        let file = export_of(&va, out.path());
        let expected = dump(&va);
        va.lock();

        let b = tempfile::tempdir().unwrap();
        let (vb, _) = Vault::create(b.path(), "other pw", KdfParams::DEFAULT).unwrap();
        put(&vb, b"old item");
        vb.set_duress("other pw", "old duress").unwrap();

        assert_eq!(
            vb.replace_from_backup("wrong", &file, pw(PW)),
            Err(Error::WrongPassword)
        );
        assert_eq!(dump(&vb).len(), 1);
        vb.replace_from_backup("other pw", &file, ImportSecret::RecoveryKey(rk.to_string()))
            .unwrap();
        assert_eq!(vb.items(), Err(Error::Locked));
        assert!(!names(b.path())
            .iter()
            .any(|n| n.starts_with(STAGING_PREFIX)));

        assert!(matches!(
            Vault::unlock(b.path(), "other pw", 0, 0).unwrap(),
            UnlockResult::WrongPassword
        ));
        assert!(matches!(
            Vault::unlock(b.path(), "duress pw", 0, 0).unwrap(),
            UnlockResult::WrongPassword
        ));
        let nv = open(b.path(), PW);
        assert_eq!(dump(&nv), expected);
        assert!(!nv.is_duress_enabled());
    }

    #[test]
    fn replace_from_backup_keeps_vault_on_bad_backup() {
        let a = tempfile::tempdir().unwrap();
        let (va, _rk) = Vault::create(a.path(), PW, KdfParams::DEFAULT).unwrap();
        put(&va, b"backup item");
        let out = tempfile::tempdir().unwrap();
        let file = export_of(&va, out.path());

        let b = tempfile::tempdir().unwrap();
        let (vb, _) = Vault::create(b.path(), "other pw", KdfParams::DEFAULT).unwrap();
        put(&vb, b"old item");
        let before = dump(&vb);
        let files = names(b.path());

        // Wrong backup secret.
        assert_eq!(
            vb.replace_from_backup("other pw", &file, pw("nope")),
            Err(Error::WrongPassword)
        );
        // Corrupt content: flip a byte near the end, so only the MAC catches it.
        let mut bytes = fs::read(&file).unwrap();
        let n = bytes.len();
        bytes[n - 40] ^= 1;
        let bad = out.path().join("bad.zenx");
        fs::write(&bad, &bytes).unwrap();
        assert_eq!(
            vb.replace_from_backup("other pw", &bad, pw(PW)),
            Err(Error::ExportFormat)
        );
        // Truncated file and missing file.
        fs::write(&bad, &bytes[..n / 2]).unwrap();
        assert_eq!(
            vb.replace_from_backup("other pw", &bad, pw(PW)),
            Err(Error::ExportFormat)
        );
        assert_eq!(
            vb.replace_from_backup("other pw", &out.path().join("none"), pw(PW)),
            Err(Error::Io)
        );

        assert_eq!(dump(&vb), before);
        assert_eq!(names(b.path()), files);
        vb.lock();
        assert_eq!(dump(&open(b.path(), "other pw")), before);
    }
}

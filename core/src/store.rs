//! Filesystem layout and atomic file writes (vault-format §2).

use std::fs::{self, File};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::rng;

const OBJECT_EXT: &str = ".zeo";
const SEQ_DIGITS: usize = 20;
pub(crate) const STAGING_PREFIX: &str = ".import-";
const TMP_MARKER: &str = ".tmp-";
const TMP_RANDOM_HEX: usize = 16;

/// Vault directory on disk.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

fn io<T>(r: std::io::Result<T>) -> Result<T> {
    r.map_err(|_| Error::Io)
}

pub(crate) fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub(crate) fn parse_id(s: &str) -> Option<[u8; 16]> {
    if !is_lower_hex(s, 32) {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

pub(crate) fn hex_id(id: &[u8]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn parse_seq(name: &str) -> Option<u64> {
    let digits = name.strip_suffix(OBJECT_EXT)?;
    if digits.len() != SEQ_DIGITS || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn is_tmp_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix('.') else {
        return false;
    };
    match rest.rfind(TMP_MARKER) {
        Some(i) if i > 0 => is_lower_hex(&rest[i + TMP_MARKER.len()..], TMP_RANDOM_HEX),
        _ => false,
    }
}

/// Names of regular, non-symlink entries (`dirs == false`) or directories (`dirs == true`).
/// A missing directory yields an empty list; non-UTF-8 names are skipped.
fn entries(dir: &Path, dirs: bool) -> Result<Vec<String>> {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(Error::Io),
    };
    let mut out = Vec::new();
    for entry in rd {
        let entry = io(entry)?;
        let ft = io(entry.file_type())?;
        let wanted = if dirs { ft.is_dir() } else { ft.is_file() };
        if let (true, Ok(name)) = (wanted, entry.file_name().into_string()) {
            out.push(name);
        }
    }
    Ok(out)
}

fn sync_dir(dir: &Path) -> Result<()> {
    let f = io(File::open(dir))?;
    match f.sync_all() {
        Ok(()) => Ok(()),
        // Some platforms cannot fsync directories.
        Err(e) if matches!(e.kind(), ErrorKind::InvalidInput | ErrorKind::Unsupported) => Ok(()),
        Err(_) => Err(Error::Io),
    }
}

impl Store {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn header_path(&self) -> PathBuf {
        self.root.join("vault.zev")
    }

    pub fn object_path(&self, id: &[u8; 16]) -> PathBuf {
        let h = hex_id(id);
        self.root
            .join("objects")
            .join(&h[..2])
            .join(format!("{h}{OBJECT_EXT}"))
    }

    pub fn journal_dir(&self, device: &[u8; 16]) -> PathBuf {
        self.root.join("journal").join(hex_id(device))
    }

    pub fn segment_path(&self, device: &[u8; 16], seq: u64) -> PathBuf {
        self.journal_dir(device)
            .join(format!("{seq:0width$}{OBJECT_EXT}", width = SEQ_DIGITS))
    }

    pub fn local_dir(&self) -> PathBuf {
        self.root.join("local")
    }

    /// Writes `path` via a temporary file in the same directory, fsync and rename.
    /// On error the target is untouched and the temporary file is removed.
    pub fn write_atomic(
        &self,
        path: &Path,
        write: impl FnOnce(&mut File) -> Result<()>,
    ) -> Result<()> {
        let dir = path.parent().ok_or(Error::Io)?;
        let name = path.file_name().and_then(|n| n.to_str()).ok_or(Error::Io)?;
        io(fs::create_dir_all(dir))?;
        let rand = rng::array::<8>(&mut rng::OsRandom)?;
        let tmp = dir.join(format!(".{name}{TMP_MARKER}{}", hex_id(&rand)));

        let res = (|| {
            let mut f = io(File::options().write(true).create_new(true).open(&tmp))?;
            write(&mut f)?;
            io(f.sync_all())?;
            drop(f);
            io(fs::rename(&tmp, path))?;
            sync_dir(dir)
        })();
        if res.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        res
    }

    /// Creates a temporary file next to `path` for streaming writes; finish with `commit_tmp`.
    pub(crate) fn create_tmp(&self, path: &Path) -> Result<(File, PathBuf)> {
        let dir = path.parent().ok_or(Error::Io)?;
        let name = path.file_name().and_then(|n| n.to_str()).ok_or(Error::Io)?;
        io(fs::create_dir_all(dir))?;
        let rand = rng::array::<8>(&mut rng::OsRandom)?;
        let tmp = dir.join(format!(".{name}{TMP_MARKER}{}", hex_id(&rand)));
        let f = io(File::options().write(true).create_new(true).open(&tmp))?;
        Ok((f, tmp))
    }

    /// Syncs `file`, renames `tmp` to `path` and syncs the directory.
    /// On error the temporary file is removed.
    pub(crate) fn commit_tmp(&self, file: File, tmp: &Path, path: &Path) -> Result<()> {
        let dir = path.parent().ok_or(Error::Io)?;
        let res = (|| {
            io(file.sync_all())?;
            drop(file);
            io(fs::rename(tmp, path))?;
            sync_dir(dir)
        })();
        if res.is_err() {
            let _ = fs::remove_file(tmp);
        }
        res
    }

    /// Removes leftover temporary files; returns how many were deleted.
    pub fn cleanup_tmp(&self) -> Result<usize> {
        let mut dirs = vec![self.root.clone(), self.local_dir()];
        for sub in ["objects", "journal"] {
            let base = self.root.join(sub);
            for d in entries(&base, true)? {
                dirs.push(base.join(d));
            }
        }
        let mut removed = 0;
        for dir in dirs {
            for name in entries(&dir, false)? {
                if is_tmp_name(&name) && fs::remove_file(dir.join(&name)).is_ok() {
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }

    /// Removes leftover import staging directories (`.import-` + 16 hex digits).
    pub(crate) fn cleanup_staging(&self) -> Result<usize> {
        let mut removed = 0;
        for name in entries(&self.root, true)? {
            let is_staging = name
                .strip_prefix(STAGING_PREFIX)
                .is_some_and(|h| is_lower_hex(h, TMP_RANDOM_HEX));
            if is_staging && fs::remove_dir_all(self.root.join(&name)).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Ids of all object files with a valid name in a matching shard directory.
    pub fn list_objects(&self) -> Result<Vec<[u8; 16]>> {
        let base = self.root.join("objects");
        let mut out = Vec::new();
        for shard in entries(&base, true)? {
            if !is_lower_hex(&shard, 2) {
                continue;
            }
            for name in entries(&base.join(&shard), false)? {
                let id = name.strip_suffix(OBJECT_EXT).and_then(parse_id);
                if let Some(id) = id.filter(|id| hex_id(id)[..2] == shard) {
                    out.push(id);
                }
            }
        }
        out.sort_unstable();
        Ok(out)
    }

    pub fn delete_object(&self, id: &[u8; 16]) -> Result<()> {
        match fs::remove_file(self.object_path(id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(_) => Err(Error::Io),
        }
    }

    pub fn list_devices(&self) -> Result<Vec<[u8; 16]>> {
        let mut out: Vec<_> = entries(&self.root.join("journal"), true)?
            .iter()
            .filter_map(|n| parse_id(n))
            .collect();
        out.sort_unstable();
        Ok(out)
    }

    /// Segment numbers of a device, ascending.
    pub fn list_segments(&self, device: &[u8; 16]) -> Result<Vec<u64>> {
        let mut out: Vec<_> = entries(&self.journal_dir(device), false)?
            .iter()
            .filter_map(|n| parse_seq(n))
            .collect();
        out.sort_unstable();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::new(dir.path());
        (dir, s)
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
    fn layout_paths() {
        let (_d, s) = store();
        let id = [0xab; 16];
        let h = "ab".repeat(16);
        assert!(s.object_path(&id).ends_with(format!("objects/ab/{h}.zeo")));
        assert!(s.journal_dir(&id).ends_with(format!("journal/{h}")));
        assert!(s
            .segment_path(&id, 42)
            .ends_with(format!("journal/{h}/00000000000000000042.zeo")));
        assert!(s.local_dir().ends_with("local"));
    }

    #[test]
    fn atomic_write_leaves_no_tmp() {
        let (_d, s) = store();
        let p = s.segment_path(&[1; 16], 0);
        s.write_atomic(&p, |f| io(f.write_all(b"data"))).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"data");
        assert_eq!(names(p.parent().unwrap()), ["00000000000000000000.zeo"]);
    }

    #[test]
    fn failed_write_keeps_old_file() {
        let (_d, s) = store();
        let p = s.local_dir().join("device.id");
        s.write_atomic(&p, |f| io(f.write_all(b"old"))).unwrap();
        let err = s
            .write_atomic(&p, |f| {
                io(f.write_all(b"new"))?;
                Err(Error::Crypto)
            })
            .unwrap_err();
        assert_eq!(err, Error::Crypto);
        assert_eq!(fs::read(&p).unwrap(), b"old");
        assert_eq!(names(p.parent().unwrap()), ["device.id"]);
    }

    #[test]
    fn cleanup_removes_only_tmp_files() {
        let (_d, s) = store();
        let id = [0x0f; 16];
        let obj = s.object_path(&id);
        s.write_atomic(&obj, |f| io(f.write_all(b"x"))).unwrap();
        let tmp = format!(".{}.tmp-0123456789abcdef", "a.zeo");
        fs::write(obj.parent().unwrap().join(&tmp), b"x").unwrap();
        fs::create_dir_all(s.local_dir()).unwrap();
        fs::write(s.local_dir().join(".state.zeo.tmp-0123456789abcdef"), b"x").unwrap();
        fs::write(s.root().join(".vault.zev.tmp-0123456789abcdef"), b"x").unwrap();
        // Not temporary files: wrong suffix, upper-case hex, no leading dot.
        fs::write(s.local_dir().join(".x.tmp-short"), b"x").unwrap();
        fs::write(s.local_dir().join(".x.tmp-0123456789ABCDEF"), b"x").unwrap();
        fs::write(s.local_dir().join("x.tmp-0123456789abcdef"), b"x").unwrap();

        assert_eq!(s.cleanup_tmp().unwrap(), 3);
        assert_eq!(
            names(obj.parent().unwrap()),
            [format!("{}.zeo", "0f".repeat(16))]
        );
        assert_eq!(names(&s.local_dir()).len(), 3);
        assert!(!s.root().join(".vault.zev.tmp-0123456789abcdef").exists());
    }

    #[test]
    fn cleanup_staging_removes_only_staging_dirs() {
        let (_d, s) = store();
        let hex = "0123456789abcdef";
        for name in [format!(".import-{hex}"), format!(".import-{hex}-x")] {
            fs::create_dir_all(s.root().join(name).join("objects")).unwrap();
        }
        fs::create_dir(s.root().join(".import-ABCDEF0123456789")).unwrap();
        fs::write(s.root().join(".import-fedcba9876543210"), b"x").unwrap();
        fs::create_dir(s.root().join("objects")).unwrap();
        assert_eq!(s.cleanup_staging().unwrap(), 1);
        assert_eq!(
            names(s.root()),
            [
                ".import-0123456789abcdef-x",
                ".import-ABCDEF0123456789",
                ".import-fedcba9876543210",
                "objects"
            ]
        );
    }

    #[test]
    fn listing_ignores_junk() {
        let (_d, s) = store();
        let a = [0x01; 16];
        let b = [0x02; 16];
        for id in [a, b] {
            s.write_atomic(&s.object_path(&id), |f| io(f.write_all(b"x")))
                .unwrap();
        }
        let shard = s.object_path(&a).parent().unwrap().to_path_buf();
        let h = "01".repeat(16);
        for junk in [
            format!("{}.zeo", "0".repeat(31)),
            format!("{}.ZEO", h),
            format!("{}.zeo", h.to_uppercase()),
            format!("{h}.zeo.bak"),
            format!("{}.zeo", "02".repeat(16)), // wrong shard
            "notes.txt".into(),
        ] {
            fs::write(shard.join(junk), b"x").unwrap();
        }
        fs::create_dir_all(s.root().join("objects/zz")).unwrap();
        fs::write(s.root().join("objects/zz").join(format!("{h}.zeo")), b"x").unwrap();
        fs::create_dir(shard.join(format!("{}.zeo", "03".repeat(16)))).unwrap();
        assert_eq!(s.list_objects().unwrap(), vec![a, b]);

        let dev = [0x07; 16];
        for seq in [2u64, 0, 1] {
            s.write_atomic(&s.segment_path(&dev, seq), |f| io(f.write_all(b"x")))
                .unwrap();
        }
        let jd = s.journal_dir(&dev);
        for junk in [
            "1.zeo",
            "00000000000000000003.zeo.tmp",
            "0000000000000000000a.zeo",
            "x",
        ] {
            fs::write(jd.join(junk), b"x").unwrap();
        }
        fs::create_dir_all(s.root().join("journal/not-a-device")).unwrap();
        fs::write(s.root().join("journal").join("0".repeat(32)), b"x").unwrap();
        assert_eq!(s.list_devices().unwrap(), vec![dev]);
        assert_eq!(s.list_segments(&dev).unwrap(), vec![0, 1, 2]);
        assert!(s.list_segments(&[9; 16]).unwrap().is_empty());
    }

    #[test]
    fn delete_object_is_idempotent() {
        let (_d, s) = store();
        let id = [5; 16];
        s.write_atomic(&s.object_path(&id), |f| io(f.write_all(b"x")))
            .unwrap();
        s.delete_object(&id).unwrap();
        s.delete_object(&id).unwrap();
        assert!(s.list_objects().unwrap().is_empty());
    }
}

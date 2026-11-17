//! Records and enums crossing the FFI boundary, with conversions to the core types.

use zeroenclave_core as zc;

use crate::error::ZeError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u8,
}

impl From<zc::KdfParams> for KdfParams {
    fn from(p: zc::KdfParams) -> Self {
        Self {
            m_kib: p.m_kib,
            t: p.t,
            p: p.p,
        }
    }
}

impl From<KdfParams> for zc::KdfParams {
    fn from(p: KdfParams) -> Self {
        Self {
            m_kib: p.m_kib,
            t: p.t,
            p: p.p,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ItemKind {
    Photo,
    Video,
    Live,
}

impl From<zc::ItemKind> for ItemKind {
    fn from(k: zc::ItemKind) -> Self {
        match k {
            zc::ItemKind::Photo => Self::Photo,
            zc::ItemKind::Video => Self::Video,
            zc::ItemKind::Live => Self::Live,
        }
    }
}

impl From<ItemKind> for zc::ItemKind {
    fn from(k: ItemKind) -> Self {
        match k {
            ItemKind::Photo => Self::Photo,
            ItemKind::Video => Self::Video,
            ItemKind::Live => Self::Live,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ObjectRole {
    Original,
    ThumbSmall,
    ThumbLarge,
    PairedVideo,
}

impl From<zc::ObjectRole> for ObjectRole {
    fn from(r: zc::ObjectRole) -> Self {
        match r {
            zc::ObjectRole::Original => Self::Original,
            zc::ObjectRole::ThumbSmall => Self::ThumbSmall,
            zc::ObjectRole::ThumbLarge => Self::ThumbLarge,
            zc::ObjectRole::PairedVideo => Self::PairedVideo,
        }
    }
}

impl From<ObjectRole> for zc::ObjectRole {
    fn from(r: ObjectRole) -> Self {
        match r {
            ObjectRole::Original => Self::Original,
            ObjectRole::ThumbSmall => Self::ThumbSmall,
            ObjectRole::ThumbLarge => Self::ThumbLarge,
            ObjectRole::PairedVideo => Self::PairedVideo,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct ItemMeta {
    pub filename: Option<String>,
    /// Capture time, Unix ms.
    pub created: Option<i64>,
    /// Import time, Unix ms.
    pub imported: i64,
    pub mime: Option<String>,
    pub width: Option<u64>,
    pub height: Option<u64>,
    /// Milliseconds, videos only.
    pub duration: Option<u64>,
    pub size: Option<u64>,
}

impl From<zc::ItemMeta> for ItemMeta {
    fn from(m: zc::ItemMeta) -> Self {
        Self {
            filename: m.filename,
            created: m.created,
            imported: m.imported,
            mime: m.mime,
            width: m.width,
            height: m.height,
            duration: m.duration,
            size: m.size,
        }
    }
}

impl From<ItemMeta> for zc::ItemMeta {
    fn from(m: ItemMeta) -> Self {
        Self {
            filename: m.filename,
            created: m.created,
            imported: m.imported,
            mime: m.mime,
            width: m.width,
            height: m.height,
            duration: m.duration,
            size: m.size,
            trashed: None,
        }
    }
}

/// Value for `VaultHandle::set_meta`; the core validates it against the field.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum MetaValue {
    Null,
    Text { value: String },
    Int { value: i64 },
    Uint { value: u64 },
}

impl From<MetaValue> for zc::Value {
    fn from(v: MetaValue) -> Self {
        match v {
            MetaValue::Null => Self::Null,
            MetaValue::Text { value } => Self::Text(value),
            MetaValue::Int { value } => Self::int(value),
            MetaValue::Uint { value } => Self::Uint(value),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ObjectRef {
    pub role: ObjectRole,
    /// 32-char lowercase hex.
    pub object_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ItemSummary {
    /// 32-char lowercase hex.
    pub id: String,
    pub kind: ItemKind,
    pub meta: ItemMeta,
    pub objects: Vec<ObjectRef>,
    /// Album ids, 32-char lowercase hex.
    pub albums: Vec<String>,
    /// In an album that is not shown in All Photos; leave out of the All Photos grid.
    pub hidden_in_all: bool,
    /// Unix ms when moved to the trash; trashed items are not part of any grid or album.
    pub trashed_at: Option<u64>,
}

impl From<zc::ItemSummary> for ItemSummary {
    fn from(s: zc::ItemSummary) -> Self {
        let trashed_at = s.meta.trashed;
        Self {
            id: hex_id(&s.id.0),
            kind: s.kind.into(),
            meta: s.meta.into(),
            objects: s
                .objects
                .into_iter()
                .map(|(role, id)| ObjectRef {
                    role: role.into(),
                    object_id: hex_id(&id),
                })
                .collect(),
            albums: s.albums.iter().map(|a| hex_id(&a.0)).collect(),
            hidden_in_all: s.hidden_in_all,
            trashed_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AlbumSummary {
    /// 32-char lowercase hex.
    pub id: String,
    pub name: String,
    pub item_count: u64,
    /// Newest member, 32-char lowercase hex.
    pub cover_item: Option<String>,
    /// A view-lock code is set.
    pub locked: bool,
    /// Items of this album appear in All Photos.
    pub show_in_all: bool,
}

impl From<zc::AlbumSummary> for AlbumSummary {
    fn from(a: zc::AlbumSummary) -> Self {
        Self {
            id: hex_id(&a.id.0),
            name: a.name,
            item_count: a.item_count,
            cover_item: a.cover_item.map(|i| hex_id(&i.0)),
            locked: a.locked,
            show_in_all: a.show_in_all,
        }
    }
}

#[derive(uniffi::Enum)]
pub enum ImportSecret {
    Password { password: String },
    RecoveryKey { recovery_key: String },
}

impl From<ImportSecret> for zc::ImportSecret {
    fn from(s: ImportSecret) -> Self {
        match s {
            ImportSecret::Password { password } => Self::Password(password),
            ImportSecret::RecoveryKey { recovery_key } => Self::RecoveryKey(recovery_key),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ImportOutcome {
    Restored,
    Merged {
        added_objects: u64,
        added_segments: u64,
    },
}

impl From<zc::ImportOutcome> for ImportOutcome {
    fn from(o: zc::ImportOutcome) -> Self {
        match o {
            zc::ImportOutcome::Restored => Self::Restored,
            zc::ImportOutcome::Merged {
                added_objects,
                added_segments,
            } => Self::Merged {
                added_objects: added_objects as u64,
                added_segments: added_segments as u64,
            },
        }
    }
}

pub(crate) fn hex_id(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// Strict parser: exactly 32 lowercase hex digits.
pub(crate) fn parse_id(s: &str) -> Result<[u8; 16], ZeError> {
    let b = s.as_bytes();
    if b.len() != 32 {
        return Err(ZeError::InvalidInput);
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(ZeError::InvalidInput),
    };
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        *o = nibble(b[2 * i])? << 4 | nibble(b[2 * i + 1])?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_round_trip_and_rejects() {
        let id = [0xab; 16];
        assert_eq!(hex_id(&id), "ab".repeat(16));
        assert_eq!(parse_id(&hex_id(&id)), Ok(id));
        assert_eq!(parse_id(&"AB".repeat(16)), Err(ZeError::InvalidInput));
        assert_eq!(parse_id("ab"), Err(ZeError::InvalidInput));
        assert_eq!(parse_id(&"zz".repeat(16)), Err(ZeError::InvalidInput));
        assert_eq!(parse_id(&"é".repeat(16)), Err(ZeError::InvalidInput));
    }
}

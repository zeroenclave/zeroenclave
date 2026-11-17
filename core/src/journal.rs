//! Per-device append-only journal and the state folded from it (vault-format §5).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::cbor::{self, Value};
use crate::error::{Error, Result};
use crate::keys::VaultKey;
use crate::object::{open_object, write_object_with, ObjectKind};
use crate::rng::{self, OsRandom, RandomSource};
use crate::store::Store;

const PAYLOAD_VERSION: u64 = 1;

pub type DeviceId = [u8; 16];

/// All verified segments per device, ordered by `seq`.
pub type Chains = BTreeMap<DeviceId, Vec<Segment>>;

macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub [u8; 16]);
    };
}

id_type!(
    /// Random item identifier.
    ItemId
);
id_type!(
    /// Random album identifier.
    AlbumId
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    Photo,
    Video,
    Live,
}

impl ItemKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Photo => "photo",
            Self::Video => "video",
            Self::Live => "live",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "photo" => Some(Self::Photo),
            "video" => Some(Self::Video),
            "live" => Some(Self::Live),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
    /// Unix ms when moved to the trash; `None` = not trashed.
    pub trashed: Option<u64>,
}

/// A journal operation; every variant carries its Lamport timestamp `t`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    ItemAdd {
        t: u64,
        item: ItemId,
        kind: ItemKind,
        /// Role (`original`, `thumb_small`, ...) to object id.
        objects: BTreeMap<String, [u8; 16]>,
        meta: ItemMeta,
    },
    ItemSet {
        t: u64,
        item: ItemId,
        field: String,
        value: Value,
    },
    ItemDel {
        t: u64,
        item: ItemId,
    },
    AlbumAdd {
        t: u64,
        album: AlbumId,
        name: String,
    },
    AlbumSet {
        t: u64,
        album: AlbumId,
        field: String,
        value: Value,
    },
    AlbumDel {
        t: u64,
        album: AlbumId,
    },
    AlbumPut {
        t: u64,
        album: AlbumId,
        item: ItemId,
    },
    AlbumPop {
        t: u64,
        album: AlbumId,
        item: ItemId,
    },
    /// Op from a newer writer; kept verbatim, ignored when folding.
    Unknown(Value),
}

fn id16(v: &Value) -> Result<[u8; 16]> {
    v.as_bytes()
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::Cbor)
}

fn field<'a>(v: &'a Value, key: &str) -> Result<&'a Value> {
    v.get(key).ok_or(Error::Cbor)
}

fn opt<T>(v: &Value, key: &str, f: impl Fn(&Value) -> Option<T>) -> Result<Option<T>> {
    v.get(key).map(|x| f(x).ok_or(Error::Cbor)).transpose()
}

fn text(v: &Value) -> Option<String> {
    v.as_str().map(str::to_owned)
}

impl ItemMeta {
    fn to_value(&self) -> Value {
        let mut m = vec![("imported", Value::int(self.imported))];
        if let Some(s) = &self.filename {
            m.push(("filename", Value::text(s)));
        }
        if let Some(n) = self.created {
            m.push(("created", Value::int(n)));
        }
        if let Some(s) = &self.mime {
            m.push(("mime", Value::text(s)));
        }
        for (k, v) in [
            ("width", self.width),
            ("height", self.height),
            ("duration", self.duration),
            ("size", self.size),
            ("trashed", self.trashed),
        ] {
            if let Some(n) = v {
                m.push((k, Value::Uint(n)));
            }
        }
        Value::Map(m.into_iter().map(|(k, v)| (Value::text(k), v)).collect())
    }

    /// Unknown fields are ignored.
    fn from_value(v: &Value) -> Result<Self> {
        v.as_map().ok_or(Error::Cbor)?;
        Ok(Self {
            filename: opt(v, "filename", text)?,
            created: opt(v, "created", Value::as_i64)?,
            imported: field(v, "imported")?.as_i64().ok_or(Error::Cbor)?,
            mime: opt(v, "mime", text)?,
            width: opt(v, "width", Value::as_u64)?,
            height: opt(v, "height", Value::as_u64)?,
            duration: opt(v, "duration", Value::as_u64)?,
            size: opt(v, "size", Value::as_u64)?,
            trashed: opt(v, "trashed", Value::as_u64)?,
        })
    }
}

fn objects_to_value(o: &BTreeMap<String, [u8; 16]>) -> Value {
    Value::Map(
        o.iter()
            .map(|(k, v)| (Value::text(k), Value::bytes(v)))
            .collect(),
    )
}

fn objects_from_value(v: &Value) -> Result<BTreeMap<String, [u8; 16]>> {
    v.as_map()
        .ok_or(Error::Cbor)?
        .iter()
        .map(|(k, v)| Ok((k.as_str().ok_or(Error::Cbor)?.to_owned(), id16(v)?)))
        .collect()
}

impl Op {
    /// Lamport timestamp, if present.
    pub fn t(&self) -> Option<u64> {
        match self {
            Self::ItemAdd { t, .. }
            | Self::ItemSet { t, .. }
            | Self::ItemDel { t, .. }
            | Self::AlbumAdd { t, .. }
            | Self::AlbumSet { t, .. }
            | Self::AlbumDel { t, .. }
            | Self::AlbumPut { t, .. }
            | Self::AlbumPop { t, .. } => Some(*t),
            Self::Unknown(v) => v.get("t").and_then(Value::as_u64),
        }
    }

    fn to_value(&self) -> Value {
        let id = |i: &ItemId| Value::bytes(&i.0);
        let al = |a: &AlbumId| Value::bytes(&a.0);
        match self {
            Self::ItemAdd {
                t,
                item,
                kind,
                objects,
                meta,
            } => Value::map([
                ("op", Value::text("item.add")),
                ("t", Value::Uint(*t)),
                ("item", id(item)),
                ("kind", Value::text(kind.as_str())),
                ("objects", objects_to_value(objects)),
                ("meta", meta.to_value()),
            ]),
            Self::ItemSet {
                t,
                item,
                field,
                value,
            } => Value::map([
                ("op", Value::text("item.set")),
                ("t", Value::Uint(*t)),
                ("item", id(item)),
                ("field", Value::text(field)),
                ("value", value.clone()),
            ]),
            Self::ItemDel { t, item } => Value::map([
                ("op", Value::text("item.del")),
                ("t", Value::Uint(*t)),
                ("item", id(item)),
            ]),
            Self::AlbumAdd { t, album, name } => Value::map([
                ("op", Value::text("album.add")),
                ("t", Value::Uint(*t)),
                ("album", al(album)),
                ("name", Value::text(name)),
            ]),
            Self::AlbumSet {
                t,
                album,
                field,
                value,
            } => Value::map([
                ("op", Value::text("album.set")),
                ("t", Value::Uint(*t)),
                ("album", al(album)),
                ("field", Value::text(field)),
                ("value", value.clone()),
            ]),
            Self::AlbumDel { t, album } => Value::map([
                ("op", Value::text("album.del")),
                ("t", Value::Uint(*t)),
                ("album", al(album)),
            ]),
            Self::AlbumPut { t, album, item } => Value::map([
                ("op", Value::text("album.put")),
                ("t", Value::Uint(*t)),
                ("album", al(album)),
                ("item", id(item)),
            ]),
            Self::AlbumPop { t, album, item } => Value::map([
                ("op", Value::text("album.pop")),
                ("t", Value::Uint(*t)),
                ("album", al(album)),
                ("item", id(item)),
            ]),
            Self::Unknown(v) => v.clone(),
        }
    }

    /// Unknown op names (and non-map items) become `Op::Unknown`; a known op
    /// with missing or mistyped fields is an error.
    fn from_value(v: &Value) -> Result<Self> {
        let Some(name) = v.get("op").and_then(Value::as_str) else {
            return Ok(Self::Unknown(v.clone()));
        };
        if !matches!(
            name,
            "item.add"
                | "item.set"
                | "item.del"
                | "album.add"
                | "album.set"
                | "album.del"
                | "album.put"
                | "album.pop"
        ) {
            return Ok(Self::Unknown(v.clone()));
        }
        let t = field(v, "t")?.as_u64().ok_or(Error::Cbor)?;
        let item = || Ok::<_, Error>(ItemId(id16(field(v, "item")?)?));
        let album = || Ok::<_, Error>(AlbumId(id16(field(v, "album")?)?));
        let fname = || Ok::<_, Error>(field(v, "field")?.as_str().ok_or(Error::Cbor)?.to_owned());
        let value = || Ok::<_, Error>(field(v, "value")?.clone());
        Ok(match name {
            "item.add" => {
                let kind = field(v, "kind")?
                    .as_str()
                    .and_then(ItemKind::parse)
                    .ok_or(Error::Cbor)?;
                Self::ItemAdd {
                    t,
                    item: item()?,
                    kind,
                    objects: objects_from_value(field(v, "objects")?)?,
                    meta: ItemMeta::from_value(field(v, "meta")?)?,
                }
            }
            "item.set" => Self::ItemSet {
                t,
                item: item()?,
                field: fname()?,
                value: value()?,
            },
            "item.del" => Self::ItemDel { t, item: item()? },
            "album.add" => Self::AlbumAdd {
                t,
                album: album()?,
                name: field(v, "name")?.as_str().ok_or(Error::Cbor)?.to_owned(),
            },
            "album.set" => Self::AlbumSet {
                t,
                album: album()?,
                field: fname()?,
                value: value()?,
            },
            "album.del" => Self::AlbumDel { t, album: album()? },
            "album.put" => Self::AlbumPut {
                t,
                album: album()?,
                item: item()?,
            },
            _ => Self::AlbumPop {
                t,
                album: album()?,
                item: item()?,
            },
        })
    }
}

/// One committed journal segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub device: DeviceId,
    pub seq: u64,
    /// SHA-256 of the previous segment file; zeros for `seq` 0.
    pub prev: [u8; 32],
    pub ops: Vec<Op>,
    /// SHA-256 of this segment's file. Set when read or written, not part of the payload.
    pub hash: [u8; 32],
}

impl Segment {
    /// Canonical CBOR payload (vault-format §5.1).
    pub fn encode(&self) -> Result<Vec<u8>> {
        cbor::encode(&Value::map([
            ("v", Value::Uint(PAYLOAD_VERSION)),
            ("device", Value::bytes(&self.device)),
            ("seq", Value::Uint(self.seq)),
            ("prev", Value::bytes(&self.prev)),
            (
                "ops",
                Value::Array(self.ops.iter().map(Op::to_value).collect()),
            ),
        ]))
    }

    /// Strict decode; the `hash` field is left zero. Unknown top-level keys are ignored.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let v = cbor::decode(data)?;
        if field(&v, "v")?.as_u64() != Some(PAYLOAD_VERSION) {
            return Err(Error::Cbor);
        }
        let ops = field(&v, "ops")?
            .as_array()
            .ok_or(Error::Cbor)?
            .iter()
            .map(Op::from_value)
            .collect::<Result<Vec<_>>>()?;
        if ops.is_empty() {
            return Err(Error::Cbor);
        }
        Ok(Self {
            device: id16(field(&v, "device")?)?,
            seq: field(&v, "seq")?.as_u64().ok_or(Error::Cbor)?,
            prev: field(&v, "prev")?
                .as_bytes()
                .and_then(|b| b.try_into().ok())
                .ok_or(Error::Cbor)?,
            ops,
            hash: [0; 32],
        })
    }
}

/// Encrypts and atomically writes a new segment; returns its file hash (the next `prev`).
#[allow(clippy::too_many_arguments)]
pub fn write_segment(
    store: &Store,
    vk: &VaultKey,
    vault_id: [u8; 16],
    device: DeviceId,
    seq: u64,
    prev: [u8; 32],
    ops: Vec<Op>,
) -> Result<[u8; 32]> {
    write_segment_with(store, vk, vault_id, device, seq, prev, ops, &mut OsRandom)
}

/// Random draw order: object_id, then as `write_object_with`.
#[allow(clippy::too_many_arguments)]
pub fn write_segment_with(
    store: &Store,
    vk: &VaultKey,
    vault_id: [u8; 16],
    device: DeviceId,
    seq: u64,
    prev: [u8; 32],
    ops: Vec<Op>,
    rng: &mut impl RandomSource,
) -> Result<[u8; 32]> {
    if ops.is_empty() {
        return Err(Error::JournalCorrupt);
    }
    let path = store.segment_path(&device, seq);
    // Segments are immutable.
    if path.exists() {
        return Err(Error::Exists);
    }
    let payload = Segment {
        device,
        seq,
        prev,
        ops,
        hash: [0; 32],
    }
    .encode()?;
    let object_id = rng::array::<16>(rng)?;
    let mut w = write_object_with(
        Vec::new(),
        vk,
        vault_id,
        object_id,
        ObjectKind::Journal,
        rng,
    )?;
    w.write_all(&payload)?;
    let file = w.finish()?;
    store.write_atomic(&path, |f| {
        std::io::Write::write_all(f, &file).map_err(|_| Error::Io)
    })?;
    Ok(Sha256::digest(&file).into())
}

/// Reads one segment file and checks that its payload matches the path.
fn read_segment(
    store: &Store,
    vk: &VaultKey,
    vault_id: [u8; 16],
    device: &DeviceId,
    seq: u64,
) -> Result<Segment> {
    let file = std::fs::read(store.segment_path(device, seq)).map_err(|_| Error::Io)?;
    let corrupt = |_| Error::JournalCorrupt;
    let mut r = open_object(Cursor::new(&file[..]), vk, vault_id, None).map_err(corrupt)?;
    if r.kind() != ObjectKind::Journal {
        return Err(Error::JournalCorrupt);
    }
    let mut seg = Segment::decode(&r.read_all().map_err(corrupt)?).map_err(corrupt)?;
    if seg.device != *device || seg.seq != seq {
        return Err(Error::JournalCorrupt);
    }
    seg.hash = Sha256::digest(&file).into();
    Ok(seg)
}

/// Reads and verifies a device's whole chain: contiguous `seq` from 0, payload
/// matching the path, and `prev` equal to the hash of the previous file.
pub fn read_device_chain(
    store: &Store,
    vk: &VaultKey,
    vault_id: [u8; 16],
    device: DeviceId,
) -> Result<Vec<Segment>> {
    let mut out: Vec<Segment> = Vec::new();
    for (i, seq) in store.list_segments(&device)?.into_iter().enumerate() {
        if seq != i as u64 {
            return Err(Error::JournalCorrupt);
        }
        let seg = read_segment(store, vk, vault_id, &device, seq)?;
        let want = out.last().map_or([0; 32], |p| p.hash);
        if seg.prev != want {
            return Err(Error::JournalCorrupt);
        }
        out.push(seg);
    }
    Ok(out)
}

/// Reads the verified chains of all devices.
pub fn read_all_chains(store: &Store, vk: &VaultKey, vault_id: [u8; 16]) -> Result<Chains> {
    let mut out = Chains::new();
    for device in store.list_devices()? {
        let chain = read_device_chain(store, vk, vault_id, device)?;
        if !chain.is_empty() {
            out.insert(device, chain);
        }
    }
    Ok(out)
}

/// A live item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub id: ItemId,
    pub kind: ItemKind,
    pub objects: BTreeMap<String, [u8; 16]>,
    pub meta: ItemMeta,
}

/// Time an item stays in the trash before it is deleted permanently (vault-format §5.4).
pub const TRASH_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// Longest album name in characters, after trimming.
pub const ALBUM_NAME_MAX: usize = 100;

/// Trims and NFC-normalizes an album name; `None` if empty or too long.
pub fn clean_album_name(name: &str) -> Option<String> {
    let n: String = name.trim().nfc().collect();
    let len = n.chars().count();
    (1..=ALBUM_NAME_MAX).contains(&len).then_some(n)
}

/// A live album; membership is kept in `State`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Album {
    pub id: AlbumId,
    pub name: String,
    /// Explicit "show in All Photos" choice; `None` follows the lock state.
    pub show_in_all: Option<bool>,
    /// `salt || digest` of the view-lock code, see `kdf::album_pin_digest`.
    pub pin: Option<Vec<u8>>,
}

/// Length of a stored album pin: 16-byte salt plus 32-byte digest.
pub const ALBUM_PIN_LEN: usize = 48;

impl Album {
    pub fn locked(&self) -> bool {
        self.pin.is_some()
    }

    /// Open albums show their items in All Photos by default, locked ones do not.
    pub fn shows_in_all(&self) -> bool {
        self.show_in_all.unwrap_or(self.pin.is_none())
    }
}

/// Index folded from the journal (vault-format §5.3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    items: BTreeMap<ItemId, Item>,
    tombstones: BTreeSet<ItemId>,
    albums: BTreeMap<AlbumId, Album>,
    album_tombstones: BTreeSet<AlbumId>,
    /// Current members per live album (latest put/pop is a put).
    members: BTreeMap<AlbumId, BTreeSet<ItemId>>,
    max_t: u64,
}

/// Next Lamport timestamp: highest seen plus one.
pub fn next_t(state: &State) -> u64 {
    state.max_t.saturating_add(1)
}

impl State {
    pub fn new() -> Self {
        Self::default()
    }

    /// Folds all ops of all segments, ordered by `(t, device_id)`; ops with equal
    /// keys keep their journal order.
    pub fn fold<'a>(segments: impl IntoIterator<Item = &'a Segment>) -> Self {
        let mut all: Vec<(u64, DeviceId, u64, usize, &Op)> = segments
            .into_iter()
            .flat_map(|s| {
                s.ops
                    .iter()
                    .enumerate()
                    .map(move |(i, op)| (op.t().unwrap_or(0), s.device, s.seq, i, op))
            })
            .collect();
        all.sort_by_key(|&(t, dev, seq, i, _)| (t, dev, seq, i));
        let mut state = Self::new();
        for (.., op) in all {
            state.apply(op);
        }
        state
    }

    /// Applies one op; callers must feed ops in `(t, device_id)` order.
    pub fn apply(&mut self, op: &Op) {
        self.max_t = self.max_t.max(op.t().unwrap_or(0));
        match op {
            Op::ItemAdd {
                item,
                kind,
                objects,
                meta,
                ..
            } => {
                if !self.tombstones.contains(item) {
                    self.items.entry(*item).or_insert_with(|| Item {
                        id: *item,
                        kind: *kind,
                        objects: objects.clone(),
                        meta: meta.clone(),
                    });
                }
            }
            Op::ItemSet {
                item, field, value, ..
            } => {
                if let Some(it) = self.items.get_mut(item) {
                    set_field(&mut it.meta, field, value);
                }
            }
            Op::ItemDel { item, .. } => {
                self.items.remove(item);
                self.tombstones.insert(*item);
                for m in self.members.values_mut() {
                    m.remove(item);
                }
            }
            Op::AlbumAdd { album, name, .. } => {
                if let Some(name) = clean_album_name(name) {
                    if !self.album_tombstones.contains(album) && !self.albums.contains_key(album) {
                        let id = *album;
                        self.albums.insert(
                            id,
                            Album {
                                id,
                                name,
                                show_in_all: None,
                                pin: None,
                            },
                        );
                        self.members.insert(id, BTreeSet::new());
                    }
                }
            }
            Op::AlbumSet {
                album,
                field,
                value,
                ..
            } => {
                if let Some(a) = self.albums.get_mut(album) {
                    // Unknown fields and wrong types are ignored.
                    match (field.as_str(), value) {
                        ("name", v) => {
                            if let Some(name) = v.as_str().and_then(clean_album_name) {
                                a.name = name;
                            }
                        }
                        ("show_in_all", Value::Bool(b)) => a.show_in_all = Some(*b),
                        ("show_in_all", Value::Null) => a.show_in_all = None,
                        ("pin", Value::Null) => a.pin = None,
                        ("pin", Value::Bytes(b)) if b.len() == ALBUM_PIN_LEN => {
                            a.pin = Some(b.clone());
                        }
                        _ => {}
                    }
                }
            }
            Op::AlbumDel { album, .. } => {
                self.albums.remove(album);
                self.members.remove(album);
                self.album_tombstones.insert(*album);
            }
            Op::AlbumPut { album, item, .. } => {
                if self.items.contains_key(item) {
                    if let Some(m) = self.members.get_mut(album) {
                        m.insert(*item);
                    }
                }
            }
            Op::AlbumPop { album, item, .. } => {
                if let Some(m) = self.members.get_mut(album) {
                    m.remove(item);
                }
            }
            // Unknown ops do not change the index.
            Op::Unknown(_) => {}
        }
    }

    /// Live albums, ordered by id.
    pub fn albums(&self) -> impl Iterator<Item = &Album> {
        self.albums.values()
    }

    pub fn album(&self, id: &AlbumId) -> Option<&Album> {
        self.albums.get(id)
    }

    /// Live members of a live album, ordered by id.
    pub fn album_members(&self, id: &AlbumId) -> Option<&BTreeSet<ItemId>> {
        self.members.get(id)
    }

    /// True if the item is in at least one live album that is not shown in All Photos.
    pub fn is_hidden_in_all(&self, item: &ItemId) -> bool {
        self.albums
            .values()
            .any(|a| !a.shows_in_all() && self.members.get(&a.id).is_some_and(|m| m.contains(item)))
    }

    /// Live items, ordered by id.
    pub fn items(&self) -> impl Iterator<Item = &Item> {
        self.items.values()
    }

    pub fn item(&self, id: &ItemId) -> Option<&Item> {
        self.items.get(id)
    }

    /// True if the item is live and in the trash.
    pub fn is_trashed(&self, id: &ItemId) -> bool {
        self.items
            .get(id)
            .is_some_and(|it| it.meta.trashed.is_some())
    }

    pub fn is_deleted(&self, id: &ItemId) -> bool {
        self.tombstones.contains(id)
    }

    /// Highest Lamport timestamp seen.
    pub fn max_t(&self) -> u64 {
        self.max_t
    }

    pub(crate) fn to_value(&self) -> Value {
        let items = self
            .items
            .values()
            .map(|it| {
                Value::map([
                    ("item", Value::bytes(&it.id.0)),
                    ("kind", Value::text(it.kind.as_str())),
                    ("objects", objects_to_value(&it.objects)),
                    ("meta", it.meta.to_value()),
                ])
            })
            .collect();
        let dead = self.tombstones.iter().map(|i| Value::bytes(&i.0)).collect();
        let albums = self
            .albums
            .values()
            .map(|a| {
                let items = self.members.get(&a.id).into_iter().flatten();
                let mut m = vec![
                    (Value::text("album"), Value::bytes(&a.id.0)),
                    (Value::text("name"), Value::text(&a.name)),
                    (
                        Value::text("items"),
                        Value::Array(items.map(|i| Value::bytes(&i.0)).collect()),
                    ),
                ];
                if let Some(b) = a.show_in_all {
                    m.push((Value::text("show_in_all"), Value::Bool(b)));
                }
                if let Some(p) = &a.pin {
                    m.push((Value::text("pin"), Value::bytes(p)));
                }
                Value::Map(m)
            })
            .collect();
        let adead = self
            .album_tombstones
            .iter()
            .map(|i| Value::bytes(&i.0))
            .collect();
        Value::map([
            ("items", Value::Array(items)),
            ("dead", Value::Array(dead)),
            ("albums", Value::Array(albums)),
            ("adead", Value::Array(adead)),
            ("t", Value::Uint(self.max_t)),
        ])
    }

    pub(crate) fn from_value(v: &Value) -> Result<Self> {
        let mut s = Self {
            max_t: field(v, "t")?.as_u64().ok_or(Error::Cbor)?,
            ..Self::default()
        };
        for it in field(v, "items")?.as_array().ok_or(Error::Cbor)? {
            let id = ItemId(id16(field(it, "item")?)?);
            let item = Item {
                id,
                kind: field(it, "kind")?
                    .as_str()
                    .and_then(ItemKind::parse)
                    .ok_or(Error::Cbor)?,
                objects: objects_from_value(field(it, "objects")?)?,
                meta: ItemMeta::from_value(field(it, "meta")?)?,
            };
            if s.items.insert(id, item).is_some() {
                return Err(Error::Cbor);
            }
        }
        for d in field(v, "dead")?.as_array().ok_or(Error::Cbor)? {
            let id = ItemId(id16(d)?);
            if s.items.contains_key(&id) || !s.tombstones.insert(id) {
                return Err(Error::Cbor);
            }
        }
        // Caches written before albums existed lack these keys.
        if let Some(albums) = v.get("albums") {
            for a in albums.as_array().ok_or(Error::Cbor)? {
                let id = AlbumId(id16(field(a, "album")?)?);
                let name = field(a, "name")?.as_str().ok_or(Error::Cbor)?.to_owned();
                let mut set = BTreeSet::new();
                for i in field(a, "items")?.as_array().ok_or(Error::Cbor)? {
                    let item = ItemId(id16(i)?);
                    if !s.items.contains_key(&item) || !set.insert(item) {
                        return Err(Error::Cbor);
                    }
                }
                let show_in_all = match a.get("show_in_all") {
                    None => None,
                    Some(Value::Bool(b)) => Some(*b),
                    Some(_) => return Err(Error::Cbor),
                };
                let pin = match a.get("pin") {
                    None => None,
                    Some(Value::Bytes(b)) if b.len() == ALBUM_PIN_LEN => Some(b.clone()),
                    Some(_) => return Err(Error::Cbor),
                };
                let album = Album {
                    id,
                    name,
                    show_in_all,
                    pin,
                };
                if s.albums.insert(id, album).is_some() {
                    return Err(Error::Cbor);
                }
                s.members.insert(id, set);
            }
        }
        if let Some(dead) = v.get("adead") {
            for d in dead.as_array().ok_or(Error::Cbor)? {
                let id = AlbumId(id16(d)?);
                if s.albums.contains_key(&id) || !s.album_tombstones.insert(id) {
                    return Err(Error::Cbor);
                }
            }
        }
        Ok(s)
    }
}

/// Last-writer-wins update of one meta field; unknown fields and wrong types are ignored.
fn set_field(meta: &mut ItemMeta, name: &str, v: &Value) {
    fn opt_text(v: &Value) -> Option<Option<String>> {
        match v {
            Value::Null => Some(None),
            _ => v.as_str().map(|s| Some(s.to_owned())),
        }
    }
    fn opt_uint(v: &Value) -> Option<Option<u64>> {
        match v {
            Value::Null => Some(None),
            _ => v.as_u64().map(Some),
        }
    }
    match name {
        "filename" => {
            if let Some(x) = opt_text(v) {
                meta.filename = x;
            }
        }
        "mime" => {
            if let Some(x) = opt_text(v) {
                meta.mime = x;
            }
        }
        "created" => match v {
            Value::Null => meta.created = None,
            _ => {
                if let Some(n) = v.as_i64() {
                    meta.created = Some(n);
                }
            }
        },
        "imported" => {
            if let Some(n) = v.as_i64() {
                meta.imported = n;
            }
        }
        "width" => {
            if let Some(x) = opt_uint(v) {
                meta.width = x;
            }
        }
        "height" => {
            if let Some(x) = opt_uint(v) {
                meta.height = x;
            }
        }
        "duration" => {
            if let Some(x) = opt_uint(v) {
                meta.duration = x;
            }
        }
        "size" => {
            if let Some(x) = opt_uint(v) {
                meta.size = x;
            }
        }
        "trashed" => {
            if let Some(x) = opt_uint(v) {
                meta.trashed = x;
            }
        }
        _ => {}
    }
}

/// Objects referenced by live items (vault-format §5.4).
pub fn referenced_objects(state: &State) -> BTreeSet<[u8; 16]> {
    state
        .items()
        .flat_map(|it| it.objects.values().copied())
        .collect()
}

/// Deletes object files that no live item references and whose mtime is older
/// than `older_than`. Files with unreadable timestamps are kept. Returns the count.
pub fn sweep(store: &Store, state: &State, older_than: std::time::Duration) -> Result<usize> {
    let keep = referenced_objects(state);
    let now = std::time::SystemTime::now();
    let mut removed = 0;
    for id in store.list_objects()? {
        if keep.contains(&id) {
            continue;
        }
        let age = std::fs::metadata(store.object_path(&id))
            .and_then(|m| m.modified())
            .ok()
            .and_then(|m| now.duration_since(m).ok());
        if age.is_some_and(|a| a >= older_than) {
            store.delete_object(&id)?;
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(test)]
pub(crate) mod test_util {
    use super::*;

    pub const VID: [u8; 16] = [0x11; 16];

    /// Deterministic non-cryptographic source for tests.
    pub struct Counter(pub u8);

    impl RandomSource for Counter {
        fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
            for b in buf {
                self.0 = self.0.wrapping_add(1);
                *b = self.0;
            }
            Ok(())
        }
    }

    pub fn vk() -> VaultKey {
        VaultKey::from_bytes([0x42; 32])
    }

    pub fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::new(dir.path());
        (dir, s)
    }

    pub fn meta(imported: i64) -> ItemMeta {
        ItemMeta {
            imported,
            ..ItemMeta::default()
        }
    }

    pub fn add(t: u64, item: u8, obj: u8) -> Op {
        Op::ItemAdd {
            t,
            item: ItemId([item; 16]),
            kind: ItemKind::Photo,
            objects: BTreeMap::from([("original".to_owned(), [obj; 16])]),
            meta: meta(1000),
        }
    }

    pub fn set(t: u64, item: u8, field: &str, value: Value) -> Op {
        Op::ItemSet {
            t,
            item: ItemId([item; 16]),
            field: field.to_owned(),
            value,
        }
    }

    pub fn del(t: u64, item: u8) -> Op {
        Op::ItemDel {
            t,
            item: ItemId([item; 16]),
        }
    }

    pub fn seg(device: u8, seq: u64, ops: Vec<Op>) -> Segment {
        Segment {
            device: [device; 16],
            seq,
            prev: [0; 32],
            ops,
            hash: [0; 32],
        }
    }

    /// Writes a valid chain of `n` single-op segments for `device`.
    pub fn write_chain(store: &Store, device: u8, n: u64) {
        let mut prev = [0u8; 32];
        for seq in 0..n {
            prev = write_segment_with(
                store,
                &vk(),
                VID,
                [device; 16],
                seq,
                prev,
                vec![add(seq + 1, device.wrapping_add(seq as u8 * 16), 1)],
                &mut Counter(seq as u8),
            )
            .unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_util::*;
    use super::*;
    use std::fs;

    fn chain(store: &Store, device: u8) -> Result<Vec<Segment>> {
        read_device_chain(store, &vk(), VID, [device; 16])
    }

    #[test]
    fn segment_round_trip_and_canonical_bytes() {
        let mut m = meta(5);
        m.filename = Some("a.heic".into());
        m.created = Some(-7);
        m.width = Some(4032);
        let s = Segment {
            device: [1; 16],
            seq: 3,
            prev: [9; 32],
            ops: vec![
                Op::ItemAdd {
                    t: 1,
                    item: ItemId([2; 16]),
                    kind: ItemKind::Live,
                    objects: BTreeMap::from([
                        ("paired_video".to_owned(), [4; 16]),
                        ("original".to_owned(), [3; 16]),
                    ]),
                    meta: m,
                },
                set(2, 2, "mime", Value::text("image/heic")),
                del(3, 2),
                Op::AlbumPut {
                    t: 4,
                    album: AlbumId([5; 16]),
                    item: ItemId([2; 16]),
                },
            ],
            hash: [0; 32],
        };
        let bytes = s.encode().unwrap();
        assert_eq!(Segment::decode(&bytes).unwrap(), s);
        assert_eq!(Segment::decode(&bytes).unwrap().encode().unwrap(), bytes);
        // Top-level key order: shorter keys first, then bytewise.
        assert_eq!(&bytes[..4], &[0xa5, 0x61, b'v', 0x01]);
        assert!(bytes.windows(4).any(|w| w == b"prev"));
    }

    #[test]
    fn decode_rejects_non_canonical_and_invalid() {
        let good = seg(1, 0, vec![del(1, 1)]).encode().unwrap();
        // Indefinite-length top-level map.
        let mut indef = vec![0xbf];
        indef.extend_from_slice(&good[1..]);
        indef.push(0xff);
        assert_eq!(Segment::decode(&indef), Err(Error::Cbor));
        // Duplicate key "v".
        let mut dup = vec![0xa6];
        dup.extend_from_slice(&good[1..]);
        dup.extend_from_slice(&[0x61, b'v', 0x01]);
        assert_eq!(Segment::decode(&dup), Err(Error::Cbor));
        // Non-shortest integer for v.
        let mut padded = good.clone();
        padded.splice(3..4, [0x18, 0x01]);
        assert_eq!(Segment::decode(&padded), Err(Error::Cbor));
        // Empty ops, wrong version.
        assert!(Segment::decode(&seg(1, 0, vec![]).encode().unwrap()).is_err());
        let v2 = cbor::encode(&Value::map([
            ("v", Value::Uint(2)),
            ("device", Value::bytes(&[1; 16])),
            ("seq", Value::Uint(0)),
            ("prev", Value::bytes(&[0; 32])),
            ("ops", Value::Array(vec![Value::Null])),
        ]))
        .unwrap();
        assert_eq!(Segment::decode(&v2), Err(Error::Cbor));
    }

    #[test]
    fn unknown_ops_and_fields_are_kept_and_ignored() {
        let future = Value::map([
            ("op", Value::text("item.rotate")),
            ("t", Value::Uint(9)),
            ("deg", Value::Uint(90)),
        ]);
        // Decoded maps come back in canonical key order.
        let future = cbor::decode(&cbor::encode(&future).unwrap()).unwrap();
        let payload = cbor::encode(&Value::map([
            ("v", Value::Uint(1)),
            ("device", Value::bytes(&[1; 16])),
            ("seq", Value::Uint(0)),
            ("prev", Value::bytes(&[0; 32])),
            ("extra", Value::Uint(1)),
            (
                "ops",
                Value::Array(vec![
                    Op::ItemAdd {
                        t: 1,
                        item: ItemId([7; 16]),
                        kind: ItemKind::Photo,
                        objects: BTreeMap::new(),
                        meta: meta(1),
                    }
                    .to_value(),
                    future.clone(),
                ]),
            ),
        ]))
        .unwrap();
        let s = Segment::decode(&payload).unwrap();
        assert_eq!(s.ops[1], Op::Unknown(future));
        assert_eq!(s.ops[1].t(), Some(9));
        let st = State::fold([&s]);
        assert_eq!(st.items().count(), 1);
        assert_eq!(st.max_t(), 9);
        assert_eq!(next_t(&st), 10);
    }

    #[test]
    fn chain_round_trip() {
        let (_d, s) = store();
        write_chain(&s, 1, 3);
        let c = chain(&s, 1).unwrap();
        assert_eq!(c.len(), 3);
        assert_eq!(c[0].prev, [0; 32]);
        assert_eq!(c[1].prev, c[0].hash);
        assert_eq!(c[2].prev, c[1].hash);
        assert!(chain(&s, 2).unwrap().is_empty());
        assert_eq!(read_all_chains(&s, &vk(), VID).unwrap().len(), 1);
    }

    #[test]
    fn write_segment_refuses_overwrite_and_empty() {
        let (_d, s) = store();
        write_chain(&s, 1, 1);
        let r = write_segment(&s, &vk(), VID, [1; 16], 0, [0; 32], vec![del(1, 1)]);
        assert_eq!(r, Err(Error::Exists));
        let r = write_segment(&s, &vk(), VID, [1; 16], 1, [0; 32], vec![]);
        assert_eq!(r, Err(Error::JournalCorrupt));
    }

    #[test]
    fn chain_gap_is_corrupt() {
        let (_d, s) = store();
        write_chain(&s, 1, 3);
        fs::remove_file(s.segment_path(&[1; 16], 1)).unwrap();
        assert_eq!(chain(&s, 1), Err(Error::JournalCorrupt));
        // Chain that does not start at 0.
        fs::remove_file(s.segment_path(&[1; 16], 0)).unwrap();
        assert_eq!(chain(&s, 1), Err(Error::JournalCorrupt));
    }

    #[test]
    fn wrong_seq_or_device_in_payload_is_corrupt() {
        let (_d, s) = store();
        write_chain(&s, 1, 2);
        // Segment 1 renamed to 2 (payload says 1, and there is a gap) and to 1 of
        // another device.
        write_chain(&s, 2, 1);
        fs::copy(s.segment_path(&[1; 16], 0), s.segment_path(&[2; 16], 1)).unwrap();
        assert_eq!(chain(&s, 2), Err(Error::JournalCorrupt));
        fs::remove_file(s.segment_path(&[2; 16], 1)).unwrap();
        fs::rename(s.segment_path(&[1; 16], 1), s.segment_path(&[1; 16], 5)).unwrap();
        assert_eq!(chain(&s, 1), Err(Error::JournalCorrupt));
    }

    #[test]
    fn broken_prev_hash_and_swapped_segments_are_corrupt() {
        let (_d, s) = store();
        write_chain(&s, 1, 3);
        // Wrong prev: rewrite segment 1 with a bad hash.
        let p1 = s.segment_path(&[1; 16], 1);
        let orig = fs::read(&p1).unwrap();
        fs::remove_file(&p1).unwrap();
        write_segment_with(
            &s,
            &vk(),
            VID,
            [1; 16],
            1,
            [7; 32],
            vec![del(2, 1)],
            &mut Counter(9),
        )
        .unwrap();
        assert_eq!(chain(&s, 1), Err(Error::JournalCorrupt));
        // Restoring the original makes the chain valid again.
        fs::write(&p1, &orig).unwrap();
        assert_eq!(chain(&s, 1).unwrap().len(), 3);
        // Swapped files 1 and 2.
        let p2 = s.segment_path(&[1; 16], 2);
        let tmp = s.root().join("swap");
        fs::rename(&p1, &tmp).unwrap();
        fs::rename(&p2, &p1).unwrap();
        fs::rename(&tmp, &p2).unwrap();
        assert_eq!(chain(&s, 1), Err(Error::JournalCorrupt));
    }

    #[test]
    fn tampered_or_foreign_segment_is_corrupt() {
        let (_d, s) = store();
        write_chain(&s, 1, 1);
        let p = s.segment_path(&[1; 16], 0);
        let mut f = fs::read(&p).unwrap();
        let n = f.len();
        f[n - 1] ^= 1;
        fs::write(&p, &f).unwrap();
        assert_eq!(chain(&s, 1), Err(Error::JournalCorrupt));
        assert_eq!(
            read_device_chain(&s, &vk(), [0x99; 16], [1; 16]),
            Err(Error::JournalCorrupt)
        );
    }

    #[test]
    fn blob_object_in_journal_dir_is_corrupt() {
        let (_d, s) = store();
        let mut w = write_object_with(
            Vec::new(),
            &vk(),
            VID,
            [3; 16],
            ObjectKind::Blob,
            &mut Counter(1),
        )
        .unwrap();
        w.write_all(&seg(1, 0, vec![del(1, 1)]).encode().unwrap())
            .unwrap();
        let file = w.finish().unwrap();
        s.write_atomic(&s.segment_path(&[1; 16], 0), |f| {
            std::io::Write::write_all(f, &file).map_err(|_| Error::Io)
        })
        .unwrap();
        assert_eq!(chain(&s, 1), Err(Error::JournalCorrupt));
    }

    #[test]
    fn fold_orders_by_t_then_device() {
        // Device 2 deletes item 1 at t=5, device 1 sets a field at t=6: del wins.
        let a = seg(
            1,
            0,
            vec![add(1, 1, 1), set(6, 1, "mime", Value::text("x"))],
        );
        let b = seg(2, 0, vec![del(5, 1), add(2, 2, 2)]);
        let st = State::fold([&a, &b]);
        assert!(st.item(&ItemId([1; 16])).is_none());
        assert!(st.is_deleted(&ItemId([1; 16])));
        assert_eq!(
            st.items().map(|i| i.id).collect::<Vec<_>>(),
            [ItemId([2; 16])]
        );
        // Input order does not matter.
        assert_eq!(State::fold([&b, &a]), st);
    }

    #[test]
    fn trash_and_restore_fold_lww_across_devices() {
        let item = ItemId([1; 16]);
        let base = seg(9, 0, vec![add(1, 1, 1)]);
        let trash = |t| set(t, 1, "trashed", Value::Uint(5000));
        let restore = |t| set(t, 1, "trashed", Value::Null);
        // Device 1 trashes at t=2, device 2 restores at t=3: restored.
        let a = seg(1, 0, vec![trash(2)]);
        let b = seg(2, 0, vec![restore(3)]);
        let st = State::fold([&base, &a, &b]);
        assert!(!st.is_trashed(&item));
        assert_eq!(State::fold([&b, &a, &base]), st);
        // Restore at t=3 loses against a later trash at t=4.
        let c = seg(1, 1, vec![trash(4)]);
        let st = State::fold([&base, &a, &b, &c]);
        assert!(st.is_trashed(&item));
        assert_eq!(st.item(&item).unwrap().meta.trashed, Some(5000));
        // Equal t: the higher device id wins.
        let st = State::fold([
            &base,
            &seg(1, 0, vec![trash(5)]),
            &seg(2, 0, vec![restore(5)]),
        ]);
        assert!(!st.is_trashed(&item));
        // Wrong types are ignored.
        let st = State::fold([
            &base,
            &seg(1, 0, vec![set(2, 1, "trashed", Value::text("x"))]),
        ]);
        assert!(!st.is_trashed(&item));
    }

    #[test]
    fn restore_after_tombstone_has_no_effect() {
        let item = ItemId([1; 16]);
        let a = seg(
            1,
            0,
            vec![
                add(1, 1, 1),
                set(2, 1, "trashed", Value::Uint(9)),
                del(3, 1),
                set(4, 1, "trashed", Value::Null),
            ],
        );
        let st = State::fold([&a]);
        assert!(st.is_deleted(&item) && st.item(&item).is_none() && !st.is_trashed(&item));
    }

    #[test]
    fn trashed_survives_state_cache_round_trip() {
        let a = seg(
            1,
            0,
            vec![add(1, 1, 1), set(2, 1, "trashed", Value::Uint(77))],
        );
        let st = State::fold([&a]);
        assert_eq!(State::from_value(&st.to_value()).unwrap(), st);
    }

    #[test]
    fn fold_lww_ties_broken_by_device_id() {
        let add1 = seg(9, 0, vec![add(1, 1, 1)]);
        let a = seg(1, 0, vec![set(5, 1, "filename", Value::text("from-1"))]);
        let b = seg(2, 0, vec![set(5, 1, "filename", Value::text("from-2"))]);
        let st = State::fold([&add1, &a, &b]);
        // Device 2 sorts after device 1 at equal t, so it wins.
        assert_eq!(
            st.item(&ItemId([1; 16])).unwrap().meta.filename.as_deref(),
            Some("from-2")
        );
        // A later t beats a higher device id; fields are independent.
        let c = seg(
            1,
            1,
            vec![
                set(6, 1, "filename", Value::text("late")),
                set(6, 1, "width", Value::Uint(10)),
                set(7, 1, "width", Value::Null),
            ],
        );
        let st = State::fold([&add1, &a, &b, &c]);
        let m = &st.item(&ItemId([1; 16])).unwrap().meta;
        assert_eq!(m.filename.as_deref(), Some("late"));
        assert_eq!(m.width, None);
    }

    #[test]
    fn set_after_del_and_dup_add_ignored() {
        let a = seg(
            1,
            0,
            vec![
                add(1, 1, 1),
                del(2, 1),
                set(3, 1, "mime", Value::text("x")),
                add(4, 1, 8),
            ],
        );
        let st = State::fold([&a]);
        assert_eq!(st.items().count(), 0);
        assert!(st.is_deleted(&ItemId([1; 16])));
        // Set on an unknown item and with a mistyped value is ignored.
        let b = seg(
            1,
            0,
            vec![
                set(1, 3, "mime", Value::text("x")),
                add(2, 1, 1),
                set(3, 1, "width", Value::text("w")),
            ],
        );
        let st = State::fold([&b]);
        assert_eq!(st.item(&ItemId([1; 16])).unwrap().meta.width, None);
        // Second add of a live item does not replace it.
        let c = seg(1, 0, vec![add(1, 1, 1), add(2, 1, 2)]);
        let st = State::fold([&c]);
        assert_eq!(
            st.item(&ItemId([1; 16])).unwrap().objects["original"],
            [1; 16]
        );
    }

    #[test]
    fn state_value_round_trip() {
        let a = seg(1, 0, vec![add(1, 1, 1), add(2, 2, 2), del(3, 2)]);
        let st = State::fold([&a]);
        let v = cbor::decode(&cbor::encode(&st.to_value()).unwrap()).unwrap();
        assert_eq!(State::from_value(&v).unwrap(), st);
    }

    #[test]
    fn sweep_deletes_only_unreferenced_and_old() {
        let (_d, s) = store();
        let put = |b: u8| {
            s.write_atomic(&s.object_path(&[b; 16]), |f| {
                std::io::Write::write_all(f, b"x").map_err(|_| Error::Io)
            })
            .unwrap();
        };
        for b in [1, 2, 3] {
            put(b);
        }
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(48 * 3600);
        for b in [1u8, 2] {
            fs::File::options()
                .write(true)
                .open(s.object_path(&[b; 16]))
                .unwrap()
                .set_modified(old)
                .unwrap();
        }
        // Object 1 is referenced; 2 is old and unreferenced; 3 is fresh.
        let st = State::fold([&seg(1, 0, vec![add(1, 1, 1)])]);
        assert_eq!(referenced_objects(&st), BTreeSet::from([[1; 16]]));
        let day = std::time::Duration::from_secs(24 * 3600);
        assert_eq!(sweep(&s, &st, day).unwrap(), 1);
        assert_eq!(s.list_objects().unwrap(), vec![[1; 16], [3; 16]]);
    }

    fn album_add(t: u64, a: u8, name: &str) -> Op {
        Op::AlbumAdd {
            t,
            album: AlbumId([a; 16]),
            name: name.to_owned(),
        }
    }

    fn put(t: u64, a: u8, item: u8) -> Op {
        Op::AlbumPut {
            t,
            album: AlbumId([a; 16]),
            item: ItemId([item; 16]),
        }
    }

    fn pop(t: u64, a: u8, item: u8) -> Op {
        Op::AlbumPop {
            t,
            album: AlbumId([a; 16]),
            item: ItemId([item; 16]),
        }
    }

    fn members(s: &State, a: u8) -> Vec<u8> {
        s.album_members(&AlbumId([a; 16]))
            .map(|m| m.iter().map(|i| i.0[0]).collect())
            .unwrap_or_default()
    }

    fn fold(ops: Vec<Op>) -> State {
        State::fold(&[seg(1, 0, ops)])
    }

    #[test]
    fn album_name_cleaning() {
        assert_eq!(clean_album_name("  Trip  ").as_deref(), Some("Trip"));
        assert_eq!(clean_album_name("e\u{301}").as_deref(), Some("\u{e9}"));
        assert_eq!(clean_album_name("   "), None);
        assert!(clean_album_name(&"a".repeat(100)).is_some());
        assert_eq!(clean_album_name(&"a".repeat(101)), None);
    }

    #[test]
    fn album_put_pop_sequence() {
        let run = |extra: Vec<Op>| {
            let mut ops = vec![add(1, 1, 1), album_add(2, 9, "A")];
            ops.extend(extra);
            members(&fold(ops), 9)
        };
        assert_eq!(run(vec![put(3, 9, 1)]), vec![1]);
        assert!(run(vec![put(3, 9, 1), pop(4, 9, 1)]).is_empty());
        assert_eq!(run(vec![pop(3, 9, 1), put(4, 9, 1)]), vec![1]);
        assert_eq!(run(vec![put(3, 9, 1), put(4, 9, 1)]), vec![1]);
    }

    #[test]
    fn album_concurrent_put_pop_ties_by_device() {
        let base = seg(1, 0, vec![add(1, 1, 1), album_add(2, 9, "A"), put(3, 9, 1)]);
        // Same t on two devices: the higher device id applies last and wins.
        let pop_low = seg(2, 0, vec![pop(4, 9, 1)]);
        let put_high = seg(3, 0, vec![put(4, 9, 1)]);
        let s = State::fold([&base, &pop_low, &put_high]);
        assert_eq!(members(&s, 9), vec![1]);
        assert_eq!(s, State::fold([&put_high, &base, &pop_low]));
        let put_low = seg(2, 0, vec![put(4, 9, 1)]);
        let pop_high = seg(3, 0, vec![pop(4, 9, 1)]);
        let s = State::fold([&base, &put_low, &pop_high]);
        assert!(members(&s, 9).is_empty());
        assert_eq!(s, State::fold([&pop_high, &put_low, &base]));
    }

    #[test]
    fn album_delete_and_item_delete_remove_membership() {
        let s = fold(vec![
            add(1, 1, 1),
            add(2, 2, 2),
            album_add(3, 9, "A"),
            put(4, 9, 1),
            put(5, 9, 2),
            del(6, 1),
        ]);
        assert_eq!(members(&s, 9), vec![2]);
        let s = fold(vec![
            add(1, 1, 1),
            album_add(2, 9, "A"),
            put(3, 9, 1),
            Op::AlbumDel {
                t: 4,
                album: AlbumId([9; 16]),
            },
            put(5, 9, 1),
            album_add(6, 9, "again"),
        ]);
        assert!(s.album(&AlbumId([9; 16])).is_none());
        assert_eq!(s.albums().count(), 0);
        assert_eq!(s.items().count(), 1);
        assert!(members(&s, 9).is_empty());
    }

    #[test]
    fn album_ops_for_unknown_targets_are_ignored() {
        let s = fold(vec![
            put(1, 9, 1),
            album_add(2, 9, "A"),
            put(3, 9, 7),
            add(4, 1, 1),
            del(5, 1),
            put(6, 9, 1),
        ]);
        assert!(members(&s, 9).is_empty());
        assert_eq!(s.albums().count(), 1);
    }

    #[test]
    fn album_rename_lww_and_validation() {
        let set_name = |t, v: &str| Op::AlbumSet {
            t,
            album: AlbumId([9; 16]),
            field: "name".to_owned(),
            value: Value::text(v),
        };
        let a = seg(1, 0, vec![album_add(1, 9, "A")]);
        let b = seg(2, 0, vec![set_name(2, "B")]);
        let c = seg(3, 0, vec![set_name(2, "C")]);
        let s = State::fold([&a, &b, &c]);
        assert_eq!(s.album(&AlbumId([9; 16])).unwrap().name, "C");
        assert_eq!(s, State::fold([&c, &b, &a]));
        let s = fold(vec![
            album_add(1, 9, "A"),
            set_name(2, " "),
            set_name(3, "B"),
        ]);
        assert_eq!(s.album(&AlbumId([9; 16])).unwrap().name, "B");
        // Unknown field is ignored; set before add is ignored.
        let other = Op::AlbumSet {
            t: 4,
            album: AlbumId([9; 16]),
            field: "color".to_owned(),
            value: Value::text("red"),
        };
        let s = fold(vec![set_name(1, "X"), album_add(2, 9, "A"), other]);
        assert_eq!(s.album(&AlbumId([9; 16])).unwrap().name, "A");
    }

    #[test]
    fn state_value_round_trip_with_albums() {
        let s = fold(vec![
            add(1, 1, 1),
            add(2, 2, 2),
            album_add(3, 9, "A"),
            album_add(4, 8, "B"),
            put(5, 9, 1),
            put(6, 9, 2),
            Op::AlbumDel {
                t: 7,
                album: AlbumId([8; 16]),
            },
        ]);
        assert_eq!(State::from_value(&s.to_value()).unwrap(), s);
        // A cache without the album keys still loads.
        let old = Value::map([
            ("items", Value::Array(vec![])),
            ("dead", Value::Array(vec![])),
            ("t", Value::Uint(0)),
        ]);
        assert_eq!(State::from_value(&old).unwrap(), State::new());
    }

    fn album_set(t: u64, a: u8, field: &str, value: Value) -> Op {
        Op::AlbumSet {
            t,
            album: AlbumId([a; 16]),
            field: field.to_owned(),
            value,
        }
    }

    fn pin_value(b: u8) -> Value {
        Value::Bytes(vec![b; ALBUM_PIN_LEN])
    }

    #[test]
    fn album_lock_fields_fold_lww() {
        let id = AlbumId([9; 16]);
        let s = fold(vec![album_add(1, 9, "A")]);
        let a = s.album(&id).unwrap();
        assert!(!a.locked() && a.shows_in_all());

        let s = fold(vec![
            album_add(1, 9, "A"),
            album_set(2, 9, "pin", pin_value(1)),
            album_set(3, 9, "pin", pin_value(2)),
        ]);
        let a = s.album(&id).unwrap();
        assert_eq!(a.pin, Some(vec![2; ALBUM_PIN_LEN]));
        // Locked albums default to hidden until an explicit choice is made.
        assert!(a.locked() && !a.shows_in_all());

        // Applied in `t` order: the later write wins whatever the op order.
        let s = fold(vec![
            album_add(1, 9, "A"),
            album_set(2, 9, "pin", pin_value(1)),
            album_set(3, 9, "show_in_all", Value::Bool(true)),
            album_set(4, 9, "pin", Value::Null),
            album_set(6, 9, "show_in_all", Value::Bool(false)),
            album_set(5, 9, "show_in_all", Value::Bool(true)),
        ]);
        let a = s.album(&id).unwrap();
        assert!(!a.locked() && !a.shows_in_all());

        // Concurrent writers: the higher device id wins on equal t.
        let base = seg(1, 0, vec![album_add(1, 9, "A")]);
        let x = seg(
            2,
            0,
            vec![album_set(2, 9, "show_in_all", Value::Bool(false))],
        );
        let y = seg(
            3,
            0,
            vec![album_set(2, 9, "show_in_all", Value::Bool(true))],
        );
        let s = State::fold(&[base, x, y]);
        assert!(s.album(&id).unwrap().shows_in_all());
    }

    #[test]
    fn album_lock_fields_ignore_bad_values() {
        let id = AlbumId([9; 16]);
        let s = fold(vec![
            album_add(1, 9, "A"),
            album_set(2, 9, "pin", Value::Bytes(vec![1; 47])),
            album_set(3, 9, "pin", Value::text("1234")),
            album_set(4, 9, "show_in_all", Value::Uint(1)),
            album_set(5, 9, "color", Value::text("red")),
            album_set(6, 8, "pin", pin_value(1)),
        ]);
        let a = s.album(&id).unwrap();
        assert_eq!((a.pin.clone(), a.show_in_all), (None, None));
        assert!(s.album(&AlbumId([8; 16])).is_none());
    }

    #[test]
    fn hidden_in_all_follows_albums() {
        let hidden = |s: &State, i: u8| s.is_hidden_in_all(&ItemId([i; 16]));
        let base = || {
            vec![
                add(1, 1, 1),
                add(2, 2, 2),
                add(3, 3, 3),
                album_add(4, 9, "open"),
                album_add(5, 8, "locked"),
                put(6, 9, 1),
                put(7, 9, 2),
                put(8, 8, 2),
                put(9, 8, 3),
                album_set(10, 8, "pin", pin_value(1)),
            ]
        };
        let with = |extra: Op| {
            let mut ops = base();
            ops.push(extra);
            fold(ops)
        };
        // Item 2 is in a shown and a hidden album: hidden. Item 1 stays visible.
        let s = fold(base());
        assert!(!hidden(&s, 1) && hidden(&s, 2) && hidden(&s, 3));

        let s = with(album_set(11, 8, "show_in_all", Value::Bool(true)));
        assert!(!hidden(&s, 2) && !hidden(&s, 3));

        // Hiding an open album works too.
        let s = with(album_set(11, 9, "show_in_all", Value::Bool(false)));
        assert!(hidden(&s, 1));

        // Deleting the hidden album un-hides its items.
        let s = with(Op::AlbumDel {
            t: 11,
            album: AlbumId([8; 16]),
        });
        assert!(!hidden(&s, 2) && !hidden(&s, 3));

        // Removing an item from the hidden album un-hides it.
        let s = with(pop(11, 8, 3));
        assert!(!hidden(&s, 3) && hidden(&s, 2));
    }

    #[test]
    fn state_value_round_trip_with_lock_fields() {
        let s = fold(vec![
            album_add(1, 9, "A"),
            album_add(2, 8, "B"),
            album_set(3, 9, "pin", pin_value(3)),
            album_set(4, 9, "show_in_all", Value::Bool(true)),
            album_set(5, 8, "show_in_all", Value::Bool(false)),
        ]);
        assert_eq!(State::from_value(&s.to_value()).unwrap(), s);
        let bad = Value::map([
            ("items", Value::Array(vec![])),
            ("dead", Value::Array(vec![])),
            (
                "albums",
                Value::Array(vec![Value::map([
                    ("album", Value::bytes(&[9; 16])),
                    ("name", Value::text("A")),
                    ("items", Value::Array(vec![])),
                    ("pin", Value::bytes(&[1; 5])),
                ])]),
            ),
            ("t", Value::Uint(0)),
        ]);
        assert!(State::from_value(&bad).is_err());
    }
}

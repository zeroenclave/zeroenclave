//! Checks the committed vectors in test-vectors/ against the core.

use std::fs;
use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::Cursor;
use zeroenclave_core::{
    auth_key, create_with, derive_master_key, duress_tag, open_object, password_kek, pin_key,
    recovery_kek, set_duress, unlock, unlock_recovery, write_object_with, write_segment_with,
    BioKey, Error, ItemKind, KdfParams, ObjectKind, RecoveryKey, SeededRandom, Segment, State,
    Store, UnlockOutcome, VaultHeader, VaultKey,
};

fn load<T: for<'de> Deserialize<'de>>(file: &str) -> T {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../test-vectors")
        .join(file);
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn arr<const N: usize>(h: &str) -> [u8; N] {
    hex::decode(h).unwrap().try_into().unwrap()
}

#[derive(Deserialize)]
struct PinFile {
    cases: Vec<PinCase>,
}

#[derive(Deserialize)]
struct PinCase {
    name: String,
    se_secret: String,
    pin: String,
    vault_id: String,
    pin_key: String,
}

#[test]
fn pin_vectors() {
    let f: PinFile = load("pin.json");
    assert!(!f.cases.is_empty());
    for c in f.cases {
        let secret = BioKey::from_bytes_for_test_vectors(arr::<32>(&c.se_secret));
        let key = pin_key(&secret, &c.pin, &arr::<16>(&c.vault_id)).unwrap();
        assert_eq!(
            hex::encode(key.expose_for_test_vectors()),
            c.pin_key,
            "{}",
            c.name
        );
    }
}

#[derive(Deserialize)]
struct KdfFile {
    cases: Vec<KdfCase>,
}

#[derive(Deserialize)]
struct KdfCase {
    name: String,
    password_utf8_hex: String,
    salt: String,
    vault_id: String,
    m_kib: u32,
    t: u32,
    p: u8,
    master_key: String,
    password_kek: String,
    duress_tag: String,
    auth_key: String,
}

#[test]
fn kdf_vectors() {
    let f: KdfFile = load("kdf.json");
    assert!(!f.cases.is_empty());
    for c in f.cases {
        let password = String::from_utf8(hex::decode(&c.password_utf8_hex).unwrap()).unwrap();
        let salt = arr::<16>(&c.salt);
        let vault_id = arr::<16>(&c.vault_id);
        let params = KdfParams {
            m_kib: c.m_kib,
            t: c.t,
            p: c.p,
        };
        let mk = derive_master_key(&password, &salt, &params).unwrap();
        let hx = |b: &[u8; 32]| hex::encode(b);
        assert_eq!(hx(mk.expose_for_test_vectors()), c.master_key, "{}", c.name);
        let kek = password_kek(&mk, &vault_id);
        assert_eq!(
            hx(kek.expose_for_test_vectors()),
            c.password_kek,
            "{}",
            c.name
        );
        let tag = duress_tag(&mk, &vault_id);
        assert_eq!(
            hx(tag.expose_for_test_vectors()),
            c.duress_tag,
            "{}",
            c.name
        );
        let auth = auth_key(&mk, &vault_id);
        assert_eq!(hx(auth.expose_for_test_vectors()), c.auth_key, "{}", c.name);
    }
}

#[derive(Deserialize)]
struct RecoveryFile {
    cases: Vec<RecoveryCase>,
    lenient: Vec<Lenient>,
    invalid: Vec<Invalid>,
}

#[derive(Deserialize)]
struct RecoveryCase {
    name: String,
    recovery_key: String,
    vault_id: String,
    encoded: String,
    recovery_kek: String,
}

#[derive(Deserialize)]
struct Lenient {
    input: String,
    recovery_key: String,
}

#[derive(Deserialize)]
struct Invalid {
    input: String,
    error: String,
}

#[test]
fn recovery_vectors() {
    let f: RecoveryFile = load("recovery.json");
    assert!(!f.cases.is_empty() && !f.invalid.is_empty());
    for c in f.cases {
        let key = arr::<32>(&c.recovery_key);
        let vault_id = arr::<16>(&c.vault_id);
        let rk = RecoveryKey::from_bytes_for_test_vectors(key);
        assert_eq!(rk.encode().as_str(), c.encoded, "{}", c.name);
        let back = RecoveryKey::decode(&c.encoded).unwrap();
        assert_eq!(back.expose_for_test_vectors(), &key, "{}", c.name);
        let kek = recovery_kek(&rk, &vault_id);
        assert_eq!(
            hex::encode(kek.expose_for_test_vectors()),
            c.recovery_kek,
            "{}",
            c.name
        );
    }
    for l in f.lenient {
        let rk = RecoveryKey::decode(&l.input).unwrap();
        assert_eq!(rk.expose_for_test_vectors(), &arr::<32>(&l.recovery_key));
    }
    for i in f.invalid {
        let want = match i.error.as_str() {
            "format" => Error::RecoveryKeyFormat,
            "checksum" => Error::RecoveryKeyChecksum,
            other => panic!("unknown error kind {other}"),
        };
        assert_eq!(
            RecoveryKey::decode(&i.input).unwrap_err(),
            want,
            "{:?}",
            i.input
        );
    }
}

#[derive(Deserialize)]
struct HeaderFile {
    cases: Vec<HeaderCase>,
}

#[derive(Deserialize)]
struct HeaderCase {
    name: String,
    seed_utf8: String,
    password_utf8_hex: String,
    duress_password_utf8_hex: String,
    m_kib: u32,
    t: u32,
    p: u8,
    vault_key: String,
    recovery_key: String,
    header: String,
    header_with_duress: String,
}

#[test]
fn header_vectors() {
    let f: HeaderFile = load("header.json");
    assert!(!f.cases.is_empty());
    for c in f.cases {
        let utf8 = |h: &str| String::from_utf8(hex::decode(h).unwrap()).unwrap();
        let password = utf8(&c.password_utf8_hex);
        let duress = utf8(&c.duress_password_utf8_hex);
        let params = KdfParams {
            m_kib: c.m_kib,
            t: c.t,
            p: c.p,
        };
        let mut rng = SeededRandom::new(c.seed_utf8.as_bytes());
        let (header, vk, rk) = create_with(&password, params, &mut rng).unwrap();
        assert_eq!(hex::encode(header.to_bytes()), c.header, "{}", c.name);
        assert_eq!(
            hex::encode(vk.expose_for_test_vectors()),
            c.vault_key,
            "{}",
            c.name
        );
        assert_eq!(rk.encode().as_str(), c.recovery_key, "{}", c.name);

        let parsed = VaultHeader::parse(&hex::decode(&c.header).unwrap()).unwrap();
        match unlock(&parsed, &password).unwrap() {
            UnlockOutcome::Open(k) => {
                assert_eq!(k.expose_for_test_vectors(), vk.expose_for_test_vectors())
            }
            other => panic!("{}: expected Open, got {other:?}", c.name),
        }
        let k = unlock_recovery(&parsed, &rk).unwrap();
        assert_eq!(k.expose_for_test_vectors(), vk.expose_for_test_vectors());

        let with = set_duress(&header, &vk, &duress).unwrap();
        assert_eq!(
            hex::encode(with.to_bytes()),
            c.header_with_duress,
            "{}",
            c.name
        );
        assert!(matches!(
            unlock(&with, &duress).unwrap(),
            UnlockOutcome::Duress
        ));
    }
}

#[derive(Deserialize)]
struct ObjectFile {
    cases: Vec<ObjectCase>,
    invalid: Vec<ObjectInvalid>,
}

#[derive(Deserialize)]
struct ObjectCase {
    name: String,
    seed_utf8: String,
    vault_key: String,
    vault_id: String,
    object_id: String,
    kind: u8,
    plaintext_len: usize,
    file_len: usize,
    header: String,
    body_first64: String,
    file_sha256: String,
}

#[derive(Deserialize)]
struct ObjectInvalid {
    name: String,
    case: String,
    truncate_to: Option<usize>,
    append_first_chunk: bool,
    xor_offset: Option<usize>,
    xor_value: Option<u8>,
    expect_vault_id: Option<String>,
    expect_object_id: Option<String>,
    error: String,
}

/// Plaintext rule: byte i is `i mod 251`.
fn rule_plaintext(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn build_object(c: &ObjectCase) -> Vec<u8> {
    assert_eq!(c.kind, 1);
    let vk = VaultKey::from_bytes_for_test_vectors(arr(&c.vault_key));
    let mut rng = SeededRandom::new(c.seed_utf8.as_bytes());
    let mut w = write_object_with(
        Vec::new(),
        &vk,
        arr(&c.vault_id),
        arr(&c.object_id),
        ObjectKind::Blob,
        &mut rng,
    )
    .unwrap();
    w.write_all(&rule_plaintext(c.plaintext_len)).unwrap();
    w.finish().unwrap()
}

#[test]
fn object_vectors() {
    let f: ObjectFile = load("object.json");
    assert!(!f.cases.is_empty());
    for c in &f.cases {
        let file = build_object(c);
        assert_eq!(file.len(), c.file_len, "{}", c.name);
        assert_eq!(hex::encode(&file[..111]), c.header, "{}", c.name);
        assert_eq!(
            hex::encode(&file[111..111 + 64.min(file.len() - 111)]),
            c.body_first64
        );
        assert_eq!(
            hex::encode(Sha256::digest(&file)),
            c.file_sha256,
            "{}",
            c.name
        );

        let vk = VaultKey::from_bytes_for_test_vectors(arr(&c.vault_key));
        let mut r = open_object(
            Cursor::new(file),
            &vk,
            arr(&c.vault_id),
            Some(arr(&c.object_id)),
        )
        .unwrap();
        assert_eq!(r.plaintext_len(), c.plaintext_len as u64, "{}", c.name);
        assert_eq!(r.read_all().unwrap(), rule_plaintext(c.plaintext_len));
    }

    assert!(!f.invalid.is_empty());
    for n in &f.invalid {
        let c = f.cases.iter().find(|c| c.name == n.case).unwrap();
        let mut file = build_object(c);
        if n.append_first_chunk {
            let first = file[111..111 + (1 << 20) + 16].to_vec();
            file.extend_from_slice(&first);
        }
        if let Some(t) = n.truncate_to {
            file.truncate(t);
        }
        if let (Some(o), Some(v)) = (n.xor_offset, n.xor_value) {
            file[o] ^= v;
        }
        let vk = VaultKey::from_bytes_for_test_vectors(arr(&c.vault_key));
        let vid = n.expect_vault_id.as_deref().map_or(arr(&c.vault_id), arr);
        let oid = n.expect_object_id.as_deref().map_or(arr(&c.object_id), arr);
        let err = open_object(Cursor::new(file), &vk, vid, Some(oid))
            .and_then(|mut r| r.read_all())
            .unwrap_err();
        let want = match n.error.as_str() {
            "format" => Error::ObjectFormat,
            "mismatch" => Error::ObjectMismatch,
            _ => Error::Corrupt,
        };
        assert_eq!(err, want, "{}", n.name);
    }
}

#[derive(Deserialize)]
struct JournalFile {
    chain: ChainCase,
    fold: FoldCase,
}

#[derive(Deserialize)]
struct ChainCase {
    vault_key: String,
    vault_id: String,
    device: String,
    segments: Vec<ChainSegment>,
}

#[derive(Deserialize)]
struct ChainSegment {
    seq: u64,
    seed_utf8: String,
    prev: String,
    payload: String,
    file_len: usize,
    file_sha256: String,
}

#[derive(Deserialize)]
struct FoldCase {
    segments: Vec<FoldSegment>,
    live: Vec<serde_json::Value>,
    tombstones: Vec<String>,
    max_t: u64,
}

#[derive(Deserialize)]
struct FoldSegment {
    payload: String,
}

#[test]
fn journal_chain_vectors() {
    let f: JournalFile = load("journal.json");
    let c = f.chain;
    let vk = VaultKey::from_bytes_for_test_vectors(arr(&c.vault_key));
    let (vault_id, device) = (arr::<16>(&c.vault_id), arr::<16>(&c.device));
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path());
    assert_eq!(c.segments.len(), 2);
    for s in &c.segments {
        let payload = hex::decode(&s.payload).unwrap();
        let seg = Segment::decode(&payload).unwrap();
        assert_eq!(seg.encode().unwrap(), payload, "seq {}", s.seq);
        assert_eq!((seg.device, seg.seq), (device, s.seq));
        assert_eq!(hex::encode(seg.prev), s.prev);
        let mut rng = SeededRandom::new(s.seed_utf8.as_bytes());
        let hash = write_segment_with(
            &store, &vk, vault_id, device, s.seq, seg.prev, seg.ops, &mut rng,
        )
        .unwrap();
        assert_eq!(hex::encode(hash), s.file_sha256, "seq {}", s.seq);
        let file = fs::read(store.segment_path(&device, s.seq)).unwrap();
        assert_eq!(file.len(), s.file_len);
        assert_eq!(hex::encode(Sha256::digest(&file)), s.file_sha256);
    }
    let chain = zeroenclave_core::read_device_chain(&store, &vk, vault_id, device).unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(hex::encode(chain[1].prev), c.segments[0].file_sha256);
}

#[test]
fn journal_fold_vectors() {
    let f: JournalFile = load("journal.json");
    let f = f.fold;
    let segs: Vec<Segment> = f
        .segments
        .iter()
        .map(|s| Segment::decode(&hex::decode(&s.payload).unwrap()).unwrap())
        .collect();
    for (s, raw) in segs.iter().zip(&f.segments) {
        assert_eq!(hex::encode(s.encode().unwrap()), raw.payload);
    }
    // Input order must not matter.
    let state = State::fold(segs.iter().rev());
    assert_eq!(state, State::fold(segs.iter()));
    assert_eq!(state.max_t(), f.max_t);
    let live: Vec<_> = state.items().collect();
    assert_eq!(live.len(), f.live.len());
    for (it, want) in live.iter().zip(&f.live) {
        assert_eq!(hex::encode(it.id.0), want["item"].as_str().unwrap());
        let kind = match it.kind {
            ItemKind::Photo => "photo",
            ItemKind::Video => "video",
            ItemKind::Live => "live",
        };
        assert_eq!(kind, want["kind"].as_str().unwrap());
        for (role, id) in &it.objects {
            assert_eq!(hex::encode(id), want["objects"][role].as_str().unwrap());
        }
        assert_eq!(it.objects.len(), want["objects"].as_object().unwrap().len());
        let m = &it.meta;
        let got = serde_json::json!({
            "imported": m.imported,
            "filename": m.filename, "created": m.created, "mime": m.mime,
            "width": m.width, "height": m.height, "duration": m.duration, "size": m.size,
            "trashed": m.trashed,
        });
        for (k, v) in got.as_object().unwrap() {
            assert_eq!(
                v,
                want["meta"].get(k).unwrap_or(&serde_json::Value::Null),
                "{k}"
            );
        }
    }
    for t in &f.tombstones {
        let id = zeroenclave_core::ItemId(arr(t));
        assert!(state.is_deleted(&id) && state.item(&id).is_none());
    }
}

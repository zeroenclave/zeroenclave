//! Writes test-vectors/{kdf,pin,recovery,header,object,journal}.json from fixed inputs.
//! Run: cargo run --release --features test-vectors --example gen_vectors

use std::fs;
use std::path::Path;

use serde_json::{json, Value as Value2};
use sha2::{Digest, Sha256};
use std::io::Cursor;
use zeroenclave_core::{
    auth_key, create_with, derive_master_key, duress_tag, open_object, password_kek, pin_key,
    recovery_kek, set_duress, write_object_with, write_segment_with, BioKey, Error, ItemId,
    ItemKind, ItemMeta, KdfParams, ObjectKind, Op, RecoveryKey, SeededRandom, Segment, State,
    Store, Value, VaultKey, CHUNK_SIZE,
};

const NFC: &str = "Gr\u{f6}\u{df}e-\u{fc}ber-\u{c4}pfel-2024";
const NFD_DURESS: &str = "Not-Passwort-\u{e4}\u{f6}\u{fc}";
const NFD: &str = "Gro\u{308}\u{df}e-u\u{308}ber-A\u{308}pfel-2024";

fn seq(start: u8) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = start.wrapping_add(i as u8);
    }
    out
}

fn kdf_case(name: &str, password: &str, salt: [u8; 16], vault_id: [u8; 16]) -> Value2 {
    let p = KdfParams::DEFAULT;
    let mk = derive_master_key(password, &salt, &p).unwrap();
    json!({
        "name": name,
        "password_utf8_hex": hex::encode(password.as_bytes()),
        "salt": hex::encode(salt),
        "vault_id": hex::encode(vault_id),
        "m_kib": p.m_kib,
        "t": p.t,
        "p": p.p,
        "master_key": hex::encode(mk.expose_for_test_vectors()),
        "password_kek": hex::encode(password_kek(&mk, &vault_id).expose_for_test_vectors()),
        "duress_tag": hex::encode(duress_tag(&mk, &vault_id).expose_for_test_vectors()),
        "auth_key": hex::encode(auth_key(&mk, &vault_id).expose_for_test_vectors()),
    })
}

fn pin_case(name: &str, se_secret: [u8; 32], pin: &str, vault_id: [u8; 16]) -> Value2 {
    let key = pin_key(
        &BioKey::from_bytes_for_test_vectors(se_secret),
        pin,
        &vault_id,
    )
    .unwrap();
    json!({
        "name": name,
        "se_secret": hex::encode(se_secret),
        "pin": pin,
        "vault_id": hex::encode(vault_id),
        "pin_key": hex::encode(key.expose_for_test_vectors()),
    })
}

fn recovery_case(name: &str, key: [u8; 32], vault_id: [u8; 16]) -> Value2 {
    let rk = RecoveryKey::from_bytes_for_test_vectors(key);
    json!({
        "name": name,
        "recovery_key": hex::encode(key),
        "vault_id": hex::encode(vault_id),
        "encoded": rk.encode().as_str(),
        "recovery_kek": hex::encode(recovery_kek(&rk, &vault_id).expose_for_test_vectors()),
    })
}

fn expect(input: &str, kind: &str) -> Value2 {
    let want = match kind {
        "format" => Error::RecoveryKeyFormat,
        _ => Error::RecoveryKeyChecksum,
    };
    assert_eq!(RecoveryKey::decode(input).unwrap_err(), want, "{input:?}");
    json!({ "input": input, "error": kind })
}

/// Random draw order: vault_id, salt, vk, recovery key, slot 0x01 nonce, slot 0x02 nonce,
/// slot 0x03 bytes, taken from the SeededRandom stream.
fn header_case(name: &str, seed: &str, password: &str, duress: &str) -> Value2 {
    let p = KdfParams::DEFAULT;
    let mut rng = SeededRandom::new(seed.as_bytes());
    let (header, vk, rk) = create_with(password, p, &mut rng).unwrap();
    let with_duress = set_duress(&header, &vk, duress).unwrap();
    json!({
        "name": name,
        "seed_utf8": seed,
        "password_utf8_hex": hex::encode(password.as_bytes()),
        "duress_password_utf8_hex": hex::encode(duress.as_bytes()),
        "m_kib": p.m_kib,
        "t": p.t,
        "p": p.p,
        "vault_key": hex::encode(vk.expose_for_test_vectors()),
        "recovery_key": rk.encode().as_str(),
        "header": hex::encode(header.to_bytes()),
        "header_with_duress": hex::encode(with_duress.to_bytes()),
    })
}

fn vault_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = 0xA0 ^ i as u8;
    }
    k
}

/// Plaintext rule: byte i is `i mod 251`.
fn plaintext(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Random draw order: dek, dek_nonce, nonce_prefix, taken from the SeededRandom stream.
fn object_file(seed: &str, len: usize) -> Vec<u8> {
    let vk = VaultKey::from_bytes_for_test_vectors(vault_key());
    let mut rng = SeededRandom::new(seed.as_bytes());
    let mut w = write_object_with(
        Vec::new(),
        &vk,
        seq(0x10),
        seq(0x20),
        ObjectKind::Blob,
        &mut rng,
    )
    .unwrap();
    w.write_all(&plaintext(len)).unwrap();
    w.finish().unwrap()
}

fn object_case(name: &str, seed: &str, len: usize) -> Value2 {
    let file = object_file(seed, len);
    let vk = VaultKey::from_bytes_for_test_vectors(vault_key());
    let mut r = open_object(Cursor::new(file.clone()), &vk, seq(0x10), Some(seq(0x20))).unwrap();
    assert_eq!(r.read_all().unwrap(), plaintext(len));
    json!({
        "name": name,
        "seed_utf8": seed,
        "vault_key": hex::encode(vault_key()),
        "vault_id": hex::encode(seq(0x10)),
        "object_id": hex::encode(seq(0x20)),
        "kind": 1,
        "plaintext_len": len,
        "plaintext_rule": "byte i = i mod 251",
        "file_len": file.len(),
        "header": hex::encode(&file[..111]),
        "body_first64": hex::encode(&file[111..111 + 64.min(file.len() - 111)]),
        "file_sha256": hex::encode(Sha256::digest(&file)),
    })
}

/// Mutation applied to the file of `case` before opening; see tests/vectors.rs.
#[allow(clippy::too_many_arguments)]
fn object_neg(
    name: &str,
    case: &str,
    seed: &str,
    len: usize,
    truncate_to: Option<usize>,
    append_first_chunk: bool,
    xor: Option<(usize, u8)>,
    expect_vault_id: Option<[u8; 16]>,
    expect_object_id: Option<[u8; 16]>,
) -> Value2 {
    let mut file = object_file(seed, len);
    if append_first_chunk {
        let first = file[111..111 + CHUNK_SIZE + 16].to_vec();
        file.extend_from_slice(&first);
    }
    if let Some(n) = truncate_to {
        file.truncate(n);
    }
    if let Some((off, v)) = xor {
        file[off] ^= v;
    }
    let vk = VaultKey::from_bytes_for_test_vectors(vault_key());
    let vid = expect_vault_id.unwrap_or(seq(0x10));
    let oid = expect_object_id.unwrap_or(seq(0x20));
    let err = open_object(Cursor::new(file), &vk, vid, Some(oid))
        .and_then(|mut r| r.read_all())
        .unwrap_err();
    let kind = match err {
        Error::ObjectFormat => "format",
        Error::ObjectMismatch => "mismatch",
        Error::Corrupt => "corrupt",
        e => panic!("{name}: unexpected {e:?}"),
    };
    json!({
        "name": name,
        "case": case,
        "truncate_to": truncate_to,
        "append_first_chunk": append_first_chunk,
        "xor_offset": xor.map(|x| x.0),
        "xor_value": xor.map(|x| x.1),
        "expect_vault_id": expect_vault_id.map(hex::encode),
        "expect_object_id": expect_object_id.map(hex::encode),
        "error": kind,
    })
}

fn item_id(b: u8) -> ItemId {
    ItemId([b; 16])
}

fn add_op(t: u64, item: u8, kind: ItemKind, objects: &[(&str, u8)], meta: ItemMeta) -> Op {
    Op::ItemAdd {
        t,
        item: item_id(item),
        kind,
        objects: objects
            .iter()
            .map(|(r, o)| (r.to_string(), [*o; 16]))
            .collect(),
        meta,
    }
}

fn set_op(t: u64, item: u8, field: &str, value: Value) -> Op {
    Op::ItemSet {
        t,
        item: item_id(item),
        field: field.into(),
        value,
    }
}

fn meta(imported: i64) -> ItemMeta {
    ItemMeta {
        imported,
        ..ItemMeta::default()
    }
}

fn segment(device: u8, seq: u64, ops: Vec<Op>) -> Segment {
    Segment {
        device: [device; 16],
        seq,
        prev: [0; 32],
        ops,
        hash: [0; 32],
    }
}

fn item_json(it: &zeroenclave_core::Item) -> Value2 {
    let m = &it.meta;
    let mut meta = serde_json::Map::new();
    meta.insert("imported".into(), json!(m.imported));
    if let Some(v) = &m.filename {
        meta.insert("filename".into(), json!(v));
    }
    if let Some(v) = m.created {
        meta.insert("created".into(), json!(v));
    }
    if let Some(v) = &m.mime {
        meta.insert("mime".into(), json!(v));
    }
    for (k, v) in [
        ("width", m.width),
        ("height", m.height),
        ("duration", m.duration),
        ("size", m.size),
        ("trashed", m.trashed),
    ] {
        if let Some(v) = v {
            meta.insert(k.into(), json!(v));
        }
    }
    let objects: serde_json::Map<String, Value2> = it
        .objects
        .iter()
        .map(|(r, o)| (r.clone(), json!(hex::encode(o))))
        .collect();
    json!({
        "item": hex::encode(it.id.0),
        "kind": match it.kind { ItemKind::Photo => "photo", ItemKind::Video => "video", ItemKind::Live => "live" },
        "objects": objects,
        "meta": meta,
    })
}

/// Two chained segments written through the real store path. Random draw order per
/// segment: object_id, dek, dek_nonce, nonce_prefix from `SeededRandom("journal-seed-<seq>")`.
fn journal_chain() -> Value2 {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path());
    let vk = VaultKey::from_bytes_for_test_vectors(vault_key());
    let mut full = meta(1_700_000_000_000);
    full.filename = Some("IMG_0001.HEIC".into());
    full.created = Some(1_699_999_000_000);
    full.mime = Some("image/heic".into());
    full.width = Some(4032);
    full.height = Some(3024);
    full.size = Some(2_345_678);
    let mut video = meta(1_700_000_000_000);
    video.duration = Some(12_500);
    let segs = [
        vec![
            add_op(
                1,
                0x31,
                ItemKind::Live,
                &[
                    ("original", 0x41),
                    ("paired_video", 0x42),
                    ("thumb_small", 0x43),
                ],
                full,
            ),
            add_op(2, 0x32, ItemKind::Video, &[("original", 0x44)], video),
        ],
        vec![
            set_op(3, 0x31, "filename", Value::text("renamed.HEIC")),
            Op::ItemDel {
                t: 4,
                item: item_id(0x32),
            },
        ],
    ];
    let mut prev = [0u8; 32];
    let mut out = Vec::new();
    for (seq, ops) in segs.into_iter().enumerate() {
        let seed = format!("journal-seed-{seq}");
        let payload = Segment {
            prev,
            ..segment(0x21, seq as u64, ops.clone())
        };
        let hash = write_segment_with(
            &store,
            &vk,
            seq10(),
            [0x21; 16],
            seq as u64,
            prev,
            ops,
            &mut SeededRandom::new(seed.as_bytes()),
        )
        .unwrap();
        let file = fs::read(store.segment_path(&[0x21; 16], seq as u64)).unwrap();
        assert_eq!(Sha256::digest(&file).as_slice(), hash);
        let bytes = payload.encode().unwrap();
        out.push(json!({
            "seq": seq,
            "seed_utf8": seed,
            "prev": hex::encode(prev),
            "payload": hex::encode(bytes),
            "file_len": file.len(),
            "file_sha256": hex::encode(hash),
        }));
        prev = hash;
    }
    let chain = zeroenclave_core::read_device_chain(&store, &vk, seq10(), [0x21; 16]).unwrap();
    assert_eq!(chain.len(), 2);
    json!({
        "vault_key": hex::encode(vault_key()),
        "vault_id": hex::encode(seq10()),
        "device": hex::encode([0x21u8; 16]),
        "segments": out,
    })
}

/// Ops of two devices (and one unknown op) with ties, a delete, a late set and trash/restore.
fn journal_fold() -> Value2 {
    let mut m = meta(100);
    m.filename = Some("a.jpg".into());
    m.width = Some(10);
    let a0 = segment(
        0x01,
        0,
        vec![
            add_op(1, 0x51, ItemKind::Photo, &[("original", 0x61)], m),
            add_op(2, 0x52, ItemKind::Photo, &[("original", 0x62)], meta(200)),
            add_op(3, 0x53, ItemKind::Video, &[("original", 0x63)], meta(300)),
        ],
    );
    let b0 = segment(
        0x02,
        0,
        vec![
            set_op(5, 0x51, "filename", Value::text("from-b")),
            set_op(4, 0x52, "width", Value::Uint(640)),
            Op::ItemDel {
                t: 6,
                item: item_id(0x53),
            },
            Op::Unknown(Value::map([
                ("op", Value::text("item.rotate")),
                ("t", Value::Uint(7)),
                ("deg", Value::Uint(90)),
            ])),
        ],
    );
    let a1 = segment(
        0x01,
        1,
        vec![
            set_op(5, 0x51, "filename", Value::text("from-a")),
            set_op(8, 0x53, "mime", Value::text("video/mp4")),
            set_op(9, 0x51, "width", Value::Null),
            // Trash: ties with device 0x02 at t=10, then cleared at t=12.
            set_op(10, 0x51, "trashed", Value::Uint(1_700_000_000_000)),
            set_op(12, 0x51, "trashed", Value::Null),
        ],
    );
    let b1 = segment(
        0x02,
        1,
        vec![
            set_op(10, 0x51, "trashed", Value::Uint(1_700_000_100_000)),
            // Stays trashed; a set on a tombstoned item is ignored.
            set_op(11, 0x52, "trashed", Value::Uint(1_700_000_200_000)),
            set_op(13, 0x53, "trashed", Value::Uint(1_700_000_300_000)),
        ],
    );
    let segs = [a0, b0, a1, b1];
    let state = State::fold(segs.iter());
    assert_eq!(state.items().count(), 2);
    json!({
        "segments": segs.iter().map(|s| json!({
            "device": hex::encode(s.device),
            "seq": s.seq,
            "payload": hex::encode(s.encode().unwrap()),
        })).collect::<Vec<_>>(),
        "live": state.items().map(item_json).collect::<Vec<_>>(),
        "tombstones": [hex::encode([0x53u8; 16])],
        "max_t": state.max_t(),
    })
}

fn seq10() -> [u8; 16] {
    seq(0x10)
}

fn write(dir: &Path, file: &str, v: &Value2) {
    let mut text = serde_json::to_string_pretty(v).unwrap();
    text.push('\n');
    fs::write(dir.join(file), text).unwrap();
}

fn main() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-vectors");
    fs::create_dir_all(&dir).unwrap();

    assert_ne!(NFC, NFD);
    let kdf = json!({
        "cases": [
            kdf_case("ascii", "correct horse battery staple", seq(0x00), seq(0x10)),
            kdf_case("german_nfc", NFC, seq(0x20), seq(0x30)),
            // Same salt and vault_id as german_nfc: master key must be identical.
            kdf_case("german_nfd", NFD, seq(0x20), seq(0x30)),
        ],
    });
    write(&dir, "kdf.json", &kdf);

    let pin = json!({
        "cases": [
            pin_case("zeros", [0u8; 32], "000000", seq(0x70)),
            pin_case("digits", [0xA5u8; 32], "482916", seq(0x80)),
            // Same secret and vault as "digits": one digit changes the key.
            pin_case("digits_other", [0xA5u8; 32], "482917", seq(0x80)),
        ],
    });
    write(&dir, "pin.json", &pin);

    let mut mixed = [0u8; 32];
    for (i, b) in mixed.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    let cases = [
        recovery_case("zero", [0u8; 32], seq(0x40)),
        recovery_case("ones", [0xFFu8; 32], seq(0x50)),
        recovery_case("mixed", mixed, seq(0x60)),
    ];

    let zero_enc = RecoveryKey::from_bytes_for_test_vectors([0u8; 32]).encode();
    let mixed_enc = RecoveryKey::from_bytes_for_test_vectors(mixed).encode();
    let mut typo = zero_enc.to_string();
    typo.replace_range(0..1, "1");
    let mut typo_last = mixed_enc.to_string();
    let last = typo_last.pop().unwrap();
    typo_last.push(if last == '2' { '3' } else { '2' });

    let lenient = zero_enc.to_lowercase().replace('0', "o").replace('-', " ");
    assert_eq!(
        RecoveryKey::decode(&lenient)
            .unwrap()
            .expose_for_test_vectors(),
        &[0u8; 32]
    );

    let invalid = [
        expect("", "format"),
        expect(&mixed_enc[..mixed_enc.len() - 1], "format"),
        expect(&format!("{}2", mixed_enc.as_str()), "format"),
        expect(&format!("U{}", &mixed_enc[1..]), "format"),
        expect(&format!("#{}", &mixed_enc[1..]), "format"),
        expect(&typo, "checksum"),
        expect(&typo_last, "checksum"),
    ];

    let recovery = json!({
        "cases": cases,
        "lenient": [
            { "input": lenient, "recovery_key": hex::encode([0u8; 32]) },
        ],
        "invalid": invalid,
    });
    write(&dir, "recovery.json", &recovery);

    let header = json!({
        "cases": [
            header_case("ascii", "header-seed-1", "correct horse battery staple", "second password"),
            header_case("german", "header-seed-2", NFC, NFD_DURESS),
        ],
    });
    write(&dir, "header.json", &header);

    let big = CHUNK_SIZE + 5;
    let sealed = CHUNK_SIZE + 16;
    let neg = |name: &str, case: &str, len: usize, t, a, x, v, o| {
        object_neg(
            name,
            case,
            &format!("object-seed-{case}"),
            len,
            t,
            a,
            x,
            v,
            o,
        )
    };
    let object = json!({
        "cases": [
            object_case("empty", "object-seed-empty", 0),
            object_case("short", "object-seed-short", 37),
            object_case("two_chunks", "object-seed-two_chunks", big),
        ],
        "invalid": [
            neg("truncate_at_chunk_boundary", "two_chunks", big, Some(111 + sealed), false, None, None, None),
            neg("append_chunk", "two_chunks", big, None, true, None, None, None),
            neg("flip_body_bit", "two_chunks", big, None, false, Some((111 + 10, 1)), None, None),
            neg("flip_last_chunk_bit", "two_chunks", big, None, false, Some((111 + sealed + 2, 0x80)), None, None),
            neg("flip_wrapped_dek", "short", 37, None, false, Some((100, 1)), None, None),
            neg("flip_nonce_prefix", "short", 37, None, false, Some((46, 1)), None, None),
            neg("flip_object_id_in_header", "short", 37, None, false, Some((30, 1)), None, None),
            neg("header_only", "empty", 0, Some(111), false, None, None, None),
            neg("truncate_into_tag", "short", 37, Some(111 + 37 + 15), false, None, None, None),
            neg("short_header", "short", 37, Some(50), false, None, None, None),
            neg("bad_magic", "short", 37, None, false, Some((0, 1)), None, None),
            neg("bad_version", "short", 37, None, false, Some((5, 2)), None, None),
            neg("kind_snapshot", "short", 37, None, false, Some((6, 0x02)), None, None),
            neg("reserved_nonzero", "short", 37, None, false, Some((7, 1)), None, None),
            neg("bad_chunk_size", "short", 37, None, false, Some((41, 1)), None, None),
            neg("other_vault", "short", 37, None, false, None, Some(seq(0x70)), None),
            neg("other_object_id", "short", 37, None, false, None, None, Some(seq(0x80))),
        ],
    });
    write(&dir, "object.json", &object);

    let journal = json!({ "chain": journal_chain(), "fold": journal_fold() });
    write(&dir, "journal.json", &journal);
}

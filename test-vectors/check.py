#!/usr/bin/env python3
"""Independent verifier for the vectors in this directory (does not use the Rust core)."""

import hashlib
import json
import sys
import unicodedata
from pathlib import Path

import cbor2
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HERE = Path(__file__).resolve().parent
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
PREFIX = b"zeroenclave v1 "


def hkdf(ikm: bytes, vault_id: bytes, label: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=vault_id, info=PREFIX + label.encode()
    ).derive(ikm)


def checksum(key: bytes) -> bytes:
    return hashlib.sha256(PREFIX + b"recovery-checksum" + key).digest()[:3]


def b32_encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    bits = len(data) * 8
    assert bits % 5 == 0
    syms = [ALPHABET[(n >> (bits - 5 * (i + 1))) & 31] for i in range(bits // 5)]
    return "".join(syms)


def encode(key: bytes) -> str:
    s = b32_encode(key + checksum(key))
    return "-".join(s[i : i + 4] for i in range(0, len(s), 4))


class DecodeError(Exception):
    def __init__(self, kind: str):
        super().__init__(kind)
        self.kind = kind


def decode(text: str) -> bytes:
    syms = []
    for ch in text:
        if ch in " -":
            continue
        ch = ch.upper() if ch.isascii() else ch
        ch = {"I": "1", "L": "1", "O": "0"}.get(ch, ch)
        if len(ch) != 1 or ch not in ALPHABET:
            raise DecodeError("format")
        syms.append(ch)
    if len(syms) != 56:
        raise DecodeError("format")
    n = 0
    for ch in syms:
        n = (n << 5) | ALPHABET.index(ch)
    payload = n.to_bytes(35, "big")
    key, tag = payload[:32], payload[32:]
    if checksum(key) != tag:
        raise DecodeError("checksum")
    return key


def check_kdf(count: int) -> int:
    cases = json.loads((HERE / "kdf.json").read_text(encoding="utf-8"))["cases"]
    masters = {}
    for c in cases:
        raw = bytes.fromhex(c["password_utf8_hex"])
        password = unicodedata.normalize("NFC", raw.decode("utf-8")).encode("utf-8")
        salt, vault_id = bytes.fromhex(c["salt"]), bytes.fromhex(c["vault_id"])
        mk = hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=c["t"],
            memory_cost=c["m_kib"],
            parallelism=c["p"],
            hash_len=32,
            type=Type.ID,
            version=19,
        )
        expected = {
            "master_key": mk,
            "password_kek": hkdf(mk, vault_id, "password-kek"),
            "duress_tag": hkdf(mk, vault_id, "duress-tag"),
            "auth_key": hkdf(mk, vault_id, "auth"),
        }
        for name, value in expected.items():
            assert value.hex() == c[name], f"kdf {c['name']}: {name} mismatch"
            count += 1
        masters[c["name"]] = c["master_key"]
    assert masters["german_nfc"] == masters["german_nfd"], "NFC/NFD keys differ"
    return count


def check_pin(count: int) -> int:
    cases = json.loads((HERE / "pin.json").read_text(encoding="utf-8"))["cases"]
    keys = {}
    for c in cases:
        vault_id = bytes.fromhex(c["vault_id"])
        assert len(c["pin"]) == 6 and c["pin"].isascii() and c["pin"].isdigit(), c["name"]
        pin_secret = hash_secret_raw(
            secret=c["pin"].encode("ascii"),
            salt=vault_id,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=Type.ID,
            version=19,
        )
        key = hkdf(bytes.fromhex(c["se_secret"]) + pin_secret, vault_id, "pin-key")
        assert key.hex() == c["pin_key"], f"pin {c['name']}: pin_key mismatch"
        keys[c["name"]] = c["pin_key"]
        count += 1
    assert keys["digits"] != keys["digits_other"], "PIN digit does not change the key"
    return count


def check_recovery(count: int) -> int:
    data = json.loads((HERE / "recovery.json").read_text(encoding="utf-8"))
    for c in data["cases"]:
        key, vault_id = bytes.fromhex(c["recovery_key"]), bytes.fromhex(c["vault_id"])
        assert encode(key) == c["encoded"], f"recovery {c['name']}: encoding mismatch"
        assert decode(c["encoded"]) == key, f"recovery {c['name']}: decode mismatch"
        kek = hkdf(key, vault_id, "recovery-kek")
        assert kek.hex() == c["recovery_kek"], f"recovery {c['name']}: kek mismatch"
        count += 1
    for c in data["lenient"]:
        assert decode(c["input"]).hex() == c["recovery_key"], "lenient decode mismatch"
        count += 1
    for c in data["invalid"]:
        try:
            decode(c["input"])
        except DecodeError as e:
            assert e.kind == c["error"], f"invalid {c['input']!r}: got {e.kind}"
            count += 1
        else:
            raise AssertionError(f"invalid {c['input']!r} was accepted")
    return count


class SeededRandom:
    """Stream of SHA-256(seed || u64_be(counter)) blocks, counter from 0."""

    def __init__(self, seed: bytes):
        self.seed, self.counter, self.buf = seed, 0, b""

    def read(self, n: int) -> bytes:
        while len(self.buf) < n:
            self.buf += hashlib.sha256(self.seed + self.counter.to_bytes(8, "big")).digest()
            self.counter += 1
        out, self.buf = self.buf[:n], self.buf[n:]
        return out


def slot_aad(slot_type: int, vault_id: bytes, kdf_block: bytes) -> bytes:
    # The recovery slot (0x02) does not bind kdf_block.
    aad = PREFIX + b"slot" + bytes([slot_type]) + vault_id
    return aad if slot_type == 2 else aad + kdf_block


def build_header(vault_id, kdf, salt, slot1, slot2, slot3, vk) -> bytes:
    m, t, p = kdf
    kdf_block = b"\x01" + m.to_bytes(4, "big") + t.to_bytes(4, "big") + bytes([p]) + salt
    body = b"ZENV" + (1).to_bytes(2, "big") + (0).to_bytes(2, "big") + vault_id + kdf_block
    body += bytes([3])
    for ty, data in ((1, slot1), (2, slot2), (3, slot3)):
        body += bytes([ty]) + len(data).to_bytes(2, "big") + data
    mac = hmac.HMAC(hkdf(vk, vault_id, "header-mac"), hashes.SHA256())
    mac.update(body)
    return body + mac.finalize()


def check_header(count: int) -> int:
    cases = json.loads((HERE / "header.json").read_text(encoding="utf-8"))["cases"]
    for c in cases:
        name = c["name"]
        rng = SeededRandom(c["seed_utf8"].encode())
        vault_id, salt, vk, rk = rng.read(16), rng.read(16), rng.read(32), rng.read(32)
        nonce1, nonce2, slot3 = rng.read(12), rng.read(12), rng.read(32)
        kdf = (c["m_kib"], c["t"], c["p"])
        kdf_block = b"\x01" + kdf[0].to_bytes(4, "big") + kdf[1].to_bytes(4, "big")
        kdf_block += bytes([kdf[2]]) + salt

        def master(pw_hex):
            pw = unicodedata.normalize("NFC", bytes.fromhex(pw_hex).decode("utf-8"))
            return hash_secret_raw(
                secret=pw.encode(),
                salt=salt,
                time_cost=kdf[1],
                memory_cost=kdf[0],
                parallelism=kdf[2],
                hash_len=32,
                type=Type.ID,
                version=19,
            )

        mk = master(c["password_utf8_hex"])
        slot1 = nonce1 + AESGCM(hkdf(mk, vault_id, "password-kek")).encrypt(
            nonce1, vk, slot_aad(1, vault_id, kdf_block)
        )
        slot2 = nonce2 + AESGCM(hkdf(rk, vault_id, "recovery-kek")).encrypt(
            nonce2, vk, slot_aad(2, vault_id, kdf_block)
        )
        header = build_header(vault_id, kdf, salt, slot1, slot2, slot3, vk)
        assert len(header) == 244, f"header {name}: length"
        assert header.hex() == c["header"], f"header {name}: bytes mismatch"
        assert vk.hex() == c["vault_key"], f"header {name}: vault key mismatch"
        assert encode(rk) == c["recovery_key"], f"header {name}: recovery key mismatch"
        count += 3

        tag = hkdf(master(c["duress_password_utf8_hex"]), vault_id, "duress-tag")
        with_duress = build_header(vault_id, kdf, salt, slot1, slot2, tag, vk)
        assert with_duress.hex() == c["header_with_duress"], f"header {name}: duress mismatch"
        count += 1
    return count


CHUNK = 1 << 20
OBJ_HEADER = 111


def object_plaintext(n: int) -> bytes:
    return bytes(i % 251 for i in range(n))


def seal(vk: bytes, vault_id: bytes, object_id: bytes, kind: int, rng: SeededRandom, pt: bytes) -> bytes:
    dek, dek_nonce, prefix = rng.read(32), rng.read(12), rng.read(7)
    head = b"ZENO" + (1).to_bytes(2, "big") + bytes([kind, 0]) + vault_id + object_id
    head += CHUNK.to_bytes(4, "big") + prefix
    assert len(head) == 51
    wrapped = AESGCM(vk).encrypt(dek_nonce, dek, PREFIX + b"dek" + head)
    header = head + dek_nonce + wrapped
    assert len(header) == OBJ_HEADER
    aad = hashlib.sha256(header).digest()
    chunks = [pt[i : i + CHUNK] for i in range(0, len(pt), CHUNK)] or [b""]
    body = b""
    for i, ch in enumerate(chunks):
        nonce = prefix + i.to_bytes(4, "big") + (b"\x01" if i == len(chunks) - 1 else b"\x00")
        body += AESGCM(dek).encrypt(nonce, ch, aad)
    return header + body


def build_object(c: dict) -> bytes:
    vk, vault_id, object_id = (bytes.fromhex(c[k]) for k in ("vault_key", "vault_id", "object_id"))
    rng = SeededRandom(c["seed_utf8"].encode())
    return seal(vk, vault_id, object_id, c["kind"], rng, object_plaintext(c["plaintext_len"]))


class ObjectError(Exception):
    def __init__(self, kind: str):
        super().__init__(kind)
        self.kind = kind


def open_object(f: bytes, vk: bytes, vault_id: bytes, object_id: bytes) -> bytes:
    """Reference reader; raises ObjectError('format' | 'mismatch' | 'corrupt')."""
    if len(f) < OBJ_HEADER:
        raise ObjectError("format")
    h = f[:OBJ_HEADER]
    if h[:4] != b"ZENO" or h[4:6] != b"\x00\x01" or h[6] not in (1, 2) or h[7] != 0:
        raise ObjectError("format")
    if int.from_bytes(h[40:44], "big") != CHUNK:
        raise ObjectError("format")
    if h[8:24] != vault_id or h[24:40] != object_id:
        raise ObjectError("mismatch")
    try:
        dek = AESGCM(vk).decrypt(h[51:63], h[63:], PREFIX + b"dek" + h[:51])
    except InvalidTag:
        raise ObjectError("corrupt")
    body = f[OBJ_HEADER:]
    sealed = CHUNK + 16
    n = -(-len(body) // sealed)
    last = len(body) - (n - 1) * sealed if n else 0
    if n == 0 or last < 16 or (n > 1 and last == 16):
        raise ObjectError("corrupt")
    aad, prefix, out = hashlib.sha256(h).digest(), h[44:51], b""
    for i in range(n):
        nonce = prefix + i.to_bytes(4, "big") + (b"\x01" if i == n - 1 else b"\x00")
        try:
            out += AESGCM(dek).decrypt(nonce, body[i * sealed : (i + 1) * sealed], aad)
        except InvalidTag:
            raise ObjectError("corrupt")
    return out


def check_object(count: int) -> int:
    data = json.loads((HERE / "object.json").read_text())
    cases = {c["name"]: c for c in data["cases"]}
    files = {}
    for name, c in cases.items():
        f = files[name] = build_object(c)
        assert len(f) == c["file_len"], f"object {name}: length"
        assert f[:OBJ_HEADER].hex() == c["header"], f"object {name}: header mismatch"
        assert f[OBJ_HEADER : OBJ_HEADER + 64].hex() == c["body_first64"], f"object {name}: body"
        assert hashlib.sha256(f).hexdigest() == c["file_sha256"], f"object {name}: hash mismatch"
        keys = [bytes.fromhex(c[k]) for k in ("vault_key", "vault_id", "object_id")]
        got = open_object(f, *keys)
        assert got == object_plaintext(c["plaintext_len"]), f"object {name}: plaintext"
        count += 1
    for n in data["invalid"]:
        c = cases[n["case"]]
        f = bytearray(files[n["case"]])
        if n["append_first_chunk"]:
            f += f[OBJ_HEADER : OBJ_HEADER + CHUNK + 16]
        if n["truncate_to"] is not None:
            del f[n["truncate_to"] :]
        if n["xor_offset"] is not None:
            f[n["xor_offset"]] ^= n["xor_value"]
        vk = bytes.fromhex(c["vault_key"])
        vid = bytes.fromhex(n["expect_vault_id"] or c["vault_id"])
        oid = bytes.fromhex(n["expect_object_id"] or c["object_id"])
        try:
            open_object(bytes(f), vk, vid, oid)
        except ObjectError as e:
            assert e.kind == n["error"], f"object invalid {n['name']}: got {e.kind}"
        else:
            raise AssertionError(f"object invalid {n['name']}: accepted")
        count += 1
    return count


def canonical_payload(hexstr: str) -> dict:
    raw = bytes.fromhex(hexstr)
    obj = cbor2.loads(raw)
    assert cbor2.dumps(obj, canonical=True) == raw, "payload is not canonical CBOR"
    return obj


def check_journal_chain(c: dict) -> int:
    vk, vault_id, device = (bytes.fromhex(c[k]) for k in ("vault_key", "vault_id", "device"))
    prev, count = bytes(32), 0
    for s in c["segments"]:
        p = canonical_payload(s["payload"])
        assert p["v"] == 1 and p["device"] == device and p["seq"] == s["seq"], "journal payload header"
        assert p["prev"] == prev == bytes.fromhex(s["prev"]), f"journal seq {s['seq']}: prev"
        assert p["ops"] and all("t" in op for op in p["ops"])
        rng = SeededRandom(s["seed_utf8"].encode())
        object_id = rng.read(16)
        f = seal(vk, vault_id, object_id, 2, rng, bytes.fromhex(s["payload"]))
        assert len(f) == s["file_len"], f"journal seq {s['seq']}: length"
        assert hashlib.sha256(f).hexdigest() == s["file_sha256"], f"journal seq {s['seq']}: hash"
        prev = hashlib.sha256(f).digest()
        count += 1
    return count


def fold(segments: list) -> tuple:
    """Independent implementation of vault-format 5.3."""
    ops = []
    for s in segments:
        for i, op in enumerate(s["ops"]):
            ops.append((op.get("t", 0), s["device"], s["seq"], i, op))
    ops.sort(key=lambda x: x[:4])
    items, dead, max_t = {}, set(), 0
    for t, _, _, _, op in ops:
        max_t = max(max_t, t)
        kind, item = op.get("op"), op.get("item")
        if kind == "item.add":
            if item not in dead and item not in items:
                items[item] = {"kind": op["kind"], "objects": dict(op["objects"]), "meta": dict(op["meta"])}
        elif kind == "item.set":
            if item in items:
                v = op["value"]
                if v is None:
                    items[item]["meta"].pop(op["field"], None)
                else:
                    items[item]["meta"][op["field"]] = v
        elif kind == "item.del":
            items.pop(item, None)
            dead.add(item)
    return items, dead, max_t


def check_journal_fold(c: dict) -> int:
    segments = []
    for s in c["segments"]:
        p = canonical_payload(s["payload"])
        assert p["device"].hex() == s["device"] and p["seq"] == s["seq"]
        segments.append(p)
    items, dead, max_t = fold(segments)
    assert max_t == c["max_t"], "journal fold: max_t"
    assert sorted(i.hex() for i in dead) == sorted(c["tombstones"]), "journal fold: tombstones"
    want = {w["item"]: w for w in c["live"]}
    assert sorted(i.hex() for i in items) == sorted(want), "journal fold: live items"
    for iid, it in items.items():
        w = want[iid.hex()]
        assert it["kind"] == w["kind"]
        assert {r: o.hex() for r, o in it["objects"].items()} == w["objects"]
        assert it["meta"] == w["meta"], f"journal fold: meta of {iid.hex()}"
    return len(segments)


def check_journal(count: int) -> int:
    data = json.loads((HERE / "journal.json").read_text())
    return count + check_journal_chain(data["chain"]) + check_journal_fold(data["fold"])


def main() -> int:
    count = check_journal(check_object(check_header(check_recovery(check_pin(check_kdf(0))))))
    print(f"OK {count} vectors")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Independent reference implementation of TCE1 v1 (TC-887), written from the
format spec, not from the Rust code. Regenerates vectors.json:

    python3 gen_vectors.py > vectors.json

Needs the `cryptography` package. All inputs are fixed, so output is stable.
"""
import hashlib
import hmac
import json
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SEG = 1 << 16


def lp(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def context(ident: dict) -> bytes:
    p = ident["purpose"]
    c = lp(b"tinycloud/at-rest/v1") + lp(p.encode())
    if p == "kv-block":
        c += lp(ident["space"].encode()) + lp(bytes.fromhex(ident["content_hash"]))
    elif p == "sql-checkpoint":
        for f in ("service", "space", "name", "checkpoint_content_hash"):
            c += lp(ident[f].encode())
        c += lp(struct.pack(">Q", ident["checkpoint_size_bytes"]))
    elif p == "sql-wal":
        for f in ("service", "space", "name"):
            c += lp(ident[f].encode())
        c += lp(struct.pack(">q", ident["revision"]))
        for f in ("checkpoint_content_hash", "delta_content_hash"):
            c += lp(ident[f].encode())
    else:
        raise ValueError(p)
    return c


def header(dek_id: int, plen: int, salt: bytes) -> bytes:
    h = b"TCE1" + bytes([1, 1, 0, 0]) + struct.pack(">IQ", dek_id, plen) + salt + bytes([16])
    h += bytes(64 - len(h))
    assert len(h) == 64
    return h


def seal(dek: bytes, dek_id: int, salt: bytes, ident: dict, pt: bytes) -> bytes:
    ctx = context(ident)
    hdr = header(dek_id, len(pt), salt)
    k = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
             info=hashlib.sha256(ctx).digest()).derive(dek)
    aead = AESGCM(k)
    aad = ctx + hdr
    n = max(1, -(-len(pt) // SEG))
    out = hdr
    for i in range(n):
        nonce = struct.pack(">I", i) + bytes([1 if i == n - 1 else 0]) + bytes(7)
        out += aead.encrypt(nonce, pt[i * SEG:(i + 1) * SEG], aad)
    assert len(out) == 64 + len(pt) + 16 * n
    return out


def pattern(n: int) -> bytes:
    return bytes(i % 251 for i in range(n))


def blake3_multihash(digest_hex: str) -> str:
    # multihash: varint code 0x1e (blake3-256), varint length 0x20, digest
    return "1e20" + digest_hex


SPACE = "tinycloud:pkh:eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266:default"
DEK = bytes(range(32))
SALT = bytes(range(0x40, 0x60))
HASH = blake3_multihash("ab" * 32)

KV = {"purpose": "kv-block", "space": SPACE, "content_hash": HASH}
CKPT = {"purpose": "sql-checkpoint", "service": "sqlite", "space": SPACE, "name": "notes",
        "checkpoint_content_hash": "bafkreiexamplecheckpoint", "checkpoint_size_bytes": 200000}
WAL = {"purpose": "sql-wal", "service": "sqlite", "space": SPACE, "name": "notes", "revision": 42,
       "checkpoint_content_hash": "bafkreiexamplecheckpoint",
       "delta_content_hash": "bafkreiexampledelta"}

CASES = [
    ("kv-empty", 1, KV, {"hex": ""}),
    ("kv-one-byte", 1, KV, {"hex": "2a"}),
    ("kv-short-text", 7, KV, {"hex": b"hello, tinycloud at rest".hex()}),
    ("kv-one-short-of-segment", 1, KV, {"pattern_len": SEG - 1}),
    ("kv-exact-segment", 1, KV, {"pattern_len": SEG}),
    ("kv-segment-plus-one", 1, KV, {"pattern_len": SEG + 1}),
    ("sql-checkpoint-multi-segment", 3, CKPT, {"pattern_len": 200000}),
    ("sql-wal-short", 0xFFFFFFFF, WAL, {"hex": b"wal frame bytes".hex()}),
]
MAX_PLAIN = (1 << 32) * SEG  # 2^48: the largest plaintext TCE1 can hold
U64_MAX = (1 << 64) - 1


def n_segments(plen: int) -> int:
    return max(1, -(-plen // SEG))


def ct_len(plen: int):
    """None if too large for TCE1."""
    if n_segments(plen) > (1 << 32):
        return None
    c = 64 + plen + 16 * n_segments(plen)
    return c if c <= U64_MAX else None


def pt_len(clen: int):
    """The plaintext length whose ciphertext is exactly clen, else None.
    Searched over the two candidate segment counts, not by formula inversion."""
    if clen < 64 + 16:
        return None
    body = clen - 64
    base = body // (SEG + 16)
    for n in (base, base + 1):
        p = body - 16 * n
        if n >= 1 and p >= 0 and ct_len(p) == clen:
            return p
    return None


def resolve(spec, total):
    """HTTP byte-range semantics: (start, end) inclusive, or None (416)."""
    if total == 0:
        return None
    kind = spec["kind"]
    if kind == "inclusive":
        s, e = spec["start"], spec["end"]
        return (s, min(e, total - 1)) if s <= e and s < total else None
    if kind == "from":
        s = spec["start"]
        return (s, total - 1) if s < total else None
    if kind == "suffix":
        n = spec["length"]
        return (total - min(n, total), total - 1) if n > 0 else None
    raise ValueError(kind)


def map_range(spec, total):
    r = resolve(spec, total)
    if r is None:
        return None
    s, e = r
    first, last = s // SEG, e // SEG
    last_len = min(SEG, total - last * SEG)
    return {"plaintext_start": s, "plaintext_end": e,
            "ciphertext_start": 64 + first * (SEG + 16),
            "ciphertext_end": 64 + last * (SEG + 16) + last_len + 16 - 1}


class Reject(Exception):
    def __init__(self, kind):
        super().__init__(kind)
        self.kind = kind


def open_ct(dek: bytes, ident: dict, ct: bytes) -> bytes:
    """Reference opener: returns plaintext or raises Reject(kind) with kind in
    header / unsupported / integrity."""
    if len(ct) < 5 or ct[0:3] != b"TCE":
        raise Reject("header")
    if not (0x31 <= ct[3] <= 0x39) or ct[4] != ct[3] - 0x30:
        raise Reject("header")
    if ct[4] != 1:
        raise Reject("unsupported")
    if len(ct) < 64:
        raise Reject("header")
    hdr = ct[:64]
    if hdr[5] != 1 or hdr[6] or hdr[7] or hdr[52] != 16 or any(hdr[53:]):
        raise Reject("header")
    dek_id, plen = struct.unpack(">IQ", hdr[8:20])
    if ct_len(plen) is None:
        raise Reject("header")
    if len(ct) != ct_len(plen):
        raise Reject("integrity")
    ctx = context(ident)
    k = HKDF(algorithm=hashes.SHA256(), length=32, salt=hdr[20:52],
             info=hashlib.sha256(ctx).digest()).derive(dek)
    aead = AESGCM(k)
    n = n_segments(plen)
    out = b""
    for i in range(n):
        off = 64 + i * (SEG + 16)
        seg_len = min(SEG, plen - i * SEG) + 16
        nonce = struct.pack(">I", i) + bytes([1 if i == n - 1 else 0]) + bytes(7)
        try:
            out += aead.decrypt(nonce, ct[off:off + seg_len], ctx + hdr)
        except Exception:
            raise Reject("integrity")
    return out


def mutate(ct: bytes, op: dict) -> bytes:
    kind = op["op"]
    if kind == "truncate":
        return ct[:op["len"]]
    if kind == "append":
        return ct + bytes.fromhex(op["hex"])
    if kind == "xor":
        b = bytearray(ct)
        b[op["at"]] ^= op["mask"]
        return bytes(b)
    if kind == "set":
        b = bytearray(ct)
        b[op["at"]:op["at"] + len(bytes.fromhex(op["hex"]))] = bytes.fromhex(op["hex"])
        return bytes(b)
    if kind == "swap_segments":
        a, b_ = op["a"], op["b"]
        sa = slice(64 + a * (SEG + 16), 64 + (a + 1) * (SEG + 16))
        sb = slice(64 + b_ * (SEG + 16), 64 + (b_ + 1) * (SEG + 16))
        b = bytearray(ct)
        b[sa], b[sb] = ct[sb], ct[sa]
        return bytes(b)
    raise ValueError(kind)


NEGATIVE = [
    # (base vector, op, expected rejection)
    ("kv-short-text", {"op": "truncate", "len": 103}, "integrity"),
    ("kv-short-text", {"op": "truncate", "len": 64}, "integrity"),
    ("kv-short-text", {"op": "append", "hex": "00"}, "integrity"),
    ("kv-short-text", {"op": "xor", "at": 103, "mask": 1}, "integrity"),
    ("kv-short-text", {"op": "xor", "at": 64, "mask": 0x80}, "integrity"),
    ("kv-short-text", {"op": "xor", "at": 30, "mask": 1}, "integrity"),
    ("kv-short-text", {"op": "xor", "at": 12 + 7, "mask": 1}, "integrity"),
    ("kv-short-text", {"op": "set", "at": 3, "hex": "3202"}, "unsupported"),
    ("kv-short-text", {"op": "set", "at": 4, "hex": "02"}, "header"),
    ("kv-short-text", {"op": "set", "at": 0, "hex": "58"}, "header"),
    ("kv-short-text", {"op": "set", "at": 6, "hex": "01"}, "header"),
    ("sql-checkpoint-multi-segment", {"op": "swap_segments", "a": 0, "b": 1}, "integrity"),
    ("sql-checkpoint-multi-segment", {"op": "truncate", "len": 64 + 3 * (SEG + 16) - 1}, "integrity"),
    ("sql-checkpoint-multi-segment", {"op": "truncate", "len": 64 + 3 * (SEG + 16)}, "integrity"),
    ("sql-checkpoint-multi-segment", {"op": "xor", "at": 64 + SEG + 16 + 5, "mask": 4}, "integrity"),
]

RANGE_TOTALS = [0, 1, SEG - 1, SEG, SEG + 1, 2 * SEG, 3 * SEG + 5]


def range_specs(total):
    pts = sorted({0, 1, SEG - 1, SEG, SEG + 1, 2 * SEG - 1, 2 * SEG, max(total - 1, 0), total, total + 1})
    specs = [{"kind": "inclusive", "start": 5, "end": 3},
             {"kind": "inclusive", "start": 0, "end": U64_MAX},
             {"kind": "from", "start": U64_MAX},
             {"kind": "suffix", "length": 0},
             {"kind": "suffix", "length": U64_MAX}]
    for p in pts:
        specs.append({"kind": "from", "start": p})
        specs.append({"kind": "suffix", "length": p})
        for q in pts:
            if p <= q:
                specs.append({"kind": "inclusive", "start": p, "end": q})
    return specs


LENGTH_PLAINTEXTS = [0, 1, SEG - 1, SEG, SEG + 1, 2 * SEG, MAX_PLAIN - 1, MAX_PLAIN,
                     MAX_PLAIN + 1, U64_MAX]
LENGTH_CIPHERTEXTS = [0, 63, 64, 79, 80, 81, 64 + SEG + 16, 64 + SEG + 17, 64 + SEG + 32,
                      64 + SEG + 33, 64 + 2 * (SEG + 16), ct_len(MAX_PLAIN), ct_len(MAX_PLAIN) + 1,
                      U64_MAX]




def main():
    vectors = []
    cts = {}
    for name, dek_id, ident, ptspec in CASES:
        pt = bytes.fromhex(ptspec["hex"]) if "hex" in ptspec else pattern(ptspec["pattern_len"])
        ct = seal(DEK, dek_id, SALT, ident, pt)
        assert open_ct(DEK, ident, ct) == pt
        cts[name] = (ct, ident)
        v = {"name": name, "dek": DEK.hex(), "dek_id": dek_id, "salt": SALT.hex(),
             "identity": ident, "plaintext": ptspec,
             "ciphertext_len": len(ct), "ciphertext_sha256": hashlib.sha256(ct).hexdigest()}
        if len(ct) <= 256:
            v["ciphertext"] = ct.hex()
        else:
            v["ciphertext_head"] = ct[:96].hex()
        vectors.append(v)

    negative = []
    for base, op, expected in NEGATIVE:
        ct, ident = cts[base]
        try:
            open_ct(DEK, ident, mutate(ct, op))
            raise AssertionError(f"reference accepted {base} {op}")
        except Reject as r:
            assert r.kind == expected, (base, op, r.kind)
        negative.append({"base": base, **op, "expect": expected})

    lengths = {
        "plaintext_to_ciphertext": [{"plaintext_len": p, "ciphertext_len": ct_len(p)}
                                    for p in LENGTH_PLAINTEXTS],
        "ciphertext_to_plaintext": [{"ciphertext_len": c, "plaintext_len": pt_len(c)}
                                    for c in LENGTH_CIPHERTEXTS],
    }
    ranges = [{"total": t, "spec": s, "mapped": map_range(s, t)}
              for t in RANGE_TOTALS for s in range_specs(t)]

    nk = bytes(range(0x80, 0xA0))

    def tag(fields):
        return hmac.new(nk, b"".join(lp(f) for f in fields), hashlib.sha256).digest()

    import base64

    def b64(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    space_tag = b64(tag([b"space", SPACE.encode()])[:16])
    obj = b64(tag([b"obj", SPACE.encode(), bytes.fromhex(HASH)]))
    names = [{"nk": nk.hex(), "space": SPACE, "content_hash": HASH, "space_tag": space_tag,
              "object_name": f"v1/{space_tag}/{obj}"}]

    print(json.dumps({
        "format": "TCE1 v1 (TC-887)",
        "pattern": "plaintext byte i = i mod 251",
        "vectors": vectors,
        "object_names": names,
        "negative": negative,
        "lengths": lengths,
        "ranges": ranges,
    }, indent=1))


if __name__ == "__main__":
    main()

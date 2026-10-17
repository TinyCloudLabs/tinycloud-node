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


def main():
    vectors = []
    for name, dek_id, ident, ptspec in CASES:
        pt = bytes.fromhex(ptspec["hex"]) if "hex" in ptspec else pattern(ptspec["pattern_len"])
        ct = seal(DEK, dek_id, SALT, ident, pt)
        v = {"name": name, "dek": DEK.hex(), "dek_id": dek_id, "salt": SALT.hex(),
             "identity": ident, "plaintext": ptspec,
             "ciphertext_len": len(ct), "ciphertext_sha256": hashlib.sha256(ct).hexdigest()}
        if len(ct) <= 256:
            v["ciphertext"] = ct.hex()
        else:
            v["ciphertext_head"] = ct[:96].hex()
        vectors.append(v)

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
    }, indent=1))


if __name__ == "__main__":
    main()

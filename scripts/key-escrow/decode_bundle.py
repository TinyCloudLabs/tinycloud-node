#!/usr/bin/env python3
"""Verify (or, for a restore, decode) a tinycloud-node key backup bundle offline.

The bundle is what `tinycloud node key backup` writes (BackupBundleV1,
tinycloud-node-server/src/node_control/key_provider.rs): scrypt(log_n=15, r=8,
p=1, 32) KEK, XChaCha20-Poly1305, AAD b"tinycloud-node/key-backup/v1".

Default (verify): decrypt in memory, derive the node's public identity the way
tinycloud-core/src/keys.rs does (blake3(root || context) -> Ed25519 seed), and
compare it with a node-keys document (the live
/.well-known/tinycloud/node-keys URL or a saved copy). Prints only public
values and PASS/FAIL; the root secret is never written anywhere.

--emit-secret (restore only): write the root secret to stdout as url-safe
base64 without padding (the TINYCLOUD_KEYS_SECRET form), for piping straight
into the sealing step. Never redirect it to a file on a shared host.

--from-app-root (TC-3554): instead of a bundle, read a dstack app root key
(the KMS AppKeyResponse.k256_key, 64 hex chars) from stdin and derive the node
root the way the guest agent's v0 GetKey does (dstack guest-api-v0.md:140-150):
HKDF-SHA256(salt=b"RATLS", IKM=k256_key, info=b"tinycloud/keys/primary", L=32).
The node uses those 32 bytes directly as its root (lib.rs Keys::Dstack).

--from-app-root also REQUIRES the KMS issuance check: --app-id, --k256-signature
(AppKeyResponse.k256_signature, r||s||v hex) and --kms-root-pubkey (the trusted
KMS root secp256k1 key for that root epoch, SEC1 hex). The signature must verify
over keccak256("dstack-kms-issued:" || app_id || sec1_compressed(app_root_pubkey))
(dstack guest-api-v0.md:264-306; app epoch 0 format, app-key-epochs.md:158-160),
high-S rejected. Without a passing check nothing is derived or emitted.

Usage:
  decode_bundle.py BUNDLE --passphrase-file F --node-keys URL_OR_FILE
  decode_bundle.py BUNDLE --passphrase-file F --emit-secret
  decode_bundle.py --from-app-root --app-id HEX --k256-signature HEX --kms-root-pubkey HEX \
      (--node-keys URL_OR_FILE | --emit-secret)  < app-root-hex
The passphrase file may be /dev/stdin. Needs: python3, cryptography, blake3.
"""
import argparse
import base64
import hashlib
import json
import struct
import sys
import urllib.request

from blake3 import blake3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

AAD = b"tinycloud-node/key-backup/v1"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b58(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def _rotl(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _qr(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = _rotl(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = _rotl(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = _rotl(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = _rotl(x[b] ^ x[c], 7)


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    x = list(struct.unpack("<4I", b"expand 32-byte k"))
    x += list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))
    for _ in range(10):
        _qr(x, 0, 4, 8, 12); _qr(x, 1, 5, 9, 13); _qr(x, 2, 6, 10, 14); _qr(x, 3, 7, 11, 15)
        _qr(x, 0, 5, 10, 15); _qr(x, 1, 6, 11, 12); _qr(x, 2, 7, 8, 13); _qr(x, 3, 4, 9, 14)
    return struct.pack("<8I", *(x[0:4] + x[12:16]))


def decrypt_bundle(bundle: dict, passphrase: bytes) -> bytes:
    if bundle.get("version") != 1:
        sys.exit(f"unsupported bundle version {bundle.get('version')}")
    kek = hashlib.scrypt(passphrase, salt=b64u_decode(bundle["kdfSalt"]), n=1 << 15, r=8, p=1,
                         maxmem=64 * 1024 * 1024, dklen=32)
    nonce = b64u_decode(bundle["nonce"])
    if len(nonce) != 24:
        sys.exit("invalid nonce length")
    subkey = hchacha20(kek, nonce[:16])
    return ChaCha20Poly1305(subkey).decrypt(b"\0\0\0\0" + nonce[16:],
                                            b64u_decode(bundle["ciphertext"]), AAD)


def public_key(root: bytes, context: bytes) -> bytes:
    seed = blake3(root + context).digest()[:32]
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)


def did_key(pub: bytes) -> str:
    return "did:key:z" + b58(b"\xed\x01" + pub)


def derived_public_identity(root: bytes) -> dict:
    renewer = public_key(root, b"tinycloud/node/renewer/v1")
    return {
        "nodeDid": did_key(public_key(root, b"tinycloud/node/identity")),
        "shareInvitationPublicKey": b64u_encode(
            public_key(root, b"tinycloud/share-email/invitation-signing")),
        "renewerDid": did_key(renewer),
        "renewerPublicKey": b64u_encode(renewer),
    }


def root_from_app_root(app_root: bytes, path: bytes = b"tinycloud/keys/primary") -> bytes:
    """dstack v0 GetKey: HKDF-SHA256(salt "RATLS", IKM app root k256 key, info path)."""
    if len(app_root) != 32:
        raise ValueError(f"app root key must be 32 bytes, got {len(app_root)}")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"RATLS", info=path).derive(app_root)


_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_KECCAK_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
               [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M64 = (1 << 64) - 1


def keccak256(data: bytes) -> bytes:
    """Keccak-256 with the original 0x01 padding (Ethereum), not SHA3-256."""
    def rol(v, n):
        return ((v << n) | (v >> (64 - n))) & _M64 if n else v
    rate = 136
    buf = bytearray(data) + b"\x01" + b"\x00" * ((-len(data) - 1) % rate)
    buf[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(buf), rate):
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(buf[off + 8 * i:off + 8 * i + 8], "little")
        for rc in _KECCAK_RC:
            c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
            d = [c[(x - 1) % 5] ^ rol(c[(x + 1) % 5], 1) for x in range(5)]
            a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
            b = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    b[y][(2 * x + 3 * y) % 5] = rol(a[x][y], _KECCAK_ROT[x][y])
            a = [[b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y]) for y in range(5)]
                 for x in range(5)]
            a[0][0] ^= rc
    return b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def verify_kms_issuance(app_root: bytes, app_id: bytes, signature: bytes,
                        kms_root_pubkey: bytes) -> bytes:
    """Check the KMS root signed this app root key for app_id (app epoch 0 format).

    Returns the SEC1-compressed app root public key; raises on any failure.
    """
    if len(app_id) != 20:
        raise ValueError(f"app id must be 20 bytes, got {len(app_id)}")
    if len(signature) != 65:
        raise ValueError(f"k256_signature must be 65 bytes (r||s||v), got {len(signature)}")
    app_pub = ec.derive_private_key(int.from_bytes(app_root, "big"), ec.SECP256K1()) \
        .public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:64], "big")
    if not (0 < r < SECP256K1_N and 0 < s <= SECP256K1_N // 2):
        raise ValueError("k256_signature: r/s out of range or high-S")
    digest = keccak256(b"dstack-kms-issued:" + app_id + app_pub)
    root = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), kms_root_pubkey)
    try:
        root.verify(encode_dss_signature(r, s), digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    except InvalidSignature:
        raise ValueError("k256_signature does not verify under --kms-root-pubkey") from None
    return app_pub


def load_node_keys(source: str) -> dict:
    if source.startswith("https://") or source.startswith("http://"):
        with urllib.request.urlopen(source, timeout=20) as resp:
            return json.load(resp)
    with open(source) as f:
        return json.load(f)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle", nargs="?")
    ap.add_argument("--passphrase-file")
    ap.add_argument("--from-app-root", action="store_true",
                    help="read a dstack app root key (64 hex) from stdin instead of a bundle")
    ap.add_argument("--app-id", help="--from-app-root: dstack app id, 20 bytes hex")
    ap.add_argument("--k256-signature", help="--from-app-root: AppKeyResponse.k256_signature hex")
    ap.add_argument("--kms-root-pubkey",
                    help="--from-app-root: trusted KMS root secp256k1 pubkey (SEC1 hex)")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--node-keys", help="URL or file of /.well-known/tinycloud/node-keys")
    mode.add_argument("--emit-secret", action="store_true")
    args = ap.parse_args()

    bundle = None
    if args.from_app_root:
        if args.bundle or args.passphrase_file:
            ap.error("--from-app-root takes no bundle or passphrase file")
        if not (args.app_id and args.k256_signature and args.kms_root_pubkey):
            ap.error("--from-app-root requires --app-id, --k256-signature and --kms-root-pubkey")
        app_root = bytes.fromhex(sys.stdin.read().strip())
        try:
            app_pub = verify_kms_issuance(
                app_root, bytes.fromhex(args.app_id.removeprefix("0x")),
                bytes.fromhex(args.k256_signature.removeprefix("0x")),
                bytes.fromhex(args.kms_root_pubkey.removeprefix("0x")))
        except ValueError as e:
            sys.exit(f"FAIL: KMS issuance check: {e}")
        root = root_from_app_root(app_root)
        del app_root
        print(f"app root: KMS issuance check PASS, app_root_pubkey {app_pub.hex()} "
              f"root_len {len(root)}", file=sys.stderr)
    else:
        if not args.bundle or not args.passphrase_file:
            ap.error("a bundle and --passphrase-file are required without --from-app-root")
        with open(args.bundle) as f:
            bundle = json.load(f)
        with open(args.passphrase_file, "rb") as f:
            passphrase = f.read().rstrip(b"\r\n")
        if not passphrase:
            sys.exit("passphrase is empty")
        root = decrypt_bundle(bundle, passphrase)
        print(f"bundle: backend {bundle['backend']} nodeDid {bundle['nodeDid']} root_len {len(root)}",
              file=sys.stderr)

    if args.emit_secret:
        sys.stdout.write(b64u_encode(root))
        return

    derived = derived_public_identity(root)
    expected = load_node_keys(args.node_keys)
    ok = bundle is None or derived["nodeDid"] == bundle["nodeDid"]
    for field, value in derived.items():
        match = expected.get(field) == value
        ok = ok and match
        print(f"{field}: {'match' if match else 'MISMATCH'} {value}")
    source = "app root" if bundle is None else "bundle"
    print(f"PASS: {source} restores the published node identity" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Independent deterministic generator for the m1-g-06 grant-output vectors."""

from __future__ import annotations

import base64
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import base58
import blake3
import cbor2
from eth_keys import keys
from eth_utils import keccak
from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parent
DEFAULT_INSTANT = 1783684800
NOW = DEFAULT_INSTANT
EXP = NOW + 300
PARENT_ISSUED_OFFSET = -3600
PARENT_WINDOW_SECONDS = 31539600
PARENT_ISSUED = NOW + PARENT_ISSUED_OFFSET
PARENT_EXP = PARENT_ISSUED + PARENT_WINDOW_SECONDS
OUTPUT_DIR = ROOT
OWNER_PRIVATE = bytes.fromhex("00" * 31 + "01")
GRANT_SEED = bytes.fromhex("22" * 32)
POLICY_SEED = bytes.fromhex("11" * 32)
HOLDER_SEED = bytes.fromhex("33" * 32)
ISSUANCE_ID = "iss_m1g06_00000001"
POLICY_ID = "pol_m1g06_transcript"


def instant_text(value: int, milliseconds: bool = True) -> str:
    suffix = ".000Z" if milliseconds else "Z"
    return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + suffix


def b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64u_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def compact(value) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def did_key(seed: bytes) -> tuple[str, bytes]:
    public = bytes(SigningKey(seed).verify_key)
    multibase = "z" + base58.b58encode(b"\xed\x01" + public).decode("ascii")
    return "did:key:" + multibase, public


def varint(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7f) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def base32lower(value: bytes) -> str:
    return base64.b32encode(value).rstrip(b"=").decode("ascii").lower()


def cid_raw_blake3(value: bytes) -> tuple[str, bytes]:
    digest = blake3.blake3(value).digest()
    raw = varint(1) + varint(0x55) + varint(0x1e) + varint(32) + digest
    return "b" + base32lower(raw), raw


GRANT_DID, GRANT_PUBLIC = did_key(GRANT_SEED)
POLICY_DID, _ = did_key(POLICY_SEED)
HOLDER_DID, _ = did_key(HOLDER_SEED)
GRANT_VM = GRANT_DID + "#" + GRANT_DID.removeprefix("did:key:")
POLICY_VM = POLICY_DID + "#" + POLICY_DID.removeprefix("did:key:")
OWNER_KEY = keys.PrivateKey(OWNER_PRIVATE)
OWNER_ADDRESS = OWNER_KEY.public_key.to_checksum_address()
OWNER_DID = f"did:pkh:eip155:1:{OWNER_ADDRESS}"
RESOURCE = (
    f"tinycloud:pkh:eip155:1:{OWNER_ADDRESS}:default/"
    "sql/xyz.tinycloud.listen/conversations"
)
CAVEAT = {
    "mode": "constrained-statements",
    "readOnly": True,
    "statements": [
        {
            "name": "listen.getConversation",
            "sql": "SELECT id, title, source, source_id, source_url, started_at, ended_at, duration_secs, summary, metadata, transcript_json, transcript_text, created_at, updated_at FROM conversation WHERE id = ?",
            "fixedParams": [{"index": 0, "value": "conv_456"}],
        },
        {
            "name": "listen.listParticipants",
            "sql": "SELECT id, name, email, speaker_label FROM participant WHERE conversation_id = ? ORDER BY COALESCE(speaker_label, name), id",
            "fixedParams": [{"index": 0, "value": "conv_456"}],
        },
    ],
}
POLICY_CAPABILITY = {
    "service": "tinycloud.sql",
    "space": "applications",
    "path": "xyz.tinycloud.listen/conversations",
    "actions": ["tinycloud.sql/read"],
    "caveats": CAVEAT,
}
# policy_core::PolicyCapability::capability_hash_hex hashes the normalized
# capability's JCS bytes with this domain separator. This generator reproduces
# that algorithm independently; it does not consume Rust-produced output.
CAPABILITY_HASH = hashlib.sha256(
    b"xyz.tinycloud.policy/PolicyCapability/v0\0" + compact(POLICY_CAPABILITY)
).hexdigest()


def eip191_sign(message: bytes) -> bytes:
    framed = b"\x19Ethereum Signed Message:\n" + str(len(message)).encode("ascii") + message
    signature = OWNER_KEY.sign_msg_hash(keccak(framed))
    return (
        signature.r.to_bytes(32, "big")
        + signature.s.to_bytes(32, "big")
        + bytes([signature.v + 27])
    )


def make_parent() -> dict:
    parent_issued_text = instant_text(PARENT_ISSUED)
    parent_exp_text = instant_text(PARENT_EXP)
    recap = {
        "att": {
            RESOURCE: {
                "tinycloud.kv/get": [{}],
                "tinycloud.sql/read": [{}],
            }
        },
        "prf": [],
    }
    recap_bytes = compact(recap)
    recap_uri = "urn:recap:" + b64u(recap_bytes)
    statement = (
        "I further authorize the stated URI to perform the following actions on my behalf:"
        f" (1) 'tinycloud.kv': 'get' for '{RESOURCE}'."
        f" (2) 'tinycloud.sql': 'read' for '{RESOURCE}'."
    )
    message = (
        "policy-engine.example wants you to sign in with your Ethereum account:\n"
        f"{OWNER_ADDRESS}\n\n{statement}\n\n"
        f"URI: {GRANT_DID}\nVersion: 1\nChain ID: 1\nNonce: m1g060001\n"
        f"Issued At: {parent_issued_text}\n"
        f"Expiration Time: {parent_exp_text}\nResources:\n- {recap_uri}"
    )
    signature = eip191_sign(message.encode("utf-8"))
    payload = {
        "domain": "policy-engine.example",
        "iss": OWNER_DID,
        "statement": statement,
        "aud": GRANT_DID,
        "version": 1,
        "nonce": "m1g060001",
        "iat": parent_issued_text,
        "exp": parent_exp_text,
        "resources": [recap_uri],
    }
    cacao = {
        "h": {"t": "eip4361"},
        "p": payload,
        "s": {"s": signature, "t": "eip191"},
    }
    # serde_ipld_dagcbor::to_vec uses DAG-CBOR's deterministic map ordering:
    # encoded key length first, then bytewise lexical order. cbor2's canonical
    # mode reproduces that ordering independently; its default insertion-order
    # encoding is not byte-compatible with the pinned node serializer.
    dag_cbor = cbor2.dumps(cacao, canonical=True)
    cid, cid_bytes = cid_raw_blake3(dag_cbor)
    return {
        "format": "siwe-cacao-eip191",
        "issuer": OWNER_DID,
        "audience": GRANT_DID,
        "delegateeLookupValue": GRANT_DID,
        "issuedAt": parent_issued_text,
        "expiresAt": parent_exp_text,
        "siweMessage": message,
        "signatureHex": signature.hex(),
        "recap": recap,
        "recapJcsUtf8Hex": recap_bytes.hex(),
        "recapResource": recap_uri,
        "cacao": {
            "h": cacao["h"],
            "p": payload,
            "s": {"sHex": signature.hex(), "t": "eip191"},
        },
        "dagCborBase64Url": b64u(dag_cbor),
        "dagCborHex": dag_cbor.hex(),
        "dagCborSerializerContract": "serde_ipld_dagcbor::to_vec(SiweCacao)@0.6.4",
        "expectedCid": cid,
        "expectedCidBytesHex": cid_bytes.hex(),
    }


def make_ucan(parent_cid: str, overrides=None, seed=GRANT_SEED) -> dict:
    facts = [{
        "xyz.tinycloud.policy/delegationMode": "terminal",
        "xyz.tinycloud.policy/policyId": POLICY_ID,
        "xyz.tinycloud.policy/capabilityHashHex": CAPABILITY_HASH,
        "xyz.tinycloud.policy/revocationMode": "refresh_only",
        "xyz.tinycloud.policy/issuanceId": ISSUANCE_ID,
    }]
    payload = {
        "iss": GRANT_VM,
        "aud": HOLDER_DID,
        "nbf": NOW,
        "exp": EXP,
        "nnc": "m1-g-06-fixed-nonce",
        "fct": facts,
        "prf": [parent_cid],
        "att": {
            RESOURCE: {
                # The pinned UCAN capabilities decoder rejects an empty
                # NotaBeneCollection. `[{}]` is its serialized, unconstrained
                # caveat form and decodes to Caveats::default().
                "tinycloud.kv/get": [{}],
                "tinycloud.sql/read": [CAVEAT],
            }
        },
    }
    if overrides:
        payload.update(overrides)
    signer_did, public = did_key(seed)
    header = {
        "alg": "EdDSA",
        "typ": "JWT",
        "ucv": "0.10.0",
        "jwk": {"kty": "OKP", "crv": "Ed25519", "x": b64u(public), "alg": "EdDSA"},
    }
    signing_input = b64u(compact(header)) + "." + b64u(compact(payload))
    signature = SigningKey(seed).sign(signing_input.encode("ascii")).signature
    encoded = signing_input + "." + b64u(signature)
    cid, cid_bytes = cid_raw_blake3(encoded.encode("ascii"))
    return {
        "encoded": encoded,
        "header": header,
        "payload": payload,
        "signerDid": signer_did,
        "signingInputAscii": signing_input,
        "signatureHex": signature.hex(),
        "delegationId": cid,
        "delegationIdBytesHex": cid_bytes.hex(),
    }


def replace_signature(ucan: dict, signature: bytes) -> dict:
    """Return a self-consistent vector after replacing the compact-JWS signature."""
    signing_input = ucan["signingInputAscii"]
    encoded = signing_input + "." + b64u(signature)
    cid, cid_bytes = cid_raw_blake3(encoded.encode("ascii"))
    return {
        **ucan,
        "encoded": encoded,
        "signatureHex": signature.hex(),
        "delegationId": cid,
        "delegationIdBytesHex": cid_bytes.hex(),
    }


def case(name, layer, verdict, reason, consult, **extra):
    return {
        "case": name,
        "enforcementLayer": layer,
        "expectedVerdict": verdict,
        "reason": reason,
        "consultCase": consult,
        **extra,
    }


def write(name: str, description: str, cases: list[dict], **extra):
    value = {"description": description, **extra, "cases": cases}
    (OUTPUT_DIR / name).write_text(json.dumps(value, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--at-instant", type=int, default=DEFAULT_INSTANT,
                        help="generation instant in epoch seconds")
    parser.add_argument("--output-dir", type=Path, default=ROOT,
                        help="directory to receive generated JSON files")
    args = parser.parse_args()

    global NOW, EXP, PARENT_ISSUED, PARENT_EXP, OUTPUT_DIR
    NOW = args.at_instant
    EXP = NOW + 300
    PARENT_ISSUED = NOW + PARENT_ISSUED_OFFSET
    PARENT_EXP = PARENT_ISSUED + PARENT_WINDOW_SECONDS
    OUTPUT_DIR = args.output_dir.resolve()
    if NOW != DEFAULT_INSTANT and OUTPUT_DIR == ROOT:
        parser.error("non-default instants are live-test material; use --output-dir")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    parent = make_parent()
    valid = make_ucan(parent["expectedCid"])
    portable = {
        "delegationId": valid["delegationId"],
        "issuanceId": ISSUANCE_ID,
        "issuerDid": GRANT_DID,
        "holderDid": HOLDER_DID,
        "policyId": POLICY_ID,
        "capabilityHashHex": CAPABILITY_HASH,
        "revocationMode": "refresh_only",
        "issuedAt": instant_text(NOW, milliseconds=False),
        "expiresAt": instant_text(EXP, milliseconds=False),
        "terminal": True,
        "encoded": valid["encoded"],
    }
    write(
        "accept.json",
        "Node-native grant-output accept vectors pinned to tinycloud-node 4b6f3fca.",
        [
            case("valid-bounded-node-native-ucan", "node-import", "accept", "valid-bounded-grant",
                 "consult-7-01", portableDelegation=portable, ucan=valid,
                 expectedExtractedCapability={"resource": RESOURCE,
                                              "ability": "tinycloud.sql/read",
                                              "notaBene": {"0": CAVEAT}}),
            case("deterministic-native-identity-and-ledger-link", "audit", "accept",
                 "same-signed-bytes-same-native-cid", "consult-8-accept-identity",
                 issuanceRecord={"issuanceId": ISSUANCE_ID, "encoded": valid["encoded"],
                                 "delegationId": valid["delegationId"], "atomicCommit": True},
                 expectedDelegationId=valid["delegationId"],
                 expectedDelegationIdBytesHex=valid["delegationIdBytesHex"]),
            case("empty-parent-caveats-permit-child-narrowing", "node-import", "accept",
                 "empty-parent-caveats-permit-narrowing", "consult-8-parent-semantics",
                 ucan=valid, parentCid=parent["expectedCid"]),
        ],
        pinnedConsumer="tinycloud-node@4b6f3fca",
        fixedInstantEpochSeconds=NOW,
        parentFormatVector=parent,
    )

    wrong_configured_issuer = make_ucan(
        parent["expectedCid"], {"iss": POLICY_VM}, seed=POLICY_SEED
    )
    no_terminal_facts = valid["payload"]["fct"][0].copy()
    no_terminal_facts.pop("xyz.tinycloud.policy/delegationMode")
    no_terminal = make_ucan(parent["expectedCid"], {"fct": [no_terminal_facts]})
    ttl = make_ucan(parent["expectedCid"], {"exp": EXP + 1})
    duplicate = make_ucan(parent["expectedCid"], {"fct": [
        valid["payload"]["fct"][0], {"xyz.tinycloud.policy/issuanceId": ISSUANCE_ID}
    ]})
    malformed_facts = valid["payload"]["fct"][0].copy()
    malformed_facts["xyz.tinycloud.policy/capabilityHashHex"] = "not-a-hash"
    malformed = make_ucan(parent["expectedCid"], {"fct": [malformed_facts]})
    outside = RESOURCE.replace("conversations", "private-ledger")
    widened = make_ucan(parent["expectedCid"], {
        "att": {outside: {"tinycloud.sql/read": [CAVEAT]}}
    })
    write("producer-reject.json", "Producer/engine rejects before node import.", [
        case("grant-issuer-config-record-mismatch", "producer/engine", "reject",
             "unauthorized-issuer", "consult-7-02", ucan=wrong_configured_issuer,
             configuredGrantIssuerDid=GRANT_DID,
             engineRecordGrantIssuerDid=POLICY_DID,
             observedTokenIssuerDid=POLICY_DID),
        case("owner-impersonation", "producer/engine", "reject",
             "owner-did-is-not-the-grant-issuer", "consult-7-02",
             configuredGrantIssuerDid=GRANT_DID,
             engineRecordGrantIssuerDid=GRANT_DID,
             observedTokenIssuerDid=OWNER_DID),
        case("missing-terminal-mode-fact", "producer/engine", "reject",
             "missing-terminal-mode-fact", "consult-7-03", ucan=no_terminal),
        case("expiry-beyond-policy-presentation-or-ttl-ceiling", "producer/engine", "reject",
             "expiry-ceiling-exceeded", "consult-7-04", ucan=ttl,
             ceilings={"policyEpochSeconds": EXP + 60, "presentationEpochSeconds": EXP + 60,
                       "maxTtlSeconds": 300, "parentEpochSeconds": PARENT_EXP}),
        case("expiry-beyond-policy-ceiling", "producer/engine", "reject",
             "expiry-ceiling-exceeded", "consult-7-04", ucan=valid,
             ceilings={"policyEpochSeconds": EXP - 1, "presentationEpochSeconds": EXP + 60,
                       "maxTtlSeconds": 300, "parentEpochSeconds": PARENT_EXP}),
        case("expiry-beyond-presentation-validity", "producer/engine", "reject",
             "expiry-ceiling-exceeded", "consult-7-04", ucan=valid,
             ceilings={"policyEpochSeconds": EXP + 60, "presentationEpochSeconds": EXP - 1,
                       "maxTtlSeconds": 300, "parentEpochSeconds": PARENT_EXP}),
        case("malformed-or-duplicate-provenance-facts", "producer/engine", "reject",
             "duplicate-provenance-fact", "consult-7-provenance", ucan=duplicate),
        case("malformed-provenance-fact", "producer/engine", "reject",
             "malformed-provenance-fact", "consult-7-provenance", ucan=malformed),
        case("capability-exceeds-configured-parent-bounds", "producer/engine", "reject",
             "issue-time-parent-containment-failure", "consult-7-05", ucan=widened,
             configuredParentCid=parent["expectedCid"]),
    ])

    _, signature_segment = valid["encoded"].rsplit(".", 1)
    invalid_signature = bytearray(b64u_decode(signature_segment))
    invalid_signature[0] ^= 0x01
    bad_sig = replace_signature(valid, bytes(invalid_signature))
    absent_cid, _ = cid_raw_blake3(b"absent-parent")
    absent = make_ucan(absent_cid)
    late = make_ucan(parent["expectedCid"], {"exp": PARENT_EXP + 1})
    write("node-import-reject.json", "tinycloud-node /delegate import rejects at 4b6f3fca.", [
        case("invalid-signature", "node-import", "reject", "invalid-signature",
             "consult-7-signature-time", ucan=bad_sig, validationTimeEpochSeconds=NOW),
        case("invalid-time", "node-import", "reject", "expired-at-import",
             "consult-7-signature-time", ucan=valid, validationTimeEpochSeconds=EXP + 1),
        case("missing-persisted-parent", "node-import", "reject", "missing-parent",
             "consult-7-06", ucan=absent, persistedParentCids=[]),
        case("terminal-parent", "node-import", "reject", "terminal-parent",
             "consult-7-07", ucan=valid,
             alternatePersistedParent={"cid": parent["expectedCid"], "delegationMode": "terminal"}),
        case("parent-time-nesting-violation", "node-import", "reject", "child-exp-after-parent-exp",
             "consult-7-08", ucan=late, parentExpiresAtEpochSeconds=PARENT_EXP),
        case("resource-or-ability-containment-failure", "node-import", "reject",
             "capability-not-contained", "consult-7-09", ucan=widened,
             persistedParentCid=parent["expectedCid"]),
        case("caveat-containment-failure", "node-import", "reject", "caveat-not-contained",
             "consult-7-10", ucan=valid,
             alternateParentCaveat={"mode": "constrained-statements", "readOnly": True,
                                    "statements": [{"name": "different", "sql": "SELECT 1",
                                                    "fixedParams": []}]}),
    ])

    write("node-invocation-reject.json", "tinycloud-node invocation-only rejects at 4b6f3fca.", [
        case("holder-audience-mismatch", "node-invocation", "reject", "wrong-invoker",
             "consult-7-11", importedDelegationId=valid["delegationId"],
             invokerDid=POLICY_DID, expectedAudience=HOLDER_DID),
        case("expired-proof-chain", "node-invocation", "reject", "proof-chain-expired",
             "consult-7-invocation-expiry", importedDelegationId=valid["delegationId"],
             invocationTimeEpochSeconds=EXP + 1),
        case("revoked-parent", "node-invocation", "reject", "revoked-ancestor",
             "consult-8-revocation-layer", importedDelegationId=valid["delegationId"],
             revokedCid=parent["expectedCid"]),
        case("unauthorized-requested-action", "node-invocation", "reject",
             "requested-action-not-authorized", "consult-7-action",
             importedDelegationId=valid["delegationId"],
             requested={"resource": RESOURCE, "ability": "tinycloud.sql/write"}),
    ])

    write("audit-reject.json", "Audit-layer issuanceId/native-CID linkage rejects from consult #8.", [
        case("issuance-id-without-ledger-record", "audit", "reject", "ledger-record-missing",
             "consult-8-01", ucan=valid, ledgerRecord=None),
        case("ledger-record-points-to-different-cid", "audit", "reject", "ledger-cid-mismatch",
             "consult-8-02", ucan=valid,
             ledgerRecord={"issuanceId": ISSUANCE_ID, "delegationId": absent_cid,
                           "encoded": valid["encoded"], "atomicCommit": True}),
        case("duplicate-issuance-id-different-signed-bytes", "audit", "reject",
             "duplicate-issuance-id-conflict", "consult-8-03", ucan=valid,
             ledgerRecords=[{"issuanceId": ISSUANCE_ID, "encoded": valid["encoded"]},
                            {"issuanceId": ISSUANCE_ID, "encoded": ttl["encoded"]}]),
        case("response-before-atomically-durable-linkage", "audit", "reject",
             "issuance-linkage-not-atomic", "consult-8-04", ucan=valid,
             ledgerRecord={"issuanceId": ISSUANCE_ID, "delegationId": valid["delegationId"],
                           "encoded": valid["encoded"], "atomicCommit": False}),
    ])


if __name__ == "__main__":
    main()

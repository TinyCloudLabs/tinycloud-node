#!/usr/bin/env node
/* Deterministic, test-only contract builder. It deliberately has no runtime-package dependency. */
import { createCipheriv, createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { blake3 } from "@noble/hashes/blake3";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../../../");
const spec = resolve(root, "specs/email-claim-v1");
const utf8 = (value) => new TextEncoder().encode(value);
const clone = (value) => JSON.parse(JSON.stringify(value));
const b64 = (value) => Buffer.from(value).toString("base64url");
const sha256 = (value) => new Uint8Array(createHash("sha256").update(value).digest());
const digest = (value) => b64(sha256(value));
const hex = (value) => new Uint8Array(Buffer.from(value, "hex"));
const fixedBytes = (length, start = 0) => Uint8Array.from({ length }, (_, index) => (start + index) & 255);

function assertString(value) {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const n = value.charCodeAt(i + 1);
      if (!(n >= 0xdc00 && n <= 0xdfff)) throw new TypeError("lone surrogate");
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) throw new TypeError("lone surrogate");
  }
}
function jcs(value) {
  if (value === null) return "null";
  if (typeof value === "string") { assertString(value); return JSON.stringify(value); }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isSafeInteger(value) || Object.is(value, -0)) throw new TypeError("unsafe number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((item) => { if (item === undefined) throw new TypeError("undefined"); return jcs(item); }).join(",")}]`;
  if (typeof value !== "object" || value === null || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) throw new TypeError("non-plain value");
  return `{${Object.keys(value).sort().map((key) => { assertString(key); if (value[key] === undefined) throw new TypeError("undefined"); return `${JSON.stringify(key)}:${jcs(value[key])}`; }).join(",")}}`;
}
function b32(bytes) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let buffer = 0; let bits = 0; let out = "";
  for (const byte of bytes) { buffer = (buffer << 8) | byte; bits += 8; while (bits >= 5) { bits -= 5; out += alphabet[(buffer >>> bits) & 31]; } }
  if (bits) out += alphabet[(buffer << (5 - bits)) & 31];
  return out;
}
function cid(bytes) { return `b${b32(Uint8Array.of(1, 0x55, 0x12, 0x20, ...sha256(bytes)))}`; }
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
function privateKey(seed) { return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seed)]), format: "der", type: "pkcs8" }); }
function publicKey(seed) { return new Uint8Array(createPublicKey(privateKey(seed)).export({ format: "der", type: "spki" }).subarray(-32)); }
const alphabet58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58(bytes) { let n = 0n; let result = ""; for (const byte of bytes) n = (n << 8n) | BigInt(byte); while (n) { result = alphabet58[Number(n % 58n)] + result; n /= 58n; } for (const byte of bytes) { if (byte) break; result = `1${result}`; } return result; }
function didKey(seed) { return `did:key:z${base58(Uint8Array.of(0xed, 1, ...publicKey(seed)))}`; }
function kid(did) { return `${did}#${did.slice("did:key:".length)}`; }
function ethereumDid(seed) {
  const point = secp256k1.getPublicKey(seed, false);
  const address = keccak_256(point.slice(1)).slice(-20);
  return `did:pkh:eip155:1:0x${Buffer.from(address).toString("hex")}`;
}
function exactNodeParent(role, audienceDid, capabilities, facts, seed, signerDid) {
  const unsigned = {
    schema: "xyz.tinycloud.policy/enforcement-delegation/v1",
    role,
    issuerDid: signerDid,
    audienceDid,
    capabilities,
    proofCids: [],
    notBefore: "2026-07-16T12:00:00Z",
    expiresAt: "2026-07-23T12:00:00Z",
    delegationMode: role === "policy-authority" ? "policy-source" : "conditional-mint",
    facts,
  };
  const unsignedJcs = jcs(unsigned);
  const digestBytes = sha256(Buffer.concat([utf8("xyz.tinycloud.policy/enforcement-delegation/v1\0"), utf8(unsignedJcs)]));
  const eip191 = Buffer.concat([Buffer.from("\\x19Ethereum Signed Message:\\n32"), Buffer.from(digestBytes)]);
  const signature = secp256k1.sign(keccak_256(eip191), seed, { lowS: true });
  const value = b64(Buffer.concat([Buffer.from(signature.toCompactRawBytes()), Buffer.from([signature.recovery])]));
  const withSignature = { ...unsigned, signature: { suite: "eip191-secp256k1-sha256-jcs-v1", value } };
  const cidBytes = utf8(jcs(withSignature));
  return { ...withSignature, delegationCid: `b${b32(Uint8Array.of(1, 0x55, 0x1e, 0x20, ...blake3(cidBytes)))}` };
}
function signedObservation(parentCid, state, sequence, checkedAt, freshUntil, signerSeed, signerDid, keyVersion) {
  const message = { type: "TinyCloudShareAuthorityStatusObservation", version: 1, parentCid, state, sequence, checkedAt, freshUntil, revokedAt: state === "revoked" ? checkedAt : null, signerKid: kid(signerDid), signerVersion: keyVersion };
  const domain = utf8("xyz.tinycloud.share/authority-status/v1\0");
  const signature = sign(null, Buffer.concat([domain, utf8(jcs(message))]), privateKey(signerSeed));
  return { ...message, signature: { alg: "EdDSA", kid: kid(signerDid), value: b64(signature) } };
}
function signedAttestation(enrollment, signerSeed, signerDid) {
  const message = { type: "TinyCloudShareEnrollmentRuntimeAttestation", version: 1, targetOrigin: enrollment.targetOrigin, nodeAudience: enrollment.nodeAudience, enforcerDid: didKey(signerSeed), enforcerKid: "did:web:node.example#enforcement-key-1", publicKey: enrollment.invitationPublicKey, keyVersion: enrollment.keyVersion, localSignerDid: signerDid, localSignerKid: kid(signerDid), measurement: "tinycloud-node-measurement-v1", measurementDigest: digest(utf8(jcs({ measurement: "tinycloud-node-measurement-v1" }))), expiresAt: "2026-07-16T12:04:00.000Z", enrollmentDigest: digest(utf8(jcs(enrollment))) };
  const signature = sign(null, Buffer.concat([utf8("xyz.tinycloud.share/enrollment-attestation/v1\0"), utf8(jcs(message))]), privateKey(signerSeed));
  return { ...message, signature: { alg: "EdDSA", kid: kid(signerDid), value: b64(signature) } };
}
function signed(name, domains, message, seed, signerDid, keyId) {
  const domain = domains.domains[name];
  if (typeof domain !== "string" || !domain.endsWith("\u0000")) throw new Error(`missing registry domain: ${name}`);
  const text = jcs(message);
  const signingBytes = Buffer.concat([utf8(domain), utf8(text)]);
  const signature = sign(null, signingBytes, privateKey(seed));
  return { name, domain, signerDid, message, jcs: text, messageDigest: digest(utf8(text)), signedBytesDigest: digest(signingBytes), signatureDigest: digest(signature), signature: { alg: "EdDSA", kid: keyId, value: b64(signature) } };
}
function shippingEnvelope(unsigned, seed, domains) {
  const domain = domains.domains.envelope;
  const text = jcs(unsigned);
  const signature = sign(null, Buffer.concat([utf8(domain), utf8(text)]), privateKey(seed));
  return { ...unsigned, signature: { signerDid: didKey(seed), algorithm: "Ed25519", value: b64(signature) } };
}
function sourceFor(kind) {
  const space = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
  if (kind === "kv") return { kind, space, path: "documents/plan.md", action: "tinycloud.kv/get" };
  const args = { document_id: 123 };
  return { kind, space, database: "documents", path: "shared/plan", statement: "shared_document_by_id", arguments: args, argumentsDigest: digest(utf8(jcs(args))), action: "tinycloud.sql/read" };
}
function bodyDigest(body) { return digest(utf8(jcs(body))); }
function artifactProof(artifact) { return { alg: "EdDSA", kid: artifact.signature.kid, signature: artifact.signature.value }; }
function sealEnvelope(plaintext, key, nonce) {
  const cipher = createCipheriv("aes-256-gcm", Buffer.from(key), Buffer.from(nonce));
  cipher.setAAD(Buffer.from("tinycloud-share-envelope-v1", "utf8"));
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final(), cipher.getAuthTag()]);
  return Uint8Array.of(1, ...nonce, ...ciphertext);
}

const domains = JSON.parse(await readFile(resolve(spec, "domains.json"), "utf8"));
const domainNames = ["envelope", "policy", "inviteAuthorization", "holderBinding", "policyChallenge", "policyPresentation", "policySession", "readInvocation", "readResponse", "authorityMaterial"];
for (const name of domainNames) if (typeof domains.domains[name] !== "string" || !domains.domains[name].endsWith("\u0000")) throw new Error(`invalid domain registry entry: ${name}`);

const seeds = { sender: hex("44".repeat(32)), node: hex("42".repeat(32)), issuer: hex("43".repeat(32)), holder: hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60") };
const ids = { senderDid: didKey(seeds.sender), holderDid: didKey(seeds.holder), nodeDid: "did:web:node.example", issuerDid: "did:web:issuer.credentials.org", nodeKid: "did:web:node.example#invitation-key-1", senderKid: kid(didKey(seeds.sender)), holderKid: kid(didKey(seeds.holder)) };
const times = { issued: "2026-07-16T12:00:00.000Z", evaluation: "2026-07-16T12:00:30.000Z", bindingExpires: "2026-07-16T12:02:00.000Z", claimExpires: "2026-07-23T12:00:00.000Z", challengeExpires: "2026-07-16T12:02:00.000Z", sessionExpires: "2026-07-16T12:05:00.000Z", readExpires: "2026-07-16T12:01:00.000Z" };
const canonicalEmail = "Alice+Notes@example.com";
const emailHash = digest(utf8(canonicalEmail));
const maxDomain253 = `${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(63)}.${"e".repeat(61)}`;
const maxDomain252 = `${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(63)}.${"e".repeat(60)}`;
const canonicalization = { accepted: [
  { id: "local-64-atext-bytes", input: `${"a".repeat(64)}@example.com`, canonical: `${"a".repeat(64)}@example.com`, localBytes: 64, domainBytes: 11, totalBytes: 76 },
  { id: "local-dot-atom-preserved", input: "Alice.O+Notes@EXAMPLE.COM", canonical: "Alice.O+Notes@example.com", localBytes: 13, domainBytes: 11, totalBytes: 25 },
  { id: "total-254-bytes", input: `a@${maxDomain252}`, canonical: `a@${maxDomain252}`, localBytes: 1, domainBytes: 252, totalBytes: 254 }
], domainBoundary: { id: "domain-253-byte-component", input: maxDomain253, canonical: maxDomain253, domainBytes: 253, validLdhLabels: true } };
const emailRejects = [
  ["leading-space", " Alice@example.com"], ["trailing-space", "Alice@example.com "], ["tab", "Alice@\texample.com"], ["newline", "Alice@example.com\n"], ["inner-space", "Alice Notes@example.com"], ["leading-dot-local", ".Alice@example.com"], ["trailing-dot-local", "Alice.@example.com"], ["repeated-dot-local", "Alice..Notes@example.com"], ["empty-local", "@example.com"], ["empty-domain", "Alice@"], ["multiple-at", "Alice@gmail.com@example.com"], ["quoted-local", '"Alice"@example.com'], ["comment-local", "Alice(comment)@example.com"], ["backslash-local", "Alice\\Bob@example.com"], ["angle-form", "Alice <alice@example.com>"], ["unicode-local", "álíce@example.com"], ["unicode-domain", "Alice@bücher.example"], ["local-over-64", `${"a".repeat(65)}@example.com`], ["label-over-63", `Alice@${"a".repeat(64)}.com`], ["empty-domain-label", "Alice@example..com"], ["trailing-domain-dot", "Alice@example.com."], ["leading-hyphen", "Alice@-example.com"], ["trailing-hyphen", "Alice@example-.com"], ["domain-over-253", `a@${maxDomain253}x`], ["total-over-254", `aa@${maxDomain252}`]
].map(([id, input]) => ({ id, input }));

function makeScenario(kind) {
  const source = sourceFor(kind);
  const sourceDigest = digest(utf8(jcs(source)));
  const policy = { type: "TinyCloudSharePolicy", version: 1, recipientEmail: canonicalEmail, contentSource: source, contentSourceDigest: sourceDigest, action: source.action, resource: source.path, expiresAt: times.claimExpires, issuerDid: ids.senderDid };
  const policyBytes = utf8(jcs(policy));
  if (new TextDecoder().decode(policyBytes).includes("policyCid")) throw new Error("policy bytes self-reference policyCid");
  const policyCid = cid(policyBytes);
  const shareId = `share-${kind}-001`;
  const unsignedEnvelope = { version: 1, shareId, delegation: `uCAESA.${kind}.terminal`, authorizationTarget: { kind: "policy", policyCid, policyBytes: b64(policyBytes) }, target: { origin: "https://node.example", nodeAudience: ids.nodeDid, spaceId: source.space, resource: { kind: "exact", path: source.path } }, display: { senderName: "TinyCloud sender", filename: "Project plan.md", recipientHint: "A***@example.com" }, expiry: times.claimExpires };
  const envelope = shippingEnvelope(unsignedEnvelope, seeds.sender, domains);
  const envelopeJcs = jcs(envelope);
  const envelopeKey = fixedBytes(32, kind === "kv" ? 0 : 0x40);
  const envelopeNonce = fixedBytes(12, kind === "kv" ? 0x10 : 0x20);
  const sealedBlob = sealEnvelope(utf8(envelopeJcs), envelopeKey, envelopeNonce);
  const shareCid = cid(sealedBlob);
  const invitationId = b64(fixedBytes(16));
  const activationId = b64(fixedBytes(16, 0x10));
  const claimSecret = b64(fixedBytes(32, 0x20));
  const claimNonce = b64(fixedBytes(32, 0xa0));
  const redemptionId = b64(fixedBytes(16, 0x40));
  const challengeId = b64(fixedBytes(32, 0x60));
  const sessionId = b64(fixedBytes(16, 0x80));
  const jti = b64(fixedBytes(16, 0xc0));
  const readJti = b64(fixedBytes(16, 0xd0));
  const reportAbuseToken = b64(fixedBytes(16, 0xe0));
  const delegationCid = cid(utf8(`deterministic-terminal-delegation-${kind}`));
  const authorityMaterialHandle = `amh_${kind}_001`;
  const policyOwnerSeed = hex("55".repeat(32));
  const policyOwnerDid = ethereumDid(policyOwnerSeed);
  const nodeSignerDid = didKey(seeds.node);
  const nodeEnforcerDid = ids.senderDid === ids.nodeDid ? ids.nodeDid : didKey(seeds.node);
  const capability = source.kind === "sql"
    ? { service: "tinycloud.sql", space: source.space, path: source.path, actions: [source.action], caveats: { mode: "constrained-statements", readOnly: true, statements: [{ name: source.statement, sql: "SELECT markdown FROM shared_documents WHERE document_id = ?", fixedParams: [{ index: 1, value: source.arguments.document_id }] }] } }
    : { service: "tinycloud.kv", space: source.space, path: source.path, actions: [source.action] };
  const capabilityCeilingHashHex = Buffer.from(sha256(Buffer.concat([utf8("xyz.tinycloud.policy/PolicyCapability/v0\0"), utf8(jcs(capability))]))).toString("hex");
  const policyId = `pol_${kind}-001`;
  const policyDigestHex = Buffer.from(sha256(policyBytes)).toString("hex");
  const authorityFacts = {
    "xyz.tinycloud.policy/ownerDid": policyOwnerDid,
    "xyz.tinycloud.policy/policyId": policyId,
    "xyz.tinycloud.policy/policyDigestHex": policyDigestHex,
    "xyz.tinycloud.policy/capabilityCeilingHashHex": capabilityCeilingHashHex,
  };
  const enforcementFacts = {
    ...authorityFacts,
    "xyz.tinycloud.policy/enforcerDid": nodeEnforcerDid,
    "xyz.tinycloud.policy/nodeAudience": ids.nodeDid,
    "xyz.tinycloud.policy/attestationBindingDigestHex": digest(utf8(jcs({ targetOrigin: "https://node.example", nodeAudience: ids.nodeDid, enforcerDid: nodeEnforcerDid, enforcerKid: "did:web:node.example#enforcement-key-1", keyVersion: 1 }))),
    "xyz.tinycloud.policy/maxSessionTtlSeconds": "300",
    "xyz.tinycloud.policy/sessionMode": "attenuable",
    "xyz.tinycloud.policy/maxRedelegationDepth": "2",
    "xyz.tinycloud.policy/auditProfile": "vp-digest-v1",
  };
  const authority = exactNodeParent("policy-authority", ids.nodeDid, [capability], authorityFacts, policyOwnerSeed, policyOwnerDid);
  const enforcement = exactNodeParent("policy-enforcement", nodeEnforcerDid, [capability], enforcementFacts, policyOwnerSeed, policyOwnerDid);
  const policyAuthorityBytes = utf8(jcs(authority));
  const policyEnforcementBytes = utf8(jcs(enforcement));
  const policyAuthorityCid = authority.delegationCid;
  const policyEnforcementCid = enforcement.delegationCid;
  const enrollment = { targetOrigin: "https://node.example", nodeAudience: ids.nodeDid, invitationKid: ids.nodeKid, invitationPublicKey: b64(publicKey(seeds.node)), keyVersion: 1, enabled: true };
  const authorityStatus = signedObservation(policyAuthorityCid, "active", 7, times.issued, "2026-07-16T12:04:00.000Z", seeds.node, nodeSignerDid, 1);
  const enforcementStatus = signedObservation(policyEnforcementCid, "active", 7, times.issued, "2026-07-16T12:04:00.000Z", seeds.node, nodeSignerDid, 1);
  const attestation = signedAttestation(enrollment, seeds.node, nodeSignerDid);
  const authorityMaterial = { type: "TinyCloudShareAuthorityMaterial", version: 1, handle: authorityMaterialHandle, policyOwnerDid, senderDid: ids.senderDid, relationship: { policyOwnerDid, senderDid: ids.senderDid, authenticated: true }, mapping: { sharePolicyCid: policyCid, shareDelegationCid: delegationCid, policyAuthorityCid, policyEnforcementCid }, policyAuthorityBytes: b64(policyAuthorityBytes), policyAuthorityCid, policyEnforcementBytes: b64(policyEnforcementBytes), policyEnforcementCid, statusObservations: [authorityStatus, enforcementStatus], enrollment, attestation };
  const authorityMaterialDigest = digest(utf8(jcs(authorityMaterial)));
  const auth = { type: "TinyCloudShareInviteAuthorization", version: 1, jti: b64(fixedBytes(16, kind === "kv" ? 1 : 2)), senderDid: ids.senderDid, shareCid, shareId, policyCid, delegationCid, authorityMaterialHandle, authorityMaterialDigest, recipientEmail: canonicalEmail, targetOrigin: "https://node.example", nodeAudience: ids.nodeDid, returnOrigin: "https://share.tinycloud.xyz", documentName: "Project plan.md", senderTrust: "verified", contentSource: source, contentSourceDigest: sourceDigest, shareExpiresAt: times.claimExpires, issuedAt: times.issued, expiresAt: "2026-07-16T12:05:00.000Z", reportAbuseToken };
  const policyArtifact = signed("policy", domains, policy, seeds.sender, ids.senderDid, ids.senderKid);
  const envelopeArtifact = { name: "envelope", domain: domains.domains.envelope, signerDid: ids.senderDid, message: unsignedEnvelope, jcs: jcs(unsignedEnvelope), messageDigest: digest(utf8(jcs(unsignedEnvelope))), signedBytesDigest: digest(Buffer.concat([utf8(domains.domains.envelope), utf8(jcs(unsignedEnvelope))])), signatureDigest: digest(Buffer.from(envelope.signature.value, "base64url")), signature: { alg: "EdDSA", kid: ids.senderKid, value: envelope.signature.value } };
  const authArtifact = signed("inviteAuthorization", domains, auth, seeds.node, ids.nodeDid, ids.nodeKid);
  const binding = { type: "TinyCloudEmailClaimHolderBinding", version: 1, redemptionId, invitationId, claimNonce, shareCid, shareId, policyCid, delegationCid, authorityMaterialHandle, authorityMaterialDigest, contentSource: source, contentSourceDigest: sourceDigest, emailHash, holderDid: ids.holderDid, targetOrigin: "https://node.example", nodeAudience: ids.nodeDid, requestOrigin: "https://share.tinycloud.xyz", issuedAt: times.issued, expiresAt: times.bindingExpires, jti };
  const challengeBody = { shareCid, shareId, delegationCid, policyCid, authorityMaterialHandle, authorityMaterialDigest, contentSource: source, contentSourceDigest: sourceDigest, holderDid: ids.holderDid, targetOrigin: "https://node.example", nodeAudience: ids.nodeDid, action: source.action, resource: source.path };
  const requestBodyDigest = bodyDigest(challengeBody);
  const challenge = { type: "TinyCloudSharePolicyChallenge", version: 1, challengeId, nonce: claimNonce, shareCid, shareId, delegationCid, policyCid, authorityMaterialHandle, authorityMaterialDigest, contentSource: source, contentSourceDigest: sourceDigest, holderDid: ids.holderDid, targetOrigin: "https://node.example", nodeAudience: ids.nodeDid, action: source.action, resource: source.path, requestBodyDigest, issuedAt: times.issued, expiresAt: times.challengeExpires };
  const sdJwtSalt = b64(fixedBytes(16, kind === "kv" ? 0x30 : 0x40));
  const issuerClaims = { iss: ids.issuerDid, sub: ids.holderDid, iat: 1784203200, nbf: 1784203200, exp: 1784808000, jti: `urn:uuid:${kind}-credential-001`, vct: "opencredentials.email/v1", tinycloud_share: { share_cid: shareCid, share_id: shareId, policy_cid: policyCid, node_audience: ids.nodeDid }, _sd_alg: "sha-256", _sd: [] };
  const disclosure = b64(utf8(jcs([sdJwtSalt, "email", canonicalEmail])));
  const disclosureDigest = digest(utf8(disclosure)); issuerClaims._sd = [disclosureDigest];
  const header = b64(utf8(jcs({ alg: "EdDSA" }))); const payload = b64(utf8(jcs(issuerClaims))); const issuerInput = `${header}.${payload}`; const issuerSig = b64(sign(null, utf8(issuerInput), privateKey(seeds.issuer))); const credentialString = `${issuerInput}.${issuerSig}~${disclosure}~`;
  const credential = { format: "vc+sd-jwt", credential: credentialString, holderDid: ids.holderDid, expiresAt: times.claimExpires, issuerDid: ids.issuerDid, vct: "opencredentials.email/v1", claims: issuerClaims, disclosures: [{ path: "/email", salt: sdJwtSalt, encoded: disclosure, digest: disclosureDigest, value: canonicalEmail }], credentialDigest: digest(utf8(credentialString)), issuerJws: { signingInput: issuerInput, signingInputDigest: digest(utf8(issuerInput)), signature: issuerSig } };
  const presentation = { type: "TinyCloudSharePolicyPresentation", version: 1, challengeId, nonce: claimNonce, shareCid, shareId, delegationCid, policyCid, authorityMaterialHandle, authorityMaterialDigest, contentSource: source, contentSourceDigest: sourceDigest, holderDid: ids.holderDid, targetOrigin: "https://node.example", nodeAudience: ids.nodeDid, credentialDigest: credential.credentialDigest, action: source.action, resource: source.path, requestBodyDigest, issuedAt: times.issued, expiresAt: times.challengeExpires, jti: b64(fixedBytes(16, 0x11)) };
  const session = { type: "TinyCloudSharePolicySession", version: 1, sessionId, shareCid, shareId, delegationCid, policyCid, authorityMaterialHandle, authorityMaterialDigest, contentSource: source, contentSourceDigest: sourceDigest, holderDid: ids.holderDid, targetOrigin: "https://node.example", nodeAudience: ids.nodeDid, action: source.action, resource: source.path, credentialDigest: credential.credentialDigest, issuedAt: times.issued, expiresAt: times.sessionExpires };
  const readBase = { type: "TinyCloudShareReadInvocation", version: 1, sessionId, shareCid, shareId, policyCid, delegationCid, authorityMaterialHandle, authorityMaterialDigest, contentSource: source, contentSourceDigest: sourceDigest, holderDid: ids.holderDid, targetOrigin: "https://node.example", nodeAudience: ids.nodeDid, action: source.action, resource: source.path, issuedAt: times.issued, expiresAt: times.readExpires, jti: readJti };
  const readRequestPreimage = { sessionId, delegationCid, authorityMaterialHandle, authorityMaterialDigest, contentSource: source, contentSourceDigest: sourceDigest, action: source.action, resource: source.path, invocation: readBase };
  const readRequestBodyDigest = bodyDigest(readRequestPreimage);
  const read = { ...readBase, requestBodyDigest: readRequestBodyDigest };
  const holderBindingArtifact = signed("holderBinding", domains, binding, seeds.holder, ids.holderDid, ids.holderKid);
  const policyChallengeArtifact = signed("policyChallenge", domains, challenge, seeds.node, ids.nodeDid, ids.nodeKid);
  const policyPresentationArtifact = signed("policyPresentation", domains, presentation, seeds.holder, ids.holderDid, ids.holderKid);
  const policySessionArtifact = signed("policySession", domains, session, seeds.node, ids.nodeDid, ids.nodeKid);
  const readArtifact = signed("readInvocation", domains, read, seeds.holder, ids.holderDid, ids.holderKid);
  const readResponseBody = { type: "TinyCloudShareReadResponse", version: 1, sessionId, requestJti: readJti, readJti, audience: ids.nodeDid, holderDid: ids.holderDid, credentialDigest: credential.credentialDigest, issuedAt: times.issued, expiresAt: times.readExpires, mediaType: "text/markdown; charset=utf-8", content: "# Project plan\n", contentSource: source, contentSourceDigest: sourceDigest, action: source.action, resource: source.path, requestBodyDigest: readRequestBodyDigest, bodyDigest: digest(utf8("# Project plan\n")), delegationCid, authorityMaterialHandle, authorityMaterialDigest };
  const readResponseSignature = sign(null, Buffer.concat([utf8(domains.domains.readResponse), utf8(jcs(readResponseBody))]), privateKey(seeds.node));
  const readResponse = { ...readResponseBody, proof: { alg: "EdDSA", kid: ids.nodeKid, signature: b64(readResponseSignature) } };
  const authorityMaterialArtifact = signed("authorityMaterial", domains, authorityMaterial, seeds.sender, ids.senderDid, ids.senderKid);
  const artifacts = [policyArtifact, envelopeArtifact, authArtifact, holderBindingArtifact, policyChallengeArtifact, policyPresentationArtifact, policySessionArtifact, readArtifact, authorityMaterialArtifact];
  const authorizationProof = artifactProof(authArtifact);
  const shareUrl = `https://share.tinycloud.xyz/s/${shareCid}#k=${b64(envelopeKey)}`;
  const authorizationBody = { shareCid, shareId, policyCid, delegationCid, authorityMaterialHandle, authorityMaterialDigest, recipientEmail: canonicalEmail, targetOrigin: "https://node.example", nodeAudience: ids.nodeDid, action: source.action, resource: source.path };
  const authorizationRequest = { jti: auth.jti, reportAbuseToken, senderDid: ids.senderDid, shareCid, shareId, delegationCid, authorityMaterialHandle, authorityMaterialDigest, policyCid, recipientEmail: canonicalEmail, targetOrigin: "https://node.example", nodeAudience: ids.nodeDid, documentName: "Project plan.md", senderTrust: "verified", contentSource: source, contentSourceDigest: sourceDigest, shareExpiresAt: times.claimExpires, requestBodyDigest: bodyDigest(authorizationBody) };
  const bodies = {
    authorizationRequest,
    authorizationResponse: { authorization: auth, proof: authorizationProof },
    createInvitationRequest: { authorization: auth, proof: authorizationProof, shareUrl },
    createInvitationResponse: { status: "accepted", retryAfterSeconds: 20, delegationCid, authorityMaterialHandle, authorityMaterialDigest }, resendRequest: { invitationId, claimSecret }, resendResponse: { status: "accepted", retryAfterSeconds: 20, delegationCid, authorityMaterialHandle, authorityMaterialDigest },
    activationRequest: { invitationId, claimSecret }, activationResponse: { status: "accepted", retryAfterSeconds: 20, activationId }, claimChallengeMagicRequest: { invitationId, method: "magic", activationId }, claimChallengeOtpRequest: { invitationId, method: "otp", otp: "042731" }, claimChallengeResponse: { claimNonce, shareCid, shareId, policyCid, delegationCid, authorityMaterialHandle, authorityMaterialDigest, contentSource: source, contentSourceDigest: sourceDigest, emailHash, targetOrigin: "https://node.example", nodeAudience: ids.nodeDid, expiresAt: times.challengeExpires },
    claimRedeemRequest: { version: "tinycloud.share-email-claim/v1", redemptionId, invitationId, method: "magic", mailboxProof: claimSecret, binding, holderProof: artifactProof(holderBindingArtifact) }, claimRedeemOtpRequest: { version: "tinycloud.share-email-claim/v1", redemptionId, invitationId, method: "otp", mailboxProof: "042731", binding, holderProof: artifactProof(holderBindingArtifact) }, claimRedeemResponse: { format: "vc+sd-jwt", credential: credentialString, holderDid: ids.holderDid, expiresAt: times.claimExpires },
    policyChallengeRequest: { shareCid, shareId, delegationCid, policyCid, authorityMaterialHandle, authorityMaterialDigest, contentSource: source, contentSourceDigest: sourceDigest, holderDid: ids.holderDid, targetOrigin: "https://node.example", nodeAudience: ids.nodeDid, action: source.action, resource: source.path, requestBodyDigest }, policyChallengeResponse: { challenge, proof: artifactProof(policyChallengeArtifact) },
    policySessionRequest: { presentation, credential: credentialString, proof: artifactProof(policyPresentationArtifact) }, policySessionResponse: { session, proof: artifactProof(policySessionArtifact) },
    kvReadRequest: { sessionId, delegationCid, authorityMaterialHandle, authorityMaterialDigest, contentSource: source, contentSourceDigest: sourceDigest, action: source.action, resource: source.path, requestBodyDigest: readRequestBodyDigest, invocation: read, proof: { alg: "EdDSA", kid: ids.holderKid, signature: artifacts[7].signature.value } },
    sqlReadRequest: { sessionId, delegationCid, authorityMaterialHandle, authorityMaterialDigest, contentSource: source, contentSourceDigest: sourceDigest, action: source.action, resource: source.path, requestBodyDigest: readRequestBodyDigest, invocation: read, proof: { alg: "EdDSA", kid: ids.holderKid, signature: artifacts[7].signature.value } },
    readResponse
  };
  const failures = { authorizationFailure: { error: { code: "invitation_authorization_invalid" } }, createInvitationFailure: { error: { code: "capability_unavailable" } }, resendFailure: { error: { code: "invalid_or_expired_claim" } }, claimChallengeFailure: { error: { code: "invalid_or_expired_claim" } }, claimRedeemFailure: { error: { code: "claim_already_used" } }, policyChallengeFailure: { error: { code: "policy_denied" } }, policySessionFailure: { error: { code: "invalid_credential_profile" } }, kvReadFailure: { error: { code: "read_denied" } }, sqlReadFailure: { error: { code: "read_denied" } } };
  const preimages = Object.fromEntries(Object.entries({ ...bodies, ...failures }).map(([name, body]) => [name, { body, jcs: jcs(body), digest: bodyDigest(body) }]));
  const signedBytePreimages = Object.fromEntries(artifacts.map((artifact) => [artifact.name, { domain: artifact.domain, jcs: artifact.jcs, digest: artifact.signedBytesDigest }]));
  return { kind, testOnly: true, canonicalEmail, emailHash, shareCid, shareId, policyCid, delegationCid, authorityMaterialHandle, authorityMaterialDigest, authorityMaterial, policyBytes: b64(policyBytes), policy, source, sourceDigest, envelopeKey: b64(envelopeKey), sealedBlob: b64(sealedBlob), envelope, authorization: auth, enrollment, evaluationTime: times.evaluation, clockSkewSeconds: 30, sdJwtSalt, credential, artifacts, preimages, signedBytePreimages, reportAbuseToken };
}

const positive = { version: "tinycloud.share-email-claim/v1", generatedBy: "build.mjs", testOnly: true, keyWarning: "NON-PRODUCTION TEST VECTORS ONLY", canonicalization, scenarios: [makeScenario("kv"), makeScenario("sql")] };
const fixtureKv = positive.scenarios[0];
const fixtureSql = positive.scenarios[1];
const negativePolicyCid = cid(utf8("negative-policy-bytes"));
const negativeShareCid = cid(utf8("negative-share-blob"));
const negativePolicyBytes = b64(utf8(jcs({ ...fixtureKv.policy, recipientEmail: "Bob@example.com" })));
const negativeEnvelopeDomain = "unregistered.example\u0000";
const negativeNoncanonical16 = `${fixtureKv.preimages.resendRequest.body.invitationId.slice(0, -1)}B`;
const negativeNoncanonical64 = `${fixtureKv.preimages.authorizationResponse.body.proof.signature.slice(0, -1)}B`;
const negativeSmallOrderDid = `did:key:z${base58(Uint8Array.of(0xed, 1, 1, ...new Uint8Array(31)))}`;
const negativeGroupOrderSignature = (() => { const value = new Uint8Array(Buffer.from(fixtureKv.artifacts.find((artifact) => artifact.name === "holderBinding").signature.value, "base64url")); const order = hex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"); value.set(order, 32); return b64(value); })();
function resignedCredential(base, claimsPatch, seedHex, detachedPatch = {}) {
  const candidate = clone(base); candidate.claims = { ...candidate.claims, ...claimsPatch }; Object.assign(candidate, detachedPatch); const parts = candidate.credential.split("~"); const header = parts[0].split(".")[0]; const payload = b64(utf8(jcs(candidate.claims))); const signingInput = `${header}.${payload}`; const signature = b64(sign(null, utf8(signingInput), privateKey(hex(seedHex)))); const disclosure = parts[1] ?? ""; candidate.credential = `${signingInput}.${signature}~${disclosure}~`; candidate.credentialDigest = digest(utf8(candidate.credential)); candidate.issuerJws = { signingInput, signingInputDigest: digest(utf8(signingInput)), signature }; return candidate;
}
const differentHolderArtifact = signed("holderBinding", domains, { ...fixtureKv.artifacts.find((artifact) => artifact.name === "holderBinding").message, holderDid: fixtureKv.artifacts[0].signerDid }, hex(domains.testKeys.senderSeedHex), fixtureKv.artifacts[0].signerDid, kid(fixtureKv.artifacts[0].signerDid));
const overlongDocumentName = `${"a".repeat(197)}😀`;
const overlongDocumentAuthorizationArtifacts = Object.fromEntries([fixtureKv, fixtureSql].map((scenario) => {
  const authorization = scenario.artifacts.find((artifact) => artifact.name === "inviteAuthorization");
  return [scenario.kind, signed("inviteAuthorization", domains, { ...authorization.message, documentName: overlongDocumentName }, seeds.node, ids.nodeDid, ids.nodeKid)];
}));
const expiredCredential = resignedCredential(fixtureKv.credential, { exp: 1784203199 }, domains.testKeys.issuerSeedHex);
const expiryBoundaryCredential = resignedCredential(fixtureKv.credential, { exp: 1784203200 }, domains.testKeys.issuerSeedHex);
const wrongIssuerDidCredential = resignedCredential(fixtureKv.credential, { iss: "did:web:evil.credentials.org" }, domains.testKeys.senderSeedHex, { issuerDid: "did:web:evil.credentials.org" });
const wrongIssuerKeyCredential = resignedCredential(fixtureKv.credential, {}, domains.testKeys.senderSeedHex);
const wrongVctCredential = resignedCredential(fixtureKv.credential, { vct: "opencredentials.email/v2" }, domains.testKeys.issuerSeedHex, { vct: "opencredentials.email/v2" });
const differentHolderCredential = resignedCredential(fixtureKv.credential, { sub: fixtureKv.artifacts[0].signerDid }, domains.testKeys.issuerSeedHex, { holderDid: fixtureKv.artifacts[0].signerDid });
const differentScopeCredential = resignedCredential(fixtureKv.credential, { tinycloud_share: { ...fixtureKv.credential.claims.tinycloud_share, share_id: "share-mutated-001" } }, domains.testKeys.issuerSeedHex);
const sqlResignedCredentials = {
  expired: resignedCredential(fixtureSql.credential, { exp: 1784203199 }, domains.testKeys.issuerSeedHex),
  expiryBoundary: resignedCredential(fixtureSql.credential, { exp: 1784203200 }, domains.testKeys.issuerSeedHex),
  wrongIssuerDid: resignedCredential(fixtureSql.credential, { iss: "did:web:evil.credentials.org" }, domains.testKeys.senderSeedHex, { issuerDid: "did:web:evil.credentials.org" }),
  wrongIssuerKey: resignedCredential(fixtureSql.credential, {}, domains.testKeys.senderSeedHex),
  wrongVct: resignedCredential(fixtureSql.credential, { vct: "opencredentials.email/v2" }, domains.testKeys.issuerSeedHex, { vct: "opencredentials.email/v2" }),
  differentHolder: resignedCredential(fixtureSql.credential, { sub: fixtureSql.artifacts[0].signerDid }, domains.testKeys.issuerSeedHex, { holderDid: fixtureSql.artifacts[0].signerDid }),
  differentScope: resignedCredential(fixtureSql.credential, { tinycloud_share: { ...fixtureSql.credential.claims.tinycloud_share, share_id: "share-mutated-001" } }, domains.testKeys.issuerSeedHex)
};
const candidateSigningKeys = {
  issuer: b64(publicKey(seeds.issuer)),
  sender: b64(publicKey(seeds.sender))
};
const credentialKeyData = (key) => ({ candidateSigningPublicKeyByKind: { kv: candidateSigningKeys[key], sql: candidateSigningKeys[key] } });
const sqlOver32Arguments = Object.fromEntries(Array.from({ length: 33 }, (_, index) => [`argument_${String(index).padStart(2, "0")}`, index]));
const scannerGetFragment = `https://share.tinycloud.xyz/s/${fixtureKv.shareCid}#k=${fixtureKv.envelopeKey}&i=${fixtureKv.preimages.activationRequest.body.invitationId}&c=${fixtureKv.preimages.activationRequest.body.claimSecret}`;
const scannerGetFragmentSql = `https://share.tinycloud.xyz/s/${fixtureSql.shareCid}#k=${fixtureSql.envelopeKey}&i=${fixtureSql.preimages.activationRequest.body.invitationId}&c=${fixtureSql.preimages.activationRequest.body.claimSecret}`;
const negativeRow = (id, kind, target, mutation, mutationData, appliesTo = ["kv", "sql"], extra = {}) => {
  if (kind === "share-url" && typeof mutationData.value === "string" && appliesTo.includes("kv") && appliesTo.includes("sql")) {
    const sqlValue = mutationData.value
      .replaceAll(fixtureKv.shareCid, fixtureSql.shareCid)
      .replaceAll(fixtureKv.envelopeKey, fixtureSql.envelopeKey)
      .replaceAll(fixtureKv.preimages.resendRequest.body.invitationId, fixtureSql.preimages.resendRequest.body.invitationId)
      .replaceAll(fixtureKv.preimages.activationRequest.body.claimSecret, fixtureSql.preimages.activationRequest.body.claimSecret);
    mutationData = { ...mutationData, valueByKind: { kv: mutationData.value, sql: sqlValue } };
    delete mutationData.value;
  }
  return { id, kind, target, mutation, mutationData, appliesTo, expected: "reject", rejectionStage: "contract-validation", ...extra };
};
const negative = { version: "tinycloud.share-email-claim/v1", testOnly: true, cases: [
  ...emailRejects.map(({ id, input }) => negativeRow(id, "email", "canonicalEmail", "reject-input", { operation: "reject-input", input }, ["kv", "sql"], { input })),
  negativeRow("policy-cid-is-real", "cid", "policyBytes", "replace-policy-bytes-with-other-bytes", { operation: "replace", replacement: "other policy bytes" }),
  negativeRow("policy-bytes-self-policy-cid", "policy", "policyBytes", "insert-policyCid-self-reference", { operation: "insert-property", property: "policyCid", value: negativePolicyCid }),
  negativeRow("share-cid-is-real", "cid", "sealedBlob", "flip-one-blob-byte", { operation: "flip-byte", offset: "last", replacementCid: negativeShareCid }),
  negativeRow("sealed-blob-aead-tamper", "aead", "sealedBlob", "flip-authenticated-byte", { operation: "flip-byte", offset: "last" }),
  negativeRow("envelope-policy-target-missing-kind", "schema", "envelope.authorizationTarget.kind", "delete-kind", { operation: "delete" }),
  negativeRow("envelope-policy-target-missing-bytes", "schema", "envelope.authorizationTarget.policyBytes", "delete-policyBytes", { operation: "delete" }),
  negativeRow("envelope-policy-target-mismatch", "envelope", "envelope.authorizationTarget", "re-sign-policyCid-with-other-policyBytes", { operation: "replace-pair", policyCid: negativePolicyCid, policyBytes: negativePolicyBytes }),
  negativeRow("envelope-origin-mismatch", "envelope", "envelope.target.origin", "re-sign-origin", { operation: "replace", value: "https://evil.example" }),
  negativeRow("share-url-userinfo", "share-url", "createInvitationRequest.shareUrl", "reject-userinfo", { operation: "replace", value: `https://user:pass@share.tinycloud.xyz/s/${fixtureKv.shareCid}#k=${fixtureKv.envelopeKey}` }, ["kv", "sql"], { rejectionStage: "share-url-origin" }),
  negativeRow("share-url-query", "share-url", "createInvitationRequest.shareUrl", "reject-query", { operation: "replace", value: `https://share.tinycloud.xyz/s/${fixtureKv.shareCid}?x=1#k=${fixtureKv.envelopeKey}` }, ["kv", "sql"], { rejectionStage: "share-url-query" }),
  negativeRow("share-url-query-missing-fragment", "share-url", "createInvitationRequest.shareUrl", "reject-query-before-missing-fragment", { operation: "replace", value: `https://share.tinycloud.xyz/s/${fixtureKv.shareCid}?x=1` }, ["kv", "sql"], { rejectionStage: "share-url-query" }),
  negativeRow("share-url-duplicate-k", "share-url", "createInvitationRequest.shareUrl", "reject-duplicate-fragment-key", { operation: "replace", value: `${fixtureKv.preimages.createInvitationRequest.body.shareUrl}&k=${fixtureKv.envelopeKey}` }, ["kv", "sql"], { rejectionStage: "share-url-fragment" }),
  negativeRow("share-url-unknown-fragment", "share-url", "createInvitationRequest.shareUrl", "reject-unknown-fragment-key", { operation: "replace", value: `${fixtureKv.preimages.createInvitationRequest.body.shareUrl}&x=${fixtureKv.envelopeKey}` }, ["kv", "sql"], { rejectionStage: "share-url-fragment" }),
  negativeRow("share-url-noncanonical-k", "share-url", "createInvitationRequest.shareUrl", "reject-noncanonical-k", { operation: "replace", value: `${fixtureKv.preimages.createInvitationRequest.body.shareUrl.slice(0, -1)}B` }, ["kv", "sql"], { rejectionStage: "share-url-key" }),
  negativeRow("share-url-wrong-origin", "share-url", "createInvitationRequest.shareUrl", "reject-wrong-origin", { operation: "replace", value: fixtureKv.preimages.createInvitationRequest.body.shareUrl.replace("https://share.tinycloud.xyz", "https://evil.example") }, ["kv", "sql"], { rejectionStage: "share-url-origin" }),
  negativeRow("share-url-wrong-path", "share-url", "createInvitationRequest.shareUrl", "reject-wrong-path", { operation: "replace", value: fixtureKv.preimages.createInvitationRequest.body.shareUrl.replace(`/s/${fixtureKv.shareCid}`, `/share/${fixtureKv.shareCid}`) }, ["kv", "sql"], { rejectionStage: "share-url-path" }),
  negativeRow("share-url-http-scheme", "share-url", "createInvitationRequest.shareUrl", "reject-http-scheme", { operation: "replace", value: fixtureKv.preimages.createInvitationRequest.body.shareUrl.replace("https://", "http://") }, ["kv", "sql"], { rejectionStage: "share-url-scheme" }),
  negativeRow("share-url-explicit-port", "share-url", "createInvitationRequest.shareUrl", "reject-explicit-port", { operation: "replace", value: fixtureKv.preimages.createInvitationRequest.body.shareUrl.replace("https://share.tinycloud.xyz", "https://share.tinycloud.xyz:443") }, ["kv", "sql"], { rejectionStage: "share-url-port" }),
  negativeRow("share-url-percent-encoded-fragment", "share-url", "createInvitationRequest.shareUrl", "reject-percent-encoded-fragment-material", { operation: "replace", value: fixtureKv.preimages.createInvitationRequest.body.shareUrl.replace("#k=", "#k=%41") }, ["kv", "sql"], { rejectionStage: "share-url-fragment-encoding" }),
  negativeRow("document-name-over-200-utf8", "schema", "inviteAuthorization.documentName", "reject-over-200-utf8-bytes", { operation: "replace-and-resign", candidateArtifactByKind: overlongDocumentAuthorizationArtifacts }, ["kv", "sql"], { rejectionStage: "document-name-bytes" }),
  negativeRow("authorization-recipient-email-mismatch", "binding", "inviteAuthorization.recipientEmail", "re-sign-recipient-email", { operation: "replace-and-resign", value: "Bob@example.com", signer: fixtureKv.artifacts[2].signerDid }),
  negativeRow("redeem-redemption-id-mismatch", "binding", "holderBinding.redemptionId", "re-sign-redemption-id", { operation: "replace-and-resign", value: b64(fixedBytes(16, 0x41)), signer: fixtureKv.artifacts[3].signerDid }),
  negativeRow("redeem-invitation-id-mismatch", "binding", "holderBinding.invitationId", "re-sign-invitation-id", { operation: "replace-and-resign", value: b64(fixedBytes(16, 0x21)), signer: fixtureKv.artifacts[3].signerDid }),
  negativeRow("share-id-propagation", "binding", "policyPresentation.shareId", "re-sign-share-id", { operation: "replace-and-resign", value: "share-mutated-001", signer: fixtureKv.artifacts[5].signerDid }),
  negativeRow("share-cid-propagation", "binding", "policyPresentation.shareCid", "re-sign-share-cid", { operation: "replace-and-resign", value: negativeShareCid, signer: fixtureKv.artifacts[5].signerDid }),
  negativeRow("policy-cid-propagation", "binding", "policyPresentation.policyCid", "re-sign-policy-cid", { operation: "replace-and-resign", value: negativePolicyCid, signer: fixtureKv.artifacts[5].signerDid }),
  negativeRow("target-origin-propagation", "binding", "policyPresentation.targetOrigin", "re-sign-target-origin", { operation: "replace-and-resign", value: "https://evil.example", signer: fixtureKv.artifacts[5].signerDid }),
  negativeRow("node-audience-propagation", "binding", "policyPresentation.nodeAudience", "re-sign-node-audience", { operation: "replace-and-resign", value: "did:web:evil.example", signer: fixtureKv.artifacts[5].signerDid }),
  negativeRow("holder-did-propagation", "binding", "policyPresentation.holderDid", "re-sign-holder-did", { operation: "replace-and-resign", value: "did:web:other-holder.example", signer: fixtureKv.artifacts[5].signerDid }),
  negativeRow("content-source-digest-propagation", "binding", "policyPresentation.contentSourceDigest", "re-sign-content-source-digest", { operation: "replace-and-resign", value: digest(utf8("other source")), signer: fixtureKv.artifacts[5].signerDid }),
  negativeRow("action-propagation", "binding", "policyPresentation.action", "re-sign-action", { operation: "replace-and-resign", valueByKind: { kv: "tinycloud.sql/read", sql: "tinycloud.kv/get" }, signer: fixtureKv.artifacts[5].signerDid }),
  negativeRow("resource-propagation", "binding", "policyPresentation.resource", "re-sign-resource", { operation: "replace-and-resign", value: "other/resource", signer: fixtureKv.artifacts[5].signerDid }),
  negativeRow("envelope-domain-from-unregistered-label", "signature", "envelope.domain", "verify-with-nonregistry-domain", { operation: "replace", value: negativeEnvelopeDomain }),
  negativeRow("jcs-lone-surrogate", "jcs", "value", "insert-lone-surrogate", { operation: "insert", jsonLiteral: "\\ud800" }),
  negativeRow("jcs-unsafe-number", "jcs", "value", "insert-unsafe-number", { operation: "insert", jsonLiteral: "9007199254740992", numberKind: "unsafe-integer", value: 9007199254740992 }),
  negativeRow("jcs-fractional-number", "jcs", "value", "insert-fractional-number", { operation: "insert", jsonLiteral: "1.5", numberKind: "fractional", value: 1.5 }),
  negativeRow("jcs-negative-zero", "jcs", "value", "insert-negative-zero", { operation: "insert", jsonLiteral: "-0", numberKind: "negative-zero", value: "-0" }),
  negativeRow("jcs-undefined", "jcs", "value", "insert-undefined", { operation: "insert", jsonLiteral: "undefined" }),
  negativeRow("noncanonical-b64url-16-tail", "encoding", "invitationId", "set-nonzero-trailing-bits", { operation: "replace", value: negativeNoncanonical16 }),
  negativeRow("noncanonical-b64url-64-tail", "encoding", "signature", "set-nonzero-trailing-bits", { operation: "replace", value: negativeNoncanonical64 }),
  negativeRow("noncanonical-holder-kid", "signature", "holderBinding.signature.kid", "use-did-key-with-wrong-fragment", { operation: "replace", value: `${fixtureKv.artifacts[3].signerDid}#wrong` }),
  negativeRow("small-order-did-key", "did-key", "holderBinding.holderDid", "identity-public-key", { operation: "replace", value: negativeSmallOrderDid }),
  negativeRow("noncanonical-ed25519-s", "signature", "holderBinding.signature.value", "set-s-to-group-order", { operation: "replace", value: negativeGroupOrderSignature }, ["kv", "sql"], { rejectionStage: "signature-encoding" }),
  negativeRow("short-signature", "signature", "readInvocation.signature.value", "truncate-signature", { operation: "truncate", bytes: 63 }),
  negativeRow("wrong-source-digest", "source", "sql.argumentsDigest", "change-one-argument", { operation: "change", field: "arguments.document_id", value: 456 }, ["sql"]),
  negativeRow("sql-string-argument", "source", "sql.arguments", "insert-non-integer-argument", { operation: "insert-property", field: "label", value: "doc_456", valueType: "string" }, ["sql"]),
  negativeRow("sql-fractional-argument", "source", "sql.arguments", "insert-non-integer-argument", { operation: "insert-property", field: "revision", value: 1.5, valueType: "fractional" }, ["sql"]),
  negativeRow("sql-negative-zero-argument", "source", "sql.arguments", "insert-non-integer-argument", { operation: "insert-property", field: "offset", jsonLiteral: "-0", value: "-0", valueType: "negative-zero" }, ["sql"]),
  negativeRow("sql-arguments-too-large", "source", "sql.arguments", "replace-with-over-32-properties", { operation: "replace-object", field: "arguments", value: sqlOver32Arguments, propertyCount: 33, valueType: "safe-json-integers" }, ["sql"]),
  negativeRow("sql-arbitrary-query-field", "schema", "sqlSource.query", "add-query", { operation: "add-property", field: "query", value: "select *" }, ["sql"]),
  negativeRow("policy-action-source-mismatch", "binding", "policy.action", "change-action-only", { operation: "replace", valueByKind: { kv: "tinycloud.sql/read", sql: "tinycloud.kv/get" } }),
  negativeRow("content-source-propagation", "binding", "policyPresentation.contentSource.path", "change-path-one-field", { operation: "replace", value: "other.md" }),
  negativeRow("credential-sub-mismatch", "credential", "credential.claims.sub", "sender-did", { operation: "replace", value: fixtureKv.artifacts[0].signerDid }),
  negativeRow("credential-legacy-email-path", "credential", "credential.disclosures[0].path", "email-address-path", { operation: "replace", value: "/email/address" }),
  negativeRow("credential-unsupported-status", "credential", "credential.claims.status", "add-status", { operation: "add-property", value: { list: "unsupported" } }),
  negativeRow("credential-expired-resigned", "credential", "credential.claims.exp", "re-sign-expired-credential", { operation: "replace-and-resign", credentialByKind: { kv: expiredCredential, sql: sqlResignedCredentials.expired }, ...credentialKeyData("issuer") }, ["kv", "sql"], { rejectionStage: "credential-time" }),
  negativeRow("credential-expiry-boundary-resigned", "credential", "credential.claims.exp", "re-sign-expiry-at-evaluation-minus-skew", { operation: "replace-and-resign", credentialByKind: { kv: expiryBoundaryCredential, sql: sqlResignedCredentials.expiryBoundary }, ...credentialKeyData("issuer"), expEquation: "evaluationTime - clockSkewSeconds" }, ["kv", "sql"], { rejectionStage: "credential-time" }),
  negativeRow("credential-issuer-did-resigned", "credential", "credential.claims.iss", "re-sign-untrusted-issuer-did", { operation: "replace-and-resign", credentialByKind: { kv: wrongIssuerDidCredential, sql: sqlResignedCredentials.wrongIssuerDid }, ...credentialKeyData("sender") }, ["kv", "sql"], { rejectionStage: "issuer-trust" }),
  negativeRow("credential-issuer-key-resigned", "credential", "credential.issuerJws.signature", "re-sign-with-untrusted-key", { operation: "replace-and-resign", credentialByKind: { kv: wrongIssuerKeyCredential, sql: sqlResignedCredentials.wrongIssuerKey }, ...credentialKeyData("sender") }, ["kv", "sql"], { rejectionStage: "issuer-key" }),
  negativeRow("credential-vct-resigned", "credential", "credential.vct", "re-sign-wrong-vct", { operation: "replace-and-resign", credentialByKind: { kv: wrongVctCredential, sql: sqlResignedCredentials.wrongVct }, ...credentialKeyData("issuer") }, ["kv", "sql"], { rejectionStage: "credential-vct" }),
  negativeRow("credential-holder-resigned", "credential", "credential.holderDid", "re-sign-different-holder", { operation: "replace-and-resign", credentialByKind: { kv: differentHolderCredential, sql: sqlResignedCredentials.differentHolder }, ...credentialKeyData("issuer") }, ["kv", "sql"], { rejectionStage: "credential-holder" }),
  negativeRow("credential-scope-resigned", "credential", "credential.claims.tinycloud_share.share_id", "re-sign-different-scope", { operation: "replace-and-resign", credentialByKind: { kv: differentScopeCredential, sql: sqlResignedCredentials.differentScope }, ...credentialKeyData("issuer") }, ["kv", "sql"], { rejectionStage: "credential-scope" }),
  negativeRow("different-holder-valid-signature", "signature", "holderBinding.holderDid", "replace-holder-and-resign", { operation: "replace-and-resign", candidateArtifact: differentHolderArtifact, signerDid: fixtureKv.artifacts[0].signerDid, keyId: fixtureKv.artifacts[0].signature.kid }, ["kv", "sql"], { rejectionStage: "cross-artifact-holder" }),
  negativeRow("policy-challenge-replay", "state", "nonce.state", "consume-twice", { operation: "transition", from: "CONSUMED", to: "CONSUMED" }),
  negativeRow("session-token-only", "state", "read.proof", "omit-holder-proof", { operation: "delete" }),
  negativeRow("old-secret-after-resend", "state", "invitation.version", "use-v1-after-v2-accepted", { operation: "replace", value: 1 }),
  negativeRow("otp-after-five-wrong", "state", "otp.attempts", "correct-code-after-lock", { operation: "replace", value: 5 }),
  negativeRow("scanner-get", "state", "fragment", "GET-consumes-claim", { operation: "consume-on-GET", valueByKind: { kv: scannerGetFragment, sql: scannerGetFragmentSql } }),
  negativeRow("scanner-fragment-percent-encoded", "share-url", "scanner.fragment", "reject-percent-encoded-fragment-material", { operation: "replace", value: scannerGetFragment.replace("#k=", "#k=%41") }, ["kv", "sql"], { rejectionStage: "scanner-fragment-encoding" }),
  negativeRow("resend-recipient-supplied-email", "schema", "resendRequest.email", "add-email", { operation: "add-property", field: "email", value: "Alice+Notes@example.com" }),
  negativeRow("capability-extra-route", "capability", "witness.routes", "add-route", { operation: "append", value: "/v1/extra" }),
  negativeRow("capability-wildcard-origin", "capability", "node.origin", "wildcard-origin", { operation: "replace", value: "https://*.example" }),
  negativeRow("node-enrollment-disabled", "enrollment", "enrollment.enabled", "reject-disabled-enrollment", { operation: "replace", enrollment: { ...fixtureKv.enrollment, enabled: false } }, ["kv", "sql"], { rejectionStage: "node-enrollment" }),
  negativeRow("node-enrollment-origin-audience", "enrollment", "enrollment.targetOrigin", "reject-authority-mismatch", { operation: "replace", enrollment: { ...fixtureKv.enrollment, targetOrigin: "https://evil.example" } }, ["kv", "sql"], { rejectionStage: "node-authority" }),
  negativeRow("node-enrollment-audience-origin", "enrollment", "enrollment.nodeAudience", "reject-authority-mismatch", { operation: "replace", enrollment: { ...fixtureKv.enrollment, nodeAudience: "did:web:evil.example" } }, ["kv", "sql"], { rejectionStage: "node-authority" }),
  negativeRow("node-enrollment-retired-key", "enrollment", "enrollment.keyVersion", "reject-retired-key-version", { operation: "replace", enrollment: { ...fixtureKv.enrollment, keyVersion: 2, invitationKid: "did:web:node.example#invitation-key-2" } }, ["kv", "sql"], { rejectionStage: "node-key-retirement" }),
  negativeRow("node-enrollment-kid-version-mismatch", "enrollment", "enrollment.invitationKid", "reject-kid-version-mismatch", { operation: "replace", enrollment: { ...fixtureKv.enrollment, invitationKid: "did:web:node.example#invitation-key-2" } }, ["kv", "sql"], { rejectionStage: "node-key-rotation" }),
  negativeRow("read-body-one-field-mutation", "preimage", "sqlReadRequest.resource", "change-one-argument", { operation: "replace", value: "other" }, ["sql"]),
  negativeRow("claim-redeem-magic-with-otp", "method", "claimRedeemRequest.mailboxProof", "magic-method-with-otp-proof", { operation: "replace", method: "magic", field: "mailboxProof", value: "042731" }),
  negativeRow("claim-redeem-otp-with-magic", "method", "claimRedeemRequest.mailboxProof", "otp-method-with-magic-proof", { operation: "replace", method: "otp", field: "mailboxProof", value: b64(fixedBytes(32, 0x20)) }),
  negativeRow("policy-challenge-response-proof", "proof", "policyChallengeResponse.proof", "use-holder-proof-for-node-artifact", { operation: "replace", artifact: "policyChallenge", signer: fixtureKv.artifacts[3].signerDid }),
  negativeRow("policy-session-response-proof", "proof", "policySessionResponse.proof", "use-holder-proof-for-node-artifact", { operation: "replace", artifact: "policySession", signer: fixtureKv.artifacts[3].signerDid }),
  negativeRow("authority-material-signature", "authority", "authorityMaterial.signature.value", "flip-authority-signature", { operation: "flip-byte", field: "signature" }),
  negativeRow("authority-material-policy-mapping", "authority", "authorityMaterial.mapping", "replace-share-policy-cid", { operation: "replace", field: "mapping", value: { ...fixtureKv.authorityMaterial.mapping, sharePolicyCid: negativePolicyCid } }),
  negativeRow("authority-status-rollback", "authority", "authorityMaterial.statusObservations", "decrease-status-sequence", { operation: "replace", field: "statusObservations", value: [] }),
  negativeRow("authority-status-stale", "authority", "authorityMaterial.statusObservations", "stale-status", { operation: "replace", field: "statusObservations", value: [] }),
  negativeRow("authority-status-revoked", "authority", "authorityMaterial.statusObservations", "revoke-active-authority", { operation: "replace", field: "statusObservations", value: [] }),
  negativeRow("authority-key-version", "authority", "authorityMaterial.attestation", "wrong-enforcer-key-version", { operation: "replace", field: "attestation", value: {} }),
  negativeRow("authority-attestation-binding", "authority", "authorityMaterial.attestation", "wrong-attestation-audience", { operation: "replace", field: "attestation", value: {} }),
  negativeRow("authority-measurement-digest-expiry", "authority", "authorityMaterial.attestation", "wrong-measurement-digest-expiry", { operation: "replace", field: "attestation", value: {} }),
  negativeRow("authority-identifier-domain-confusion", "authority", "authorityMaterial.mapping", "use-policy-cid-as-delegation-cid", { operation: "replace", field: "mapping", value: { ...fixtureKv.authorityMaterial.mapping, shareDelegationCid: fixtureKv.policyCid } }),
  negativeRow("sd-jwt-missing-alg", "sd-jwt", "credential.claims._sd_alg", "delete-sd-alg", { operation: "delete", expected: "sha-256" }),
  negativeRow("sd-jwt-two-element-disclosure", "sd-jwt", "credential.disclosures[0].encoded", "replace-disclosure-with-two-elements", { operation: "replace", arrayShape: ["email", "Alice+Notes@example.com"] })
] };
const states = { version: "tinycloud.share-email-claim/v1", testOnly: true, delivery: [
  { name: "create-accepted", events: [["ABSENT","PENDING_DELIVERY(v1)"],["PENDING_DELIVERY(v1)","ACTIVE(v1)"],["ACTIVE(v1)","REDEEMING(v1,redemption-001)"],["REDEEMING(v1,redemption-001)","CONSUMED(v1)"]], providerIdempotencyKey: "invite:create:auth-kv-001", encryptedUntilProviderAcceptance: true, atomicActivation: true, materialDeletedAfterAccept: true },
  { name: "resend-accepted", events: [["ACTIVE(v1)","PENDING_DELIVERY(v2)"],["PENDING_DELIVERY(v2)","ACTIVE(v2)"],["ACTIVE(v2)","REDEEMING(v2,redemption-002)"],["REDEEMING(v2,redemption-002)","CONSUMED(v2)"]], providerIdempotencyKey: "invite:resend:invitation-001:v2", oldVersionRemainsActiveWhilePending: true, oldVersionInvalidatedOnlyAfterAccept: true, replacementMaterialEncryptedUntilAcceptance: true, atomicActivation: true },
  { name: "resend-provider-failure", events: [["ACTIVE(v1)","PENDING_DELIVERY(v2)"],["PENDING_DELIVERY(v2)","ACTIVE(v1)"],["ACTIVE(v1)","REDEEMING(v1,redemption-003)"],["REDEEMING(v1,redemption-003)","CONSUMED(v1)"]], providerIdempotencyKey: "invite:resend:invitation-001:v2", oldVersionRemainsUsable: true, replacementDiscardedOnFailure: true },
  { name: "crash-after-provider-accept", events: [["ACTIVE(v1)","PENDING_DELIVERY(v2)"],["PENDING_DELIVERY(v2)","RECOVERING_PROVIDER_ACCEPT(v2)"],["RECOVERING_PROVIDER_ACCEPT(v2)","ACTIVE(v2)"]], providerAcceptedBeforeCrash: true, sameIdempotencyKeyOnRetry: true, recoveryReconcilesProviderAcceptance: true, oneEffectiveSend: true, oldVersionInvalidatedAfterRecovery: true }
], invitation: ["ABSENT","ACTIVE(v1)","REDEEMING(v1,redemption-001)","CONSUMED(v1)"], nonce: ["ISSUED","VERIFYING","CONSUMED"], session: ["ACTIVE","EXPIRED","REVOKED"], operations: ["create_persist_outbox","provider_accept","activate_v1","wrong_otp_x5","lock_v1","resend_persist_v2","provider_accept_v2","invalidate_v1","claim_v2","consume_nonce","crash_after_provider_accept","retry_same_provider_idempotency","same_redemption_idempotent","different_redemption_rejected","scanner_get_no_state_change"], semantics: { claimMaterial: { encryptedUntilProviderAcceptance: true, deletedAfterProviderAcceptance: true }, resend: { oldVersionActiveWhilePending: true, invalidatedOnlyAfterProviderAcceptance: true, providerIdempotent: true }, sameRedemptionConcurrency: { attempts: 20, effectiveIssuances: 1, sameResultForSameId: true }, otp: { wrongAttemptsBeforeLock: 5, correctAfterLock: "reject", invalidMagicDoesNotIncrementOtp: true } }, issuanceRecovery: {
  seedCiphertext: b64(fixedBytes(48, 0x70)),
  retrySeedCiphertext: b64(fixedBytes(48, 0x70)),
  pendingSeedCiphertext: b64(fixedBytes(48, 0x70)),
  retryPendingSeedCiphertext: b64(fixedBytes(48, 0x70)),
  resultBytes: b64(utf8("vc+sd-jwt:deterministic-result-001")),
  resultDigest: digest(utf8("vc+sd-jwt:deterministic-result-001")),
  idempotencyKey: "issuance:invitation-001:redemption-001",
  timeline: [
    { at: "2026-07-16T12:00:00.000Z", event: "seed_persisted", state: "PENDING_ENCRYPTED", seedEncrypted: true, credentialGenerated: false, durableCompletion: false, resultPersisted: false },
    { at: "2026-07-16T12:00:01.000Z", event: "credential_generated_then_crash", state: "PENDING_ENCRYPTED", seedEncrypted: true, credentialGenerated: true, durableCompletion: false, resultPersisted: false },
    { at: "2026-07-16T12:00:02.000Z", event: "retry_same_seed", state: "RETRYING", seedEncrypted: true, credentialGenerated: true, durableCompletion: false, resultPersisted: false },
    { at: "2026-07-16T12:00:03.000Z", event: "prepare_atomic_success", state: "RETRYING", seedEncrypted: true, credentialGenerated: true, durableCompletion: false, resultPersisted: false, consumedPersisted: false },
    { at: "2026-07-16T12:00:03.000Z", event: "atomic_credential_result_consumed_persisted", state: "CONSUMED", seedEncrypted: false, credentialGenerated: true, credentialPersisted: true, durableCompletion: true, durableCompletionAt: "2026-07-16T12:00:03.000Z", invitationState: "CONSUMED", consumedPersisted: true, resultPersisted: true, atomicConsumedAndResult: true, atomicCredentialResultInvitationConsumedAndSeedDeletion: true, resultDigest: digest(utf8("vc+sd-jwt:deterministic-result-001")) }
  ],
  terminalFailureTimeline: [
    { at: "2026-07-16T12:00:00.000Z", event: "seed_persisted", state: "PENDING_ENCRYPTED", seedEncrypted: true, terminalErrorPersisted: false },
    { at: "2026-07-16T12:00:02.000Z", event: "retry_exhausted", state: "RETRYING", seedEncrypted: true, terminalErrorPersisted: false },
    { at: "2026-07-16T12:00:03.000Z", event: "atomic_terminal_result_consumed_persisted", state: "TERMINAL_ERROR", seedEncrypted: false, terminalResultPersisted: true, terminalErrorPersisted: true, resultPersisted: true, invitationState: "CONSUMED", consumedPersisted: true, atomicConsumedAndResult: true, atomicTerminalAndSeedDeletion: true, atomicTerminalResultInvitationConsumedAndSeedDeletion: true, errorCode: "credential_issuance_failed" }
  ],
  invariants: {
    pendingSeedEncrypted: true,
    retrySeedByteIdentical: true,
    completionRequiresDurableWrite: true,
    durableCompletionAt: "2026-07-16T12:00:03.000Z",
    consumedAndResultPersistedAtomically: true,
    noDurableResultBeforeAtomicSuccess: true,
    terminalResultAndConsumedPersistedAtomically: true,
    terminalResolutionAtomic: true,
    cleanupRefusesPendingSeed: true,
    redactionWindowSeconds: 900,
    redactionStartsOnlyAt: "durable_completion",
    redactionMeasuredFrom: "2026-07-16T12:00:03.000Z",
    redactionAt: "2026-07-16T12:15:03.000Z"
  },
  cleanup: { pendingSeedAction: "refuse", completedSeedAction: "delete", pendingSeedRemains: true },
  terminalResolution: {
    states: ["PENDING_ENCRYPTED", "RETRYING", "CONSUMED", "TERMINAL_ERROR"],
    successOutcome: "CONSUMED",
    failureOutcome: "TERMINAL_ERROR",
    atomic: true,
    atomicConsumedAndResultPersisted: true,
    atomicCredentialResultInvitationConsumedAndSeedDeletion: true,
    atomicTerminalAndSeedDeletion: true,
    atomicTerminalResultInvitationConsumedAndSeedDeletion: true
  }
} };

const durable = (invitation, extra = {}) => ({ invitation, ...extra });
states.operationProgram = [
  { id: "create-persist-outbox", operation: "transaction", pre: { durableRows: durable("ABSENT", { outbox: null, claimMaterial: "encrypted" }) }, commands: [{ name: "create_invitation", operands: { version: 1, outboxKey: "invite:create:auth-kv-001", claimMaterial: "encrypted" } }], expected: { durableRows: durable("PENDING_DELIVERY(v1)", { outbox: "invite:create:auth-kv-001", claimMaterial: "encrypted" }) } },
  { id: "provider-accept-v1", operation: "transaction", pre: { durableRows: durable("PENDING_DELIVERY(v1)", { providerAccepted: false, claimMaterial: "encrypted" }) }, commands: [{ name: "provider_accept", operands: { version: 1, claimMaterialAfter: "deleted" } }], expected: { durableRows: durable("ACTIVE(v1)", { providerAccepted: true, claimMaterial: "deleted" }) } },
  { id: "premature-resend-invalidation", operation: "reject", pre: { durableRows: durable("PENDING_DELIVERY(v2)", { activeVersion: 1, pendingVersion: 2, oldSecret: "present" }) }, commands: [{ name: "invalidate_old_version", operands: { version: 1, onlyAfter: "provider_acceptance" } }], expected: { durableRows: durable("PENDING_DELIVERY(v2)", { activeVersion: 1, pendingVersion: 2, oldSecret: "present" }) } },
  { id: "resend-persist-v2", operation: "transaction", pre: { durableRows: durable("ACTIVE(v1)", { activeVersion: 1, pendingVersion: null, oldSecret: "present" }) }, commands: [{ name: "prepare_resend", operands: { fromVersion: 1, toVersion: 2, replacementMaterial: "encrypted" } }], expected: { durableRows: durable("PENDING_DELIVERY(v2)", { activeVersion: 1, pendingVersion: 2, oldSecret: "present", replacementMaterial: "encrypted" }) } },
  { id: "provider-failure-recovery", operation: "transaction", pre: { durableRows: durable("PENDING_DELIVERY(v2)", { activeVersion: 1, pendingVersion: 2, oldSecret: "present", replacementMaterial: "encrypted" }) }, commands: [{ name: "provider_reject", operands: { pendingVersion: 2, restoreVersion: 1, replacementMaterialAfter: "discarded" } }], expected: { durableRows: durable("ACTIVE(v1)", { activeVersion: 1, pendingVersion: null, oldSecret: "present", replacementMaterial: "discarded" }) } },
  { id: "provider-accept-crash", operation: "crash", pre: { durableRows: durable("PENDING_DELIVERY(v2)", { activeVersion: 1, pendingVersion: 2, providerAccepted: false }) }, commands: [{ name: "provider_accept_then_crash", operands: { version: 2, idempotencyKey: "invite:resend:invitation-001:v2", sendCount: 1 } }], expected: { durableRows: durable("PENDING_DELIVERY(v2)", { activeVersion: 1, pendingVersion: 2, providerAccepted: true, crashObserved: true }) } },
  { id: "provider-accept-retry", operation: "retry", pre: { durableRows: durable("PENDING_DELIVERY(v2)", { activeVersion: 1, pendingVersion: 2, providerAccepted: true, crashObserved: true }) }, commands: [{ name: "reconcile_provider_acceptance", operands: { version: 2, idempotencyKey: "invite:resend:invitation-001:v2", sendCount: 1, retireVersion: 1 } }], expected: { durableRows: durable("ACTIVE(v2)", { activeVersion: 2, pendingVersion: null, oldSecret: "retired", providerSendCount: 1 }) } },
  { id: "atomic-issuance-success", operation: "transaction", pre: { durableRows: durable("REDEEMING(v1,redemption-001)", { seed: "encrypted", result: null, consumed: false }) }, commands: [{ name: "resolve_issuance", operands: { redemptionId: "redemption-001", outcome: "success", result: "persisted", seedAfter: "deleted" } }], expected: { durableRows: durable("CONSUMED(v1)", { seed: "deleted", result: "persisted", consumed: true }) } },
  { id: "atomic-issuance-failure", operation: "transaction", pre: { durableRows: durable("REDEEMING(v1,redemption-002)", { seed: "encrypted", result: null, consumed: false }) }, commands: [{ name: "resolve_issuance", operands: { redemptionId: "redemption-002", outcome: "failure", result: "terminal-error", seedAfter: "deleted" } }], expected: { durableRows: durable("TERMINAL_ERROR", { seed: "deleted", result: "terminal-error", consumed: true }) } },
  { id: "atomic-partial-write-rejected", operation: "reject", pre: { durableRows: durable("REDEEMING(v1,redemption-003)", { seed: "encrypted", result: null, consumed: false }) }, commands: [{ name: "atomic_write", operands: { writes: ["result", "consumed"], requireAtomic: true } }], expected: { durableRows: durable("REDEEMING(v1,redemption-003)", { seed: "encrypted", result: null, consumed: false }) } },
  { id: "cleanup-pending-seed-refused", operation: "reject", pre: { durableRows: durable("REDEEMING(v1,redemption-004)", { seed: "encrypted" }) }, commands: [{ name: "cleanup_seed", operands: { pendingSeedAction: "refuse", requiresDurableCompletion: true } }], expected: { durableRows: durable("REDEEMING(v1,redemption-004)", { seed: "encrypted" }) } },
  { id: "same-redemption-contenders", operation: "transaction", pre: { durableRows: durable("ACTIVE(v1)", { redemptionId: "redemption-001", issuanceCount: 0 }) }, commands: [{ name: "redeem_if_active", operands: { redemptionId: "redemption-001", attempts: 20, result: "same-result", cachedOutcome: { status: "issued", result: "same-result" } } }], expected: { durableRows: durable("CONSUMED(v1)", { redemptionId: "redemption-001", issuanceCount: 1, result: "same-result" }) } },
  { id: "different-redemption-rejected", operation: "reject", pre: { durableRows: durable("CONSUMED(v1)", { redemptionId: "redemption-001", issuanceCount: 1 }) }, commands: [{ name: "redeem_if_active", operands: { redemptionId: "redemption-002", attempts: 1, result: "different-result" } }], expected: { durableRows: durable("CONSUMED(v1)", { redemptionId: "redemption-001", issuanceCount: 1 }) } },
  { id: "otp-wrong-vs-invalid-magic", operation: "transaction", pre: { durableRows: durable("ACTIVE(v1)", { otpAttempts: 0, invalidMagicOtpAttempts: 0 }) }, commands: [{ name: "wrong_otp_attempts", operands: { attempts: 5, lockAt: 5, invalidMagicAttempts: 0 } }], expected: { durableRows: durable("LOCKED(v1)", { otpAttempts: 5, invalidMagicOtpAttempts: 0 }) } },
  { id: "nonce-replay-rejected", operation: "reject", pre: { durableRows: { nonce: "CONSUMED" } }, commands: [{ name: "consume_nonce", operands: { requiredState: "VERIFYING" } }], expected: { durableRows: { nonce: "CONSUMED" } } },
  { id: "jti-replay-rejected", operation: "reject", pre: { durableRows: { jti: "authorization-jti-001", digest: "digest-a" } }, commands: [{ name: "reserve_jti", operands: { jti: "authorization-jti-001", digest: "digest-b" } }], expected: { durableRows: { jti: "authorization-jti-001", digest: "digest-a" } } },
  { id: "scanner-get-no-mutation", operation: "read-only", pre: { durableRows: durable("ACTIVE(v1)", { consumed: false }) }, commands: [{ name: "scanner_get", operands: { method: "GET", mutate: false } }], expected: { durableRows: durable("ACTIVE(v1)", { consumed: false }) } }
];
delete states.issuanceRecovery;
delete states.semantics;
for (const flow of states.delivery) for (const key of ["encryptedUntilProviderAcceptance", "atomicActivation", "materialDeletedAfterAccept", "oldVersionRemainsActiveWhilePending", "oldVersionInvalidatedOnlyAfterAccept", "replacementMaterialEncryptedUntilAcceptance", "oldVersionRemainsUsable", "replacementDiscardedOnFailure", "providerAcceptedBeforeCrash", "sameIdempotencyKeyOnRetry", "recoveryReconcilesProviderAcceptance", "oneEffectiveSend", "oldVersionInvalidatedAfterRecovery"]) delete flow[key];

async function put(path, value) { await mkdir(dirname(path), { recursive: true }); await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8"); }
await put(resolve(here, "positive.json"), positive); await put(resolve(here, "negative.json"), negative); await put(resolve(here, "states.json"), states);
const files = {}; for (const name of ["positive.json", "negative.json", "states.json", "build.mjs", "validate.mjs", "loader.ts", "rust/Cargo.toml", "rust/Cargo.lock", "rust/src/main.rs"]) files[name] = digest(await readFile(resolve(here, name))); for (const name of ["domains.json", "schemas.json", "authority-material.schema.json", "README.md"]) files[name] = digest(await readFile(resolve(spec, name)));
const manifestCore = { manifestVersion: 1, contractVersion: "tinycloud.share-email-claim/v1", files, testOnly: true }; await put(resolve(here, "manifest.json"), { ...manifestCore, manifestDigest: digest(utf8(jcs(manifestCore))) });
console.log(JSON.stringify({ manifestDigest: digest(utf8(jcs(manifestCore))), files }, null, 2));

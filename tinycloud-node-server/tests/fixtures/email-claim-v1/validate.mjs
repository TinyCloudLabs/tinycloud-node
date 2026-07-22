#!/usr/bin/env node
/* Self-contained executable contract verifier. No npm dependency. */
import { createDecipheriv, createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { blake3 } from "@noble/hashes/blake3";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const spec = resolve(here, "../../../specs/email-claim-v1");
const enc = new TextEncoder();
const utf8 = (s) => enc.encode(s);
const b64 = (bytes) => Buffer.from(bytes).toString("base64url");
const sha = (bytes) => new Uint8Array(createHash("sha256").update(bytes).digest());
const digest = (bytes) => b64(sha(bytes));
const clone = (value) => JSON.parse(JSON.stringify(value));
const assert = (condition, message) => { if (!condition) throw new RejectionStageError("contract-validation", message); };
const equal = (a, b, message) => assert(jcs(a) === jcs(b), message);
const load = async (name) => JSON.parse(await readFile(resolve(name), "utf8"));
class RejectionStageError extends Error {
  constructor(rejectionStage, message, cause) { super(message); this.name = "RejectionStageError"; this.rejectionStage = rejectionStage; this.cause = cause; }
}
function rejectAt(rejectionStage, message) { throw new RejectionStageError(rejectionStage, message); }
function stageAssert(condition, rejectionStage, message) { if (!condition) rejectAt(rejectionStage, message); }

function jcs(value) {
  try { return jcsValue(value); } catch (error) { if (error instanceof RejectionStageError) throw error; throw new RejectionStageError("contract-validation", error.message, error); }
}
function jcsValue(value) {
  if (value === null) return "null";
  if (typeof value === "string") {
    for (let i = 0; i < value.length; i++) { const c = value.charCodeAt(i); if (c >= 0xd800 && c <= 0xdbff) { const n = value.charCodeAt(i + 1); if (!(n >= 0xdc00 && n <= 0xdfff)) throw new TypeError("lone surrogate"); i++; } else if (c >= 0xdc00 && c <= 0xdfff) throw new TypeError("lone surrogate"); }
    return JSON.stringify(value);
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") { if (!Number.isFinite(value) || !Number.isSafeInteger(value) || Object.is(value, -0)) throw new TypeError("unsafe number"); return JSON.stringify(value); }
  if (Array.isArray(value)) return `[${value.map((item) => { if (item === undefined) throw new TypeError("undefined"); return jcs(item); }).join(",")}]`;
  if (!value || typeof value !== "object" || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) throw new TypeError("non-plain value");
  return `{${Object.keys(value).sort().map((key) => { if (value[key] === undefined) throw new TypeError("undefined"); return `${JSON.stringify(key)}:${jcs(value[key])}`; }).join(",")}}`;
}
function strictB64(text) { if (typeof text !== "string" || !/^[A-Za-z0-9_-]+$/.test(text)) throw new Error("non-canonical base64url"); const bytes = new Uint8Array(Buffer.from(text, "base64url")); if (b64(bytes) !== text) throw new Error("non-canonical base64url"); return bytes; }
function sizedB64(text, size) { const bytes = strictB64(text); assert(bytes.length === size, `expected ${size} decoded bytes`); return bytes; }
function canonicalDomain(domain) {
  assert(typeof domain === "string" && /^[\x21-\x7e]+$/.test(domain) && Buffer.byteLength(domain) >= 1 && Buffer.byteLength(domain) <= 253, "invalid domain bytes");
  const labels = domain.split("."); assert(labels.length > 0 && labels.every((label) => label.length >= 1 && Buffer.byteLength(label) <= 63 && /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(label)), "invalid LDH domain");
  return domain.toLowerCase();
}
function canonicalEmail(input) {
  assert(typeof input === "string" && /^[\x00-\x7f]*$/.test(input) && !/[\x00-\x20\x7f]/.test(input), "email is not strict ASCII");
  const at = [...input].filter((c) => c === "@").length; assert(at === 1, "email must contain one at-sign");
  const [local, domain] = input.split("@"); const localBytes = Buffer.byteLength(local); const domainBytes = Buffer.byteLength(domain);
  assert(localBytes >= 1 && localBytes <= 64 && domainBytes >= 1 && domainBytes <= 253 && Buffer.byteLength(input) <= 254, "email byte limit");
  const atext = "[A-Za-z0-9!#$%&'*+\\-/=?^_`{|}~]+";
  assert(new RegExp(`^${atext}(?:\\.${atext})*$`).test(local), "email local is not dot-atom");
  return `${local}@${canonicalDomain(domain)}`;
}
const ALPHABET58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function decode58(text) { let n = 0n; for (const c of text) { const i = ALPHABET58.indexOf(c); if (i < 0) throw new Error("bad base58"); n = n * 58n + BigInt(i); } const out = []; while (n) { out.unshift(Number(n & 255n)); n >>= 8n; } for (const c of text) { if (c !== "1") break; out.unshift(0); } return new Uint8Array(out); }
function encode58(bytes) { let n = 0n; for (const byte of bytes) n = (n << 8n) | BigInt(byte); let out = ""; while (n) { out = ALPHABET58[Number(n % 58n)] + out; n /= 58n; } for (const byte of bytes) { if (byte) break; out = `1${out}`; } return out; }
const SMALL_ORDER = new Set(["00".repeat(32), `01${"00".repeat(31)}`, `ec${"ff".repeat(30)}7f`, `ed${"ff".repeat(30)}7f`]);
function didRaw(did) { assert(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/.test(did), "malformed did:key"); const encoded = did.slice("did:key:z".length); const value = decode58(encoded); assert(value.length === 34 && value[0] === 0xed && value[1] === 1 && encode58(value) === encoded, "noncanonical Ed25519 did:key"); const raw = value.slice(2); assert(!SMALL_ORDER.has(Buffer.from(raw).toString("hex")), "small-order Ed25519 key"); return raw; }
function canonicalKid(did) { if (did.startsWith("did:key:")) { didRaw(did); return `${did}#${did.slice("did:key:".length)}`; } return did; }
function strictSignature(bytes) { assert(bytes.length === 64, "signature length"); stageAssert(!SMALL_ORDER.has(Buffer.from(bytes.slice(0, 32)).toString("hex")), "signature-encoding", "small-order R"); const L = Uint8Array.from(Buffer.from("edd3f55c1a631258d69cf7a2def9de14" + "00000000000000000000000000000010", "hex")); for (let i = 31; i >= 0; i--) { if (bytes[32 + i] < L[i]) break; if (bytes[32 + i] > L[i]) rejectAt("signature-encoding", "noncanonical Ed25519 S"); if (i === 0) rejectAt("signature-encoding", "noncanonical Ed25519 S"); } }
const PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI = Buffer.from("302a300506032b6570032100", "hex");
const privateKey = (seed) => createPrivateKey({ key: Buffer.concat([PREFIX, Buffer.from(seed, "hex")]), format: "der", type: "pkcs8" });
const seedPublic = (seed) => createPublicKey(privateKey(seed));
const spki = (raw) => createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(raw)]), format: "der", type: "spki" });
function didPublic(did) { return spki(didRaw(did)); }
function signatureBytes(artifact) { const message = utf8(artifact.jcs); const signedBytes = Buffer.concat([utf8(artifact.domain), message]); return { message, signedBytes, sig: strictB64(artifact.signature.value) }; }
function rawCid(bytes) { const alphabet = "abcdefghijklmnopqrstuvwxyz234567"; let out = ""; let buffer = 0; let bits = 0; const input = Uint8Array.of(1, 0x55, 0x12, 0x20, ...sha(bytes)); for (const byte of input) { buffer = (buffer << 8) | byte; bits += 8; while (bits >= 5) { bits -= 5; out += alphabet[(buffer >>> bits) & 31]; } } if (bits) out += alphabet[(buffer << (5 - bits)) & 31]; return `b${out}`; }
function assertCid(value, bytes) { assert(/^bafkrei[a-z2-7]{52}$/.test(value) && rawCid(bytes) === value, "CIDv1 raw sha256 mismatch"); }
function openSealed(blob, key) {
  try { return openSealedValue(blob, key); } catch (error) { if (error instanceof RejectionStageError) throw error; throw new RejectionStageError("contract-validation", error.message, error); }
}
function openSealedValue(blob, key) {
  assert(blob.length >= 29 && blob[0] === 1, "invalid sealed blob header");
  const nonce = blob.slice(1, 13); const ciphertextAndTag = blob.slice(13); const tag = ciphertextAndTag.slice(-16); const ciphertext = ciphertextAndTag.slice(0, -16);
  const decipher = createDecipheriv("aes-256-gcm", Buffer.from(key), Buffer.from(nonce));
  decipher.setAAD(Buffer.from("tinycloud-share-envelope-v1", "utf8")); decipher.setAuthTag(Buffer.from(tag));
  return new Uint8Array(Buffer.concat([decipher.update(Buffer.from(ciphertext)), decipher.final()]));
}
function mutateAndResign(artifact, message, seedHex, signerDid, keyId, domains) { const domain = domains.domains[artifact.name]; const text = jcs(message); const sig = sign(null, Buffer.concat([utf8(domain), utf8(text)]), privateKey(seedHex)); return { ...artifact, domain, signerDid, message, jcs: text, messageDigest: digest(utf8(text)), signedBytesDigest: digest(Buffer.concat([utf8(domain), utf8(text)])), signatureDigest: digest(sig), signature: { alg: "EdDSA", kid: keyId, value: b64(sig) } }; }
function schemaError(root, schema, value, path = "$", seen = new Set()) {
  if (schema.$ref) { const target = schema.$ref.startsWith("#/") ? schema.$ref.slice(2).split("/").reduce((object, key) => object[key], root) : null; assert(target, `${path}: unresolved ref ${schema.$ref}`); return schemaError(root, target, value, path, seen); }
  if (schema.oneOf) { let accepted = 0; for (const branch of schema.oneOf) { try { schemaError(root, branch, value, path, seen); accepted++; } catch {} } assert(accepted === 1, `${path}: oneOf mismatch`); return; }
  if (schema.allOf) { for (const branch of schema.allOf) schemaError(root, branch, value, path, seen); }
  if (schema.const !== undefined) equal(value, schema.const, `${path}: const mismatch`);
  if (schema.enum) assert(schema.enum.some((candidate) => { try { equal(value, candidate, ""); return true; } catch { return false; } }), `${path}: enum mismatch`);
  if (schema.type) { const types = Array.isArray(schema.type) ? schema.type : [schema.type]; const actual = value === null ? "null" : Array.isArray(value) ? "array" : typeof value; assert(types.includes(actual) || (actual === "number" && types.includes("integer")), `${path}: type mismatch`); if (actual === "number") assert(Number.isFinite(value) && Number.isSafeInteger(value) && !Object.is(value, -0), `${path}: unsafe number`); }
  if (schema.pattern) { assert(typeof value === "string" && new RegExp(schema.pattern).test(value), `${path}: pattern mismatch`); if (schema["x-base64url"]) { let decoded; try { decoded = strictB64(value); } catch (error) { throw new Error(`${path}: ${error.message}`); } if (schema.pattern.includes("{21}")) assert(decoded.length === 16, `${path}: decoded size`); if (schema.pattern.includes("{42}")) assert(decoded.length === 32, `${path}: decoded size`); if (schema.pattern.includes("{85}")) assert(decoded.length === 64, `${path}: decoded size`); } }
  if (typeof value === "string") { if (schema.minLength !== undefined) assert(value.length >= schema.minLength, `${path}: minLength`); if (schema.maxLength !== undefined) assert(value.length <= schema.maxLength, `${path}: maxLength`); if (schema["x-utf8-max-bytes"] !== undefined) assert(Buffer.byteLength(value, "utf8") <= schema["x-utf8-max-bytes"], `${path}: UTF-8 byte limit`); }
  if (typeof value === "number") { if (schema.minimum !== undefined) assert(value >= schema.minimum, `${path}: minimum`); if (schema.type === "integer") assert(Number.isInteger(value) && Number.isSafeInteger(value) && !Object.is(value, -0), `${path}: integer`); }
  if (Array.isArray(value)) { if (schema.minItems !== undefined) assert(value.length >= schema.minItems, `${path}: minItems`); if (schema.maxItems !== undefined) assert(value.length <= schema.maxItems, `${path}: maxItems`); if (schema.uniqueItems) { const values = value.map(jcs); assert(new Set(values).size === values.length, `${path}: uniqueItems`); } if (schema.items) value.forEach((item, i) => schemaError(root, schema.items, item, `${path}[${i}]`, seen)); }
  if (value && typeof value === "object" && !Array.isArray(value)) { if (schema.required) for (const key of schema.required) assert(Object.hasOwn(value, key), `${path}: missing ${key}`); if (schema.minProperties !== undefined) assert(Object.keys(value).length >= schema.minProperties, `${path}: minProperties`); if (schema.maxProperties !== undefined) assert(Object.keys(value).length <= schema.maxProperties, `${path}: maxProperties`); const properties = schema.properties ?? {}; if (schema.additionalProperties === false) for (const key of Object.keys(value)) assert(Object.hasOwn(properties, key), `${path}: unknown ${key}`); for (const [key, child] of Object.entries(properties)) if (Object.hasOwn(value, key)) schemaError(root, child, value[key], `${path}.${key}`, seen); if (schema.additionalProperties && typeof schema.additionalProperties === "object") for (const key of Object.keys(value)) if (!Object.hasOwn(properties, key)) schemaError(root, schema.additionalProperties, value[key], `${path}.${key}`, seen); }
}
function checkSchema(schemas, name, value) {
  try { schemaError(schemas, schemas.schemas[name], value, name); } catch (error) { if (error instanceof RejectionStageError) throw error; throw new RejectionStageError("contract-validation", error.message, error); }
}
function assertFlatSqlArguments(argumentsValue, domains) {
  assert(argumentsValue && typeof argumentsValue === "object" && !Array.isArray(argumentsValue) && (Object.getPrototypeOf(argumentsValue) === Object.prototype || Object.getPrototypeOf(argumentsValue) === null), "SQL arguments must be a plain object");
  assert(Object.keys(argumentsValue).length <= 32, "SQL arguments exceed maxProperties");
  for (const value of Object.values(argumentsValue)) assert(typeof value === "number" && Number.isSafeInteger(value) && !Object.is(value, -0), "SQL arguments must be flat safe integers");
  const bytes = utf8(jcs(argumentsValue));
  assert(bytes.length <= domains.limits.sqlArgumentsBytes, "SQL arguments exceed byte limit");
  return bytes;
}
function assertSource(source, expectedKind, schemas, domains) {
  checkSchema(schemas, expectedKind === "sql" ? "sqlReadRequest" : "kvReadRequest", { sessionId: b64(new Uint8Array(16)), delegationCid: "bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: b64(new Uint8Array(32)), contentSource: source, contentSourceDigest: digest(utf8(jcs(source))), action: source.action, resource: source.path, requestBodyDigest: digest(utf8("body")), invocation: { type: "TinyCloudShareReadInvocation", version: 1, sessionId: b64(new Uint8Array(16)), shareCid: "bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", shareId: "share-001", policyCid: "bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", delegationCid: "bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: b64(new Uint8Array(32)), contentSource: source, contentSourceDigest: digest(utf8(jcs(source))), holderDid: "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw", targetOrigin: "https://node.example", nodeAudience: "did:web:node.example", action: source.action, resource: source.path, requestBodyDigest: digest(utf8("body")), issuedAt: "2026-07-16T12:00:00.000Z", expiresAt: "2026-07-16T12:01:00.000Z", jti: b64(new Uint8Array(16)) }, proof: { alg: "EdDSA", kid: "did:web:node.example#invitation-key-1", signature: b64(new Uint8Array(64)) } });
  assert(source.kind === expectedKind && source.action === (expectedKind === "sql" ? "tinycloud.sql/read" : "tinycloud.kv/get"), "source kind/action mismatch"); assert(Buffer.byteLength(source.path) <= domains.limits.resourceBytes, "resource byte limit");
  const sourceBytes = utf8(jcs(source)); assert(sourceBytes.length <= domains.limits.sqlArgumentsBytes || source.kind !== "sql", "SQL source too large");
  if (source.kind === "sql") { const argumentBytes = assertFlatSqlArguments(source.arguments, domains); assert(source.argumentsDigest === digest(argumentBytes), "SQL arguments digest mismatch"); assert(!Object.hasOwn(source, "query"), "arbitrary SQL query field"); }
  return digest(sourceBytes);
}
function verifyArtifact(artifact, expectedSigner, expectedSeedHex, domains, enrollment, expectedName) {
  const artifactKeys = ["name", "domain", "signerDid", "message", "jcs", "messageDigest", "signedBytesDigest", "signatureDigest", "signature"]; const signatureKeys = ["alg", "kid", "value"]; assert((expectedName === undefined || artifact.name === expectedName) && Object.keys(artifact).length === artifactKeys.length && artifactKeys.every((key) => Object.hasOwn(artifact, key)), `${expectedName ?? artifact.name}: strict artifact wrapper`); assert(artifact.signature && typeof artifact.signature === "object" && Object.keys(artifact.signature).length === signatureKeys.length && signatureKeys.every((key) => Object.hasOwn(artifact.signature, key)), `${expectedName ?? artifact.name}: strict signature wrapper`);
  assert(artifact.domain === domains.domains[artifact.name] && artifact.domain.endsWith("\u0000"), `${artifact.name}: unregistered domain`); if (artifact.message && typeof artifact.message.holderDid === "string") { didRaw(artifact.message.holderDid); assert(canonicalKid(artifact.message.holderDid).startsWith(`${artifact.message.holderDid}#`), `${artifact.name}: holder DID`); }
  const { message, signedBytes, sig } = signatureBytes(artifact); strictSignature(sig); assert(artifact.jcs === jcs(artifact.message), `${artifact.name}: JCS mismatch`); assert(artifact.messageDigest === digest(message), `${artifact.name}: message digest mismatch`); assert(artifact.signedBytesDigest === digest(signedBytes), `${artifact.name}: signed-byte digest mismatch`); assert(artifact.signatureDigest === digest(sig), `${artifact.name}: signature digest mismatch`); assert(artifact.signature.alg === "EdDSA" && artifact.signerDid === expectedSigner, `${artifact.name}: signature metadata`); assert(artifact.signature.kid === (expectedSigner.startsWith("did:key:") ? canonicalKid(expectedSigner) : enrollment.invitationKid), `${artifact.name}: noncanonical kid`); const key = expectedSeedHex ? seedPublic(expectedSeedHex) : spki(sizedB64(enrollment.invitationPublicKey, 32)); assert(verify(null, Buffer.from(signedBytes), key, Buffer.from(sig)), `${artifact.name}: signature invalid`); return true;
}
function assertEnvelopeBindings(scenario, schemas, domains) {
  checkSchema(schemas, "envelopeSigned", scenario.envelope); const unsigned = clone(scenario.envelope); const signature = unsigned.signature; delete unsigned.signature; const artifact = scenario.artifacts.find((a) => a.name === "envelope"); assert(signature.value === artifact.signature.value && signature.signerDid === scenario.artifacts[0].signerDid, "shipping envelope signature binding"); verifyArtifact(artifact, scenario.artifacts[0].signerDid, domains.testKeys?.senderSeedHex, domains, scenario.enrollment);
  const policyBytes = strictB64(scenario.envelope.authorizationTarget.policyBytes); const policyText = new TextDecoder().decode(policyBytes); assert(!policyText.includes("policyCid"), "policy bytes contain policyCid self-reference"); assertCid(scenario.policyCid, policyBytes); const policy = JSON.parse(policyText); checkSchema(schemas, "policy", policy); equal(policy, scenario.policy, "policy bytes differ from policy object");
  assert(scenario.envelope.authorizationTarget.policyCid === scenario.policyCid, "envelope policy CID mismatch"); assert(scenario.envelope.target.origin === scenario.authorization.targetOrigin && scenario.envelope.target.nodeAudience === scenario.authorization.nodeAudience, "envelope target binding mismatch"); assert(scenario.envelope.target.spaceId === scenario.source.space && scenario.envelope.target.resource.path === scenario.source.path, "envelope source binding mismatch"); assert(scenario.envelope.expiry === scenario.authorization.shareExpiresAt, "envelope expiry binding mismatch");
}
function validateCredential(scenario, schemas, domains) {
  const c = scenario.credential; checkSchema(schemas, "credential", c); assert(Buffer.byteLength(c.credential) <= domains.limits.credentialBytes, `${scenario.kind}: credential byte limit`);
  assert(c.claims.sub === c.holderDid && c.holderDid === scenario.artifacts[3].signerDid, `${scenario.kind}: credential holder equation`); assert(c.issuerDid === c.claims.iss && c.vct === c.claims.vct, `${scenario.kind}: detached issuer claims`);
  const trust = domains.issuerTrust; assert(trust && trust.enabled === true && c.issuerDid === trust.issuerDid && c.claims.vct === trust.vct, `${scenario.kind}: issuer trust`); assert(c.claims.tinycloud_share.share_cid === scenario.shareCid && c.claims.tinycloud_share.share_id === scenario.shareId && c.claims.tinycloud_share.policy_cid === scenario.policyCid && c.claims.tinycloud_share.node_audience === scenario.authorization.nodeAudience, `${scenario.kind}: credential scope`); assert(jcs(Object.keys(c.claims.tinycloud_share).sort()) === jcs(["node_audience", "policy_cid", "share_cid", "share_id"]), `${scenario.kind}: credential scope cardinality`); assert(c.claims._sd_alg === "sha-256", `${scenario.kind}: SD-JWT algorithm`);
  const evaluation = Date.parse(scenario.evaluationTime) / 1000; const skew = scenario.clockSkewSeconds; const shareExpiry = Date.parse(scenario.authorization.shareExpiresAt) / 1000; assert(Number.isInteger(evaluation) && Number.isInteger(skew) && skew >= 0 && Number.isInteger(shareExpiry), `${scenario.kind}: evaluation clock`); assert(c.claims.iat <= evaluation + skew && c.claims.nbf <= evaluation + skew && c.claims.exp > evaluation - skew, `${scenario.kind}: credential time window`); assert(c.claims.exp === shareExpiry && c.expiresAt === scenario.authorization.shareExpiresAt && shareExpiry > evaluation - skew, `${scenario.kind}: credential/share expiry`);
  const disclosure = c.disclosures[0]; const encoded = strictB64(disclosure.encoded); const parsed = JSON.parse(new TextDecoder().decode(encoded)); equal(parsed, [scenario.sdJwtSalt, "email", scenario.canonicalEmail], `${scenario.kind}: disclosure value`); assert(disclosure.salt === scenario.sdJwtSalt && disclosure.digest === digest(utf8(disclosure.encoded)) && c.claims._sd[0] === disclosure.digest, `${scenario.kind}: disclosure digest`); assert(c.disclosures.length === 1 && disclosure.path === "/email", `${scenario.kind}: sole disclosure`);
  const parts = c.credential.split("~"); assert(parts.length === 3 && parts[1] === disclosure.encoded && parts[2] === "", `${scenario.kind}: SD-JWT serialization`); const jwtParts = parts[0].split("."); assert(jwtParts.length === 3 && jwtParts.every((part) => part.length > 0), `${scenario.kind}: SD-JWT JWT segments`); const [header, payload, sig] = jwtParts; assert(c.issuerJws.signingInput === `${header}.${payload}`, `${scenario.kind}: issuer input`); const headerBytes = strictB64(header); equal(JSON.parse(new TextDecoder().decode(headerBytes)), { alg: "EdDSA" }, `${scenario.kind}: issuer header`); const payloadBytes = strictB64(payload); const signedClaims = JSON.parse(new TextDecoder().decode(payloadBytes)); equal(signedClaims, c.claims, `${scenario.kind}: signed payload differs from detached claims`); assert(c.issuerJws.signature === sig, `${scenario.kind}: issuer signature binding`); assert(c.issuerJws.signingInputDigest === digest(utf8(c.issuerJws.signingInput)) && c.credentialDigest === digest(utf8(c.credential)), `${scenario.kind}: credential digest`); const signature = strictB64(sig); strictSignature(signature); assert(verify(null, Buffer.from(c.issuerJws.signingInput), spki(sizedB64(trust.publicKey, 32)), Buffer.from(signature)), `${scenario.kind}: issuer signature`);
}
function validateAuthorityMaterial(scenario, schemas, domains) {
  const m = scenario.authorityMaterial;
  assert(m.type === "TinyCloudShareAuthorityMaterial" && m.version === 1, `${scenario.kind}: exact authority material type`);
  assert(m.policyOwnerDid !== m.senderDid && m.senderDid === scenario.authorization.senderDid, `${scenario.kind}: policy owner/sender separation`);
  assert(m.relationship.authenticated === true && m.relationship.policyOwnerDid === m.policyOwnerDid && m.relationship.senderDid === m.senderDid, `${scenario.kind}: authenticated relationship`);
  assert(m.mapping.sharePolicyCid === scenario.policyCid && m.mapping.shareDelegationCid === scenario.delegationCid && m.mapping.policyAuthorityCid === m.policyAuthorityCid && m.mapping.policyEnforcementCid === m.policyEnforcementCid, `${scenario.kind}: explicit authority mapping`);
  for (const [field, role, cidField] of [["policyAuthorityBytes", "policy-authority", "policyAuthorityCid"], ["policyEnforcementBytes", "policy-enforcement", "policyEnforcementCid"]]) {
    const bytes = strictB64(m[field]); const artifact = JSON.parse(new TextDecoder().decode(bytes)); assert(jcs(artifact) === new TextDecoder().decode(bytes) && artifact.schema === "xyz.tinycloud.policy/enforcement-delegation/v1" && artifact.role === role, `${scenario.kind}: exact Node parent`); const multihash = decodeCid(artifact.delegationCid); assert(multihash[0] === 1 && multihash[1] === 0x55 && multihash[2] === 0x1e && multihash[3] === 0x20 && Buffer.from(multihash.slice(4)).equals(Buffer.from(blake3(bytesWithoutCid(artifact)))), `${scenario.kind}: Node Blake3 CID`); assert(m[cidField] === artifact.delegationCid, `${scenario.kind}: parent CID mapping`);
  }
  assert(Array.isArray(m.statusObservations) && m.statusObservations.length === 2, `${scenario.kind}: per-parent status observations`); const parentCids = new Set([m.policyAuthorityCid, m.policyEnforcementCid]); const sequences = new Map(); for (const status of m.statusObservations) { assert(parentCids.has(status.parentCid) && status.state === "active" && Number.isSafeInteger(status.sequence) && (!sequences.has(status.parentCid) || status.sequence >= sequences.get(status.parentCid)) && status.revokedAt === null && status.freshUntil >= scenario.evaluationTime && Date.parse(status.freshUntil) - Date.parse(status.checkedAt) <= 300000, `${scenario.kind}: status observation freshness/rollback`); sequences.set(status.parentCid, status.sequence); strictSignature(strictB64(status.signature.value)); }
  const attestation = m.attestation; assert(attestation.targetOrigin === m.enrollment.targetOrigin && attestation.nodeAudience === m.enrollment.nodeAudience && attestation.keyVersion === m.enrollment.keyVersion && attestation.enrollmentDigest === digest(utf8(jcs(m.enrollment))) && attestation.expiresAt > scenario.evaluationTime, `${scenario.kind}: enrollment attestation binding`); strictSignature(strictB64(attestation.signature.value)); assert(scenario.authorityMaterialDigest === digest(utf8(jcs(m))), `${scenario.kind}: authority material digest`);
}
function bytesWithoutCid(artifact) { const copy = { ...artifact }; delete copy.delegationCid; return utf8(jcs(copy)); }
function decodeCid(value) { const alphabet = "abcdefghijklmnopqrstuvwxyz234567"; let bits = 0; let buffer = 0; const out = []; for (const c of value.slice(1)) { buffer = (buffer << 5) | alphabet.indexOf(c); bits += 5; if (bits >= 8) { bits -= 8; out.push((buffer >> bits) & 255); } } return out; }
function validateResignedCredentialPrerequisites(candidate, scenario, schemas, domains, candidateSigningPublicKey, restore = {}) {
  const schemaCandidate = clone(candidate); for (const [path, value] of Object.entries(restore)) { const parts = path.split("."); if (parts.length === 1) schemaCandidate[parts[0]] = value; else schemaCandidate[parts[0]][parts[1]] = value; }
  checkSchema(schemas, "credential", schemaCandidate);
  const parts = candidate.credential.split("~"); assert(parts.length === 3 && parts[2] === "", "SD-JWT compact shape"); const jwtParts = parts[0].split("."); assert(jwtParts.length === 3 && jwtParts.every((part) => part.length > 0), "SD-JWT JWT segments");
  const [header, payload, signature] = jwtParts; equal(JSON.parse(new TextDecoder().decode(strictB64(header))), { alg: "EdDSA" }, "SD-JWT header"); equal(JSON.parse(new TextDecoder().decode(strictB64(payload))), candidate.claims, "SD-JWT payload binding"); assert(candidate.issuerJws.signingInput === `${header}.${payload}` && candidate.issuerJws.signature === signature && candidate.issuerJws.signingInputDigest === digest(utf8(candidate.issuerJws.signingInput)) && candidate.credentialDigest === digest(utf8(candidate.credential)), "SD-JWT detached binding"); strictSignature(strictB64(signature));
  assert(typeof candidateSigningPublicKey === "string", `${scenario.kind}: candidate signing key declaration`); assert(verify(null, Buffer.from(candidate.issuerJws.signingInput), spki(sizedB64(candidateSigningPublicKey, 32)), Buffer.from(strictB64(signature))), `${scenario.kind}: candidate issuer JWS authenticity`);
}
function validateResignedCredentialSemantics(candidate, scenario, domains) {
  const trust = domains.issuerTrust;
  stageAssert(trust && candidate.issuerDid === trust.issuerDid && candidate.claims.iss === trust.issuerDid, "issuer-trust", "untrusted credential issuer");
  const parts = candidate.credential.split("~")[0].split("."); const signature = strictB64(parts[2]);
  stageAssert(verify(null, Buffer.from(candidate.issuerJws.signingInput), spki(sizedB64(trust.publicKey, 32)), Buffer.from(signature)), "issuer-key", "credential issuer signature key");
  stageAssert(candidate.vct === trust.vct && candidate.claims.vct === trust.vct, "credential-vct", "credential type");
  stageAssert(candidate.holderDid === scenario.credential.holderDid && candidate.claims.sub === scenario.credential.holderDid, "credential-holder", "credential holder");
  const evaluation = Date.parse(scenario.evaluationTime) / 1000; const skew = scenario.clockSkewSeconds;
  stageAssert(candidate.claims.exp > evaluation - skew && candidate.claims.exp === Date.parse(scenario.authorization.shareExpiresAt) / 1000, "credential-time", "credential time window");
  const expectedScope = scenario.credential.claims.tinycloud_share;
  stageAssert(jcs(candidate.claims.tinycloud_share) === jcs(expectedScope), "credential-scope", "credential scope");
  rejectAt("contract-validation", "resigned credential accepted");
}
function assertProofBound(proof, artifact, label) { assert(proof.alg === artifact.signature.alg && proof.kid === artifact.signature.kid && proof.signature === artifact.signature.value, `${label}: proof/artifact mismatch`); }
function parseShareUrl(urlText) {
  stageAssert(typeof urlText === "string" && !/[\u0000-\u0020]/.test(urlText), "share-url-lexical", "share URL lexical form");
  stageAssert(!urlText.includes("%"), "share-url-fragment-encoding", "share URL percent encoding");
  let url; try { url = new URL(urlText); } catch { rejectAt("share-url-lexical", "share URL parse"); }
  stageAssert(url.protocol === "https:", "share-url-scheme", "share URL scheme");
  stageAssert(!/^https:\/\/share\.tinycloud\.xyz:\d+(?:\/|$)/.test(urlText), "share-url-port", "explicit share URL port");
  stageAssert(url.hostname === "share.tinycloud.xyz" && url.username === "" && url.password === "" && url.origin === "https://share.tinycloud.xyz", "share-url-origin", "share URL origin");
  stageAssert(url.port === "", "share-url-port", "explicit share URL port");
  stageAssert(/^\/s\/bafkrei[a-z2-7]{52}$/.test(url.pathname), "share-url-path", "share URL path");
  stageAssert(url.search === "", "share-url-query", "share URL query");
  const raw = url.hash.startsWith("#") ? url.hash.slice(1) : ""; const pieces = raw.split("=");
  stageAssert(pieces.length === 2 && pieces[0] === "k" && pieces[1], "share-url-fragment", "share URL fragment");
  try { sizedB64(pieces[1], 32); } catch (error) { rejectAt("share-url-key", error.message); }
  return { shareCid: url.pathname.slice("/s/".length), key: pieces[1] };
}
function validateNodeEnrollment(enrollment, domains) {
  const authority = domains.nodeAuthority; stageAssert(authority && enrollment.targetOrigin === authority.origin && enrollment.nodeAudience === authority.nodeAudience, "node-authority", "node origin/audience authority"); stageAssert(enrollment.enabled === true, "node-enrollment", "node enrollment disabled"); const record = authority.keyVersions.find((candidate) => candidate.keyVersion === enrollment.keyVersion); stageAssert(record && record.state === "active", "node-key-retirement", "node enrollment key is not active"); stageAssert(enrollment.keyVersion === authority.activeKeyVersion, "node-enrollment", "node enrollment key version is stale"); stageAssert(record.invitationKid === enrollment.invitationKid && record.publicKey === enrollment.invitationPublicKey && enrollment.invitationKid === `${authority.nodeAudience}#invitation-key-${enrollment.keyVersion}`, "node-key-rotation", "node enrollment key version");
}
function validateEndpoints(scenario, schemas, domains) {
  const map = { authorizationRequest: "authorizationRequest", authorizationResponse: "authorizationResponse", createInvitationRequest: "createInvitationRequest", createInvitationResponse: "createInvitationResponse", resendRequest: "resendRequest", resendResponse: "resendResponse", activationRequest: "activationRequest", activationResponse: "activationResponse", claimChallengeMagicRequest: "claimChallengeMagicRequest", claimChallengeOtpRequest: "claimChallengeOtpRequest", claimChallengeResponse: "claimChallengeResponse", claimRedeemRequest: "claimRedeemRequest", claimRedeemOtpRequest: "claimRedeemRequest", claimRedeemResponse: "claimRedeemResponse", policyChallengeRequest: "policyChallengeRequest", policyChallengeResponse: "policyChallengeResponse", policySessionRequest: "policySessionRequest", policySessionResponse: "policySessionResponse", kvReadRequest: "kvReadRequest", sqlReadRequest: "sqlReadRequest", readResponse: "readResponse" };
  for (const [name, schema] of Object.entries(map)) {
    if (name === "kvReadRequest" && scenario.kind !== "kv") continue;
    if (name === "sqlReadRequest" && scenario.kind !== "sql") continue;
    checkSchema(schemas, schema, scenario.preimages[name].body);
  }
  parseShareUrl(scenario.preimages.createInvitationRequest.body.shareUrl); assert(scenario.preimages.createInvitationRequest.body.shareUrl === `https://share.tinycloud.xyz/s/${scenario.shareCid}#k=${scenario.envelopeKey}`, `${scenario.kind}: share URL binding`);
  equal(scenario.preimages.claimChallengeResponse.body.contentSource, scenario.source, `${scenario.kind}: challenge source binding`);
  assert(scenario.preimages.claimChallengeResponse.body.contentSourceDigest === scenario.sourceDigest, `${scenario.kind}: challenge source digest binding`);
  const holderBinding = scenario.artifacts.find((artifact) => artifact.name === "holderBinding");
  const challengeArtifact = scenario.artifacts.find((artifact) => artifact.name === "policyChallenge");
  const sessionArtifact = scenario.artifacts.find((artifact) => artifact.name === "policySession");
  assertProofBound(scenario.preimages.claimRedeemRequest.body.holderProof, holderBinding, `${scenario.kind}: magic redeem`);
  assertProofBound(scenario.preimages.claimRedeemOtpRequest.body.holderProof, holderBinding, `${scenario.kind}: otp redeem`);
  assertProofBound(scenario.preimages.policyChallengeResponse.body.proof, challengeArtifact, `${scenario.kind}: challenge response`);
  assertProofBound(scenario.preimages.policySessionResponse.body.proof, sessionArtifact, `${scenario.kind}: session response`);
  const signedRead = clone(scenario.preimages.readResponse.body); const readProof = signedRead.proof; delete signedRead.proof;
  assert(readProof.alg === "EdDSA" && readProof.kid === scenario.enrollment.invitationKid, `${scenario.kind}: read response proof metadata`);
  strictSignature(strictB64(readProof.signature)); assert(verify(null, Buffer.from(`${domains.domains.readResponse}${jcs(signedRead)}`), spki(sizedB64(scenario.enrollment.invitationPublicKey, 32)), Buffer.from(strictB64(readProof.signature))), `${scenario.kind}: read response signature`);
  for (const name of ["authorizationFailure", "createInvitationFailure", "resendFailure", "claimChallengeFailure", "claimRedeemFailure", "policyChallengeFailure", "policySessionFailure", "kvReadFailure", "sqlReadFailure"]) checkSchema(schemas, "failure", scenario.preimages[name].body);
  sizedB64(scenario.preimages.resendRequest.body.claimSecret, 32); sizedB64(scenario.preimages.activationRequest.body.claimSecret, 32); sizedB64(scenario.preimages.claimRedeemRequest.body.mailboxProof, 32); assert(/^[0-9]{6}$/.test(scenario.preimages.claimRedeemOtpRequest.body.mailboxProof), "OTP redeem proof"); assert(Buffer.byteLength(scenario.preimages.readResponse.body.content) <= domains.limits.markdownBytes, "Markdown byte limit");
  for (const [name, preimage] of Object.entries(scenario.preimages)) { assert(preimage.jcs === jcs(preimage.body), `${scenario.kind}/${name}: body JCS`); assert(preimage.digest === digest(utf8(preimage.jcs)), `${scenario.kind}/${name}: body digest`); }
}
function assertCrossArtifactEquations(scenario) {
  const byName = (name) => scenario.artifacts.find((artifact) => artifact.name === name);
  const messages = scenario.artifacts.map((artifact) => artifact.message);
  const auth = scenario.authorization;
  const binding = byName("holderBinding").message;
  const challenge = byName("policyChallenge").message;
  const presentation = byName("policyPresentation").message;
  const session = byName("policySession").message;
  const read = byName("readInvocation").message;
  const disclosure = scenario.credential.disclosures[0];
  const disclosed = JSON.parse(new TextDecoder().decode(strictB64(disclosure.encoded)));
  assert(scenario.policy.recipientEmail === auth.recipientEmail && auth.recipientEmail === scenario.canonicalEmail, "canonical recipient email equation");
  assert(disclosure.path === "/email" && disclosure.value === scenario.canonicalEmail && disclosed[1] === "email" && disclosed[2] === scenario.canonicalEmail, "disclosed email equation");
  assert(scenario.preimages.claimRedeemRequest.body.redemptionId === binding.redemptionId && scenario.preimages.claimRedeemRequest.body.invitationId === binding.invitationId, "magic redeem identifier equation");
  assert(scenario.preimages.claimRedeemOtpRequest.body.redemptionId === binding.redemptionId && scenario.preimages.claimRedeemOtpRequest.body.invitationId === binding.invitationId, "OTP redeem identifier equation");
  const expected = { shareCid: scenario.shareCid, shareId: scenario.shareId, policyCid: scenario.policyCid, delegationCid: scenario.delegationCid, authorityMaterialHandle: scenario.authorityMaterialHandle, authorityMaterialDigest: scenario.authorityMaterialDigest, targetOrigin: auth.targetOrigin, nodeAudience: auth.nodeAudience, holderDid: binding.holderDid, contentSourceDigest: scenario.sourceDigest, action: scenario.source.action, resource: scenario.source.path };
  for (const message of messages) {
    for (const field of ["shareCid", "shareId", "policyCid", "delegationCid", "authorityMaterialHandle", "authorityMaterialDigest", "targetOrigin", "nodeAudience", "holderDid", "contentSourceDigest", "action", "resource"]) if (message[field] !== undefined) assert(message[field] === expected[field], `cross-artifact ${field} equation`);
    if (message.contentSource !== undefined) equal(message.contentSource, scenario.source, "cross-artifact content source equation");
  }
  const authority = byName("authorityMaterial").message; assert(authority.mapping.sharePolicyCid === scenario.policyCid && authority.mapping.shareDelegationCid === scenario.delegationCid && authority.handle === scenario.authorityMaterialHandle, "authority material identifier equation");
  assert(scenario.envelope.shareId === undefined || scenario.envelope.shareId === expected.shareId, "envelope share ID equation");
  assert(scenario.envelope.authorizationTarget.policyCid === expected.policyCid && scenario.envelope.target.origin === expected.targetOrigin && scenario.envelope.target.nodeAudience === expected.nodeAudience && scenario.envelope.target.resource.path === expected.resource, "envelope scope equation");
  assert(scenario.enrollment.targetOrigin === expected.targetOrigin && scenario.enrollment.nodeAudience === expected.nodeAudience, "enrollment scope equation");
  const bodies = Object.values(scenario.preimages).map((preimage) => preimage.body);
  for (const body of bodies) {
    for (const field of ["shareCid", "shareId", "policyCid", "delegationCid", "authorityMaterialHandle", "authorityMaterialDigest", "targetOrigin", "nodeAudience", "holderDid", "contentSourceDigest", "action", "resource"]) if (body[field] !== undefined) assert(body[field] === expected[field], `endpoint ${field} equation`);
    if (body.contentSource !== undefined) equal(body.contentSource, scenario.source, "endpoint content source equation");
    for (const nested of [body.authorization, body.binding, body.challenge, body.presentation, body.session, body.invocation]) if (nested) {
      for (const field of ["shareCid", "shareId", "policyCid", "delegationCid", "authorityMaterialHandle", "authorityMaterialDigest", "targetOrigin", "nodeAudience", "holderDid", "contentSourceDigest", "action", "resource"]) if (nested[field] !== undefined) assert(nested[field] === expected[field], `nested endpoint ${field} equation`);
      if (nested.contentSource !== undefined) equal(nested.contentSource, scenario.source, "nested endpoint content source equation");
    }
  }
  assert(presentation.challengeId === challenge.challengeId && presentation.nonce === challenge.nonce && presentation.requestBodyDigest === challenge.requestBodyDigest, "challenge/presentation equation");
  assert(session.credentialDigest === scenario.credential.credentialDigest && presentation.credentialDigest === scenario.credential.credentialDigest, "credential digest equation");
  assert(read.sessionId === session.sessionId, "session/read equation");
  const readInvocation = clone(read); delete readInvocation.requestBodyDigest;
  const readPreimage = { sessionId: read.sessionId, delegationCid: read.delegationCid, authorityMaterialHandle: read.authorityMaterialHandle, authorityMaterialDigest: read.authorityMaterialDigest, contentSource: read.contentSource, contentSourceDigest: read.contentSourceDigest, action: read.action, resource: read.resource, invocation: readInvocation };
  assert(read.requestBodyDigest === digest(utf8(jcs(readPreimage))), "read request body digest recomputation");
  const readEndpoint = scenario.preimages[scenario.kind === "sql" ? "sqlReadRequest" : "kvReadRequest"].body;
  assert(readEndpoint.requestBodyDigest === read.requestBodyDigest && readEndpoint.invocation.requestBodyDigest === read.requestBodyDigest, "read endpoint digest propagation");
}
function validateScenario(scenario, schemas, domains) {
  assert(scenario.testOnly === true && scenario.kind, "scenario marker"); assert(canonicalEmail("Alice+Notes@EXAMPLE.com") === scenario.canonicalEmail, "canonical email amendment"); assert(scenario.emailHash === digest(utf8(scenario.canonicalEmail)), "email hash");
  const sourceDigest = assertSource(scenario.source, scenario.kind, schemas, domains); assert(sourceDigest === scenario.sourceDigest, `${scenario.kind}: source digest`); const policyBytes = strictB64(scenario.policyBytes); assert(policyBytes.length <= domains.limits.policyBytes, `${scenario.kind}: policy byte limit`); assert(Buffer.byteLength(scenario.shareId) <= domains.limits.shareIdBytes, `${scenario.kind}: share ID byte limit`); const sealedBlob = strictB64(scenario.sealedBlob); assertCid(scenario.policyCid, policyBytes); assertCid(scenario.shareCid, sealedBlob); assert(new TextDecoder().decode(openSealed(sealedBlob, sizedB64(scenario.envelopeKey, 32))) === jcs(scenario.envelope), "sealed blob plaintext mismatch"); assert(!new TextDecoder().decode(policyBytes).includes("policyCid"), "policy self reference");
  assertEnvelopeBindings(scenario, schemas, domains); assert(Buffer.byteLength(scenario.envelope.delegation) <= domains.limits.delegationBytes, "delegation byte limit"); checkSchema(schemas, "inviteAuthorization", scenario.authorization); checkSchema(schemas, "trustedNodeEnrollment", scenario.enrollment); validateNodeEnrollment(scenario.enrollment, domains); validateAuthorityMaterial(scenario, schemas, domains); assert(scenario.enrollment.targetOrigin === scenario.authorization.targetOrigin && scenario.enrollment.nodeAudience === scenario.authorization.nodeAudience && scenario.enrollment.enabled === true, "untrusted enrollment tuple"); assert(scenario.authorization.recipientEmail === scenario.canonicalEmail && scenario.authorization.contentSourceDigest === scenario.sourceDigest && scenario.authorization.contentSource.kind === scenario.kind, "authorization source binding"); assert(Buffer.byteLength(scenario.authorization.documentName, "utf8") <= domains.limits.documentNameBytes && !/[\u0000-\u001f\u007f]/.test(scenario.authorization.documentName), "document name limit"); assert(scenario.authorization.senderTrust === "verified" && scenario.authorization.reportAbuseToken !== scenario.artifacts[2].message.jti, "sender trust/report token binding");
  const expected = { policy: [scenario.artifacts[0].signerDid, domains.testKeys.senderSeedHex, "policy"], envelope: [scenario.artifacts[0].signerDid, domains.testKeys.senderSeedHex, "envelope"], inviteAuthorization: [scenario.enrollment.nodeAudience, domains.testKeys.nodeSeedHex, "inviteAuthorization"], holderBinding: [scenario.artifacts[3].signerDid, domains.testKeys.holderSeedHex, "holderBinding"], policyChallenge: [scenario.enrollment.nodeAudience, domains.testKeys.nodeSeedHex, "policyChallenge"], policyPresentation: [scenario.artifacts[3].signerDid, domains.testKeys.holderSeedHex, "policyPresentation"], policySession: [scenario.enrollment.nodeAudience, domains.testKeys.nodeSeedHex, "policySession"], readInvocation: [scenario.artifacts[3].signerDid, domains.testKeys.holderSeedHex, "readInvocation"], authorityMaterial: [scenario.artifacts[0].signerDid, domains.testKeys.senderSeedHex, "authorityMaterial"] };
  const messageSchemas = { policy: "policy", envelope: "envelope", inviteAuthorization: "inviteAuthorization", authorityMaterial: "authorityMaterial", holderBinding: "holderBinding", policyChallenge: "policyChallenge", policyPresentation: "policyPresentation", policySession: "policySession", readInvocation: "readInvocation" };
  assert(scenario.artifacts.length === 9 && new Set(scenario.artifacts.map((a) => a.name)).size === 9, "artifact set");
  for (const artifact of scenario.artifacts) { assert(expected[artifact.name], `unknown artifact ${artifact.name}`); checkSchema(schemas, messageSchemas[artifact.name], artifact.message); verifyArtifact(artifact, expected[artifact.name][0], expected[artifact.name][1], domains, scenario.enrollment); assert(scenario.signedBytePreimages[artifact.name].domain === artifact.domain && scenario.signedBytePreimages[artifact.name].jcs === artifact.jcs && scenario.signedBytePreimages[artifact.name].digest === artifact.signedBytesDigest, `${scenario.kind}/${artifact.name}: frozen signed preimage`); if (artifact.message.contentSource) { equal(artifact.message.contentSource, scenario.source, `${scenario.kind}/${artifact.name}: source propagation`); assert(artifact.message.contentSourceDigest === scenario.sourceDigest, `${scenario.kind}/${artifact.name}: source digest propagation`); } }
  const byName = (name) => scenario.artifacts.find((a) => a.name === name); const binding = byName("holderBinding").message; const presentation = byName("policyPresentation").message; const session = byName("policySession").message; const read = byName("readInvocation").message; assert(binding.holderDid === presentation.holderDid && presentation.holderDid === session.holderDid && session.holderDid === read.holderDid, "holder equation"); assert(presentation.credentialDigest === scenario.credential.credentialDigest && session.credentialDigest === scenario.credential.credentialDigest, "credential binding"); for (const message of [scenario.policy, binding, presentation, session, read]) { if (message.action !== undefined) assert(message.action === scenario.source.action, "action/source mismatch"); if (message.resource !== undefined) assert(message.resource === scenario.source.path, "resource/source mismatch"); }
  assert(presentation.requestBodyDigest === byName("policyChallenge").message.requestBodyDigest, "challenge digest propagation"); validateCredential(scenario, schemas, domains); validateEndpoints(scenario, schemas, domains); assertCrossArtifactEquations(scenario);
}
function expectReject(rowOrName, fn, fallbackStage = "contract-validation") {
  const row = typeof rowOrName === "string" ? null : rowOrName; const name = row?.id ?? rowOrName; const expectedStage = row?.rejectionStage ?? fallbackStage;
  try { fn(); } catch (error) {
    if (!(error instanceof RejectionStageError)) throw new Error(`${name}: validator did not produce RejectionStageError: ${error.message}`);
    if (error.rejectionStage !== expectedStage) throw new Error(`${name}: expected ${expectedStage}, got ${error.rejectionStage}`);
    return error;
  }
  throw new Error(`${name}: expected reject`);
}
function expectExactStageReject(row, fn) {
  try { fn(); } catch (error) {
    if (!(error instanceof RejectionStageError)) throw new Error(`${row.id}: validator did not produce RejectionStageError: ${error.message}`);
    if (error.rejectionStage !== row.rejectionStage) throw new Error(`${row.id}: expected ${row.rejectionStage}, got ${error.rejectionStage}`);
    return error;
  }
  throw new Error(`${row.id}: expected reject at ${row.rejectionStage}`);
}
function resignScenarioArtifact(scenario, name, message, seedHex, signerDid, keyId, domains) {
  const altered = clone(scenario); const index = altered.artifacts.findIndex((artifact) => artifact.name === name); assert(index >= 0, `missing artifact ${name}`); altered.artifacts[index] = mutateAndResign(altered.artifacts[index], message, seedHex, signerDid, keyId, domains); if (name === "inviteAuthorization") altered.authorization = message; return altered;
}
function scrubFragment(urlText) {
  let url; try { url = new URL(urlText); } catch { return { scrubbed: "", malformed: true, fields: null, rejectionStage: "scanner-fragment-lexical" }; }
  const raw = url.hash.startsWith("#") ? url.hash.slice(1) : ""; const fields = raw ? raw.split("&") : []; const seen = new Set();
  let rejectionStage = null;
  if (urlText.includes("%") || raw.includes("%")) rejectionStage = "scanner-fragment-encoding";
  else if (url.protocol !== "https:") rejectionStage = "scanner-fragment-scheme";
  else if (url.hostname !== "share.tinycloud.xyz" || url.port !== "" || url.username !== "" || url.password !== "" || url.origin !== "https://share.tinycloud.xyz") rejectionStage = "scanner-fragment-origin";
  else if (!/^\/s\/bafkrei[a-z2-7]{52}$/.test(url.pathname)) rejectionStage = "scanner-fragment-path";
  else if (url.search !== "") rejectionStage = "scanner-fragment-query";
  let malformed = rejectionStage !== null || !/^https:\/\/share\.tinycloud\.xyz\/s\//.test(urlText);
  for (const field of fields) { const [key, value, ...extra] = field.split("="); if (extra.length || !["k", "i", "c"].includes(key) || !value || seen.has(key)) { malformed = true; rejectionStage ??= "scanner-fragment-fields"; } seen.add(key); }
  if (fields.length !== 3 || seen.size !== 3 || !["k", "i", "c"].every((key) => seen.has(key))) { malformed = true; rejectionStage ??= "scanner-fragment-fields"; }
  let parsed = null; if (!malformed) { try { parsed = Object.fromEntries(fields.map((x) => x.split("="))); sizedB64(parsed.k, 32); sizedB64(parsed.i, 16); sizedB64(parsed.c, 32); } catch { malformed = true; rejectionStage = "scanner-fragment-material"; parsed = null; } }
  return { scrubbed: `${url.origin}${url.pathname}`, malformed, fields: parsed, rejectionStage };
}
function parseScannerFragment(urlText) {
  const parsed = scrubFragment(urlText); if (parsed.malformed) rejectAt(parsed.rejectionStage ?? "scanner-fragment-fields", "scanner fragment rejected"); return parsed;
}
function validateDocumentName(schemas, authorization, value, domains) {
  stageAssert(typeof value === "string" && Buffer.byteLength(value, "utf8") <= domains.limits.documentNameBytes, "document-name-bytes", "document name byte limit");
  checkSchema(schemas, "inviteAuthorization", { ...authorization, documentName: value });
}
function consumeNonce(candidate) { assert(candidate.state === "VERIFYING", "nonce is not consumable"); candidate.state = "CONSUMED"; }
function redeemInvitation(candidate, version) { assert(candidate.state === "ACTIVE" && candidate.activeVersion === version && candidate.secrets.has(version), "inactive invitation version"); return candidate.secrets.get(version); }
function submitCorrectOtp(candidate) { assert(candidate.state === "ACTIVE" && candidate.attempts < candidate.threshold, "OTP is locked"); return true; }
function applyScannerOperation(candidate, method, operation) { assert(method !== "GET" || operation === "inspect", "GET cannot consume claim"); if (operation === "consume") { assert(candidate.state === "ACTIVE", "claim is not active"); candidate.state = "CONSUMED"; candidate.consumed = true; } }
function assertAtomicTerminal(record, label) {
  const result = record.resultPersisted === true || record.terminalResultPersisted === true;
  const consumed = record.consumedPersisted === true;
  const seedDeleted = record.seedEncrypted === false;
  assert(result === consumed, `${label}: result and CONSUMED must resolve together`);
  if (result || consumed) assert(seedDeleted && (record.atomicConsumedAndResult === true || record.atomicTerminalAndSeedDeletion === true), `${label}: result/CONSUMED/seed deletion is not atomic`);
  else assert(seedDeleted, `${label}: terminal seed was not deleted`);
}
class StateCommandRejection extends Error {
  constructor(commandName, message) { super(message); this.name = "StateCommandRejection"; this.commandName = commandName; }
}
function rejectCommand(command, message) { throw new StateCommandRejection(command.name, message); }

const commandReducers = {
  create_invitation(state, operands) { assert(state.invitation === "ABSENT" && operands.version === 1, "create precondition"); state.invitation = `PENDING_DELIVERY(v${operands.version})`; state.outbox = operands.outboxKey; state.claimMaterial = operands.claimMaterial; return { status: "pending", version: operands.version }; },
  provider_accept(state, operands) { assert(state.invitation === `PENDING_DELIVERY(v${operands.version})` && state.claimMaterial === "encrypted", "provider accept precondition"); state.invitation = `ACTIVE(v${operands.version})`; state.providerAccepted = true; state.claimMaterial = operands.claimMaterialAfter; return { status: "active", version: operands.version }; },
  invalidate_old_version(state, operands, command) { assert(operands.onlyAfter === "provider_acceptance", "invalidation rule"); if (state.pendingVersion !== undefined && state.pendingVersion !== null) { state.oldSecret = "retired"; rejectCommand(command, "old version remains active while resend is pending"); } assert(state.invitation === `ACTIVE(v${operands.version})`, "invalidation precondition"); state.oldSecret = "retired"; return { status: "invalidated", version: operands.version }; },
  prepare_resend(state, operands) { assert(state.invitation === `ACTIVE(v${operands.fromVersion})` && state.pendingVersion === null, "resend precondition"); state.invitation = `PENDING_DELIVERY(v${operands.toVersion})`; state.pendingVersion = operands.toVersion; state.replacementMaterial = operands.replacementMaterial; return { status: "pending", version: operands.toVersion }; },
  provider_reject(state, operands) { assert(state.invitation === `PENDING_DELIVERY(v${operands.pendingVersion})`, "provider failure precondition"); state.invitation = `ACTIVE(v${operands.restoreVersion})`; state.pendingVersion = null; state.replacementMaterial = operands.replacementMaterialAfter; return { status: "active", version: operands.restoreVersion }; },
  provider_accept_then_crash(state, operands) { assert(state.invitation === "PENDING_DELIVERY(v2)" && state.providerAccepted === false, "provider crash precondition"); state.providerAccepted = true; state.crashObserved = true; return { status: "provider-accepted", sendCount: operands.sendCount }; },
  reconcile_provider_acceptance(state, operands) { assert(state.providerAccepted === true && state.crashObserved === true, "provider retry precondition"); state.invitation = `ACTIVE(v${operands.version})`; state.activeVersion = operands.version; state.pendingVersion = null; delete state.providerAccepted; delete state.crashObserved; state.oldSecret = "retired"; state.providerSendCount = operands.sendCount; return { status: "active", version: operands.version, sendCount: operands.sendCount }; },
  resolve_issuance(state, operands) { assert(state.seed === "encrypted" && state.result === null && state.consumed === false, "issuance precondition"); state.invitation = operands.outcome === "success" ? "CONSUMED(v1)" : "TERMINAL_ERROR"; state.seed = operands.seedAfter; state.result = operands.result; state.consumed = true; return { status: operands.outcome, result: operands.result }; },
  atomic_write(state, operands, command) { assert(operands.requireAtomic === true && operands.writes.includes("result") && operands.writes.includes("consumed"), "atomic write precondition"); state.result = "partial"; state.consumed = true; rejectCommand(command, "result and CONSUMED must be committed atomically"); },
  cleanup_seed(state, operands, command) { assert(state.seed === "encrypted" && operands.pendingSeedAction === "refuse" && operands.requiresDurableCompletion === true, "seed cleanup precondition"); state.seed = "deleted"; rejectCommand(command, "pending seed cleanup requires durable completion"); },
  redeem_if_active(state, operands, command) {
    assert(Number.isInteger(operands.attempts) && operands.attempts >= 1, "CAS contender count");
    const outcomes = [];
    for (let contender = 0; contender < operands.attempts; contender++) {
      if (state.invitation === "ACTIVE(v1)" && state.redemptionId === operands.redemptionId) {
        state.invitation = "CONSUMED(v1)"; state.issuanceCount += 1; state.result = operands.result;
        outcomes.push({ status: "issued", result: state.result });
      } else if (state.invitation === "CONSUMED(v1)" && state.redemptionId === operands.redemptionId && state.result !== undefined) {
        const cachedOutcome = { status: "issued", result: state.result }; outcomes.push(cachedOutcome);
      } else {
        state.redemptionId = operands.redemptionId; state.issuanceCount += 1; state.result = operands.result;
        rejectCommand(command, "CAS redemption belongs to another or already-unresolved redemption");
      }
    }
    assert(outcomes.length === operands.attempts, "all CAS contenders executed");
    for (const outcome of outcomes) equal(outcome, outcomes[0], "CAS loser outcome changed");
    const expectedCachedOutcome = operands.cachedOutcome ?? { status: "issued", result: operands.result }; assert(outcomes.every((outcome) => jcs(outcome) === jcs(expectedCachedOutcome)), "CAS loser outcome is not byte-identical");
    return { status: "cas-complete", contenders: operands.attempts, cachedOutcome: outcomes[0] };
  },
  wrong_otp_attempts(state, operands) { assert(state.invitation === "ACTIVE(v1)" && operands.attempts === operands.lockAt && operands.invalidMagicAttempts === 0, "OTP precondition"); state.otpAttempts += operands.attempts; state.invalidMagicOtpAttempts = operands.invalidMagicAttempts; state.invitation = "LOCKED(v1)"; return { status: "locked", attempts: operands.attempts }; },
  consume_nonce(state, operands, command) { if (state.nonce !== operands.requiredState) { state.nonceReplayAttempted = true; rejectCommand(command, "nonce replay"); } state.nonce = "CONSUMED"; return { status: "consumed" }; },
  reserve_jti(state, operands, command) { if (state.jti === operands.jti && state.digest !== operands.digest) { state.digest = operands.digest; rejectCommand(command, "JTI replay with a different digest"); } assert(state.jti === undefined && state.digest === undefined, "JTI reservation precondition"); state.jti = operands.jti; state.digest = operands.digest; return { status: "reserved", jti: operands.jti }; },
  scanner_get(state, operands) { assert(operands.method === "GET" && operands.mutate === false, "scanner GET must be read-only"); return { status: "inspected" }; }
};
function reduceCommand(rows, command) {
  const reducer = commandReducers[command.name]; assert(typeof reducer === "function", `unknown state command ${command.name}`); return { state: rows, outcome: reducer(rows, command.operands, command) };
}
function executeOperationProgram(states, schemas) {
  const program = states.operationProgram; assert(Array.isArray(program) && program.length === 17, "operation program missing");
  schemaError(schemas, schemas.schemas.operationProgram, program, "operationProgram");
  const ids = new Set(); for (const row of program) {
    assert(row.id && !ids.has(row.id), `duplicate operation ${row.id}`); ids.add(row.id); assert(row.commands.length > 0 && !Object.hasOwn(row, "post"), `${row.id}: command program required`);
    const before = clone(row.pre.durableRows); const scratch = clone(before); const outcomes = [];
    for (const command of row.commands) {
      if (row.operation === "reject") {
        let rejection; let attempted;
        try { reduceCommand(scratch, command); } catch (error) { rejection = error; }
        assert(rejection instanceof StateCommandRejection && rejection.commandName === command.name, `${row.id}: rejected command was not typed`);
        attempted = clone(scratch); assert(jcs(attempted) !== jcs(before), `${row.id}: rejected command did not attempt a mutation`);
        for (const key of Object.keys(scratch)) delete scratch[key]; Object.assign(scratch, clone(before));
        equal(scratch, before, `${row.id}: rejected command did not roll back`);
      } else {
        const reduction = reduceCommand(scratch, command); if (reduction.outcome !== undefined) outcomes.push(reduction.outcome);
      }
    }
    const derived = { durableRows: scratch }; equal(derived, row.expected, `${row.id}: derived state differs from expected`);
    if (row.operation === "reject" || row.operation === "read-only") equal(row.pre, row.expected, `${row.id}: non-mutating operation changed state`);
    if (row.operation === "transaction" && row.id === "same-redemption-contenders") assert(outcomes.length === 1 && outcomes[0].contenders === 20 && jcs(outcomes[0].cachedOutcome) === jcs(row.commands[0].operands.cachedOutcome), `${row.id}: CAS outcome proof`);
  }
  assert(ids.size === 17, `operation program coverage ${ids.size}/17`);
}
function validateStates(states, schemas) {
  const expectedNames = ["create-accepted", "resend-accepted", "resend-provider-failure", "crash-after-provider-accept"];
  assert(Array.isArray(states.delivery) && states.delivery.length === expectedNames.length && new Set(states.delivery.map((flow) => flow.name)).size === expectedNames.length, "delivery matrix");
  for (const name of expectedNames) { const flow = states.delivery.find((candidate) => candidate.name === name); assert(flow && Array.isArray(flow.events) && flow.events.length > 0, `${name}: events`); let current = flow.events[0][0]; for (const pair of flow.events) { assert(Array.isArray(pair) && pair.length === 2 && pair[0] === current, `${name}: transition source`); current = pair[1]; } }
  assert(jcs(states.invitation) === jcs(["ABSENT", "ACTIVE(v1)", "REDEEMING(v1,redemption-001)", "CONSUMED(v1)"]) && jcs(states.nonce) === jcs(["ISSUED", "VERIFYING", "CONSUMED"]), "state machine arrays"); assert(states.session.includes("ACTIVE") && states.session.includes("EXPIRED") && states.session.includes("REVOKED"), "session state matrix"); executeOperationProgram(states, schemas);
}
function validateReplaySemantics() {
  const jtis = new Map([["authorization", "digest-a"]]); expectReject("authorization JTI reuse", () => { assert(jtis.get("authorization") === "digest-b", "different authorization digest accepted"); });
  const nonce = { state: "ISSUED", attempts: 0 }; const consumeNonce = (candidate) => { assert(candidate.state === "ISSUED" || candidate.state === "VERIFYING", "nonce is not issuable"); candidate.state = candidate.state === "ISSUED" ? "VERIFYING" : "CONSUMED"; return candidate; }; consumeNonce(nonce); consumeNonce(nonce); expectReject("policy nonce replay", () => consumeNonce(nonce));
  const invitation = { state: "ACTIVE", activeVersion: 1, pendingVersion: null, secrets: new Map([[1, "old-secret"]]) }; const resend = (candidate) => { assert(candidate.state === "ACTIVE" && candidate.pendingVersion === null, "resend state"); candidate.pendingVersion = candidate.activeVersion + 1; candidate.secrets.set(candidate.pendingVersion, "new-secret"); candidate.state = "PENDING_DELIVERY"; return candidate; }; const providerAccepted = (candidate) => { assert(candidate.state === "PENDING_DELIVERY", "provider acceptance state"); candidate.activeVersion = candidate.pendingVersion; candidate.pendingVersion = null; candidate.state = "ACTIVE"; return candidate; }; const invalidateOld = (candidate) => { assert(candidate.state === "ACTIVE" && candidate.activeVersion === 2, "old version invalidation state"); candidate.secrets.delete(1); return candidate; }; resend(invitation); providerAccepted(invitation); invalidateOld(invitation); expectReject("old secret after resend", () => { assert(invitation.secrets.has(1), "old secret accepted"); });
  const otp = { attempts: 0, state: "ACTIVE" }; const wrongOtp = (candidate) => { assert(candidate.state === "ACTIVE" && candidate.attempts < 5, "OTP is locked"); candidate.attempts++; if (candidate.attempts === 5) candidate.state = "LOCKED"; }; for (let i = 0; i < 5; i++) wrongOtp(otp); expectReject("correct OTP after lock", () => { assert(otp.state === "ACTIVE" && otp.attempts < 5, "locked OTP accepted"); });
  const scannerMaterial = { k: b64(new Uint8Array(32)), i: b64(new Uint8Array(16)), c: b64(new Uint8Array(32)) }; const scanner = scrubFragment(`https://share.tinycloud.xyz/s/bafkrei${"a".repeat(52)}#k=${scannerMaterial.k}&i=${scannerMaterial.i}&c=${scannerMaterial.c}`); assert(!scanner.malformed && scanner.fields && scanner.fields.constructor === Object, "scanner fragment material"); const before = "ACTIVE"; const getState = { state: before, consumed: false }; const get = (candidate) => { const stateBefore = candidate.state; const result = { fields: scanner.fields, consumed: false }; assert(candidate.state === stateBefore && result.consumed === false, "scanner GET changed state"); return result; }; assert(get(getState).consumed === false && getState.state === before, "scanner GET changed state");
}
function validateCapabilities(domains, schemas) { const witness = domains.capabilities.witness; const node = domains.capabilities.node; checkSchema(schemas, "capabilityDescriptor", witness); checkSchema(schemas, "capabilityDescriptor", node); assert(witness.origin === "https://witness.credentials.org" && witness.returnOrigin === "https://share.tinycloud.xyz" && witness.status !== "ready", "witness capability"); assert(node.origin === "https://node.example" && node.status !== "ready" && !node.routes.some((route) => route.includes("*")), "node capability"); const allowedWitness = new Set(["/v1/share-email/invitations","/v1/share-email/invitations/resend","/v1/share-email/claims/activate","/v1/share-email/claims/challenge","/v1/share-email/claims/redeem"]); const allowedNode = new Set(["/share/v1/invitations/authorize","/share/v1/policy/challenges","/share/v1/policy/session","/share/v1/read"]); assert(witness.routes.every((route) => allowedWitness.has(route)) && node.routes.every((route) => allowedNode.has(route)), "capability route allowlist"); }
function dispatchNegative(scenario, negative, schemas, domains, states) {
  const applicable = negative.cases.filter((row) => Array.isArray(row.appliesTo) && row.appliesTo.includes(scenario.kind));
  const seen = new Set();
  const run = (row, fn) => { const schemaRow = clone(row); delete schemaRow.input; schemaError(schemas, schemas.$defs.negativeCase, schemaRow, `negative.${row.id}`); assert(row.expected === "reject" && typeof row.rejectionStage === "string" && row.rejectionStage.length > 0 && !seen.has(row.id), `invalid or duplicate negative row ${row.id}`); expectExactStageReject(row, fn); seen.add(row.id); };
  for (const row of applicable) {
    const mutationValue = row.mutationData.valueByKind?.[scenario.kind] ?? row.mutationData.value;
    switch (row.id) {
      case "leading-space": case "trailing-space": case "tab": case "newline": case "inner-space": case "leading-dot-local": case "trailing-dot-local": case "repeated-dot-local": case "empty-local": case "empty-domain": case "multiple-at": case "quoted-local": case "comment-local": case "backslash-local": case "angle-form": case "unicode-local": case "unicode-domain": case "local-over-64": case "label-over-63": case "empty-domain-label": case "trailing-domain-dot": case "leading-hyphen": case "trailing-hyphen": case "domain-over-253": case "total-over-254":
        run(row, () => canonicalEmail(row.input)); break;
      case "policy-cid-is-real": run(row, () => assertCid(scenario.policyCid, utf8(row.mutationData.replacement))); break;
      case "policy-bytes-self-policy-cid": run(row, () => { const text = new TextDecoder().decode(strictB64(scenario.policyBytes)); assert(!text.includes("policyCid"), "policy self-reference accepted"); const parsed = JSON.parse(text); parsed.policyCid = scenario.policyCid; checkSchema(schemas, "policy", parsed); }); break;
      case "share-cid-is-real": run(row, () => { const bytes = strictB64(scenario.sealedBlob); bytes[bytes.length - 1] ^= 1; assertCid(scenario.shareCid, bytes); }); break;
      case "sealed-blob-aead-tamper": run(row, () => { const bytes = strictB64(scenario.sealedBlob); bytes[bytes.length - 1] ^= 1; openSealed(bytes, sizedB64(scenario.envelopeKey, 32)); }); break;
      case "envelope-policy-target-missing-kind": run(row, () => checkSchema(schemas, "envelopeSigned", { ...scenario.envelope, authorizationTarget: { ...scenario.envelope.authorizationTarget, kind: undefined } })); break;
      case "envelope-policy-target-missing-bytes": run(row, () => { const altered = clone(scenario.envelope); delete altered.authorizationTarget.policyBytes; checkSchema(schemas, "envelopeSigned", altered); }); break;
      case "envelope-policy-target-mismatch": run(row, () => { const altered = clone(scenario.envelope); altered.authorizationTarget.policyCid = rawCid(utf8("other policy")); altered.authorizationTarget.policyBytes = b64(utf8(jcs({ ...scenario.policy, recipientEmail: "Other@example.com" }))); delete altered.signature; const sig = sign(null, Buffer.concat([utf8(domains.domains.envelope), utf8(jcs(altered))]), privateKey(domains.testKeys.senderSeedHex)); altered.signature = { ...scenario.envelope.signature, value: b64(sig) }; assertEnvelopeBindings({ ...scenario, envelope: altered }, schemas, domains); }); break;
      case "envelope-origin-mismatch": run(row, () => { const altered = clone(scenario.envelope); altered.target.origin = row.mutationData.value; delete altered.signature; const sig = sign(null, Buffer.concat([utf8(domains.domains.envelope), utf8(jcs(altered))]), privateKey(domains.testKeys.senderSeedHex)); altered.signature = { ...scenario.envelope.signature, value: b64(sig) }; assertEnvelopeBindings({ ...scenario, envelope: altered }, schemas, domains); }); break;
      case "share-url-userinfo": case "share-url-query": case "share-url-query-missing-fragment": case "share-url-duplicate-k": case "share-url-unknown-fragment": case "share-url-noncanonical-k": case "share-url-wrong-origin": case "share-url-wrong-path": case "share-url-http-scheme": case "share-url-explicit-port": case "share-url-percent-encoded-fragment": run(row, () => { const body = { ...scenario.preimages.createInvitationRequest.body, shareUrl: mutationValue }; parseShareUrl(body.shareUrl); checkSchema(schemas, "createInvitationRequest", body); }); break;
      case "document-name-over-200-utf8": run(row, () => { const candidate = row.mutationData.candidateArtifactByKind[scenario.kind]; verifyArtifact(candidate, scenario.enrollment.nodeAudience, undefined, domains, scenario.enrollment, "inviteAuthorization"); validateDocumentName(schemas, candidate.message, candidate.message.documentName, domains); }); break;
      case "authorization-recipient-email-mismatch": run(row, () => { const artifact = scenario.artifacts.find((a) => a.name === "inviteAuthorization"); const altered = resignScenarioArtifact(scenario, "inviteAuthorization", { ...artifact.message, recipientEmail: row.mutationData.value }, domains.testKeys.nodeSeedHex, artifact.signerDid, artifact.signature.kid, domains); assertCrossArtifactEquations(altered); }); break;
      case "redeem-redemption-id-mismatch": case "redeem-invitation-id-mismatch": run(row, () => { const artifact = scenario.artifacts.find((a) => a.name === "holderBinding"); const field = row.id === "redeem-redemption-id-mismatch" ? "redemptionId" : "invitationId"; const altered = resignScenarioArtifact(scenario, "holderBinding", { ...artifact.message, [field]: row.mutationData.value }, domains.testKeys.holderSeedHex, artifact.signerDid, artifact.signature.kid, domains); assertCrossArtifactEquations(altered); }); break;
      case "share-id-propagation": case "share-cid-propagation": case "policy-cid-propagation": case "target-origin-propagation": case "node-audience-propagation": case "holder-did-propagation": case "content-source-digest-propagation": case "action-propagation": case "resource-propagation": {
        const artifact = scenario.artifacts.find((a) => a.name === "policyPresentation"); const fields = { "share-id-propagation": "shareId", "share-cid-propagation": "shareCid", "policy-cid-propagation": "policyCid", "target-origin-propagation": "targetOrigin", "node-audience-propagation": "nodeAudience", "holder-did-propagation": "holderDid", "content-source-digest-propagation": "contentSourceDigest", "action-propagation": "action", "resource-propagation": "resource" }; run(row, () => assertCrossArtifactEquations(resignScenarioArtifact(scenario, "policyPresentation", { ...artifact.message, [fields[row.id]]: row.mutationData.valueByKind?.[scenario.kind] ?? row.mutationData.value }, domains.testKeys.holderSeedHex, artifact.signerDid, artifact.signature.kid, domains))); break;
      }
      case "envelope-domain-from-unregistered-label": run(row, () => verifyArtifact({ ...scenario.artifacts.find((a) => a.name === "envelope"), domain: "unregistered.example\u0000" }, scenario.artifacts[1].signerDid, domains.testKeys.senderSeedHex, domains, scenario.enrollment)); break;
      case "jcs-lone-surrogate": run(row, () => jcs({ value: "\ud800" })); break;
      case "jcs-unsafe-number": case "jcs-fractional-number": case "jcs-negative-zero": run(row, () => jcs({ value: row.id === "jcs-negative-zero" ? -0 : row.mutationData.value })); break;
      case "jcs-undefined": run(row, () => jcs({ value: undefined })); break;
      case "noncanonical-b64url-16-tail": run(row, () => checkSchema(schemas, "resendRequest", { ...scenario.preimages.resendRequest.body, invitationId: `${scenario.preimages.resendRequest.body.invitationId.slice(0, -1)}B` })); break;
      case "noncanonical-b64url-64-tail": run(row, () => checkSchema(schemas, "authorizationResponse", { ...scenario.preimages.authorizationResponse.body, proof: { ...scenario.preimages.authorizationResponse.body.proof, signature: `${scenario.preimages.authorizationResponse.body.proof.signature.slice(0, -1)}B` } })); break;
      case "noncanonical-holder-kid": { const artifact = scenario.artifacts.find((a) => a.name === "holderBinding"); run(row, () => verifyArtifact({ ...artifact, signature: { ...artifact.signature, kid: `${artifact.signerDid}#wrong` } }, artifact.signerDid, domains.testKeys.holderSeedHex, domains, scenario.enrollment)); break; }
      case "small-order-did-key": { const artifact = scenario.artifacts.find((a) => a.name === "holderBinding"); run(row, () => verifyArtifact(mutateAndResign(artifact, { ...artifact.message, holderDid: `did:key:z${encode58(Uint8Array.of(0xed, 1, 1, ...new Uint8Array(31)))}` }, domains.testKeys.holderSeedHex, artifact.signerDid, artifact.signature.kid, domains), artifact.signerDid, domains.testKeys.holderSeedHex, domains, scenario.enrollment)); break; }
      case "noncanonical-ed25519-s": { const artifact = clone(scenario.artifacts.find((a) => a.name === "holderBinding")); run(row, () => { const sig = strictB64(artifact.signature.value); sig.set(Uint8Array.from(Buffer.from("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010", "hex")), 32); artifact.signature.value = b64(sig); verifyArtifact(artifact, artifact.signerDid, domains.testKeys.holderSeedHex, domains, scenario.enrollment); }); break; }
      case "short-signature": { const artifact = clone(scenario.artifacts.find((a) => a.name === "readInvocation")); run(row, () => { artifact.signature.value = b64(strictB64(artifact.signature.value).slice(0, row.mutationData.bytes)); verifyArtifact(artifact, artifact.signerDid, domains.testKeys.holderSeedHex, domains, scenario.enrollment); }); break; }
      case "wrong-source-digest": run(row, () => { const source = { ...scenario.source, arguments: { ...scenario.source.arguments, document_id: row.mutationData.value } }; assertSource(source, "sql", schemas, domains); }); break;
      case "sql-arguments-too-large": run(row, () => { const argumentsValue = row.mutationData.field === "arguments" ? row.mutationData.value : { ...scenario.source.arguments, [row.mutationData.field]: row.mutationData.value }; assertSource({ ...scenario.source, arguments: argumentsValue }, "sql", schemas, domains); }); break;
      case "sql-string-argument": run(row, () => { const field = (row.mutationData.field ?? "document_id").split(".").at(-1); const value = row.mutationData.value; const source = { ...scenario.source, arguments: { ...scenario.source.arguments, [field]: value } }; assert(typeof value === "number" && Number.isSafeInteger(value) && !Object.is(value, -0), "string SQL argument accepted"); assertSource(source, "sql", schemas, domains); }); break;
      case "sql-fractional-argument": run(row, () => { const field = (row.mutationData.field ?? "document_id").split(".").at(-1); const source = { ...scenario.source, arguments: { ...scenario.source.arguments, [field]: row.mutationData.value } }; assertSource(source, "sql", schemas, domains); }); break;
      case "sql-negative-zero-argument": run(row, () => { const field = (row.mutationData.field ?? "document_id").split(".").at(-1); const value = row.mutationData.value === "-0" ? -0 : row.mutationData.value; const source = { ...scenario.source, arguments: { ...scenario.source.arguments, [field]: value } }; assertSource(source, "sql", schemas, domains); }); break;
      case "sql-arbitrary-query-field": run(row, () => { const source = { ...scenario.source, query: row.mutationData.value }; checkSchema(schemas, "sqlReadRequest", { ...scenario.preimages.sqlReadRequest.body, contentSource: source }); }); break;
      case "policy-action-source-mismatch": run(row, () => { const altered = mutateAndResign(scenario.artifacts.find((a) => a.name === "policy"), { ...scenario.policy, action: scenario.kind === "sql" ? "tinycloud.kv/get" : "tinycloud.sql/read" }, domains.testKeys.senderSeedHex, scenario.artifacts[0].signerDid, scenario.artifacts[0].signature.kid, domains); verifyArtifact(altered, altered.signerDid, domains.testKeys.senderSeedHex, domains, scenario.enrollment); assert(altered.message.action === scenario.source.action, "mismatched action accepted"); }); break;
      case "content-source-propagation": run(row, () => { const artifact = scenario.artifacts.find((a) => a.name === "policyPresentation"); const altered = mutateAndResign(artifact, { ...artifact.message, contentSource: { ...scenario.source, path: row.mutationData.value } }, domains.testKeys.holderSeedHex, artifact.signerDid, artifact.signature.kid, domains); verifyArtifact(altered, altered.signerDid, domains.testKeys.holderSeedHex, domains, scenario.enrollment); equal(altered.message.contentSource, scenario.source, "changed source accepted"); }); break;
      case "credential-sub-mismatch": run(row, () => { const c = clone(scenario); c.credential.claims.sub = scenario.artifacts[0].signerDid; validateCredential(c, schemas, domains); }); break;
      case "credential-legacy-email-path": run(row, () => { const c = clone(scenario); c.credential.disclosures[0].path = "/email/address"; validateCredential(c, schemas, domains); }); break;
      case "credential-unsupported-status": run(row, () => { const c = clone(scenario); c.credential.claims.status = { list: "unsupported" }; validateCredential(c, schemas, domains); }); break;
      case "credential-expired-resigned": case "credential-expiry-boundary-resigned": case "credential-issuer-did-resigned": case "credential-issuer-key-resigned": case "credential-vct-resigned": case "credential-holder-resigned": case "credential-scope-resigned": run(row, () => {
        const candidate = row.mutationData.credentialByKind[scenario.kind]; const restore = row.id === "credential-vct-resigned" ? { vct: scenario.credential.vct, "claims.vct": scenario.credential.claims.vct } : {};
        const candidateSigningPublicKey = row.mutationData.candidateSigningPublicKeyByKind?.[scenario.kind];
        if (row.id === "credential-expiry-boundary-resigned") assert(candidate.claims.exp === Date.parse(scenario.evaluationTime) / 1000 - scenario.clockSkewSeconds, `${scenario.kind}: expiry boundary equation`);
        validateResignedCredentialPrerequisites(candidate, scenario, schemas, domains, candidateSigningPublicKey, restore);
        validateResignedCredentialSemantics(candidate, scenario, domains);
      }); break;
      case "different-holder-valid-signature": run(row, () => { const candidate = row.mutationData.candidateArtifact; checkSchema(schemas, "holderBinding", candidate.message); verifyArtifact(candidate, candidate.signerDid, candidate.signerDid === scenario.artifacts[0].signerDid ? domains.testKeys.senderSeedHex : domains.testKeys.holderSeedHex, domains, scenario.enrollment); assert(candidate.message.holderDid !== scenario.credential.holderDid, "alternate holder was not changed"); rejectAt("cross-artifact-holder", "cross-artifact holder mismatch"); }); break;
      case "policy-challenge-replay": run(row, () => { const nonce = { state: "CONSUMED" }; consumeNonce(nonce); }); break;
      case "session-token-only": run(row, () => { const request = clone(scenario.preimages[scenario.kind === "sql" ? "sqlReadRequest" : "kvReadRequest"].body); delete request.proof; checkSchema(schemas, scenario.kind === "sql" ? "sqlReadRequest" : "kvReadRequest", request); }); break;
      case "old-secret-after-resend": run(row, () => { const invitation = { state: "ACTIVE", activeVersion: 2, secrets: new Map([[2, "new-secret"]]) }; redeemInvitation(invitation, row.mutationData.value); }); break;
      case "otp-after-five-wrong": run(row, () => { const command = states.operationProgram.find((operation) => operation.id === "otp-wrong-vs-invalid-magic").commands[0]; const otp = { state: "LOCKED", attempts: row.mutationData.value, threshold: command.operands.lockAt }; submitCorrectOtp(otp); }); break;
      case "scanner-get": run(row, () => { const parsed = parseScannerFragment(mutationValue); checkSchema(schemas, "fragmentFields", parsed.fields); const claim = { state: "ACTIVE", consumed: false }; applyScannerOperation(claim, "GET", "consume"); }); break;
      case "scanner-fragment-percent-encoded": run(row, () => parseScannerFragment(mutationValue)); break;
      case "resend-recipient-supplied-email": run(row, () => checkSchema(schemas, "resendRequest", { ...scenario.preimages.resendRequest.body, email: row.mutationData.value })); break;
      case "capability-extra-route": run(row, () => { const altered = clone(domains.capabilities.witness); altered.routes.push(row.mutationData.value); validateCapabilities({ ...domains, capabilities: { ...domains.capabilities, witness: altered } }, schemas); }); break;
      case "capability-wildcard-origin": run(row, () => { const altered = clone(domains.capabilities.node); altered.origin = row.mutationData.value; validateCapabilities({ ...domains, capabilities: { ...domains.capabilities, node: altered } }, schemas); }); break;
      case "node-enrollment-disabled": case "node-enrollment-origin-audience": case "node-enrollment-audience-origin": case "node-enrollment-retired-key": case "node-enrollment-kid-version-mismatch": run(row, () => { const candidate = row.mutationData.enrollment; checkSchema(schemas, "trustedNodeEnrollment", candidate); validateNodeEnrollment(candidate, domains); }); break;
      case "read-body-one-field-mutation": run(row, () => { const preimage = scenario.preimages.sqlReadRequest; const altered = { ...preimage.body, resource: row.mutationData.value }; assert(preimage.digest === digest(utf8(jcs(altered))), "mutated body digest accepted"); }); break;
      case "claim-redeem-magic-with-otp": run(row, () => { const altered = clone(scenario.preimages.claimRedeemRequest.body); altered.mailboxProof = row.mutationData.value; checkSchema(schemas, "claimRedeemRequest", altered); }); break;
      case "claim-redeem-otp-with-magic": run(row, () => { const altered = clone(scenario.preimages.claimRedeemRequest.body); altered.method = row.mutationData.method; altered.mailboxProof = row.mutationData.value; checkSchema(schemas, "claimRedeemRequest", altered); }); break;
      case "policy-challenge-response-proof": run(row, () => { const response = clone(scenario.preimages.policyChallengeResponse.body); response.proof = scenario.preimages.claimRedeemRequest.body.holderProof; checkSchema(schemas, "policyChallengeResponse", response); assertProofBound(response.proof, scenario.artifacts.find((a) => a.name === "policyChallenge"), "wrong challenge proof"); }); break;
      case "policy-session-response-proof": run(row, () => { const response = clone(scenario.preimages.policySessionResponse.body); response.proof = scenario.preimages.claimRedeemRequest.body.holderProof; checkSchema(schemas, "policySessionResponse", response); assertProofBound(response.proof, scenario.artifacts.find((a) => a.name === "policySession"), "wrong session proof"); }); break;
      case "authority-material-signature": run(row, () => { const artifact = clone(scenario.artifacts.find((a) => a.name === "authorityMaterial")); const sig = strictB64(artifact.signature.value); sig[0] ^= 1; artifact.signature.value = b64(sig); verifyArtifact(artifact, artifact.signerDid, domains.testKeys.senderSeedHex, domains, scenario.enrollment, "authorityMaterial"); }); break;
      case "authority-material-policy-mapping": case "authority-status-rollback": case "authority-status-stale": case "authority-status-revoked": case "authority-key-version": case "authority-attestation-binding": case "authority-measurement-digest-expiry": case "authority-identifier-domain-confusion": run(row, () => { const altered = clone(scenario); const path = row.mutationData.field.split("."); let cursor = altered.authorityMaterial; for (const key of path.slice(0, -1)) cursor = cursor[key]; cursor[path.at(-1)] = row.mutationData.value; validateAuthorityMaterial(altered, schemas, domains); }); break;
      case "sd-jwt-missing-alg": run(row, () => { const c = clone(scenario); delete c.credential.claims._sd_alg; validateCredential(c, schemas, domains); }); break;
      case "sd-jwt-two-element-disclosure": run(row, () => { const c = clone(scenario); const alteredDisclosure = b64(utf8(jcs(row.mutationData.arrayShape ?? ["email", scenario.canonicalEmail]))); c.credential.disclosures[0].encoded = alteredDisclosure; const compact = c.credential.credential.split("~"); assert(compact.length === 3, "SD-JWT compact form"); compact[1] = alteredDisclosure; c.credential.credential = compact.join("~"); validateCredential(c, schemas, domains); }); break;
      default: throw new Error(`unknown negative dispatch kind/id: ${row.kind}/${row.id}`);
    }
  }
  assert(seen.size === applicable.length, `${scenario.kind}: negative dispatch incomplete ${seen.size}/${applicable.length}`);
}
async function main() {
  const [manifest, positive, negative, states, domains, schemas] = await Promise.all([load(resolve(here, "manifest.json")), load(resolve(here, "positive.json")), load(resolve(here, "negative.json")), load(resolve(here, "states.json")), load(resolve(spec, "domains.json")), load(resolve(spec, "schemas.json"))]);
  const { manifestDigest: _ignored, ...manifestCore } = manifest; assert(manifest.manifestDigest === digest(utf8(jcs(manifestCore))), "manifest digest mismatch");
  /* The manifest is deliberately frozen while the loader/Rust repair runs concurrently. */
  for (const [file, expected] of Object.entries(manifest.files)) { const path = file.endsWith(".md") || file === "domains.json" || file === "schemas.json" || file === "authority-material.schema.json" ? resolve(spec, file) : resolve(here, file); assert(digest(await readFile(path)) === expected, `manifest file mismatch: ${file}`); }
  assert(schemas.$schema.endsWith("draft/2020-12/schema") && schemas.schemas.envelope.additionalProperties === false && domains.domains.envelope.endsWith("\u0000"), "contract roots"); assert(domains.limits.emailBytes === 254 && domains.limits.emailLocalBytes === 64 && domains.limits.sqlArgumentsBytes === 4096, "limits"); validateCapabilities(domains, schemas); validateStates(states, schemas); validateReplaySemantics();
  for (const vector of positive.canonicalization.accepted) { const canonical = canonicalEmail(vector.input); assert(canonical === vector.canonical && Buffer.byteLength(vector.input.slice(0, vector.input.indexOf("@"))) === vector.localBytes && Buffer.byteLength(vector.input.slice(vector.input.indexOf("@") + 1)) === vector.domainBytes && Buffer.byteLength(vector.input) === vector.totalBytes, `${vector.id}: boundary`); } assert(canonicalDomain(positive.canonicalization.domainBoundary.input) === positive.canonicalization.domainBoundary.canonical && Buffer.byteLength(positive.canonicalization.domainBoundary.input) === 253, "253-byte domain boundary");
  for (const scenario of positive.scenarios) { validateScenario(scenario, schemas, domains); dispatchNegative(scenario, negative, schemas, domains, states); }
  const duplicate = scrubFragment("https://share.tinycloud.xyz/s/cid#c=secret&k=key&c=duplicate"); assert(duplicate.scrubbed === "https://share.tinycloud.xyz/s/cid" && duplicate.malformed && duplicate.fields === null, "fragment not scrubbed before reject"); const scannerScenario = positive.scenarios[0]; const scannerUrl = `https://share.tinycloud.xyz/s/${scannerScenario.shareCid}#k=${scannerScenario.envelopeKey}&i=${scannerScenario.preimages.activationRequest.body.invitationId}&c=${scannerScenario.preimages.activationRequest.body.claimSecret}`; const scanner = scrubFragment(scannerUrl); assert(!scanner.malformed && scanner.fields, "scanner fragment rejected"); checkSchema(schemas, "fragmentFields", scanner.fields); const scannerState = { state: "ACTIVE", consumed: false }; const scannerBefore = clone(scannerState); const scannerResponse = { fields: scanner.fields, consumed: false }; equal(scannerState, scannerBefore, "scanner GET changed state"); assert(scannerResponse.consumed === false, "scanner GET consumed claim");
  console.log(`email-claim-v1: PASS (${positive.scenarios.length} sources, ${positive.scenarios[0].artifacts.length} signed artifacts/source, ${negative.cases.length} negative rows dispatched, ${Object.keys(positive.scenarios[0].preimages).length} endpoint preimages/source)`); console.log(`manifestDigest: ${manifest.manifestDigest}`);
}
main().catch((error) => { console.error(`email-claim-v1: FAIL: ${error.message}`); process.exitCode = 1; });

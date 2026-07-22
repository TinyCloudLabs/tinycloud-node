import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type Obj = { [key: string]: unknown };
type Schema = { [key: string]: unknown };
type RejectionStage = "contract-validation" | "credential-holder" | "credential-scope" | "credential-time" | "credential-vct" | "cross-artifact-holder" | "document-name-bytes" | "issuer-key" | "issuer-trust" | "node-authority" | "node-enrollment" | "node-key-retirement" | "node-key-rotation" | "scanner-fragment-encoding" | "share-url-fragment" | "share-url-fragment-encoding" | "share-url-key" | "share-url-origin" | "share-url-path" | "share-url-port" | "share-url-query" | "share-url-scheme" | "signature-encoding";

class StageError extends Error {
  readonly stage: RejectionStage;
  constructor(stage: RejectionStage, message: string, cause?: unknown) {
    super(message);
    this.name = "StageError";
    this.stage = stage;
    if (cause !== undefined) this.cause = cause;
  }
}

class StateCommandRejection extends StageError {
  readonly commandName: string;
  readonly attemptedState: Obj;
  constructor(commandName: string, attemptedState: Obj, message: string) {
    super("contract-validation", message);
    this.name = "StateCommandRejection";
    this.commandName = commandName;
    this.attemptedState = clone(attemptedState);
  }
}

export interface FixtureManifest {
  manifestVersion: 1;
  contractVersion: "tinycloud.share-email-claim/v1";
  files: Record<string, string>;
  testOnly: true;
  manifestDigest: string;
}
export interface FixtureBundle {
  manifest: FixtureManifest;
  positive: unknown;
  negative: unknown;
  states: unknown;
  domains: unknown;
  schemas: unknown;
}

const textEncoder = new TextEncoder();
const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64url");
const bytes = (value: string): Uint8Array => new Uint8Array(Buffer.from(value, "base64url"));
const digest = (value: Uint8Array): string => b64(new Uint8Array(createHash("sha256").update(value).digest()));
const utf8 = (value: string): Uint8Array => textEncoder.encode(value);
const record = (value: unknown, label: string): Obj => { if (!value || typeof value !== "object" || Array.isArray(value)) throw new StageError("contract-validation", `${label}: expected object`); return value as Obj; };
const list = (value: unknown, label: string): unknown[] => { if (!Array.isArray(value)) throw new StageError("contract-validation", `${label}: expected array`); return value; };
const string = (value: unknown, label: string): string => { if (typeof value !== "string") throw new StageError("contract-validation", `${label}: expected string`); return value; };
const clone = (value: unknown): Obj => JSON.parse(JSON.stringify(value)) as Obj;
const assert = (condition: boolean, message: string): void => { if (!condition) throw new StageError("contract-validation", message); };
const expectReject = (label: string, operation: () => void): void => { let rejected = false; try { operation(); } catch { rejected = true; } assert(rejected, `${label}: expected reject`); };
function fixedStageBoundary(stage: RejectionStage, operation: () => void): void {
  try { operation(); } catch (error) { if (error instanceof StageError) throw error; throw new StageError(stage, error instanceof Error ? error.message : String(error), error); }
}
function expectStageReject(row: Obj, operation: () => void): void {
  const id = string(row.id, "negative.id"); const expected = string(row.rejectionStage, `${id}.rejectionStage`) as RejectionStage;
  let error: unknown;
  try { operation(); } catch (caught) { error = caught; }
  if (!(error instanceof StageError)) throw new Error(`${id}: expected StageError`);
  assert(error.stage === expected, `${id}: expected stage ${expected}, got ${error.stage}: ${error.message}`);
}
function stagedAssert(condition: boolean, stage: RejectionStage, message: string): void { if (!condition) throw new StageError(stage, message); }

function schemaRef(root: Obj, reference: string): Schema {
  const parts = reference.slice(2).split("/").map((part) => part.replace(/~1/g, "/").replace(/~0/g, "~"));
  const value = parts.reduce<unknown>((current, part) => record(current, reference)[part], root);
  return record(value, reference);
}
function validateSchema(value: unknown, schema: Schema, root: Obj, label: string): void {
  if (schema.$ref !== undefined) { validateSchema(value, schemaRef(root, string(schema.$ref, `${label}.$ref`)), root, label); return; }
  if (schema.oneOf !== undefined) {
    const alternatives = list(schema.oneOf, `${label}.oneOf`); let accepted = 0;
    for (const alternative of alternatives) { try { validateSchema(value, record(alternative, `${label}.alternative`), root, label); accepted++; } catch { /* try the next branch */ } }
    assert(accepted === 1, `${label}: oneOf`); return;
  }
  if (schema.allOf !== undefined) for (const part of list(schema.allOf, `${label}.allOf`)) validateSchema(value, record(part, `${label}.allOf.part`), root, label);
  if (schema.const !== undefined) assert(jcs(value) === jcs(schema.const), `${label}: const`);
  if (schema.enum !== undefined) assert(list(schema.enum, `${label}.enum`).some((candidate) => jcs(candidate) === jcs(value)), `${label}: enum`);
  const type = schema.type === undefined ? undefined : string(schema.type, `${label}.type`);
  if (type === "object") {
    const object = record(value, label); const properties = schema.properties === undefined ? {} : record(schema.properties, `${label}.properties`);
    const required = schema.required === undefined ? [] : list(schema.required, `${label}.required`).map((item) => string(item, `${label}.required.item`));
    for (const key of required) assert(Object.hasOwn(object, key), `${label}: missing ${key}`);
    if (schema.additionalProperties === false) for (const key of Object.keys(object)) assert(Object.hasOwn(properties, key), `${label}: additional ${key}`);
    if (schema.additionalProperties && typeof schema.additionalProperties === "object") for (const [key, child] of Object.entries(object)) if (!Object.hasOwn(properties, key)) validateSchema(child, record(schema.additionalProperties, `${label}.additionalProperties`), root, `${label}.${key}`);
    for (const [key, child] of Object.entries(properties)) if (Object.hasOwn(object, key)) validateSchema(object[key], record(child, `${label}.${key}.schema`), root, `${label}.${key}`);
  } else if (type === "array") {
    const array = list(value, label); if (schema.minItems !== undefined) assert(array.length >= Number(schema.minItems), `${label}: minItems`); if (schema.maxItems !== undefined) assert(array.length <= Number(schema.maxItems), `${label}: maxItems`);
    if (schema.uniqueItems === true) assert(new Set(array.map((item) => jcs(item))).size === array.length, `${label}: uniqueItems`);
    if (schema.items !== undefined) for (const [index, item] of array.entries()) validateSchema(item, record(schema.items, `${label}.items`), root, `${label}[${index}]`);
  } else if (type === "string") {
    const text = string(value, label); const byteLength = utf8(text).length;
    if (schema.minLength !== undefined) assert(byteLength >= Number(schema.minLength), `${label}: minLength`); if (schema.maxLength !== undefined) assert(byteLength <= Number(schema.maxLength), `${label}: maxLength`);
    if (schema.pattern !== undefined) assert(new RegExp(string(schema.pattern, `${label}.pattern`), "u").test(text), `${label}: pattern`);
    if (schema.$ref !== undefined) return;
  } else if (type === "integer") assert(typeof value === "number" && Number.isSafeInteger(value), `${label}: integer`);
  else if (type === "number") assert(typeof value === "number" && Number.isFinite(value), `${label}: number`);
  else if (type === "boolean") assert(typeof value === "boolean", `${label}: boolean`);
  else if (type === "null") assert(value === null, `${label}: null`);
  if (schema.minimum !== undefined) assert(typeof value === "number" && value >= Number(schema.minimum), `${label}: minimum`);
  if (schema.maximum !== undefined) assert(typeof value === "number" && value <= Number(schema.maximum), `${label}: maximum`);
  if (schema.type === undefined && schema.properties === undefined && schema.items === undefined && schema.const === undefined && schema.enum === undefined) assert(value !== undefined, `${label}: undefined`);
}
function validateContractSchema(value: unknown, schemaName: string, schemas: Obj, label = schemaName): void {
  const schemaRoot = schemas; const definitions = record(schemas.schemas, "schemas.schemas"); const defs = record(schemas.$defs, "schemas.$defs"); const schema = record(definitions[schemaName] ?? defs[schemaName], `${schemaName} schema`); validateSchema(value, schema, schemaRoot, label);
}

function jcs(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") { for (let i = 0; i < value.length; i++) { const unit = value.charCodeAt(i); if (unit >= 0xd800 && unit <= 0xdbff) { const next = value.charCodeAt(i + 1); if (!(next >= 0xdc00 && next <= 0xdfff)) throw new TypeError("lone surrogate"); i++; } else if (unit >= 0xdc00 && unit <= 0xdfff) throw new TypeError("lone surrogate"); } const encoded = JSON.stringify(value); if (encoded === undefined) throw new TypeError("string encoding"); return encoded; }
  if (typeof value === "number") { if (!Number.isFinite(value) || !Number.isSafeInteger(value) || Object.is(value, -0)) throw new TypeError("unsafe number"); return JSON.stringify(value); }
  if (Array.isArray(value)) return `[${value.map((item) => { if (item === undefined) throw new TypeError("undefined"); return jcs(item); }).join(",")}]`;
  if (typeof value !== "object" || value === undefined || Object.getPrototypeOf(value) !== Object.prototype) throw new TypeError("non-plain value");
  return `{${Object.keys(value).sort().map((key) => { const child = (value as Obj)[key]; if (child === undefined) throw new TypeError("undefined"); return `${JSON.stringify(key)}:${jcs(child)}`; }).join(",")}}`;
}
function strictB64(value: string): Uint8Array { if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new StageError("contract-validation", "base64url alphabet"); const decoded = bytes(value); assert(b64(decoded) === value, "noncanonical base64url"); return decoded; }
function canonicalEmail(value: unknown): string {
  const email = string(value, "email"); assert(/^[\x21-\x7e]+$/.test(email), "email ASCII/whitespace"); assert((email.match(/@/g) ?? []).length === 1, "email at-sign"); const at = email.indexOf("@"); const local = email.slice(0, at); const domain = email.slice(at + 1); assert(new TextEncoder().encode(local).length <= 64 && new TextEncoder().encode(domain).length <= 253 && new TextEncoder().encode(email).length <= 254, "email byte limits"); assert(/^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+(?:\.[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+)*$/.test(local), "email dot atom"); assert(domain.split(".").every((label) => /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(label) && label.length <= 63), "email domain"); return `${local}@${domain.toLowerCase()}`;
}
function valueAt(root: Obj, path: string): unknown { return path.split(".").reduce<unknown>((current, key) => record(current, path)[key], root); }
function replaceArtifact(scenario: Obj, name: string, field: string, value: unknown, domains: Obj, signer?: unknown): Obj {
  const altered = clone(scenario); const artifacts = list(altered.artifacts, "artifacts") as Obj[]; const artifact = artifacts.find((candidate) => candidate.name === name); if (!artifact) throw new Error(`missing artifact ${name}`); const message = { ...record(artifact.message, `${name}.message`), [field]: value };
  const registry = record(domains.domains, "domains"); const domain = string(registry[name], `${name}.domain`); const testKeys = record(domains.testKeys, "testKeys"); const signerLabel = signer === "sender" ? "senderSeedHex" : name === "inviteAuthorization" ? "nodeSeedHex" : "holderSeedHex"; const seed = string(testKeys[signerLabel], `${signerLabel}`); const textMessage = jcs(message); const prefix = Buffer.from("302e020100300506032b657004220420", "hex"); const key = createPrivateKey({ key: Buffer.concat([prefix, Buffer.from(seed, "hex")]), format: "der", type: "pkcs8" }); const signature = new Uint8Array(sign(null, Buffer.concat([utf8(domain), utf8(textMessage)]), key));
  const originalSignature = record(artifact.signature, `${name}.signature`); const senderDid = signer === "sender" ? string(record(scenario.authorization, "authorization").senderDid, "senderDid") : undefined; const alteredArtifact = { ...artifact, domain, message, jcs: textMessage, messageDigest: digest(utf8(textMessage)), signedBytesDigest: digest(Buffer.concat([utf8(domain), utf8(textMessage)])), signatureDigest: digest(signature), signerDid: senderDid ?? artifact.signerDid, signature: { ...originalSignature, kid: senderDid === undefined ? originalSignature.kid : `${senderDid}#${senderDid.slice("did:key:".length)}`, value: b64(signature) } }; artifacts[artifacts.indexOf(artifact)] = alteredArtifact; if (name === "inviteAuthorization") altered.authorization = message; return altered;
}
function crossEquations(scenario: Obj): void {
  const artifacts = list(scenario.artifacts, "artifacts") as Obj[]; const byName = (name: string): Obj => { const artifact = artifacts.find((item) => item.name === name); if (!artifact) throw new Error(`missing ${name}`); return record(artifact.message, `${name}.message`); }; const auth = record(scenario.authorization, "authorization"); const binding = byName("holderBinding"); const credential = record(scenario.credential, "credential"); const disclosure = record(list(credential.disclosures, "disclosures")[0], "disclosure"); const disclosed = JSON.parse(new TextDecoder().decode(strictB64(string(disclosure.encoded, "disclosure.encoded"))) as string) as unknown[];
  assert(string(record(scenario.policy, "policy").recipientEmail, "policy.email") === string(auth.recipientEmail, "authorization.email") && string(auth.recipientEmail, "authorization.email") === string(scenario.canonicalEmail, "canonicalEmail"), "canonical email equation"); assert(disclosure.path === "/email" && disclosure.value === scenario.canonicalEmail && disclosed.length === 3 && disclosed[1] === "email" && disclosed[2] === scenario.canonicalEmail, "disclosed email equation");
  const redeem = record(record(record(scenario.preimages, "preimages").claimRedeemRequest, "claimRedeemRequest").body, "claimRedeemRequest.body"); const otpRedeem = record(record(record(scenario.preimages, "preimages").claimRedeemOtpRequest, "claimRedeemOtpRequest").body, "claimRedeemOtpRequest.body"); assert(redeem.redemptionId === binding.redemptionId && redeem.invitationId === binding.invitationId && otpRedeem.redemptionId === binding.redemptionId && otpRedeem.invitationId === binding.invitationId, "redeem identifier equation");
  const source = record(scenario.source, "source"); const expected: Record<string, unknown> = { shareCid: scenario.shareCid, shareId: scenario.shareId, policyCid: scenario.policyCid, delegationCid: scenario.delegationCid, authorityMaterialHandle: scenario.authorityMaterialHandle, authorityMaterialDigest: scenario.authorityMaterialDigest, targetOrigin: auth.targetOrigin, nodeAudience: auth.nodeAudience, holderDid: binding.holderDid, contentSourceDigest: scenario.sourceDigest, action: source.action, resource: source.path };
  const check = (value: Obj): void => { for (const field of Object.keys(expected)) if (value[field] !== undefined) assert(value[field] === expected[field], `${field} equation`); if (value.contentSource !== undefined) assert(jcs(value.contentSource) === jcs(source), "content source equation"); };
  for (const artifact of artifacts) check(record(artifact.message, "artifact.message")); const envelope = record(scenario.envelope, "envelope"); assert(envelope.shareId === expected.shareId && record(envelope.authorizationTarget, "authorizationTarget").policyCid === expected.policyCid && record(envelope.target, "target").origin === expected.targetOrigin && record(envelope.target, "target").nodeAudience === expected.nodeAudience && record(record(envelope.target, "target").resource, "resource").path === expected.resource, "envelope equation"); const enrollment = record(scenario.enrollment, "enrollment"); assert(enrollment.targetOrigin === expected.targetOrigin && enrollment.nodeAudience === expected.nodeAudience, "enrollment equation");
  for (const value of Object.values(record(scenario.preimages, "preimages"))) { const body = record(value, "preimage").body; check(record(body, "preimage.body")); for (const nested of [record(body, "preimage.body").authorization, record(body, "preimage.body").binding, record(body, "preimage.body").challenge, record(body, "preimage.body").presentation, record(body, "preimage.body").session, record(body, "preimage.body").invocation]) if (nested) check(record(nested, "nested preimage")); }
}

function reduceDurableRows(preRows: Obj, label: string, row: Obj): Obj {
  const machine = clone(preRows);
  const commands = list(row.commands, `${label}.commands`); assert(commands.length === 1, `${label}: exactly one command`); const command = record(commands[0], `${label}.command`); const commandName = string(command.name, `${label}.command.name`); const operands = command.operands === undefined ? {} : record(command.operands, `${label}.command.operands`);
  const argument = (name: string): unknown => operands[name];
  const attempts = Number(argument("attempts"));
  const fail = (message: string): never => { throw new StateCommandRejection(commandName, machine, `${label}: ${message}`); };
  switch (commandName) {
    case "create_invitation":
      assert(argument("version") === 1 && argument("outboxKey") === "invite:create:auth-kv-001" && machine.invitation === "ABSENT" && machine.outbox === null && machine.claimMaterial === "encrypted", `${label}: precondition`);
      machine.invitation = `PENDING_DELIVERY(v${String(argument("version"))})`; machine.outbox = argument("outboxKey"); break;
    case "provider_accept":
      assert(argument("version") === 1 && argument("claimMaterialAfter") === "deleted" && machine.invitation === "PENDING_DELIVERY(v1)" && machine.providerAccepted === false && machine.claimMaterial === "encrypted", `${label}: precondition`);
      machine.invitation = `ACTIVE(v${String(argument("version"))})`; machine.providerAccepted = true; machine.claimMaterial = argument("claimMaterialAfter"); break;
    case "invalidate_old_version":
      assert(argument("version") === 1 && argument("onlyAfter") === "provider_acceptance" && machine.invitation === "PENDING_DELIVERY(v2)" && machine.activeVersion === 1 && machine.pendingVersion === 2, `${label}: precondition`);
      machine.oldSecret = "retired";
      fail("invalidation before provider acceptance");
    case "prepare_resend":
      assert(argument("fromVersion") === 1 && argument("toVersion") === 2 && argument("replacementMaterial") === "encrypted" && machine.invitation === "ACTIVE(v1)" && machine.activeVersion === 1 && machine.pendingVersion === null, `${label}: precondition`);
      machine.invitation = `PENDING_DELIVERY(v${String(argument("toVersion"))})`; machine.pendingVersion = argument("toVersion"); machine.replacementMaterial = argument("replacementMaterial"); break;
    case "provider_reject":
      assert(argument("pendingVersion") === 2 && argument("restoreVersion") === 1 && argument("replacementMaterialAfter") === "discarded" && machine.invitation === "PENDING_DELIVERY(v2)" && machine.activeVersion === 1 && machine.pendingVersion === 2, `${label}: precondition`);
      machine.invitation = `ACTIVE(v${String(argument("restoreVersion"))})`; machine.pendingVersion = null; machine.replacementMaterial = argument("replacementMaterialAfter"); break;
    case "provider_accept_then_crash":
      assert(argument("version") === 2 && argument("idempotencyKey") === "invite:resend:invitation-001:v2" && argument("sendCount") === 1 && machine.invitation === "PENDING_DELIVERY(v2)" && machine.providerAccepted === false, `${label}: precondition`);
      machine.providerAccepted = true; machine.crashObserved = true; break;
    case "reconcile_provider_acceptance":
      assert(argument("version") === 2 && argument("idempotencyKey") === "invite:resend:invitation-001:v2" && argument("sendCount") === 1 && argument("retireVersion") === 1 && machine.providerAccepted === true && machine.crashObserved === true, `${label}: precondition`);
      machine.invitation = `ACTIVE(v${String(argument("version"))})`; machine.activeVersion = argument("version"); machine.pendingVersion = null; machine.oldSecret = "retired"; machine.providerSendCount = argument("sendCount"); delete machine.providerAccepted; delete machine.crashObserved; break;
    case "resolve_issuance": {
      const redemptionId = string(argument("redemptionId"), `${label}.redemptionId`); const outcome = string(argument("outcome"), `${label}.outcome`); const result = string(argument("result"), `${label}.result`);
      assert((outcome === "success" && result === "persisted") || (outcome === "failure" && result === "terminal-error"), `${label}: issuance outcome`);
      assert(argument("seedAfter") === "deleted" && machine.invitation === `REDEEMING(v1,${redemptionId})` && machine.seed === "encrypted" && machine.result === null && machine.consumed === false, `${label}: precondition`);
      if (outcome === "success") machine.invitation = "CONSUMED(v1)"; else machine.invitation = "TERMINAL_ERROR";
      machine.seed = argument("seedAfter"); machine.result = result; machine.consumed = true; break;
    }
    case "atomic_write":
      assert(jcs(argument("writes")) === jcs(["result", "consumed"]) && argument("requireAtomic") === true, `${label}: precondition`); machine.result = "partial"; machine.consumed = true; fail("partial write");
    case "cleanup_seed":
      assert(argument("pendingSeedAction") === "refuse" && argument("requiresDurableCompletion") === true && machine.seed === "encrypted", `${label}: precondition`); machine.seed = "deleted"; fail("pending seed cleanup");
    case "redeem_if_active": {
      const redemptionId = string(argument("redemptionId"), `${label}.redemptionId`); const result = string(argument("result"), `${label}.result`); assert(Number.isSafeInteger(attempts) && attempts > 0, `${label}: attempts`);
      const sameRedemption = machine.redemptionId === redemptionId && result === "same-result" && machine.invitation === "ACTIVE(v1)" && machine.issuanceCount === 0;
      if (!sameRedemption) { machine.redemptionId = redemptionId; machine.result = result; machine.issuanceCount = Number(machine.issuanceCount) + 1; fail("different redemption"); }
      let cachedOutcome: Obj | undefined; const attemptOutcomes: Obj[] = [];
      for (let attempt = 0; attempt < attempts; attempt++) {
        if (machine.invitation === "ACTIVE(v1)" && machine.issuanceCount === 0) { machine.invitation = "CONSUMED(v1)"; machine.issuanceCount = 1; machine.result = result; }
        const outcome = { status: "issued", result: string(machine.result, `${label}.cachedResult`) };
        attemptOutcomes.push(outcome);
        if (cachedOutcome === undefined) cachedOutcome = clone(outcome);
        else assert(jcs(outcome) === jcs(cachedOutcome), `${label}: CAS cached outcome changed at attempt ${attempt + 1}`);
      }
      const finalOutcome = cachedOutcome ?? fail("missing CAS outcome");
      if (argument("cachedOutcome") !== undefined) assert(jcs(finalOutcome) === jcs(argument("cachedOutcome")), `${label}: cached outcome mismatch`);
      if (argument("cachedResult") !== undefined) assert(finalOutcome.result === argument("cachedResult"), `${label}: cached result mismatch`);
      if (argument("attemptOutcomes") !== undefined) assert(jcs(attemptOutcomes) === jcs(argument("attemptOutcomes")), `${label}: CAS attempt outcomes mismatch`);
      break;
    }
    case "wrong_otp_attempts": {
      const lockAt = Number(argument("lockAt")); assert(Number.isSafeInteger(attempts) && attempts === lockAt && argument("invalidMagicAttempts") === 0 && machine.invitation === "ACTIVE(v1)" && machine.otpAttempts === 0 && machine.invalidMagicOtpAttempts === 0, `${label}: OTP precondition`);
      let cachedOutcome: string | undefined; const attemptOutcomes: string[] = [];
      for (let attempt = 0; attempt < attempts; attempt++) {
        machine.otpAttempts = Number(machine.otpAttempts) + 1;
        const outcome = Number(machine.otpAttempts) >= lockAt ? "LOCKED" : "ACTIVE";
        attemptOutcomes.push(outcome);
        if (cachedOutcome === undefined) cachedOutcome = outcome; else assert(outcome === cachedOutcome || attempt === attempts - 1, `${label}: OTP cached outcome changed at attempt ${attempt + 1}`);
      }
      machine.invitation = Number(machine.otpAttempts) >= lockAt ? "LOCKED(v1)" : "ACTIVE(v1)";
      if (argument("attemptOutcomes") !== undefined) assert(jcs(attemptOutcomes) === jcs(argument("attemptOutcomes")), `${label}: OTP attempt outcomes mismatch`);
      break;
    }
    case "consume_nonce":
      assert(argument("requiredState") === "VERIFYING" && machine.nonce === "CONSUMED", `${label}: precondition`); machine.nonceReplayAttempted = true; fail("nonce replay");
    case "reserve_jti":
      assert(argument("jti") === "authorization-jti-001" && argument("digest") === "digest-b" && machine.jti === "authorization-jti-001" && machine.digest === "digest-a", `${label}: precondition`); machine.digest = argument("digest"); fail("JTI replay");
    case "scanner_get":
      assert(argument("method") === "GET" && argument("mutate") === false, `${label}: scanner operation`); return machine;
    default: fail("unknown serialized command");
  }
  return machine;
}

function validateOperationProgram(states: Obj): void {
  const program = list(states.operationProgram, "states.operationProgram"); assert(program.length > 0, "operation program empty");
  for (const rowValue of program) {
    const row = record(rowValue, "operation program row"); const id = string(row.id, "operation id"); const operation = string(row.operation, `${id}.operation`); const pre = record(row.pre, `${id}.pre`); const expected = record(row.expected, `${id}.expected`);
    assert(row.commands !== undefined && row.attempted === undefined && row.post === undefined, `${id}: pre/commands/expected operation`); assert(Object.keys(pre).length === 1 && Object.hasOwn(pre, "durableRows") && Object.keys(expected).length === 1 && Object.hasOwn(expected, "durableRows"), `${id}: durable row envelope`);
    const beforeRows = record(pre.durableRows, `${id}.pre.durableRows`);
    const beforeSnapshot = jcs(beforeRows);
    if (operation === "reject") {
      let rejection: unknown;
      try { reduceDurableRows(beforeRows, id, row); } catch (error) { rejection = error; }
      if (!(rejection instanceof StateCommandRejection)) throw new Error(`${id}: expected typed command rejection`);
      assert(rejection.commandName === string(record(list(row.commands, `${id}.commands`)[0], `${id}.command`).name, `${id}.command.name`), `${id}: rejected command name`);
      assert(jcs(rejection.attemptedState) !== beforeSnapshot, `${id}: rejected command did not attempt a mutation`);
      assert(jcs(beforeRows) === beforeSnapshot, `${id}: rejected scratch state escaped`);
      assert(jcs(beforeRows) === jcs(expected.durableRows), `${id}: rollback changed durable rows`); continue;
    }
    assert(operation === "transaction" || operation === "crash" || operation === "retry" || operation === "read-only", `${id}: operation vocabulary`);
    const derived = reduceDurableRows(beforeRows, id, row); if (operation === "read-only") assert(jcs(derived) === beforeSnapshot, `${id}: read-only state changed`); assert(jcs(derived) === jcs(expected.durableRows), `${id}: derived post-state`);
  }
}

function validateRecovery(states: Obj): void {
  if (!Object.hasOwn(states, "issuanceRecovery")) { validateOperationProgram(states); return; }
  const recovery = record(states.issuanceRecovery, "issuanceRecovery");
  assert(recovery.seedCiphertext === recovery.retrySeedCiphertext && recovery.pendingSeedCiphertext === recovery.retryPendingSeedCiphertext && recovery.seedCiphertext === recovery.pendingSeedCiphertext, "retry seed bytes changed");
  const timeline = list(recovery.timeline, "recovery.timeline").map((value) => record(value, "recovery event"));
  const event = (index: number): Obj => record(timeline[index], `recovery.timeline[${index}]`); const t0 = event(0); const t1 = event(1); const t2 = event(2); const t3 = event(3); const t4 = event(4);
  assert(timeline.length === 5 && t0.state === "PENDING_ENCRYPTED" && t1.event === "credential_generated_then_crash" && t1.credentialGenerated === true && t1.durableCompletion === false && t2.event === "retry_same_seed" && t3.event === "prepare_atomic_success" && t3.state === "RETRYING" && t3.durableCompletion === false && t3.resultPersisted === false && t3.consumedPersisted === false && t4.event === "atomic_credential_result_consumed_persisted" && t4.state === "CONSUMED" && t4.credentialPersisted === true && t4.durableCompletion === true && t4.durableCompletionAt === "2026-07-16T12:00:03.000Z" && t4.invitationState === "CONSUMED" && t4.consumedPersisted === true && t4.resultPersisted === true && t4.atomicConsumedAndResult === true && t4.atomicCredentialResultInvitationConsumedAndSeedDeletion === true && t4.resultDigest === recovery.resultDigest, "recovery timeline");
  assert(t0.seedEncrypted === true && t1.seedEncrypted === true && t2.seedEncrypted === true && t3.seedEncrypted === true && t4.seedEncrypted === false, "recovery seed lifecycle");
  const failure = list(recovery.terminalFailureTimeline, "terminalFailureTimeline").map((value) => record(value, "terminal failure event"));
  const failureEvent = (index: number): Obj => record(failure[index], `terminalFailureTimeline[${index}]`); const f0 = failureEvent(0); const f1 = failureEvent(1); const f2 = failureEvent(2);
  assert(failure.length === 3 && f0.state === "PENDING_ENCRYPTED" && f0.seedEncrypted === true && f1.state === "RETRYING" && f1.seedEncrypted === true && f2.event === "atomic_terminal_result_consumed_persisted" && f2.state === "TERMINAL_ERROR" && f2.terminalResultPersisted === true && f2.terminalErrorPersisted === true && f2.resultPersisted === true && f2.seedEncrypted === false && f2.invitationState === "CONSUMED" && f2.consumedPersisted === true && f2.atomicTerminalAndSeedDeletion === true && f2.atomicTerminalResultInvitationConsumedAndSeedDeletion === true && f2.errorCode === "credential_issuance_failed", "atomic terminal failure");
  const invariants = record(recovery.invariants, "recovery invariants");
  for (const key of ["pendingSeedEncrypted", "retrySeedByteIdentical", "completionRequiresDurableWrite", "consumedAndResultPersistedAtomically", "noDurableResultBeforeAtomicSuccess", "terminalResultAndConsumedPersistedAtomically", "terminalResolutionAtomic", "cleanupRefusesPendingSeed"]) assert(invariants[key] === true, `${key}: invariant`);
  assert(invariants.durableCompletionAt === "2026-07-16T12:00:03.000Z" && invariants.redactionWindowSeconds === 900 && invariants.redactionStartsOnlyAt === "durable_completion" && invariants.redactionMeasuredFrom === "2026-07-16T12:00:03.000Z" && invariants.redactionAt === "2026-07-16T12:15:03.000Z", "redaction window");
  const cleanup = record(recovery.cleanup, "cleanup");
  assert(cleanup.pendingSeedAction === "refuse" && cleanup.pendingSeedRemains === true && cleanup.completedSeedAction === "delete", "cleanup policy");
  const terminal = record(recovery.terminalResolution, "terminal resolution");
  assert(terminal.atomic === true && terminal.atomicConsumedAndResultPersisted === true && terminal.atomicCredentialResultInvitationConsumedAndSeedDeletion === true && terminal.atomicTerminalAndSeedDeletion === true && terminal.atomicTerminalResultInvitationConsumedAndSeedDeletion === true && terminal.successOutcome === "CONSUMED" && terminal.failureOutcome === "TERMINAL_ERROR" && jcs(terminal.states) === jcs(["PENDING_ENCRYPTED", "RETRYING", "CONSUMED", "TERMINAL_ERROR"]), "terminal resolution");
  assert(digest(utf8(new TextDecoder().decode(strictB64(string(recovery.resultBytes, "resultBytes"))))) === recovery.resultDigest, "result digest");
  assert(t0.event === "seed_persisted" && t1.state === "PENDING_ENCRYPTED" && t2.state === "RETRYING" && t3.state === "RETRYING" && t4.state === "CONSUMED", "issuance success trace");
  assert(f0.event === "seed_persisted" && f1.state === "RETRYING" && f2.state === "TERMINAL_ERROR", "issuance failure trace");
  executeRecoveryInterpreter(recovery);
}

const b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58Decode(value: string): Uint8Array {
  assert(/^[1-9A-HJ-NP-Za-km-z]+$/.test(value), "base58 alphabet");
  let number = 0n;
  for (const character of value) { const digit = b58Alphabet.indexOf(character); assert(digit >= 0, "base58 digit"); number = number * 58n + BigInt(digit); }
  let hex = number.toString(16); if (hex.length % 2) hex = `0${hex}`;
  const decoded = hex.length === 0 ? new Uint8Array() : new Uint8Array(Buffer.from(hex, "hex"));
  let leadingZeroes = 0; while (leadingZeroes < value.length && value[leadingZeroes] === "1") leadingZeroes++;
  return leadingZeroes === 0 ? decoded : new Uint8Array([...new Uint8Array(leadingZeroes), ...decoded]);
}
function validateDidKey(value: unknown, label: string): string {
  const did = string(value, label); assert(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/.test(did), `${label}: did:key`);
  const encoded = did.slice("did:key:z".length); const key = base58Decode(encoded); assert(key.length === 34 && key[0] === 0xed && key[1] === 0x01, `${label}: Ed25519 multicodec`);
  const publicKey = key.slice(2); const yBytes = new Uint8Array(publicKey); yBytes[31] = (yBytes[31] ?? 0) & 0x7f; const y = littleEndianNumber(yBytes);
  assert(y < (1n << 255n) - 19n, `${label}: noncanonical Edwards point`);
  assert(!(publicKey[0] === 1 && publicKey.slice(1).every((byte) => byte === 0)), `${label}: small-order Edwards point`);
  return did;
}
function validateFixedB64(value: unknown, length: number, label: string): Uint8Array { const decoded = strictB64(string(value, label)); assert(decoded.length === length, `${label}: byte length`); return decoded; }
function littleEndianNumber(value: Uint8Array): bigint { let number = 0n; for (let index = value.length - 1; index >= 0; index--) number = (number << 8n) | BigInt(value[index] ?? 0); return number; }
function validateEd25519Signature(value: unknown, label: string): Uint8Array {
  const signature = validateFixedB64(value, 64, label); const scalar = signature.slice(32); const order = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn;
  stagedAssert(((scalar[31] ?? 0) & 0xe0) === 0 && littleEndianNumber(scalar) > 0n && littleEndianNumber(scalar) < order, "signature-encoding", `${label}: noncanonical Ed25519 S`); return signature;
}
function verifyEd25519(value: unknown, did: unknown, domain: string, message: Obj, label: string): void {
  const signature = validateEd25519Signature(value, label); const holderDid = validateDidKey(did, `${label}.did`); const keyBytes = base58Decode(holderDid.slice("did:key:z".length)).slice(2); const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), keyBytes]), format: "der", type: "spki" });
  assert(verify(null, Buffer.concat([utf8(domain), utf8(jcs(message))]), key, signature), `${label}: signature verification`);
}
function validateProof(value: unknown, label: string, expectedKid?: string): void {
  const proof = record(value, label); assert(Object.keys(proof).length === 3 && Object.keys(proof).every((key) => ["alg", "kid", "signature"].includes(key)), `${label}: strict proof shape`); assert(proof.alg === "EdDSA", `${label}: algorithm`); const kid = string(proof.kid, `${label}.kid`); assert(/^did:(?:web:[^#\s]+|key:z[^#\s]+)#[^#\s]+$/.test(kid), `${label}: kid shape`); if (kid.startsWith("did:key:")) { const did = kid.split("#", 1)[0] ?? ""; validateDidKey(did, `${label}.kid.did`); assert(kid === `${did}#${did.slice("did:key:".length)}`, `${label}: noncanonical did:key kid`); } if (expectedKid !== undefined) assert(kid === expectedKid, `${label}: key binding`); validateEd25519Signature(proof.signature, `${label}.signature`);
}

function rawPublicKeyFromDid(did: string, label: string): ReturnType<typeof createPublicKey> {
  const validated = validateDidKey(did, label); const keyBytes = base58Decode(validated.slice("did:key:z".length)).slice(2); return createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), keyBytes]), format: "der", type: "spki" });
}
function rawPublicKey(value: unknown, label: string): ReturnType<typeof createPublicKey> {
  const keyBytes = validateFixedB64(value, 32, label); return createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), keyBytes]), format: "der", type: "spki" });
}
function publicKeyFromSeed(seed: string, label: string): ReturnType<typeof createPublicKey> {
  assert(/^[0-9a-f]{64}$/u.test(seed), `${label}: seed`); const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return createPublicKey(createPrivateKey({ key: Buffer.concat([prefix, Buffer.from(seed, "hex")]), format: "der", type: "pkcs8" }));
}
function candidateIssuerKeys(credential: Obj, domains: Obj, label: string): ReturnType<typeof createPublicKey>[] {
  const keys: ReturnType<typeof createPublicKey>[] = []; const add = (value: unknown, keyLabel: string): void => {
    if (typeof value === "string") { keys.push(value.startsWith("did:key:") ? rawPublicKeyFromDid(value, keyLabel) : rawPublicKey(value, keyLabel)); return; }
    const declared = record(value, keyLabel); const publicKey = declared.publicKey ?? declared.key ?? declared.value; assert(publicKey !== undefined, `${keyLabel}: public key`); add(publicKey, `${keyLabel}.publicKey`);
  };
  const issuerJws = record(credential.issuerJws, `${label}.issuerJws`);
  const declared = [credential.signingKey, credential.issuerKey, credential.issuerSigningKey, credential.issuerPublicKey, credential.signingPublicKey, issuerJws.key, issuerJws.signingKey, issuerJws.publicKey, issuerJws.verificationKey].find((value) => value !== undefined);
  if (declared !== undefined) { add(declared, `${label}.candidateSigningKey`); return keys; }
  // Legacy test vectors predate an explicit candidate-key field. Their test-key
  // registry is the declaration for the alternate signing key; trust is still
  // checked separately below against the frozen issuer registry key.
  const testKeys = record(domains.testKeys, `${label}.testKeys`);
  for (const name of ["senderSeedHex", "issuerSeedHex"]) if (testKeys[name] !== undefined) keys.push(publicKeyFromSeed(string(testKeys[name], `${label}.testKeys.${name}`), `${label}.testKeys.${name}`));
  return keys;
}
function expectedKid(did: string): string { return `${did}#${did.startsWith("did:key:") ? did.slice("did:key:".length) : "invitation-key-1"}`; }
function base32Decode(value: string): Uint8Array {
  assert(/^[a-z2-7]+$/.test(value), "CID base32"); const alphabet = "abcdefghijklmnopqrstuvwxyz234567"; let bits = 0; let buffer = 0; const output: number[] = [];
  for (const character of value) { buffer = (buffer << 5) | alphabet.indexOf(character); bits += 5; if (bits >= 8) { bits -= 8; output.push((buffer >> bits) & 0xff); } }
  return new Uint8Array(output);
}
function validateCidBytes(cid: unknown, value: Uint8Array, label: string): void { const text = string(cid, label); assert(/^bafkrei[a-z2-7]{52}$/.test(text), `${label}: CID shape`); const multihash = base32Decode(text.slice(1)); assert(multihash.length === 36 && multihash[0] === 0x01 && multihash[1] === 0x55 && multihash[2] === 0x12 && multihash[3] === 0x20, `${label}: CID multihash`); const actual = new Uint8Array(createHash("sha256").update(value).digest()); assert(Buffer.from(actual).equals(Buffer.from(multihash.slice(4))), `${label}: CID digest`); }
function validatePolicyBytes(target: Obj, label: string): void { const policyBytes = strictB64(string(target.policyBytes, `${label}.policyBytes`)); const text = new TextDecoder().decode(policyBytes); const policy = record(JSON.parse(text) as unknown, `${label}.policy`); assert(jcs(policy) === text, `${label}: policy bytes are not JCS`); validateCidBytes(target.policyCid, policyBytes, `${label}.policyCid`); }
function validateExactAuthorityMaterial(scenario: Obj, domains: Obj, label: string): void {
  const material = record(scenario.authorityMaterial, label);
  const keys = ["type", "version", "handle", "policyOwnerDid", "senderDid", "relationship", "mapping", "policyAuthorityBytes", "policyAuthorityCid", "policyEnforcementBytes", "policyEnforcementCid", "statusObservations", "enrollment", "attestation"];
  assert(material.type === "TinyCloudShareAuthorityMaterial" && material.version === 1 && Object.keys(material).length === keys.length && keys.every((key) => Object.hasOwn(material, key)), `${label}: exact authority material shape`);
  assert(material.policyOwnerDid !== material.senderDid && material.senderDid === record(scenario.authorization, "authorization").senderDid, `${label}: sender/owner separation`);
  const relationship = record(material.relationship, `${label}.relationship`); assert(relationship.authenticated === true && relationship.policyOwnerDid === material.policyOwnerDid && relationship.senderDid === material.senderDid, `${label}: authenticated relationship`);
  const mapping = record(material.mapping, `${label}.mapping`); assert(mapping.sharePolicyCid === scenario.policyCid && mapping.shareDelegationCid === scenario.delegationCid && mapping.policyAuthorityCid === material.policyAuthorityCid && mapping.policyEnforcementCid === material.policyEnforcementCid, `${label}: explicit identifier mapping`);
  for (const [field, expectedRole] of [["policyAuthorityBytes", "policy-authority"], ["policyEnforcementBytes", "policy-enforcement"]] as const) { const bytes = strictB64(string(material[field], `${label}.${field}`)); const artifact = record(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown, `${label}.${field}.artifact`); assert(jcs(artifact) === new TextDecoder().decode(bytes) && artifact.schema === "xyz.tinycloud.policy/enforcement-delegation/v1" && artifact.role === expectedRole && typeof artifact.signature === "object" && typeof artifact.delegationCid === "string" && /^bafkr4i[a-z2-7]{52}$/.test(artifact.delegationCid), `${label}: exact Node #117 ${expectedRole}`); assert(material[field === "policyAuthorityBytes" ? "policyAuthorityCid" : "policyEnforcementCid"] === artifact.delegationCid, `${label}: ${expectedRole} CID mapping`); }
  const observations = list(material.statusObservations, `${label}.statusObservations`); assert(observations.length === 2, `${label}: one status observation per parent`); const parents = new Set([material.policyAuthorityCid, material.policyEnforcementCid]); const sequences = new Map<unknown, number>(); for (const raw of observations) { const observation = record(raw, `${label}.statusObservation`); for (const key of ["parentCid", "state", "checkedAt", "freshUntil", "signerKid"]) string(observation[key], `${label}.statusObservation.${key}`); const sequence = Number(observation.sequence); const freshUntil = string(observation.freshUntil, `${label}.statusObservation.freshUntil`); const checkedAt = string(observation.checkedAt, `${label}.statusObservation.checkedAt`); assert(parents.has(observation.parentCid) && observation.state === "active" && Number.isSafeInteger(sequence) && sequence >= 1 && (!sequences.has(observation.parentCid) || sequence >= sequences.get(observation.parentCid)!) && observation.revokedAt === null && freshUntil >= string(scenario.evaluationTime, "evaluationTime") && Date.parse(freshUntil) - Date.parse(checkedAt) <= 300_000, `${label}: status freshness/monotonicity`); sequences.set(observation.parentCid, sequence); const observationSignature = record(observation.signature, `${label}.statusObservation.signature`); validateProof({ alg: observationSignature.alg, kid: observationSignature.kid, signature: observationSignature.value }, `${label}.statusObservation.signature`, string(observation.signerKid, `${label}.statusObservation.signerKid`)); }
  const enrollment = record(material.enrollment, `${label}.enrollment`); const attestation = record(material.attestation, `${label}.attestation`); const attestationSignature = record(attestation.signature, `${label}.attestation.signature`); assert(attestation.targetOrigin === enrollment.targetOrigin && attestation.nodeAudience === enrollment.nodeAudience && attestation.keyVersion === enrollment.keyVersion && attestation.enrollmentDigest === digest(utf8(jcs(enrollment))) && Date.parse(string(attestation.expiresAt, `${label}.attestation.expiresAt`)) > Date.parse(string(scenario.evaluationTime, "evaluationTime")), `${label}: enrollment/runtime attestation binding`); validateProof({ alg: attestationSignature.alg, kid: attestationSignature.kid, signature: attestationSignature.value }, `${label}.attestation.signature`, string(attestationSignature.kid, `${label}.attestation.signature.kid`));
  assert(scenario.authorityMaterialDigest === digest(utf8(jcs(material))), `${label}: exact bundle digest`);
}
function validateAuthorityMaterial(scenario: Obj, domains: Obj, label = "authorityMaterial"): void { validateExactAuthorityMaterial(scenario, domains, label); }
function validateEnvelopeTarget(target: Obj, label: string): void { assert(target.kind === "policy", `${label}: kind`); string(target.policyCid, `${label}.policyCid`); validatePolicyBytes(target, label); }
function validateArtifactEncoding(artifact: Obj, domains: Obj, scenario: Obj): void {
  const name = string(artifact.name, "artifact.name"); const registry = record(domains.domains, "domains"); const message = record(artifact.message, `${name}.message`); const domain = string(registry[name], `${name}.domain`); assert(artifact.domain === domain && artifact.jcs === jcs(message), `${name}: JCS/domain`); assert(artifact.messageDigest === digest(utf8(string(artifact.jcs, `${name}.jcs`))), `${name}: message digest`); const signature = record(artifact.signature, `${name}.signature`); validateProof(signature, `${name}.signature`); const signatureBytes = strictB64(string(signature.value, `${name}.signature.value`)); assert(artifact.signedBytesDigest === digest(Buffer.concat([utf8(domain), utf8(string(artifact.jcs, `${name}.jcs`))])) && artifact.signatureDigest === digest(signatureBytes), `${name}: signed bytes digest`);
  if (name === "holderBinding" || name === "policyPresentation" || name === "readInvocation") { const holderDid = validateDidKey(message.holderDid, `${name}.holderDid`); assert(string(signature.kid, `${name}.kid`) === `${holderDid}#${holderDid.slice("did:key:".length)}`, `${name}: holder key binding`); }
  if (name === "policy") { const issuerDid = validateDidKey(message.issuerDid, `${name}.issuerDid`); assert(string(signature.kid, `${name}.kid`) === `${issuerDid}#${issuerDid.slice("did:key:".length)}`, `${name}: issuer key binding`); }
  if (name === "inviteAuthorization") assert(string(signature.kid, `${name}.kid`) === string(record(scenario.enrollment, "enrollment").invitationKid, `${name}.invitationKid`), `${name}: invitation key binding`);
}
function validateSignedArtifact(artifact: Obj, scenario: Obj, domains: Obj, schemas?: Obj): void {
  const name = string(artifact.name, "artifact.name"); const schemaNames = new Set(["policy", "envelope", "inviteAuthorization", "authorityMaterial", "holderBinding", "policyChallenge", "policyPresentation", "policySession", "readInvocation"]); assert(schemaNames.has(name), `${name}: signed artifact name`);
  const artifactKeys = ["name", "domain", "message", "jcs", "messageDigest", "signedBytesDigest", "signatureDigest", "signature", "signerDid"]; assert(Object.keys(artifact).length === artifactKeys.length && artifactKeys.every((key) => Object.hasOwn(artifact, key)), `${name}: strict artifact wrapper`);
  const registry = record(domains.domains, "domains"); const message = record(artifact.message, `${name}.message`); if (schemas !== undefined) validateContractSchema(message, name, schemas, `${name}.message`);
  const domain = string(registry[name], `${name}.domain`); const textMessage = jcs(message); assert(artifact.domain === domain && artifact.jcs === textMessage, `${name}: exact JCS/domain`); assert(artifact.messageDigest === digest(utf8(textMessage)), `${name}: message digest`);
  const signature = record(artifact.signature, `${name}.signature`); assert(Object.keys(signature).length === 3 && signature.alg === "EdDSA" && Object.keys(signature).every((key) => ["alg", "kid", "value"].includes(key)), `${name}: strict signature shape`); const value = validateEd25519Signature(signature.value, `${name}.signature.value`); assert(artifact.signedBytesDigest === digest(Buffer.concat([utf8(domain), utf8(textMessage)])), `${name}: signed byte digest`); assert(artifact.signatureDigest === digest(value), `${name}: signature digest`);
  const enrollment = record(scenario.enrollment, "enrollment"); const messageHolder = message.holderDid === undefined ? undefined : validateDidKey(message.holderDid, `${name}.holderDid`); const kid = string(signature.kid, `${name}.signature.kid`); let signerDid: string; let verificationKey: ReturnType<typeof createPublicKey>;
  if (name === "inviteAuthorization" || name === "policyChallenge" || name === "policySession") { signerDid = string(enrollment.nodeAudience, "enrollment.nodeAudience"); assert(kid === string(enrollment.invitationKid, "enrollment.invitationKid"), `${name}: canonical node kid`); verificationKey = rawPublicKey(enrollment.invitationPublicKey, "enrollment.invitationPublicKey"); }
  else if (name === "authorityMaterial") { signerDid = string(record(scenario.authorityMaterial, "authorityMaterial").senderDid, "authorityMaterial.senderDid"); assert(kid === `${signerDid}#${signerDid.slice("did:key:".length)}`, `${name}: sender key selection`); verificationKey = rawPublicKeyFromDid(signerDid, `${name}.signerDid`); }
  else { signerDid = name === "policy" || name === "envelope" ? string(message.issuerDid ?? record(scenario.policy, "policy").issuerDid, `${name}.issuerDid`) : string(messageHolder, `${name}.holderDid`); assert(kid === `${signerDid}#${signerDid.slice("did:key:".length)}`, `${name}: canonical holder/issuer kid`); verificationKey = rawPublicKeyFromDid(signerDid, `${name}.signerDid`); }
  assert(artifact.signerDid === signerDid, `${name}: signer DID`); assert(verify(null, Buffer.concat([utf8(domain), utf8(textMessage)]), verificationKey, value), `${name}: Ed25519 signature`);
}
function validateSignedBytePreimages(scenario: Obj, domains: Obj): void {
  const registry = record(domains.domains, "domains"); const preimages = record(scenario.signedBytePreimages, "signedBytePreimages");
  for (const [name, raw] of Object.entries(preimages)) { const value = record(raw, `${name}.signedBytePreimage`); assert(Object.keys(value).length === 3 && ["domain", "jcs", "digest"].every((key) => Object.hasOwn(value, key)), `${name}: strict signed-byte preimage`); const artifact = (list(scenario.artifacts, "artifacts") as Obj[]).find((candidate) => candidate.name === name); if (artifact === undefined) throw new StageError("contract-validation", `${name}: missing artifact`); const message = record(artifact.message, `${name}.message`); const domain = string(registry[name], `${name}.domain`); const textMessage = jcs(message); assert(value.domain === domain && value.jcs === textMessage && value.digest === digest(Buffer.concat([utf8(domain), utf8(textMessage)])), `${name}: signed-byte preimage`); }
}
function validateSqlArguments(value: unknown, label: string, domains?: Obj): void {
  const args = record(value, `${label}.arguments`); assert(Object.getPrototypeOf(args) === Object.prototype, `${label}: SQL arguments must be a plain object`); const limits = domains === undefined ? undefined : record(domains.limits, `${label}.limits`);
  const maxProperties = limits?.sqlArgumentsMaxProperties === undefined ? 32 : Number(limits.sqlArgumentsMaxProperties);
  const maxBytes = limits?.sqlArgumentsBytes === undefined ? 4096 : Number(limits.sqlArgumentsBytes);
  assert(Number.isSafeInteger(maxProperties) && maxProperties >= 0 && Object.keys(args).length <= maxProperties, `${label}: SQL arguments maxProperties`);
  for (const [key, argument] of Object.entries(args)) {
    assert(key.length > 0, `${label}: empty SQL argument name`);
    assert(typeof argument === "number" && Number.isSafeInteger(argument) && Number.isFinite(argument) && !Object.is(argument, -0), `${label}: SQL argument must be a safe integer`);
  }
  assert(utf8(jcs(args)).length <= maxBytes, `${label}: SQL arguments limit`);
}
function validateSource(source: Obj, scenario: Obj, label: string, domains?: Obj): void {
  assert(source.kind === scenario.kind && source.action === (scenario.kind === "kv" ? "tinycloud.kv/get" : "tinycloud.sql/read"), `${label}: source action`);
  if (scenario.kind === "sql") { const args = record(source.arguments, `${label}.arguments`); validateSqlArguments(args, label, domains); assert(digest(utf8(jcs(args))) === source.argumentsDigest, `${label}: SQL arguments digest`); assert(!Object.hasOwn(source, "query"), `${label}: arbitrary SQL query`); }
  assert(digest(utf8(jcs(source))) === scenario.sourceDigest, `${label}: source digest`);
}
function validateCredentialProfile(credential: Obj, scenario: Obj, label: string, domains: Obj, schemas?: Obj): void {
  if (schemas !== undefined) validateContractSchema(credential, "credential", schemas, label);
  assert(credential.format === "vc+sd-jwt", `${label}: credential format`); assert(utf8(string(credential.credential, `${label}.credential`)).length <= Number(record(domains.limits, `${label}.limits`).credentialBytes), `${label}: credential byte limit`);
  const trust = record(domains.issuerTrust, `${label}.issuerTrust`); const trustedIssuerDid = string(trust.issuerDid, `${label}.issuerTrust.issuerDid`); const trustedVct = string(trust.vct, `${label}.issuerTrust.vct`); const trustedKid = string(trust.kid, `${label}.issuerTrust.kid`); const trustEnabled = trust.enabled === undefined ? true : trust.enabled; const trustedKey = rawPublicKey(trust.publicKey, `${label}.issuerTrust.publicKey`);
  const issuerDid = string(credential.issuerDid, `${label}.issuerDid`); const claims = record(credential.claims, `${label}.claims`); const claimKeys = ["iss", "sub", "iat", "nbf", "exp", "jti", "vct", "tinycloud_share", "_sd_alg", "_sd"]; assert(Object.keys(claims).length === claimKeys.length && Object.keys(claims).every((key) => claimKeys.includes(key)), `${label}: strict claim shape`);
  const holderDid = validateDidKey(credential.holderDid, `${label}.holderDid`); assert(claims._sd_alg === "sha-256", `${label}: claim binding`);
  const holderBinding = (list(scenario.artifacts, `${label}.artifacts`) as Obj[]).find((artifact) => artifact.name === "holderBinding");
  const share = record(claims.tinycloud_share, `${label}.tinycloud_share`); const shareKeys = ["share_cid", "share_id", "policy_cid", "node_audience"]; assert(Object.keys(share).length === shareKeys.length && Object.keys(share).every((key) => shareKeys.includes(key)), `${label}: strict share claim shape`);
  const sd = list(claims._sd, `${label}._sd`); assert(sd.length === 1, `${label}: SD-JWT digest count`); const disclosures = list(credential.disclosures, `${label}.disclosures`); assert(disclosures.length === 1, `${label}: disclosure count`); const disclosure = record(disclosures[0], `${label}.disclosure`); assert(disclosure.path === "/email" && canonicalEmail(disclosure.value) === scenario.canonicalEmail, `${label}: email disclosure`); const encoded = string(disclosure.encoded, `${label}.encoded`); const disclosureText = new TextDecoder("utf-8", { fatal: true }).decode(strictB64(encoded)); const tuple = JSON.parse(disclosureText) as unknown[]; assert(jcs(tuple) === disclosureText && tuple.length === 3 && tuple[0] === disclosure.salt && tuple[1] === "email" && tuple[2] === scenario.canonicalEmail && disclosure.salt === scenario.sdJwtSalt && disclosure.digest === digest(utf8(encoded)) && sd[0] === disclosure.digest, `${label}: disclosure digest`);
  const compact = string(credential.credential, `${label}.credential`); const compactParts = compact.split("~"); const jwtText = string(compactParts[0], `${label}.jwt`); assert(compactParts.length === 3 && compactParts[1] === encoded && compactParts[2] === "", `${label}: SD-JWT compact form`); const jwtParts = jwtText.split("."); const headerSegment = string(jwtParts[0], `${label}.headerSegment`); const payloadSegment = string(jwtParts[1], `${label}.payloadSegment`); const signatureSegment = string(jwtParts[2], `${label}.signatureSegment`); assert(jwtParts.length === 3 && jwtParts.every((part) => part.length > 0), `${label}: SD-JWT JWT segments`); const headerText = new TextDecoder("utf-8", { fatal: true }).decode(strictB64(headerSegment)); const header = record(JSON.parse(headerText) as unknown, `${label}.header`); assert(jcs(header) === headerText && Object.keys(header).length === 1 && header.alg === "EdDSA", `${label}: exact issuer header`); const payloadText = new TextDecoder("utf-8", { fatal: true }).decode(strictB64(payloadSegment)); const payload = record(JSON.parse(payloadText) as unknown, `${label}.payload`); assert(jcs(payload) === payloadText && payloadText === jcs(claims) && b64(utf8(payloadText)) === payloadSegment, `${label}: signed payload/detached claims equality`);
  const issuerJws = record(credential.issuerJws, `${label}.issuerJws`); const signingInput = `${headerSegment}.${payloadSegment}`; const issuerSignature = validateEd25519Signature(signatureSegment, `${label}.issuerSignature`); assert(issuerJws.signingInput === signingInput && issuerJws.signature === signatureSegment && issuerJws.signingInputDigest === digest(utf8(signingInput)) && issuerJws.signature === b64(issuerSignature) && credential.credentialDigest === digest(utf8(compact)), `${label}: issuer preimages`);
  const candidateKeys = candidateIssuerKeys(credential, domains, label); stagedAssert(candidateKeys.some((key) => verify(null, utf8(signingInput), key, issuerSignature)), "issuer-key", `${label}: candidate issuer signature authenticity`);
  stagedAssert(trustEnabled === true && issuerDid === trustedIssuerDid && claims.iss === trustedIssuerDid, "issuer-trust", `${label}: issuer trust`);
  stagedAssert(trustedKid.startsWith(`${trustedIssuerDid}#`) && verify(null, utf8(signingInput), trustedKey, issuerSignature), "issuer-key", `${label}: trusted issuer signature verification`);
  stagedAssert(credential.vct === trustedVct && claims.vct === trustedVct, "credential-vct", `${label}: credential VCT`); stagedAssert(claims.sub === holderDid, "credential-holder", `${label}: claim holder equation`); stagedAssert(holderBinding !== undefined && holderDid === holderBinding.signerDid, "credential-holder", `${label}: holder equation`); stagedAssert(share.share_cid === scenario.shareCid && share.share_id === scenario.shareId && share.policy_cid === scenario.policyCid && share.node_audience === record(scenario.authorization, "authorization").nodeAudience, "credential-scope", `${label}: share claim binding`);
  const evaluationTime = Date.parse(string(scenario.evaluationTime, `${label}.evaluationTime`)); const skewSeconds = Number(scenario.clockSkewSeconds); assert(Number.isSafeInteger(evaluationTime) && Number.isSafeInteger(skewSeconds) && skewSeconds >= 0, `${label}: evaluation clock`); const iat = Number(claims.iat); const nbf = Number(claims.nbf); const exp = Number(claims.exp); stagedAssert(iat <= evaluationTime / 1000 + skewSeconds && nbf <= evaluationTime / 1000 + skewSeconds && nbf >= iat && exp + skewSeconds > evaluationTime / 1000, "credential-time", `${label}: credential time evaluation`); stagedAssert(credential.vct === trustedVct, "credential-vct", `${label}: credential VCT`); assert(exp * 1000 === Date.parse(string(credential.expiresAt, `${label}.expiresAt`)) && credential.expiresAt === record(scenario.policy, "policy").expiresAt, `${label}: credential/share expiry`);
}
function validateReadBody(body: Obj, scenario: Obj, label: string, domains?: Obj): void { const required = ["sessionId", "delegationCid", "authorityMaterialHandle", "authorityMaterialDigest", "contentSource", "contentSourceDigest", "action", "resource", "requestBodyDigest", "invocation", "proof"]; assert(Object.keys(body).every((key) => required.includes(key)) && required.every((key) => Object.hasOwn(body, key)), `${label}: strict read shape`); validateSource(record(body.contentSource, `${label}.contentSource`), scenario, `${label}.contentSource`, domains); assert(body.delegationCid === scenario.delegationCid && body.authorityMaterialHandle === scenario.authorityMaterialHandle && body.authorityMaterialDigest === scenario.authorityMaterialDigest && body.contentSourceDigest === scenario.sourceDigest && body.action === record(scenario.source, "source").action && body.resource === record(scenario.source, "source").path, `${label}: source binding`); validateProof(body.proof, `${label}.proof`); }
function validateRedeemBody(body: Obj, scenario: Obj, label: string): void { const keys = ["version", "redemptionId", "invitationId", "method", "mailboxProof", "binding", "holderProof"]; assert(Object.keys(body).length === keys.length && keys.every((key) => Object.hasOwn(body, key)), `${label}: strict redeem shape`); assert(body.version === "tinycloud.share-email-claim/v1", `${label}: version`); validateFixedB64(body.redemptionId, 16, `${label}.redemptionId`); validateFixedB64(body.invitationId, 16, `${label}.invitationId`); if (body.method === "magic") validateFixedB64(body.mailboxProof, 32, `${label}.mailboxProof`); else if (body.method === "otp") assert(typeof body.mailboxProof === "string" && /^[0-9]{6}$/.test(body.mailboxProof), `${label}: OTP shape`); else throw new StageError("contract-validation", `${label}: method`); const binding = record(body.binding, `${label}.binding`); const holderDid = validateDidKey(binding.holderDid, `${label}.binding.holderDid`); assert(binding.shareId === scenario.shareId && binding.shareCid === scenario.shareCid && binding.policyCid === scenario.policyCid, `${label}: binding equations`); validateProof(body.holderProof, `${label}.holderProof`, `${holderDid}#${holderDid.slice("did:key:".length)}`); }
function proofFromArtifact(artifact: Obj, label: string): Obj { const signature = record(artifact.signature, `${label}.signature`); return { alg: "EdDSA", kid: signature.kid, signature: signature.value }; }
function sameJson(left: unknown, right: unknown, label: string): void { assert(jcs(left) === jcs(right), `${label}: equality`); }
function parseShareUrl(value: unknown, scenario: Obj, label: string): { url: URL; rawFragment: string } {
  const raw = string(value, label); let url: URL;
  try { url = new URL(raw); } catch (error) { throw new StageError("share-url-origin", `${label}: invalid URL`, error); }
  stagedAssert(url.protocol === "https:", "share-url-scheme", `${label}: HTTPS scheme required`);
  const authorityStart = raw.indexOf("://"); const afterAuthority = authorityStart < 0 ? "" : raw.slice(authorityStart + 3); const delimiter = afterAuthority.search(/[/?#]/u); const authorityEnd = delimiter < 0 ? raw.length : authorityStart + 3 + delimiter; const authority = authorityStart < 0 ? "" : raw.slice(authorityStart + 3, authorityEnd); const hostPort = authority.slice(authority.lastIndexOf("@") + 1); const colon = hostPort.lastIndexOf(":");
  stagedAssert(url.port === "" && !(colon >= 0 && /^\d+$/u.test(hostPort.slice(colon + 1))), "share-url-port", `${label}: explicit port is forbidden`);
  stagedAssert(url.username === "" && url.password === "" && url.hostname === "share.tinycloud.xyz" && url.origin === "https://share.tinycloud.xyz", "share-url-origin", `${label}: exact share URL origin`);
  stagedAssert(url.pathname === `/s/${scenario.shareCid}`, "share-url-path", `${label}: exact share URL path`);
  const hashIndex = raw.indexOf("#"); const beforeFragment = hashIndex < 0 ? raw : raw.slice(0, hashIndex); const queryIndex = beforeFragment.indexOf("?");
  stagedAssert(queryIndex < 0, "share-url-query", `${label}: query is forbidden`);
  return { url, rawFragment: hashIndex < 0 ? "" : raw.slice(hashIndex + 1) };
}
function validateShareUrl(value: unknown, scenario: Obj, label: string): void {
  const { rawFragment } = parseShareUrl(value, scenario, label);
  stagedAssert(!rawFragment.includes("%"), "share-url-fragment-encoding", `${label}: percent-encoded fragment material`);
  const pairs = [...new URLSearchParams(rawFragment).entries()]; stagedAssert(pairs.length === 1 && pairs[0]?.[0] === "k", "share-url-fragment", `${label}: exact fragment`);
  try { validateFixedB64(pairs[0]?.[1], 32, `${label}.k`); } catch (error) { throw new StageError("share-url-key", `${label}: share URL key`, error); }
}
function validateScannerUrl(value: unknown, scenario: Obj, label: string): void {
  const { rawFragment } = parseShareUrl(value, scenario, label);
  stagedAssert(!rawFragment.includes("%"), "scanner-fragment-encoding", `${label}: percent-encoded fragment material`);
  const pairs = [...new URLSearchParams(rawFragment).entries()]; const keys = pairs.map(([key]) => key);
  stagedAssert(pairs.length === 3 && new Set(keys).size === 3 && keys.every((key) => ["k", "i", "c"].includes(key)), "share-url-fragment", `${label}: scanner fragment shape`);
  const fragment = new URLSearchParams(pairs); try { validateFixedB64(fragment.get("k"), 32, `${label}.k`); validateFixedB64(fragment.get("i"), 16, `${label}.i`); validateFixedB64(fragment.get("c"), 32, `${label}.c`); } catch (error) { throw new StageError("share-url-key", `${label}: scanner fragment key`, error); }
}
function validateEndpointBindings(scenario: Obj, preimages: Obj, domains: Obj): void {
  const artifacts = list(scenario.artifacts, "artifacts") as Obj[]; const artifact = (name: string): Obj => { const found = artifacts.find((candidate) => candidate.name === name); if (!found) throw new Error(`missing ${name}`); return found; };
  const bodyOf = (name: string): Obj => record(record(preimages[name], name).body, `${name}.body`);
  const auth = record(record(scenario.authorization, "authorization"), "authorization");
  const authorizationRequest = bodyOf("authorizationRequest"); sameJson(authorizationRequest, { jti: auth.jti, reportAbuseToken: scenario.reportAbuseToken, senderDid: auth.senderDid, shareCid: auth.shareCid, shareId: auth.shareId, policyCid: auth.policyCid, delegationCid: auth.delegationCid, authorityMaterialHandle: auth.authorityMaterialHandle, authorityMaterialDigest: auth.authorityMaterialDigest, recipientEmail: auth.recipientEmail, targetOrigin: auth.targetOrigin, nodeAudience: auth.nodeAudience, documentName: auth.documentName, senderTrust: auth.senderTrust, contentSource: auth.contentSource, contentSourceDigest: auth.contentSourceDigest, shareExpiresAt: auth.shareExpiresAt, requestBodyDigest: authorizationRequest.requestBodyDigest }, "authorization request");
  const authorizationBody = { shareCid: authorizationRequest.shareCid, shareId: authorizationRequest.shareId, policyCid: authorizationRequest.policyCid, delegationCid: authorizationRequest.delegationCid, authorityMaterialHandle: authorizationRequest.authorityMaterialHandle, authorityMaterialDigest: authorizationRequest.authorityMaterialDigest, recipientEmail: authorizationRequest.recipientEmail, targetOrigin: authorizationRequest.targetOrigin, nodeAudience: authorizationRequest.nodeAudience, action: record(scenario.source, "source").action, resource: record(scenario.source, "source").path }; assert(authorizationRequest.requestBodyDigest === digest(utf8(jcs(authorizationBody))), "authorization request body digest recomputation");
  const authResponse = bodyOf("authorizationResponse"); sameJson(authResponse.authorization, auth, "authorization response body"); sameJson(authResponse.proof, proofFromArtifact(artifact("inviteAuthorization"), "inviteAuthorization"), "authorization response proof");
  const create = bodyOf("createInvitationRequest"); sameJson(create.authorization, auth, "create invitation authorization"); sameJson(create.proof, proofFromArtifact(artifact("inviteAuthorization"), "inviteAuthorization"), "create invitation proof"); validateShareUrl(create.shareUrl, scenario, "createInvitationRequest.shareUrl");
  for (const name of ["claimRedeemRequest", "claimRedeemOtpRequest"]) { const redeem = bodyOf(name); const bindingArtifact = artifact("holderBinding"); sameJson(redeem.binding, bindingArtifact.message, `${name}.binding`); sameJson(redeem.holderProof, proofFromArtifact(bindingArtifact, "holderBinding"), `${name}.holderProof`); }
  const challengeResponse = bodyOf("policyChallengeResponse"); sameJson(challengeResponse.challenge, artifact("policyChallenge").message, "policy challenge response"); sameJson(challengeResponse.proof, proofFromArtifact(artifact("policyChallenge"), "policyChallenge"), "policy challenge response proof");
  const sessionRequest = bodyOf("policySessionRequest"); sameJson(sessionRequest.presentation, artifact("policyPresentation").message, "policy session presentation"); assert(sessionRequest.credential === record(scenario.credential, "credential").credential, "policy session credential"); sameJson(sessionRequest.proof, proofFromArtifact(artifact("policyPresentation"), "policyPresentation"), "policy session proof");
  const sessionResponse = bodyOf("policySessionResponse"); sameJson(sessionResponse.session, artifact("policySession").message, "policy session response"); sameJson(sessionResponse.proof, proofFromArtifact(artifact("policySession"), "policySession"), "policy session response proof");
  for (const name of ["kvReadRequest", "sqlReadRequest"]) { const read = bodyOf(name); sameJson(read.invocation, artifact("readInvocation").message, `${name}.invocation`); sameJson(read.proof, proofFromArtifact(artifact("readInvocation"), "readInvocation"), `${name}.proof`); }
  const readResponse = bodyOf("readResponse"); const readResponseBody = { ...readResponse }; const readResponseProof = record(readResponseBody.proof, "readResponse.proof"); delete readResponseBody.proof; validateProof(readResponseProof, "readResponse.proof", string(record(scenario.enrollment, "enrollment").invitationKid, "enrollment.invitationKid")); assert(verify(null, Buffer.concat([utf8(string(record(domains.domains, "domains").readResponse, "domains.readResponse")), utf8(jcs(readResponseBody))]), rawPublicKey(record(scenario.enrollment, "enrollment").invitationPublicKey, "enrollment.invitationPublicKey"), strictB64(string(readResponseProof.signature, "readResponse.proof.signature"))), "read response signature"); assert(readResponse.bodyDigest === digest(utf8(string(readResponse.content, "readResponse.content"))), "read response body digest");
  const challengeRequest = bodyOf("policyChallengeRequest"); const challenge = record(artifact("policyChallenge").message, "policyChallenge.message"); for (const key of ["shareCid", "shareId", "delegationCid", "policyCid", "authorityMaterialHandle", "authorityMaterialDigest", "contentSourceDigest", "holderDid", "targetOrigin", "nodeAudience", "action", "resource", "requestBodyDigest"]) assert(challengeRequest[key] === challenge[key], `policy challenge request ${key}`);
  const response = bodyOf("claimChallengeResponse"); const binding = record(artifact("holderBinding").message, "holderBinding.message"); for (const key of ["claimNonce", "shareCid", "shareId", "policyCid", "delegationCid", "authorityMaterialHandle", "authorityMaterialDigest", "contentSource", "contentSourceDigest", "targetOrigin", "nodeAudience"]) assert(response[key] === binding[key] || jcs(response[key]) === jcs(binding[key]), `claim challenge response ${key}`);
  for (const name of ["kvReadRequest", "sqlReadRequest"]) validateReadBody(bodyOf(name), scenario, name, domains);
}
function validateEndpoints(scenario: Obj, domains: Obj, schemas: Obj): void {
  const preimages = record(scenario.preimages, "preimages"); const readSchema = scenario.kind === "kv" ? "kvReadRequest" : "sqlReadRequest"; const schemaByName: Record<string, string> = { authorizationRequest: "authorizationRequest", authorizationResponse: "authorizationResponse", createInvitationRequest: "createInvitationRequest", createInvitationResponse: "createInvitationResponse", resendRequest: "resendRequest", resendResponse: "resendResponse", activationRequest: "activationRequest", activationResponse: "activationResponse", claimChallengeMagicRequest: "claimChallengeMagicRequest", claimChallengeOtpRequest: "claimChallengeOtpRequest", claimChallengeResponse: "claimChallengeResponse", claimRedeemRequest: "claimRedeemRequest", claimRedeemOtpRequest: "claimRedeemRequest", claimRedeemResponse: "claimRedeemResponse", policyChallengeRequest: "policyChallengeRequest", policyChallengeResponse: "policyChallengeResponse", policySessionRequest: "policySessionRequest", policySessionResponse: "policySessionResponse", kvReadRequest: readSchema, sqlReadRequest: readSchema, readResponse: "readResponse", authorizationFailure: "failure", createInvitationFailure: "failure", resendFailure: "failure", claimChallengeFailure: "failure", claimRedeemFailure: "failure", policyChallengeFailure: "failure", policySessionFailure: "failure", kvReadFailure: "failure", sqlReadFailure: "failure" };
  for (const [name, raw] of Object.entries(preimages)) { const preimage = record(raw, `${name}.preimage`); assert(Object.keys(preimage).length === 3 && Object.keys(preimage).every((key) => ["body", "jcs", "digest"].includes(key)), `${name}: strict preimage shape`); const body = record(preimage.body, `${name}.body`); const textBody = jcs(body); assert(preimage.jcs === textBody && preimage.digest === digest(utf8(textBody)), `${name}: body JCS/digest`); const schemaName = schemaByName[name]; if (schemaName === undefined) throw new Error(`${name}: endpoint schema mapping`); validateContractSchema(body, schemaName, schemas, `${name}.body`); }
  validateEndpointBindings(scenario, preimages, domains);
}
function validateEnrollment(scenario: Obj, domains: Obj, schemas: Obj): void {
  const enrollment = record(scenario.enrollment, "enrollment"); validateContractSchema(enrollment, "trustedNodeEnrollment", schemas, "enrollment"); const authority = record(domains.nodeAuthority, "nodeAuthority"); const authorityOrigin = string(authority.origin, "nodeAuthority.origin"); const authorityAudience = string(authority.nodeAudience, "nodeAuthority.nodeAudience");
  const nodeCapability = record(record(domains.capabilities, "capabilities").node, "node capability"); validateContractSchema(nodeCapability, "capabilityDescriptor", schemas, "node capability");
  stagedAssert(enrollment.targetOrigin === authorityOrigin && enrollment.nodeAudience === authorityAudience, "node-authority", "enrollment origin/audience");
  const activeVersion = Number(authority.activeKeyVersion); const keyVersion = Number(enrollment.keyVersion); assert(Number.isSafeInteger(activeVersion) && Number.isSafeInteger(keyVersion) && activeVersion >= 1 && keyVersion >= 1, "enrollment key version");
  const versions = list(authority.keyVersions, "nodeAuthority.keyVersions").map((value) => record(value, "node authority key version")); const key = versions.find((candidate) => Number(candidate.keyVersion) === keyVersion); if (key === undefined) throw new StageError("contract-validation", "enrollment key version is not registered");
  stagedAssert(key.state !== "retired", "node-key-retirement", "retired node invitation key"); stagedAssert(keyVersion === activeVersion, "node-key-rotation", "enrollment key is not active");
  const activeKey = versions.find((candidate) => Number(candidate.keyVersion) === activeVersion); if (activeKey === undefined) throw new StageError("contract-validation", "active node key is not registered"); assert(activeKey.state === "active", "active node key");
  stagedAssert(enrollment.invitationKid === activeKey.invitationKid && enrollment.invitationKid === key.invitationKid, "node-key-rotation", "enrollment kid/version binding"); stagedAssert(enrollment.invitationPublicKey === activeKey.publicKey && enrollment.invitationPublicKey === key.publicKey, "node-enrollment", "enrollment public key binding");
  if (enrollment.enabled !== undefined) stagedAssert(enrollment.enabled === true, "node-enrollment", "disabled enrollment");
  assert(nodeCapability.origin === authorityOrigin && nodeCapability.version === activeVersion && nodeCapability.status === "disabled-until-authority-ready", "node authority status");
}
type IssuanceState = { state: "PENDING_ENCRYPTED" | "RETRYING" | "CONSUMED" | "TERMINAL_ERROR"; seedEncrypted: boolean; credentialGenerated: boolean; durableCompletion: boolean; resultPersisted: boolean; consumedPersisted: boolean; terminalResultPersisted: boolean; terminalErrorPersisted: boolean; invitationState: "ACTIVE" | "CONSUMED" };
function executeIssuanceOperation(machine: IssuanceState, operation: string, resultDigest: string): void {
  switch (operation) {
    case "seed_persisted": machine.state = "PENDING_ENCRYPTED"; machine.seedEncrypted = true; break;
    case "credential_generated_then_crash": assert(machine.state === "PENDING_ENCRYPTED" && machine.seedEncrypted, "credential generation precondition"); machine.credentialGenerated = true; break;
    case "retry_same_seed": assert(machine.seedEncrypted && machine.credentialGenerated && !machine.durableCompletion, "retry seed precondition"); machine.state = "RETRYING"; break;
    case "prepare_atomic_success": assert(machine.state === "RETRYING" && machine.seedEncrypted && machine.resultPersisted === false && machine.consumedPersisted === false, "atomic prepare precondition"); break;
    case "atomic_credential_result_consumed_persisted": assert(machine.state === "RETRYING" && machine.seedEncrypted && machine.resultPersisted === false && machine.consumedPersisted === false, "atomic success precondition"); machine.state = "CONSUMED"; machine.seedEncrypted = false; machine.durableCompletion = true; machine.resultPersisted = true; machine.consumedPersisted = true; machine.invitationState = "CONSUMED"; assert(resultDigest.length > 0, "result persistence"); break;
    case "retry_exhausted": assert((machine.state === "PENDING_ENCRYPTED" || machine.state === "RETRYING") && machine.seedEncrypted, "terminal retry precondition"); machine.state = "RETRYING"; break;
    case "atomic_terminal_result_consumed_persisted": assert(machine.state === "RETRYING" && machine.seedEncrypted && !machine.resultPersisted && !machine.consumedPersisted, "atomic terminal precondition"); machine.state = "TERMINAL_ERROR"; machine.seedEncrypted = false; machine.terminalResultPersisted = true; machine.terminalErrorPersisted = true; machine.resultPersisted = true; machine.consumedPersisted = true; machine.invitationState = "CONSUMED"; break;
    default: throw new Error(`unknown issuance operation ${operation}`);
  }
}
function executeRecoveryInterpreter(recovery: Obj): void {
  const resultDigest = string(recovery.resultDigest, "recovery.resultDigest"); const success: IssuanceState = { state: "PENDING_ENCRYPTED", seedEncrypted: false, credentialGenerated: false, durableCompletion: false, resultPersisted: false, consumedPersisted: false, terminalResultPersisted: false, terminalErrorPersisted: false, invitationState: "ACTIVE" };
  for (const event of list(recovery.timeline, "recovery.timeline")) executeIssuanceOperation(success, string(record(event, "recovery event").event, "recovery event.event"), resultDigest); assert(success.state === "CONSUMED" && success.durableCompletion && success.resultPersisted && success.consumedPersisted && !success.seedEncrypted, "success recovery interpreter");
  const failure: IssuanceState = { state: "PENDING_ENCRYPTED", seedEncrypted: false, credentialGenerated: false, durableCompletion: false, resultPersisted: false, consumedPersisted: false, terminalResultPersisted: false, terminalErrorPersisted: false, invitationState: "ACTIVE" };
  for (const event of list(recovery.terminalFailureTimeline, "terminalFailureTimeline")) executeIssuanceOperation(failure, string(record(event, "terminal failure event").event, "terminal failure event.event"), resultDigest); assert(failure.state === "TERMINAL_ERROR" && failure.terminalResultPersisted && failure.terminalErrorPersisted && failure.resultPersisted && failure.consumedPersisted && !failure.seedEncrypted, "terminal recovery interpreter");
  const pending: IssuanceState = { state: "PENDING_ENCRYPTED", seedEncrypted: true, credentialGenerated: false, durableCompletion: false, resultPersisted: false, consumedPersisted: false, terminalResultPersisted: false, terminalErrorPersisted: false, invitationState: "ACTIVE" }; expectReject("partial durable issuance write", () => { assert(pending.resultPersisted === false && pending.consumedPersisted === false && pending.seedEncrypted, "partial write rejected"); executeIssuanceOperation(pending, "prepare_atomic_success", resultDigest); }); assert(pending.seedEncrypted && !pending.resultPersisted && !pending.consumedPersisted, "partial write changed state");
}
function validateStateInterpreter(states: Obj): void {
  if (Object.hasOwn(states, "operationProgram")) { validateOperationProgram(states); return; }
  throw new Error("operation program is required");
}
function validateCapability(capability: Obj, original: Obj, label: string): void { const origin = string(capability.origin, `${label}.origin`); const parsed = new URL(origin); assert(parsed.protocol === "https:" && !origin.includes("*") && capability.version === 1, `${label}: origin/version`); const routes = list(capability.routes, `${label}.routes`).map((route) => string(route, `${label}.route`)); const originalRoutes = new Set(list(original.routes, `${label}.originalRoutes`).map((route) => string(route, `${label}.originalRoute`))); assert(new Set(routes).size === routes.length && routes.every((route) => originalRoutes.has(route)), `${label}: route allowlist`); }
function validateTransition(states: Obj, from: string, to: string): void { const known = new Set(list(states.nonce, "states.nonce").map((value) => string(value, "nonce state"))); assert(known.has(from) && known.has(to), "nonce state vocabulary"); const candidate = { state: "ISSUED" }; const transition = (next: string): void => { assert((candidate.state === "ISSUED" && next === "VERIFYING") || (candidate.state === "VERIFYING" && next === "CONSUMED"), "invalid nonce transition"); candidate.state = next; }; transition("VERIFYING"); transition("CONSUMED"); assert(candidate.state === from, "nonce candidate state mismatch"); transition(to); }
function redeemInvitationCandidate(candidate: { state: string; activeVersion: number; secrets: Map<number, string> }, version: number): string { assert(candidate.state === "ACTIVE" && candidate.activeVersion === version && candidate.secrets.has(version), "inactive invitation version"); return string(candidate.secrets.get(version), "invitation secret"); }
function submitCorrectOtpCandidate(candidate: { state: string; attempts: number; threshold: number }): void { assert(candidate.state === "ACTIVE" && candidate.attempts < candidate.threshold, "OTP is locked"); }
function applyScannerOperation(candidate: { state: string; consumed: boolean }, method: string, operation: string): void { assert(method !== "GET" || operation === "inspect", "GET cannot consume claim"); if (operation === "consume") { assert(candidate.state === "ACTIVE", "claim is not active"); candidate.state = "CONSUMED"; candidate.consumed = true; } }
function validateResponseProof(scenario: Obj, data: Obj, responseName: string): void { const preimages = record(scenario.preimages, "preimages"); const candidate = clone(record(record(preimages[responseName], responseName).body, `${responseName}.body`)); const proof = record(candidate.proof, `${responseName}.proof`); const signer = validateDidKey(data.signer, `${responseName}.mutation.signer`); candidate.proof = { ...proof, kid: `${signer}#${signer.slice("did:key:".length)}` }; validateProof(candidate.proof, `${responseName}.proof`, string(record(scenario.enrollment, "enrollment").invitationKid, "enrollment.invitationKid")); }
function mutatePath(root: Obj, path: string, operation: string, value: unknown): void {
  const parts = path.replace(/\[(\d+)\]/g, ".$1").split(".").filter(Boolean); if (parts.length === 0) throw new Error("mutation path"); const field = parts.pop(); if (field === undefined) throw new Error("mutation field"); let parent = root; for (const part of parts) parent = record(parent[part], `mutation.${part}`); if (operation === "delete") { delete parent[field]; return; } if (operation === "append") { const array = list(parent[field], `mutation.${field}`); array.push(value); return; } parent[field] = value;
}
function executeSerializedNegative(row: Obj, scenario: Obj, domains: Obj, states: Obj, schemas: Obj): void {
  const id = string(row.id, "negative.id"); const target = row.target === undefined ? "" : string(row.target, `${id}.target`); const data = record(row.mutationData, `${id}.mutationData`); const operation = data.operation === undefined ? "" : string(data.operation, `${id}.operation`);
  expectStageReject(row, () => fixedStageBoundary("contract-validation", () => {
    if (target.startsWith("credential.")) { const credential = clone(record(scenario.credential, "credential")); mutatePath(credential, target.slice("credential.".length), operation === "delete" ? "delete" : operation === "append" ? "append" : "replace", data.value ?? data.replacement); validateCredentialProfile(credential, scenario, id, domains); return; }
    if (target.includes(".") && target.split(".")[0] !== "nonce" && (target.startsWith("enrollment.") || target.startsWith("node.") || target.startsWith("capability."))) { const altered = clone(scenario); const path = target.startsWith("enrollment.") ? target : target.startsWith("node.") ? `enrollment.${target.slice(5)}` : target; mutatePath(altered, path, operation, data.value); validateEnrollment(altered, domains, schemas); return; }
    if (target.startsWith("artifact.") || target.includes(".signature") || target.includes("holderBinding.")) { const artifactName = target.startsWith("artifact.") ? string(data.artifact, `${id}.artifact`) : (target.split(".")[0] ?? ""); const field = target.startsWith("artifact.") ? target.slice("artifact.".length).split(".").slice(1).join(".") : target.slice(artifactName.length + 1); const altered = replaceArtifact(scenario, artifactName, field, data.value, domains, data.signer); const candidate = (list(altered.artifacts, "artifacts") as Obj[]).find((item) => item.name === artifactName); if (candidate === undefined) throw new Error(`${id}: artifact`); validateArtifactEncoding(candidate, domains, scenario); crossEquations(altered); return; }
    if (target.startsWith("read.") || target.includes("Request.")) { const name = target.startsWith("read.") ? (scenario.kind === "sql" ? "sqlReadRequest" : "kvReadRequest") : target.split(".")[0] ?? ""; const preimage = record(record(scenario.preimages, "preimages")[name], name); const body = clone(record(preimage.body, `${name}.body`)); const field = target.startsWith("read.") ? target.slice(5) : target.slice(name.length + 1); mutatePath(body, field, operation, data.value); validateReadBody(body, scenario, id, domains); return; }
    if (target.startsWith("nonce.")) { validateTransition(states, string(data.from, `${id}.from`), string(data.to, `${id}.to`)); return; }
    if (target === "scanner.fragment") { validateScannerUrl(data.value, scenario, `${id}.scanner.fragment`); return; }
    if (operation === "consume-on-GET") { const before = { state: "ACTIVE", consumed: false }; applyScannerOperation(before, "GET", "consume"); assert(before.consumed === true, "scanner mutation did not attempt consumption"); return; }
    if (target.includes("invitation.version")) { redeemInvitationCandidate({ state: "ACTIVE", activeVersion: 2, secrets: new Map([[2, "new-secret"]]) }, Number(data.value)); return; }
    if (target.includes("otp.")) { submitCorrectOtpCandidate({ state: "LOCKED", attempts: Number(data.value), threshold: 5 }); return; }
    throw new Error(`${id}: unsupported serialized mutation target ${target}`);
  }));
}

function executeNegative(row: Obj, scenario: Obj, domains: Obj, states: Obj, schemas: Obj): void {
  const id = string(row.id, "negative.id"); const data = record(row.mutationData, `${id}.mutationData`); const artifacts = list(scenario.artifacts, "artifacts") as Obj[];
  const values = data.valueByKind === undefined ? undefined : record(data.valueByKind, `${id}.valueByKind`); const mutationValue = values?.[string(scenario.kind, `${id}.scenarioKind`)] ?? data.value;
  const expectReject = (label: string, operation: () => void): void => { assert(label === id, `${id}: negative label`); expectStageReject(row, () => fixedStageBoundary("contract-validation", operation)); };
  switch (id) {
    case "leading-space": case "trailing-space": case "tab": case "newline": case "inner-space": case "leading-dot-local": case "trailing-dot-local": case "repeated-dot-local": case "empty-local": case "empty-domain": case "multiple-at": case "quoted-local": case "comment-local": case "backslash-local": case "angle-form": case "unicode-local": case "unicode-domain": case "local-over-64": case "label-over-63": case "empty-domain-label": case "trailing-domain-dot": case "leading-hyphen": case "trailing-hyphen": case "domain-over-253": case "total-over-254": expectReject(id, () => canonicalEmail(data.input)); break;
    case "policy-cid-is-real": expectReject(id, () => { const target = { ...record(record(scenario.envelope, "envelope").authorizationTarget, "authorizationTarget"), policyBytes: b64(utf8(string(data.replacement, id))) }; validateEnvelopeTarget(target, id); }); break;
    case "policy-bytes-self-policy-cid": expectReject(id, () => { const policy = { ...record(scenario.policy, "policy"), [string(data.property, id)]: data.value }; const target = { ...record(record(scenario.envelope, "envelope").authorizationTarget, "authorizationTarget"), policyBytes: b64(utf8(jcs(policy))) }; validateEnvelopeTarget(target, id); }); break;
    case "share-cid-is-real": case "sealed-blob-aead-tamper": expectReject(id, () => { const blob = strictB64(string(scenario.sealedBlob, "sealedBlob")); const last = blob.length - 1; assert(last >= 0, `${id}: empty blob`); blob[last] = (blob[last] ?? 0) ^ 1; validateCidBytes(scenario.shareCid, blob, id); }); break;
    case "envelope-policy-target-missing-kind": case "envelope-policy-target-missing-bytes": expectReject(id, () => { const target = { ...record(record(scenario.envelope, "envelope").authorizationTarget, "authorizationTarget") }; delete target[id.endsWith("kind") ? "kind" : "policyBytes"]; validateEnvelopeTarget(target, id); }); break;
    case "envelope-policy-target-mismatch": expectReject(id, () => { const mutationTarget = { ...record(record(scenario.envelope, "envelope").authorizationTarget, "authorizationTarget"), policyCid: data.policyCid, policyBytes: data.policyBytes }; validateEnvelopeTarget(mutationTarget, id); }); break;
    case "envelope-origin-mismatch": expectReject(id, () => { const envelope = clone(record(scenario.envelope, "envelope")); const target = record(envelope.target, "target"); target.origin = data.value; crossEquations({ ...scenario, envelope }); }); break;
    case "share-url-userinfo": case "share-url-query": case "share-url-query-missing-fragment": case "share-url-duplicate-k": case "share-url-unknown-fragment": case "share-url-noncanonical-k": case "share-url-wrong-origin": case "share-url-wrong-path": case "share-url-http-scheme": case "share-url-explicit-port": case "share-url-percent-encoded-fragment": expectReject(id, () => validateShareUrl(mutationValue, scenario, id)); break;
    case "document-name-over-200-utf8": expectStageReject(row, () => { const candidates = record(data.candidateArtifactByKind, `${id}.candidateArtifactByKind`); const candidate = record(candidates[string(scenario.kind, `${id}.scenarioKind`)], `${id}.candidateArtifact`); assert(candidate.name === "inviteAuthorization", `${id}: artifact role`); validateSignedArtifact(candidate, scenario, domains); const authorization = record(candidate.message, `${id}.message`); const documentName = string(authorization.documentName, `${id}.documentName`); if (utf8(documentName).length > 200) throw new StageError("document-name-bytes", `${id}: documentName byte boundary`); fixedStageBoundary("contract-validation", () => validateContractSchema(authorization, "inviteAuthorization", schemas, id)); }); break;
    case "authorization-recipient-email-mismatch": expectReject(id, () => { const altered = replaceArtifact(scenario, "inviteAuthorization", "recipientEmail", data.value, domains); validateArtifactEncoding(record((list(altered.artifacts, "artifacts") as Obj[]).find((item) => item.name === "inviteAuthorization"), "altered authorization"), domains, scenario); crossEquations(altered); }); break;
    case "redeem-redemption-id-mismatch": case "redeem-invitation-id-mismatch": expectReject(id, () => { const altered = replaceArtifact(scenario, "holderBinding", id.includes("redemption") ? "redemptionId" : "invitationId", data.value, domains); const binding = record((list(altered.artifacts, "artifacts") as Obj[]).find((item) => item.name === "holderBinding"), "altered holder binding"); validateArtifactEncoding(binding, domains, scenario); crossEquations(altered); }); break;
    case "share-id-propagation": case "share-cid-propagation": case "policy-cid-propagation": case "target-origin-propagation": case "node-audience-propagation": case "holder-did-propagation": case "content-source-digest-propagation": case "action-propagation": case "resource-propagation": { const field: Record<string, string> = { "share-id-propagation": "shareId", "share-cid-propagation": "shareCid", "policy-cid-propagation": "policyCid", "target-origin-propagation": "targetOrigin", "node-audience-propagation": "nodeAudience", "holder-did-propagation": "holderDid", "content-source-digest-propagation": "contentSourceDigest", "action-propagation": "action", "resource-propagation": "resource" }; const mutationField = string(field[id], `${id}.field`); const values = data.valueByKind === undefined ? undefined : record(data.valueByKind, id); const value = values?.[String(scenario.kind)] ?? data.value; expectReject(id, () => { const altered = replaceArtifact(scenario, "policyPresentation", mutationField, value, domains); const presentation = record((list(altered.artifacts, "artifacts") as Obj[]).find((item) => item.name === "policyPresentation"), "altered presentation"); validateArtifactEncoding(presentation, domains, scenario); crossEquations(altered); }); break; }
    case "envelope-domain-from-unregistered-label": expectReject(id, () => { const registry = record(record(domains, "domains").domains, "domains"); assert(string(data.value, id) === string(registry.envelope, "envelope domain"), "unregistered envelope domain"); }); break;
    case "jcs-lone-surrogate": expectReject(id, () => jcs(JSON.parse(string(data.jsonLiteral, id)))); break;
    case "jcs-unsafe-number": case "jcs-fractional-number": case "jcs-negative-zero": expectReject(id, () => { const literal = string(data.jsonLiteral, id); const candidate = literal === "-0" ? -0 : JSON.parse(literal) as unknown; jcs(candidate); }); break;
    case "jcs-undefined": expectReject(id, () => jcs(undefined)); break;
    case "noncanonical-b64url-16-tail": case "noncanonical-b64url-64-tail": expectReject(id, () => validateFixedB64(data.value, id.includes("16") ? 16 : 64, id)); break;
    case "noncanonical-holder-kid": expectReject(id, () => { const holder = record((artifacts.find((item) => item.name === "holderBinding")), "holderBinding"); const signature = record(holder.signature, "holderBinding.signature"); const candidate = { ...signature, kid: data.value }; validateProof(candidate, id, `${string(record(holder.message, "holderBinding.message").holderDid, "holderDid")}#${string(record(holder.message, "holderBinding.message").holderDid, "holderDid").slice("did:key:".length)}`); }); break;
    case "small-order-did-key": expectReject(id, () => { const holder = record((artifacts.find((item) => item.name === "holderBinding")), "holderBinding"); validateDidKey(data.value, id); validateArtifactEncoding({ ...holder, message: { ...record(holder.message, "holderBinding.message"), holderDid: data.value } }, domains, scenario); }); break;
    case "noncanonical-ed25519-s": expectReject(id, () => { const holder = record(artifacts.find((item) => item.name === "holderBinding"), "holderBinding"); const message = record(holder.message, "holderBinding.message"); verifyEd25519(data.value, message.holderDid, string(record(domains.domains, "domains").holderBinding, "holderBinding.domain"), message, id); }); break;
    case "short-signature": expectReject(id, () => { const read = record((artifacts.find((item) => item.name === "readInvocation")), "readInvocation"); const signature = record(read.signature, "readInvocation.signature"); validateEd25519Signature(b64(validateFixedB64(signature.value, 64, id).slice(0, Number(data.bytes))), id); }); break;
    case "wrong-source-digest": expectReject(id, () => { const preimage = record(record(scenario.preimages, "preimages").sqlReadRequest, "sqlReadRequest"); const body = clone(record(preimage.body, "sqlReadRequest.body")); const source = record(body.contentSource, "sqlReadRequest.contentSource"); const args = { ...record(source.arguments, "sqlReadRequest.arguments"), document_id: data.value }; source.arguments = args; validateSource(source, scenario, id, domains); }); break;
    case "sql-arguments-too-large": expectReject(id, () => { const preimage = record(record(scenario.preimages, "preimages").sqlReadRequest, "sqlReadRequest"); const body = clone(record(preimage.body, "sqlReadRequest.body")); const source = record(body.contentSource, "sqlReadRequest.contentSource"); const field = string(data.field, id); source.arguments = field === "arguments" && data.value !== undefined ? data.value : { ...record(source.arguments, "sqlReadRequest.arguments"), [field.split(".").at(-1) ?? field]: data.value }; validateSource(source, scenario, id, domains); }); break;
    case "sql-string-argument": case "sql-fractional-argument": case "sql-negative-zero-argument": expectReject(id, () => {
      const preimage = record(record(scenario.preimages, "preimages").sqlReadRequest, "sqlReadRequest"); const body = clone(record(preimage.body, "sqlReadRequest.body")); const source = record(body.contentSource, "sqlReadRequest.contentSource"); const field = data.field === undefined ? undefined : (string(data.field, id).split(".").at(-1) ?? string(data.field, id)); const rawValue = data.value === undefined ? data.argument : data.value; const value = data.jsonLiteral === "-0" || data.valueType === "negative-zero" ? -0 : rawValue;
      if (field === undefined && (typeof value === "string" || typeof value === "number")) source.arguments = value;
      else { const args = { ...record(source.arguments, "sqlReadRequest.arguments") }; const argumentField = string(field, `${id}.field`); assert(value !== undefined, `${id}: SQL argument mutation`); args[argumentField] = value; source.arguments = args; }
      validateSource(source, scenario, id, domains);
    }); break;
    case "sql-arbitrary-query-field": expectReject(id, () => { const preimage = record(record(scenario.preimages, "preimages").sqlReadRequest, "sqlReadRequest"); const body = { ...clone(record(preimage.body, "sqlReadRequest.body")), [string(data.field, id)]: data.value }; validateReadBody(body, scenario, id, domains); }); break;
    case "policy-action-source-mismatch": expectReject(id, () => { const values = record(data.valueByKind, id); const policy = clone(record(scenario.policy, "policy")); policy.action = values[String(scenario.kind)]; const source = record(policy.contentSource, "policy.contentSource"); assert(policy.action === source.action && policy.action === record(scenario.source, "source").action, `${id}: action/source equation`); }); break;
    case "content-source-propagation": expectReject(id, () => { const altered = replaceArtifact(scenario, "policyPresentation", "contentSource", { ...record(scenario.source, "source"), path: data.value }, domains); const presentation = record((list(altered.artifacts, "artifacts") as Obj[]).find((item) => item.name === "policyPresentation"), "altered presentation"); validateArtifactEncoding(presentation, domains, scenario); crossEquations(altered); }); break;
    case "credential-sub-mismatch": expectReject(id, () => { const credential = clone(record(scenario.credential, "credential")); const claims = record(credential.claims, "credential.claims"); claims.sub = data.value; validateCredentialProfile(credential, scenario, id, domains); }); break;
    case "credential-legacy-email-path": expectReject(id, () => { const credential = clone(record(scenario.credential, "credential")); const disclosure = record(list(credential.disclosures, "credential.disclosures")[0], "credential.disclosure"); disclosure.path = data.value; validateCredentialProfile(credential, scenario, id, domains); }); break;
    case "credential-unsupported-status": expectReject(id, () => { const credential = clone(record(scenario.credential, "credential")); const claims = record(credential.claims, "credential.claims"); claims.status = data.value; validateCredentialProfile(credential, scenario, id, domains); }); break;
    case "credential-expired-resigned": case "credential-expiry-boundary-resigned": case "credential-issuer-did-resigned": case "credential-issuer-key-resigned": case "credential-vct-resigned": case "credential-holder-resigned": case "credential-scope-resigned": expectReject(id, () => { const candidates = record(data.credentialByKind, `${id}.credentialByKind`); const candidate = record(candidates[string(scenario.kind, `${id}.kind`)], `${id}.credential`); const candidateKeys = data.candidateSigningPublicKeyByKind === undefined ? undefined : record(data.candidateSigningPublicKeyByKind, `${id}.candidateSigningPublicKeyByKind`); const candidateKey = candidateKeys?.[string(scenario.kind, `${id}.kind`)]; if (candidateKey !== undefined) candidate.issuerSigningKey = candidateKey; validateCredentialProfile(candidate, scenario, id, domains); }); break;
    case "different-holder-valid-signature": expectReject(id, () => { const candidate = record(data.candidateArtifact, `${id}.candidateArtifact`); validateSignedArtifact(candidate, scenario, domains, schemas); const altered = clone(scenario); const alteredArtifacts = list(altered.artifacts, `${id}.artifacts`) as Obj[]; const index = alteredArtifacts.findIndex((item) => item.name === "holderBinding"); assert(index >= 0, `${id}: holder binding artifact`); alteredArtifacts[index] = candidate; try { crossEquations(altered); } catch (error) { throw new StageError("cross-artifact-holder", `${id}: holder artifact is not bound to the other artifacts`, error); } throw new StageError("cross-artifact-holder", `${id}: holder artifact unexpectedly matched`); }); break;
    case "policy-challenge-replay": expectReject(id, () => validateTransition(states, string(data.from, id), string(data.to, id))); break;
    case "session-token-only": expectReject(id, () => { const name = scenario.kind === "sql" ? "sqlReadRequest" : "kvReadRequest"; const body = clone(record(record(record(scenario.preimages, "preimages")[name], name).body, `${name}.body`)); delete body.proof; validateReadBody(body, scenario, id, domains); }); break;
    case "old-secret-after-resend": expectReject(id, () => redeemInvitationCandidate({ state: "ACTIVE", activeVersion: 2, secrets: new Map([[2, "new-secret"]]) }, Number(data.value))); break;
    case "otp-after-five-wrong": expectReject(id, () => { const row = (list(states.operationProgram, "states.operationProgram") as Obj[]).find((candidate) => candidate.id === "otp-wrong-vs-invalid-magic"); if (!row) throw new Error(`${id}: OTP command`); const command = record(list(row.commands, `${id}.commands`)[0], `${id}.command`); const operands = record(command.operands, `${id}.operands`); submitCorrectOtpCandidate({ state: "LOCKED", attempts: Number(data.value), threshold: Number(operands.lockAt) }); }); break;
    case "scanner-get": expectReject(id, () => {
      validateScannerUrl(mutationValue, scenario, id);
      const candidate = { state: "ACTIVE", consumed: false }; applyScannerOperation(candidate, "GET", "consume");
    }); break;
    case "scanner-fragment-percent-encoded": expectStageReject(row, () => validateScannerUrl(mutationValue, scenario, id)); break;
    case "resend-recipient-supplied-email": expectReject(id, () => { const original = record(record(record(scenario.preimages, "preimages").resendRequest, "resendRequest").body, "resendRequest.body"); const body = { ...original, [string(data.field, id)]: data.value }; assert(Object.keys(body).length === 2 && Object.keys(body).every((key) => key === "invitationId" || key === "claimSecret"), `${id}: strict resend shape`); }); break;
    case "capability-extra-route": case "capability-wildcard-origin": expectReject(id, () => { const capabilities = record(record(domains, "domains").capabilities, "capabilities"); const original = record(capabilities.witness, "witness capability"); const candidate = clone(original); if (id === "capability-extra-route") candidate.routes = [...list(original.routes, "witness.routes"), data.value]; else candidate.origin = data.value; validateCapability(candidate, original, id); }); break;
    case "read-body-one-field-mutation": expectReject(id, () => { const preimage = record(record(scenario.preimages, "preimages").sqlReadRequest, "sqlReadRequest"); const body = { ...clone(record(preimage.body, "sqlReadRequest.body")), resource: data.value }; validateReadBody(body, scenario, id); assert(string(preimage.digest, `${id}.digest`) === digest(utf8(jcs(body))), `${id}: request body digest`); }); break;
    case "claim-redeem-magic-with-otp": expectReject(id, () => { const source = record(record(record(scenario.preimages, "preimages").claimRedeemRequest, "claimRedeemRequest").body, "claimRedeemRequest.body"); const body = clone(source); body.mailboxProof = data.value; validateRedeemBody(body, scenario, id); }); break;
    case "claim-redeem-otp-with-magic": expectReject(id, () => { const source = record(record(record(scenario.preimages, "preimages").claimRedeemOtpRequest, "claimRedeemOtpRequest").body, "claimRedeemOtpRequest.body"); const body = clone(source); body.mailboxProof = data.value; validateRedeemBody(body, scenario, id); }); break;
    case "policy-challenge-response-proof": case "policy-session-response-proof": expectReject(id, () => validateResponseProof(scenario, data, id.startsWith("policy-challenge") ? "policyChallengeResponse" : "policySessionResponse")); break;
    case "sd-jwt-missing-alg": expectReject(id, () => { const credential = clone(record(scenario.credential, "credential")); const claims = record(credential.claims, "credential.claims"); delete claims._sd_alg; validateCredentialProfile(credential, scenario, id, domains); }); break;
    case "sd-jwt-two-element-disclosure": expectReject(id, () => { const credential = clone(record(scenario.credential, "credential")); const disclosure = record(list(credential.disclosures, `${id}.disclosures`)[0], `${id}.disclosure`); const encoded = b64(utf8(jcs(list(data.arrayShape, id)))); disclosure.encoded = encoded; const compact = string(credential.credential, `${id}.credential`).split("~"); assert(compact.length === 3, `${id}: compact credential shape`); compact[1] = encoded; credential.credential = compact.join("~"); validateCredentialProfile(credential, scenario, id, domains); }); break;
    case "node-enrollment-disabled": case "node-enrollment-origin-audience": case "node-enrollment-audience-origin": case "node-enrollment-retired-key": case "node-enrollment-kid-version-mismatch": expectReject(id, () => { const altered = clone(scenario); altered.enrollment = data.enrollment; validateEnrollment(altered, domains, schemas); }); break;
    default: executeSerializedNegative(row, scenario, domains, states, schemas);
  }
}

function validateNegativeNative(positive: Obj, negative: Obj, domains: Obj, states: Obj, schemas: Obj): void {
  const rows = list(negative.cases, "negative.cases").map((value) => record(value, "negative row")); const seen = new Set<string>(); const stages = new Set<RejectionStage>(["contract-validation", "credential-holder", "credential-scope", "credential-time", "credential-vct", "cross-artifact-holder", "document-name-bytes", "issuer-key", "issuer-trust", "node-authority", "node-enrollment", "node-key-retirement", "node-key-rotation", "scanner-fragment-encoding", "share-url-fragment", "share-url-fragment-encoding", "share-url-key", "share-url-origin", "share-url-path", "share-url-port", "share-url-query", "share-url-scheme", "signature-encoding"]); for (const row of rows) { const id = string(row.id, "negative.id"); assert(!seen.has(id), `duplicate negative ${id}`); seen.add(id); assert(row.expected === "reject", `${id}: expected reject marker`); if (row.rejectionStage !== undefined && row.rejectionStage !== null) assert(stages.has(string(row.rejectionStage, `${id}.rejectionStage`) as RejectionStage), `${id}: unknown rejection stage`); assert(!JSON.stringify(row).includes("scenario."), `${id}: symbolic placeholder`); const applies = list(row.appliesTo, `${id}.appliesTo`); assert(applies.length > 0, `${id}: appliesTo`); for (const scenarioValue of list(positive.scenarios, "positive.scenarios")) { const scenario = record(scenarioValue, "scenario"); if (applies.includes(scenario.kind)) executeNegative(row, scenario, domains, states, schemas); } }
}
function validatePositiveScenario(scenario: Obj, domains: Obj, schemas: Obj): void {
  const kind = string(scenario.kind, "scenario.kind"); assert(kind === "kv" || kind === "sql", "scenario kind"); assert(scenario.testOnly === true, "scenario test marker"); validateEnrollment(scenario, domains, schemas); validateAuthorityMaterial(scenario, domains); validateContractSchema(scenario.authorityMaterial, "authorityMaterial", schemas, `${kind}.authorityMaterial`); validateContractSchema(scenario.source, kind === "kv" ? "sourceKv" : "sourceSql", schemas, `${kind}.source`); validateContractSchema(scenario.policy, "policy", schemas, `${kind}.policy`); validateContractSchema(scenario.envelope, "envelopeSigned", schemas, `${kind}.envelope`); validateContractSchema(scenario.authorization, "inviteAuthorization", schemas, `${kind}.authorization`); validateContractSchema(scenario.credential, "credential", schemas, `${kind}.credential`);
  const artifacts = list(scenario.artifacts, "artifacts") as Obj[]; assert(artifacts.length === 9 && new Set(artifacts.map((artifact) => string(artifact.name, "artifact.name"))).size === artifacts.length, `${kind}: artifact set`); for (const artifact of artifacts) validateSignedArtifact(artifact, scenario, domains, schemas); validateSignedBytePreimages(scenario, domains);
  const policyArtifact = artifacts.find((artifact) => artifact.name === "policy"); const envelopeArtifact = artifacts.find((artifact) => artifact.name === "envelope"); if (policyArtifact === undefined || envelopeArtifact === undefined) throw new Error(`${kind}: policy/envelope artifacts`); sameJson(policyArtifact.message, scenario.policy, `${kind}: policy artifact`); const envelopeMessage = clone(record(scenario.envelope, "envelope")); delete envelopeMessage.signature; sameJson(envelopeArtifact.message, envelopeMessage, `${kind}: envelope artifact`);
  const envelope = record(scenario.envelope, "envelope"); const envelopeSignature = record(envelope.signature, "envelope.signature"); const artifactSignature = record(envelopeArtifact.signature, "envelope artifact signature"); assert(envelopeSignature.value === artifactSignature.value && envelopeSignature.signerDid === envelopeArtifact.signerDid, `${kind}: envelope signature binding`); validatePolicyBytes(record(envelope.authorizationTarget, "authorizationTarget"), `${kind}.authorizationTarget`); validateCidBytes(scenario.shareCid, strictB64(string(scenario.sealedBlob, `${kind}.sealedBlob`)), `${kind}.sealedBlob`); assert(scenario.policyBytes === b64(utf8(jcs(scenario.policy))), `${kind}: policy bytes`); assert(digest(utf8(jcs(scenario.source))) === scenario.sourceDigest, `${kind}: source digest`); validateCredentialProfile(record(scenario.credential, `${kind}.credential`), scenario, `${kind}.credential`, domains, schemas); validateEndpoints(scenario, domains, schemas); crossEquations(scenario);
}

/** Loads, verifies, and natively executes the complete language-neutral matrix. */
export async function loadFixtureBundle(baseDir = dirname(fileURLToPath(import.meta.url))): Promise<FixtureBundle> {
  const manifest = await readJson<FixtureManifest>(resolve(baseDir, "manifest.json")); const { manifestDigest: _ignored, ...manifestCore } = manifest; assert(manifest.manifestDigest === digest(utf8(jcs(manifestCore))), "manifest digest mismatch"); const specDir = resolve(baseDir, "../../../specs/email-claim-v1"); for (const [name, expected] of Object.entries(manifest.files)) { const path = name === "README.md" || name === "domains.json" || name === "schemas.json" || name === "authority-material.schema.json" ? resolve(specDir, name) : resolve(baseDir, name); assert(digest(await readFile(path)) === expected, `manifest file mismatch: ${name}`); }
  const positive = await readJson(resolve(baseDir, "positive.json")); const negative = await readJson(resolve(baseDir, "negative.json")); const states = await readJson(resolve(baseDir, "states.json")); const domains = await readJson(resolve(specDir, "domains.json")); const schemas = await readJson(resolve(specDir, "schemas.json")); const positiveObject = record(positive, "positive"); const stateObject = record(states, "states"); const domainObject = record(domains, "domains"); const schemaObject = record(schemas, "schemas"); const scenarios = list(positiveObject.scenarios, "positive.scenarios").map((value) => record(value, "scenario")); assert(scenarios.length === 2, "positive scenario count"); for (const scenario of scenarios) validatePositiveScenario(scenario, domainObject, schemaObject); validateRecovery(stateObject); validateStateInterpreter(stateObject); validateNegativeNative(positiveObject, record(negative, "negative"), domainObject, stateObject, schemaObject); return { manifest, positive, negative, states, domains, schemas };
}

async function readJson<T>(path: string): Promise<T> { return JSON.parse(await readFile(path, "utf8")) as T; }

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) loadFixtureBundle().then(({ manifest, negative }) => console.log(`email-claim-v1 loader: ${manifest.manifestDigest} (${list(record(negative, "negative").cases, "cases").length} native negative rows)`)).catch((error: unknown) => { console.error(error instanceof Error ? error.message : error); process.exitCode = 1; });

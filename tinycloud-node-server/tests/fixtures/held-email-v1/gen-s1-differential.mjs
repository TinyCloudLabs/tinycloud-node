// Generator for s1-differential.json. Usage:
//   TS_VERIFIER=<sdk-core dist/held-credentials/index.js> VIEM_ROOT=<dir with node_modules/viem> \
//   OUT=<cases.json path> node gen-s1-differential.mjs
// See s1-differential.provenance.json for the pinned verifier and output hashes.
import { createHash, createPrivateKey, createPublicKey, sign as edSign } from "node:crypto";
import { createRequire } from "node:module";
import { readFileSync, writeFileSync } from "node:fs";

const require = createRequire(process.env.VIEM_ROOT ?? `${process.cwd()}/`);
const { privateKeyToAccount } = require("viem/accounts");
const { getAddress } = require("viem");
const TS = await import(process.env.TS_VERIFIER ?? "@tinycloud/sdk-core/dist/held-credentials/index.js");
const { parseIssuerSet, verifyHeldPresentation, InMemoryNonceStore } = TS;

const AUDIENCE = "verifier.example";
const CALLER = "did:pkh:eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const OTHER = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
const HOLDER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const ANVIL_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ISSUER = "did:web:issuer.credentials.org";
const KID = "did:web:issuer.credentials.org#k1";
const PROFILE = "tinycloud.email-held/v1";
const VCT = "opencredentials.email/v1";
const BINDING = "tinycloud.credentials/account-binding/v1";
const DAY = 86400;
const IAT = 1767225600;
const NOW = "2026-01-01T01:00:00Z";
const ISSUED_AT = "2026-01-01T00:59:00Z";
const NONCE_OK = "heldtestnonce0000000001";

const seed = Buffer.from(Array.from({ length: 32 }, (_, i) => (i * 37 + 11) & 0xff));
const priv = createPrivateKey({
  key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
  format: "der",
  type: "pkcs8",
});
const pubX = createPublicKey(priv).export({ format: "jwk" }).x;
const account = privateKeyToAccount(ANVIL_KEY);

const b64 = (s) => Buffer.from(s).toString("base64url");
const sha = (s) => createHash("sha256").update(s).digest("base64url");
const disc = (salt, name, value) => b64(JSON.stringify([salt, name, value]));
const digest = (d) => sha(Buffer.from(d, "ascii"));
const edSignB64 = (input) => edSign(null, Buffer.from(input, "ascii"), priv).toString("base64url");

const EMAIL_D = disc("salt-email", "email", "alice@example.com");
const DOMAIN_D = disc("salt-domain", "emailDomain", "example.com");

const issuerConfig = (over = {}) => ({
  issuerDid: ISSUER,
  kid: KID,
  alg: "EdDSA",
  publicKey: pubX,
  vcts: [VCT],
  profiles: [PROFILE],
  notBefore: "2025-01-01T00:00:00Z",
  retiredAt: null,
  notAfter: null,
  ...over,
});

const basePayload = (disclosures) => ({
  iss: ISSUER,
  sub: CALLER,
  iat: IAT,
  nbf: IAT,
  exp: IAT + 30 * DAY,
  jti: "urn:uuid:0b6d2c4e-8a1f-4d3e-9b7a-1c2d3e4f5a6b",
  vct: VCT,
  profile: PROFILE,
  profileVersion: 1,
  holderBinding: { did: CALLER, signingDomain: BINDING },
  status: { method: "none" },
  _sd_alg: "sha-256",
  _sd: disclosures.map(digest),
});

const baseHeader = { alg: "EdDSA", typ: "vc+sd-jwt", kid: KID };

// header/payload: object (JSON-stringified) or raw string. sig: "valid" | raw string.
function jwt({ header = baseHeader, payload, disclosures = [EMAIL_D, DOMAIN_D], sig = "valid", raw }) {
  if (raw !== undefined) return raw;
  const hs = typeof header === "string" ? header : JSON.stringify(header);
  const ps = typeof payload === "string" ? payload : JSON.stringify(payload ?? basePayload([EMAIL_D, DOMAIN_D]));
  const input = `${b64(hs)}.${b64(ps)}`;
  const s = sig === "valid" ? edSignB64(input) : sig;
  return [`${input}.${s}`, ...disclosures, ""].join("~");
}

function siweMessage(f) {
  const lines = [
    `${f.domain ?? AUDIENCE} wants you to sign in with your Ethereum account:`,
    f.address ?? HOLDER,
    "",
    f.statement ?? "Present a TinyCloud held credential",
    "",
    `URI: ${f.uri ?? `https://${AUDIENCE}`}`,
    `Version: ${f.version ?? "1"}`,
    `Chain ID: ${f.chainId ?? "1"}`,
    `Nonce: ${f.nonce}`,
    `Issued At: ${ISSUED_AT}`,
  ];
  if (f.expirationTime) lines.push(`Expiration Time: ${f.expirationTime}`);
  if (f.notBefore) lines.push(`Not Before: ${f.notBefore}`);
  lines.push("Resources:", ...(f.resources ?? []).map((r) => `- ${r}`));
  return lines.join("\n");
}

async function sign(message) {
  return account.signMessage({ message });
}

const SD_HASH = (sdJwt) => `urn:tinycloud:sd-hash:${sha(Buffer.from(sdJwt, "ascii"))}`;

// Case constructor. `o` may set sdJwt (already built), siwe fields, policy overrides.
const cases = [];
function add(name, o = {}) {
  cases.push({ name, o });
}

// Build a case body, computing TS outcome.
async function build(c) {
  const o = c.o;
  const policy = {
    now: o.now ?? NOW,
    caller: o.caller ?? CALLER,
    audience: o.audience ?? AUDIENCE,
    issuers: o.issuers ?? [issuerConfig()],
    acceptedIssuers: o.acceptedIssuers ?? [{ issuerDid: ISSUER }],
    acceptedProfiles: o.acceptedProfiles ?? [{ id: PROFILE, version: 1 }],
  };
  const sdJwt = o.sdJwt ?? jwt(o.jwt ?? {});
  const nonceBoundTo = o.nonceBoundTo ?? policy.caller;
  const issueNonce = o.nonce ?? undefined;
  const store = new InMemoryNonceStore();
  const nonce = o.noNonce ? (o.nonceValue ?? NONCE_OK) : issueNonce ?? store.issue(AUDIENCE, nonceBoundTo);
  if (!o.noNonce && issueNonce !== undefined) store.nonces.set(`${AUDIENCE}\n${nonce}`, nonceBoundTo);
  const sdHashResource = o.resources ?? [SD_HASH(sdJwt)];
  const message =
    o.message ??
    siweMessage({
      domain: o.domain,
      address: o.address,
      statement: o.statement,
      uri: o.uri,
      version: o.version,
      chainId: o.chainId,
      nonce,
      expirationTime: o.expirationTime,
      notBefore: o.siweNotBefore,
      resources: sdHashResource,
    });
  const signature = o.signature ?? (await sign(message));
  const body = { sdJwt, siwe: { message, signature } };
  return { body, policy, nonce, store, nonces: [...store.nonces.entries()], message, sdJwt, signature };
}

async function tsOutcome(b) {
  let raw;
  try {
    raw = parseIssuerSet({ format: "tinycloud.credentials-issuers/v1", version: 1, issuers: b.policy.issuers }, { didMethods: { issuer: ["web"] } });
  } catch (e) {
    return { code: e.code ?? "bad-issuer-set", detail: String(e.message) };
  }
  try {
    const r = await verifyHeldPresentation(b.body, {
      now: new Date(b.policy.now),
      issuerSet: raw,
      acceptedIssuers: b.policy.acceptedIssuers,
      acceptedProfiles: b.policy.acceptedProfiles.map((p) => ({ profile: p.id, profileVersion: p.version })),
      didMethods: { issuer: ["web"] },
      audience: b.policy.audience,
      nonceStore: b.store,
      callerAccount: b.policy.caller,
    });
    return { code: "ok", subject: r.subject, issuer: r.issuer };
  } catch (e) {
    return { code: e.code ?? "THREW:" + String(e.message), detail: String(e.message) };
  }
}

// ---- mutation catalogue -------------------------------------------------
const P = (mut) => {
  const p = basePayload([EMAIL_D, DOMAIN_D]);
  mut(p);
  return p;
};

add("base-valid");
// presentation shape
add("pres-nonascii-sdjwt", { sdJwt: jwt({}).replace("eyJ", "eyJ\u00e9") });
add("pres-no-trailing-tilde", { sdJwt: jwt({}).slice(0, -1) });
add("pres-zero-disclosures", { sdJwt: jwt({ disclosures: [] }) });
add("pres-empty-disclosure", { sdJwt: jwt({}).replace(`~${EMAIL_D}~`, `~~${EMAIL_D}~`) });
add("pres-extra-tilde-end", { sdJwt: jwt({}) + "~" });
add("pres-sdjwt-with-kbjwt", { sdJwt: jwt({}) + "eyJhbGciOi.kb.sig" });
add("pres-jwt-two-segments", { sdJwt: jwt({ raw: "aGVhZGVy.cGF5bG9hZA~" + EMAIL_D + "~" }) });
add("pres-jwt-empty-sig", { sdJwt: jwt({ sig: "" }) });
add("pres-jwt-four-segments", { sdJwt: jwt({ raw: `${b64(JSON.stringify(baseHeader))}.${b64(JSON.stringify(basePayload([EMAIL_D, DOMAIN_D])))}.x.y~${EMAIL_D}~${DOMAIN_D}~` }) });
add("pres-too-many-disclosures", { sdJwt: jwt({ disclosures: [EMAIL_D, DOMAIN_D, EMAIL_D, DOMAIN_D, EMAIL_D, DOMAIN_D, EMAIL_D, DOMAIN_D, EMAIL_D] }) });
add("pres-long-sdjwt", { sdJwt: jwt({ payload: { ...basePayload([EMAIL_D, DOMAIN_D]), pad: "x".repeat(17000) } }) });

// header
add("hdr-alg-none", { jwt: { header: { ...baseHeader, alg: "none" } } });
add("hdr-typ-wrong", { jwt: { header: { ...baseHeader, typ: "JWT" } } });
add("hdr-extra-member", { jwt: { header: { ...baseHeader, x5c: "a" } } });
add("hdr-no-kid", { jwt: { header: { alg: "EdDSA", typ: "vc+sd-jwt" } } });
add("hdr-kid-no-hash", { jwt: { header: { ...baseHeader, kid: ISSUER } } });
add("hdr-kid-hash-first", { jwt: { header: { ...baseHeader, kid: "#k1" } } });
add("hdr-kid-bad-char", { jwt: { header: { ...baseHeader, kid: `${ISSUER}#k 1` } } });
add("hdr-kid-empty-frag", { jwt: { header: { ...baseHeader, kid: `${ISSUER}#` } } });
add("hdr-kid-number", { jwt: { header: { ...baseHeader, kid: 7 } } });
add("hdr-kid-pkh", { jwt: { header: { ...baseHeader, kid: "did:pkh:eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266#k1" } } });
add("hdr-kid-did-method-uppercase", { jwt: { header: { ...baseHeader, kid: "did:WEB:issuer.credentials.org#k1" } } });
add("hdr-kid-empty-did-id", { jwt: { header: { ...baseHeader, kid: "did:web:#k1" } } });
add("hdr-kid-no-method", { jwt: { header: { ...baseHeader, kid: "issuer.credentials.org#k1" } } });
add("hdr-array", { jwt: { header: "[1,2]" } });
add("hdr-dup-key", { jwt: { header: '{"alg":"EdDSA","alg":"EdDSA","typ":"vc+sd-jwt","kid":"' + KID + '"}' } });
add("hdr-not-json", { jwt: { header: "not json" } });

// signature
add("sig-flipped", { jwt: { sig: (() => { const s = edSignB64(`${b64(JSON.stringify(baseHeader))}.${b64(JSON.stringify(basePayload([EMAIL_D, DOMAIN_D])))}`); return s.slice(0, -2) + (s.at(-2) === "A" ? "B" : "A") + s.at(-1); })() } });
add("sig-short", { jwt: { sig: "AAAA" } });
add("sig-nonb64", { jwt: { sig: "@@@@" } });
add("sig-padded", { jwt: { sig: edSignB64("x") + "==" } });

// payload
add("pl-iss-mismatch", { jwt: { payload: P((p) => (p.iss = "did:web:other.example")) } });
add("pl-iat-missing", { jwt: { payload: P((p) => delete p.iat) } });
add("pl-iat-float", { jwt: { payload: P((p) => { p.iat = IAT + 0.5; p.nbf = IAT + 0.5; }) } });
add("pl-iat-string", { jwt: { payload: P((p) => { p.iat = String(IAT); p.nbf = String(IAT); }) } });
add("pl-nbf-ne-iat", { jwt: { payload: P((p) => (p.nbf = IAT + 1)) } });
add("pl-exp-missing", { jwt: { payload: P((p) => delete p.exp) } });
add("pl-iat-huge-safe", { jwt: { payload: P((p) => { p.iat = 9007199254740991; p.nbf = p.iat; p.exp = p.iat + 1; }) } });
add("pl-iat-year-10000", { jwt: { payload: P((p) => { p.iat = 253402300800; p.nbf = p.iat; p.exp = p.iat + 60; }) } });
add("pl-iat-negative", { jwt: { payload: P((p) => { p.iat = -1; p.nbf = -1; p.exp = 60; }) } });
add("pl-not-yet-valid", { jwt: { payload: P((p) => { p.iat = IAT + 7200; p.nbf = p.iat; p.exp = p.iat + DAY; }) } });
add("pl-expired", { jwt: { payload: P((p) => { p.iat = IAT - 90 * DAY; p.nbf = p.iat; p.exp = IAT - 60 * DAY; }) } });
add("pl-exp-eq-iat", { jwt: { payload: P((p) => (p.exp = IAT)) } });
add("pl-lifetime-over-365d", { jwt: { payload: P((p) => (p.exp = IAT + 366 * DAY)) } });
add("pl-lifetime-exactly-365d", { jwt: { payload: P((p) => (p.exp = IAT + 365 * DAY)) } });
add("pl-profile-missing", { jwt: { payload: P((p) => delete p.profile) } });
add("pl-profile-other", { jwt: { payload: P((p) => (p.profile = "tinycloud.other/v1")) } });
add("pl-profile-version-2", { jwt: { payload: P((p) => (p.profileVersion = 2)) } });
add("pl-profile-version-string", { jwt: { payload: P((p) => (p.profileVersion = "1")) } });
add("pl-vct-other", { jwt: { payload: P((p) => (p.vct = "opencredentials.other/v1")) } });
add("pl-vct-missing", { jwt: { payload: P((p) => delete p.vct) } });
add("pl-extra-claim", { jwt: { payload: P((p) => (p.extra = "x")) } });
add("pl-sd-alg-wrong", { jwt: { payload: P((p) => (p._sd_alg = "sha-512")) } });
add("pl-sd-not-array", { jwt: { payload: P((p) => (p._sd = "x")) } });
add("pl-sd-nonstring", { jwt: { payload: P((p) => (p._sd = [digest(EMAIL_D), 3])) } });
add("pl-sd-duplicate", { jwt: { payload: P((p) => (p._sd = [digest(EMAIL_D), digest(EMAIL_D)])) } });
add("pl-jti-not-uuid", { jwt: { payload: P((p) => (p.jti = "urn:uuid:abc")) } });
add("pl-jti-v1", { jwt: { payload: P((p) => (p.jti = "urn:uuid:0b6d2c4e-8a1f-1d3e-9b7a-1c2d3e4f5a6b")) } });
add("pl-jti-not-urn", { jwt: { payload: P((p) => (p.jti = "0b6d2c4e-8a1f-4d3e-9b7a-1c2d3e4f5a6b")) } });
add("pl-status-other", { jwt: { payload: P((p) => (p.status = { method: "bitstring" })) } });
add("pl-status-extra", { jwt: { payload: P((p) => (p.status = { method: "none", idx: 1 })) } });
add("pl-status-missing", { jwt: { payload: P((p) => delete p.status) } });
add("pl-sub-not-pkh", { jwt: { payload: P((p) => (p.sub = "mailto:alice@example.com")) } });
add("pl-sub-other-chain", { jwt: { payload: P((p) => { p.sub = CALLER.replace("eip155:1:", "eip155:10:"); p.holderBinding.did = p.sub; }) } });
add("pl-sub-missing", { jwt: { payload: P((p) => delete p.sub) } });
add("pl-binding-extra", { jwt: { payload: P((p) => (p.holderBinding.x = 1)) } });
add("pl-binding-domain", { jwt: { payload: P((p) => (p.holderBinding.signingDomain = "other/v1")) } });
add("pl-binding-did-mismatch", { jwt: { payload: P((p) => (p.holderBinding.did = OTHER)) } });
add("pl-binding-missing", { jwt: { payload: P((p) => delete p.holderBinding) } });
add("pl-payload-array", { jwt: { payload: "[]" } });
add("pl-payload-dup-key", { jwt: { payload: `{"iss":"${ISSUER}","iss":"${ISSUER}"}` } });

// disclosures
const withDisc = (ds) => ({ jwt: { disclosures: ds, payload: basePayload(ds) } });
add("disc-digest-not-in-sd", { jwt: { disclosures: [disc("other", "email", "alice@example.com"), DOMAIN_D] } });
add("disc-repeated", { jwt: { disclosures: [EMAIL_D, EMAIL_D], payload: { ...basePayload([EMAIL_D]), _sd: [digest(EMAIL_D)] } } });
add("disc-not-base64", { jwt: { disclosures: ["@@@", DOMAIN_D] } });
add("disc-not-array", { jwt: { disclosures: [b64(JSON.stringify({ a: 1 })), DOMAIN_D] } });
add("disc-len-2", withDisc([b64(JSON.stringify(["s", "email"])), DOMAIN_D]));
add("disc-name-number", withDisc([b64(JSON.stringify(["s", 1, "x"])), DOMAIN_D]));
add("disc-salt-number", withDisc([b64(JSON.stringify([1, "email", "alice@example.com"])), DOMAIN_D]));
add("disc-value-number", withDisc([b64(JSON.stringify(["s", "email", 1])), DOMAIN_D]));
add("disc-value-array", withDisc([b64(JSON.stringify(["s", "email", ["a"]])), DOMAIN_D]));
add("disc-name-reserved-iss", withDisc([b64(JSON.stringify(["s", "iss", "x"])), DOMAIN_D]));
add("disc-name-signed-optional", withDisc([b64(JSON.stringify(["s", "vct", "x"])), DOMAIN_D]));
add("disc-name-not-disclosable", withDisc([disc("s", "nickname", "x"), DOMAIN_D]));
add("disc-claim-twice", { jwt: { disclosures: [EMAIL_D, disc("salt-email-2", "email", "bob@example.com"), DOMAIN_D], payload: basePayload([EMAIL_D, disc("salt-email-2", "email", "bob@example.com"), DOMAIN_D]) } });
add("disc-missing-domain", { jwt: { disclosures: [EMAIL_D], payload: basePayload([EMAIL_D]) } });
add("disc-missing-email", { jwt: { disclosures: [DOMAIN_D], payload: basePayload([DOMAIN_D]) } });
add("disc-domain-mismatch", withDisc([EMAIL_D, disc("salt-domain", "emailDomain", "other.com")]));
add("disc-email-invalid", withDisc([disc("salt-email", "email", "not-an-email"), DOMAIN_D]));
add("disc-email-uppercase", withDisc([disc("salt-email", "email", "Alice@Example.com"), DOMAIN_D]));
add("disc-email-unicode", withDisc([disc("salt-email", "email", "älice@example.com"), DOMAIN_D]));
add("disc-email-empty", withDisc([disc("salt-email", "email", ""), DOMAIN_D]));
add("disc-empty-salt", withDisc([disc("", "email", "alice@example.com"), DOMAIN_D]));
add("disc-no-disclosures-at-all", { jwt: { disclosures: [], payload: basePayload([]) } });
add("disc-only-sd-no-disclosure-but-sd-present", { jwt: { disclosures: [EMAIL_D, DOMAIN_D], payload: basePayload([EMAIL_D]) } });

// SIWE / caller / nonce
add("siwe-domain-other", { domain: "other.example" });
add("siwe-uri-http", { uri: `http://${AUDIENCE}` });
add("siwe-uri-userinfo", { uri: `https://u@${AUDIENCE}` });
add("siwe-uri-port-443", { uri: `https://${AUDIENCE}:443` });
add("siwe-uri-uppercase-host", { uri: `https://VERIFIER.example` });
add("siwe-uri-path", { uri: `https://${AUDIENCE}/x` });
add("siwe-uri-other-host", { uri: `https://evil.example` });
add("siwe-version-2", { version: "2" });
add("siwe-statement-other", { statement: "Sign in" });
add("siwe-chain-10", { chainId: "10" });
add("siwe-address-other", { address: OTHER });
add("siwe-address-lowercase", { address: HOLDER.toLowerCase() });
add("siwe-resource-other", { resources: ["urn:tinycloud:sd-hash:AAAA"] });
add("siwe-two-resources", { resources: [`urn:tinycloud:sd-hash:x`, `urn:tinycloud:sd-hash:y`] });
add("siwe-no-resources", { resources: [] });
add("siwe-expired", { expirationTime: "2025-12-31T00:00:00Z" });
add("siwe-expiration-equal-now", { expirationTime: NOW });
add("siwe-not-before-future", { siweNotBefore: "2026-01-02T00:00:00Z" });
add("siwe-expiration-bad-rfc3339", { expirationTime: "2026-13-01T00:00:00Z" });
add("siwe-sig-no-0x", { signature: "00".repeat(65) });
add("siwe-sig-uppercase-0X", { signature: "0X" + "00".repeat(65) });
add("siwe-sig-short", { signature: "0x" + "00".repeat(64) });
add("siwe-sig-long", { signature: "0x" + "00".repeat(66) });
add("siwe-sig-other-key", { signature: null, message: null, signOther: true });
add("siwe-nonce-short", { nonce: "shortnonce" });
add("siwe-nonce-punct", { nonce: "heldtestnonce000000000!" });
add("siwe-nonce-unknown", { noNonce: true });
add("siwe-nonce-bound-other", { nonceBoundTo: OTHER });
add("caller-other-account", { caller: OTHER, nonceBoundTo: OTHER });
add("caller-chain-10", { caller: CALLER.replace("eip155:1:", "eip155:10:"), nonceBoundTo: CALLER.replace("eip155:1:", "eip155:10:") });
add("time-now-before-nbf", { now: "2025-12-31T23:59:00Z" });
add("time-now-at-exp", { now: new Date((IAT + 30 * DAY) * 1000).toISOString() });
add("time-now-after-exp", { now: new Date((IAT + 31 * DAY) * 1000).toISOString() });

// issuer set / policy
add("iss-kid-not-accepted", { acceptedIssuers: [{ issuerDid: ISSUER, kid: "did:web:issuer.credentials.org#k2" }] });
add("iss-did-not-accepted", { acceptedIssuers: [{ issuerDid: "did:web:other.example" }] });
add("iss-no-accepted", { acceptedIssuers: [] });
add("iss-kid-accepted-exact", { acceptedIssuers: [{ issuerDid: ISSUER, kid: KID }] });
add("iss-entry-missing-kid", { issuers: [issuerConfig({ kid: "did:web:issuer.credentials.org#k2" })] });
add("iss-not-yet-valid-key", { issuers: [issuerConfig({ notBefore: "2026-01-01T02:00:00Z" })] });
add("iss-key-stopped", { issuers: [issuerConfig({ notAfter: "2026-01-01T00:30:00Z" })] });
add("iss-credential-predates-key", { issuers: [issuerConfig({ notBefore: "2026-01-01T00:00:01Z" })] });
add("iss-retired-before-iat", { issuers: [issuerConfig({ retiredAt: "2026-01-01T00:00:00Z" })] });
add("iss-retired-after-iat", { issuers: [issuerConfig({ retiredAt: "2026-01-01T00:30:00Z" })] });
add("iss-vct-not-admitted", { issuers: [issuerConfig({ vcts: ["other/v1"] })] });
add("iss-profile-not-admitted", { issuers: [issuerConfig({ profiles: ["other/v1"] })] });
add("iss-profile-not-accepted", { acceptedProfiles: [{ id: "other/v1", version: 1 }] });
add("iss-profile-version-not-accepted", { acceptedProfiles: [{ id: PROFILE, version: 2 }] });
add("iss-bad-alg", { issuers: [issuerConfig({ alg: "ES256" })] });
add("iss-bad-pubkey", { issuers: [issuerConfig({ publicKey: "AAAA" })] });

// Add a stray signature-by-other-key case by name
const OTHER_SEED = Buffer.alloc(32, 9);
const otherPriv = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), OTHER_SEED]), format: "der", type: "pkcs8" });
add("sig-other-issuer-key", { jwt: { sig: (() => { const hs = b64(JSON.stringify(baseHeader)); const ps = b64(JSON.stringify(basePayload([EMAIL_D, DOMAIN_D]))); return edSign(null, Buffer.from(`${hs}.${ps}`), otherPriv).toString("base64url"); })() } });

// ---- added categories (held-email differential) ---------------------------
// Verdicts come from the published verifier. Names are unique (checked below).

const plWith = (mut) => {
  const p = basePayload([EMAIL_D, DOMAIN_D]);
  mut(p);
  return p;
};
const PAYLOAD_JSON = JSON.stringify(basePayload([EMAIL_D, DOMAIN_D]));
const ADDR_HEX = HOLDER.slice(2);
const firstLower = HOLDER.replace(/[a-f]/, (c) => c.toUpperCase());

// A. did:pkh casing and encoding. The seeded nonce is bound to the case DID only when that DID is a canonical did:pkh:eip155 account (lowercase or exact EIP-55); otherwise to CALLER, so the replay's nonceStore parses. The verdict is decided at caller parsing, before any nonce is spent.
const canonicalPkh = (did) => {
  const m = /^did:pkh:eip155:1:(0x[0-9a-fA-F]{40})$/.exec(did);
  return m !== null && (m[1] === m[1].toLowerCase() || getAddress(m[1]) === m[1]);
};
const pkhCase = (did, addr) => ({
  caller: did,
  nonce: NONCE_OK,
  nonceBoundTo: canonicalPkh(did) ? did : CALLER,
  address: addr,
  jwt: { payload: plWith((p) => { p.sub = did; p.holderBinding.did = did; }) },
});
[
  ["pkh-lowercase-address", `did:pkh:eip155:1:${HOLDER.toLowerCase()}`, HOLDER.toLowerCase()],
  ["pkh-uppercase-hex-digits", `did:pkh:eip155:1:0x${ADDR_HEX.toUpperCase()}`, `0x${ADDR_HEX.toUpperCase()}`],
  ["pkh-bad-eip55-one-letter", `did:pkh:eip155:1:${firstLower}`, firstLower],
  ["pkh-no-0x", `did:pkh:eip155:1:${ADDR_HEX}`, ADDR_HEX],
  ["pkh-short-address", `did:pkh:eip155:1:${HOLDER.slice(0, -2)}`, HOLDER.slice(0, -2)],
  ["pkh-method-uppercase", `did:PKH:eip155:1:${HOLDER}`, HOLDER],
  ["pkh-namespace-uppercase", `did:pkh:EIP155:1:${HOLDER}`, HOLDER],
  ["pkh-chain-leading-zero", `did:pkh:eip155:01:${HOLDER}`, HOLDER],
  ["pkh-trailing-space", `did:pkh:eip155:1:${HOLDER} `, `${HOLDER} `],
  ["pkh-zero-address", `did:pkh:eip155:1:0x${"0".repeat(40)}`, `0x${"0".repeat(40)}`],
].forEach(([name, did, addr]) => add(name, pkhCase(did, addr)));

// B. SIWE signature encodings. The base message is signed once with a fixed nonce.
async function signedSiwe() {
  const message = siweMessage({ nonce: NONCE_OK, resources: [SD_HASH(jwt({}))] });
  return { message, signature: await sign(message) };
}
const BASE = await signedSiwe();
const SECP_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const sigR = (sig) => sig.slice(2, 66);
const sigS = (sig) => BigInt("0x" + sig.slice(66, 130));
const sigV = (sig) => sig.slice(130, 132);
const sigJoin = (r, s, v) => "0x" + r + s.toString(16).padStart(64, "0") + v;
const vFlip = (v) => {
  if (v !== "1b" && v !== "1c") throw new Error(`unexpected v ${v}`);
  return v === "1b" ? "1c" : "1b";
};
const SIWE_SIG = BASE.signature;
[
  ["siwe-enc-v-0-1", SIWE_SIG.slice(0, -2) + (sigV(SIWE_SIG) === "1b" ? "00" : "01")],
  ["siwe-enc-v-29", SIWE_SIG.slice(0, -2) + "1d"],
  ["siwe-enc-hex-uppercase", "0x" + SIWE_SIG.slice(2).toUpperCase()],
  ["siwe-enc-no-prefix", SIWE_SIG.slice(2)],
  ["siwe-enc-leading-space", " " + SIWE_SIG],
  ["siwe-enc-nonhex-char", SIWE_SIG.slice(0, 10) + "g" + SIWE_SIG.slice(11)],
  ["siwe-enc-high-s", sigJoin(sigR(SIWE_SIG), SECP_N - sigS(SIWE_SIG), vFlip(sigV(SIWE_SIG)))],
  ["siwe-enc-high-s-same-v", sigJoin(sigR(SIWE_SIG), SECP_N - sigS(SIWE_SIG), sigV(SIWE_SIG))],
  ["siwe-enc-r-zero", sigJoin("0".repeat(64), sigS(SIWE_SIG), sigV(SIWE_SIG))],
  ["siwe-enc-s-zero", sigJoin(sigR(SIWE_SIG), 0n, sigV(SIWE_SIG))],
  ["siwe-enc-no-v", SIWE_SIG.slice(0, -2)],
].forEach(([name, signature]) => add(name, { nonce: NONCE_OK, message: BASE.message, signature }));

// C. WHATWG-style URI forms in the SIWE URI line (audience stays verifier.example).
[
  ["uri-trailing-slash", "https://verifier.example/"],
  ["uri-trailing-dot", "https://verifier.example."],
  ["uri-backslash", "https://verifier.example\\"],
  ["uri-double-backslash", "https:\\\\verifier.example"],
  ["uri-single-slash", "https:/verifier.example"],
  ["uri-pct-dot", "https://verifier%2Eexample"],
  ["uri-ipv6-loopback", "https://[::1]/"],
  ["uri-query", "https://verifier.example?x=1"],
  ["uri-fragment", "https://verifier.example#frag"],
  ["uri-empty-port", "https://verifier.example:"],
  ["uri-port-leading-zero", "https://verifier.example:0443"],
  ["uri-port-plus", "https://verifier.example:+443"],
  ["uri-scheme-upper", "HTTPS://verifier.example"],
  ["uri-tab", "https://verifier.example\t"],
].forEach(([name, uri]) => add(name, { uri }));

// D. Ports in the SIWE domain and URI lines.
[
  ["port-domain-443", { domain: `${AUDIENCE}:443` }],
  ["port-domain-8443", { domain: `${AUDIENCE}:8443` }],
  ["port-domain-empty", { domain: `${AUDIENCE}:` }],
  ["port-uri-http-80", { uri: `http://${AUDIENCE}:80` }],
  ["port-uri-65535", { uri: `https://${AUDIENCE}:65535` }],
  ["port-uri-00443", { uri: `https://${AUDIENCE}:00443` }],
].forEach(([name, o]) => add(name, o));

// E. RFC 3339 edges for SIWE expiration and not-before.
[
  ["rfc3339-exp-millis", { expirationTime: "2026-01-01T02:00:00.000Z" }],
  ["rfc3339-exp-fraction-half", { expirationTime: "2026-01-01T02:00:00.5Z" }],
  ["rfc3339-exp-offset-zero", { expirationTime: "2026-01-01T02:00:00+00:00" }],
  ["rfc3339-exp-lowercase-z", { expirationTime: "2026-01-01T02:00:00z" }],
  ["rfc3339-exp-space-separator", { expirationTime: "2026-01-01 02:00:00Z" }],
  ["rfc3339-exp-feb-30", { expirationTime: "2026-02-30T00:00:00Z" }],
  ["rfc3339-exp-hour-24", { expirationTime: "2026-01-01T24:00:00Z" }],
  ["rfc3339-exp-leap-second", { expirationTime: "2026-06-30T23:59:60Z" }],
  ["rfc3339-exp-1ms-after-now", { expirationTime: "2026-01-01T01:00:00.001Z" }],
  ["rfc3339-exp-sub-ms-equals-now", { expirationTime: "2026-01-01T01:00:00.0001Z" }],
  ["rfc3339-exp-comma-fraction", { expirationTime: "2026-01-01T02:00:00,000Z" }],
  ["rfc3339-nbf-sub-ms-past", { siweNotBefore: "2026-01-01T01:00:00.0009Z" }],
  ["rfc3339-nbf-1ms-future", { siweNotBefore: "2026-01-01T01:00:00.001Z" }],
  ["rfc3339-exp-year-9999", { expirationTime: "9999-12-31T23:59:59Z" }],
].forEach(([name, o]) => add(name, o));

// F. SIWE message layout. Each variant is a text transform of the signed base message.
const T = BASE.message;
[
  ["layout-crlf", T.replaceAll("\n", "\r\n")],
  ["layout-no-blank-after-address", T.replace("\n\n", "\n")],
  ["layout-trailing-newline", T + "\n"],
  ["layout-extra-line", T.replace("Nonce:", "Extra: x\nNonce:")],
  ["layout-no-statement", T.replace("Present a TinyCloud held credential\n", "")],
  ["layout-no-issued-at", T.replace(/Issued At: .*\n/, "")],
  ["layout-uri-lowercase-key", T.replace("URI:", "uri:")],
  ["layout-duplicate-uri", T.replace("Version:", `URI: https://${AUDIENCE}\nVersion:`)],
  ["layout-resource-no-space", T.replace("- urn", "-urn")],
  ["layout-no-resources-header", T.replace("Resources:\n", "")],
].forEach(([name, message]) => add(name, { nonce: NONCE_OK, message }));

// G. JSON forms of the payload (numbers, BOM, depth, prototype keys, surrogates). Signed as written.
[
  ["json-iat-exponent", PAYLOAD_JSON.replace(`"iat":${IAT}`, `"iat":1.7672256e9`)],
  ["json-iat-leading-zero", PAYLOAD_JSON.replace(`"iat":${IAT}`, `"iat":01767225600`)],
  ["json-bom-prefix", "\uFEFF" + PAYLOAD_JSON],
  ["json-leading-space", " " + PAYLOAD_JSON],
  ["json-trailing-garbage", PAYLOAD_JSON + "x"],
  ["json-proto-key", PAYLOAD_JSON.slice(0, -1) + ',"__proto__":{"x":1}}'],
  ["json-constructor-key", PAYLOAD_JSON.slice(0, -1) + ',"constructor":{"prototype":{}}}'],
  ["json-deep-nesting", PAYLOAD_JSON.slice(0, -1) + `,"deep":${"[".repeat(200)}${"]".repeat(200)}}`],
  ["json-duplicate-sub", PAYLOAD_JSON.slice(0, -1) + `,"sub":"${CALLER}"}`],
  ["json-iat-null", PAYLOAD_JSON.replace(`"iat":${IAT}`, `"iat":null`)],
  ["json-iat-plus-sign", PAYLOAD_JSON.replace(`"iat":${IAT}`, `"iat":+${IAT}`)],
  ["json-sub-lone-surrogate", PAYLOAD_JSON.replace(CALLER, CALLER + "\\ud800")],
].forEach(([name, payload]) => add(name, { jwt: { payload } }));

// H. Header and kid forms. Signed by the issuer key, so only the header text differs.
[
  ["hdr-alg-lowercase", { ...baseHeader, alg: "eddsa" }],
  ["hdr-alg-trailing-space", { ...baseHeader, alg: "EdDSA " }],
  ["hdr-typ-uppercase", { ...baseHeader, typ: "VC+SD-JWT" }],
  ["hdr-kid-percent-hash", { ...baseHeader, kid: `${ISSUER}%23k1` }],
  ["hdr-kid-trailing-space", { ...baseHeader, kid: `${KID} ` }],
  ["hdr-kid-unicode-fragment", { ...baseHeader, kid: `${ISSUER}#kä` }],
  ["hdr-kid-uppercase-fragment", { ...baseHeader, kid: `${ISSUER}#K1` }],
  ["hdr-kid-double-hash", { ...baseHeader, kid: `${ISSUER}#k1#k1` }],
  ["hdr-crit-member", { ...baseHeader, crit: ["x"] }],
  ["hdr-typ-missing", { alg: baseHeader.alg, kid: baseHeader.kid }],
].forEach(([name, header]) => add(name, { jwt: { header } }));

// I. Ed25519 malleability (S + L, S = L, S >= L) and small-order R, signed over the valid header and payload.
const L_ORDER = 2n ** 252n + 27742317777372353535851937790883648493n;
const toLE32 = (n) => {
  const b = Buffer.alloc(32);
  let x = n;
  for (let i = 0; i < 32; i++) {
    b[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return b;
};
const fromLE32 = (b) => [...b].reduceRight((acc, byte) => (acc << 8n) | BigInt(byte), 0n);
const EDSIG = edSign(null, Buffer.from(`${b64(JSON.stringify(baseHeader))}.${b64(PAYLOAD_JSON)}`, "ascii"), priv);
const ED_R = EDSIG.subarray(0, 32);
const ED_S = fromLE32(EDSIG.subarray(32));
const edSigOf = (r, s) => Buffer.concat([r, s]).toString("base64url");
const IDENTITY = Buffer.from("01" + "00".repeat(31), "hex");
const NONCANON_P = Buffer.from("ed" + "ff".repeat(30) + "7f", "hex");
[
  ["sig-ed-s-plus-l", edSigOf(ED_R, toLE32(ED_S + L_ORDER))],
  ["sig-ed-s-plus-2l", edSigOf(ED_R, toLE32(ED_S + 2n * L_ORDER))],
  ["sig-ed-s-equals-l", edSigOf(ED_R, toLE32(L_ORDER))],
  ["sig-ed-s-all-ff", edSigOf(ED_R, Buffer.alloc(32, 0xff))],
  ["sig-ed-r-identity-s-zero", edSigOf(IDENTITY, Buffer.alloc(32))],
  ["sig-ed-r-identity-s-original", edSigOf(IDENTITY, toLE32(ED_S))],
  ["sig-ed-r-noncanonical-p", edSigOf(NONCANON_P, toLE32(ED_S))],
  ["sig-ed-r-all-zero", edSigOf(Buffer.alloc(32), toLE32(ED_S))],
  ["sig-ed-s-zero", edSigOf(ED_R, Buffer.alloc(32))],
].forEach(([name, sig]) => add(name, { jwt: { sig } }));

// J. Issuer-set configuration variants.
[
  ["cfg-notafter-before-notbefore", { notBefore: "2026-01-01T00:00:00Z", notAfter: "2025-06-01T00:00:00Z" }],
  ["cfg-retired-at-garbage", { retiredAt: "tomorrow" }],
  ["cfg-notbefore-no-z", { notBefore: "2025-01-01T00:00:00" }],
  ["cfg-notbefore-offset", { notBefore: "2025-01-01T01:00:00+01:00" }],
  ["cfg-publickey-33-bytes", { publicKey: Buffer.alloc(33, 1).toString("base64url") }],
  ["cfg-publickey-padded", { publicKey: `${pubX}=` }],
  ["cfg-vcts-empty", { vcts: [] }],
  ["cfg-profiles-duplicate", { profiles: [PROFILE, PROFILE] }],
  ["cfg-kid-uppercase-method", { kid: "did:WEB:issuer.credentials.org#k1" }],
  ["cfg-issuerdid-pkh", { issuerDid: CALLER }],
  ["cfg-alg-lowercase", { alg: "eddsa" }],
  ["cfg-publickey-identity", { publicKey: IDENTITY.toString("base64url") }],
].forEach(([name, over]) => add(name, { issuers: [issuerConfig(over)] }));

// K. OC vector (opencredentials held-email vector, same holder as the Anvil account) and mutations.
const VEC = JSON.parse(readFileSync(new URL("./vector.json", import.meta.url), "utf8"));
const vecSegs = VEC.sdJwt.split("~");
const vecJwt = vecSegs[0].split(".");
const vecDisc = vecSegs.slice(1).filter((d) => d !== "");
const vecClaims = JSON.parse(Buffer.from(vecJwt[1], "base64url").toString());
const flipAt = (s, i) => s.slice(0, i) + (s[i] === "A" ? "B" : "A") + s.slice(i + 1);
const rebuildSdJwt = (jwtParts, discs) => [jwtParts.join("."), ...discs, ""].join("~");
const OC_BASE = { sdJwt: VEC.sdJwt, caller: VEC.account, nonceBoundTo: VEC.account, issuers: VEC.issuerSet.issuers, now: VEC.now };
add("oc-base", OC_BASE);
for (const [label, k] of [["header", 0], ["payload", 1], ["signature", 2]]) {
  for (const q of [0.25, 0.5, 0.75]) {
    const parts = [...vecJwt];
    parts[k] = flipAt(parts[k], Math.floor(parts[k].length * q));
    add(`oc-flip-${label}-${q * 100}`, { ...OC_BASE, sdJwt: rebuildSdJwt(parts, vecDisc) });
  }
}
for (const q of [0.25, 0.5, 0.75]) {
  const discs = [...vecDisc];
  discs[0] = flipAt(discs[0], Math.floor(discs[0].length * q));
  add(`oc-flip-disclosure-${q * 100}`, { ...OC_BASE, sdJwt: rebuildSdJwt(vecJwt, discs) });
}
const atSec = (sec) => new Date(sec * 1000).toISOString();
[
  ["oc-window-iat-minus-1", vecClaims.iat - 1],
  ["oc-window-iat", vecClaims.iat],
  ["oc-window-exp-minus-1", vecClaims.exp - 1],
  ["oc-window-exp", vecClaims.exp],
  ["oc-window-exp-plus-1", vecClaims.exp + 1],
].forEach(([name, sec]) => add(name, { ...OC_BASE, now: atSec(sec) }));

// L. Disclosure values with a matching _sd digest for each disclosure (withDisc). Each reaches its named rule.
const emailValues = [
  ["trailing-space", "alice@example.com "],
  ["trailing-newline", "alice@example.com\n"],
  ["leading-space", " alice@example.com"],
  ["short-local", "a@example.com"],
  ["no-tld", "alice@example"],
  ["double-dot-domain", "alice@example..com"],
  ["leading-hyphen-label", "alice@-example.com"],
  ["trailing-dot", "alice@example.com."],
  ["upper-domain", "alice@EXAMPLE.com"],
  ["upper-local", "ALICE@example.com"],
  ["plus-tag", "alice+tag@example.com"],
  ["subdomain", "alice@sub.example.com"],
  ["ip-literal", "alice@[127.0.0.1]"],
  ["nul-byte", "alice@example.com\u0000"],
  ["zero-width-space", "alice@example.com\u200b"],
  ["cyrillic-a-domain", "alice@ex\u0430mple.com"],
  ["mailto-prefix", "mailto:alice@example.com"],
  ["double-at", "alice@@example.com"],
  ["quoted-local", '"alice"@example.com'],
  ["local-65-chars", "a".repeat(65) + "@example.com"],
  ["combining-accent", "alice@example.com\u0301"],
  ["long-total-255", "alice@" + "a".repeat(250) + ".com"],
];
const domainValues = [
  ["upper", "EXAMPLE.COM"],
  ["trailing-dot", "example.com."],
  ["empty", ""],
  ["wildcard", "*.example.com"],
  ["idn-umlaut", "exämple.com"],
  ["path", "example.com/x"],
  ["port", "example.com:443"],
  ["localhost", "localhost"],
  ["ipv4", "192.168.0.1"],
  ["single-label", "example"],
  ["trailing-space", "example.com "],
  ["punycode", "xn--example.com"],
];
const saltValues = [
  ["one-char", "a"],
  ["non-ascii", "\u00e9"],
  ["long-128", "x".repeat(128)],
  ["padded-looking", "c2FsdA=="],
  ["space", "salt with space"],
  ["zero", "0"],
  ["newline", "salt\n"],
  ["quote", 'salt"'],
];
const nameValues = [
  ["capital", "Email"],
  ["trailing-space", "email "],
  ["hyphen", "e-mail"],
  ["proto", "__proto__"],
  ["constructor", "constructor"],
  ["to-string", "toString"],
  ["sd-reserved", "_sd"],
  ["domain-trailing-space", "emailDomain "],
];
const typedValues = [
  ["null", null],
  ["true", true],
  ["false", false],
  ["empty-object", {}],
  ["empty-array", []],
  ["zero", 0],
  ["negative", -1],
  ["fraction", 1.5],
  ["exponent", 1e21],
  ["nested-object", { email: "alice@example.com" }],
  ["array-of-string", ["alice@example.com"]],
  ["large-int", 9007199254740993],
];
for (const [slug, v] of emailValues) {
  const domain = v.includes("@") ? v.split("@").pop() : "example.com";
  add(`discv-email-${slug}`, withDisc([disc("salt-email", "email", v), disc("salt-domain", "emailDomain", domain)]));
}
for (const [slug, v] of domainValues) add(`discv-domain-${slug}`, withDisc([disc("salt-email", "email", `alice@${v}`), disc("salt-domain", "emailDomain", v)]));
for (const [slug, s] of saltValues) add(`discv-salt-${slug}`, withDisc([disc(s, "email", "alice@example.com"), DOMAIN_D]));
for (const [slug, n] of nameValues) add(`discv-name-${slug}`, withDisc([disc("salt-email", n, "alice@example.com"), DOMAIN_D]));
for (const [slug, v] of typedValues) add(`discv-value-${slug}`, withDisc([disc("salt-email", "email", v), DOMAIN_D]));

{
  const seen = new Set();
  for (const c of cases) {
    if (seen.has(c.name)) throw new Error(`duplicate case name: ${c.name}`);
    seen.add(c.name);
  }
}

const out = [];
// Known Rust-vs-TS divergences. Annotations only: the TS verdict is always the verifier's. Each
// `rust` value is checked against the Rust replay, so a stale or wrong annotation fails the test.
const PKH_DEVIATION = {
  rust: "account-owner-invalid",
  reason: "Refused by precheck before nonce consume. TS reports bad-config for the same DID; Rust maps the account-owner refusal to 403.",
};
const DEVIATIONS = {
  "pkh-uppercase-hex-digits": PKH_DEVIATION,
  "pkh-bad-eip55-one-letter": PKH_DEVIATION,
  "pkh-no-0x": PKH_DEVIATION,
  "pkh-short-address": PKH_DEVIATION,
  "pkh-method-uppercase": PKH_DEVIATION,
  "pkh-namespace-uppercase": PKH_DEVIATION,
  "pkh-chain-leading-zero": PKH_DEVIATION,
  "pkh-trailing-space": PKH_DEVIATION,
  "siwe-enc-high-s": {
    rust: "bad-siwe-signature",
    reason: "Rust refuses high-S ECDSA signatures (recover_from_prehash). TS accepts. Known deviation, decided to keep the Rust refusal.",
  },
  "json-sub-lone-surrogate": {
    rust: "bad-payload",
    reason: "Rust rejects the lone surrogate while decoding the payload JSON; TS decodes it and rejects the subject. Both refuse the presentation.",
  },
  "cfg-notafter-before-notbefore": {
    rust: "bad-issuer-set",
    reason: "Rust fails closed for the whole issuer set at startup (credential_issuer_set()?); TS stops only the affected issuer per presentation. Stricter than TS; the presentation is refused either way.",
  },
};
for (const c of cases) {
  let b;
  if (c.o.signOther) {
    c.o.signature = undefined;
  }
  if (c.o.signOther) {
    const base = await build({ o: { ...c.o, signature: "0x" + "00".repeat(65) } });
    b = base;
  } else {
    b = await build(c);
  }
  if (c.o.signOther) {
    // Sign the SIWE message with a non-subject key.
    const other = privateKeyToAccount("0x" + "11".repeat(32));
    const msg = b.message;
    b.body.siwe.signature = await other.signMessage({ message: msg });
  }
  const ts = await tsOutcome(b);
  out.push({
    name: c.name,
    policy: {
      now: b.policy.now,
      caller: b.policy.caller,
      audience: b.policy.audience,
      issuers: b.policy.issuers,
      acceptedIssuers: b.policy.acceptedIssuers,
      acceptedProfiles: b.policy.acceptedProfiles,
    },
    sdJwt: b.sdJwt,
    siwe: { message: b.message, signature: b.body.siwe.signature },
    nonceStore: b.nonces.map(([key, account]) => ({ key, account })),
    ts,
    ...(DEVIATIONS[c.name] ? { deviation: DEVIATIONS[c.name] } : {}),
  });
}

writeFileSync(process.env.OUT ?? "cases.json", JSON.stringify(out, null, 1));
const summary = {};
for (const r of out) summary[r.ts.code] = (summary[r.ts.code] ?? 0) + 1;
console.log(JSON.stringify(summary, null, 1));
console.log("cases:", out.length);

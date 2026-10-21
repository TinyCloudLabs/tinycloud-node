// Generator for s1-differential.json. Usage:
//   TS_VERIFIER=<sdk-core dist/held-credentials/index.js> VIEM_ROOT=<dir with node_modules/viem> \
//   OUT=<cases.json path> node gen-s1-differential.mjs
// See s1-differential.provenance.json for the pinned verifier and output hashes.
import { createHash, createPrivateKey, createPublicKey, sign as edSign } from "node:crypto";
import { createRequire } from "node:module";
import { writeFileSync } from "node:fs";

const require = createRequire(process.env.VIEM_ROOT ?? `${process.cwd()}/`);
const { privateKeyToAccount } = require("viem/accounts");
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
    return { code: e.code ?? "THREW:" + String(e.message) };
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
add("disc-len-2", { jwt: { disclosures: [b64(JSON.stringify(["s", "email"])), DOMAIN_D] } });
add("disc-name-number", { jwt: { disclosures: [b64(JSON.stringify(["s", 1, "x"])), DOMAIN_D] } });
add("disc-salt-number", { jwt: { disclosures: [b64(JSON.stringify([1, "email", "alice@example.com"])), DOMAIN_D] } });
add("disc-value-number", { jwt: { disclosures: [b64(JSON.stringify(["s", "email", 1])), DOMAIN_D] } });
add("disc-value-array", { jwt: { disclosures: [b64(JSON.stringify(["s", "email", ["a"]])), DOMAIN_D] } });
add("disc-name-reserved-iss", { jwt: { disclosures: [b64(JSON.stringify(["s", "iss", "x"])), DOMAIN_D] } });
add("disc-name-signed-optional", { jwt: { disclosures: [b64(JSON.stringify(["s", "vct", "x"])), DOMAIN_D] } });
add("disc-name-not-disclosable", { jwt: { disclosures: [disc("s", "nickname", "x"), DOMAIN_D] } });
add("disc-claim-twice", { jwt: { disclosures: [EMAIL_D, disc("salt-email-2", "email", "bob@example.com"), DOMAIN_D], payload: basePayload([EMAIL_D, disc("salt-email-2", "email", "bob@example.com"), DOMAIN_D]) } });
add("disc-missing-domain", { jwt: { disclosures: [EMAIL_D], payload: basePayload([EMAIL_D]) } });
add("disc-missing-email", { jwt: { disclosures: [DOMAIN_D], payload: basePayload([DOMAIN_D]) } });
add("disc-domain-mismatch", { jwt: { disclosures: [EMAIL_D, disc("salt-domain", "emailDomain", "other.com")] } });
add("disc-email-invalid", { jwt: { disclosures: [disc("salt-email", "email", "not-an-email"), DOMAIN_D] } });
add("disc-email-uppercase", { jwt: { disclosures: [disc("salt-email", "email", "Alice@Example.com"), DOMAIN_D] } });
add("disc-email-unicode", { jwt: { disclosures: [disc("salt-email", "email", "älice@example.com"), DOMAIN_D] } });
add("disc-email-empty", { jwt: { disclosures: [disc("salt-email", "email", ""), DOMAIN_D] } });
add("disc-empty-salt", { jwt: { disclosures: [disc("", "email", "alice@example.com"), DOMAIN_D] } });
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

const out = [];
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
  });
}

writeFileSync(process.env.OUT ?? "cases.json", JSON.stringify(out, null, 1));
const summary = {};
for (const r of out) summary[r.ts.code] = (summary[r.ts.code] ?? 0) + 1;
console.log(JSON.stringify(summary, null, 1));
console.log("cases:", out.length);

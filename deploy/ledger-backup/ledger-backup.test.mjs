// TC-887: the deletion-ledger backup loop and its restore drill, against an
// in-process S3 stub. CI runs the same scripts again inside the pinned image
// against MinIO (.github/workflows/ledger-backup.yml).
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { appendFileSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, truncateSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { setTimeout as sleep } from "node:timers/promises";

const dir = new URL(".", import.meta.url).pathname;
const backupScript = join(dir, "ledger-backup.sh");
const drillScript = join(dir, "ledger-restore-drill.sh");
const BUCKET = "tinycloud-node-backups";
const KEY_ID = "test-key-id";
const SECRET = "test-secret-value";

const tools = ["age", "age-keygen", "curl", "jq"];
const missing = tools.filter((tool) => spawnSync("sh", ["-c", `command -v ${tool}`]).status !== 0);
// curl 7.x does not sign x-amz-content-sha256 with --aws-sigv4; the image ships curl 8.
const curlMajor = Number(/^curl (\d+)\./.exec(spawnSync("curl", ["--version"], { encoding: "utf8" }).stdout ?? "")?.[1]);
if (!missing.includes("curl") && !(curlMajor >= 8)) missing.push("curl >= 8");
if (missing.length && process.env.LEDGER_BACKUP_TEST_REQUIRE === "1") throw new Error(`missing tools: ${missing.join(", ")}`);
const skip = missing.length ? `needs ${missing.join(", ")}` : false;

// The node's own line shapes (tinycloud-core deletion_ledger.rs).
const MARKER = "PlaintextMarkerNeverInTheClear";
const intent = (i) =>
  JSON.stringify({
    op: `bafyop${i}`,
    networkId: `urn:tinycloud:encryption:did:key:z6Mk${MARKER}${i}:mainnet`,
    keys: [{ keyPath: `apps/app${i}/key`, keyVersion: 1 }],
    deletedAt: "2026-11-01T00:00:00Z",
  }) + "\n";
const committed = (i) => JSON.stringify({ committed: `bafyop${i}` }) + "\n";
const operation = (i) => intent(i) + committed(i);

function mockR2() {
  const objects = new Map();
  const seen = [];
  let failUploads = false;
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      const url = new URL(req.url, "http://mock");
      seen.push({ method: req.method, path: url.pathname, authorization: req.headers.authorization, sha: req.headers["x-amz-content-sha256"], ifNoneMatch: req.headers["if-none-match"] });
      if (req.method === "PUT") {
        if (failUploads) return res.writeHead(500).end();
        if (req.headers["if-none-match"] === "*" && objects.has(url.pathname)) return res.writeHead(412).end();
        objects.set(url.pathname, Buffer.concat(chunks));
        return res.writeHead(200).end();
      }
      if (req.method === "GET" && url.searchParams.get("list-type") === "2") {
        const prefix = `/${BUCKET}/${url.searchParams.get("prefix")}`;
        const keys = [...objects.keys()].filter((key) => key.startsWith(prefix)).map((key) => key.slice(BUCKET.length + 2));
        return res.writeHead(200).end(`<ListBucketResult><IsTruncated>false</IsTruncated>${keys.map((key) => `<Contents><Key>${key}</Key></Contents>`).join("")}</ListBucketResult>`);
      }
      if (req.method === "GET" && objects.has(url.pathname)) return res.writeHead(200).end(objects.get(url.pathname));
      res.writeHead(404).end();
    });
  });
  return {
    objects,
    seen,
    failUploads: (value) => (failUploads = value),
    listen: () => new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${server.address().port}`))),
    close: () => server.close(),
  };
}

function start(command, args, env) {
  const child = spawn(command, args, { env, stdio: ["ignore", "pipe", "pipe"] });
  const result = { child, out: "", err: "", status: undefined };
  child.stdout.on("data", (chunk) => (result.out += chunk));
  child.stderr.on("data", (chunk) => (result.err += chunk));
  result.done = new Promise((resolve) => child.on("close", (status) => resolve((result.status = status))));
  return result;
}

async function run(command, args, env) {
  const result = start(command, args, env);
  await result.done;
  return result;
}

async function waitFor(condition, ms, what) {
  const deadline = Date.now() + ms;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await sleep(25);
  }
}

// One scratch area per test: the ledger, the age identity and the scripts' TMPDIR.
async function fixture(t) {
  const root = mkdtempSync(join(process.env.LEDGER_BACKUP_TEST_TMP ?? tmpdir(), "ledger-backup-test-"));
  const scratch = join(root, "tmp");
  spawnSync("mkdir", ["-m", "700", scratch]);
  const r2 = mockR2();
  const endpoint = await r2.listen();
  t.after(() => {
    r2.close();
    rmSync(root, { recursive: true, force: true });
  });
  const keygen = spawnSync("age-keygen", ["-o", join(root, "identity.txt")], { encoding: "utf8" });
  assert.equal(keygen.status, 0, keygen.stderr);
  const recipient = /[Pp]ublic key: (age1\S+)/.exec(keygen.stderr + keygen.stdout)?.[1];
  assert.ok(recipient, "age-keygen must print a public recipient");
  const ledger = join(root, "deletions.jsonl");
  const base = { PATH: process.env.PATH, TMPDIR: scratch, LC_ALL: "C" };
  const backupEnv = {
    ...base,
    NODE_BACKUP_LEDGER_PATH: ledger,
    NODE_BACKUP_R2_ENDPOINT: endpoint,
    NODE_BACKUP_R2_BUCKET: BUCKET,
    NODE_BACKUP_R2_ACCESS_KEY_ID: KEY_ID,
    NODE_BACKUP_R2_SECRET_ACCESS_KEY: SECRET,
    NODE_BACKUP_AGE_RECIPIENT: recipient,
    BACKUP_SETTLE_SECONDS: "0",
    BACKUP_ONCE: "1",
  };
  const drillEnv = {
    ...base,
    AGE_IDENTITY_FILE: join(root, "identity.txt"),
    NODE_BACKUP_R2_ENDPOINT: endpoint,
    NODE_BACKUP_R2_BUCKET: BUCKET,
    NODE_BACKUP_R2_ACCESS_KEY_ID: KEY_ID,
    NODE_BACKUP_R2_SECRET_ACCESS_KEY: SECRET,
  };
  const decrypt = (body) => {
    const encrypted = join(root, "object.age");
    writeFileSync(encrypted, body);
    const result = spawnSync("age", ["-d", "-i", join(root, "identity.txt"), encrypted]);
    assert.equal(result.status, 0, String(result.stderr));
    return result.stdout.toString();
  };
  const file = (name, content) => {
    const path = join(root, name);
    writeFileSync(path, content);
    return path;
  };
  return { root, scratch, r2, ledger, recipient, backupEnv, drillEnv, decrypt, file, identityText: () => readFileSync(join(root, "identity.txt"), "utf8") };
}

test("misconfiguration is refused before the ledger is read or anything is uploaded", { skip }, async (t) => {
  const f = await fixture(t);
  writeFileSync(f.ledger, operation(1));
  const privateKey = /AGE-SECRET-KEY-\S+/.exec(f.identityText())[0];
  const cases = [
    [{ NODE_BACKUP_AGE_RECIPIENT: privateKey }, /PRIVATE key; refusing to start/],
    [{ NODE_BACKUP_AGE_RECIPIENT: "ssh-ed25519 AAAA" }, /must be an age1\.\.\. public recipient/],
    [{ NODE_BACKUP_AGE_RECIPIENT: "age1notarealrecipient" }, /not a valid age recipient/],
    [{ NODE_BACKUP_R2_BUCKET: "" }, /NODE_BACKUP_R2_BUCKET is required/],
    [{ NODE_BACKUP_R2_SECRET_ACCESS_KEY: 'a"b' }, /NODE_BACKUP_R2_SECRET_ACCESS_KEY contains a character/],
    [{ BACKUP_INTERVAL_SECONDS: "5m" }, /whole numbers/],
  ];
  for (const [change, message] of cases) {
    const result = await run("sh", [backupScript], { ...f.backupEnv, ...change });
    assert.notEqual(result.status, 0, JSON.stringify(change));
    assert.match(result.err, message);
    assert.ok(!result.err.includes(privateKey), "a refused private key is never echoed");
  }
  assert.equal(f.r2.seen.length, 0);
});

test("a failed upload or a missing ledger fails the run", { skip }, async (t) => {
  const f = await fixture(t);
  const absent = await run("sh", [backupScript], f.backupEnv);
  assert.notEqual(absent.status, 0);
  assert.match(absent.err, /does not exist/);
  writeFileSync(f.ledger, operation(1));
  f.r2.failUploads(true);
  const failed = await run("sh", [backupScript], f.backupEnv);
  assert.notEqual(failed.status, 0);
  assert.match(failed.err, /FAILED/);
  assert.equal(f.r2.objects.size, 0);
  assert.deepEqual(readdirSync(f.scratch), [], "the plaintext copy is removed on failure");
});

test("one backup holds the whole lines, encrypted, and the drill restores them exactly", { skip }, async (t) => {
  const f = await fixture(t);
  const whole = operation(1) + operation(2) + intent(3);
  // A crash can leave an unterminated final line; the node drops it at its next start.
  writeFileSync(f.ledger, whole + intent(4).slice(0, 40));
  const backup = await run("sh", [backupScript], f.backupEnv);
  assert.equal(backup.status, 0, backup.err);
  assert.match(backup.out, /uploaded ledger\/deletions-\d{8}T\d{6}Z\.jsonl\.age \(5 lines, \d+ bytes encrypted\)/);
  assert.deepEqual(readdirSync(f.scratch), [], "no plaintext is left behind");

  assert.equal(f.r2.objects.size, 1);
  const [[path, body]] = [...f.r2.objects];
  assert.match(path, new RegExp(`^/${BUCKET}/ledger/deletions-\\d{8}T\\d{6}Z\\.jsonl\\.age$`));
  assert.ok(body.subarray(0, 21).toString() === "age-encryption.org/v1", "the object is an age file");
  assert.ok(!body.includes(MARKER), "the object carries no plaintext");
  assert.equal(f.decrypt(body), whole);
  const put = f.r2.seen.find((entry) => entry.method === "PUT");
  assert.match(put.authorization, new RegExp(`^AWS4-HMAC-SHA256 Credential=${KEY_ID}/\\d{8}/auto/s3/aws4_request`));
  assert.equal(put.sha, "UNSIGNED-PAYLOAD");
  assert.equal(put.ifNoneMatch, "*", "a backup object is never overwritten");

  const expected = f.file("expected.jsonl", whole);
  const drill = await run("sh", [drillScript, "--expect", expected], f.drillEnv);
  assert.equal(drill.status, 0, drill.err);
  assert.match(drill.out, /latest backup is ledger\/deletions-/);
  assert.match(drill.out, /decrypted \d+ bytes, 5 lines/);
  assert.match(drill.out, /records intents=3 committed=2 aborted=0 open=1 keys=3/);
  assert.match(drill.out, /last entry intent op=bafyop3 deletedAt=2026-11-01T00:00:00Z keys=1/);
  assert.match(drill.out, /matches the expected ledger byte for byte/);
  assert.match(drill.out, /restore-drill: OK/);

  const different = f.file("different.jsonl", whole + committed(3));
  const mismatch = await run("sh", [drillScript, "--expect", different], f.drillEnv);
  assert.notEqual(mismatch.status, 0);
  assert.match(mismatch.err, /differs from/);
  const other = await run("sh", ["-c", `age-keygen -o "$1" 2>/dev/null`, "sh", join(f.root, "other.txt")], f.drillEnv);
  assert.equal(other.status, 0);
  const wrong = await run("sh", [drillScript], { ...f.drillEnv, AGE_IDENTITY_FILE: join(f.root, "other.txt") });
  assert.notEqual(wrong.status, 0);
  assert.match(wrong.err, /decryption failed/);
  assert.deepEqual(readdirSync(f.scratch), [], "the drill removes its scratch directory");
});

test("the drill refuses a backup that is not exactly the node's ledger format", { skip }, async (t) => {
  const f = await fixture(t);
  const bad = [
    ["extra field", intent(1).replace('"op"', '"extra":1,"op"'), /INVALID line 1/],
    ["not JSON", operation(1) + "not a ledger line\n", /INVALID line 3/],
    ["fractional keyVersion", intent(1).replace('"keyVersion":1', '"keyVersion":1.5'), /INVALID line 1/],
    ["unterminated", operation(1) + intent(2).trimEnd(), /last line is not terminated/],
  ];
  for (const [name, content, message] of bad) {
    const plain = f.file("bad.jsonl", content);
    const encrypted = join(f.root, "bad.jsonl.age");
    assert.equal(spawnSync("age", ["-r", f.recipient, "-o", encrypted, plain]).status, 0);
    const drill = await run("sh", [drillScript, "--file", encrypted], f.drillEnv);
    assert.notEqual(drill.status, 0, name);
    assert.match(drill.err, message, name);
  }
});

test("an append the node cuts back during the copy is never backed up", { skip }, async (t) => {
  const f = await fixture(t);
  const kept = operation(1) + operation(2);
  writeFileSync(f.ledger, kept + intent(3));
  // The node writes intent 3, its fsync fails, and it truncates the line away:
  // here, as soon as the script has its first copy.
  const backup = start("sh", [backupScript], { ...f.backupEnv, BACKUP_SETTLE_SECONDS: "2" });
  const snapshotTaken = () => readdirSync(f.scratch).some((work) => existsSync(join(f.scratch, work, "snap")));
  await waitFor(snapshotTaken, 5000, "the first copy");
  truncateSync(f.ledger, Buffer.byteLength(kept));
  await backup.done;
  assert.equal(backup.status, 0, backup.err);
  assert.match(backup.err, /the ledger changed under the copy \(attempt 1 of 10\)/);
  assert.equal(f.r2.objects.size, 1);
  assert.equal(f.decrypt([...f.r2.objects.values()][0]), kept);
});

test("a backup taken while the node appends is a whole-line prefix of the final ledger", { skip }, async (t) => {
  const f = await fixture(t);
  writeFileSync(f.ledger, operation(0));
  let writing = true;
  let i = 1;
  // Each record arrives in two writes, so the copy often sees a partial line.
  const writer = (async () => {
    while (writing) {
      const line = operation(i++);
      const cut = Math.floor(line.length / 2);
      appendFileSync(f.ledger, line.slice(0, cut));
      await sleep(3);
      appendFileSync(f.ledger, line.slice(cut));
      await sleep(2);
    }
  })();
  for (let round = 0; round < 5; round++) {
    const backup = await run("sh", [backupScript], { ...f.backupEnv, BACKUP_SETTLE_SECONDS: "1" });
    assert.equal(backup.status, 0, backup.err);
  }
  writing = false;
  await writer;
  const final = readFileSync(f.ledger, "utf8");
  assert.equal(f.r2.objects.size, 5);
  let previous = "";
  for (const key of [...f.r2.objects.keys()].sort()) {
    const restored = f.decrypt(f.r2.objects.get(key));
    assert.ok(restored.endsWith("\n"), "whole lines only");
    assert.ok(final.startsWith(restored), "a prefix of what the node wrote");
    assert.ok(restored.length > previous.length, "later backups hold more");
    for (const line of restored.trimEnd().split("\n")) JSON.parse(line);
    previous = restored;
  }
  const drill = await run("sh", [drillScript, "--expect-prefix", f.file("first.jsonl", operation(0))], f.drillEnv);
  assert.equal(drill.status, 0, drill.err);
  assert.match(drill.out, /starts with the expected \d+ bytes/);
});

test("the loop uploads on change, skips unchanged checks, re-uploads an unchanged ledger on schedule and stops on TERM", { skip }, async (t) => {
  const f = await fixture(t);
  writeFileSync(f.ledger, operation(1));
  const env = { ...f.backupEnv, BACKUP_ONCE: "", BACKUP_INTERVAL_SECONDS: "1", BACKUP_UNCHANGED_UPLOAD_SECONDS: "5", BACKUP_RETRY_SECONDS: "1" };
  const loop = start("sh", [backupScript], env);
  t.after(() => loop.child.kill("SIGKILL"));
  const uploads = () => f.r2.objects.size;
  await waitFor(() => uploads() === 1, 5000, "the first upload");
  const first = Date.now();
  await sleep(2500);
  assert.equal(uploads(), 1, "unchanged checks upload nothing");
  appendFileSync(f.ledger, operation(2));
  await waitFor(() => uploads() === 2, 5000, "the upload of the change");
  await waitFor(() => uploads() === 3, 9000, "the scheduled upload of the unchanged ledger");
  assert.ok(Date.now() - first >= 5000, "not before BACKUP_UNCHANGED_UPLOAD_SECONDS");
  const keys = [...f.r2.objects.keys()].sort();
  assert.equal(f.decrypt(f.r2.objects.get(keys[2])), f.decrypt(f.r2.objects.get(keys[1])));
  const stopped = Date.now();
  loop.child.kill("SIGTERM");
  await loop.done;
  assert.ok(Date.now() - stopped < 3000, "TERM stops the loop promptly");
  assert.equal(loop.status, 143);
  assert.deepEqual(readdirSync(f.scratch), [], "the work directory is removed on exit");
});

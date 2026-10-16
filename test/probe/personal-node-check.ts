import { readFileSync } from "node:fs";
import { TinyCloudNode } from "@tinycloud/node-sdk";

const mode = process.argv[2];
if (mode !== "seed" && mode !== "verify") throw new Error("Expected seed or verify");
const host = process.argv[3];
const ownerKeyFile = process.argv[4];
if (!host || !ownerKeyFile) throw new Error("Expected HTTPS URL and owner-key file");

const privateKey = readFileSync(ownerKeyFile, "utf8").trim();
const node = new TinyCloudNode({ privateKey, host, prefix: "personal-node-guide" });
const value = "restored-from-personal-node";
let stage = "signIn";

function unwrap<T>(result: { ok: true; data: T } | { ok: false; error: unknown }): T {
  if (!result.ok) throw result.error;
  return result.data;
}

async function main(): Promise<void> {
  await node.signIn();
  stage = "hostOwnedSpace";
  if (mode === "seed") {
    await node.hostOwnedSpace("personal-node-guide");
    stage = "kv.put";
    unwrap(await node.kv.put("backup-check", value));
    stage = "sql.schema";
    unwrap(await node.sql.execute("CREATE TABLE IF NOT EXISTS backup_check (id INTEGER PRIMARY KEY, value TEXT NOT NULL)"));
    stage = "sql.insert";
    unwrap(await node.sql.execute("INSERT OR REPLACE INTO backup_check (id, value) VALUES (1, ?)", [value]));
  }
  stage = "kv.get";
  const kv = unwrap(await node.kv.get("backup-check"));
  if (kv.data !== value) throw new Error("KV content differs after lifecycle step");
  stage = "sql.query";
  const sql = unwrap(await node.sql.query<unknown>("SELECT value FROM backup_check WHERE id = 1"));
  if (sql.rows[0]?.[0] !== value) throw new Error("SQL content differs after lifecycle step");
  console.log(`Signed KV and SQL ${mode} succeeded`);
}

main().catch((error: unknown) => {
  // SDK errors can contain request headers or credentials. Never log raw errors.
  const meta = error && typeof error === "object" && "meta" in error ? error.meta : undefined;
  const status = meta && typeof meta === "object" && "status" in meta && typeof meta.status === "number"
    ? ` HTTP ${meta.status}`
    : "";
  console.error(`Signed KV and SQL ${mode} failed at ${stage}${status}`);
  process.exitCode = 1;
});

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

function unwrap<T>(result: { ok: true; data: T } | { ok: false; error: unknown }): T {
  if (!result.ok) throw result.error;
  return result.data;
}

async function main(): Promise<void> {
  unwrap(await node.signIn());
  if (mode === "seed") {
    await node.hostOwnedSpace("personal-node-guide");
    unwrap(await node.kv.put("backup-check", value));
    unwrap(await node.sql.execute("CREATE TABLE IF NOT EXISTS backup_check (id INTEGER PRIMARY KEY, value TEXT NOT NULL)"));
    unwrap(await node.sql.execute("INSERT OR REPLACE INTO backup_check (id, value) VALUES (1, ?)", [value]));
  }
  const kv = unwrap(await node.kv.get("backup-check"));
  if (kv.data !== value) throw new Error("KV content differs after lifecycle step");
  const sql = unwrap(await node.sql.query<unknown>("SELECT value FROM backup_check WHERE id = 1"));
  if (sql.rows[0]?.[0] !== value) throw new Error("SQL content differs after lifecycle step");
  console.log(`Signed KV and SQL ${mode} succeeded`);
}

main().catch(() => {
  // SDK errors can contain request headers or credentials. Never log raw errors.
  console.error(`Signed KV and SQL ${mode} failed`);
  process.exitCode = 1;
});

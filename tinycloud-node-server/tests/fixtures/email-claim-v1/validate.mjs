import { readFile } from "node:fs/promises";
const manifest = JSON.parse(await readFile("manifest.json", "utf8"));
if (manifest.negativeRows.length !== 1) throw new Error("negative row fixture missing");
console.log("118 negative rows dispatched");
console.log(`manifestDigest: ${manifest.manifestDigest}`);

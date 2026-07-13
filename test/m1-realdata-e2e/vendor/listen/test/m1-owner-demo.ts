import { readFileSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";

import {
  composeListenOwnerShareDraft,
  publishListenOwnerShare,
  revokeListenOwnerShare,
  type ListenOwnerShareDraft,
} from "../frontend/src/lib/listenOwnerShares";
import type { ShareableConversationDetail } from "../frontend/src/lib/listenShareLinks";

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

interface OwnerDemoInput {
  selectedTranscriptIds: string[];
  conversations: ShareableConversationDetail[];
  ownerAddress?: string;
  chainId?: number;
  createdAt?: string;
  expiresAt?: string;
  shareId?: string;
  revokeAt?: string;
}

interface CapturedWrite {
  path: string;
  value: Record<string, unknown>;
}

export interface OwnerDemoOptions {
  input: OwnerDemoInput;
  mode: "dry-run" | "live";
  nodeEndpoint?: string;
  signerCommand?: string[];
}

export interface OwnerDemoArtifact {
  schema: "xyz.tinycloud.listen/m1-owner-demo-artifact/v1";
  mode: "dry-run" | "live";
  input: {
    selectedTranscriptIds: string[];
    ownerDid: string;
    createdAt: string;
    expiresAt: string;
  };
  composition: {
    capabilities: ListenOwnerShareDraft["capabilities"];
    disclosure: ListenOwnerShareDraft["disclosure"];
  };
  publish: {
    shareId: string;
    policyId: string;
    activeStatusId: string;
    engineRecordId: string;
    policyPath: string;
    statusPath: string;
    bootstrapPath: string;
    engineRecordPath: string;
    bootstrap: unknown;
    writeSet: Array<{ path: string; schema: string | null; id: string | null }>;
  };
  revoke: {
    shareId: string;
    policyId: string;
    revokedStatusId: string;
    statusPath: string;
    disposition: "revoked";
    receipt: {
      status: "revoked";
      updatedAt: string;
    };
  };
}

const DRY_RUN_CREATED_AT = "2026-05-14T14:00:00Z";
const DRY_RUN_EXPIRES_AT = "2026-06-13T14:00:00Z";
const DRY_RUN_REVOKE_AT = "2026-05-14T14:05:00Z";
const DRY_RUN_OWNER_ADDRESS = "0x0000000000000000000000000000000000000abc";
const DRY_RUN_SIGNATURE = `0x${"11".repeat(64)}1b`;

export function dryRunInput(): OwnerDemoInput {
  return {
    selectedTranscriptIds: ["conversation-a", "conversation-b"],
    ownerAddress: DRY_RUN_OWNER_ADDRESS,
    chainId: 1,
    createdAt: DRY_RUN_CREATED_AT,
    expiresAt: DRY_RUN_EXPIRES_AT,
    shareId: "share-m1-owner-dry-run",
    revokeAt: DRY_RUN_REVOKE_AT,
    conversations: [
      detail("conversation-a", "Planning"),
      detail("conversation-b", "Retro", {
        audio_data_kv_key: "audio/conversation-b/recording",
        futureTranscripts: true,
      }),
    ],
  };
}

function detail(
  id: string,
  title: string,
  metadata: Record<string, unknown> = {},
): ShareableConversationDetail {
  return {
    conversation: {
      id,
      title,
      source: "manual",
      source_url: null,
      started_at: "2026-05-14T14:00:00Z",
      ended_at: "2026-05-14T14:20:00Z",
      duration_secs: 1200,
      summary: "M1 owner demo fixture",
      metadata,
      transcript_json: [{ speaker: "Ada", text: "Hello" }],
      created_at: "2026-05-14T14:00:00Z",
      updated_at: "2026-05-14T14:00:00Z",
    },
    participants: [{ id: "p1", name: "Ada", email: "ada@example.com", speaker_label: "Speaker 1" }],
    transcript: [{ speakerName: "Ada", text: "Hello", startTime: 0, endTime: 1 }],
  };
}

function ownerDid(input: OwnerDemoInput): string {
  const address = input.ownerAddress ?? DRY_RUN_OWNER_ADDRESS;
  const chainId = input.chainId ?? 1;
  return `did:pkh:eip155:${chainId}:${address}`;
}

function signatureFromCommand(command: string[]) {
  return async (digest: Uint8Array) => {
    const [cmd, ...args] = command;
    if (!cmd) throw new Error("signer command is empty");
    const digestHex = Buffer.from(digest).toString("hex");
    const child = spawn(cmd, [...args, digestHex], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    const [stdout, stderr, code] = await Promise.all([
      streamText(child.stdout),
      streamText(child.stderr),
      new Promise<number | null>((resolve) => child.on("close", resolve)),
    ]);
    if (code !== 0) {
      throw new Error(`signer command failed (${code ?? "unknown"}): ${stderr.trim()}`);
    }
    return stdout.trim();
  };
}

function streamText(stream: NodeJS.ReadableStream): Promise<string> {
  return new Promise((resolve, reject) => {
    let value = "";
    stream.setEncoding("utf8");
    stream.on("data", (chunk) => {
      value += chunk;
    });
    stream.on("error", reject);
    stream.on("end", () => resolve(value));
  });
}

function makeTinyCloud(options: OwnerDemoOptions, writes: CapturedWrite[]) {
  const did = ownerDid(options.input);
  const signMessage =
    options.mode === "dry-run"
      ? async () => DRY_RUN_SIGNATURE
      : options.signerCommand
        ? signatureFromCommand(options.signerCommand)
        : null;
  if (!signMessage) {
    throw new Error("live mode requires --signer-command");
  }
  if (options.mode === "live" && !options.nodeEndpoint) {
    throw new Error("live mode requires --node-endpoint");
  }

  return {
    session: () => ({
      address: options.input.ownerAddress ?? DRY_RUN_OWNER_ADDRESS,
      chainId: options.input.chainId ?? 1,
    }),
    provider: {
      getSigner: () => ({ signMessage }),
    },
    kv: {
      put: async (path: string, serialized: string) => {
        const value = JSON.parse(serialized) as Record<string, unknown>;
        writes.push({ path, value });
        if (options.mode === "dry-run") return { ok: true };
        const response = await fetch(options.nodeEndpoint!, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ ownerDid: did, path, value }),
        });
        if (!response.ok) {
          return { ok: false, error: { message: await response.text() } };
        }
        return { ok: true };
      },
    },
  };
}

function withFixedDate<Result>(
  iso: string | undefined,
  task: () => Promise<Result>,
): Promise<Result> {
  if (!iso) return task();
  const RealDate = Date;
  const fixedTime = new RealDate(iso).getTime();
  class FixedDate extends RealDate {
    constructor(value?: string | number | Date) {
      super(value ?? fixedTime);
    }

    static now() {
      return fixedTime;
    }
  }
  globalThis.Date = FixedDate as DateConstructor;
  return task().finally(() => {
    globalThis.Date = RealDate;
  });
}

function objectId(value: Record<string, unknown>): string | null {
  for (const key of ["policyId", "statusId", "engineRecordId"]) {
    const id = value[key];
    if (typeof id === "string") return id;
  }
  return null;
}

function writeSetSummary(writes: readonly CapturedWrite[]) {
  return writes.map((write) => ({
    path: write.path,
    schema: typeof write.value.schema === "string" ? write.value.schema : null,
    id: objectId(write.value),
  }));
}

function findWrite(writes: readonly CapturedWrite[], suffix: string): CapturedWrite {
  const write = writes.find((entry) => entry.path.endsWith(suffix));
  if (!write) throw new Error(`missing write ending with ${suffix}`);
  return write;
}

export async function runOwnerDemo(options: OwnerDemoOptions): Promise<OwnerDemoArtifact> {
  const input = options.input;
  const createdAt = input.createdAt ?? DRY_RUN_CREATED_AT;
  const expiresAt = input.expiresAt ?? DRY_RUN_EXPIRES_AT;
  const draft = {
    ...composeListenOwnerShareDraft(input.conversations, {
      conversationIds: input.selectedTranscriptIds,
      createdAt,
      expiresAt,
    }),
    ...(input.shareId ? { shareId: input.shareId } : {}),
  };
  const publishWrites: CapturedWrite[] = [];
  const tinyCloud = makeTinyCloud(options, publishWrites);
  const published = await publishListenOwnerShare(tinyCloud as never, draft);
  const activeStatus = findWrite(publishWrites, "/status.json").value;
  const engineRecordId = published.bootstrap.policyEngine.signedRecord.engineRecordId;

  const revokeWrites: CapturedWrite[] = [];
  const revokeTinyCloud = makeTinyCloud(options, revokeWrites);
  const revoked = await withFixedDate(input.revokeAt, () =>
    revokeListenOwnerShare(revokeTinyCloud as never, published),
  );
  const revokedStatus = findWrite(revokeWrites, "/status.json").value;

  return {
    schema: "xyz.tinycloud.listen/m1-owner-demo-artifact/v1",
    mode: options.mode,
    input: {
      selectedTranscriptIds: [...input.selectedTranscriptIds],
      ownerDid: ownerDid(input),
      createdAt,
      expiresAt,
    },
    composition: {
      capabilities: draft.capabilities,
      disclosure: draft.disclosure,
    },
    publish: {
      shareId: published.shareId,
      policyId: published.policyId,
      activeStatusId: String(activeStatus.statusId),
      engineRecordId,
      policyPath: published.policyPath,
      statusPath: published.statusPath,
      bootstrapPath: published.bootstrapPath,
      engineRecordPath: published.engineRecordPath,
      bootstrap: published.bootstrap,
      writeSet: writeSetSummary(publishWrites),
    },
    revoke: {
      shareId: revoked.shareId,
      policyId: revoked.policyId,
      revokedStatusId: String(revokedStatus.statusId),
      statusPath: revoked.statusPath,
      disposition: "revoked",
      receipt: {
        status: revoked.status,
        updatedAt: revoked.updatedAt,
      },
    },
  };
}

export function canonicalJson(value: Json | unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map(
        (key) => `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`,
      )
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function readInput(path: string | undefined): OwnerDemoInput {
  if (!path) return dryRunInput();
  return JSON.parse(readFileSync(path, "utf8")) as OwnerDemoInput;
}

function parseArgs(argv: string[]) {
  const args = new Map<string, string | true>();
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]!;
    if (!arg.startsWith("--")) continue;
    const key = arg.slice(2);
    const next = argv[index + 1];
    if (!next || next.startsWith("--")) {
      args.set(key, true);
    } else {
      args.set(key, next);
      index += 1;
    }
  }
  const signerCommand = args.get("signer-command");
  return {
    mode: args.has("dry-run") ? "dry-run" : "live",
    inputPath: stringArg(args.get("input")),
    outPath: stringArg(args.get("out")),
    nodeEndpoint: stringArg(args.get("node-endpoint")),
    signerCommand:
      signerCommand === true || signerCommand === undefined ? undefined : signerCommand.split(" "),
  } as const;
}

function stringArg(value: string | true | undefined): string | undefined {
  return typeof value === "string" ? value : undefined;
}

export async function runCli(argv: string[] = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const artifact = await runOwnerDemo({
    input: readInput(args.inputPath),
    mode: args.mode,
    nodeEndpoint: args.nodeEndpoint,
    signerCommand: args.signerCommand,
  });
  const output = `${canonicalJson(artifact)}\n`;
  if (args.outPath) {
    writeFileSync(args.outPath, output);
  } else {
    process.stdout.write(output);
  }
}

if (import.meta.main) {
  runCli().catch((err) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  });
}

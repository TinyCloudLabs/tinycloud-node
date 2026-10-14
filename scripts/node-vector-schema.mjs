import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const schemaPath = `${root}log-shipper/fields.json`;
const vectorPath = `${root}log-shipper/vector.yaml`;
const beginMarker = "# BEGIN GENERATED FROM fields.json";
const endMarker = "# END GENERATED FROM fields.json";

const sourceMessages = {
  "invocation replay insert failed": ["node_warning", "invocation_replay_insert_failed"],
  "invocation replay cleanup failed": ["node_warning", "invocation_replay_cleanup_failed"],
  "dstack socket available but get_info failed: ": ["node_warning", "dstack_get_info_failed"],
  "share-v2 local-tee feature active: deriving a deterministic, non-attested TEE identity from node key material": ["node_warning", "share_local_tee_identity"],
  "retention: delivered hook delivery prune failed": ["node_warning", "retention_hook_delivery_prune_failed"],
  "retention: dead-letter hook delivery prune failed": ["node_warning", "retention_dead_letter_prune_failed"],
  "retention: signed KV ticket prune failed": ["node_warning", "retention_signed_ticket_prune_failed"],
  "quota service returned an invalid body: ": ["node_warning", "quota_invalid_body"],
  "quota service returned ": ["node_warning", "quota_fallback"],
  "failed to load tunnel state; tunnel not started": ["node_warning", "tunnel_state_load_failed"],
  "invalid loopback API address; tunnel not started": ["node_warning", "tunnel_address_invalid"],
  "failed to load link state; LAN listener not started": ["node_warning", "link_state_load_failed"],
  "failed to bind link LAN listener; LAN listener not started": ["node_warning", "link_bind_failed"],
  "failed to build TLS config; LAN listener not started": ["node_warning", "link_tls_config_failed"],
  "link LAN listener exited with error": ["node_error", "link_listener_error"],
  "failed to record link listener bind state": ["node_warning", "link_listener_state_write_failed"],
  "failed to record link listener bind failure": ["node_warning", "link_bind_state_write_failed"],
  "failed to load config for auto-renew": ["node_warning", "link_auto_renew_config_failed"],
  "link auto-renew failed": ["node_warning", "link_auto_renew_failed"],
  "failed to hot-reload renewed link cert": ["node_warning", "link_cert_reload_failed"],
  "failed to reload TLS material after link auto-renew": ["node_warning", "link_listener_cert_reload_failed"],
  "link disable: service delete failed; local state removed anyway": ["node_warning", "link_disable_failed"],
  "link connection error": ["node_warning", "link_connection_error"],
  "link listener accept error": ["node_warning", "link_listener_accept_failed"],
  "webhook delivery attempt failed": ["node_warning", "webhook_delivery_failed"],
  "webhook dispatcher loop failed": ["node_warning", "webhook_dispatcher_failed"],
  "addressed delegation authorization failed": ["node_error", "share_authorization_failed"],
  "native share authorization denied": ["node_error", "share_native_authorization_denied"],
  "native share KV put failed": ["node_error", "share_native_kv_put_failed"],
  "share v2 readiness probe failed": ["node_error", "share_v2_readiness_failed"],
  "share v2 is enabled but shareEmail.invitationPublicKey is unset": ["node_error", "share_invitation_key_missing"],
  "configured share invitation key does not match the node's derived signing key": ["node_error", "share_invitation_key_mismatch"],
  "share/v2 policy challenge denied": ["node_warning", "share_policy_denied"],
  "Failed to get TDX quote: ": ["node_error", "attestation_quote_failed"],
  "failed to read committed hook events": ["node_warning", "hook_events_read_failed"],
  "failed to load kv write hook rows": ["node_warning", "hook_rows_load_failed"],
  "failed to load kv delete hook rows": ["node_warning", "hook_rows_load_failed"],
  "missing committed kv hook row for invocation": ["node_warning", "missing_committed_hook_row"],
  "database write committed but webhook enqueue failed": ["node_warning", "webhook_enqueue_failed"],
  "tunnel: failed to prepare connection attempt": ["node_warning", "tunnel_connection_prepare_failed"],
  "tunnel: no frame within idle timeout; treating connection as dead": ["node_warning", "tunnel_idle_timeout"],
  "tunnel: read error": ["node_warning", "tunnel_read_failed"],
  "tunnel: dropping malformed frame": ["node_warning", "tunnel_malformed_frame"],
  "tunnel: relay sent an error frame": ["node_warning", "tunnel_relay_error"],
  "tunnel: failed to write frame": ["node_warning", "tunnel_write_failed"],
  "tunnel: failed to record runtime state": ["node_warning", "tunnel_state_record_failed"],
  "tunnel: failed to clear runtime state after disable": ["node_warning", "tunnel_state_clear_failed"],
  "tunnel authentication rejected": ["node_warning", "tunnel_auth_rejected"],
};

const quote = (value) => JSON.stringify(value);

function vrlValidationLines(spec, accessor) {
  if (spec.type === "enum") return [
    `if !is_string(${accessor}) { abort }`,
    `${accessor} = to_string!(${accessor})`,
    `if !includes(${JSON.stringify(spec.values)}, ${accessor}) { abort }`,
  ];
  if (spec.type === "integer") return [
    `if !is_integer(${accessor}) { abort }`,
    `${accessor} = to_int!(${accessor})`,
    `if ${accessor} < ${spec.min} || ${accessor} > ${spec.max} { abort }`,
  ];
  if (spec.type === "number") return [
    `if !(is_integer(${accessor}) || is_float(${accessor})) { abort }`,
    `${accessor} = to_float!(${accessor})`,
    `if ${accessor} < ${spec.min} || ${accessor} > ${spec.max} { abort }`,
  ];
  if (spec.type === "boolean") return [`if !is_boolean(${accessor}) { abort }`];
  if (spec.type === "string") return [
    `if !is_string(${accessor}) { abort }`,
    `${accessor} = to_string!(${accessor})`,
    `if length(${accessor}) > ${spec.max_len} { abort }`,
    `if !match!(${accessor}, r'${spec.regex}') { abort }`,
  ];
  throw new Error(`unsupported type for ${spec.type}`);
}
export function renderAllowlist(schema) {

  checkNodeSchema(schema);
  const service = schema.services["tinycloud-node"];

  const lines = [
    beginMarker,
    "if exists(.partial_message) { abort }",
    "if !is_string(.tag) { abort }",
    "tag = .tag",
    "if !is_string(.log) { abort }",
    "j, parse_err = parse_json(.log)",
    "if parse_err != null || !is_object(j) { abort }",
    "out = {}",
    "if tag == \"tinycloud.node\" {",
    "  fields = get(j, [\"fields\"]) ?? null",
    "  if !is_object(fields) { abort }",
    "  level = get(j, [\"level\"]) ?? null",
    "  if !is_string(level) { abort }",
    "  level = downcase!(level)",
    "  if !includes([\"warn\", \"error\"], level) { abort }",
    "  msg = get(fields, [\"message\"]) ?? null",
    "  if !is_string(msg) { abort }",
    "  event = null",
    "  event_code = null",
  ];
  const messagePairs = Object.entries(sourceMessages);
  for (const [index, [message, [event, code]]] of messagePairs.entries()) {
    const condition = message.endsWith(": ") || message === "quota service returned " ? `starts_with!(msg, ${quote(message)})` : `msg == ${quote(message)}`;
    lines.push(`  ${index === 0 ? "if" : "else if"} ${condition} { event = ${quote(event)}; event_code = ${quote(code)} }`);
  }
  lines.push("  else if msg == \"node fatal panic\" { event = \"node_fatal_panic\"; event_code = \"other\" }");
  lines.push("  else { abort }");
  lines.push("  if event == \"node_warning\" && level != \"warn\" { abort }");
  lines.push("  if (event == \"node_error\" || event == \"node_fatal_panic\") && level != \"error\" { abort }");
  lines.push("  level = if event == \"node_warning\" { \"warn\" } else { \"error\" }");
  lines.push("  out.svc = \"api\"");
  lines.push("  out.level = level");
  lines.push("  out.event = event");
  lines.push("  out.event_code = event_code");
  lines.push("  ts = get(j, [\"timestamp\"]) ?? null");
  lines.push("  if !is_string(ts) { abort }");
  lines.push("  parsed_ts, time_err = parse_timestamp(ts, format: \"%+\")");
  lines.push("  if time_err != null { abort }");
  lines.push("  out.ts = format_timestamp!(parsed_ts, format: \"%Y-%m-%dT%H:%M:%S%.3fZ\")");
  lines.push("} else if tag == \"tinycloud.ingress\" {");
  lines.push("  out.svc = \"ingress\"");
  lines.push("  ts = get(j, [\"time\"]) ?? null");
  lines.push("  if !is_string(ts) { abort }");
  lines.push("  parsed_ts, time_err = parse_timestamp(ts, format: \"%+\")");
  lines.push("  if time_err != null { abort }");
  lines.push("  out.ts = format_timestamp!(parsed_ts, format: \"%Y-%m-%dT%H:%M:%S%.3fZ\")");
  lines.push("  route = get(j, [\"route\"]) ?? null");
  lines.push("  if !is_string(route) { abort }");
  lines.push("  route = to_string!(route)");
  lines.push("  if length(route) > 256 { abort }");
  const knownRoutes = service.fields.route.values.filter((value) => value !== "<unmatched>");
  lines.push(`  if !includes(${JSON.stringify(knownRoutes)}, route) { route = "<unmatched>" }`);
  for (const line of vrlValidationLines(service.fields.route, "route")) lines.push(`  ${line}`);
  lines.push("  out.route = route");
  lines.push("  method = get(j, [\"method\"]) ?? null");
  for (const line of vrlValidationLines(service.fields.method, "method")) lines.push(`  ${line}`);
  lines.push("  out.method = method");
  lines.push("  status = get(j, [\"status\"]) ?? null");
  for (const line of vrlValidationLines(service.fields.status, "status")) lines.push(`  ${line}`);
  lines.push("  out.status = status");
  lines.push("  bytes = get(j, [\"bytes\"]) ?? null");
  for (const line of vrlValidationLines(service.fields.bytes_sent, "bytes")) lines.push(`  ${line}`);
  lines.push("  out.bytes_sent = bytes");
  lines.push("  upstream_status_raw = \"-\"");
  lines.push("  if exists(j.upstream_status) { upstream_status_raw = j.upstream_status }");
  lines.push("  if !is_string(upstream_status_raw) { abort }");
  lines.push("  upstream_status_raw = to_string!(upstream_status_raw)");
  lines.push("  if length(upstream_status_raw) > 63 { abort }");
  lines.push("  upstream_status = \"\"");
  lines.push("  if upstream_status_raw != \"-\" && upstream_status_raw != \"\" {");
  lines.push("    if !match!(upstream_status_raw, r'^[1-5][0-9]{2}(, ?[1-5][0-9]{2})*$') { abort }");
  lines.push("    upstream_status = slice!(upstream_status_raw, 0, 3)");
  lines.push("  }");
  for (const line of vrlValidationLines(service.fields.upstream_status, "upstream_status")) lines.push(`  ${line}`);
  lines.push("  out.upstream_status = upstream_status");
  lines.push("  request_time = get(j, [\"request_time\"]) ?? null");
  for (const line of vrlValidationLines(service.fields.request_time_seconds, "request_time")) lines.push(`  ${line}`);
  lines.push("  out.request_time_seconds = request_time");
  lines.push("  status_class = if status >= 500 { \"5xx\" } else if status >= 400 { \"4xx\" } else if status >= 300 { \"3xx\" } else if status >= 200 { \"2xx\" } else { \"1xx\" }");
  lines.push("  out.status_class = status_class");
  lines.push("  if status >= 400 { out.level = if status >= 500 { \"error\" } else { \"warn\" }; out.event = \"ingress_failure_count\"; out.request_count = 1 }");
  lines.push("  else if status >= 200 && status < 300 { out.level = \"info\"; out.event = \"ingress_success_count\"; out.request_count = 1 }");
  lines.push("  else if request_time >= 1 { out.level = \"warn\"; out.event = \"ingress_request_slow\" }");
  lines.push("  else { abort }");
  lines.push("} else { abort }");
  lines.push(". = out");
  lines.push("if length(encode_json(.)) > 280 { abort }");
  lines.push(endMarker);
  return lines.join("\n");
}

export function checkVectorFile(schema, yaml = readFileSync(vectorPath, "utf8")) {
  const match = yaml.match(/# BEGIN GENERATED FROM fields\.json[\s\S]*?# END GENERATED FROM fields\.json/);
  if (!match) throw new Error("vector.yaml is missing generated allowlist markers");
  const actual = match[0].split("\n").map((line) => line.replace(/^      /, "")).join("\n");
  if (actual !== renderAllowlist(schema)) throw new Error("vector.yaml allowlist differs from fields.json-generated VRL");
  for (const name of ["allowlist", "slow_success", "request_minute", "request_output", "budget_size_guard"]) {
    const block = yaml.match(new RegExp(`^  ${name}:\\n([\\s\\S]*?)(?=\\n  [a-z][a-z0-9_]*:\\n|\\nsinks:)`, "m"))?.[1];
    if (!block?.includes("type: remap") || !block.includes("drop_on_error: true")) throw new Error(`${name} remap must set drop_on_error: true`);
  }
  const requestOutput = yaml.match(/  request_output:\n([\s\S]*?)(?=\n  [a-z][a-z0-9_]*:\n|$)/)?.[1];
  if (!requestOutput?.includes("drop_on_abort: true")) throw new Error("request_output must drop aborts");
  const count = schema.services["tinycloud-node"].fields.request_count;
  const countGuard = `if !is_integer(count) { abort }\n      count = to_int!(count)\n      if count < ${count.min} || count > ${count.max} { abort }`;
  if (!requestOutput.includes(countGuard)) throw new Error("request output count bounds differ from fields.json");
  const requiredBudgetConfig = [
    "panic: .event == \"node_fatal_panic\"",
    "app_error: .event == \"node_error\"",
    "app_warning: .event == \"node_warning\"",
    "ingress_summary: .event == \"ingress_failure_count\" || .event == \"ingress_success_count\"",
    "group_by: [route, status_class, event, minute]",
    "inputs: [classify_by_budget.panic]",
    "threshold: 2",
    "inputs: [classify_by_budget.app_error]",
    "threshold: 5",
    "inputs: [classify_by_budget.app_warning]",
    "inputs: [request_output, classify_by_budget.ingress_slow, slow_success, throttle_app_warning]",
    "threshold: 27",
    "expire_after_ms: 75000",
    "end_every_period_ms: 60000",
    "flush_period_ms: 1000",
    "if length(encode_json(.)) > 280 { abort }",
    "inputs: [throttle_panic, throttle_app_error, throttle_ingress]",
  ];
  if (requiredBudgetConfig.some((line) => !yaml.includes(line))) throw new Error("Vector priority lanes, counters, reduce timers, or event-size bound differ from reviewed budget");
  const monthlyBudgetBytes = (2 + 5 + 5 + 27) * 60 * 24 * 30 * 281;
  if (monthlyBudgetBytes > 480000000) throw new Error(`Vector event budget exceeds 0.48 GB/month: ${monthlyBudgetBytes} bytes`);
  if ((yaml.match(/threshold: 5\n/g) ?? []).length !== 2) throw new Error("node error and warning lanes must each be capped at five events/minute");
}
export function renderComposeVectorConfig(vectorYaml) {
  return vectorYaml.trimEnd().split("\n").map((line) => `        ${line.replaceAll("$", () => "$$")}`).join("\n");
}

export function checkComposeVectorConfig(compose = readFileSync(`${root}docker-compose.dstack-postgres.yaml`, "utf8"), vectorYaml = readFileSync(vectorPath, "utf8")) {
  const start = compose.indexOf("      VECTOR_CONFIG_YAML: |\n");
  const end = compose.indexOf("    entrypoint:", start);
  if (start < 0 || end < 0) throw new Error("compose Vector config block not found");
  const actual = compose.slice(start + "      VECTOR_CONFIG_YAML: |\n".length, end)
    .split("\n")
    .filter((line) => line.startsWith("        "))
    .map((line) => line.slice(8).replaceAll("$$", "$"))
    .join("\n")
    .replace(/\n+$/, "");
  if (actual !== vectorYaml.trimEnd()) throw new Error("compose Vector config differs from log-shipper/vector.yaml");
}

function writeComposeVectorConfig() {
  const composePath = `${root}docker-compose.dstack-postgres.yaml`;
  const compose = readFileSync(composePath, "utf8");
  const start = compose.indexOf("      VECTOR_CONFIG_YAML: |\n");
  const end = compose.indexOf("    entrypoint:", start);
  if (start < 0 || end < 0) throw new Error("compose Vector config block not found");
  const block = `      VECTOR_CONFIG_YAML: |\n${renderComposeVectorConfig(readFileSync(vectorPath, "utf8"))}\n`;
  writeFileSync(composePath, `${compose.slice(0, start)}${block}${compose.slice(end)}`);
}

export function checkNodeSchema(schema) {
  const service = schema.services?.["tinycloud-node"];
  if (!service) throw new Error("fields.json has no services.tinycloud-node section");
  if (Object.keys(schema.common ?? {}).sort().join(",") !== "event,level,ts") throw new Error("common must contain exactly level, ts and event");
  if (JSON.stringify(schema.common.level) !== JSON.stringify({ type: "enum", values: ["debug", "info", "warn", "error"] })) throw new Error("common.level differs from the emitted level allowlist");
  if (JSON.stringify(schema.common.ts) !== JSON.stringify({ type: "string", regex: "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$", max_len: 24 })) throw new Error("common.ts differs from the emitted timestamp format");
  if (schema.common.event?.type !== "event") throw new Error("common.event must use event type");
  if (service.events.join(",") !== "node_fatal_panic,node_warning,node_error,ingress_failure_count,ingress_request_slow,ingress_success_count") throw new Error("tinycloud-node event set differs from the reviewed set");
  if (Object.values(sourceMessages).some(([, code]) => !new Set(service.fields.event_code?.values ?? []).has(code))) throw new Error("source message map contains an event_code missing from fields.json");
  if (Object.keys(service.fields).sort().join(",") !== [
    "bytes_sent", "event_code", "method", "request_count", "request_time_seconds", "route", "status", "status_class", "svc", "upstream_status",
  ].sort().join(",")) throw new Error("tinycloud-node fields differ from the reviewed field set");
  if (service.fields.request_count?.type !== "integer" || service.fields.request_count.min !== 1 || service.fields.request_count.max !== 1000000) throw new Error("request_count must remain bounded to 1..1000000");
  if (service.fields.route?.type !== "enum" || service.fields.route.values.length !== 36 || !service.fields.route.values.includes("<unmatched>")) throw new Error("route output must be a 36-value bounded enum including <unmatched>");
  if (JSON.stringify(service.fields.svc) !== JSON.stringify({ type: "enum", values: ["api", "ingress"] })) throw new Error("svc enum differs from emitted values");
  if (JSON.stringify(service.fields.status_class) !== JSON.stringify({ type: "enum", values: ["1xx", "2xx", "3xx", "4xx", "5xx"] })) throw new Error("status_class enum differs from emitted values");
  if (service.fields.event_code?.type !== "enum" || !service.fields.event_code.values.includes("other")) throw new Error("event_code must preserve the fixed panic other value");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
  const rendered = renderAllowlist(schema);
  if (process.argv.includes("--check")) checkVectorFile(schema);
  else if (process.argv.includes("--write")) {
    const yaml = readFileSync(vectorPath, "utf8");
    const block = rendered.split("\n").map((line) => `      ${line}`).join("\n");
    const updated = yaml.replace(/      # BEGIN GENERATED FROM fields\.json[\s\S]*?      # END GENERATED FROM fields\.json/, () => block);
    if (!yaml.includes("# BEGIN GENERATED FROM fields.json") || !yaml.includes("# END GENERATED FROM fields.json")) throw new Error("vector.yaml is missing generated allowlist markers");
    if (updated !== yaml) writeFileSync(vectorPath, updated);
  } else if (process.argv.includes("--write-compose")) writeComposeVectorConfig();
  else if (process.argv.includes("--check-compose")) checkComposeVectorConfig();
  else process.stdout.write(`${rendered}\n`);
}

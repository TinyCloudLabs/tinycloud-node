import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { checkComposeDeploymentPackaging, checkVectorFile, renderAllowlist, renderComposeVectorConfig } from "./node-vector-schema.mjs";

const workflow = readFileSync(new URL("../.github/workflows/rust.yml", import.meta.url), "utf8");
const schema = JSON.parse(readFileSync(new URL("../log-shipper/fields.json", import.meta.url), "utf8"));
const compose = readFileSync(new URL("../docker-compose.dstack-postgres.yaml", import.meta.url), "utf8");
const deployWorkflow = readFileSync(new URL("../.github/workflows/docker.yml", import.meta.url), "utf8");
const vector = readFileSync(new URL("../log-shipper/vector.yaml", import.meta.url), "utf8");

test("generated allowlist emits known fixed messages and builds output from validated fields", () => {
  const result = renderAllowlist(schema);
  assert.match(result, /msg == "invocation replay insert failed"/);
  assert.match(result, /event_code = "invocation_replay_insert_failed"/);
  assert.match(result, /out = \{\}/);
  assert.doesNotMatch(result, /out\.message|out\.msg|\. = j/);
  assert.match(result, /parse_err != null \|\| !is_object\(j\) \{ abort \}/);
  assert.match(result, /if exists\(\.partial_message\) \{ abort \}/);
  assert.match(result, /if !is_string\(route\) \{ abort \}[\s\S]*if length\(route\) > 256 \{ abort \}/);
  assert.match(result, /if !includes\(\[.*\/healthz.*\], route\) \{ route = "<unmatched>" \}/);
  assert.doesNotMatch(result, /if length\(encode_json\(\.\)\) > 280/);
  assert.match(result, /upstream_status_raw, r'\^\[1-5\]\[0-9\]\{2\}\(, \?\[1-5\]\[0-9\]\{2\}\| : \[1-5\]\[0-9\]\{2\}\)\*\$'/);
  assert.match(result, /event_code = "other"/);
  assert.match(result, /level = if event == "node_warning" \{ "warn" \} else \{ "error" \}/);
});

test("unknown event message and malformed allowed values abort instead of forwarding", () => {
  const result = renderAllowlist(schema);
  assert.match(result, /else \{ abort \}/);
  assert.match(result, /if !is_integer\(status\) \{ abort \}[\s\S]*if status < 100 \|\| status > 599 \{ abort \}/);
});

test("generator rejects schema drift outside common and tinycloud-node", () => {
  assert.throws(() => renderAllowlist({ ...schema, common: { ...schema.common, reader_output: {} } }), /common/);
  assert.throws(() => renderAllowlist({ ...schema, services: {} }), /tinycloud-node/);
  assert.throws(
    () => renderAllowlist({ ...schema, common: { ...schema.common, level: { type: "enum", values: ["warn", "error"] } } }),
    /common\.level/,
  );
  assert.throws(
    () => renderAllowlist({
      ...schema,
      services: {
        ...schema.services,
        "tinycloud-node": {
          ...schema.services["tinycloud-node"],
          fields: {
            ...schema.services["tinycloud-node"].fields,
            request_count: { type: "integer", min: 1, max: 1000001 },
          },
        },
      },
    }),
    /request_count/,
  );
});
test("generator rejects incompatible enums and removed event codes", () => {
  const withField = (name, field) => ({
    ...schema,
    services: {
      ...schema.services,
      "tinycloud-node": {
        ...schema.services["tinycloud-node"],
        fields: { ...schema.services["tinycloud-node"].fields, [name]: field },
      },
    },
  });
  assert.throws(() => renderAllowlist(withField("svc", { type: "enum", values: ["api"] })), /svc enum/);
  assert.throws(() => renderAllowlist(withField("status_class", { type: "enum", values: ["2xx", "4xx"] })), /status_class enum/);
  assert.throws(
    () => renderAllowlist(withField("event_code", {
      ...schema.services["tinycloud-node"].fields.event_code,
      values: schema.services["tinycloud-node"].fields.event_code.values.filter((value) => value !== "invocation_replay_insert_failed"),
    })),
    /event_code missing/,
  );
  assert.throws(
    () => renderAllowlist(withField("event_code", {
      ...schema.services["tinycloud-node"].fields.event_code,
      values: schema.services["tinycloud-node"].fields.event_code.values.filter((value) => value !== "other"),
    })),
    /panic other value/,
  );
});
test("success counter validates its bounded output and abort policy", () => {
  assert.doesNotThrow(() => checkVectorFile(schema));
});
test("CI runs native Vector validation and tests after checking the pinned release checksum", () => {
  assert.match(workflow, /version=0\.59\.0/);
  assert.match(workflow, /expected_sha256=a8dbc43c18ae25d0b23a712c9262f3aad904e352b1db5e7db1d9c4aecab59496/);
  assert.match(workflow, /sha256sum --check --ignore-missing/);
  assert.match(workflow, /validate --no-environment log-shipper\/vector\.yaml/);
  assert.match(workflow, /test log-shipper\/vector\.yaml log-shipper\/vector\.tests\.yaml/);
});

test("deployed compose rejects file-backed configs, env_file, and relative bind sources", () => {
  for (const invalid of [
    "services:\n  vector:\n    env_file: .env",
    "configs:\n  vector:\n    file: ./vector.yaml",
    "services:\n  vector:\n    volumes:\n      - ./vector.yaml:/etc/vector/vector.yaml:ro",
    "services:\n  vector:\n    volumes:\n      - type: bind\n        source: ../vector.yaml\n        target: /etc/vector/vector.yaml",
    "services:\n  vector:\n    volumes:\n      - type: bind\n        source: ${LOCAL_CONFIG_PATH}\n        target: /etc/vector/vector.yaml",
  ]) {
    assert.throws(() => checkComposeDeploymentPackaging(invalid), /Compose packaging/);
  }
  assert.doesNotThrow(() => checkComposeDeploymentPackaging(compose));
});
test("compose embeds source Vector config without allowing Compose to interpolate its regexes", () => {
  assert.equal(
    renderComposeVectorConfig("sources:\n  test: true\nregex: ^[a-z]+$\ntoken: ${BETTERSTACK_SOURCE_TOKEN}"),
    "        sources:\n          test: true\n        regex: ^[a-z]+$$\n        token: $${BETTERSTACK_SOURCE_TOKEN}",
  );
});
test("missing Better Stack token leaves node and ingress startup independent", () => {
  assert.match(compose, /BETTERSTACK_SOURCE_TOKEN: "\$\{BETTERSTACK_SOURCE_TOKEN:-\}"/);
  assert.doesNotMatch(compose, /BETTERSTACK_SOURCE_TOKEN[^\n]*:\?/);
  const node = compose.slice(compose.indexOf("  tinycloud:\n"), compose.indexOf("  dstack-ingress:\n"));
  const ingress = compose.slice(compose.indexOf("  dstack-ingress:\n"), compose.indexOf("  ssh-gateway:\n"));
  assert.doesNotMatch(node, /depends_on:[\s\S]*?vector/);
  assert.doesNotMatch(ingress, /depends_on:[\s\S]*?vector/);
  assert.match(node, /driver: gelf[\s\S]*gelf-address: udp:\/\/127\.0\.0\.1:12201[\s\S]*labels: "tc\.logship"/);
  assert.match(ingress, /driver: gelf[\s\S]*gelf-address: udp:\/\/127\.0\.0\.1:12201[\s\S]*labels: "tc\.logship"/);
  assert.match(compose, /Better Stack token is absent; Vector is idle/);
  const requiredVarsStart = deployWorkflow.indexOf("required_vars=(");
  const requiredVarsEnd = deployWorkflow.indexOf("\n          )", requiredVarsStart);
  assert.ok(requiredVarsStart >= 0 && requiredVarsEnd > requiredVarsStart);
  assert.doesNotMatch(deployWorkflow.slice(requiredVarsStart, requiredVarsEnd), /BETTERSTACK_SOURCE_TOKEN/);
  assert.ok(
    deployWorkflow.indexOf("phala deploy --cvm-id tinycloud-node") <
      deployWorkflow.indexOf("name: Sync production allowed_envs"),
    "allowed_envs sync must not gate compose startup",
  );
});
test("WARN lane bypasses the ingress throttle and stays behind the size guard", () => {
  assert.match(vector, /throttle_app_warning:\n    type: throttle\n    inputs: \[classify_by_budget\.app_warning\]\n    window_secs: 60\n    threshold: 5/);
  assert.match(vector, /throttle_ingress:\n    type: throttle\n    inputs: \[request_output, classify_by_budget\.ingress_slow, slow_success\]\n    window_secs: 60\n    threshold: 27/);
  assert.match(vector, /budget_size_guard:\n    type: remap\n    inputs: \[throttle_panic, throttle_app_error, throttle_app_warning, throttle_ingress\]/);
  assert.match(vector, /sinks:\n  betterstack:\n    type: http\n    inputs: \[budget_size_guard\]/);
});

test("node schema includes bounded fixed logship counter events", () => {
  assert.ok(schema.services["tinycloud-node"].events.includes("logship_gate_dropped_total"));
  assert.ok(schema.services["tinycloud-node"].events.includes("logship_unexpected_label"));
  assert.deepEqual(schema.services["tinycloud-node"].fields.svc.values, ["api", "ingress", "logship"]);
  assert.deepEqual(schema.services["tinycloud-node"].fields.reason.values, ["malformed_envelope", "unexpected_label", "unknown_message", "unlabelled"]);
  assert.deepEqual(schema.services["tinycloud-node"].fields.count, { type: "integer", min: 1, max: 1000000000 });
});

test("first transform gates GELF labels before field stripping and JSON parsing", () => {
  const firstTransform = vector.match(/transforms:\n\s{2}([a-z][a-z0-9_]*):/);
  assert.equal(firstTransform?.[1], "logship_gate");
  assert.match(vector, /gelf_in:\n    type: socket\n    mode: udp\n    address: 0\.0\.0\.0:12201\n    max_length: 262144\n    framing: \{ method: chunked_gelf, chunked_gelf: \{ decompression: Auto \} \}\n    decoding: \{ codec: gelf \}/);
  assert.match(vector, /lbl = string\(get\(\., \["_tc\.logship"\]\) \?\? null\) \?\? ""/);
  assert.ok(vector.indexOf("  logship_gate:") < vector.indexOf("  strip_gelf_fields:"));
  assert.ok(vector.indexOf("  strip_gelf_fields:") < vector.indexOf("  parse_gelf_message:"));
  assert.ok(vector.indexOf("  parse_gelf_message:") < vector.indexOf("  allowlist:"));
  assert.doesNotMatch(vector, /docker_files|parse_docker_envelope|read_from:/);
  assert.match(compose, /driver: gelf[\s\S]*gelf-address: udp:\/\/127\.0\.0\.1:12201[\s\S]*labels: "tc\.logship"/);
  assert.match(compose, /127\.0\.0\.1:12201:12201\/udp/);
  assert.match(compose, /ipv4_address: 10\.255\.253\.2/);
  const nodeService = compose.slice(compose.indexOf("  tinycloud:\n"), compose.indexOf("  dstack-ingress:\n"));
  const ingressStart = compose.indexOf("  dstack-ingress:\n");
  const ingressService = compose.slice(ingressStart, compose.indexOf("  ssh-gateway:\n", ingressStart));
  const sshStart = compose.indexOf("  ssh-gateway:\n");
  const sshService = compose.slice(sshStart, compose.indexOf("  vector:\n", sshStart));
  const vectorStart = compose.indexOf("  vector:\n");
  const vectorService = compose.slice(vectorStart, compose.indexOf("\nvolumes:\n", vectorStart));
  assert.match(nodeService, /labels:\n\s+tc\.logship: "tinycloud-node"/);
  assert.match(ingressService, /labels:\n\s+tc\.logship: "tinycloud-ingress"/);
  assert.match(sshService, /driver: json-file[\s\S]*max-size: "10m"[\s\S]*max-file: "3"/);
  assert.doesNotMatch(sshService, /tc\.logship/);
  assert.match(vectorService, /user: "10001:10001"[\s\S]*read_only: true[\s\S]*cap_drop: \[ALL\][\s\S]*mem_limit: 64m/);
  assert.match(vectorService, /tmpfs:\n\s+- \/var\/lib\/vector:rw,noexec,nosuid,size=8m/);
  assert.match(vectorService, /networks:\n\s+logship:\n\s+ipv4_address: 10\.255\.253\.2/);
  const vectorPorts = [...vectorService.matchAll(/^\s+- "([^"]+)"$/gm)].map((match) => match[1]).filter((port) => port.includes(":12201:"));
  assert.deepEqual(vectorPorts, ["127.0.0.1:12201:12201/udp"]);
  assert.match(vectorService, /driver: json-file[\s\S]*max-size: "10m"[\s\S]*max-file: "3"/);
  assert.doesNotMatch(vectorService, /labels:\n\s+tc\.logship:/);
  assert.doesNotMatch(compose, /fluentd|\/var\/lib\/docker|docker\.sock/);
  assert.match(compose, /networks:\n  logship:\n    driver: bridge\n    ipam:\n      config:\n        - subnet: 10\.255\.253\.0\/28/);
});

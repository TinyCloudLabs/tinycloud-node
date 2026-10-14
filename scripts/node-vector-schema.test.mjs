import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { checkVectorFile, renderAllowlist, renderComposeVectorConfig } from "./node-vector-schema.mjs";

const workflow = readFileSync(new URL("../.github/workflows/rust.yml", import.meta.url), "utf8");
const schema = JSON.parse(readFileSync(new URL("../log-shipper/fields.json", import.meta.url), "utf8"));
const compose = readFileSync(new URL("../docker-compose.dstack-postgres.yaml", import.meta.url), "utf8");
const deployWorkflow = readFileSync(new URL("../.github/workflows/docker.yml", import.meta.url), "utf8");

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
  assert.match(result, /length\(encode_json\(\.\)\) > 280/);
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
test("compose embeds source Vector config without allowing Compose to interpolate its regexes", () => {
  assert.equal(
    renderComposeVectorConfig("sources:\n  test: true\nregex: ^[a-z]+$"),
    "        sources:\n          test: true\n        regex: ^[a-z]+$$",
  );
});
test("missing Better Stack token leaves node and ingress startup independent", () => {
  assert.match(compose, /BETTERSTACK_SOURCE_TOKEN: "\$\{BETTERSTACK_SOURCE_TOKEN:-\}"/);
  assert.doesNotMatch(compose, /BETTERSTACK_SOURCE_TOKEN[^\n]*:\?/);
  const node = compose.slice(compose.indexOf("  tinycloud:\n"), compose.indexOf("  dstack-ingress:\n"));
  const ingress = compose.slice(compose.indexOf("  dstack-ingress:\n"), compose.indexOf("  ssh-gateway:\n"));
  assert.doesNotMatch(node, /depends_on:[\s\S]*?vector/);
  assert.doesNotMatch(ingress, /depends_on:[\s\S]*?vector/);
  assert.match(node, /fluentd-async: "true"/);
  assert.match(ingress, /fluentd-async: "true"/);
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

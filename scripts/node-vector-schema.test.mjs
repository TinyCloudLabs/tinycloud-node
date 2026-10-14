import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { checkVectorFile, renderAllowlist, renderComposeVectorConfig } from "./node-vector-schema.mjs";

const schema = JSON.parse(readFileSync(new URL("../log-shipper/fields.json", import.meta.url), "utf8"));

test("generated allowlist emits known fixed messages and builds output from validated fields", () => {
  const result = renderAllowlist(schema);
  assert.match(result, /msg == "invocation replay insert failed"/);
  assert.match(result, /event_code = "invocation_replay_insert_failed"/);
  assert.match(result, /out = \{\}/);
  assert.doesNotMatch(result, /out\.message|out\.msg|\. = j/);
  assert.match(result, /parse_err != null \|\| !is_object\(j\) \{ abort \}/);
  assert.match(result, /if exists\(\.partial_message\) \{ abort \}/);
});

test("unknown event message and malformed allowed values abort instead of forwarding", () => {
  const result = renderAllowlist(schema);
  assert.match(result, /else \{ abort \}/);
  assert.match(result, /is_integer\(status\) && status >= 100 && status <= 599/);
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
test("success counter validates its bounded output and abort policy", () => {
  assert.doesNotThrow(() => checkVectorFile(schema));
});
test("compose embeds source Vector config without allowing Compose to interpolate its regexes", () => {
  assert.equal(
    renderComposeVectorConfig("sources:\n  test: true\nregex: ^[a-z]+$"),
    "        sources:\n          test: true\n        regex: ^[a-z]+$$",
  );
});

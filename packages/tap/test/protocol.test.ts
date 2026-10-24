import assert from "node:assert/strict";
import { test } from "node:test";

import { parseDictionary } from "../src/sfv.ts";
import { promiseApi, runConformance } from "./conformance.ts";

test("structured fields reject ambiguous and malformed input", () => {
  const parsed = parseDictionary('sig1=("@authority" "@path");created=1700000000;keyid="abc"');
  assert.equal(parsed.entries.length, 1);
  assert.throws(() => parseDictionary("a=1, a=2"), /duplicate dictionary key/);
  assert.throws(() => parseDictionary("a=01"), /leading zero/);
  assert.equal(parseDictionary('a="hi\\""').entries[0]?.value.type, "item");
});

test("promise API conformance", async () => {
  await runConformance(promiseApi());
});

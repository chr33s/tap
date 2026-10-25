import assert from "node:assert/strict";
import { test } from "node:test";

import { assertSafeRequestTarget, parseTarget } from "tap";

import { parseDictionary } from "../src/sfv.ts";
import { promiseApi, runConformance } from "./conformance.ts";

test("structured fields reject ambiguous and malformed input", () => {
  const parsed = parseDictionary('sig1=("@authority" "@path");created=1700000000;keyid="abc"');
  assert.equal(parsed.entries.length, 1);
  assert.throws(() => parseDictionary("a=1, a=2"), /duplicate dictionary key/);
  assert.throws(() => parseDictionary("a=01"), /leading zero/);
  assert.equal(parseDictionary('a="hi\\""').entries[0]?.value.type, "item");
  assert.equal(parseDictionary("a=foo-bar").entries[0]?.value.type, "item");
  assert.equal(parseDictionary("a=(b);tag=agent-browser-auth").entries.length, 1);
});

test("request targets reject fragments, backslashes, and dot segments", () => {
  assert.equal(parseTarget("https://example.com/product/1?q=1").tapPath, "/product/1");
  assert.throws(() => parseTarget("https://example.com/product/../admin"), /dot segment/);
  assert.throws(() => parseTarget("https://example.com/product/%2e%2e/admin"), /dot segment/);
  assert.throws(() => parseTarget("https://example.com/product/%2E/%2e%2E/x"), /dot segment/);
  assert.throws(() => parseTarget("https://example.com/product/1#x"), /fragment/);
  assert.throws(() => parseTarget("https://example.com/a\\b"), /backslash/);
  // The proxy boundary applies the same path rules as the verifier.
  assertSafeRequestTarget("/product/1?q=%2e%2e");
  assert.throws(() => assertSafeRequestTarget("/product/%2e%2e/admin"), /dot segment/);
  assert.throws(() => assertSafeRequestTarget("/product/1#x"), /fragment/);
  assert.throws(() => assertSafeRequestTarget("/a\\b"), /backslash/);
  assert.throws(() => assertSafeRequestTarget("/a?b\\c"), /backslash/);
  assert.throws(() => assertSafeRequestTarget("/a\tb"), /control character/);
  assert.throws(() => assertSafeRequestTarget("product"), /invalid request target/);
});

test("promise API conformance", async () => {
  await runConformance(promiseApi());
});

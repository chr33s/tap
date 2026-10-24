import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { test } from "node:test";

import {
  createManualClock,
  createMemoryReplayStore,
  createSigner,
  createStaticKeyResolver,
  createTapClient,
  createTapVerifier,
  generateKeyPair,
  type ResolvedKey,
} from "tap";

const require = createRequire(import.meta.url);
const pinned = require("../../../fixtures/pinned-js-verifier.mjs") as {
  parseRFC9421SignatureInput(input: string): { params: string[] };
  buildRFC9421SignatureString(params: string[], requestData: { authority: string; path: string }, header: string): string;
  verifyEd25519Signature(publicKey: string, signature: string, base: string): boolean;
  verifyRSASignature(publicKey: string, signature: string, base: string): boolean;
};

test("legacySample matches the pinned JavaScript verifier and Python signer", async () => {
  const pair = generateKeyPair("ed25519");
  const clock = createManualClock(1_700_000_100_000);
  const client = createTapClient({
    keyId: "primary-ed25519",
    profile: "legacySample",
    signer: createSigner("ed25519", pair.privateKey),
    clock,
    nonce: () => "nonce-legacy-1",
  });
  const url = "http://Example.COM:8080/product/1?q=1";
  const headers = await client.signRequest(
    { method: "GET", url, headers: [["host", "Example.COM:8080"]] },
    { tag: "agent-browser-auth" },
  );
  assert.match(headers["Signature-Input"], /^sig2=\("@authority" "@path"\); created=1700000100; expires=1700000580; keyId="primary-ed25519"; alg="ed25519"; nonce="nonce-legacy-1"; tag="agent-browser-auth"$/);
  const parsed = pinned.parseRFC9421SignatureInput(headers["Signature-Input"]);
  const base = pinned.buildRFC9421SignatureString(parsed.params, { authority: "Example.COM:8080", path: "/product/1?q=1" }, headers["Signature-Input"]);
  const signature = headers.Signature.slice("sig2=:".length, -1);
  assert.equal(pinned.verifyEd25519Signature(pair.publicKey, signature, base), true);

  const pythonBase = python({
    op: "base",
    authority: "Example.COM:8080",
    path: "/product/1?q=1",
    keyId: "primary-ed25519",
    nonce: "nonce-legacy-1",
    created: 1700000100,
    expires: 1700000580,
    tag: "agent-browser-auth",
    alg: "ed25519",
  }).base as string;
  assert.equal(base, pythonBase);
  const pythonSig = python({ op: "sign-ed25519", seed: pair.privateKey.trim(), base }).signature as string;
  assert.equal(pythonSig, signature);
  python({ op: "verify-ed25519", public: pair.publicKey.trim(), signature, base });

  const key: ResolvedKey = {
    keyId: "primary-ed25519",
    publicKey: pair.publicKey.trim(),
    algorithm: "ed25519",
    agentId: "4",
    agentName: "Legacy",
    agentDomain: "https://legacy.example",
    expiresAt: null,
  };
  const verifier = createTapVerifier({
    profile: "legacySample",
    resolver: createStaticKeyResolver([key]),
    replay: createMemoryReplayStore(clock),
    trustSource: "legacy",
    origins: ["http://example.com:8080"],
    clock,
  });
  const verified = await verifier.verifyRequest(
    {
      method: "GET",
      url,
      headers: [
        ["host", "Example.COM:8080"],
        ["signature-input", headers["Signature-Input"]],
        ["signature", headers.Signature],
      ],
    },
    { tag: "agent-browser-auth" },
  );
  assert.equal(verified.agentId, "4");
  await assert.rejects(
    () => verifier.verifyRequest(
      { method: "GET", url: "http://Example.COM:8080/product/1?q=2", headers: [["signature-input", headers["Signature-Input"]], ["signature", headers.Signature]] },
      { tag: "agent-browser-auth" },
    ),
    (error: unknown) => error instanceof Error && "code" in error && error.code === "invalid_signature",
  );
});

test("RSA-PSS legacy signatures verify in TypeScript, Python, and the pinned verifier", async () => {
  const pair = generateKeyPair("rsa-pss-sha256");
  const clock = createManualClock(1_700_000_100_000);
  const client = createTapClient({
    keyId: "primary",
    profile: "legacySample",
    signer: createSigner("rsa-pss-sha256", pair.privateKey),
    clock,
    nonce: () => "nonce-rsa-1",
  });
  const headers = await client.signRequest(
    { method: "GET", url: "https://merchant.test/product/9", headers: [] },
    { tag: "agent-payer-auth" },
  );
  const parsed = pinned.parseRFC9421SignatureInput(headers["Signature-Input"]);
  const base = pinned.buildRFC9421SignatureString(parsed.params, { authority: "merchant.test", path: "/product/9" }, headers["Signature-Input"]);
  const signature = headers.Signature.slice("sig2=:".length, -1);
  assert.equal(pinned.verifyRSASignature(pair.publicKey, signature, base), true);
  python({ op: "verify-rsa", pem: pair.publicKey, signature, base });
  const foreign = python({ op: "sign-rsa", pem: pair.privateKey, base }).signature as string;
  assert.notEqual(foreign, signature);
  const verifier = createTapVerifier({
    profile: "legacySample",
    resolver: createStaticKeyResolver([{
      keyId: "primary",
      publicKey: pair.publicKey,
      algorithm: "rsa-pss-sha256",
      agentId: "9",
      agentName: "RSA",
      agentDomain: "https://rsa.example",
      expiresAt: null,
    }]),
    replay: createMemoryReplayStore(clock),
    trustSource: "rsa",
    origins: ["https://merchant.test"],
    clock,
  });
  const foreignHeaders = {
    "Signature-Input": headers["Signature-Input"],
    Signature: `sig2=:${foreign}:`,
  };
  const verified = await verifier.verifyRequest(
    {
      method: "GET",
      url: "https://merchant.test/product/9",
      headers: [
        ["signature-input", foreignHeaders["Signature-Input"]],
        ["signature", foreignHeaders.Signature],
      ],
    },
    { tag: "agent-payer-auth" },
  );
  assert.equal(verified.algorithm, "rsa-pss-sha256");
});

function python(payload: Record<string, unknown>): Record<string, unknown> {
  const result = spawnSync("python3", ["fixtures/legacy_interop.py"], {
    input: JSON.stringify(payload),
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout) as Record<string, unknown>;
}

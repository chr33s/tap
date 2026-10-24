import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  createManualClock,
  createMemoryReplayStore,
  createRegistryKeyResolver,
  createSqliteReplayStore,
  createTapClient,
  createSigner,
  createTapVerifier,
  generateKeyPair,
  type ResolvedKey,
} from "tap";

test("sqlite replay survives restart and invalid signatures do not consume nonces", async () => {
  const pair = generateKeyPair("ed25519");
  const clock = createManualClock(1_700_000_200_000);
  const directory = mkdtempSync(join(tmpdir(), "tap-replay-"));
  const file = join(directory, "replay.db");
  const first = createSqliteReplayStore(file, clock);
  const key: ResolvedKey = {
    keyId: "k1",
    publicKey: pair.publicKey.trim(),
    algorithm: "ed25519",
    agentId: "1",
    agentName: "A",
    agentDomain: "https://a.example",
    expiresAt: null,
  };
  const client = createTapClient({
    keyId: "k1",
    profile: "tap",
    signer: createSigner("ed25519", pair.privateKey),
    clock,
    nonce: () => "nonce-store-1",
  });
  const request = { method: "GET", url: "https://example.com/a", headers: [] as Array<[string, string]> };
  const headers = await client.signRequest(request, { tag: "agent-browser-auth" });
  const signed = {
    ...request,
    headers: [
      ["signature-input", headers["Signature-Input"]],
      ["signature", headers.Signature],
    ],
  };
  const bad = {
    ...signed,
    headers: [
      ["signature-input", headers["Signature-Input"]],
      ["signature", headers.Signature.replace("sig1=:", "sig1=:AAAA")],
    ],
  };
  const verifier = () => createTapVerifier({
    profile: "tap",
    resolver: { async resolve() { return key; } },
    replay: first,
    trustSource: "store",
    clock,
  });
  await assert.rejects(() => verifier().verifyRequest(bad, { tag: "agent-browser-auth" }), (error: unknown) =>
    error instanceof Error && "code" in error && error.code === "invalid_signature");
  await verifier().verifyRequest(signed, { tag: "agent-browser-auth" });
  first.close();
  const second = createSqliteReplayStore(file, clock);
  await assert.rejects(
    () => createTapVerifier({
      profile: "tap",
      resolver: { async resolve() { return key; } },
      replay: second,
      trustSource: "store",
      clock,
    }).verifyRequest(signed, { tag: "agent-browser-auth" }),
    (error: unknown) => error instanceof Error && "code" in error && error.code === "replay",
  );
  second.close();
});

test("memory replay rejects expired claim deadlines", async () => {
  const clock = createManualClock(1_000_000);
  const store = createMemoryReplayStore(clock);
  assert.equal(await store.claim({ trustSource: "t", keyId: "k", nonce: "n", until: 1_000 }), "expired");
  assert.equal(await store.claim({ trustSource: "t", keyId: "k", nonce: "n", until: 1_001 }), "claimed");
  assert.equal(await store.claim({ trustSource: "t", keyId: "k", nonce: "n", until: 1_002 }), "duplicate");
});

test("registry cache expires and never serves a stale key after a failed refresh", async () => {
  const clock = createManualClock(1_700_000_000_000);
  let mode: "ok" | "gone" | "down" = "ok";
  const body = {
    key_id: "k1",
    public_key: generateKeyPair("ed25519").publicKey.trim(),
    algorithm: "ed25519",
    is_active: "true",
    agent_id: 3,
    agent_name: "Agent",
    agent_domain: "https://agent.example",
    expires_at: null as number | null,
  };
  const resolver = createRegistryKeyResolver({
    registryUrl: "http://registry.test",
    cacheTtlMs: 5_000,
    transientRetries: 0,
    clock,
    fetchImpl: async () => {
      if (mode === "down") throw new Error("down");
      if (mode === "gone") return new Response("missing", { status: 404 });
      return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
    },
  });
  const first = await resolver.resolve("k1");
  assert.equal(first.agentId, "3");
  mode = "gone";
  assert.equal((await resolver.resolve("k1")).agentId, "3");
  clock.advance(5_001);
  await assert.rejects(() => resolver.resolve("k1"), (error: unknown) =>
    error instanceof Error && "code" in error && error.code === "trust");
  mode = "ok";
  await resolver.resolve("k1");
  mode = "down";
  clock.advance(5_001);
  await assert.rejects(() => resolver.resolve("k1"), (error: unknown) =>
    error instanceof Error && "code" in error && error.code === "resolver_unavailable");
});

test("key cache is capped by expires_at and cancellation is explicit", async () => {
  const clock = createManualClock(1_700_000_000_000);
  let fetches = 0;
  const pair = generateKeyPair("ed25519");
  const resolver = createRegistryKeyResolver({
    registryUrl: "https://registry.test/base",
    cacheTtlMs: 60_000,
    transientRetries: 0,
    clock,
    fetchImpl: async (_url, init) => {
      fetches += 1;
      if (init?.signal?.aborted) {
        throw Object.assign(new Error("aborted"), { name: "AbortError" });
      }
      return new Response(JSON.stringify({
        key_id: "k1",
        public_key: pair.publicKey.trim(),
        algorithm: "ed25519",
        is_active: "true",
        agent_id: 1,
        agent_name: "A",
        agent_domain: "https://a.example",
        expires_at: clock.now() + 2,
      }), { status: 200 });
    },
  });
  await resolver.resolve("k1");
  clock.advance(1_500);
  await resolver.resolve("k1");
  assert.equal(fetches, 1);
  clock.advance(600);
  await resolver.resolve("k1");
  assert.equal(fetches, 2);
  const pending = createRegistryKeyResolver({
    registryUrl: "https://registry.test",
    transientRetries: 2,
    fetchImpl: (_url, init) => new Promise((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => {
        reject(Object.assign(new Error("aborted"), { name: "AbortError" }));
      });
    }),
  });
  const controller = new AbortController();
  const promise = pending.resolve("k1", controller.signal);
  controller.abort();
  await assert.rejects(promise, (error: unknown) => error instanceof Error && "code" in error && error.code === "cancelled");
});

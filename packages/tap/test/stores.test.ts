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
    origins: ["https://example.com"],
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
    origins: ["https://example.com"],
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

test("registry urls outside loopback must be https", () => {
  assert.throws(() => createRegistryKeyResolver({ registryUrl: "http://registry.example" }), (error: unknown) =>
    error instanceof Error && "code" in error && error.code === "policy");
  assert.doesNotThrow(() => createRegistryKeyResolver({ registryUrl: "http://127.0.0.2:9", transientRetries: 0 }));
  assert.doesNotThrow(() => createRegistryKeyResolver({ registryUrl: "https://registry.example", transientRetries: 0 }));
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
    registryUrl: "https://registry.test",
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
  await assert.rejects(() => resolver.resolve("k1"), (error: unknown) =>
    error instanceof Error && "code" in error && error.code === "trust");
  clock.advance(5_001);
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

test("an unrelated signature without a tag does not hide the TAP signature", async () => {
  const pair = generateKeyPair("ed25519");
  const clock = createManualClock(1_700_000_300_000);
  const key: ResolvedKey = {
    keyId: "k1",
    publicKey: pair.publicKey.trim(),
    algorithm: "ed25519",
    agentId: "1",
    agentName: "A",
    agentDomain: "https://a.example",
    expiresAt: null,
  };
  const client = createTapClient({ keyId: "k1", profile: "tap", signer: createSigner("ed25519", pair.privateKey), clock });
  const request = { method: "GET", url: "https://example.com/a", headers: [] as Array<[string, string]> };
  const signed = await client.signRequest(request, { tag: "agent-browser-auth" });
  const verified = await createTapVerifier({
    profile: "tap",
    resolver: { async resolve() { return key; } },
    replay: createMemoryReplayStore(clock),
    trustSource: "store",
    origins: ["https://example.com"],
    clock,
  }).verifyRequest({
    ...request,
    headers: [
      ["signature-input", `sig0=("@authority");created=${clock.now()};keyid="cdn", ${signed["Signature-Input"]}`],
      ["signature", `sig0=:AAAA:, ${signed.Signature}`],
    ],
  }, { tag: "agent-browser-auth" });
  assert.equal(verified.keyId, "k1");
});

test("memory replay drops expired claims", async () => {
  const clock = createManualClock(1_000_000);
  const store = createMemoryReplayStore(clock);
  assert.equal(await store.claim({ trustSource: "t", keyId: "k", nonce: "a", until: 1_001 }), "claimed");
  clock.advance(2_000);
  assert.equal(await store.claim({ trustSource: "t", keyId: "k", nonce: "a", until: 1_010 }), "claimed");
  assert.equal(await store.claim({ trustSource: "t", keyId: "k", nonce: "a", until: 1_010 }), "duplicate");
});

test("sqlite replay reclaims a nonce whose deadline passed before it was pruned", async () => {
  const clock = createManualClock(1_000_000);
  const store = createSqliteReplayStore(":memory:", clock);
  assert.equal(await store.claim({ trustSource: "t", keyId: "k", nonce: "a", until: 1_001 }), "claimed");
  assert.equal(await store.claim({ trustSource: "t", keyId: "k", nonce: "a", until: 1_001 }), "duplicate");
  clock.advance(2_000);
  assert.equal(await store.claim({ trustSource: "t", keyId: "k", nonce: "a", until: 1_010 }), "claimed");
  assert.equal(await store.claim({ trustSource: "t", keyId: "k", nonce: "a", until: 1_010 }), "duplicate");
  store.close();
});

test("registry lookups keep the url prefix, cache misses, and share concurrent requests", async () => {
  const clock = createManualClock(1_700_000_000_000);
  const urls: string[] = [];
  let release: () => void = () => undefined;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const pair = generateKeyPair("ed25519");
  const resolver = createRegistryKeyResolver({
    registryUrl: "https://registry.test/registry",
    cacheTtlMs: 5_000,
    transientRetries: 0,
    clock,
    fetchImpl: async (url) => {
      urls.push(String(url));
      if (String(url).endsWith("/missing")) return new Response("missing", { status: 404 });
      await gate;
      return new Response(JSON.stringify({
        key_id: "k1",
        public_key: pair.publicKey.trim(),
        algorithm: "ed25519",
        is_active: "true",
        agent_id: 1,
        agent_name: "A",
        agent_domain: "https://a.example",
        expires_at: null,
      }), { status: 200 });
    },
  });
  const concurrent = Promise.all(Array.from({ length: 5 }, () => resolver.resolve("k1")));
  release();
  assert.equal((await concurrent).length, 5);
  assert.deepEqual(urls, ["https://registry.test/registry/keys/k1"]);
  for (let i = 0; i < 3; i += 1) {
    await assert.rejects(() => resolver.resolve("missing"), (error: unknown) =>
      error instanceof Error && "code" in error && error.code === "trust");
  }
  assert.equal(urls.filter((url) => url.endsWith("/missing")).length, 1);
  clock.advance(5_001);
  await assert.rejects(() => resolver.resolve("missing"));
  assert.equal(urls.filter((url) => url.endsWith("/missing")).length, 2);
});

test("the verifier rejects other origins before the key lookup and rejects malformed tags and dot key ids", async () => {
  const pair = generateKeyPair("ed25519");
  const clock = createManualClock(1_700_000_400_000);
  let lookups = 0;
  const key: ResolvedKey = {
    keyId: "k1",
    publicKey: pair.publicKey.trim(),
    algorithm: "ed25519",
    agentId: "1",
    agentName: "A",
    agentDomain: "https://a.example",
    expiresAt: null,
  };
  const verifier = createTapVerifier({
    profile: "tap",
    resolver: { async resolve() { lookups += 1; return key; } },
    replay: createMemoryReplayStore(clock),
    trustSource: "store",
    origins: ["https://SHOP-B.example:443"],
    clock,
  });
  const code = (expected: string) => (error: unknown) => error instanceof Error && "code" in error && error.code === expected;
  const client = createTapClient({ keyId: "k1", profile: "tap", signer: createSigner("ed25519", pair.privateKey), clock });
  const signedFor = async (url: string) => {
    const headers = await client.signRequest({ method: "GET", url, headers: [] }, { tag: "agent-browser-auth" });
    return {
      method: "GET",
      url,
      headers: [["signature-input", headers["Signature-Input"]], ["signature", headers.Signature]] as Array<[string, string]>,
    };
  };
  await assert.rejects(async () => verifier.verifyRequest(await signedFor("https://shop-a.example/p"), { tag: "agent-browser-auth" }), code("policy"));
  assert.equal(lookups, 0);
  assert.equal((await verifier.verifyRequest(await signedFor("https://shop-b.example/p"), { tag: "agent-browser-auth" })).keyId, "k1");
  assert.throws(() => createTapVerifier({
    profile: "tap",
    resolver: { async resolve() { return key; } },
    replay: createMemoryReplayStore(clock),
    trustSource: "store",
    origins: [],
  }), code("policy"));

  const created = clock.now();
  const raw = (input: string) => ({
    method: "GET",
    url: "https://shop-b.example/p",
    headers: [["signature-input", input], ["signature", "sig1=:AAAA:"]] as Array<[string, string]>,
  });
  await assert.rejects(() => verifier.verifyRequest(
    raw(`sig1=("@authority" "@path");created=${created};expires=${created + 60};keyid="k1";alg="ed25519";nonce="nonce-tag-1";tag=agent-browser-auth`),
    { tag: "agent-browser-auth" },
  ), code("malformed"));
  await assert.rejects(() => verifier.verifyRequest(
    raw(`sig1=("@authority" "@path");created=${created};expires=${created + 60};keyid="..";alg="ed25519";nonce="nonce-dot-1";tag="agent-browser-auth"`),
    { tag: "agent-browser-auth" },
  ), code("malformed"));
  assert.equal(lookups, 1);
});

test("a flood of unknown key ids cannot evict a registered key", async () => {
  const clock = createManualClock(1_700_000_000_000);
  const pair = generateKeyPair("ed25519");
  let goodFetches = 0;
  const resolver = createRegistryKeyResolver({
    registryUrl: "https://registry.test",
    cacheTtlMs: 30_000,
    transientRetries: 0,
    clock,
    fetchImpl: async (url) => {
      if (!String(url).endsWith("/keys/good")) return new Response("missing", { status: 404 });
      goodFetches += 1;
      return new Response(JSON.stringify({
        key_id: "good",
        public_key: pair.publicKey.trim(),
        algorithm: "ed25519",
        is_active: "true",
        agent_id: 1,
        agent_name: "A",
        agent_domain: "https://a.example",
        expires_at: null,
      }), { status: 200 });
    },
  });
  await resolver.resolve("good");
  for (let i = 0; i < 12_000; i += 1) await resolver.resolve(`miss-${i}`).catch(() => undefined);
  await resolver.resolve("good");
  assert.equal(goodFetches, 1);
});

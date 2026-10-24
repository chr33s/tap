import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { createManualClock, createSigner, createTapClient, generateKeyPair, type ManualClock } from "tap";

import { loadProxyConfig, matchRoute, type ProxyConfig } from "../src/config.ts";
import { startProxy, type ProxyHandle } from "../src/server.ts";
import { startRegistry, type RegistryHandle } from "../../registry/src/server.ts";

const TOKEN = "registry-admin-token";

test("proxy verifies, forwards, replays, and honors revocation within the cache bound", async () => {
  const clock = createManualClock(1_700_000_000_000);
  const directory = mkdtempSync(join(tmpdir(), "tap-proxy-"));
  const echo = await startEcho();
  const registry = await startRegistry({
    host: "127.0.0.1",
    port: 0,
    adminToken: TOKEN,
    databasePath: join(directory, "registry.db"),
    now: () => clock.now(),
  });
  const alpha = generateKeyPair("ed25519");
  const bravo = generateKeyPair("ed25519");
  const agentId = await registerActive(registry, "alpha-1", alpha.publicKey.trim());
  await addKey(registry, agentId, "bravo-1", bravo.publicKey.trim(), true);
  const proxy = await startProxy(await config(echo.url, registry.url, join(directory, "replay.db"), {
    trustedProxies: ["127.0.0.1"],
    cacheTtlMs: 5_000,
    bodyLimit: 1024,
    headerLimit: 2048,
    protectedRoutes: [
      { prefix: "/product", tag: "agent-browser-auth" },
      { prefix: "/pay", tag: "agent-payer-auth", requiredComponents: ["@method"] },
    ],
    publicRoutes: [{ prefix: "/health", methods: ["GET"] }],
    backendToken: "backend-secret",
  }), clock);
  try {
    const unsigned = await send(proxy, "GET", "/product/1");
    assert.equal(unsigned.status, 403);
    assert.equal(unsigned.body.code, "policy");

    const unmatched = await send(proxy, "GET", "/products");
    assert.equal(unmatched.status, 403);
    assert.equal(unmatched.body.code, "policy");

    const health = await send(proxy, "GET", "/health", {
      "x-tap-agent-id": "forged",
      "x-tap-covered": "forged",
      "x-signature-verified": "yes",
      "x-tap-backend-token": "stolen",
    });
    assert.equal(health.status, 200);
    assert.equal(health.body.headers["x-tap-agent-id"], undefined);
    assert.equal(health.body.headers["x-tap-covered"], undefined);
    assert.equal(health.body.headers["x-signature-verified"], undefined);
    assert.equal(health.body.headers["x-tap-backend-token"], "backend-secret");

    const healthPost = await send(proxy, "POST", "/health");
    assert.equal(healthPost.status, 403);

    const signerA = clientFor("alpha-1", alpha.privateKey, clock);
    const signerB = clientFor("bravo-1", bravo.privateKey, clock);
    const product = `${proxy.url}/product/1`;
    const first = await signerA.signRequest({ method: "GET", url: product, headers: [] }, { tag: "agent-browser-auth" });
    const ok = await send(proxy, "GET", "/product/1?x=1", {
      "Signature-Input": first["Signature-Input"],
      Signature: first.Signature,
      "x-tap-agent-id": "forged",
      "x-tap-covered": "forged",
      "x-agent-verified": "yes",
    });
    assert.equal(ok.status, 200);
    assert.equal(ok.body.url, "/product/1?x=1");
    assert.equal(ok.body.headers["x-tap-agent-id"], String(agentId));
    assert.equal(ok.body.headers["x-tap-key-id"], "alpha-1");
    assert.equal(ok.body.headers["x-tap-tag"], "agent-browser-auth");
    assert.equal(ok.body.headers["x-tap-covered"], "@authority,@path");
    assert.equal(ok.body.headers["x-agent-verified"], undefined);
    assert.equal(ok.body.headers.host, new URL(echo.url).host);

    const replay = await send(proxy, "GET", "/product/1", {
      "Signature-Input": first["Signature-Input"],
      Signature: first.Signature,
    });
    assert.equal(replay.status, 403);
    assert.equal(replay.body.code, "replay");

    const bad = await signerA.signRequest(
      { method: "POST", url: `${proxy.url}/product/body`, headers: [["content-type", "text/plain"]] },
      { tag: "agent-browser-auth" },
    );
    const tampered = await send(proxy, "POST", "/product/body", {
      "content-type": "text/plain",
      "Signature-Input": bad["Signature-Input"],
      Signature: bad.Signature.replace("sig1=:", "sig1=:AAAA"),
    }, "hello");
    assert.equal(tampered.status, 403);
    assert.equal(tampered.body.code, "invalid_signature");
    const bodyOk = await send(proxy, "POST", "/product/body", {
      "content-type": "text/plain",
      "Signature-Input": bad["Signature-Input"],
      Signature: bad.Signature,
    }, "hello");
    assert.equal(bodyOk.status, 200);
    assert.equal(Buffer.from(bodyOk.body.body, "base64").toString(), "hello");

    const malformed = await send(proxy, "GET", "/product/1", { "Signature-Input": "nope", Signature: "sig1=:AA==:" });
    assert.equal(malformed.status, 400);
    assert.equal(malformed.body.code, "malformed");

    const huge = await send(proxy, "GET", "/product/1", { "x-big": "a".repeat(3000) });
    assert.equal(huge.status, 400);

    const tooBig = await send(proxy, "POST", "/product/1", { "content-length": "5000" }, "x".repeat(5000));
    assert.equal(tooBig.status, 413);

    const pay = await signerA.signRequest(
      { method: "POST", url: `${proxy.url}/pay`, headers: [] },
      { tag: "agent-payer-auth" },
    );
    const missingMethod = await send(proxy, "POST", "/pay", {
      "Signature-Input": pay["Signature-Input"],
      Signature: pay.Signature,
    });
    assert.equal(missingMethod.status, 403);
    assert.equal(missingMethod.body.code, "policy");

    const forwarded = await signerA.signRequest(
      { method: "GET", url: "https://shop.example/product/9", headers: [] },
      { tag: "agent-browser-auth" },
    );
    const trusted = await send(proxy, "GET", "/product/9", {
      "x-forwarded-proto": "https",
      "x-forwarded-host": "shop.example",
      "Signature-Input": forwarded["Signature-Input"],
      Signature: forwarded.Signature,
    });
    assert.equal(trusted.status, 200);
    assert.equal(trusted.body.url, "/product/9");

    const races = await Promise.all(Array.from({ length: 8 }, async () => {
      const signed = await signerB.signRequest(
        { method: "GET", url: `${proxy.url}/product/race`, headers: [] },
        { tag: "agent-browser-auth", nonce: "nonce-race-proxy" },
      );
      return send(proxy, "GET", "/product/race", {
        "Signature-Input": signed["Signature-Input"],
        Signature: signed.Signature,
      });
    }));
    assert.equal(races.filter((item) => item.status === 200).length, 1);
    assert.equal(races.filter((item) => item.body.code === "replay").length, 7);

    clock.advance(4_000);
    const bravoHit = await signedSend(proxy, signerB, "GET", "/product/bravo", "agent-browser-auth");
    assert.equal(bravoHit.status, 200);
    assert.equal(bravoHit.body.headers["x-tap-key-id"], "bravo-1");
    await callRegistry(registry, "PUT", `/agents/${agentId}/keys/alpha-1`, { is_active: "false" });
    const stillCached = await signedSend(proxy, signerA, "GET", "/product/cached", "agent-browser-auth");
    assert.equal(stillCached.status, 200);
    clock.advance(2_000);
    const revoked = await signedSend(proxy, signerA, "GET", "/product/revoked", "agent-browser-auth");
    assert.equal(revoked.status, 403);
    assert.equal(revoked.body.code, "trust");
    const bravoStill = await signedSend(proxy, signerB, "GET", "/product/bravo-2", "agent-browser-auth");
    assert.equal(bravoStill.status, 200);

    const durable = await signerB.signRequest(
      { method: "GET", url: "https://shop.example/product/durable", headers: [] },
      { tag: "agent-browser-auth" },
    );
    const durableHeaders = {
      "x-forwarded-proto": "https",
      "x-forwarded-host": "shop.example",
      "Signature-Input": durable["Signature-Input"],
      Signature: durable.Signature,
    };
    assert.equal((await send(proxy, "GET", "/product/durable", durableHeaders)).status, 200);
    await proxy.close();
    const restarted = await startProxy(await config(echo.url, registry.url, join(directory, "replay.db"), {
      trustedProxies: ["127.0.0.1"],
      cacheTtlMs: 5_000,
      protectedRoutes: [{ prefix: "/product", tag: "agent-browser-auth" }],
      publicRoutes: [{ prefix: "/health", methods: ["GET"] }],
    }), clock);
    try {
      const again = await send(restarted, "GET", "/product/durable", durableHeaders);
      assert.equal(again.status, 403);
      assert.equal(again.body.code, "replay");
    } finally {
      await restarted.close();
    }
  } finally {
    await proxy.close().catch(() => undefined);
    await registry.close();
    await echo.close();
  }
});

test("proxy reports registry and upstream failures and cancels in-flight verification", async () => {
  const clock = createManualClock(1_700_000_100_000);
  const directory = mkdtempSync(join(tmpdir(), "tap-proxy-fail-"));
  const echo = await startEcho();
  const pair = generateKeyPair("ed25519");
  let registryHits = 0;
  const failing = await listen((req, res) => {
    registryHits += 1;
    res.writeHead(500);
    res.end("no");
    req.resume();
  });
  const proxy = await startProxy(await config(echo.url, failing.url, join(directory, "replay.db"), {
    cacheTtlMs: 0,
    protectedRoutes: [{ prefix: "/product", tag: "agent-browser-auth" }],
    publicRoutes: [{ prefix: "/health" }],
  }), clock);
  try {
    const client = clientFor("k", pair.privateKey, clock);
    const down = await signedSend(proxy, client, "GET", "/product/1", "agent-browser-auth");
    assert.equal(down.status, 503);
    assert.equal(down.body.code, "resolver_unavailable");
    assert.equal(registryHits, 3);
    assert.equal(echo.hits.length, 0);
  } finally {
    await proxy.close();
    await failing.close();
  }

  let deniedHits = 0;
  const denied = await listen((req, res) => {
    deniedHits += 1;
    res.writeHead(401);
    res.end("no");
    req.resume();
  });
  const deniedProxy = await startProxy(await config(echo.url, denied.url, join(directory, "denied.db"), {
    cacheTtlMs: 0,
    protectedRoutes: [{ prefix: "/product", tag: "agent-browser-auth" }],
    publicRoutes: [],
  }), clock);
  try {
    const client = clientFor("k", pair.privateKey, clock);
    const result = await signedSend(deniedProxy, client, "GET", "/product/1", "agent-browser-auth");
    assert.equal(result.status, 503);
    assert.equal(deniedHits, 1);
  } finally {
    await deniedProxy.close();
    await denied.close();
  }

  const registry = await startRegistry({
    host: "127.0.0.1",
    port: 0,
    adminToken: TOKEN,
    databasePath: join(directory, "registry.db"),
    now: () => clock.now(),
  });
  await registerActive(registry, "k", pair.publicKey.trim());
  const closedUpstream = await startProxy(await config("http://127.0.0.1:1", registry.url, join(directory, "up.db"), {
    cacheTtlMs: 0,
    upstreamTimeoutMs: 500,
    protectedRoutes: [{ prefix: "/product", tag: "agent-browser-auth" }],
    publicRoutes: [],
  }), clock);
  try {
    const client = clientFor("k", pair.privateKey, clock);
    const result = await signedSend(closedUpstream, client, "GET", "/product/1", "agent-browser-auth");
    assert.equal(result.status, 502);
    assert.equal(result.body.code, "bad_gateway");
  } finally {
    await closedUpstream.close();
    await registry.close();
  }

  let released = false;
  const slow = await listen((req, res) => {
    const timer = setTimeout(() => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        key_id: "k",
        public_key: pair.publicKey.trim(),
        algorithm: "ed25519",
        is_active: "true",
        agent_id: 1,
        agent_name: "Slow",
        agent_domain: "https://slow.example",
        expires_at: null,
      }));
    }, 400);
    req.on("aborted", () => {
      clearTimeout(timer);
      released = true;
    });
    res.on("close", () => {
      if (!res.writableEnded) {
        clearTimeout(timer);
        released = true;
      }
    });
  });
  const before = echo.hits.length;
  const slowProxy = await startProxy(await config(echo.url, slow.url, join(directory, "slow.db"), {
    cacheTtlMs: 0,
    protectedRoutes: [{ prefix: "/product", tag: "agent-browser-auth" }],
    publicRoutes: [],
  }), clock);
  try {
    const client = clientFor("k", pair.privateKey, clock);
    const signed = await client.signRequest(
      { method: "GET", url: `${slowProxy.url}/product/slow`, headers: [] },
      { tag: "agent-browser-auth" },
    );
    const controller = new AbortController();
    const pending = fetch(`${slowProxy.url}/product/slow`, {
      headers: {
        "Signature-Input": signed["Signature-Input"],
        Signature: signed.Signature,
      },
      signal: controller.signal,
    }).then(() => "done", () => "aborted");
    await delay(30);
    controller.abort();
    assert.equal(await pending, "aborted");
    await delay(500);
    assert.equal(echo.hits.length, before);
    assert.equal(released, true);
  } finally {
    await slowProxy.close();
    await slow.close();
    await echo.close();
  }
});

test("proxy rejects confusing targets, bounds the body before forwarding, and ignores untrusted forwarded headers", async () => {
  const directory = mkdtempSync(join(tmpdir(), "tap-proxy-target-"));
  const echo = await startEcho();
  const registry = await startRegistry({
    host: "127.0.0.1",
    port: 0,
    adminToken: TOKEN,
    databasePath: join(directory, "registry.db"),
  });
  const pair = generateKeyPair("ed25519");
  await registerActive(registry, "edge-1", pair.publicKey.trim());
  const clock = createManualClock(Date.now());
  const proxy = await startProxy(await config(echo.url, registry.url, join(directory, "replay.db"), {
    cacheTtlMs: 0,
    bodyLimit: 64,
    trustedProxies: [],
    protectedRoutes: [{ prefix: "/product", tag: "agent-browser-auth" }],
    publicRoutes: [{ prefix: "/health" }],
  }), clock);
  try {
    const before = echo.hits.length;
    for (const path of ["/product/../admin", "/product/%2e%2e/admin", "/product/%2E/%2e%2E/admin", "/health/../admin"]) {
      const response = await rawHttp(proxy.port, `GET ${path} HTTP/1.1\r\nHost: 127.0.0.1:${proxy.port}\r\nConnection: close\r\n\r\n`);
      assert.equal(response.status, 400, path);
      assert.match(response.body, /malformed/);
    }
    const slash = await rawHttp(
      proxy.port,
      `GET /product/..\\admin HTTP/1.1\r\nHost: 127.0.0.1:${proxy.port}\r\nConnection: close\r\n\r\n`,
    );
    assert.equal(slash.status, 400);
    const fragment = await rawHttp(
      proxy.port,
      `GET /product/1#extra HTTP/1.1\r\nHost: 127.0.0.1:${proxy.port}\r\nConnection: close\r\n\r\n`,
    );
    assert.equal(fragment.status, 400);
    const chunk = "x".repeat(80);
    const oversized = await rawHttp(
      proxy.port,
      `POST /product/1 HTTP/1.1\r\nHost: 127.0.0.1:${proxy.port}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n${chunk.length.toString(16)}\r\n${chunk}\r\n0\r\n\r\n`,
    );
    assert.equal(oversized.status, 413);
    assert.equal(echo.hits.length, before);

    const client = clientFor("edge-1", pair.privateKey, clock);
    const signed = await client.signRequest(
      { method: "GET", url: `${proxy.url}/product/1`, headers: [] },
      { tag: "agent-browser-auth" },
    );
    const ignored = await send(proxy, "GET", "/product/1", {
      "Signature-Input": signed["Signature-Input"],
      Signature: signed.Signature,
      "x-forwarded-host": "evil.example",
      "x-forwarded-proto": "https",
    });
    assert.equal(ignored.status, 200);
    assert.equal(ignored.body.headers["x-tap-covered"], "@authority,@path");
    const forged = await client.signRequest(
      { method: "GET", url: "https://evil.example/product/1", headers: [] },
      { tag: "agent-browser-auth" },
    );
    const rejected = await send(proxy, "GET", "/product/1", {
      "Signature-Input": forged["Signature-Input"],
      Signature: forged.Signature,
      "x-forwarded-host": "evil.example",
      "x-forwarded-proto": "https",
    });
    assert.equal(rejected.status, 403);
    assert.equal(rejected.body.code, "invalid_signature");
  } finally {
    await proxy.close();
    await registry.close();
    await echo.close();
  }
});

test("proxy survives an upstream response reset", async () => {
  const directory = mkdtempSync(join(tmpdir(), "tap-proxy-reset-"));
  let calls = 0;
  const upstream = await listen((req, res) => {
    calls += 1;
    if (calls === 1) {
      res.writeHead(200, { "content-type": "text/plain", "content-length": "4" });
      res.write("nope");
      res.destroy(new Error("reset"));
      return;
    }
    req.resume();
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok");
  });
  const proxy = await startProxy(await config(upstream.url, "http://127.0.0.1:9", join(directory, "replay.db"), {
    protectedRoutes: [{ prefix: "/product", tag: "agent-browser-auth" }],
    publicRoutes: [{ prefix: "/health" }],
  }));
  try {
    await fetch(`${proxy.url}/health`).then((response) => response.text(), () => "reset");
    const second = await fetch(`${proxy.url}/health`);
    assert.equal(second.status, 200);
    assert.equal(await second.text(), "ok");
    assert.equal(calls, 2);
  } finally {
    await proxy.close();
    await upstream.close();
  }
});

test("a route prefix ending in a slash matches only below it", () => {
  const routes = {
    protectedRoutes: [{ prefix: "/", tag: "agent-browser-auth" as const }],
    publicRoutes: [{ prefix: "/static/" }],
  };
  assert.equal(matchRoute("/static", "GET", routes).kind, "protected");
  assert.equal(matchRoute("/static/", "GET", routes).kind, "public");
  assert.equal(matchRoute("/static/app.js", "GET", routes).kind, "public");
  assert.equal(matchRoute("/STATIC/app.js", "GET", routes).kind, "public");
  assert.equal(matchRoute("/admin/", "GET", { protectedRoutes: [{ prefix: "/admin", tag: "agent-browser-auth" }], publicRoutes: [] }).kind, "protected");
});

test("proxy route policy treats star as every method and requires https and a backend token off loopback", () => {
  assert.equal(matchRoute("/product/2", "POST", {
    protectedRoutes: [{ prefix: "/product", tag: "agent-browser-auth", methods: ["*"] }],
    publicRoutes: [],
  }).kind, "protected");
  const base = {
    UPSTREAM_URL: "http://127.0.0.1:9",
    TAP_ORIGINS: "http://127.0.0.1:3001",
    REGISTRY_URL: "http://127.0.0.1:9",
    TAP_PROTECTED_ROUTES: JSON.stringify([{ prefix: "/product", tag: "agent-browser-auth" }]),
  };
  assert.throws(() => loadProxyConfig({
    ...base,
    UPSTREAM_URL: "http://backend.example",
  }), /TAP_BACKEND_TOKEN/);
  assert.throws(() => loadProxyConfig({
    ...base,
    REGISTRY_URL: "http://registry.example",
  }), /https/);
  assert.throws(() => loadProxyConfig({
    ...base,
    REGISTRY_URL: "http://user:pass@127.0.0.1:9",
  }), /userinfo/);
  assert.throws(() => loadProxyConfig({
    ...base,
    TAP_PROTECTED_ROUTES: JSON.stringify([{ prefix: "/product", tag: "agent-browser-auth", methods: ["*"] }]),
    TAP_PUBLIC_ROUTES: JSON.stringify([{ prefix: "/product", methods: ["GET"] }]),
  }), /ambiguous/);
  const loaded = loadProxyConfig({
    ...base,
    UPSTREAM_URL: "https://backend.example",
    REGISTRY_URL: "https://registry.example",
    TAP_BACKEND_TOKEN: "backend-secret",
  });
  assert.equal(loaded.backendToken, "backend-secret");
  assert.equal(loaded.registryUrl, "https://registry.example");
});

function clientFor(keyId: string, privateKey: string, clock: ManualClock) {
  return createTapClient({
    keyId,
    profile: "tap",
    signer: createSigner("ed25519", privateKey),
    clock,
  });
}

async function signedSend(
  proxy: ProxyHandle,
  client: ReturnType<typeof createTapClient>,
  method: string,
  path: string,
  tag: "agent-browser-auth" | "agent-payer-auth",
) {
  const signed = await client.signRequest({ method, url: `${proxy.url}${path}`, headers: [] }, { tag });
  return send(proxy, method, path, {
    "Signature-Input": signed["Signature-Input"],
    Signature: signed.Signature,
  });
}

async function config(upstream: string, registryUrl: string, replayDatabase: string, extra: Partial<ProxyConfig>): Promise<ProxyConfig> {
  const port = extra.port ?? await freePort();
  return {
    host: "127.0.0.1",
    port,
    upstream: new URL(upstream),
    origins: extra.origins ?? [`http://127.0.0.1:${port}`, "https://shop.example"],
    registryUrl,
    profile: "tap",
    trustSource: `registry:${registryUrl}`,
    protectedRoutes: extra.protectedRoutes ?? [{ prefix: "/product", tag: "agent-browser-auth" }],
    publicRoutes: extra.publicRoutes ?? [],
    cacheTtlMs: extra.cacheTtlMs ?? 0,
    replayDatabase,
    trustedProxies: extra.trustedProxies ?? [],
    allowedSkewSeconds: extra.allowedSkewSeconds ?? 0,
    upstreamTimeoutMs: extra.upstreamTimeoutMs ?? 1_000,
    headerLimit: extra.headerLimit ?? 16_384,
    bodyLimit: extra.bodyLimit ?? 1_048_576,
    backendToken: extra.backendToken,
  };
}

async function registerActive(registry: RegistryHandle, keyId: string, publicKey: string): Promise<number> {
  const created = await callRegistry(registry, "POST", "/agents/register", {
    name: "Agent",
    domain: `https://${keyId}.example`,
    keys: [{ key_id: keyId, public_key: publicKey, algorithm: "ed25519" }],
  });
  assert.equal(created.status, 201);
  const id = created.body.agent.id as number;
  assert.equal((await callRegistry(registry, "PUT", `/agents/${id}`, { is_active: "true" })).status, 200);
  assert.equal((await callRegistry(registry, "PUT", `/agents/${id}/keys/${keyId}`, { is_active: "true" })).status, 200);
  return id;
}

async function addKey(registry: RegistryHandle, agentId: number, keyId: string, publicKey: string, active: boolean): Promise<void> {
  const added = await callRegistry(registry, "POST", `/agents/${agentId}/keys`, {
    key_id: keyId,
    public_key: publicKey,
    algorithm: "ed25519",
  });
  assert.equal(added.status, 201);
  if (active) {
    assert.equal((await callRegistry(registry, "PUT", `/agents/${agentId}/keys/${keyId}`, { is_active: "true" })).status, 200);
  }
}

async function callRegistry(registry: RegistryHandle, method: string, path: string, body: unknown) {
  const response = await fetch(`${registry.url}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${TOKEN}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}

async function send(
  proxy: ProxyHandle,
  method: string,
  path: string,
  headers: Record<string, string> = {},
  body?: string,
) {
  const response = await fetch(`${proxy.url}${path}`, { method, headers, body });
  const text = await response.text();
  let parsed: unknown = text;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = { raw: text };
  }
  return { status: response.status, body: parsed };
}

interface EchoHit {
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

function startEcho(): Promise<{ url: string; hits: EchoHit[]; close(): Promise<void> }> {
  const hits: EchoHit[] = [];
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => {
        const hit: EchoHit = {
          method: req.method ?? "GET",
          url: req.url ?? "/",
          headers: req.headers,
          body: Buffer.concat(chunks).toString("base64"),
        };
        hits.push(hit);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ echoed: true, ...hit }));
      });
    });
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address !== "object") {
        reject(new Error("echo failed"));
        return;
      }
      resolve({
        url: `http://127.0.0.1:${address.port}`,
        hits,
        close: () => new Promise((done, fail) => server.close((error) => (error ? fail(error) : done()))),
      });
    });
  });
}

function listen(handler: http.RequestListener): Promise<{ url: string; close(): Promise<void> }> {
  return new Promise((resolve, reject) => {
    const server = http.createServer(handler);
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address !== "object") {
        reject(new Error("listen failed"));
        return;
      }
      resolve({
        url: `http://127.0.0.1:${address.port}`,
        close: () => new Promise((done, fail) => server.close((error) => (error ? fail(error) : done()))),
      });
    });
  });
}

function rawHttp(port: number, request: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, "127.0.0.1", () => socket.write(request));
    const chunks: Buffer[] = [];
    socket.on("data", (chunk: Buffer) => chunks.push(chunk));
    socket.on("error", reject);
    socket.on("end", () => {
      const text = Buffer.concat(chunks).toString("utf8");
      const [head, body = ""] = text.split("\r\n\r\n");
      resolve({ status: Number(head?.split(" ")[1] ?? 0), body });
    });
  });
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = address && typeof address === "object" ? address.port : 0;
      server.close(() => resolve(port));
    });
  });
}

test("proxy matches routes on the path an upstream would route, checks the origin, and keeps the upstream prefix", async () => {
  const directory = mkdtempSync(join(tmpdir(), "tap-proxy-canon-"));
  const echo = await startEcho();
  const registry = await startRegistry({
    host: "127.0.0.1",
    port: 0,
    adminToken: TOKEN,
    databasePath: join(directory, "registry.db"),
  });
  const pair = generateKeyPair("ed25519");
  await registerActive(registry, "canon-1", pair.publicKey.trim());
  const clock = createManualClock(Date.now());
  const proxy = await startProxy(await config(`${echo.url}/base/`, registry.url, join(directory, "replay.db"), {
    cacheTtlMs: 0,
    trustedProxies: ["127.0.0.1"],
    protectedRoutes: [{ prefix: "/admin", tag: "agent-browser-auth" }],
    publicRoutes: [{ prefix: "/" }],
  }), clock);
  try {
    const get = (path: string) =>
      rawHttp(proxy.port, `GET ${path} HTTP/1.1\r\nHost: 127.0.0.1:${proxy.port}\r\nConnection: close\r\n\r\n`);
    for (const path of ["/ADMIN", "/admin;x/secret", "/Admin/", "/%2561dmin", "/%252561dmin", "/admin%253Bx"]) {
      const response = await get(path);
      assert.equal(response.status, 403, path);
      assert.match(response.body, /policy/, path);
    }
    for (const path of ["/%61dmin", "//admin", "/%2Fadmin", "/x/..%2Fadmin", "/%u0061dmin", "/%25252561dmin"]) {
      const response = await get(path);
      assert.equal(response.status, 400, path);
      assert.match(response.body, /malformed/, path);
    }
    assert.equal(echo.hits.length, 0);
    for (const path of ["/search/50%off", "/caf%E9.txt", "/caf%C3%A9.txt"]) {
      assert.equal((await get(path)).status, 200, path);
    }

    echo.hits.length = 0;
    const open = await send(proxy, "GET", "/home?x=1");
    assert.equal(open.status, 200);
    assert.equal(open.body.url, "/base/home?x=1");

    const client = clientFor("canon-1", pair.privateKey, clock);
    const elsewhere = await client.signRequest(
      { method: "GET", url: "https://shop-a.example/admin/1", headers: [] },
      { tag: "agent-browser-auth" },
    );
    const crossMerchant = await send(proxy, "GET", "/admin/1", {
      "x-forwarded-proto": "https",
      "x-forwarded-host": "shop-a.example",
      "Signature-Input": elsewhere["Signature-Input"],
      Signature: elsewhere.Signature,
    });
    assert.equal(crossMerchant.status, 403);
    assert.equal(crossMerchant.body.code, "policy");

    const ours = await client.signRequest(
      { method: "GET", url: "https://SHOP.example:443/admin/1", headers: [] },
      { tag: "agent-browser-auth" },
    );
    const accepted = await send(proxy, "GET", "/admin/1", {
      "x-forwarded-proto": "https",
      "x-forwarded-host": "shop.example",
      "Signature-Input": ours["Signature-Input"],
      Signature: ours.Signature,
    });
    assert.equal(accepted.status, 200);
    assert.equal(accepted.body.url, "/base/admin/1");
  } finally {
    await proxy.close();
    await registry.close();
    await echo.close();
  }
});

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { startProxy } from "../apps/proxy/src/server.ts";
import { startRegistry } from "../apps/registry/src/server.ts";

const TOKEN = "registry-admin-token";

test("dev key, registry approval, and agent send reach the echo backend", async () => {
  const directory = mkdtempSync(join(tmpdir(), "tap-smoke-"));
  const keys = join(directory, "keys");
  const generated = await agent(["keygen", "--alg", "ed25519", "--out", keys]);
  assert.equal(generated.code, 0);
  const publicKey = generated.stdout.trim();
  assert.match(publicKey, /^[A-Za-z0-9+/]{43}=$/);
  assert.doesNotMatch(generated.stdout, /PRIVATE/);
  const privatePath = join(keys, "ed25519.private");
  assert.notEqual(readFileSync(privatePath, "utf8").trim(), publicKey);

  const echo = await startEcho();
  const registry = await startRegistry({
    host: "127.0.0.1",
    port: 0,
    adminToken: TOKEN,
    databasePath: join(directory, "registry.db"),
  });
  const created = await fetch(`${registry.url}/agents/register`, {
    method: "POST",
    headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
    body: JSON.stringify({
      name: "Smoke",
      domain: "https://smoke.example",
      keys: [{ key_id: "smoke-1", public_key: publicKey, algorithm: "ed25519" }],
    }),
  });
  const createdBody = await created.json() as { agent: { id: number; is_active: string; keys: Array<{ is_active: string }> } };
  assert.equal(created.status, 201);
  assert.equal(createdBody.agent.is_active, "false");
  assert.equal(createdBody.agent.keys[0]?.is_active, "false");
  const id = createdBody.agent.id;
  assert.equal((await fetch(`${registry.url}/keys/smoke-1`)).status, 404);
  for (const path of [`/agents/${id}`, `/agents/${id}/keys/smoke-1`] as const) {
    const response = await fetch(`${registry.url}${path}`, {
      method: "PUT",
      headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
      body: JSON.stringify({ is_active: "true" }),
    });
    assert.equal(response.status, 200);
  }
  const proxy = await startProxy({
    host: "127.0.0.1",
    port: 0,
    upstream: new URL(echo.url),
    registryUrl: registry.url,
    profile: "tap",
    trustSource: `registry:${registry.url}`,
    protectedRoutes: [{ prefix: "/product", tag: "agent-browser-auth" }],
    publicRoutes: [{ prefix: "/public" }],
    cacheTtlMs: 1_000,
    replayDatabase: join(directory, "replay.db"),
    trustedProxies: [],
    allowedSkewSeconds: 0,
    upstreamTimeoutMs: 2_000,
    headerLimit: 16_384,
    bodyLimit: 1_048_576,
    backendToken: "backend-secret",
  });
  try {
    const bodyFile = join(directory, "body.txt");
    writeFileSync(bodyFile, "order=1");
    const sent = await agent([
      "send",
      "--url",
      `${proxy.url}/product/42?color=red`,
      "--method",
      "POST",
      "--tag",
      "agent-browser-auth",
      "--key-id",
      "smoke-1",
      "--key-file",
      privatePath,
      "--data-file",
      bodyFile,
      "--header",
      "content-type:text/plain",
    ]);
    assert.equal(sent.code, 0, sent.stderr);
    assert.match(sent.stderr, /HTTP 200/);
    const echoed = JSON.parse(sent.stdout) as { url: string; headers: Record<string, string>; body: string };
    assert.equal(echoed.url, "/product/42?color=red");
    assert.equal(Buffer.from(echoed.body, "base64").toString(), "order=1");
    assert.equal(echoed.headers["x-tap-agent-id"], String(id));
    assert.equal(echoed.headers["x-tap-key-id"], "smoke-1");
    assert.equal(echoed.headers["x-tap-tag"], "agent-browser-auth");
    assert.equal(echoed.headers["x-tap-covered"], "@authority,@path");
    assert.equal(echoed.headers["x-tap-backend-token"], "backend-secret");

    const inactive = await fetch(`${registry.url}/agents/${id}/keys/smoke-1`, {
      method: "PUT",
      headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
      body: JSON.stringify({ is_active: "false" }),
    });
    assert.equal(inactive.status, 200);
    await delay(1_100);
    const rejected = await agent([
      "send",
      "--url",
      `${proxy.url}/product/42`,
      "--tag",
      "agent-browser-auth",
      "--key-id",
      "smoke-1",
      "--key-file",
      privatePath,
    ]);
    assert.equal(rejected.code, 0);
    assert.match(rejected.stderr, /HTTP 403/);
    assert.equal(JSON.parse(rejected.stdout).code, "trust");
  } finally {
    await proxy.close();
    await registry.close();
    await echo.close();
  }
});

function agent(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["apps/agent/dist/main.js", ...args], { cwd: "/workspace" });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.on("error", reject);
    child.on("close", (code) => {
      resolve({
        code: code ?? 1,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      });
    });
  });
}

function startEcho(): Promise<{ url: string; close(): Promise<void> }> {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => {
        const payload = JSON.stringify({
          url: req.url,
          headers: req.headers,
          body: Buffer.concat(chunks).toString("base64"),
        });
        res.writeHead(200, { "content-type": "application/json" });
        res.end(payload);
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
        close: () => new Promise((done, fail) => server.close((error) => (error ? fail(error) : done()))),
      });
    });
  });
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

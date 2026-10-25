import assert from "node:assert/strict";
import { test } from "node:test";

import { generateKeyPair } from "@chr33s/tap";

import { assertBindPolicy, startRegistry, type RegistryHandle } from "../src/server.ts";

const TOKEN = "registry-admin-token";

test("registry refuses cleartext binds off loopback", () => {
  assert.doesNotThrow(() => assertBindPolicy("127.0.0.1", false));
  assert.doesNotThrow(() => assertBindPolicy("127.0.0.2", false));
  assert.doesNotThrow(() => assertBindPolicy("localhost", false));
  assert.doesNotThrow(() => assertBindPolicy("::1", false));
  assert.doesNotThrow(() => assertBindPolicy("0.0.0.0", true));
  assert.throws(() => assertBindPolicy("0.0.0.0", false), /HTTPS is required/);
});

test("registry lifecycle, auth, rotation, and lookup", async () => {
  const registry = await startRegistry({
    host: "127.0.0.1",
    port: 0,
    adminToken: TOKEN,
    databasePath: ":memory:",
    now: () => 1_700_000_000,
  });
  try {
    const health = await call(registry, "GET", "/");
    assert.equal(health.status, 200);
    assert.match(String(health.body.notice), /does not imply Visa certification/);

    const missing = await call(registry, "POST", "/agents/register", { name: "A", domain: "https://a.example" });
    assert.equal(missing.status, 401);

    const wrong = await call(registry, "POST", "/agents/register", { name: "A", domain: "https://a.example" }, "nope-token-value!!");
    assert.equal(wrong.status, 403);

    const pair = generateKeyPair("ed25519");
    const other = generateKeyPair("ed25519");
    const created = await call(
      registry,
      "POST",
      "/agents/register",
      {
        name: "Alpha",
        domain: "https://alpha.example",
        contact_email: "ops@alpha.example",
        is_active: "true",
        keys: [{ key_id: "alpha-1", public_key: pair.publicKey.trim(), algorithm: "ed25519" }],
      },
      TOKEN,
    );
    assert.equal(created.status, 201);
    const agent = created.body.agent as AgentBody;
    assert.equal(agent.is_active, "false");
    assert.equal(agent.keys[0]?.is_active, "false");
    assert.equal(agent.contact_email, "ops@alpha.example");

    assert.equal((await call(registry, "GET", "/agents")).body.length, 0);
    assert.equal((await call(registry, "GET", `/agents/${agent.id}`)).status, 404);
    assert.equal((await call(registry, "GET", "/keys/alpha-1")).status, 404);

    const earlyKey = await call(registry, "PUT", `/agents/${agent.id}/keys/alpha-1`, { is_active: "true" }, TOKEN);
    assert.equal(earlyKey.status, 409);

    // Key ids the verifier would refuse to look up cannot be registered.
    for (const keyId of [".", "..", "a/b", "a b"]) {
      const dot = await call(registry, "POST", `/agents/${agent.id}/keys`, {
        key_id: keyId,
        public_key: other.publicKey.trim(),
        algorithm: "ed25519",
      }, TOKEN);
      assert.equal(dot.status, 400, keyId);
      assert.equal(dot.body.message, "invalid key id");
    }

    const activated = await call(registry, "PUT", `/agents/${agent.id}`, { is_active: "true" }, TOKEN);
    assert.equal(activated.status, 200);
    assert.equal((activated.body.agent as AgentBody).is_active, "true");

    const boolActive = await call(registry, "PUT", `/agents/${agent.id}/keys/alpha-1`, { is_active: true }, TOKEN);
    assert.equal(boolActive.status, 400);

    const keyOn = await call(registry, "PUT", `/agents/${agent.id}/keys/alpha-1`, { is_active: "true" }, TOKEN);
    assert.equal(keyOn.status, 200);
    assert.equal((keyOn.body.key as KeyBody).is_active, "true");

    const listed = await call(registry, "GET", "/agents");
    assert.equal(listed.body.length, 1);
    assert.equal("contact_email" in listed.body[0], false);
    const lookup = await call(registry, "GET", "/keys/alpha-1");
    assert.equal(lookup.status, 200);
    assert.equal(lookup.headers.get("cache-control"), "no-store");
    assert.equal(lookup.body.key_id, "alpha-1");
    assert.equal(lookup.body.algorithm, "ed25519");
    assert.equal(lookup.body.is_active, "true");
    assert.equal(lookup.body.agent_id, agent.id);
    assert.equal(lookup.body.agent_name, "Alpha");
    assert.equal(lookup.body.agent_domain, "https://alpha.example");
    assert.equal(lookup.body.expires_at, null);
    assert.equal((await call(registry, "GET", `/agents/${agent.id}/keys/alpha-1`)).status, 200);

    const replaced = await call(
      registry,
      "PUT",
      `/agents/${agent.id}/keys/alpha-1`,
      { public_key: other.publicKey.trim() },
      TOKEN,
    );
    assert.equal(replaced.status, 400);

    const renamed = await call(
      registry,
      "POST",
      "/agents/register",
      { name: "Alpha Two", domain: "https://alpha.example", is_active: "false" },
      TOKEN,
    );
    assert.equal(renamed.status, 200);
    assert.equal((renamed.body.agent as AgentBody).is_active, "true");
    assert.equal((renamed.body.agent as AgentBody).name, "Alpha Two");
    assert.equal((await call(registry, "GET", "/keys/alpha-1")).body.agent_name, "Alpha Two");

    const withKeys = await call(
      registry,
      "POST",
      "/agents/register",
      {
        name: "Alpha Two",
        domain: "https://alpha.example",
        keys: [{ key_id: "alpha-2", public_key: other.publicKey.trim(), algorithm: "ed25519" }],
      },
      TOKEN,
    );
    assert.equal(withKeys.status, 409);

    const added = await call(
      registry,
      "POST",
      `/agents/${agent.id}/keys`,
      { key_id: "alpha-2", public_key: other.publicKey.trim(), algorithm: "ed25519", is_active: "true" },
      TOKEN,
    );
    assert.equal(added.status, 201);
    assert.equal((added.body.key as KeyBody).is_active, "false");
    assert.equal((await call(registry, "GET", "/keys/alpha-2")).status, 404);

    const secondAgent = await call(
      registry,
      "POST",
      "/agents/register",
      {
        name: "Beta",
        domain: "https://beta.example",
        keys: [{ key_id: "alpha-1", public_key: other.publicKey.trim(), algorithm: "ed25519" }],
      },
      TOKEN,
    );
    assert.equal(secondAgent.status, 409);

    await call(registry, "PUT", `/agents/${agent.id}/keys/alpha-2`, { is_active: "true" }, TOKEN);
    assert.equal((await call(registry, "GET", "/keys/alpha-1")).status, 200);
    assert.equal((await call(registry, "GET", "/keys/alpha-2")).status, 200);

    const expired = await call(
      registry,
      "PUT",
      `/agents/${agent.id}/keys/alpha-2`,
      { expires_at: 1_700_000_000 },
      TOKEN,
    );
    assert.equal(expired.status, 200);
    assert.equal((await call(registry, "GET", "/keys/alpha-2")).status, 404);

    const removed = await call(registry, "DELETE", `/agents/${agent.id}`, undefined, TOKEN);
    assert.equal(removed.status, 200);
    assert.equal((await call(registry, "GET", "/keys/alpha-1")).status, 404);
    assert.equal((await call(registry, "GET", "/agents")).body.length, 0);

    const again = await call(registry, "PUT", `/agents/${agent.id}`, { is_active: "true" }, TOKEN);
    assert.equal(again.status, 200);
    assert.equal((await call(registry, "GET", "/keys/alpha-1")).status, 404);
    const reenabled = await call(registry, "PUT", `/agents/${agent.id}/keys/alpha-1`, { is_active: "true" }, TOKEN);
    assert.equal(reenabled.status, 200);
    assert.equal((await call(registry, "GET", "/keys/alpha-1")).status, 200);
  } finally {
    await registry.close();
  }
});

interface AgentBody {
  id: number;
  name: string;
  is_active: string;
  contact_email?: string | null;
  keys: KeyBody[];
}

interface KeyBody {
  key_id: string;
  is_active: string;
}

async function call(
  registry: RegistryHandle,
  method: string,
  path: string,
  body?: unknown,
  token?: string,
): Promise<{ status: number; body: any; headers: Headers }> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (token) headers.authorization = `Bearer ${token}`;
  const response = await fetch(`${registry.url}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  return {
    status: response.status,
    headers: response.headers,
    body: text.length === 0 ? null : JSON.parse(text),
  };
}

import { timingSafeEqual } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import { dirname } from "node:path";
import type { DatabaseSync } from "node:sqlite";

import { Context, Effect, Layer, ManagedRuntime, Schema } from "effect";
import { assertKeyId, isLoopbackHost } from "@chr33s/tap";

import { HttpReply } from "./http-error.js";
import {
  StoreFailure,
  addKey,
  deactivateAgent,
  getPublicAgent,
  listPublicAgents,
  lookupKey,
  openRegistryDatabase,
  registerAgent,
  updateAgent,
  updateKey,
  type AgentPatch,
  type KeyInput,
  type KeyPatch,
  type RegisterInput,
} from "./store.js";

const Active = Schema.Literals(["true", "false"]);
const AlgorithmName = Schema.Literals(["ed25519", "rsa-pss-sha256"]);

const KeyBody = Schema.Struct({
  key_id: Schema.String,
  public_key: Schema.String,
  algorithm: AlgorithmName,
  description: Schema.optional(Schema.NullOr(Schema.String)),
  is_active: Schema.optional(Active),
});

const RegisterBody = Schema.Struct({
  name: Schema.String,
  domain: Schema.String,
  description: Schema.optional(Schema.NullOr(Schema.String)),
  contact_email: Schema.optional(Schema.NullOr(Schema.String)),
  is_active: Schema.optional(Active),
  keys: Schema.optional(Schema.Array(KeyBody)),
});

const AgentPatchBody = Schema.Struct({
  name: Schema.optional(Schema.String),
  description: Schema.optional(Schema.NullOr(Schema.String)),
  contact_email: Schema.optional(Schema.NullOr(Schema.String)),
  is_active: Schema.optional(Active),
});

const KeyPatchBody = Schema.Struct({
  description: Schema.optional(Schema.NullOr(Schema.String)),
  is_active: Schema.optional(Active),
  expires_at: Schema.optional(Schema.NullOr(Schema.Int)),
});

export interface RegistryOptions {
  host: string;
  port: number;
  adminToken: string;
  databasePath: string;
  tlsCert?: string;
  tlsKey?: string;
  now?: () => number;
}

export interface RegistryHandle {
  url: string;
  port: number;
  close(): Promise<void>;
}

class RegistryDb extends Context.Service<RegistryDb, { readonly db: DatabaseSync }>()("tap/registry/Db") {}

interface HttpResult {
  status: number;
  body: unknown;
}

export function assertBindPolicy(host: string, tls: boolean): void {
  if (!isLoopbackHost(host) && !tls) {
    throw new Error("HTTPS is required when the registry is not bound to a loopback address");
  }
}

export async function startRegistry(options: RegistryOptions): Promise<RegistryHandle> {
  if (options.adminToken.length < 16) throw new Error("TAP_ADMIN_TOKEN must be at least 16 characters");
  const tls = Boolean(options.tlsCert && options.tlsKey);
  assertBindPolicy(options.host, tls);
  if (options.databasePath !== ":memory:") mkdirSync(dirname(options.databasePath), { recursive: true });
  const runtime = ManagedRuntime.make(
    Layer.effect(
      RegistryDb,
      Effect.acquireRelease(
        Effect.sync(() => ({ db: openRegistryDatabase(options.databasePath) })),
        (db) => Effect.sync(() => db.db.close()),
      ),
    ),
  );
  const server = tls
    ? https.createServer(
        {
          cert: readFileSync(options.tlsCert ?? ""),
          key: readFileSync(options.tlsKey ?? ""),
        },
        (req, res) => accept(req, res, runtime, options),
      )
    : http.createServer((req, res) => accept(req, res, runtime, options));
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  const port = await listen(server, options.host, options.port);
  const scheme = tls ? "https" : "http";
  return {
    port,
    url: `${scheme}://${options.host}:${port}`,
    async close() {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
      await runtime.dispose();
    },
  };
}

function accept(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  runtime: ManagedRuntime.ManagedRuntime<RegistryDb, unknown>,
  options: RegistryOptions,
): void {
  void runtime.runPromise(handle(req, options)).then(
    (result) => writeJson(res, result.status, result.body),
    () => writeJson(res, 500, { error: "internal", message: "internal error" }),
  );
}

function handle(req: http.IncomingMessage, options: RegistryOptions): Effect.Effect<HttpResult, never, RegistryDb> {
  return Effect.gen(function* () {
    const db = (yield* RegistryDb).db;
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const method = req.method ?? "GET";
    const now = options.now?.() ?? Math.floor(Date.now() / 1000);
    if (method === "GET") {
      return yield* attempt(() => routeGet(db, url.pathname, now));
    }
    yield* attemptVoid(() => requireAdmin(req, options.adminToken));
    if (method === "POST" && url.pathname === "/agents/register") {
      const body = yield* readJson(req, Schema.decodeUnknownSync(RegisterBody));
      return yield* attempt(() => {
        const result = registerAgent(db, toRegister(body), now);
        return {
          status: result.created ? 201 : 200,
          body: {
            success: true,
            message: result.created ? "agent registered inactive" : "agent metadata updated; activation unchanged",
            agent: result.agent,
          },
        };
      });
    }
    if (method === "DELETE") {
      return yield* attempt(() => {
        const agentPath = /^\/agents\/([1-9][0-9]*)$/.exec(url.pathname);
        if (!agentPath?.[1]) return { status: 404, body: { error: "not_found", message: "not found" } };
        deactivateAgent(db, Number(agentPath[1]), now);
        return { status: 200, body: { message: "agent deactivated" } };
      });
    }
    if (method === "PUT") {
      const raw = yield* readRaw(req);
      return yield* attempt(() => routePut(db, url.pathname, raw, now));
    }
    if (method === "POST") {
      const body = yield* readJson(req, Schema.decodeUnknownSync(KeyBody));
      return yield* attempt(() => {
        const addKeyPath = /^\/agents\/([1-9][0-9]*)\/keys$/.exec(url.pathname);
        if (!addKeyPath?.[1]) return { status: 404, body: { error: "not_found", message: "not found" } };
        const key = addKey(db, Number(addKeyPath[1]), toKeyInput(body), now);
        return { status: 201, body: { success: true, message: "key added inactive", key } };
      });
    }
    return { status: 404, body: { error: "not_found", message: "not found" } };
  }).pipe(
    Effect.catchTag("HttpReply", (failure) => Effect.succeed({ status: failure.status, body: failure.body })),
    Effect.catch(() => Effect.succeed({ status: 500, body: { error: "internal", message: "internal error" } })),
  );
}

function routeGet(db: DatabaseSync, pathname: string, now: number): HttpResult {
  if (pathname === "/") {
    return {
      status: 200,
      body: {
        message: "Agent Registry Service is running",
        notice: "Local approval expresses this deployment's trust policy and does not imply Visa certification.",
      },
    };
  }
  if (pathname === "/agents") return { status: 200, body: listPublicAgents(db, now) };
  const keyLookup = /^\/keys\/([^/]+)$/.exec(pathname);
  if (keyLookup?.[1]) return { status: 200, body: lookupKey(db, decodePath(keyLookup[1]), undefined, now) };
  const agentKeyLookup = /^\/agents\/([1-9][0-9]*)\/keys\/([^/]+)$/.exec(pathname);
  if (agentKeyLookup?.[1] && agentKeyLookup[2]) {
    return { status: 200, body: lookupKey(db, decodePath(agentKeyLookup[2]), Number(agentKeyLookup[1]), now) };
  }
  const agentPath = /^\/agents\/([1-9][0-9]*)$/.exec(pathname);
  if (agentPath?.[1]) return { status: 200, body: getPublicAgent(db, Number(agentPath[1]), now) };
  return { status: 404, body: { error: "not_found", message: "not found" } };
}

function routePut(db: DatabaseSync, pathname: string, raw: unknown, now: number): HttpResult {
  const agentPath = /^\/agents\/([1-9][0-9]*)$/.exec(pathname);
  if (agentPath?.[1]) {
    rejectFields(raw, ["name", "description", "contact_email", "is_active"]);
    const agent = updateAgent(db, Number(agentPath[1]), toAgentPatch(decodeBody(Schema.decodeUnknownSync(AgentPatchBody), raw)), now);
    return { status: 200, body: { success: true, message: "agent updated", agent } };
  }
  const keyPath = /^\/agents\/([1-9][0-9]*)\/keys\/([^/]+)$/.exec(pathname);
  if (keyPath?.[1] && keyPath[2]) {
    rejectFields(raw, ["description", "is_active", "expires_at"]);
    const key = updateKey(db, Number(keyPath[1]), decodePath(keyPath[2]), toKeyPatch(decodeBody(Schema.decodeUnknownSync(KeyPatchBody), raw)), now);
    return { status: 200, body: { success: true, message: "key updated", key } };
  }
  return { status: 404, body: { error: "not_found", message: "not found" } };
}

function attempt(fn: () => HttpResult): Effect.Effect<HttpResult, HttpReply> {
  return Effect.try({
    try: fn,
    catch: asReply,
  });
}

function attemptVoid(fn: () => void): Effect.Effect<void, HttpReply> {
  return Effect.try({
    try: fn,
    catch: asReply,
  });
}

function asReply(cause: unknown): HttpReply {
  if (cause instanceof HttpReply) return cause;
  if (cause instanceof StoreFailure) return storeReply(cause);
  return new HttpReply({ status: 500, body: { error: "internal", message: "internal error" } });
}

function storeReply(failure: StoreFailure): HttpReply {
  switch (failure.kind) {
    case "not_found":
      return new HttpReply({ status: 404, body: { error: "not_found", message: failure.message } });
    case "conflict":
      return new HttpReply({ status: 409, body: { error: "conflict", message: failure.message } });
    case "invalid":
      return new HttpReply({ status: 400, body: { error: "malformed", message: failure.message } });
    case "ambiguous":
    case "internal":
      return new HttpReply({ status: 500, body: { error: "internal", message: failure.message } });
  }
}

function toRegister(body: typeof RegisterBody.Type): RegisterInput {
  return {
    name: requiredText(body.name, "name", 255),
    domain: domain(body.domain),
    description: optionalText(body.description, 1000),
    contactEmail: optionalEmail(body.contact_email),
    keys: (body.keys ?? []).map(toKeyInput),
  };
}

function toKeyInput(body: typeof KeyBody.Type): KeyInput {
  const keyId = requiredText(body.key_id, "key_id", 100);
  // The same rule the verifier applies, so every registered key id is resolvable.
  try {
    assertKeyId(keyId);
  } catch {
    throw new HttpReply({ status: 400, body: { error: "malformed", message: "invalid key id" } });
  }
  return {
    keyId,
    publicKey: requiredText(body.public_key, "public_key", 16_384),
    algorithm: body.algorithm,
    description: optionalText(body.description, 1000),
  };
}

function toAgentPatch(body: typeof AgentPatchBody.Type): AgentPatch {
  const patch: AgentPatch = {};
  if (body.name !== undefined) patch.name = requiredText(body.name, "name", 255);
  if (body.description !== undefined) patch.description = optionalText(body.description, 1000);
  if (body.contact_email !== undefined) patch.contactEmail = optionalEmail(body.contact_email);
  if (body.is_active !== undefined) patch.isActive = body.is_active === "true";
  return patch;
}

function toKeyPatch(body: typeof KeyPatchBody.Type): KeyPatch {
  const patch: KeyPatch = { expiresAtSet: body.expires_at !== undefined };
  if (body.description !== undefined) patch.description = optionalText(body.description, 1000);
  if (body.is_active !== undefined) patch.isActive = body.is_active === "true";
  if (body.expires_at !== undefined) {
    if (body.expires_at !== null && (body.expires_at <= 0 || body.expires_at > 9_999_999_999)) {
      throw new HttpReply({ status: 400, body: { error: "malformed", message: "invalid expires_at" } });
    }
    patch.expiresAt = body.expires_at;
  }
  return patch;
}

function requireAdmin(req: http.IncomingMessage, expected: string): void {
  const header = req.headers.authorization;
  if (typeof header !== "string" || !header.startsWith("Bearer ")) {
    throw new HttpReply({ status: 401, body: { error: "unauthorized", message: "admin credential required" } });
  }
  const presented = header.slice("Bearer ".length);
  const left = Buffer.from(presented);
  const right = Buffer.from(expected);
  const match = left.length === right.length && timingSafeEqual(left, right);
  if (!match) {
    throw new HttpReply({ status: 403, body: { error: "forbidden", message: "admin credential rejected" } });
  }
}

function readJson<A>(req: http.IncomingMessage, decode: (input: unknown) => A): Effect.Effect<A, HttpReply> {
  return Effect.flatMap(readRaw(req), (raw) =>
    Effect.try({
      try: () => decodeBody(decode, raw),
      catch: (cause) =>
        cause instanceof HttpReply
          ? cause
          : new HttpReply({ status: 400, body: { error: "malformed", message: "invalid request body" } }),
    }),
  );
}

function readRaw(req: http.IncomingMessage): Effect.Effect<unknown, HttpReply> {
  if (!String(req.headers["content-type"] ?? "").startsWith("application/json")) {
    return Effect.fail(new HttpReply({ status: 400, body: { error: "malformed", message: "content-type must be application/json" } }));
  }
  return Effect.tryPromise({
    try: () => readBody(req, 65_536),
    catch: (cause) =>
      cause instanceof HttpReply
        ? cause
        : new HttpReply({ status: 400, body: { error: "malformed", message: "invalid json" } }),
  });
}

function decodeBody<A>(decode: (input: unknown) => A, value: unknown): A {
  try {
    return decode(value);
  } catch (cause) {
    if (cause instanceof HttpReply) throw cause;
    throw new HttpReply({ status: 400, body: { error: "malformed", message: "invalid request body" } });
  }
}

function rejectFields(value: unknown, allowed: readonly string[]): void {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new HttpReply({ status: 400, body: { error: "malformed", message: "invalid request body" } });
  }
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      throw new HttpReply({ status: 400, body: { error: "malformed", message: `cannot change ${key}` } });
    }
  }
}

async function readBody(req: http.IncomingMessage, limit: number): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buf.length;
    if (size > limit) {
      throw new HttpReply({ status: 413, body: { error: "malformed", message: "payload too large" } });
    }
    chunks.push(buf);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new HttpReply({ status: 400, body: { error: "malformed", message: "invalid json" } });
  }
}

function requiredText(value: string, field: string, max: number): string {
  const trimmed = value.trim();
  if (trimmed.length < 1 || trimmed.length > max) {
    throw new HttpReply({ status: 400, body: { error: "malformed", message: `invalid ${field}` } });
  }
  return trimmed;
}

function optionalText(value: string | null | undefined, max: number): string | null {
  if (value === undefined || value === null) return null;
  const trimmed = value.trim();
  if (trimmed.length === 0) return null;
  if (trimmed.length > max) {
    throw new HttpReply({ status: 400, body: { error: "malformed", message: "text is too long" } });
  }
  return trimmed;
}

function optionalEmail(value: string | null | undefined): string | null {
  const text = optionalText(value, 255);
  if (text === null) return null;
  if (!/^[^\s@]+@[^\s@]+$/.test(text)) {
    throw new HttpReply({ status: 400, body: { error: "malformed", message: "invalid contact_email" } });
  }
  return text;
}

function domain(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length > 255 || !/^https?:\/\/[A-Za-z0-9._:-]+(?:\/[^\s]*)?$/.test(trimmed)) {
    throw new HttpReply({ status: 400, body: { error: "malformed", message: "invalid domain" } });
  }
  return trimmed;
}

function decodePath(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    throw new HttpReply({ status: 400, body: { error: "malformed", message: "invalid path" } });
  }
}

function writeJson(res: http.ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  res.end(payload);
}

function listen(server: http.Server | https.Server, host: string, port: number): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      const address = server.address();
      if (address && typeof address === "object") resolve(address.port);
      else reject(new Error("registry failed to bind"));
    });
  });
}


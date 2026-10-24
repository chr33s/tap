import { mkdirSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import { dirname } from "node:path";

import { Effect, Layer, ManagedRuntime } from "effect";
import { TapError, isTapError, type Clock, type RequestData, type VerifiedAgent } from "tap";
import { TapFailure, TapVerifierService, cachingRegistryResolverLayer, sqliteReplayLayer, tapVerifierLayer } from "tap-effect";

import { matchRoute, type ProxyConfig } from "./config.js";

const HOP = new Set(["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "te", "trailer"]);

export interface ProxyHandle {
  url: string;
  port: number;
  close(): Promise<void>;
}

type Runtime = ManagedRuntime.ManagedRuntime<TapVerifierService, never>;

export async function startProxy(config: ProxyConfig, clock?: Clock): Promise<ProxyHandle> {
  if (config.replayDatabase !== ":memory:") mkdirSync(dirname(config.replayDatabase), { recursive: true });
  const dependencies = Layer.mergeAll(
    cachingRegistryResolverLayer({
      registryUrl: config.registryUrl,
      cacheTtlMs: config.cacheTtlMs,
      clock,
      transientRetries: 2,
      timeoutMs: 2_000,
    }),
    sqliteReplayLayer(config.replayDatabase, clock),
  );
  const runtime = ManagedRuntime.make(
    tapVerifierLayer({
      profile: config.profile,
      trustSource: config.trustSource,
      clock,
      allowedSkewSeconds: config.allowedSkewSeconds,
    }).pipe(Layer.provide(dependencies)),
  );
  const server = http.createServer((req, res) => {
    void handle(req, res, config, runtime);
  });
  server.requestTimeout = config.upstreamTimeoutMs + 5_000;
  server.headersTimeout = 10_000;
  const port = await listen(server, config.host, config.port);
  return {
    port,
    url: `http://${config.host}:${port}`,
    async close() {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
      await runtime.dispose();
    },
  };
}

async function handle(req: http.IncomingMessage, res: http.ServerResponse, config: ProxyConfig, runtime: Runtime): Promise<void> {
  const method = req.method ?? "GET";
  const pathOnly = (req.url ?? "/").split("?")[0] ?? "/";
  try {
    if (headerBytes(req) > config.headerLimit) {
      return send(res, req, 400, { error: "malformed", code: "malformed" }, method, pathOnly);
    }
    const length = contentLength(req);
    if (length !== undefined && length > config.bodyLimit) {
      return send(res, req, 413, { error: "malformed", code: "malformed" }, method, pathOnly);
    }
    const decision = matchRoute(pathOnly, method, config);
    if (decision.kind === "unmatched") {
      return send(res, req, 403, { error: "verification_failed", code: "policy" }, method, pathOnly);
    }
    let verified: VerifiedAgent | undefined;
    if (decision.kind === "protected") {
      const request = externalRequest(req, config);
      const required = decision.route.requiredComponents ? [...decision.route.requiredComponents] : undefined;
      const abort = new AbortController();
      const onAborted = (): void => abort.abort();
      if (req.aborted) abort.abort();
      req.on("aborted", onAborted);
      try {
        verified = await runtime.runPromise(
          Effect.gen(function* () {
            const verifier = yield* TapVerifierService;
            return yield* verifier.verifyRequest(request, {
              tag: decision.route.tag,
              signal: abort.signal,
              ...(required ? { requiredComponents: required } : {}),
            });
          }),
        );
      } finally {
        req.off("aborted", onAborted);
      }
    }
    forward(req, res, config, verified, method, pathOnly);
  } catch (error) {
    const mapped = mapError(error);
    if (!res.headersSent) send(res, req, mapped.status, mapped.body, method, pathOnly);
    else res.destroy();
  }
}

function forward(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  config: ProxyConfig,
  verified: VerifiedAgent | undefined,
  method: string,
  pathOnly: string,
): void {
  const headers = outgoingHeaders(req, config, verified);
  const transport = config.upstream.protocol === "https:" ? https : http;
  const signal = AbortSignal.timeout(config.upstreamTimeoutMs);
  const upstreamReq = transport.request(
    {
      protocol: config.upstream.protocol,
      hostname: config.upstream.hostname,
      port: config.upstream.port || (config.upstream.protocol === "https:" ? 443 : 80),
      method: req.method,
      path: req.url,
      headers,
      signal,
    },
    (upstreamRes) => {
      const responseHeaders = { ...upstreamRes.headers };
      delete responseHeaders["transfer-encoding"];
      delete responseHeaders.connection;
      res.writeHead(upstreamRes.statusCode ?? 502, responseHeaders);
      upstreamRes.pipe(res);
      log(method, pathOnly, upstreamRes.statusCode ?? 502);
    },
  );
  let seen = 0;
  req.on("data", (chunk: Buffer) => {
    seen += chunk.length;
    if (seen > config.bodyLimit) {
      upstreamReq.destroy();
      if (!res.headersSent) send(res, req, 413, { error: "malformed", code: "malformed" }, method, pathOnly);
      else res.destroy();
    }
  });
  req.on("aborted", () => upstreamReq.destroy());
  upstreamReq.on("error", () => {
    if (!res.headersSent) send(res, req, 502, { error: "bad_gateway", code: "bad_gateway" }, method, pathOnly);
    else res.destroy();
  });
  req.pipe(upstreamReq);
}

function externalRequest(req: http.IncomingMessage, config: ProxyConfig): RequestData {
  const remote = normalizeIp(req.socket.remoteAddress ?? "");
  const trusted = config.trustedProxies.map(normalizeIp).includes(remote);
  const encrypted = "encrypted" in req.socket && Boolean(req.socket.encrypted);
  let proto = encrypted ? "https" : "http";
  let host = singleHeader(req, "host");
  if (trusted) {
    const forwardedProto = singleHeader(req, "x-forwarded-proto")?.split(",")[0]?.trim();
    const forwardedHost = singleHeader(req, "x-forwarded-host")?.split(",")[0]?.trim();
    if (forwardedProto) proto = forwardedProto;
    if (forwardedHost) host = forwardedHost;
  }
  if (!host || (proto !== "http" && proto !== "https") || /[\r\n\s]/.test(host)) {
    throw new TapError("malformed", "invalid external host");
  }
  const path = req.url ?? "/";
  if (!path.startsWith("/")) throw new TapError("malformed", "invalid request target");
  const headers: Array<[string, string]> = [];
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    for (const item of Array.isArray(value) ? value : [value]) headers.push([name, item]);
  }
  return { method: req.method ?? "GET", url: `${proto}://${host}${path}`, headers };
}

function outgoingHeaders(
  req: http.IncomingMessage,
  config: ProxyConfig,
  verified: VerifiedAgent | undefined,
): http.OutgoingHttpHeaders {
  const headers: http.OutgoingHttpHeaders = {};
  for (const [name, value] of Object.entries(req.headers)) {
    const lower = name.toLowerCase();
    if (value === undefined || HOP.has(lower) || lower === "host" || isIdentityHeader(lower)) continue;
    headers[lower] = value;
  }
  headers.host = config.upstream.host;
  if (verified) {
    headers["x-tap-agent-id"] = verified.agentId;
    headers["x-tap-key-id"] = verified.keyId;
    headers["x-tap-tag"] = verified.tag;
  }
  if (config.backendToken) headers["x-tap-backend-token"] = config.backendToken;
  return headers;
}

function isIdentityHeader(name: string): boolean {
  return name.startsWith("x-tap-") || name === "x-signature-verified" || name === "x-agent-verified";
}

function mapError(error: unknown): { status: number; body: { error: string; code: string } } {
  const code = error instanceof TapFailure || isTapError(error) ? error.code : undefined;
  if (code === "malformed") return { status: 400, body: { error: "malformed", code } };
  if (code === "resolver_unavailable" || code === "store_unavailable" || code === "cancelled") {
    return { status: 503, body: { error: "unavailable", code } };
  }
  if (code) return { status: 403, body: { error: "verification_failed", code } };
  return { status: 502, body: { error: "bad_gateway", code: "bad_gateway" } };
}

function send(
  res: http.ServerResponse,
  req: http.IncomingMessage,
  status: number,
  body: { error: string; code: string },
  method: string,
  pathOnly: string,
): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  res.end(payload);
  req.destroy();
  log(method, pathOnly, status, body.code);
}

function headerBytes(req: http.IncomingMessage): number {
  let size = 0;
  for (const [name, value] of Object.entries(req.headers)) {
    size += name.length;
    if (Array.isArray(value)) size += value.join("").length;
    else size += value?.length ?? 0;
  }
  return size;
}

function contentLength(req: http.IncomingMessage): number | undefined {
  const raw = singleHeader(req, "content-length");
  if (raw === undefined) return undefined;
  if (!/^[0-9]+$/.test(raw)) throw new TapError("malformed", "invalid content-length");
  return Number(raw);
}

function singleHeader(req: http.IncomingMessage, name: string): string | undefined {
  const value = req.headers[name];
  if (Array.isArray(value)) return value[0];
  return value;
}

function normalizeIp(ip: string): string {
  return ip.startsWith("::ffff:") ? ip.slice("::ffff:".length) : ip;
}

function log(method: string, pathOnly: string, status: number, code?: string): void {
  process.stderr.write(`${method} ${pathOnly} ${status}${code ? ` ${code}` : ""}\n`);
}

function listen(server: http.Server, host: string, port: number): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      const address = server.address();
      if (address && typeof address === "object") resolve(address.port);
      else reject(new Error("proxy failed to bind"));
    });
  });
}

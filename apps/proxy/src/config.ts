import { Schema } from "effect";
import { isProfile, MAX_KEY_CACHE_TTL_MS, type ProfileName } from "tap";

const Tag = Schema.Literals(["agent-browser-auth", "agent-payer-auth"]);

export const ProtectedRouteSchema = Schema.Struct({
  prefix: Schema.String,
  tag: Tag,
  methods: Schema.optional(Schema.Array(Schema.String)),
  requiredComponents: Schema.optional(Schema.Array(Schema.String)),
});

export const PublicRouteSchema = Schema.Struct({
  prefix: Schema.String,
  methods: Schema.optional(Schema.Array(Schema.String)),
});

export type ProtectedRoute = typeof ProtectedRouteSchema.Type;
export type PublicRoute = typeof PublicRouteSchema.Type;

export interface ProxyConfig {
  host: string;
  port: number;
  upstream: URL;
  registryUrl: string;
  profile: ProfileName;
  trustSource: string;
  protectedRoutes: readonly ProtectedRoute[];
  publicRoutes: readonly PublicRoute[];
  cacheTtlMs: number;
  replayDatabase: string;
  trustedProxies: readonly string[];
  allowedSkewSeconds: number;
  upstreamTimeoutMs: number;
  headerLimit: number;
  bodyLimit: number;
  backendToken?: string;
}

export function loadProxyConfig(env: NodeJS.ProcessEnv): ProxyConfig {
  const upstreamRaw = required(env, "UPSTREAM_URL");
  const registryUrl = required(env, "REGISTRY_URL");
  const profileRaw = env.TAP_PROFILE ?? "tap";
  if (!isProfile(profileRaw)) throw new Error("TAP_PROFILE must be tap or legacySample");
  let upstream: URL;
  try {
    upstream = new URL(upstreamRaw);
  } catch {
    throw new Error("UPSTREAM_URL is invalid");
  }
  if (upstream.protocol !== "http:" && upstream.protocol !== "https:") throw new Error("UPSTREAM_URL must be http(s)");
  const protectedRoutes = Schema.decodeUnknownSync(Schema.Array(ProtectedRouteSchema))(parseJson(env.TAP_PROTECTED_ROUTES, []));
  const publicRoutes = Schema.decodeUnknownSync(Schema.Array(PublicRouteSchema))(parseJson(env.TAP_PUBLIC_ROUTES, []));
  validateRoutes(protectedRoutes, publicRoutes);
  const cacheTtlMs = boundedInt(env.TAP_CACHE_TTL_MS, 5_000, 0, MAX_KEY_CACHE_TTL_MS);
  return {
    host: env.HOST ?? "127.0.0.1",
    port: boundedInt(env.PORT, 3001, 0, 65535),
    upstream,
    registryUrl,
    profile: profileRaw,
    trustSource: env.TAP_TRUST_SOURCE ?? `registry:${registryUrl}`,
    protectedRoutes,
    publicRoutes,
    cacheTtlMs,
    replayDatabase: env.TAP_REPLAY_DATABASE ?? "./data/replay.db",
    trustedProxies: (env.TAP_TRUSTED_PROXIES ?? "").split(",").map((item) => item.trim()).filter((item) => item.length > 0),
    allowedSkewSeconds: boundedInt(env.TAP_ALLOWED_SKEW_SECONDS, 0, 0, 60),
    upstreamTimeoutMs: boundedInt(env.TAP_UPSTREAM_TIMEOUT_MS, 10_000, 1, 120_000),
    headerLimit: boundedInt(env.TAP_HEADER_LIMIT, 16_384, 1024, 65_536),
    bodyLimit: boundedInt(env.TAP_BODY_LIMIT, 1_048_576, 1, 10_485_760),
    backendToken: env.TAP_BACKEND_TOKEN,
  };
}

export type RouteDecision =
  | { kind: "public" }
  | { kind: "protected"; route: ProtectedRoute }
  | { kind: "unmatched" };

export function matchRoute(pathname: string, method: string, config: Pick<ProxyConfig, "protectedRoutes" | "publicRoutes">): RouteDecision {
  const matches: Array<{ kind: "public" | "protected"; prefix: string; route?: ProtectedRoute }> = [];
  for (const route of config.protectedRoutes) {
    if (prefixMatch(pathname, route.prefix) && methodMatch(method, route.methods)) {
      matches.push({ kind: "protected", prefix: route.prefix, route });
    }
  }
  for (const route of config.publicRoutes) {
    if (prefixMatch(pathname, route.prefix) && methodMatch(method, route.methods)) {
      matches.push({ kind: "public", prefix: route.prefix });
    }
  }
  if (matches.length === 0) return { kind: "unmatched" };
  const bestLength = Math.max(...matches.map((match) => match.prefix.length));
  const best = matches.filter((match) => match.prefix.length === bestLength);
  const kinds = new Set(best.map((match) => match.kind));
  if (kinds.size !== 1 || best.length !== 1) return { kind: "unmatched" };
  const winner = best[0];
  if (!winner) return { kind: "unmatched" };
  if (winner.kind === "public") return { kind: "public" };
  if (!winner.route) return { kind: "unmatched" };
  return { kind: "protected", route: winner.route };
}

function validateRoutes(protectedRoutes: readonly ProtectedRoute[], publicRoutes: readonly PublicRoute[]): void {
  if (protectedRoutes.length === 0) throw new Error("TAP_PROTECTED_ROUTES must contain at least one route");
  const seen = new Map<string, string>();
  for (const route of [...protectedRoutes, ...publicRoutes]) {
    if (!route.prefix.startsWith("/") || route.prefix.includes("?")) throw new Error(`invalid route prefix ${route.prefix}`);
    const methods = route.methods ?? ["*"];
    for (const method of methods) {
      const key = `${route.prefix} ${method.toUpperCase()}`;
      if (seen.has(key)) throw new Error(`ambiguous route ${key}`);
      seen.set(key, "1");
    }
  }
}

function prefixMatch(pathname: string, prefix: string): boolean {
  if (prefix === "/") return true;
  if (pathname === prefix) return true;
  const normalized = prefix.endsWith("/") ? prefix : `${prefix}/`;
  return pathname.startsWith(normalized);
}

function methodMatch(method: string, methods: readonly string[] | undefined): boolean {
  if (!methods || methods.length === 0) return true;
  const upper = method.toUpperCase();
  return methods.some((item) => item.toUpperCase() === upper);
}

function required(env: NodeJS.ProcessEnv, key: string): string {
  const value = env[key];
  if (!value) throw new Error(`${key} is required`);
  return value;
}

function parseJson(value: string | undefined, fallback: unknown): unknown {
  if (value === undefined || value.trim() === "") return fallback;
  return JSON.parse(value) as unknown;
}

function boundedInt(value: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = value === undefined || value === "" ? fallback : Number(value);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`expected an integer from ${min} to ${max}`);
  }
  return parsed;
}

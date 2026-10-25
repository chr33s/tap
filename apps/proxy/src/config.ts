import { Schema } from "effect";
import { TapError, isLoopbackHost, isProfile, MAX_KEY_CACHE_TTL_MS, normalizeOrigin, normalizeRegistryUrl, type ProfileName } from "tap";

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
  /**
   * Origins this proxy serves, as `scheme://authority`. A signature is only
   * accepted for one of these, so a request signed for another merchant that
   * trusts the same registry is rejected.
   */
  origins: readonly string[];
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
  normalizeRegistryUrl(registryUrl);
  const profileRaw = env.TAP_PROFILE ?? "tap";
  if (!isProfile(profileRaw)) throw new Error("TAP_PROFILE must be tap or legacySample");
  const upstream = parseHttpUrl(upstreamRaw, "UPSTREAM_URL");
  if (!isLoopbackHost(upstream.hostname) && !env.TAP_BACKEND_TOKEN) {
    throw new Error("TAP_BACKEND_TOKEN is required when the upstream is not a loopback host");
  }
  const origins = required(env, "TAP_ORIGINS").split(",").map((item) => item.trim()).filter((item) => item.length > 0)
    .map(parseOrigin);
  if (origins.length === 0) throw new Error("TAP_ORIGINS is required");
  const protectedRoutes = Schema.decodeUnknownSync(Schema.Array(ProtectedRouteSchema))(parseJson(env.TAP_PROTECTED_ROUTES, []));
  const publicRoutes = Schema.decodeUnknownSync(Schema.Array(PublicRouteSchema))(parseJson(env.TAP_PUBLIC_ROUTES, []));
  validateRoutes(protectedRoutes, publicRoutes);
  const cacheTtlMs = boundedInt(env.TAP_CACHE_TTL_MS, 5_000, 0, MAX_KEY_CACHE_TTL_MS);
  return {
    host: env.HOST ?? "127.0.0.1",
    port: boundedInt(env.PORT, 3001, 0, 65535),
    upstream,
    origins,
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
  const path = canonicalRoutePath(pathname);
  const matches: Array<{ kind: "public" | "protected"; prefix: string; route?: ProtectedRoute }> = [];
  for (const route of config.protectedRoutes) {
    const prefix = routePrefix(route);
    if (prefixMatch(path, prefix) && methodMatch(method, route.methods)) {
      matches.push({ kind: "protected", prefix, route });
    }
  }
  for (const route of config.publicRoutes) {
    const prefix = routePrefix(route);
    if (prefixMatch(path, prefix) && methodMatch(method, route.methods)) {
      matches.push({ kind: "public", prefix });
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

const prefixes = new WeakMap<ProtectedRoute | PublicRoute, string>();

function routePrefix(route: ProtectedRoute | PublicRoute): string {
  let prefix = prefixes.get(route);
  if (prefix === undefined) {
    prefix = canonicalRoutePath(route.prefix);
    prefixes.set(route, prefix);
  }
  return prefix;
}

/** Upstreams commonly decode up to this many layers; a path still encoded after that is rejected. */
const MAX_DECODE_ROUNDS = 3;
const UNRESERVED_OR_SLASH = /[A-Za-z0-9\-._~/\\]/;

/**
 * Path form used only for route matching; the raw path is still what is
 * verified and forwarded.
 *
 * Spellings that only exist to look different from the routed path are
 * rejected outright: `//`, `%uXXXX`, and escapes of unreserved characters,
 * `/`, or `\`. What remains is decoded repeatedly (an upstream may decode
 * more than once), case-folded, and stripped of `;` segment parameters. Each
 * step can only make a path match more prefixes, so a protected prefix is
 * never missed because an upstream normalizes harder than this does.
 * Malformed escapes such as a bare `%` are left as literal text.
 */
export function canonicalRoutePath(path: string): string {
  if (path.includes("//")) throw new TapError("malformed", "path contains an empty segment");
  if (/%u[0-9A-Fa-f]{4}/i.test(path)) throw new TapError("malformed", "path contains a %u escape");
  for (const match of path.matchAll(/%([0-9A-Fa-f]{2})/g)) {
    if (UNRESERVED_OR_SLASH.test(String.fromCharCode(Number.parseInt(match[1] ?? "", 16)))) {
      throw new TapError("malformed", "path escapes a character that needs no escaping");
    }
  }
  // Byte-wise so Latin-1 escapes decode too; non-ASCII text is compared as its UTF-8 escapes.
  let decoded = path.replace(/[^\u0000-\u007f]/gu, (char) => encodeURIComponent(char).toLowerCase());
  for (let round = 0; round < MAX_DECODE_ROUNDS; round += 1) {
    const next = decoded.replace(/%([0-9A-Fa-f]{2})/g, (_match, hex: string) => String.fromCharCode(Number.parseInt(hex, 16)));
    if (next === decoded) break;
    decoded = next;
  }
  if (/%[0-9A-Fa-f]{2}/.test(decoded)) throw new TapError("malformed", "path is encoded too many times");
  if (/[\u0000-\u001f\u007f\\]/.test(decoded)) throw new TapError("malformed", "path contains a control character or backslash");
  const raw = decoded.split("/").map((segment) => (segment.split(";")[0] ?? "").replace(/^ +| +$/g, ""));
  const segments: string[] = [];
  for (const segment of raw) {
    if (segment.length === 0) continue;
    if (segment === "." || segment === "..") throw new TapError("malformed", "request target contains a dot segment");
    segments.push(segment.toLowerCase());
  }
  if (segments.length === 0) return "/";
  // A final segment that was only spaces routes like a trailing slash.
  const trailingSlash = raw[raw.length - 1] === "";
  return `/${segments.join("/")}${trailingSlash ? "/" : ""}`;
}

function validateRoutes(protectedRoutes: readonly ProtectedRoute[], publicRoutes: readonly PublicRoute[]): void {
  if (protectedRoutes.length === 0) throw new Error("TAP_PROTECTED_ROUTES must contain at least one route");
  const entries: Array<{ prefix: string; methods: readonly string[] }> = [];
  for (const route of [...protectedRoutes, ...publicRoutes]) {
    if (!route.prefix.startsWith("/") || route.prefix.includes("?")) throw new Error(`invalid route prefix ${route.prefix}`);
    let prefix: string;
    try {
      prefix = canonicalRoutePath(route.prefix);
    } catch {
      throw new Error(`invalid route prefix ${route.prefix}`);
    }
    const methods = methodSet(route.methods);
    for (const previous of entries) {
      if (previous.prefix === prefix && methodsOverlap(previous.methods, methods)) {
        throw new Error(`ambiguous route ${route.prefix}`);
      }
    }
    entries.push({ prefix, methods });
  }
}

function methodSet(methods: readonly string[] | undefined): readonly string[] {
  if (!methods || methods.length === 0 || methods.some((item) => item === "*")) return ["*"];
  return [...new Set(methods.map((item) => item.toUpperCase()))];
}

function methodsOverlap(left: readonly string[], right: readonly string[]): boolean {
  if (left.includes("*") || right.includes("*")) return true;
  return left.some((method) => right.includes(method));
}

/** A prefix ending in `/` matches only below it; `/static/` does not match `/static`. */
function prefixMatch(pathname: string, prefix: string): boolean {
  if (prefix.endsWith("/")) return pathname.startsWith(prefix);
  return pathname === prefix || pathname.startsWith(`${prefix}/`);
}

function methodMatch(method: string, methods: readonly string[] | undefined): boolean {
  if (!methods || methods.length === 0 || methods.some((item) => item === "*")) return true;
  const upper = method.toUpperCase();
  return methods.some((item) => item.toUpperCase() === upper);
}

function parseHttpUrl(value: string, key: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${key} is invalid`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error(`${key} must be http(s)`);
  if (url.username || url.password || url.search || url.hash) {
    throw new Error(`${key} must not contain userinfo, a query, or a fragment`);
  }
  return url;
}

function parseOrigin(value: string): string {
  try {
    return normalizeOrigin(value);
  } catch {
    throw new Error("TAP_ORIGINS must list origins such as https://shop.example");
  }
}

function required(env: NodeJS.ProcessEnv, key: string): string {
  const value = env[key];
  if (!value) throw new Error(`${key} is required`);
  return value;
}

function parseJson(value: string | undefined, fallback: unknown): unknown {
  if (value === undefined || value.trim() === "") return fallback;
  return JSON.parse(value);
}

function boundedInt(value: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = value === undefined || value === "" ? fallback : Number(value);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`expected an integer from ${min} to ${max}`);
  }
  return parsed;
}

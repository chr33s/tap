import { isAbortError, mergeSignals, throwIfAborted } from "./abort.js";
import { systemClock } from "./clock.js";
import { assertPublicKey, canonicalPublicKey } from "./crypto.js";
import { tapError } from "./errors.js";
import { MAX_KEY_CACHE_TTL_MS, isAlgorithm, type Clock, type KeyResolver, type ResolvedKey } from "./types.js";

export interface RegistryKeyResolverOptions {
  registryUrl: string;
  /** Requested TTL. Values above 30 seconds are capped. */
  cacheTtlMs?: number;
  timeoutMs?: number;
  clock?: Clock;
  fetchImpl?: typeof fetch;
  /**
   * Extra attempts after a transient registry failure. `401`/`403` are not
   * retried. Default is 2.
   */
  transientRetries?: number;
}

interface CacheEntry {
  key: ResolvedKey;
  freshUntilMs: number;
}

/**
 * Resolves keys from a configured registry. The registry URL is fixed at
 * construction; request headers cannot redirect it. Redirect responses fail
 * closed. Cache hits never outlive `min(ttl, 30s, key expiry)`.
 */
export function createRegistryKeyResolver(options: RegistryKeyResolverOptions): KeyResolver {
  const registryUrl = normalizeRegistryUrl(options.registryUrl);
  const ttlMs = Math.min(Math.max(options.cacheTtlMs ?? 5_000, 0), MAX_KEY_CACHE_TTL_MS);
  const timeoutMs = options.timeoutMs ?? 2_000;
  const retries = Math.max(0, options.transientRetries ?? 2);
  const clock = options.clock ?? systemClock;
  const fetchImpl = options.fetchImpl ?? fetch;
  const cache = new Map<string, CacheEntry>();

  return {
    async resolve(keyId, signal) {
      throwIfAborted(signal);
      const nowMs = clock.nowMs();
      const cached = cache.get(keyId);
      if (cached && cached.freshUntilMs > nowMs && !isExpired(cached.key, clock.now())) {
        return cached.key;
      }
      if (cached) cache.delete(keyId);
      let lastError: unknown;
      for (let attempt = 0; attempt <= retries; attempt += 1) {
        throwIfAborted(signal);
        try {
          const key = await fetchRegistryKey({ registryUrl, keyId, timeoutMs, signal, fetchImpl, clock });
          const freshFor = key.expiresAt === null
            ? ttlMs
            : Math.min(ttlMs, Math.max(0, key.expiresAt * 1000 - clock.nowMs()));
          if (freshFor > 0) cache.set(keyId, { key, freshUntilMs: clock.nowMs() + freshFor });
          return key;
        } catch (error) {
          lastError = error;
          if (!isTransient(error) || attempt === retries) break;
        }
      }
      throw lastError;
    },
  };
}

export function createStaticKeyResolver(keys: readonly ResolvedKey[]): KeyResolver {
  const byId = new Map<string, ResolvedKey>();
  for (const key of keys) {
    if (byId.has(key.keyId)) throw tapError("trust", `ambiguous key id ${key.keyId}`);
    byId.set(key.keyId, key);
  }
  return {
    async resolve(keyId, signal) {
      throwIfAborted(signal);
      const key = byId.get(keyId);
      if (!key) throw tapError("trust", "key not found");
      return key;
    },
  };
}

export async function fetchRegistryKey(input: {
  registryUrl: string;
  keyId: string;
  timeoutMs: number;
  signal?: AbortSignal;
  fetchImpl?: typeof fetch;
  clock?: Clock;
}): Promise<ResolvedKey> {
  throwIfAborted(input.signal);
  const clock = input.clock ?? systemClock;
  const fetchImpl = input.fetchImpl ?? fetch;
  const url = new URL(`/keys/${encodeURIComponent(input.keyId)}`, normalizeRegistryUrl(input.registryUrl));
  const timeout = AbortSignal.timeout(input.timeoutMs);
  const signal = mergeSignals([input.signal, timeout]);
  let response: Response;
  try {
    response = await fetchImpl(url, {
      method: "GET",
      redirect: "error",
      headers: { accept: "application/json" },
      signal,
    });
  } catch (error) {
    if (input.signal?.aborted || isAbortError(error) && input.signal?.aborted) {
      throw tapError("cancelled", "operation aborted");
    }
    if (isAbortError(error)) throw tapError("resolver_unavailable", "registry request timed out");
    throw tapError("resolver_unavailable", "registry request failed");
  }
  if (response.status === 404) throw tapError("trust", "key not found");
  if (response.status === 401 || response.status === 403) {
    throw tapError("resolver_unavailable", "unauthorized");
  }
  if (!response.ok) throw tapError("resolver_unavailable", `registry status ${response.status}`);
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw tapError("resolver_unavailable", "registry returned invalid json");
  }
  return parseRegistryKey(body, clock.now());
}

export function parseRegistryKey(body: unknown, nowSeconds: number): ResolvedKey {
  if (!isRecord(body)) throw tapError("resolver_unavailable", "registry key document is invalid");
  const keyId = requiredString(body, "key_id");
  const publicKey = requiredString(body, "public_key");
  const algorithmRaw = requiredString(body, "algorithm").toLowerCase();
  const agentId = stringifyId(body.agent_id);
  const agentName = requiredString(body, "agent_name");
  const agentDomain = requiredString(body, "agent_domain");
  if (body.is_active !== "true") throw tapError("trust", "key is inactive");
  if (!isAlgorithm(algorithmRaw)) throw tapError("trust", "key algorithm is not allowed");
  const expiresAt = parseExpiresAt(body.expires_at);
  if (expiresAt !== null && expiresAt <= nowSeconds) throw tapError("trust", "key is expired");
  let canonical: string;
  try {
    canonical = canonicalPublicKey(algorithmRaw, publicKey);
    assertPublicKey(algorithmRaw, canonical);
  } catch (error) {
    if (isTapTrust(error)) throw error;
    throw tapError("trust", "invalid public key");
  }
  return {
    keyId,
    publicKey: canonical,
    algorithm: algorithmRaw,
    agentId,
    agentName,
    agentDomain,
    expiresAt,
  };
}

function normalizeRegistryUrl(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw tapError("policy", "registry url is invalid");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") throw tapError("policy", "registry url must be http(s)");
  if (url.username || url.password) throw tapError("policy", "registry url userinfo is not allowed");
  url.hash = "";
  url.search = "";
  return url.toString();
}

function parseExpiresAt(value: unknown): number | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw tapError("resolver_unavailable", "expires_at is invalid");
  }
  return value;
}

function stringifyId(value: unknown): string {
  if (typeof value === "number" && Number.isSafeInteger(value)) return String(value);
  if (typeof value === "string" && value.length > 0 && value.length <= 64) return value;
  throw tapError("resolver_unavailable", "agent_id is invalid");
}

function requiredString(body: Record<string, unknown>, key: string): string {
  const value = body[key];
  if (typeof value !== "string" || value.length === 0 || value.length > 16_384) {
    throw tapError("resolver_unavailable", `${key} is invalid`);
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isExpired(key: ResolvedKey, nowSeconds: number): boolean {
  return key.expiresAt !== null && key.expiresAt <= nowSeconds;
}

function isTransient(error: unknown): boolean {
  return error instanceof Error
    && "code" in error
    && error.code === "resolver_unavailable"
    && "reason" in error
    && error.reason !== "unauthorized";
}

function isTapTrust(error: unknown): boolean {
  return error instanceof Error && "code" in error && (error.code === "trust" || error.code === "resolver_unavailable");
}

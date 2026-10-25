import { isAbortError, mergeSignals, throwIfAborted } from "./abort.js";
import { systemClock } from "./clock.js";
import { assertPublicKey, canonicalPublicKey } from "./crypto.js";
import { isTapError, tapError } from "./errors.js";
import { assertKeyId } from "./fields.js";
import { MAX_KEY_CACHE_TTL_MS, isAlgorithm, type Clock, type KeyResolver, type ResolvedKey } from "./types.js";

export interface RegistryKeyResolverOptions {
  registryUrl: string;
  /** Requested TTL. Values above 30 seconds are capped. */
  cacheTtlMs?: number;
  timeoutMs?: number;
  clock?: Clock;
  fetchImpl?: typeof fetch;
  /**
   * Extra attempts after a transient registry failure: a network error, a
   * timeout, or a `5xx`. Anything the registry answered deterministically
   * (`401`/`403`, a redirect, an unparseable document) is not retried.
   * Attempts are spaced by `retryBackoffMs`, doubling each time. Default is 2.
   */
  transientRetries?: number;
  /** Delay before the first retry, in milliseconds. Default is 50. */
  retryBackoffMs?: number;
}

/**
 * Entry caps; oldest entries are evicted first. Misses are attacker-chosen key
 * ids, so they live in their own map and cannot evict registered keys.
 */
const MAX_KEY_ENTRIES = 10_000;
const MAX_MISS_ENTRIES = 1_000;

interface CacheEntry {
  key: ResolvedKey;
  freshUntilMs: number;
}

interface MissEntry {
  error: unknown;
  freshUntilMs: number;
}

interface Lookup {
  promise: Promise<ResolvedKey>;
  controller: AbortController;
  waiters: number;
}

/**
 * Resolves keys from a configured registry. The registry URL is fixed at
 * construction; request headers cannot redirect it. Redirect responses fail
 * closed. Cache hits never outlive `min(ttl, 30s, key expiry)`. Lookups run
 * before the signature can be checked, so unknown, inactive, and expired keys
 * and unusable registry documents are cached for the same TTL, and concurrent
 * lookups for one key id share a single registry request.
 */
export function createRegistryKeyResolver(options: RegistryKeyResolverOptions): KeyResolver {
  const registryUrl = normalizeRegistryUrl(options.registryUrl);
  const ttlMs = Math.min(Math.max(options.cacheTtlMs ?? 5_000, 0), MAX_KEY_CACHE_TTL_MS);
  const timeoutMs = options.timeoutMs ?? 2_000;
  const retries = Math.max(0, options.transientRetries ?? 2);
  const backoffMs = Math.max(0, options.retryBackoffMs ?? 50);
  const clock = options.clock ?? systemClock;
  const fetchImpl = options.fetchImpl ?? fetch;
  const cache = new Map<string, CacheEntry>();
  const misses = new Map<string, MissEntry>();
  const inflight = new Map<string, Lookup>();

  const lookup = async (keyId: string, signal: AbortSignal): Promise<ResolvedKey> => {
    let lastError: unknown;
    for (let attempt = 0; attempt <= retries; attempt += 1) {
      throwIfAborted(signal);
      try {
        const key = await fetchRegistryKey({ registryUrl, keyId, timeoutMs, signal, fetchImpl, clock });
        const freshFor = key.expiresAt === null
          ? ttlMs
          : Math.min(ttlMs, Math.max(0, key.expiresAt * 1000 - clock.nowMs()));
        if (freshFor > 0) remember(cache, MAX_KEY_ENTRIES, keyId, { key, freshUntilMs: clock.nowMs() + freshFor });
        return key;
      } catch (error) {
        lastError = error;
        const transient = isTransient(error);
        // Deterministic answers are remembered so a registry that is serving
        // a broken document is not asked again on every request.
        if (!transient && isCacheableMiss(error) && ttlMs > 0) {
          remember(misses, MAX_MISS_ENTRIES, keyId, { error, freshUntilMs: clock.nowMs() + ttlMs });
        }
        if (!transient || attempt === retries) break;
        await sleep(backoffMs * 2 ** attempt, signal);
      }
    }
    throw lastError;
  };

  return {
    async resolve(keyId, signal) {
      throwIfAborted(signal);
      const nowMs = clock.nowMs();
      const miss = misses.get(keyId);
      if (miss && miss.freshUntilMs > nowMs) throw miss.error;
      if (miss) misses.delete(keyId);
      const cached = cache.get(keyId);
      if (cached && cached.freshUntilMs > nowMs && !isExpired(cached.key, clock.now())) return cached.key;
      if (cached) cache.delete(keyId);
      let shared = inflight.get(keyId);
      if (!shared) {
        const controller = new AbortController();
        const entry: Lookup = { controller, waiters: 0, promise: lookup(keyId, controller.signal) };
        entry.promise
          .finally(() => {
            if (inflight.get(keyId) === entry) inflight.delete(keyId);
          })
          .catch(() => undefined);
        inflight.set(keyId, entry);
        shared = entry;
      }
      return await waitFor(shared, signal, () => {
        if (inflight.get(keyId) === shared) inflight.delete(keyId);
      });
    },
  };
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  if (ms <= 0) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(timer);
      resolve();
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

function remember<T>(map: Map<string, T>, limit: number, keyId: string, entry: T): void {
  map.delete(keyId);
  if (map.size >= limit) {
    const oldest = map.keys().next().value;
    if (oldest !== undefined) map.delete(oldest);
  }
  map.set(keyId, entry);
}

/**
 * Waits on a shared lookup. The registry request is aborted only when every
 * caller waiting on it has been cancelled.
 */
function waitFor(lookup: Lookup, signal: AbortSignal | undefined, detach: () => void): Promise<ResolvedKey> {
  lookup.waiters += 1;
  return new Promise((resolve, reject) => {
    let settled = false;
    const onAbort = (): void => {
      if (settled) return;
      settled = true;
      lookup.waiters -= 1;
      if (lookup.waiters === 0) {
        detach();
        lookup.controller.abort();
      }
      reject(tapError("cancelled", "operation aborted"));
    };
    if (signal?.aborted) return onAbort();
    signal?.addEventListener("abort", onAbort, { once: true });
    lookup.promise.then(
      (key) => {
        if (settled) return;
        settled = true;
        signal?.removeEventListener("abort", onAbort);
        resolve(key);
      },
      (error: unknown) => {
        if (settled) return;
        settled = true;
        signal?.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
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
  assertKeyId(input.keyId);
  const clock = input.clock ?? systemClock;
  const fetchImpl = input.fetchImpl ?? fetch;
  const base = normalizeRegistryUrl(input.registryUrl);
  // Relative to the registry URL so a path prefix such as `/registry/` is kept.
  const url = new URL(`keys/${encodeURIComponent(input.keyId)}`, base.endsWith("/") ? base : `${base}/`);
  const timeout = AbortSignal.timeout(input.timeoutMs);
  const signal = mergeSignals([input.signal, timeout]);
  let response: Response;
  try {
    // `manual` so a redirect is seen as the registry's deterministic answer
    // rather than a network failure; it is never followed.
    response = await fetchImpl(url, {
      method: "GET",
      redirect: "manual",
      headers: { accept: "application/json" },
      signal,
    });
  } catch (error) {
    if (input.signal?.aborted) throw tapError("cancelled", "operation aborted");
    if (isAbortError(error)) throw tapError("resolver_unavailable", TRANSIENT_TIMEOUT);
    throw tapError("resolver_unavailable", TRANSIENT_NETWORK);
  }
  if (response.status === 0 || (response.status >= 300 && response.status < 400)) {
    throw tapError("resolver_unavailable", "registry redirected");
  }
  if (response.status === 404) throw tapError("trust", "key not found");
  if (response.status === 401 || response.status === 403) {
    throw tapError("resolver_unavailable", "unauthorized");
  }
  if (response.status >= 500) throw tapError("resolver_unavailable", `${TRANSIENT_STATUS}${response.status}`);
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
    if (isCacheableMiss(error)) throw error;
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

export function isLoopbackHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "localhost" || host === "::1") return true;
  const parts = host.split(".");
  if (parts.length !== 4 || parts[0] !== "127") return false;
  return parts.every((part) => /^\d+$/.test(part) && Number(part) <= 255);
}

export function normalizeRegistryUrl(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw tapError("policy", "registry url is invalid");
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopbackHost(url.hostname))) {
    throw tapError("policy", "registry url must use https outside loopback");
  }
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

const TRANSIENT_TIMEOUT = "registry request timed out";
const TRANSIENT_NETWORK = "registry request failed";
const TRANSIENT_STATUS = "registry unavailable, status ";

/** Only failures that a later attempt could plausibly resolve. */
function isTransient(error: unknown): boolean {
  if (!isTapError(error) || error.code !== "resolver_unavailable") return false;
  return error.reason === TRANSIENT_TIMEOUT || error.reason === TRANSIENT_NETWORK || error.reason.startsWith(TRANSIENT_STATUS);
}

/** Deterministic registry answers: unknown or unusable keys and bad documents. */
function isCacheableMiss(error: unknown): boolean {
  return isTapError(error) && (error.code === "trust" || error.code === "resolver_unavailable");
}

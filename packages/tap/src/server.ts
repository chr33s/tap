/**
 * Server-side TAP API: verification, key resolution, and replay admission.
 * Merchant servers can call `createTapVerifier` directly and own replay
 * themselves when no proxy is deployed.
 */
export { createMemoryReplayStore, createSqliteReplayStore } from "./replay.js";
export {
  createRegistryKeyResolver,
  createStaticKeyResolver,
  fetchRegistryKey,
  isLoopbackHost,
  normalizeRegistryUrl,
  parseRegistryKey,
  type RegistryKeyResolverOptions,
} from "./resolver.js";
export { normalizeOrigin } from "./target.js";
export { createTapVerifier, verifyRequest, type TapVerifierOptions } from "./verifier.js";
export {
  TapError,
  isTapError,
  MAX_KEY_CACHE_TTL_MS,
  type Clock,
  type KeyResolver,
  type ProfileName,
  type ReplayStore,
  type RequestData,
  type ResolvedKey,
  type TapVerifier,
  type VerifiedAgent,
  type VerifyOptions,
} from "./index.js";

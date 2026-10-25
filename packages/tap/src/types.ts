export const PROFILES = ["tap", "legacySample"] as const;
export type ProfileName = (typeof PROFILES)[number];

export const INTENT_TAGS = ["agent-browser-auth", "agent-payer-auth"] as const;
export type IntentTag = (typeof INTENT_TAGS)[number];

export const ALGORITHMS = ["ed25519", "rsa-pss-sha256"] as const;
export type Algorithm = (typeof ALGORITHMS)[number];

/** Maximum signature lifetime (`expires - created`), in seconds. */
export const MAX_SIGNATURE_LIFETIME_SECONDS = 480;

/**
 * Registry key cache ceiling. Revocation can be delayed by at most this long,
 * or until `expires_at` when that is sooner. Expired cache entries are never
 * served, including when the registry cannot be reached.
 */
export const MAX_KEY_CACHE_TTL_MS = 30_000;

export const TAP_LABEL = "sig1";
export const LEGACY_LABEL = "sig2";

/**
 * Absolute request as the signer and verifier both see it.
 * `url` keeps the original path and query encoding; do not round-trip it
 * through `URL#pathname` or `URL#search`, which decode bytes.
 */
export interface RequestData {
  method: string;
  url: string;
  headers: ReadonlyArray<readonly [string, string]>;
}

export interface SignatureHeaders {
  readonly "Signature-Input": string;
  readonly Signature: string;
}

export interface Signer {
  readonly algorithm: Algorithm;
  sign(data: Uint8Array, signal?: AbortSignal): Promise<Uint8Array>;
}

export interface SignOptions {
  tag: IntentTag;
  /** Covered components in signed order. Defaults to `@authority` and `@path`. */
  coveredComponents?: readonly string[];
  /** Seconds from `created` until `expires`. Default and maximum are 480. */
  lifetimeSeconds?: number;
  /** Overrides the clock for tests. Unix seconds. */
  created?: number;
  /** Overrides the nonce source. Production callers should omit this. */
  nonce?: string;
  signal?: AbortSignal;
}

export interface VerifyOptions {
  tag: IntentTag;
  /** Components that must appear in addition to profile requirements. */
  requiredComponents?: readonly string[];
  signal?: AbortSignal;
}

export interface VerifiedAgent {
  agentId: string;
  agentName: string;
  agentDomain: string;
  keyId: string;
  algorithm: Algorithm;
  tag: IntentTag;
  nonce: string;
  created: number;
  expires: number;
  /** Components that were actually signed, in order. Unlisted data is not authenticated. */
  coveredComponents: readonly string[];
}

export interface ResolvedKey {
  keyId: string;
  publicKey: string;
  algorithm: Algorithm;
  agentId: string;
  agentName: string;
  agentDomain: string;
  /** Unix seconds, exclusive. `null` means the key does not expire. */
  expiresAt: number | null;
}

export interface KeyResolver {
  resolve(keyId: string, signal?: AbortSignal): Promise<ResolvedKey>;
}

export interface ReplayClaim {
  trustSource: string;
  keyId: string;
  nonce: string;
  /** Exclusive unix-second deadline (`expires + allowedSkew`). */
  until: number;
}

export type ClaimResult = "claimed" | "duplicate" | "expired";

export interface ReplayStore {
  claim(entry: ReplayClaim, signal?: AbortSignal): Promise<ClaimResult>;
}

export interface Clock {
  /** Unix epoch milliseconds. */
  nowMs(): number;
  /** Unix epoch seconds, an integer. */
  now(): number;
}

export interface TapClient {
  signRequest(request: RequestData, options: SignOptions): Promise<SignatureHeaders>;
}

export interface TapVerifier {
  verifyRequest(request: RequestData, options: VerifyOptions): Promise<VerifiedAgent>;
}

export function isIntentTag(value: string): value is IntentTag {
  return (INTENT_TAGS as readonly string[]).includes(value);
}

export function isAlgorithm(value: string): value is Algorithm {
  return (ALGORITHMS as readonly string[]).includes(value);
}

export function isProfile(value: string): value is ProfileName {
  return (PROFILES as readonly string[]).includes(value);
}

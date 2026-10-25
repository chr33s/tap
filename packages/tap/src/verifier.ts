import { throwIfAborted } from "./abort.js";
import { systemClock } from "./clock.js";
import { isTapError, tapError } from "./errors.js";
import { assertTimeWindow, cryptographicVerify, parseSignatureHeaders } from "./message.js";
import { normalizeOrigin, originOf, parseTarget } from "./target.js";
import type {
  Clock,
  KeyResolver,
  ProfileName,
  ReplayStore,
  RequestData,
  TapVerifier,
  VerifiedAgent,
  VerifyOptions,
} from "./types.js";

export interface TapVerifierOptions {
  profile: ProfileName;
  resolver: KeyResolver;
  replay: ReplayStore;
  /**
   * Stable name of the trust source mixed into replay keys. This is the
   * configured registry, never a URL taken from the request.
   */
  trustSource: string;
  /**
   * Origins (`https://shop.example`) this verifier serves. A signature for any
   * other `@authority` is rejected, so a request signed for another merchant
   * that trusts the same registry cannot be replayed here.
   */
  origins: readonly string[];
  clock?: Clock;
  /** Acceptance window and replay retention extension. Default is zero. */
  allowedSkewSeconds?: number;
}

/** Acceptance-window extension. Also the extra time a nonce stays claimed. */
export function assertAllowedSkew(skew: number): void {
  if (!Number.isInteger(skew) || skew < 0 || skew > 60) {
    throw tapError("policy", "clock skew must be an integer from 0 to 60 seconds");
  }
}

/** Normalized, de-duplicated origin list. Throws `policy` when it is empty. */
export function normalizeOrigins(origins: readonly string[] | undefined): string[] {
  if (!origins || origins.length === 0) throw tapError("policy", "at least one origin is required");
  return [...new Set(origins.map(normalizeOrigin))];
}

/** Verifier options with every default applied and every policy check done. */
export type VerifierDeps = TapVerifierOptions & { clock: Clock; allowedSkewSeconds: number };

/**
 * Applies the verifier's option policy once: a non-empty trust source,
 * normalized origins, a bounded skew, and a default clock. Every host that
 * calls `verifyRequest` directly goes through this.
 */
export function normalizeVerifierOptions<T extends Omit<TapVerifierOptions, "resolver" | "replay">>(
  options: T,
): T & { origins: string[]; clock: Clock; allowedSkewSeconds: number } {
  if (options.trustSource.trim().length === 0) throw tapError("policy", "trust source is required");
  const allowedSkewSeconds = options.allowedSkewSeconds ?? 0;
  assertAllowedSkew(allowedSkewSeconds);
  return {
    ...options,
    origins: normalizeOrigins(options.origins),
    allowedSkewSeconds,
    clock: options.clock ?? systemClock,
  };
}

export function createTapVerifier(options: TapVerifierOptions): TapVerifier {
  const deps = normalizeVerifierOptions(options);
  return {
    verifyRequest(request, verifyOptions) {
      return verifyRequest(request, verifyOptions, deps);
    },
  };
}

export async function verifyRequest(
  request: RequestData,
  verifyOptions: VerifyOptions,
  deps: VerifierDeps,
): Promise<VerifiedAgent> {
  throwIfAborted(verifyOptions.signal);
  const target = parseTarget(request.url);
  // Before the key lookup, so a foreign origin never reaches the registry.
  if (!deps.origins.includes(originOf(target))) {
    throw tapError("policy", "request origin is not served by this verifier");
  }
  const parsed = parseSignatureHeaders({
    request,
    target,
    profile: deps.profile,
    expectedTag: verifyOptions.tag,
    requiredComponents: verifyOptions.requiredComponents,
  });
  const now = () => {
    const value = deps.clock.now();
    if (!Number.isInteger(value)) throw tapError("invalid_time", "clock must return integer seconds");
    return value;
  };
  assertTimeWindow(parsed.created, parsed.expires, now(), deps.allowedSkewSeconds);

  let key;
  try {
    key = await deps.resolver.resolve(parsed.keyId, verifyOptions.signal);
  } catch (error) {
    if (isTapError(error)) throw error;
    throw tapError("resolver_unavailable", "key resolver failed");
  }
  throwIfAborted(verifyOptions.signal);
  // The key lookup is the only step that takes real time before the nonce is
  // claimed, so the window is re-checked here and nowhere later: a failure
  // after the claim would consume the nonce and still reject.
  assertTimeWindow(parsed.created, parsed.expires, now(), deps.allowedSkewSeconds);
  if (key.keyId !== parsed.keyId) throw tapError("trust", "resolved key id does not match");
  if (key.algorithm !== parsed.alg) throw tapError("trust", "key algorithm does not match the signature");
  if (key.agentId.length === 0 || key.agentDomain.length === 0) throw tapError("trust", "resolved agent identity is incomplete");
  if (key.expiresAt !== null && key.expiresAt <= now()) throw tapError("trust", "key is expired");

  // Unusable key material surfaces as `trust`; only a signature that does not
  // verify under a usable key is `invalid_signature`.
  if (!cryptographicVerify(parsed, key.publicKey)) throw tapError("invalid_signature", "signature verification failed");

  const until = parsed.expires + deps.allowedSkewSeconds;
  let claim;
  try {
    claim = await deps.replay.claim(
      {
        trustSource: deps.trustSource,
        keyId: parsed.keyId,
        nonce: parsed.nonce,
        until,
      },
      verifyOptions.signal,
    );
  } catch (error) {
    if (isTapError(error)) throw error;
    throw tapError("store_unavailable", "replay store failed");
  }
  if (claim === "expired") throw tapError("invalid_time", "replay claim deadline has passed");
  if (claim === "duplicate") throw tapError("replay", "nonce has already been used");
  throwIfAborted(verifyOptions.signal);
  return {
    agentId: key.agentId,
    agentName: key.agentName,
    agentDomain: key.agentDomain,
    keyId: key.keyId,
    algorithm: key.algorithm,
    tag: parsed.tag,
    nonce: parsed.nonce,
    created: parsed.created,
    expires: parsed.expires,
    coveredComponents: parsed.components,
  };
}

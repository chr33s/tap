import { throwIfAborted } from "./abort.js";
import { systemClock } from "./clock.js";
import { isTapError, tapError } from "./errors.js";
import { assertTimeWindow, cryptographicVerify, parseSignatureHeaders } from "./message.js";
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

export function createTapVerifier(options: TapVerifierOptions): TapVerifier {
  if (options.trustSource.trim().length === 0) throw tapError("policy", "trust source is required");
  const skew = options.allowedSkewSeconds ?? 0;
  assertAllowedSkew(skew);
  const clock = options.clock ?? systemClock;
  return {
    verifyRequest(request, verifyOptions) {
      return verifyRequest(request, verifyOptions, {
        ...options,
        allowedSkewSeconds: skew,
        clock,
      });
    },
  };
}

export async function verifyRequest(
  request: RequestData,
  verifyOptions: VerifyOptions,
  deps: TapVerifierOptions & { clock: Clock; allowedSkewSeconds: number },
): Promise<VerifiedAgent> {
  throwIfAborted(verifyOptions.signal);
  const parsed = parseSignatureHeaders({
    request,
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
  assertTimeWindow(parsed.created, parsed.expires, now(), deps.allowedSkewSeconds);
  if (key.keyId !== parsed.keyId) throw tapError("trust", "resolved key id does not match");
  if (key.algorithm !== parsed.alg) throw tapError("trust", "key algorithm does not match the signature");
  if (key.agentId.length === 0 || key.agentDomain.length === 0) throw tapError("trust", "resolved agent identity is incomplete");
  if (key.expiresAt !== null && key.expiresAt <= now()) throw tapError("trust", "key is expired");

  let valid = false;
  try {
    valid = cryptographicVerify(parsed, key.publicKey);
  } catch (error) {
    if (isTapError(error) && error.code === "trust") throw error;
    valid = false;
  }
  if (!valid) throw tapError("invalid_signature", "signature verification failed");

  assertTimeWindow(parsed.created, parsed.expires, now(), deps.allowedSkewSeconds);
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
  assertTimeWindow(parsed.created, parsed.expires, now(), deps.allowedSkewSeconds);
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

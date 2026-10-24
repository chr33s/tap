import { Context, Duration, Effect, Layer, Schedule } from "effect";
import {
  TapError,
  assertAllowedSkew,
  assertTimeWindow,
  createMemoryReplayStore,
  createRegistryKeyResolver,
  createSqliteReplayStore,
  createTapClient,
  cryptographicVerify,
  fetchRegistryKey,
  parseSignatureHeaders,
  systemClock,
  verifyRequest,
  type ClaimResult,
  type Clock,
  type KeyResolver,
  type ProfileName,
  type ReplayClaim,
  type ReplayStore,
  type RequestData,
  type ResolvedKey,
  type SignOptions,
  type SignatureHeaders,
  type TapClientOptions,
  type VerifiedAgent,
  type VerifyOptions,
} from "tap";

import { TapFailure, toTapFailure } from "./errors.js";

export class TapClientService extends Context.Service<
  TapClientService,
  {
    readonly signRequest: (request: RequestData, options: SignOptions) => Effect.Effect<SignatureHeaders, TapFailure>;
  }
>()("tap/TapClientService") {}

export class KeyResolverService extends Context.Service<
  KeyResolverService,
  {
    readonly resolve: (keyId: string, signal?: AbortSignal) => Effect.Effect<ResolvedKey, TapFailure>;
  }
>()("tap/KeyResolverService") {}

export class ReplayStoreService extends Context.Service<
  ReplayStoreService,
  {
    readonly claim: (entry: ReplayClaim, signal?: AbortSignal) => Effect.Effect<ClaimResult, TapFailure>;
  }
>()("tap/ReplayStoreService") {}

export class TapVerifierService extends Context.Service<
  TapVerifierService,
  {
    readonly verifyRequest: (request: RequestData, options: VerifyOptions) => Effect.Effect<VerifiedAgent, TapFailure>;
  }
>()("tap/TapVerifierService") {}

export function tapClientLayer(options: TapClientOptions): Layer.Layer<TapClientService> {
  const client = createTapClient(options);
  return Layer.succeed(TapClientService, {
    signRequest: (request, signOptions) =>
      Effect.tryPromise({
        try: (signal) => client.signRequest(request, { ...signOptions, signal: merge(signOptions.signal, signal) }),
        catch: toTapFailure,
      }),
  });
}

export interface VerifierLayerConfig {
  profile: ProfileName;
  trustSource: string;
  clock?: Clock;
  allowedSkewSeconds?: number;
}

/**
 * Shared verification pipeline. Key resolution and replay admission come from
 * the surrounding layers. Replay claims are not retried.
 */
export function tapVerifierLayer(
  config: VerifierLayerConfig,
): Layer.Layer<TapVerifierService, never, KeyResolverService | ReplayStoreService> {
  const skew = config.allowedSkewSeconds ?? 0;
  const clock = config.clock ?? systemClock;
  assertAllowedSkew(skew);
  if (config.trustSource.trim().length === 0) {
    throw new TapError("policy", "trust source is required");
  }
  return Layer.effect(
    TapVerifierService,
    Effect.gen(function* () {
      const resolver = yield* KeyResolverService;
      const replay = yield* ReplayStoreService;
      return {
        verifyRequest: (request, options) =>
          Effect.scoped(
            Effect.gen(function* () {
              const fiberSignal = yield* Effect.abortSignal;
              const signal = merge(options.signal, fiberSignal);
              const parsed = yield* Effect.try({
                try: () =>
                  parseSignatureHeaders({
                    request,
                    profile: config.profile,
                    expectedTag: options.tag,
                    requiredComponents: options.requiredComponents,
                  }),
                catch: toTapFailure,
              });
              const readNow = (): number => {
                const value = clock.now();
                if (!Number.isInteger(value)) {
                  throw new TapError("invalid_time", "clock must return integer seconds");
                }
                return value;
              };
              yield* Effect.try({
                try: () => assertTimeWindow(parsed.created, parsed.expires, readNow(), skew),
                catch: toTapFailure,
              });
              const key = yield* resolver.resolve(parsed.keyId, signal);
              yield* Effect.try({
                try: () => {
                  assertTimeWindow(parsed.created, parsed.expires, readNow(), skew);
                  if (key.keyId !== parsed.keyId) throw new TapError("trust", "resolved key id does not match");
                  if (key.algorithm !== parsed.alg) throw new TapError("trust", "key algorithm does not match the signature");
                  if (key.agentId.length === 0 || key.agentDomain.length === 0) {
                    throw new TapError("trust", "resolved agent identity is incomplete");
                  }
                  if (key.expiresAt !== null && key.expiresAt <= readNow()) throw new TapError("trust", "key is expired");
                  if (!cryptographicVerify(parsed, key.publicKey)) {
                    throw new TapError("invalid_signature", "signature verification failed");
                  }
                  assertTimeWindow(parsed.created, parsed.expires, readNow(), skew);
                },
                catch: toTapFailure,
              });
              const claim = yield* replay.claim(
                {
                  trustSource: config.trustSource,
                  keyId: parsed.keyId,
                  nonce: parsed.nonce,
                  until: parsed.expires + skew,
                },
                signal,
              );
              yield* Effect.try({
                try: () => {
                  if (claim === "expired") throw new TapError("invalid_time", "replay claim deadline has passed");
                  if (claim === "duplicate") throw new TapError("replay", "nonce has already been used");
                  assertTimeWindow(parsed.created, parsed.expires, readNow(), skew);
                  if (signal?.aborted) throw new TapError("cancelled", "operation aborted");
                },
                catch: toTapFailure,
              });
              const verified: VerifiedAgent = {
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
              return verified;
            }),
          ),
      };
    }),
  );
}

/** Promise verifier wrapped as an Effect, for hosts that already built core dependencies. */
export function tapVerifierFromPromises(input: VerifierLayerConfig & {
  resolver: KeyResolver;
  replay: ReplayStore;
}): Layer.Layer<TapVerifierService> {
  assertAllowedSkew(input.allowedSkewSeconds ?? 0);
  if (input.trustSource.trim().length === 0) throw new TapError("policy", "trust source is required");
  return Layer.succeed(TapVerifierService, {
    verifyRequest: (request, options) =>
      Effect.tryPromise({
        try: (signal) =>
          verifyRequest(request, { ...options, signal: merge(options.signal, signal) }, {
            profile: input.profile,
            trustSource: input.trustSource,
            resolver: input.resolver,
            replay: input.replay,
            clock: input.clock ?? systemClock,
            allowedSkewSeconds: input.allowedSkewSeconds ?? 0,
          }),
        catch: toTapFailure,
      }),
  });
}

export interface RegistryResolverConfig {
  registryUrl: string;
  cacheTtlMs?: number;
  timeoutMs?: number;
  clock?: Clock;
  fetchImpl?: typeof fetch;
  /** Retries after the first attempt. Authentication failures are not retried. */
  retries?: number;
  transientRetries?: number;
}

/**
 * Uncached registry reads with Effect retries. Authentication failures and
 * replay claims are never retried; this layer does not claim nonces.
 */
export function registryKeyResolverLayer(config: RegistryResolverConfig): Layer.Layer<KeyResolverService> {
  const retries = config.retries ?? config.transientRetries ?? 2;
  return Layer.succeed(KeyResolverService, {
    resolve: (keyId, signal) =>
      Effect.tryPromise({
        try: (fiberSignal) =>
          fetchRegistryKey({
            registryUrl: config.registryUrl,
            keyId,
            timeoutMs: config.timeoutMs ?? 2_000,
            signal: merge(signal, fiberSignal),
            fetchImpl: config.fetchImpl,
            clock: config.clock,
          }),
        catch: toTapFailure,
      }).pipe(
        Effect.retry({
          times: retries,
          schedule: Schedule.spaced(Duration.millis(10)),
          while: (error) => error.code === "resolver_unavailable" && error.reason !== "unauthorized",
        }),
      ),
  });
}

/** Cached registry resolver. The core cache enforces the 30 second revocation bound. */
export function cachingRegistryResolverLayer(config: RegistryResolverConfig): Layer.Layer<KeyResolverService> {
  const resolver = createRegistryKeyResolver({
    ...config,
    transientRetries: config.transientRetries ?? config.retries ?? 2,
  });
  return Layer.succeed(KeyResolverService, {
    resolve: (keyId, signal) =>
      Effect.tryPromise({
        try: (fiberSignal) => resolver.resolve(keyId, merge(signal, fiberSignal)),
        catch: toTapFailure,
      }),
  });
}

export function memoryReplayLayer(store: ReplayStore = createMemoryReplayStore()): Layer.Layer<ReplayStoreService> {
  return Layer.succeed(ReplayStoreService, {
    claim: (entry, signal) =>
      Effect.tryPromise({
        try: () => store.claim(entry, signal),
        catch: toTapFailure,
      }),
  });
}

export function sqliteReplayLayer(filename: string, clock?: Clock): Layer.Layer<ReplayStoreService> {
  return Layer.effect(
    ReplayStoreService,
    Effect.acquireRelease(
      Effect.sync(() => createSqliteReplayStore(filename, clock)),
      (store) => Effect.sync(() => store.close()),
    ).pipe(
      Effect.map((store) => ({
        claim: (entry: ReplayClaim, signal?: AbortSignal) =>
          Effect.tryPromise({
            try: () => store.claim(entry, signal),
            catch: toTapFailure,
          }),
      })),
    ),
  );
}

function merge(left?: AbortSignal, right?: AbortSignal): AbortSignal | undefined {
  if (left && right) return AbortSignal.any([left, right]);
  return left ?? right;
}

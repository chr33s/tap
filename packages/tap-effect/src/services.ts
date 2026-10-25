import { Context, Effect, Layer } from "effect";
import {
  TapError,
  assertAllowedSkew,
  createMemoryReplayStore,
  createRegistryKeyResolver,
  createSqliteReplayStore,
  createTapClient,
  mergeSignals,
  normalizeOrigins,
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
  type TapVerifierOptions,
  type VerifiedAgent,
  type VerifyOptions,
} from "@chr33s/tap";

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
        try: (signal) => client.signRequest(request, { ...signOptions, signal: mergeSignals([signOptions.signal, signal]) }),
        catch: toTapFailure,
      }),
  });
}

export interface VerifierLayerConfig {
  profile: ProfileName;
  trustSource: string;
  /** Origins this verifier serves; see `TapVerifierOptions.origins`. */
  origins: readonly string[];
  clock?: Clock;
  allowedSkewSeconds?: number;
}

/**
 * Effect adapter over `verifyRequest`. Key resolution and replay admission
 * come from the surrounding layers and run with this layer's context.
 * Replay claims are not retried.
 */
export function tapVerifierLayer(
  config: VerifierLayerConfig,
): Layer.Layer<TapVerifierService, never, KeyResolverService | ReplayStoreService> {
  const deps = verifierDeps(config);
  return Layer.effect(
    TapVerifierService,
    Effect.gen(function* () {
      const resolver = yield* KeyResolverService;
      const replay = yield* ReplayStoreService;
      const context = yield* Effect.context<KeyResolverService | ReplayStoreService>();
      const run = Effect.runPromiseWith(context);
      return promiseVerifier({
        ...deps,
        resolver: {
          resolve: (keyId, signal) => unwrap(run(resolver.resolve(keyId, signal))),
        },
        replay: {
          claim: (entry, signal) => unwrap(run(replay.claim(entry, signal))),
        },
      });
    }),
  );
}

/** Promise verifier wrapped as an Effect, for hosts that already built core dependencies. */
export function tapVerifierFromPromises(input: VerifierLayerConfig & {
  resolver: KeyResolver;
  replay: ReplayStore;
}): Layer.Layer<TapVerifierService> {
  return Layer.succeed(TapVerifierService, promiseVerifier({
    ...verifierDeps(input),
    resolver: input.resolver,
    replay: input.replay,
  }));
}

export interface RegistryResolverConfig {
  registryUrl: string;
  cacheTtlMs?: number;
  timeoutMs?: number;
  clock?: Clock;
  fetchImpl?: typeof fetch;
  /** Retries after a network error, timeout, or `5xx`. Deterministic registry answers are not retried. */
  transientRetries?: number;
  /** Delay before the first retry, doubling each time. Default is 50 ms. */
  retryBackoffMs?: number;
}

/** Cached registry resolver. The core resolver owns the retry loop and the 30 second revocation bound. */
export function cachingRegistryResolverLayer(config: RegistryResolverConfig): Layer.Layer<KeyResolverService> {
  const resolver = createRegistryKeyResolver(config);
  return Layer.succeed(KeyResolverService, {
    resolve: (keyId, signal) =>
      Effect.tryPromise({
        try: (fiberSignal) => resolver.resolve(keyId, mergeSignals([signal, fiberSignal])),
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

function verifierDeps(config: VerifierLayerConfig): Omit<TapVerifierOptions, "resolver" | "replay"> & {
  clock: Clock;
  allowedSkewSeconds: number;
} {
  const allowedSkewSeconds = config.allowedSkewSeconds ?? 0;
  assertAllowedSkew(allowedSkewSeconds);
  if (config.trustSource.trim().length === 0) throw new TapError("policy", "trust source is required");
  return {
    profile: config.profile,
    trustSource: config.trustSource,
    origins: normalizeOrigins(config.origins),
    clock: config.clock ?? systemClock,
    allowedSkewSeconds,
  };
}

function promiseVerifier(deps: TapVerifierOptions & { clock: Clock; allowedSkewSeconds: number }) {
  return {
    verifyRequest: (request: RequestData, options: VerifyOptions) =>
      Effect.tryPromise({
        try: (signal: AbortSignal) =>
          verifyRequest(request, { ...options, signal: mergeSignals([options.signal, signal]) }, deps),
        catch: toTapFailure,
      }),
  };
}

function unwrap<A>(promise: Promise<A>): Promise<A> {
  return promise.then(
    (value) => value,
    (error: unknown) => {
      if (error instanceof TapFailure) throw new TapError(error.code, error.reason);
      throw error;
    },
  );
}

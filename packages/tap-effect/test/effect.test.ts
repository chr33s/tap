import assert from "node:assert/strict";
import { test } from "node:test";

import { Effect, Layer, ManagedRuntime } from "effect";
import { createSigner, generateKeyPair, type KeyResolver, type ReplayStore } from "tap";
import {
  KeyResolverService,
  ReplayStoreService,
  TapClientService,
  TapFailure,
  TapVerifierService,
  registryKeyResolverLayer,
  tapClientLayer,
  tapVerifierLayer,
  toTapFailure,
} from "tap-effect";

import { runConformance, type ConformanceApi } from "../../tap/test/conformance.ts";

test("effect API passes the conformance suite", async () => {
  await runConformance(effectApi());
});

test("effect retries transient key reads and does not retry unauthorized responses", async () => {
  const pair = generateKeyPair("ed25519");
  let failures = 0;
  const runtime = ManagedRuntime.make(registryKeyResolverLayer({
    registryUrl: "https://registry.test",
    retries: 2,
    fetchImpl: async () => {
      failures += 1;
      if (failures < 3) throw new Error("temporary");
      return new Response(JSON.stringify({
        key_id: "k",
        public_key: pair.publicKey.trim(),
        algorithm: "ed25519",
        is_active: "true",
        agent_id: "1",
        agent_name: "A",
        agent_domain: "https://a.example",
        expires_at: null,
      }), { status: 200 });
    },
  }));
  const key = await runtime.runPromise(Effect.gen(function* () {
    const resolver = yield* KeyResolverService;
    return yield* resolver.resolve("k");
  }));
  assert.equal(key.keyId, "k");
  assert.equal(failures, 3);
  await runtime.dispose();

  let denied = 0;
  const deniedRuntime = ManagedRuntime.make(registryKeyResolverLayer({
    registryUrl: "https://registry.test",
    retries: 2,
    fetchImpl: async () => {
      denied += 1;
      return new Response("no", { status: 401 });
    },
  }));
  await assert.rejects(
    () => deniedRuntime.runPromise(Effect.gen(function* () {
      const resolver = yield* KeyResolverService;
      return yield* resolver.resolve("k");
    })),
    (error: unknown) => error instanceof TapFailure && error.reason === "unauthorized",
  );
  assert.equal(denied, 1);
  await deniedRuntime.dispose();
});

function effectApi(): ConformanceApi {
  return {
    async sign(input) {
      const runtime = ManagedRuntime.make(tapClientLayer({
        keyId: input.keyId,
        profile: input.profile,
        signer: createSigner(input.algorithm, input.privateKey),
        clock: input.clock,
        nonce: () => input.nonce ?? "nonce-default-1",
      }));
      try {
        return await runtime.runPromise(Effect.gen(function* () {
          const client = yield* TapClientService;
          return yield* client.signRequest(input.request, input.options);
        }));
      } finally {
        await runtime.dispose();
      }
    },
    async verify(input) {
      const runtime = ManagedRuntime.make(
        tapVerifierLayer({
          profile: input.profile,
          trustSource: input.trustSource ?? "test-source",
          clock: input.clock,
          allowedSkewSeconds: input.allowedSkewSeconds,
        }).pipe(Layer.provide(Layer.mergeAll(resolverLayer(input.resolver), replayLayer(input.replay)))),
      );
      try {
        return await runtime.runPromise(Effect.gen(function* () {
          const verifier = yield* TapVerifierService;
          return yield* verifier.verifyRequest(input.request, input.options);
        }));
      } finally {
        await runtime.dispose();
      }
    },
  };
}

function resolverLayer(resolver: KeyResolver): Layer.Layer<KeyResolverService> {
  return Layer.succeed(KeyResolverService, {
    resolve: (keyId, signal) => Effect.tryPromise({
      try: () => resolver.resolve(keyId, signal),
      catch: toTapFailure,
    }),
  });
}

function replayLayer(store: ReplayStore): Layer.Layer<ReplayStoreService> {
  return Layer.succeed(ReplayStoreService, {
    claim: (entry, signal) => Effect.tryPromise({
      try: () => store.claim(entry, signal),
      catch: toTapFailure,
    }),
  });
}

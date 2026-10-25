import assert from "node:assert/strict";

import {
  TapError,
  createManualClock,
  createMemoryReplayStore,
  createSigner,
  createStaticKeyResolver,
  createTapClient,
  parseTarget,
  type Clock,
  type KeyResolver,
  type ProfileName,
  type ReplayStore,
  type RequestData,
  type ResolvedKey,
  type SignOptions,
  type SignatureHeaders,
  type VerifiedAgent,
  type VerifyOptions,
} from "@chr33s/tap";

const SEED = "uGx6XjUWoeo2uCUokFS83WvEKev+FYRsmGZQOdGYBSw=";
const PUBLIC_KEY = "IvsH6xEgJSeC9U4IsQanNtetaYi6BUiNarA0N04rN2s=";
const EXPECTED_SIG = "mFkCOm3oAd+FY41uKQAurbjy9N/abIbPQtvFN72dTY5jgsJhFxuxE5kcffknUfFqNhS5qRuYSRk34+rlWINmAA==";

export interface ConformanceApi {
  sign(input: {
    request: RequestData;
    profile: ProfileName;
    keyId: string;
    privateKey: string;
    algorithm: "ed25519" | "rsa-pss-sha256";
    clock?: Clock;
    nonce?: string;
    options: SignOptions;
  }): Promise<SignatureHeaders>;
  verify(input: {
    request: RequestData;
    profile: ProfileName;
    resolver: KeyResolver;
    replay: ReplayStore;
    clock?: Clock;
    trustSource?: string;
    origins?: readonly string[];
    allowedSkewSeconds?: number;
    options: VerifyOptions;
  }): Promise<VerifiedAgent>;
}

/** The request's own origin, so harness callers that do not care about origins still verify. */
export function originsFor(url: string): string[] {
  const target = parseTarget(url);
  return [`${target.scheme}://${target.normalizedAuthority}`];
}

export async function runConformance(api: ConformanceApi): Promise<void> {
  const clock = createManualClock(1_700_000_000_000);
  const request: RequestData = { method: "GET", url: "https://example.com/product/1", headers: [] };
  const headers = await api.sign({
    request,
    profile: "tap",
    keyId: "agent-key-1",
    privateKey: SEED,
    algorithm: "ed25519",
    clock,
    nonce: "nonce-fixed-1",
    options: { tag: "agent-browser-auth" },
  });
  assert.equal(
    headers["Signature-Input"],
    'sig1=("@authority" "@path");created=1700000000;expires=1700000480;keyid="agent-key-1";alg="ed25519";nonce="nonce-fixed-1";tag="agent-browser-auth"',
  );
  assert.equal(headers.Signature, `sig1=:${EXPECTED_SIG}:`);
  const again = await api.sign({
    request,
    profile: "tap",
    keyId: "agent-key-1",
    privateKey: SEED,
    algorithm: "ed25519",
    clock,
    nonce: "nonce-fixed-1",
    options: { tag: "agent-browser-auth" },
  });
  assert.deepEqual(again, headers);

  const key = resolved(PUBLIC_KEY);
  const replay = createMemoryReplayStore(clock);
  const verified = await api.verify({
    request: withHeaders(request, headers),
    profile: "tap",
    resolver: createStaticKeyResolver([key]),
    replay,
    clock,
    options: { tag: "agent-browser-auth" },
  });
  assert.equal(verified.agentId, "7");
  assert.equal(verified.keyId, "agent-key-1");
  assert.deepEqual(verified.coveredComponents, ["@authority", "@path"]);
  assert.equal(verified.tag, "agent-browser-auth");

  const spaced = headers["Signature-Input"].replace(";created=", "; created=");
  await api.verify({
    request: withHeaders(request, { ...headers, "Signature-Input": spaced }),
    profile: "tap",
    resolver: createStaticKeyResolver([key]),
    replay: createMemoryReplayStore(clock),
    clock,
    options: { tag: "agent-browser-auth" },
  });

  await rejects("invalid_signature", () =>
    api.verify({
      request: withHeaders({ ...request, url: "https://example.com/product/2" }, headers),
      profile: "tap",
      resolver: createStaticKeyResolver([key]),
      replay: createMemoryReplayStore(clock),
      clock,
      options: { tag: "agent-browser-auth" },
    }),
  );
  await api.verify({
    request: withHeaders(request, headers),
    profile: "tap",
    resolver: createStaticKeyResolver([key]),
    replay: createMemoryReplayStore(clock),
    clock,
    options: { tag: "agent-browser-auth" },
  });

  const methodRequest: RequestData = { ...request, method: "POST" };
  await api.verify({
    request: withHeaders(methodRequest, headers),
    profile: "tap",
    resolver: createStaticKeyResolver([key]),
    replay: createMemoryReplayStore(clock),
    clock,
    options: { tag: "agent-browser-auth" },
  });
  await rejects("policy", () =>
    api.verify({
      request: withHeaders(request, headers),
      profile: "tap",
      resolver: createStaticKeyResolver([key]),
      replay: createMemoryReplayStore(clock),
      clock,
      options: { tag: "agent-browser-auth", requiredComponents: ["@method"] },
    }),
  );

  const covered = await api.sign({
    request: { method: "POST", url: "https://example.com/product/1?q=1", headers: [["content-type", "application/json"]] },
    profile: "tap",
    keyId: "agent-key-1",
    privateKey: SEED,
    algorithm: "ed25519",
    clock,
    nonce: "nonce-covered-1",
    options: { tag: "agent-payer-auth", coveredComponents: ["@method", "@authority", "@path", "@query", "content-type"] },
  });
  const coveredVerified = await api.verify({
    request: withHeaders(
      { method: "POST", url: "https://example.com/product/1?q=1", headers: [["content-type", "application/json"]] },
      covered,
    ),
    profile: "tap",
    resolver: createStaticKeyResolver([key]),
    replay: createMemoryReplayStore(clock),
    clock,
    options: { tag: "agent-payer-auth" },
  });
  assert.deepEqual(coveredVerified.coveredComponents, ["@method", "@authority", "@path", "@query", "content-type"]);
  await api.verify({
    request: withHeaders(
      { method: "POST", url: "https://example.com/product/1?q=2", headers: [["content-type", "application/json"]] },
      covered,
    ),
    profile: "tap",
    resolver: createStaticKeyResolver([key]),
    replay: createMemoryReplayStore(clock),
    clock,
    options: { tag: "agent-payer-auth" },
  }).then(() => assert.fail("query is covered"), (error: unknown) => assert.equal(codeOf(error), "invalid_signature"));

  const queryUrl = "https://example.com/product/1?a=b%20c";
  const queryHeaders = await api.sign({
    request: { method: "GET", url: queryUrl, headers: [] },
    profile: "tap",
    keyId: "agent-key-1",
    privateKey: SEED,
    algorithm: "ed25519",
    clock,
    nonce: "nonce-query-1",
    options: { tag: "agent-browser-auth" },
  });
  await api.verify({
    request: withHeaders({ method: "GET", url: "https://example.com/product/1?a=other", headers: [] }, queryHeaders),
    profile: "tap",
    resolver: createStaticKeyResolver([key]),
    replay: createMemoryReplayStore(clock),
    clock,
    options: { tag: "agent-browser-auth" },
  });

  await rejects("policy", () =>
    api.verify({
      request: withHeaders(request, headers),
      profile: "tap",
      resolver: createStaticKeyResolver([key]),
      replay: createMemoryReplayStore(clock),
      clock,
      options: { tag: "agent-payer-auth" },
    }),
  );
  await rejects("trust", () =>
    api.verify({
      request: withHeaders(request, headers),
      profile: "tap",
      resolver: createStaticKeyResolver([]),
      replay: createMemoryReplayStore(clock),
      clock,
      options: { tag: "agent-browser-auth" },
    }),
  );
  await rejects("trust", () =>
    api.verify({
      request: withHeaders(request, headers),
      profile: "tap",
      resolver: createStaticKeyResolver([{ ...key, algorithm: "rsa-pss-sha256", publicKey: "not-a-key" }]),
      replay: createMemoryReplayStore(clock),
      clock,
      options: { tag: "agent-browser-auth" },
    }),
  );

  const later = createManualClock(1_700_000_480_000);
  await rejects("invalid_time", () =>
    api.verify({
      request: withHeaders(request, headers),
      profile: "tap",
      resolver: createStaticKeyResolver([key]),
      replay: createMemoryReplayStore(later),
      clock: later,
      options: { tag: "agent-browser-auth" },
    }),
  );
  const skewed = createManualClock(1_700_000_480_000);
  await api.verify({
    request: withHeaders(request, headers),
    profile: "tap",
    resolver: createStaticKeyResolver([key]),
    replay: createMemoryReplayStore(skewed),
    clock: skewed,
    allowedSkewSeconds: 1,
    options: { tag: "agent-browser-auth" },
  });
  const tooLate = createManualClock(1_700_000_481_000);
  await rejects("invalid_time", () =>
    api.verify({
      request: withHeaders(request, headers),
      profile: "tap",
      resolver: createStaticKeyResolver([key]),
      replay: createMemoryReplayStore(tooLate),
      clock: tooLate,
      allowedSkewSeconds: 1,
      options: { tag: "agent-browser-auth" },
    }),
  );

  await rejects("invalid_time", () =>
    api.sign({
      request,
      profile: "tap",
      keyId: "agent-key-1",
      privateKey: SEED,
      algorithm: "ed25519",
      clock,
      nonce: "nonce-long-1",
      options: { tag: "agent-browser-auth", lifetimeSeconds: 481 },
    }),
  );

  const ambiguousInput = `${headers["Signature-Input"]}, ${headers["Signature-Input"].replace("sig1=", "sig2=")}`;
  const ambiguousSig = `${headers.Signature}, ${headers.Signature.replace("sig1=", "sig2=")}`;
  await rejects("policy", () =>
    api.verify({
      request: withHeaders(request, { "Signature-Input": ambiguousInput, Signature: ambiguousSig }),
      profile: "tap",
      resolver: createStaticKeyResolver([key]),
      replay: createMemoryReplayStore(clock),
      clock,
      options: { tag: "agent-browser-auth" },
    }),
  );

  const shared = createMemoryReplayStore(clock);
  const fresh = await api.sign({
    request,
    profile: "tap",
    keyId: "agent-key-1",
    privateKey: SEED,
    algorithm: "ed25519",
    clock,
    nonce: "nonce-race-1",
    options: { tag: "agent-browser-auth" },
  });
  const signed = withHeaders(request, fresh);
  const results = await Promise.all(
    Array.from({ length: 8 }, () =>
      api.verify({
        request: signed,
        profile: "tap",
        resolver: createStaticKeyResolver([key]),
        replay: shared,
        clock,
        options: { tag: "agent-browser-auth" },
      }).then(() => "ok", (error: unknown) => codeOf(error)),
    ),
  );
  assert.equal(results.filter((result) => result === "ok").length, 1);
  assert.equal(results.filter((result) => result === "replay").length, 7);

  const ac = new AbortController();
  ac.abort();
  await rejects("cancelled", () =>
    api.verify({
      request: withHeaders(request, headers),
      profile: "tap",
      resolver: createStaticKeyResolver([key]),
      replay: createMemoryReplayStore(clock),
      clock,
      options: { tag: "agent-browser-auth", signal: ac.signal },
    }),
  );

  await rejects("resolver_unavailable", () =>
    api.verify({
      request: withHeaders(request, fresh),
      profile: "tap",
      resolver: {
        async resolve() {
          throw new TapError("resolver_unavailable", "down");
        },
      },
      replay: createMemoryReplayStore(clock),
      clock,
      options: { tag: "agent-browser-auth" },
    }),
  );
}

export function promiseApi(): ConformanceApi {
  return {
    async sign(input) {
      const client = createTapClient({
        keyId: input.keyId,
        profile: input.profile,
        signer: createSigner(input.algorithm, input.privateKey),
        clock: input.clock,
        nonce: () => input.nonce ?? "nonce-default-1",
      });
      return client.signRequest(input.request, input.options);
    },
    async verify(input) {
      const { createTapVerifier } = await import("@chr33s/tap");
      const verifier = createTapVerifier({
        profile: input.profile,
        resolver: input.resolver,
        replay: input.replay,
        trustSource: input.trustSource ?? "test-source",
        origins: input.origins ?? originsFor(input.request.url),
        clock: input.clock,
        allowedSkewSeconds: input.allowedSkewSeconds,
      });
      return verifier.verifyRequest(input.request, input.options);
    },
  };
}

function resolved(publicKey: string): ResolvedKey {
  return {
    keyId: "agent-key-1",
    publicKey,
    algorithm: "ed25519",
    agentId: "7",
    agentName: "Example Agent",
    agentDomain: "https://agent.example",
    expiresAt: null,
  };
}

function withHeaders(request: RequestData, headers: SignatureHeaders): RequestData {
  return {
    ...request,
    headers: [
      ...request.headers,
      ["signature-input", headers["Signature-Input"]],
      ["signature", headers.Signature],
    ],
  };
}

async function rejects(expected: string, fn: () => Promise<unknown>): Promise<void> {
  await assert.rejects(fn, (error: unknown) => {
    assert.equal(codeOf(error), expected);
    return true;
  });
}

function codeOf(error: unknown): string {
  if (typeof error === "object" && error !== null && "code" in error) return String(error.code);
  return "";
}

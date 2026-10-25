import type { ProxyConfig } from "../src/config.ts";

type Required = Pick<ProxyConfig, "port" | "upstream" | "registryUrl" | "replayDatabase">;

/** A `ProxyConfig` with test defaults; every hand-built config in the tests goes through here. */
export function testProxyConfig(overrides: Required & Partial<ProxyConfig>): ProxyConfig {
  return {
    host: "127.0.0.1",
    origins: [`http://127.0.0.1:${overrides.port}`, "https://shop.example"],
    profile: "tap",
    trustSource: `registry:${overrides.registryUrl}`,
    protectedRoutes: [{ prefix: "/product", tag: "agent-browser-auth" }],
    publicRoutes: [],
    cacheTtlMs: 0,
    trustedProxies: [],
    allowedSkewSeconds: 0,
    upstreamTimeoutMs: 1_000,
    headersTimeoutMs: 10_000,
    headerLimit: 16_384,
    bodyLimit: 1_048_576,
    ...overrides,
  };
}

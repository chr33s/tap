import { loadProxyConfig } from "./config.js";
import { startProxy } from "./server.js";

const config = loadProxyConfig(process.env);
if (!isLoopback(config.upstream.hostname) && !config.backendToken) {
  process.stderr.write("warning: upstream is not loopback and TAP_BACKEND_TOKEN is unset\n");
}
process.stderr.write(
  `key cache TTL ${config.cacheTtlMs}ms (maximum revocation delay is min(TTL, 30000ms, key expires_at); stale keys are not served)\n`,
);

const handle = await startProxy(config);
process.stdout.write(`proxy listening on ${handle.url}\n`);

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    void handle.close().then(() => process.exit(0));
  });
}

function isLoopback(host: string): boolean {
  return host === "127.0.0.1" || host === "localhost" || host === "::1";
}

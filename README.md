# Trusted Agent Protocol (TypeScript)

Shared TAP libraries plus a signing agent, an operator registry, and a verifying reverse proxy. The libraries do not depend on a merchant application. Python is used only by the legacy interoperability tests.

This follows the Visa sample at [`16d59bdf`](https://github.com/visa/trusted-agent-protocol/commit/16d59bdf3f8a542bc538d0962edbb80ea30a02af) for the wire formats it still needs, and replaces that sample's permissive checks. See [NOTICE.md](./NOTICE.md) for the upstream license and specification. Local registry approval is this deployment's trust policy and does not mean Visa certified the agent.

## Layout

| Path | Role |
| --- | --- |
| `packages/tap` | Parsing, signature base, Node crypto, `tap/client`, and `tap/server`. No Effect dependency. |
| `packages/tap-effect` | The same operations as Effect services and layers. |
| `apps/agent` | `keygen`, `sign`, and `send`. |
| `apps/registry` | Agent and public-key lifecycle API. SQLite. |
| `apps/proxy` | Reverse proxy that verifies TAP before forwarding. |

Profiles do not fall back into each other.

- `tap` is RFC 9421 canonical Structured Fields, Ed25519 only. `@path` excludes the query. `@authority` is normalized. Required coverage is `@authority` and `@path`, plus `created`, `expires`, `keyid`, `alg`, `nonce`, and tag `agent-browser-auth` or `agent-payer-auth`. `@method` and `@query` are optional. Lifetime is 1 to 480 seconds.
- `legacySample` keeps the sample's `sig2` bytes: `keyId`, spaces after semicolons, and the query inside `@path`. Ed25519 and RSA-PSS-SHA256 (SHA-256, MGF1, maximum salt) are allowed. The old Python `sig1` verifier is not supported.

Uncovered method, query, and body bytes are not authenticated. Body digests are outside this version. `VerifiedAgent.coveredComponents` is the list that was signed.

## Requirements

Node.js 22.13 or newer (Node.js 24 is the intended runtime). npm. The interop tests also need Python 3 with `cryptography`.

```bash
npm install
npm run build
npm test
```

## Registry

```bash
cp apps/registry/.env.example .env.registry
# edit TAP_ADMIN_TOKEN
set -a && source .env.registry && set +a
npm run start:registry
```

`HOST=127.0.0.1` may use HTTP. Any other bind address requires `TLS_CERT_FILE` and `TLS_KEY_FILE`. Mutations need `Authorization: Bearer <TAP_ADMIN_TOKEN>`. Reads of active trust records do not.

New agents and new keys stay inactive until an operator activates them. Registration updates metadata for an existing domain and does not replace keys or change activation. Key ids are unique across the registry and the public key stored for an id cannot be replaced. Rotate by adding and activating a new id, then revoking the old one. Deactivating an agent disables every key it owns.

Public key lookups return `key_id`, `public_key`, `algorithm`, `is_active`, `agent_id`, `agent_name`, `agent_domain`, and `expires_at` only when the agent and the key are active and the key is unexpired. `is_active` is the string `"true"` or `"false"` on the wire. `expires_at` is Unix seconds or null. Ambiguous key ids fail closed instead of returning an arbitrary row.

## Proxy

```bash
cp apps/proxy/.env.example .env.proxy
set -a && source .env.proxy && set +a
npm run start:proxy
```

Protected routes name the expected tag and any extra covered components. Omit `methods`, or set `"*"`, to match every method. Public routes must be listed too. Anything else is rejected. The proxy verifies the URL the client addressed (honoring forwarded host and proto only from `TAP_TRUSTED_PROXIES`) and then connects to `UPSTREAM_URL`, keeping any path in it as a prefix. That URL's origin must be listed in `TAP_ORIGINS`, so a signature made for another merchant that trusts the same registry is rejected. Paths with `//`, `%uXXXX`, or an escaped unreserved character, `/`, or `\` are rejected with `400`. Other paths are matched after up to three rounds of percent-decoding, case folding, and dropping `;` segment parameters, so `/ADMIN`, `/%2561dmin`, and `/admin;x` all match a protected `/admin` prefix; a path still encoded after three rounds is rejected. A prefix ending in `/` matches only paths below it. The raw path is still what is verified and forwarded. Request targets that contain a fragment, a backslash, or a `.` or `..` segment (including `%2e`) are rejected before routing. It strips incoming `x-tap-*`, `x-signature-verified`, and `x-agent-verified`, and sets `x-tap-agent-id`, `x-tap-key-id`, `x-tap-tag`, and `x-tap-covered` only after verification. `x-tap-covered` is the signed component list in order, so the backend can see that an uncovered method, query, or body was not authenticated.

`REGISTRY_URL` must be `https` unless its host is loopback (`localhost`, `::1`, or `127.0.0.0/8`). The registry bind policy uses that same definition. `TAP_BACKEND_TOKEN` is required when `UPSTREAM_URL` is not loopback; the proxy sends it as `x-tap-backend-token` and removes any client-supplied value.

Key lookups are cached for at most `min(TAP_CACHE_TTL_MS, 30000, key expires_at)` milliseconds. That is the longest revocation can lag. After the entry expires, a registry failure is an error; the proxy does not reuse the stale key. The proxy admits each nonce once in its SQLite replay store. A backend behind the proxy should trust the injected headers and should not admit the nonce again. A backend without this proxy should call `createTapVerifier` from `tap/server` and admit nonces itself.

`400` malformed input, `413` when the body exceeds the limit, `403` failed or missing verification, `503` registry or replay store unavailable, `502` upstream failure. Forwarded requests are not retried.

## Agent

```bash
npm run tap-agent -- keygen --alg ed25519 --out ./tap-keys
npm run tap-agent -- sign --key-file ./tap-keys/ed25519.private --key-id agent-key-1 \
  --url http://127.0.0.1:3001/product/1 --tag agent-browser-auth
npm run tap-agent -- send --key-file ./tap-keys/ed25519.private --key-id agent-key-1 \
  --url http://127.0.0.1:3001/product/1 --tag agent-browser-auth
```

`sign` and `send` read the private key from the file. Each call generates a new nonce, signs the given URL, and does not follow redirects or retry. Publish only the `.public` file to the registry.

## Library

```ts
import { createSigner, createTapClient } from "tap/client";
import { createRegistryKeyResolver, createSqliteReplayStore, createTapVerifier } from "tap/server";
```

`createTapVerifier` and `tapVerifierLayer` require `origins`, the origins the verifier serves (`["https://shop.example"]`); a signature for any other `@authority` fails with `policy` before the key lookup. `RequestData.url` is the absolute URL with the original path and query encoding. Pass an `AbortSignal` through sign, verify, resolve, and claim. Effect hosts should build one `ManagedRuntime` from `tap-effect` and run each request on it. The Effect verifier calls the same `verifyRequest` pipeline as the promise API. The registry resolver retries transient key reads and does not retry `401`/`403`. Replay claims are not retried.

import { tapError } from "./errors.js";
import type { Algorithm, ProfileName } from "./types.js";

const KEY_ID = /^[A-Za-z0-9._-]{1,100}$/;
const NONCE = /^[A-Za-z0-9._~-]{8,128}$/;

export function assertKeyId(keyId: string): void {
  // `.` and `..` would be dot segments in the registry lookup URL.
  if (!KEY_ID.test(keyId) || keyId === "." || keyId === "..") throw tapError("malformed", "invalid key id");
}

export function assertNonce(nonce: string): void {
  if (!NONCE.test(nonce)) throw tapError("malformed", "invalid nonce");
}

export function requireComponents(components: readonly string[], required: readonly string[] | undefined): void {
  if (!required) return;
  const seen = new Set(components);
  for (const component of required) {
    if (!seen.has(component)) throw tapError("policy", `missing required component ${component}`);
  }
}

export function assertAlgorithm(profile: ProfileName, alg: string): asserts alg is Algorithm {
  if (profile === "tap" && alg !== "ed25519") throw tapError("policy", "algorithm not allowed");
  if (profile === "legacySample" && alg !== "ed25519" && alg !== "rsa-pss-sha256") {
    throw tapError("policy", "algorithm not allowed");
  }
}

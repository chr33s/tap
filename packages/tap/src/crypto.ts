import crypto from "node:crypto";

import { throwIfAborted } from "./abort.js";
import { tapError } from "./errors.js";
import type { Algorithm, Signer } from "./types.js";

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export interface GeneratedKeyPair {
  algorithm: Algorithm;
  /** Base64 raw Ed25519 key or PEM. */
  publicKey: string;
  /** Base64 raw Ed25519 seed or PEM. */
  privateKey: string;
}

export function generateKeyPair(algorithm: Algorithm): GeneratedKeyPair {
  if (algorithm === "ed25519") {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const spki = Buffer.from(publicKey.export({ format: "der", type: "spki" }));
    const pkcs8 = Buffer.from(privateKey.export({ format: "der", type: "pkcs8" }));
    return {
      algorithm,
      publicKey: spki.subarray(spki.length - 32).toString("base64"),
      privateKey: pkcs8.subarray(pkcs8.length - 32).toString("base64"),
    };
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  return {
    algorithm,
    publicKey: publicKey.export({ format: "pem", type: "spki" }).toString(),
    privateKey: privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
  };
}

export function createSigner(algorithm: Algorithm, privateKeyMaterial: string): Signer {
  if (algorithm === "ed25519") {
    const key = loadEd25519Private(privateKeyMaterial);
    return {
      algorithm,
      async sign(data, signal) {
        throwIfAborted(signal);
        return crypto.sign(null, Buffer.from(data), key);
      },
    };
  }
  const key = loadRsaPrivate(privateKeyMaterial);
  return {
    algorithm,
    async sign(data, signal) {
      throwIfAborted(signal);
      return crypto.sign("sha256", Buffer.from(data), {
        key,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN,
      });
    },
  };
}

export function verifySignature(
  algorithm: Algorithm,
  publicKeyMaterial: string,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    if (algorithm === "ed25519") {
      if (signature.length !== 64) return false;
      const key = loadEd25519Public(publicKeyMaterial);
      return crypto.verify(null, Buffer.from(message), key, Buffer.from(signature));
    }
    const key = loadRsaPublic(publicKeyMaterial);
    return crypto.verify(
      "sha256",
      Buffer.from(message),
      {
        key,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN,
      },
      Buffer.from(signature),
    );
  } catch {
    return false;
  }
}

export function assertPublicKey(algorithm: Algorithm, material: string): void {
  if (algorithm === "ed25519") loadEd25519Public(material);
  else loadRsaPublic(material);
}

export function canonicalPublicKey(algorithm: Algorithm, material: string): string {
  if (algorithm === "ed25519") {
    const trimmed = material.trim();
    if (trimmed.includes("PRIVATE KEY")) throw tapError("trust", "private keys are not accepted");
    if (trimmed.startsWith("-----BEGIN ")) {
      const key = loadEd25519Public(trimmed);
      const spki = Buffer.from(key.export({ format: "der", type: "spki" }));
      return spki.subarray(spki.length - 32).toString("base64");
    }
    const raw = decodeKeyBytes(trimmed);
    if (raw.length !== 32) throw tapError("trust", "ed25519 public key must be 32 bytes");
    return raw.toString("base64");
  }
  const key = loadRsaPublic(material);
  return key.export({ format: "pem", type: "spki" }).toString().replace(/\r\n/g, "\n");
}

function loadEd25519Private(material: string): crypto.KeyObject {
  const trimmed = material.trim();
  if (trimmed.startsWith("-----BEGIN ")) {
    const key = crypto.createPrivateKey(trimmed);
    if (key.asymmetricKeyType !== "ed25519") throw tapError("policy", "private key is not ed25519");
    return key;
  }
  const seed = decodeKeyBytes(trimmed);
  if (seed.length !== 32) throw tapError("policy", "ed25519 seed must be 32 bytes");
  return crypto.createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
}

function loadEd25519Public(material: string): crypto.KeyObject {
  const trimmed = material.trim();
  if (trimmed.includes("PRIVATE KEY")) throw tapError("trust", "private keys are not accepted");
  if (trimmed.startsWith("-----BEGIN ")) {
    const key = crypto.createPublicKey(trimmed);
    if (key.asymmetricKeyType !== "ed25519") throw tapError("trust", "public key is not ed25519");
    return key;
  }
  const raw = decodeKeyBytes(trimmed);
  if (raw.length !== 32) throw tapError("trust", "ed25519 public key must be 32 bytes");
  return crypto.createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

function loadRsaPrivate(material: string): crypto.KeyObject {
  let key: crypto.KeyObject;
  try {
    key = crypto.createPrivateKey(material);
  } catch {
    throw tapError("policy", "invalid rsa private key");
  }
  if (key.asymmetricKeyType !== "rsa") throw tapError("policy", "private key is not rsa");
  const bits = key.asymmetricKeyDetails?.modulusLength ?? 0;
  if (bits < 2048) throw tapError("policy", "rsa key must be at least 2048 bits");
  return key;
}

function loadRsaPublic(material: string): crypto.KeyObject {
  const trimmed = material.trim();
  if (trimmed.includes("PRIVATE KEY")) throw tapError("trust", "private keys are not accepted");
  if (!trimmed.startsWith("-----BEGIN PUBLIC KEY-----") || !trimmed.endsWith("-----END PUBLIC KEY-----")) {
    throw tapError("trust", "rsa public key must be SPKI PEM");
  }
  let key: crypto.KeyObject;
  try {
    key = crypto.createPublicKey(trimmed);
  } catch {
    throw tapError("trust", "invalid rsa public key");
  }
  if (key.asymmetricKeyType !== "rsa") throw tapError("trust", "public key is not rsa");
  const bits = key.asymmetricKeyDetails?.modulusLength ?? 0;
  if (bits < 2048) throw tapError("trust", "rsa key must be at least 2048 bits");
  return key;
}

function decodeKeyBytes(material: string): Buffer {
  const compact = material.replace(/\s+/g, "");
  const normalized = compact.replace(/-/g, "+").replace(/_/g, "/");
  const pad = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  const buf = Buffer.from(normalized + pad, "base64");
  if (buf.length === 0 || buf.toString("base64").replace(/=+$/, "") !== normalized.replace(/=+$/, "")) {
    throw tapError("trust", "invalid base64 key");
  }
  return buf;
}

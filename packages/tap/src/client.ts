import crypto from "node:crypto";

import { throwIfAborted } from "./abort.js";
import { systemClock } from "./clock.js";
import { tapError } from "./errors.js";
import { assertProfileAlgorithm, createSignatureMaterial, formatSignatureHeaders } from "./message.js";
import {
  MAX_SIGNATURE_LIFETIME_SECONDS,
  type Clock,
  type ProfileName,
  type RequestData,
  type SignOptions,
  type SignatureHeaders,
  type Signer,
  type TapClient,
} from "./types.js";

export interface TapClientOptions {
  keyId: string;
  signer: Signer;
  profile: ProfileName;
  clock?: Clock;
  nonce?: () => string;
}

export function randomNonce(): string {
  return crypto.randomBytes(18).toString("base64url");
}

export function createTapClient(options: TapClientOptions): TapClient {
  const clock = options.clock ?? systemClock;
  const nonceSource = options.nonce ?? randomNonce;
  assertProfileAlgorithm(options.profile, options.signer.algorithm);
  return {
    signRequest(request, signOptions) {
      return signRequest(request, {
        ...signOptions,
        keyId: options.keyId,
        signer: options.signer,
        profile: options.profile,
        clock,
        nonceSource,
      });
    },
  };
}

export async function signRequest(
  request: RequestData,
  options: SignOptions & {
    keyId: string;
    signer: Signer;
    profile: ProfileName;
    clock?: Clock;
    nonceSource?: () => string;
  },
): Promise<SignatureHeaders> {
  throwIfAborted(options.signal);
  const clock = options.clock ?? systemClock;
  const lifetime = options.lifetimeSeconds ?? MAX_SIGNATURE_LIFETIME_SECONDS;
  if (!Number.isInteger(lifetime) || lifetime <= 0 || lifetime > MAX_SIGNATURE_LIFETIME_SECONDS) {
    throw tapError("invalid_time", "signature lifetime must be between 1 and 480 seconds");
  }
  const created = options.created ?? clock.now();
  const nonce = options.nonce ?? (options.nonceSource ?? randomNonce)();
  const material = createSignatureMaterial({
    request,
    profile: options.profile,
    components: options.coveredComponents ?? ["@authority", "@path"],
    created,
    expires: created + lifetime,
    keyId: options.keyId,
    alg: options.signer.algorithm,
    nonce,
    tag: options.tag,
  });
  throwIfAborted(options.signal);
  const signature = await options.signer.sign(Buffer.from(material.base, "utf8"), options.signal);
  throwIfAborted(options.signal);
  if (options.signer.algorithm === "ed25519" && signature.length !== 64) {
    throw tapError("invalid_signature", "ed25519 signature must be 64 bytes");
  }
  return formatSignatureHeaders(options.profile, material, signature);
}

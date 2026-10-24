import { verifySignature } from "./crypto.js";
import { tapError } from "./errors.js";
import { assertAlgorithm, assertKeyId, assertNonce, requireComponents } from "./fields.js";
import { legacySignatureParams, parseLegacy } from "./legacy.js";
import { SfParseError, parseDictionary, serializeMember, type SfInnerList, type SfParameter } from "./sfv.js";
import {
  assertCoveredComponents,
  buildSignatureBase,
  componentValue,
  headerValues,
  parseTarget,
  type ParsedTarget,
} from "./target.js";
import {
  LEGACY_LABEL,
  MAX_SIGNATURE_LIFETIME_SECONDS,
  TAP_LABEL,
  isAlgorithm,
  isIntentTag,
  type Algorithm,
  type IntentTag,
  type ProfileName,
  type RequestData,
  type SignatureHeaders,
} from "./types.js";

export interface SignatureMaterial {
  label: string;
  components: readonly string[];
  values: ReadonlyArray<readonly [string, string]>;
  created: number;
  expires: number;
  keyId: string;
  alg: Algorithm;
  nonce: string;
  tag: IntentTag;
  /** Exact `@signature-params` value, without the signature label. */
  signatureParams: string;
  base: string;
}

export interface ParsedSignature extends SignatureMaterial {
  signature: Uint8Array;
}

export function assertTimeWindow(created: number, expires: number, now: number, skewSeconds: number): void {
  if (!Number.isInteger(created) || !Number.isInteger(expires) || !Number.isInteger(now) || !Number.isInteger(skewSeconds)) {
    throw tapError("invalid_time", "timestamps must be integers");
  }
  if (skewSeconds < 0) throw tapError("policy", "clock skew must be non-negative");
  const lifetime = expires - created;
  if (lifetime <= 0 || lifetime > MAX_SIGNATURE_LIFETIME_SECONDS) {
    throw tapError("invalid_time", "signature lifetime must be between 1 and 480 seconds");
  }
  if (now < created - skewSeconds || now >= expires + skewSeconds) {
    throw tapError("invalid_time", "signature is outside its validity window");
  }
}

export function createSignatureMaterial(input: {
  request: RequestData;
  profile: ProfileName;
  components: readonly string[];
  created: number;
  expires: number;
  keyId: string;
  alg: Algorithm;
  nonce: string;
  tag: string;
}): SignatureMaterial {
  assertCoveredComponents(input.components);
  assertKeyId(input.keyId);
  assertNonce(input.nonce);
  if (!isIntentTag(input.tag)) throw tapError("policy", "unsupported intent tag");
  assertAlgorithm(input.profile, input.alg);
  const lifetime = input.expires - input.created;
  if (!Number.isInteger(input.created) || !Number.isInteger(input.expires) || lifetime <= 0 || lifetime > MAX_SIGNATURE_LIFETIME_SECONDS) {
    throw tapError("invalid_time", "signature lifetime must be between 1 and 480 seconds");
  }
  const target = parseTarget(input.request.url);
  if (input.request.method.length === 0) throw tapError("malformed", "method is empty");
  const values = input.components.map((name) => [name, componentValue(input.request, target, name, input.profile)] as const);
  const signatureParams = input.profile === "legacySample"
    ? legacySignatureParams(input.components, input)
    : tapParams(input.components, input);
  const label = input.profile === "legacySample" ? LEGACY_LABEL : TAP_LABEL;
  return {
    label,
    components: input.components,
    values,
    created: input.created,
    expires: input.expires,
    keyId: input.keyId,
    alg: input.alg,
    nonce: input.nonce,
    tag: input.tag,
    signatureParams,
    base: buildSignatureBase(values, signatureParams),
  };
}

export function formatSignatureHeaders(profile: ProfileName, material: SignatureMaterial, signature: Uint8Array): SignatureHeaders {
  const encoded = Buffer.from(signature).toString("base64");
  if (profile === "legacySample") {
    return {
      "Signature-Input": `${LEGACY_LABEL}=${material.signatureParams}`,
      Signature: `${LEGACY_LABEL}=:${encoded}:`,
    };
  }
  return {
    "Signature-Input": `${material.label}=${material.signatureParams}`,
    Signature: `${material.label}=:${encoded}:`,
  };
}

export function parseSignatureHeaders(input: {
  request: RequestData;
  profile: ProfileName;
  expectedTag: IntentTag;
  requiredComponents?: readonly string[];
}): ParsedSignature {
  const signatureInput = singleHeader(input.request, "signature-input");
  const signature = singleHeader(input.request, "signature");
  if (signatureInput === undefined || signature === undefined) {
    throw tapError("policy", "missing signature headers");
  }
  if (input.profile === "legacySample") return parseLegacy(input.request, signatureInput, signature, input.expectedTag, input.requiredComponents);
  return parseTap(input.request, signatureInput, signature, input.expectedTag, input.requiredComponents);
}

export function cryptographicVerify(material: ParsedSignature, publicKey: string): boolean {
  return verifySignature(material.alg, publicKey, Buffer.from(material.base, "utf8"), material.signature);
}

function parseTap(
  request: RequestData,
  signatureInput: string,
  signatureHeader: string,
  expectedTag: IntentTag,
  requiredComponents: readonly string[] | undefined,
): ParsedSignature {
  let inputDict;
  let sigDict;
  try {
    inputDict = parseDictionary(signatureInput.trim());
    sigDict = parseDictionary(signatureHeader.trim());
  } catch (error) {
    if (error instanceof SfParseError) throw tapError("malformed", error.message);
    throw error;
  }
  const inputLabels = inputDict.entries.map((entry) => entry.key);
  const sigLabels = sigDict.entries.map((entry) => entry.key);
  if (inputLabels.length === 0 || sigLabels.length === 0) throw tapError("malformed", "missing signature label");
  if (inputLabels.join("\0") !== sigLabels.join("\0")) throw tapError("malformed", "signature labels do not match");

  const candidates = [];
  for (const entry of inputDict.entries) {
    if (entry.value.type !== "inner-list") throw tapError("malformed", "signature parameters must be an inner list");
    // Other members, such as an intermediary's own signature, may carry no tag.
    const tag = entry.value.params.find((param) => param.key === "tag");
    if (tag === undefined) continue;
    if (tag.value.type !== "string") throw tapError("malformed", "parameter tag must be a string");
    if (tag.value.value === expectedTag) candidates.push(entry);
  }
  if (candidates.length === 0) throw tapError("policy", "no signature matches the expected tag");
  if (candidates.length > 1) throw tapError("policy", "multiple signatures match the expected tag");
  const chosen = candidates[0];
  if (!chosen || chosen.value.type !== "inner-list") throw tapError("policy", "no signature matches the expected tag");
  const sigEntry = sigDict.entries.find((entry) => entry.key === chosen.key);
  if (!sigEntry || sigEntry.value.type !== "item" || sigEntry.value.bare.type !== "binary" || sigEntry.value.params.length > 0) {
    throw tapError("malformed", "signature member must be a byte sequence");
  }
  return finishParsed(request, "tap", chosen.key, chosen.value, sigEntry.value.bare.value, expectedTag, requiredComponents);
}

function finishParsed(
  request: RequestData,
  profile: ProfileName,
  label: string,
  inner: SfInnerList,
  signature: Uint8Array,
  expectedTag: IntentTag,
  requiredComponents: readonly string[] | undefined,
): ParsedSignature {
  for (const item of inner.items) {
    if (item.params.length > 0 || item.bare.type !== "string") {
      throw tapError("malformed", "component parameters are not supported");
    }
  }
  const components = inner.items.map((item) => (item.bare.type === "string" ? item.bare.value : ""));
  const created = integerParam(inner.params, "created");
  const expires = integerParam(inner.params, "expires");
  const keyId = stringParam(inner.params, "keyid");
  const alg = stringParam(inner.params, "alg");
  const nonce = stringParam(inner.params, "nonce");
  const tag = stringParam(inner.params, "tag");
  const allowed = new Set(["created", "expires", "keyid", "alg", "nonce", "tag"]);
  for (const param of inner.params) {
    if (!allowed.has(param.key)) throw tapError("malformed", `unsupported parameter ${param.key}`);
  }
  if (!isIntentTag(tag) || tag !== expectedTag) throw tapError("policy", "signature tag does not match");
  if (!isAlgorithm(alg)) throw tapError("policy", "algorithm not allowed");
  assertAlgorithm(profile, alg);
  assertKeyId(keyId);
  assertNonce(nonce);
  assertCoveredComponents(components);
  requireComponents(components, requiredComponents);
  const target = parseTarget(request.url);
  const values = components.map((name) => [name, componentValue(request, target, name, profile)] as const);
  const signatureParams = serializeMember(inner);
  return {
    label,
    components,
    values,
    created,
    expires,
    keyId,
    alg,
    nonce,
    tag,
    signatureParams,
    base: buildSignatureBase(values, signatureParams),
    signature,
  };
}

function tapParams(
  components: readonly string[],
  fields: { created: number; expires: number; keyId: string; alg: string; nonce: string; tag: string },
): string {
  const inner: SfInnerList = {
    type: "inner-list",
    items: components.map((component) => ({
      type: "item",
      bare: { type: "string", value: component },
      params: [],
    })),
    params: [
      { key: "created", value: { type: "integer", value: fields.created } },
      { key: "expires", value: { type: "integer", value: fields.expires } },
      { key: "keyid", value: { type: "string", value: fields.keyId } },
      { key: "alg", value: { type: "string", value: fields.alg } },
      { key: "nonce", value: { type: "string", value: fields.nonce } },
      { key: "tag", value: { type: "string", value: fields.tag } },
    ],
  };
  return serializeMember(inner);
}

function singleHeader(request: RequestData, name: string): string | undefined {
  const values = headerValues(request.headers, name);
  if (values.length === 0) return undefined;
  if (values.length > 1) return values.join(", ");
  return values[0];
}

function stringParam(params: readonly SfParameter[], key: string): string {
  const param = params.find((item) => item.key === key);
  if (!param || param.value.type !== "string") throw tapError("malformed", `parameter ${key} must be a string`);
  return param.value.value;
}

function integerParam(params: readonly SfParameter[], key: string): number {
  const param = params.find((item) => item.key === key);
  if (!param || param.value.type !== "integer") throw tapError("malformed", `parameter ${key} must be an integer`);
  return param.value.value;
}

export function assertProfileAlgorithm(profile: ProfileName, alg: Algorithm): void {
  assertAlgorithm(profile, alg);
}

export function readTarget(url: string): ParsedTarget {
  return parseTarget(url);
}

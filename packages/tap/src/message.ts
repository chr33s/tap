import { verifySignature } from "./crypto.js";
import { tapError } from "./errors.js";
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

const KEY_ID = /^[A-Za-z0-9._-]{1,100}$/;
const NONCE = /^[A-Za-z0-9._~-]{8,128}$/;

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
    ? legacyParams(input.components, input)
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
    const tag = stringParam(entry.value.params, "tag");
    if (tag === expectedTag) candidates.push(entry);
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

function parseLegacy(
  request: RequestData,
  signatureInput: string,
  signatureHeader: string,
  expectedTag: IntentTag,
  requiredComponents: readonly string[] | undefined,
): ParsedSignature {
  const trimmed = signatureInput.trim();
  if (!trimmed.startsWith(`${LEGACY_LABEL}=`) || trimmed.includes(",")) {
    throw tapError("malformed", "legacy signature-input must be a single sig2 member");
  }
  const signatureParams = trimmed.slice(LEGACY_LABEL.length + 1);
  const match = /^\(([^)]*)\)(.*)$/s.exec(signatureParams);
  if (!match?.[1] || match[2] === undefined) throw tapError("malformed", "legacy signature parameters are incomplete");
  const components = parseLegacyComponents(match[1]);
  const fields = parseLegacyAttributes(match[2]);
  const sigMatch = /^sig2=:([A-Za-z0-9+/]+={0,2}):$/.exec(signatureHeader.trim());
  if (!sigMatch?.[1]) throw tapError("malformed", "legacy signature must be sig2=:base64:");
  let signature: Buffer;
  try {
    signature = Buffer.from(sigMatch[1], "base64");
    if (signature.toString("base64").replace(/=+$/, "") !== sigMatch[1].replace(/=+$/, "")) {
      throw tapError("malformed", "invalid signature encoding");
    }
  } catch (error) {
    if (error instanceof Error && error.name === "TapError") throw error;
    throw tapError("malformed", "invalid signature encoding");
  }
  const tag = fields.tag;
  if (!isIntentTag(tag) || tag !== expectedTag) throw tapError("policy", "signature tag does not match");
  if (!isAlgorithm(fields.alg)) throw tapError("policy", "algorithm not allowed");
  assertAlgorithm("legacySample", fields.alg);
  assertKeyId(fields.keyId);
  assertNonce(fields.nonce);
  const created = strictInteger(fields.created, "created");
  const expires = strictInteger(fields.expires, "expires");
  assertCoveredComponents(components);
  requireComponents(components, requiredComponents);
  const target = parseTarget(request.url);
  const values = components.map((name) => [name, componentValue(request, target, name, "legacySample")] as const);
  return {
    label: LEGACY_LABEL,
    components,
    values,
    created,
    expires,
    keyId: fields.keyId,
    alg: fields.alg,
    nonce: fields.nonce,
    tag,
    signatureParams,
    base: buildSignatureBase(values, signatureParams),
    signature,
  };
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

function legacyParams(
  components: readonly string[],
  fields: { created: number; expires: number; keyId: string; alg: string; nonce: string; tag: string },
): string {
  const covered = components.map((component) => `"${component}"`).join(" ");
  return `(${covered}); created=${fields.created}; expires=${fields.expires}; keyId="${fields.keyId}"; alg="${fields.alg}"; nonce="${fields.nonce}"; tag="${fields.tag}"`;
}

function parseLegacyComponents(inner: string): string[] {
  const parts = inner.trim().split(/\s+/).filter((part) => part.length > 0);
  if (parts.length === 0) throw tapError("malformed", "no covered components");
  return parts.map((part) => {
    if (!(part.startsWith("\"") && part.endsWith("\"")) || part.length < 3) {
      throw tapError("malformed", "legacy component must be a quoted string");
    }
    const value = part.slice(1, -1);
    if (value.includes("\"")) throw tapError("malformed", "invalid legacy component");
    return value;
  });
}

function parseLegacyAttributes(rest: string): { created: string; expires: string; keyId: string; alg: string; nonce: string; tag: string } {
  const found = new Map<string, { value: string; kind: "string" | "integer" }>();
  let index = 0;
  while (index < rest.length) {
    while (rest[index] === " " || rest[index] === "\t") index += 1;
    if (rest[index] !== ";") throw tapError("malformed", "legacy parameters must be semicolon-separated");
    index += 1;
    while (rest[index] === " " || rest[index] === "\t") index += 1;
    const keyMatch = /^([A-Za-z_][A-Za-z0-9_]*)=/.exec(rest.slice(index));
    if (!keyMatch?.[1]) throw tapError("malformed", "invalid legacy parameter");
    index += keyMatch[0].length;
    const key = keyMatch[1];
    let value = "";
    let kind: "string" | "integer";
    if (rest[index] === "\"") {
      const end = rest.indexOf("\"", index + 1);
      if (end < 0) throw tapError("malformed", "unterminated legacy parameter");
      value = rest.slice(index + 1, end);
      if (value.includes("\\")) throw tapError("malformed", "invalid legacy parameter");
      index = end + 1;
      kind = "string";
    } else {
      const num = /^([0-9]+)/.exec(rest.slice(index));
      if (!num?.[1]) throw tapError("malformed", "invalid legacy parameter");
      value = num[1];
      index += value.length;
      kind = "integer";
    }
    if (found.has(key)) throw tapError("malformed", `duplicate parameter ${key}`);
    found.set(key, { value, kind });
  }
  const required = ["created", "expires", "keyId", "alg", "nonce", "tag"] as const;
  for (const key of required) {
    if (!found.has(key)) throw tapError("malformed", `missing ${key}`);
  }
  if (found.size !== required.length) throw tapError("malformed", "unsupported legacy parameter");
  const created = found.get("created");
  const expires = found.get("expires");
  const keyId = found.get("keyId");
  const alg = found.get("alg");
  const nonce = found.get("nonce");
  const tag = found.get("tag");
  if (!created || !expires || !keyId || !alg || !nonce || !tag) {
    throw tapError("malformed", "incomplete legacy parameters");
  }
  if (created.kind !== "integer" || expires.kind !== "integer") {
    throw tapError("malformed", "created and expires must be integers");
  }
  for (const field of [keyId, alg, nonce, tag]) {
    if (field.kind !== "string") throw tapError("malformed", "legacy string parameters must be quoted");
  }
  return {
    created: created.value,
    expires: expires.value,
    keyId: keyId.value,
    alg: alg.value,
    nonce: nonce.value,
    tag: tag.value,
  };
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

function strictInteger(value: string, name: string): number {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) throw tapError("malformed", `${name} must be an integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw tapError("malformed", `${name} is out of range`);
  return parsed;
}

function requireComponents(components: readonly string[], required: readonly string[] | undefined): void {
  if (!required) return;
  const seen = new Set(components);
  for (const component of required) {
    if (!seen.has(component)) throw tapError("policy", `missing required component ${component}`);
  }
}

function assertKeyId(keyId: string): void {
  if (!KEY_ID.test(keyId)) throw tapError("malformed", "invalid key id");
}

function assertNonce(nonce: string): void {
  if (!NONCE.test(nonce)) throw tapError("malformed", "invalid nonce");
}

function assertAlgorithm(profile: ProfileName, alg: string): asserts alg is Algorithm {
  if (profile === "tap" && alg !== "ed25519") throw tapError("policy", "algorithm not allowed");
  if (profile === "legacySample" && alg !== "ed25519" && alg !== "rsa-pss-sha256") {
    throw tapError("policy", "algorithm not allowed");
  }
}

export function assertProfileAlgorithm(profile: ProfileName, alg: Algorithm): void {
  assertAlgorithm(profile, alg);
}

export function readTarget(url: string): ParsedTarget {
  return parseTarget(url);
}

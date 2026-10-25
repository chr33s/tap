import { tapError } from "./errors.js";
import { assertAlgorithm, assertKeyId, assertNonce, requireComponents } from "./fields.js";
import { assertCoveredComponents, buildSignatureBase, componentValue, type ParsedTarget } from "./target.js";
import { LEGACY_LABEL, isAlgorithm, isIntentTag, type IntentTag, type RequestData } from "./types.js";

import type { ParsedSignature } from "./message.js";

export function legacySignatureParams(
  components: readonly string[],
  fields: { created: number; expires: number; keyId: string; alg: string; nonce: string; tag: string },
): string {
  const covered = components.map((component) => `"${component}"`).join(" ");
  return `(${covered}); created=${fields.created}; expires=${fields.expires}; keyId="${fields.keyId}"; alg="${fields.alg}"; nonce="${fields.nonce}"; tag="${fields.tag}"`;
}

export function parseLegacy(
  request: RequestData,
  target: ParsedTarget,
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

function strictInteger(value: string, name: string): number {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) throw tapError("malformed", `${name} must be an integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw tapError("malformed", `${name} is out of range`);
  return parsed;
}

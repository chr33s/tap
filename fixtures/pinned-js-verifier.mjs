/* © 2025 Visa.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * Verification helpers extracted from visa/trusted-agent-protocol
 * cdn-proxy/server.js at 16d59bdf. Console logging is omitted. The parse,
 * signature-base, and crypto options match that sample.
 */
import crypto from "node:crypto";

export function parseRFC9421SignatureInput(signatureInput) {
  const signatureMatch = signatureInput.match(/sig2=\(([^)]+)\);\s*(.+)/);
  if (!signatureMatch) throw new Error("Invalid RFC 9421 signature input format - must start with sig2=()");
  const [, paramString, attributesString] = signatureMatch;
  const params = paramString.split(/\s+/).map((part) => part.replace(/['"]/g, ""));
  const attributes = {};
  const attributeMatches = attributesString.matchAll(/(\w+)=("[^"]*"|\d+)/g);
  for (const match of attributeMatches) {
    const [, key, value] = match;
    attributes[key] = value.startsWith("\"") ? value.slice(1, -1) : Number.parseInt(value, 10);
  }
  return {
    params,
    nonce: attributes.nonce,
    created: attributes.created,
    expires: attributes.expires,
    keyId: attributes.keyId,
    algorithm: attributes.alg,
    tag: attributes.tag,
  };
}

export function buildRFC9421SignatureString(params, requestData, signatureInputHeader) {
  const components = [];
  for (const param of params) {
    if (param === "@authority") components.push(`"@authority": ${requestData.authority}`);
    else if (param === "@path") components.push(`"@path": ${requestData.path}`);
    else if (param === "content-type") components.push(`"content-type": ${requestData.contentType || "application/json"}`);
    else if (param === "host") components.push(`"host": ${requestData.host || requestData.authority}`);
    else if (requestData[param]) components.push(`"${param}": ${requestData[param]}`);
  }
  let signatureParams = signatureInputHeader;
  if (signatureInputHeader.startsWith("sig2=")) signatureParams = signatureInputHeader.substring(5);
  components.push(`"@signature-params": ${signatureParams}`);
  return components.join("\n");
}

export function verifyRSASignature(publicKeyPem, signatureBase64, signatureString) {
  const publicKey = crypto.createPublicKey({ key: publicKeyPem, format: "pem", type: "spki" });
  const signatureBuffer = Buffer.from(signatureBase64, "base64");
  const verifier = crypto.createVerify("RSA-SHA256");
  verifier.update(signatureString, "utf-8");
  return verifier.verify(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN,
    },
    signatureBuffer,
  );
}

export function verifyEd25519Signature(publicKeyBase64, signatureBase64, signatureString) {
  const publicKeyBuffer = Buffer.from(publicKeyBase64, "base64");
  if (publicKeyBuffer.length !== 32) throw new Error(`Ed25519 public key must be 32 bytes, got ${publicKeyBuffer.length} bytes`);
  const derPrefix = Buffer.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
  const publicKey = crypto.createPublicKey({
    key: Buffer.concat([derPrefix, publicKeyBuffer]),
    format: "der",
    type: "spki",
  });
  const signatureBuffer = Buffer.from(signatureBase64, "base64");
  if (signatureBuffer.length !== 64) throw new Error(`Ed25519 signature must be 64 bytes, got ${signatureBuffer.length} bytes`);
  return crypto.verify(null, Buffer.from(signatureString, "utf-8"), publicKey, signatureBuffer);
}

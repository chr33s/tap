#!/usr/bin/env node
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

import {
  createSigner,
  createTapClient,
  isAlgorithm,
  isIntentTag,
  isProfile,
  type Algorithm,
  type IntentTag,
  type ProfileName,
  type RequestData,
  generateKeyPair,
} from "tap";

interface Args {
  command: string;
  flags: Map<string, string[]>;
}

function parseArgs(argv: string[]): Args {
  const positional: string[] = [];
  const flags = new Map<string, string[]>();
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token) continue;
    if (token.startsWith("--")) {
      const key = token.slice(2);
      const next = argv[index + 1];
      const value = next === undefined || next.startsWith("--") ? "true" : argv[++index] ?? "true";
      flags.set(key, [...(flags.get(key) ?? []), value]);
    } else {
      positional.push(token);
    }
  }
  return { command: positional[0] ?? "help", flags };
}

function flag(args: Args, name: string, fallback?: string): string {
  return args.flags.get(name)?.at(-1) ?? process.env[envName(name)] ?? fallback ?? "";
}

function envName(flagName: string): string {
  if (flagName === "key-file") return "TAP_KEY_FILE";
  if (flagName === "key-id") return "TAP_KEY_ID";
  if (flagName === "profile") return "TAP_PROFILE";
  if (flagName === "alg") return "TAP_ALG";
  return "";
}

function usage(): void {
  process.stderr.write(`tap-agent keygen|sign|send

  keygen --alg ed25519|rsa-pss-sha256 [--out ./tap-keys]
  sign   --url URL --tag agent-browser-auth|agent-payer-auth [--method GET] [--covered @authority,@path]
  send   --url URL --tag ... [--method GET] [--data-file file] [--header Name:value]

Private keys are read from --key-file or TAP_KEY_FILE. Each send uses a new nonce,
signs the final URL, and does not follow redirects or retry.
`);
}

const args = parseArgs(process.argv.slice(2));

try {
  if (args.command === "keygen") await keygen(args);
  else if (args.command === "sign") await sign(args, false);
  else if (args.command === "send") await sign(args, true);
  else {
    usage();
    process.exit(args.command === "help" ? 0 : 2);
  }
} catch (error) {
  const message = error instanceof Error ? error.message : "agent failed";
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

async function keygen(input: Args): Promise<void> {
  const alg = algorithm(flag(input, "alg", "ed25519"));
  const out = flag(input, "out", "./tap-keys");
  mkdirSync(out, { recursive: true });
  const pair = generateKeyPair(alg);
  const privatePath = `${out}/${alg}.private`;
  const publicPath = `${out}/${alg}.public`;
  writeFileSync(privatePath, pair.privateKey.endsWith("\n") ? pair.privateKey : `${pair.privateKey}\n`, { mode: 0o600 });
  chmodSync(privatePath, 0o600);
  writeFileSync(publicPath, pair.publicKey.endsWith("\n") ? pair.publicKey : `${pair.publicKey}\n`, { mode: 0o644 });
  process.stdout.write(pair.publicKey.endsWith("\n") ? pair.publicKey : `${pair.publicKey}\n`);
  process.stderr.write(`wrote ${publicPath}\n`);
}

async function sign(input: Args, deliver: boolean): Promise<void> {
  const profile = profileName(flag(input, "profile", "tap"));
  const alg = algorithm(flag(input, "alg", profile === "tap" ? "ed25519" : "ed25519"));
  const keyId = required(flag(input, "key-id"), "key id");
  const keyFile = required(flag(input, "key-file"), "key file");
  const url = wireUrl(required(flag(input, "url"), "url"));
  const method = (flag(input, "method", "GET") || "GET").toUpperCase();
  const tag = intent(required(flag(input, "tag"), "tag"));
  const covered = flag(input, "covered");
  const lifetime = flag(input, "lifetime");
  const privateKey = readFileSync(keyFile, "utf8");
  const headers = headerPairs(input.flags.get("header") ?? []);
  const dataFile = flag(input, "data-file");
  const body = dataFile ? readFileSync(dataFile) : undefined;
  if (body && !headers.some(([name]) => name.toLowerCase() === "content-type")) {
    headers.push(["content-type", "application/octet-stream"]);
  }
  const request: RequestData = { method, url, headers };
  const client = createTapClient({
    keyId,
    profile,
    signer: createSigner(alg, privateKey),
  });
  const signed = await client.signRequest(request, {
    tag,
    ...(covered ? { coveredComponents: covered.split(",").map((item) => item.trim()).filter(Boolean) } : {}),
    ...(lifetime ? { lifetimeSeconds: Number(lifetime) } : {}),
  });
  if (!deliver) {
    process.stdout.write(`Signature-Input: ${signed["Signature-Input"]}\n`);
    process.stdout.write(`Signature: ${signed.Signature}\n`);
    return;
  }
  const response = await fetch(url, {
    method,
    headers: {
      ...Object.fromEntries(headers),
      "Signature-Input": signed["Signature-Input"],
      Signature: signed.Signature,
      "user-agent": "tap-agent/1.0",
    },
    body,
    redirect: "manual",
  });
  process.stderr.write(`HTTP ${response.status}\n`);
  process.stdout.write(Buffer.from(await response.arrayBuffer()));
}

/**
 * The URL exactly as `fetch` will put it on the wire (WHATWG percent-encoding,
 * lowercase host, default port dropped, no fragment), so the signed `@path`
 * and `@authority` match what the verifier rebuilds.
 */
function wireUrl(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("url must be an absolute http(s) URL");
  }
  parsed.hash = "";
  return parsed.href;
}

function headerPairs(values: readonly string[]): Array<[string, string]> {
  return values.map((value) => {
    const index = value.indexOf(":");
    if (index <= 0) throw new Error(`invalid header ${value}`);
    return [value.slice(0, index).trim(), value.slice(index + 1).trim()];
  });
}

function algorithm(value: string): Algorithm {
  if (!isAlgorithm(value)) throw new Error("algorithm must be ed25519 or rsa-pss-sha256");
  return value;
}

function profileName(value: string): ProfileName {
  if (!isProfile(value)) throw new Error("profile must be tap or legacySample");
  return value;
}

function intent(value: string): IntentTag {
  if (!isIntentTag(value)) throw new Error("tag must be agent-browser-auth or agent-payer-auth");
  return value;
}

function required(value: string, label: string): string {
  if (!value) throw new Error(`${label} is required`);
  return value;
}

import { Schema } from "effect";

import { startRegistry } from "./server.js";

const Env = Schema.Struct({
  TAP_ADMIN_TOKEN: Schema.String,
  HOST: Schema.optional(Schema.String),
  PORT: Schema.optional(Schema.String),
  TAP_DATABASE_PATH: Schema.optional(Schema.String),
  TLS_CERT_FILE: Schema.optional(Schema.String),
  TLS_KEY_FILE: Schema.optional(Schema.String),
});

const envInput: Record<string, string> = {};
for (const key of ["TAP_ADMIN_TOKEN", "HOST", "PORT", "TAP_DATABASE_PATH", "TLS_CERT_FILE", "TLS_KEY_FILE"] as const) {
  const value = process.env[key];
  if (value !== undefined) envInput[key] = value;
}
const env = Schema.decodeUnknownSync(Env)(envInput);
const port = env.PORT === undefined ? 9002 : Number(env.PORT);
if (!Number.isInteger(port) || port < 0 || port > 65535) {
  throw new Error("PORT must be an integer from 0 to 65535");
}

const handle = await startRegistry({
  host: env.HOST ?? "127.0.0.1",
  port,
  adminToken: env.TAP_ADMIN_TOKEN,
  databasePath: env.TAP_DATABASE_PATH ?? "./data/registry.db",
  tlsCert: env.TLS_CERT_FILE,
  tlsKey: env.TLS_KEY_FILE,
});

process.stdout.write(`registry listening on ${handle.url}\n`);
process.stdout.write("local approval does not imply Visa certification\n");

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    void handle.close().then(() => process.exit(0));
  });
}

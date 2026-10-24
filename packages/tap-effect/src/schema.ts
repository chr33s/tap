import { Schema } from "effect";

export const IntentTagSchema = Schema.Literals(["agent-browser-auth", "agent-payer-auth"]);
export const AlgorithmSchema = Schema.Literals(["ed25519", "rsa-pss-sha256"]);
export const ProfileSchema = Schema.Literals(["tap", "legacySample"]);
export const ActivationSchema = Schema.Literals(["true", "false"]);

export const RegistryKeySchema = Schema.Struct({
  key_id: Schema.String,
  public_key: Schema.String,
  algorithm: AlgorithmSchema,
  is_active: ActivationSchema,
  agent_id: Schema.Union([Schema.String, Schema.Int]),
  agent_name: Schema.String,
  agent_domain: Schema.String,
  expires_at: Schema.optional(Schema.NullOr(Schema.Int)),
  description: Schema.optional(Schema.NullOr(Schema.String)),
});

export const VerifiedAgentSchema = Schema.Struct({
  agentId: Schema.String,
  agentName: Schema.String,
  agentDomain: Schema.String,
  keyId: Schema.String,
  algorithm: AlgorithmSchema,
  tag: IntentTagSchema,
  nonce: Schema.String,
  created: Schema.Int,
  expires: Schema.Int,
  coveredComponents: Schema.Array(Schema.String),
});

export type RegistryKeyDocument = typeof RegistryKeySchema.Type;
export type VerifiedAgentDocument = typeof VerifiedAgentSchema.Type;

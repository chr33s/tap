import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

import { canonicalPublicKey, isAlgorithm, type Algorithm } from "tap";

import { reply } from "./http-error.js";

export interface AgentRecord {
  id: number;
  name: string;
  domain: string;
  description: string | null;
  contact_email: string | null;
  is_active: "true" | "false";
  created_at: string;
  updated_at: string;
  keys: KeyRecord[];
}

export interface KeyRecord {
  id: number;
  agent_id: number;
  key_id: string;
  public_key: string;
  algorithm: Algorithm;
  description: string | null;
  is_active: "true" | "false";
  expires_at: number | null;
  created_at: string;
  updated_at: string;
}

export interface PublicKeyRecord {
  key_id: string;
  public_key: string;
  algorithm: Algorithm;
  is_active: "true";
  agent_id: number;
  agent_name: string;
  agent_domain: string;
  expires_at: number | null;
  description: string | null;
}

interface AgentRow {
  id: number;
  name: string;
  domain: string;
  description: string | null;
  contact_email: string | null;
  is_active: number;
  created_at: number;
  updated_at: number;
}

interface KeyRow {
  id: number;
  agent_id: number;
  key_id: string;
  public_key: string;
  algorithm: string;
  description: string | null;
  is_active: number;
  expires_at: number | null;
  created_at: number;
  updated_at: number;
}

export interface RegisterInput {
  name: string;
  domain: string;
  description: string | null;
  contactEmail: string | null;
  keys: KeyInput[];
}

export interface KeyInput {
  keyId: string;
  publicKey: string;
  algorithm: Algorithm;
  description: string | null;
}

export interface AgentPatch {
  name?: string;
  description?: string | null;
  contactEmail?: string | null;
  isActive?: boolean;
}

export interface KeyPatch {
  description?: string | null;
  isActive?: boolean;
  expiresAt?: number | null;
  expiresAtSet: boolean;
}

const MIGRATION_ID = "001_init";

export function openRegistryDatabase(filename: string): DatabaseSync {
  const db = new DatabaseSync(filename);
  db.exec("PRAGMA foreign_keys = ON");
  db.exec("PRAGMA busy_timeout = 2000");
  db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (id TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)");
  const applied = db.prepare("SELECT id FROM schema_migrations WHERE id = ?").get(MIGRATION_ID);
  if (!applied) {
    const sql = readFileSync(new URL("../migrations/001_init.sql", import.meta.url), "utf8");
    db.exec("BEGIN IMMEDIATE");
    try {
      db.exec(sql);
      db.prepare("INSERT INTO schema_migrations (id, applied_at) VALUES (?, ?)").run(MIGRATION_ID, nowSeconds());
      db.exec("COMMIT");
    } catch (error) {
      try {
        db.exec("ROLLBACK");
      } catch {
        // Preserve the migration error.
      }
      db.close();
      throw error;
    }
  }
  return db;
}

export function registerAgent(db: DatabaseSync, input: RegisterInput, now = nowSeconds()): { created: boolean; agent: AgentRecord } {
  return transaction(db, () => {
    const existing = db.prepare("SELECT * FROM agents WHERE domain = ?").get(input.domain) as AgentRow | undefined;
    if (existing) {
      if (input.keys.length > 0) reply(409, "conflict", "registration does not replace keys");
      db.prepare(
        "UPDATE agents SET name = ?, description = ?, contact_email = ?, updated_at = ? WHERE id = ?",
      ).run(input.name, input.description, input.contactEmail, now, existing.id);
      return { created: false, agent: mustLoadAgent(db, existing.id, now) };
    }
    const info = db.prepare(
      "INSERT INTO agents (name, domain, description, contact_email, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, 0, ?, ?)",
    ).run(input.name, input.domain, input.description, input.contactEmail, now, now);
    const agentId = Number(info.lastInsertRowid);
    for (const key of input.keys) insertKey(db, agentId, key, now);
    return { created: true, agent: mustLoadAgent(db, agentId, now) };
  });
}

export function listPublicAgents(db: DatabaseSync, now = nowSeconds()): Array<Omit<AgentRecord, "contact_email">> {
  const rows = db.prepare("SELECT * FROM agents WHERE is_active = 1 ORDER BY id").all() as unknown as AgentRow[];
  return rows.map((row) => publicAgent(row, activeKeys(db, row.id, now)));
}

export function getPublicAgent(db: DatabaseSync, id: number, now = nowSeconds()): Omit<AgentRecord, "contact_email"> {
  const row = agentById(db, id);
  if (!row || row.is_active !== 1) reply(404, "not_found", "agent not found");
  return publicAgent(row, activeKeys(db, row.id, now));
}

export function updateAgent(db: DatabaseSync, id: number, patch: AgentPatch, now = nowSeconds()): AgentRecord {
  return transaction(db, () => {
    const row = agentById(db, id);
    if (!row) reply(404, "not_found", "agent not found");
    const name = patch.name ?? row.name;
    const description = patch.description === undefined ? row.description : patch.description;
    const contact = patch.contactEmail === undefined ? row.contact_email : patch.contactEmail;
    const active = patch.isActive === undefined ? row.is_active === 1 : patch.isActive;
    db.prepare(
      "UPDATE agents SET name = ?, description = ?, contact_email = ?, is_active = ?, updated_at = ? WHERE id = ?",
    ).run(name, description, contact, active ? 1 : 0, now, id);
    if (!active) {
      db.prepare("UPDATE agent_keys SET is_active = 0, updated_at = ? WHERE agent_id = ?").run(now, id);
    }
    return mustLoadAgent(db, id, now);
  });
}

export function deactivateAgent(db: DatabaseSync, id: number, now = nowSeconds()): void {
  transaction(db, () => {
    const row = agentById(db, id);
    if (!row) reply(404, "not_found", "agent not found");
    db.prepare("UPDATE agents SET is_active = 0, updated_at = ? WHERE id = ?").run(now, id);
    db.prepare("UPDATE agent_keys SET is_active = 0, updated_at = ? WHERE agent_id = ?").run(now, id);
  });
}

export function addKey(db: DatabaseSync, agentId: number, input: KeyInput, now = nowSeconds()): KeyRecord {
  return transaction(db, () => {
    const agent = agentById(db, agentId);
    if (!agent) reply(404, "not_found", "agent not found");
    insertKey(db, agentId, input, now);
    const row = db.prepare("SELECT * FROM agent_keys WHERE key_id = ?").get(input.keyId) as KeyRow | undefined;
    if (!row) reply(500, "internal", "key insert failed");
    return toKey(row);
  });
}

export function updateKey(db: DatabaseSync, agentId: number, keyId: string, patch: KeyPatch, now = nowSeconds()): KeyRecord {
  return transaction(db, () => {
    const agent = agentById(db, agentId);
    if (!agent) reply(404, "not_found", "agent not found");
    const rows = db.prepare("SELECT * FROM agent_keys WHERE key_id = ?").all(keyId) as unknown as KeyRow[];
    if (rows.length > 1) reply(500, "internal", "ambiguous key id");
    const row = rows[0];
    if (!row || row.agent_id !== agentId) reply(404, "not_found", "key not found");
    const active = patch.isActive === undefined ? row.is_active === 1 : patch.isActive;
    if (active && agent.is_active !== 1) reply(409, "conflict", "agent is inactive");
    const description = patch.description === undefined ? row.description : patch.description;
    const expires = patch.expiresAtSet ? (patch.expiresAt ?? null) : row.expires_at;
    db.prepare(
      "UPDATE agent_keys SET is_active = ?, description = ?, expires_at = ?, updated_at = ? WHERE id = ?",
    ).run(active ? 1 : 0, description, expires, now, row.id);
    const updated = db.prepare("SELECT * FROM agent_keys WHERE id = ?").get(row.id) as unknown as KeyRow;
    return toKey(updated);
  });
}

export function lookupKey(db: DatabaseSync, keyId: string, agentId: number | undefined, now = nowSeconds()): PublicKeyRecord {
  const rows = db.prepare(`
    SELECT k.key_id, k.public_key, k.algorithm, k.is_active, k.expires_at, k.description,
           k.agent_id, a.name AS agent_name, a.domain AS agent_domain, a.is_active AS agent_active
    FROM agent_keys k
    JOIN agents a ON a.id = k.agent_id
    WHERE k.key_id = ?
  `).all(keyId) as unknown as Array<Record<string, unknown>>;
  if (rows.length > 1) reply(500, "internal", "ambiguous key id");
  const row = rows[0];
  if (!row) reply(404, "not_found", "key not found");
  if (agentId !== undefined && Number(row.agent_id) !== agentId) reply(404, "not_found", "key not found");
  if (row.agent_active !== 1 || row.is_active !== 1) reply(404, "not_found", "key not found");
  const expiresAt = row.expires_at === null || row.expires_at === undefined ? null : Number(row.expires_at);
  if (expiresAt !== null && expiresAt <= now) reply(404, "not_found", "key not found");
  const algorithm = String(row.algorithm);
  if (!isAlgorithm(algorithm)) reply(404, "not_found", "key not found");
  return {
    key_id: String(row.key_id),
    public_key: String(row.public_key),
    algorithm,
    is_active: "true",
    agent_id: Number(row.agent_id),
    agent_name: String(row.agent_name),
    agent_domain: String(row.agent_domain),
    expires_at: expiresAt,
    description: row.description === null || row.description === undefined ? null : String(row.description),
  };
}

export function assertSingle<T>(rows: readonly T[], label: string): T | undefined {
  if (rows.length > 1) reply(500, "internal", `ambiguous ${label}`);
  return rows[0];
}

function insertKey(db: DatabaseSync, agentId: number, input: KeyInput, now: number): void {
  let canonical: string;
  try {
    canonical = canonicalPublicKey(input.algorithm, input.publicKey);
  } catch {
    reply(400, "malformed", "invalid public key");
  }
  try {
    db.prepare(
      `INSERT INTO agent_keys
        (agent_id, key_id, public_key, algorithm, description, is_active, expires_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 0, NULL, ?, ?)`,
    ).run(agentId, input.keyId, canonical, input.algorithm, input.description, now, now);
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    if (message.includes("UNIQUE")) reply(409, "conflict", "key id already exists");
    throw error;
  }
}

function mustLoadAgent(db: DatabaseSync, id: number, now: number): AgentRecord {
  const row = agentById(db, id);
  if (!row) reply(404, "not_found", "agent not found");
  const keys = (db.prepare("SELECT * FROM agent_keys WHERE agent_id = ? ORDER BY id").all(id) as unknown as KeyRow[]).map(toKey);
  return toAgent(row, keys, now);
}

function activeKeys(db: DatabaseSync, agentId: number, now: number): KeyRecord[] {
  const rows = db.prepare(
    "SELECT * FROM agent_keys WHERE agent_id = ? AND is_active = 1 AND (expires_at IS NULL OR expires_at > ?) ORDER BY id",
  ).all(agentId, now) as unknown as KeyRow[];
  return rows.map(toKey);
}

function agentById(db: DatabaseSync, id: number): AgentRow | undefined {
  return db.prepare("SELECT * FROM agents WHERE id = ?").get(id) as AgentRow | undefined;
}

function publicAgent(row: AgentRow, keys: KeyRecord[]): Omit<AgentRecord, "contact_email"> {
  return {
    id: row.id,
    name: row.name,
    domain: row.domain,
    description: row.description,
    is_active: "true",
    created_at: iso(row.created_at),
    updated_at: iso(row.updated_at),
    keys,
  };
}

function toAgent(row: AgentRow, keys: KeyRecord[], _now: number): AgentRecord {
  return {
    id: row.id,
    name: row.name,
    domain: row.domain,
    description: row.description,
    contact_email: row.contact_email,
    is_active: row.is_active === 1 ? "true" : "false",
    created_at: iso(row.created_at),
    updated_at: iso(row.updated_at),
    keys,
  };
}

function toKey(row: KeyRow): KeyRecord {
  const algorithm = row.algorithm;
  if (!isAlgorithm(algorithm)) reply(500, "internal", "stored algorithm is invalid");
  return {
    id: row.id,
    agent_id: row.agent_id,
    key_id: row.key_id,
    public_key: row.public_key,
    algorithm,
    description: row.description,
    is_active: row.is_active === 1 ? "true" : "false",
    expires_at: row.expires_at,
    created_at: iso(row.created_at),
    updated_at: iso(row.updated_at),
  };
}

function transaction<T>(db: DatabaseSync, fn: () => T): T {
  db.exec("BEGIN IMMEDIATE");
  try {
    const value = fn();
    db.exec("COMMIT");
    return value;
  } catch (error) {
    try {
      db.exec("ROLLBACK");
    } catch {
      // Preserve the original error.
    }
    throw error;
  }
}

function iso(seconds: number): string {
  return new Date(seconds * 1000).toISOString();
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

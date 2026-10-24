import { DatabaseSync } from "node:sqlite";

import { throwIfAborted } from "./abort.js";
import { systemClock } from "./clock.js";
import { tapError } from "./errors.js";
import type { ClaimResult, Clock, ReplayClaim, ReplayStore } from "./types.js";

export function createMemoryReplayStore(clock: Clock = systemClock): ReplayStore {
  const claims = new Map<string, number>();
  return {
    async claim(entry, signal) {
      throwIfAborted(signal);
      return claimInMap(claims, entry, clock.now());
    },
  };
}

export function createSqliteReplayStore(filename: string, clock: Clock = systemClock): ReplayStore & { close(): void } {
  const db = new DatabaseSync(filename);
  try {
    db.exec("PRAGMA journal_mode = WAL");
    db.exec("PRAGMA busy_timeout = 2000");
    db.exec(`
      CREATE TABLE IF NOT EXISTS replay_nonce (
        trust_source TEXT NOT NULL,
        key_id TEXT NOT NULL,
        nonce TEXT NOT NULL,
        until_unix INTEGER NOT NULL,
        PRIMARY KEY (trust_source, key_id, nonce)
      )
    `);
  } catch (error) {
    db.close();
    throw tapError("store_unavailable", error instanceof Error ? error.message : "unable to open replay store");
  }
  const deleteExpired = db.prepare("DELETE FROM replay_nonce WHERE until_unix <= ?");
  const insert = db.prepare(
    "INSERT INTO replay_nonce (trust_source, key_id, nonce, until_unix) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING",
  );
  return {
    async claim(entry, signal) {
      throwIfAborted(signal);
      const now = clock.now();
      if (!Number.isInteger(entry.until) || entry.until <= now) return "expired";
      if (entry.trustSource.length === 0 || entry.keyId.length === 0 || entry.nonce.length === 0) {
        throw tapError("store_unavailable", "replay claim is missing an identity");
      }
      try {
        db.exec("BEGIN IMMEDIATE");
        deleteExpired.run(now);
        const info = insert.run(entry.trustSource, entry.keyId, entry.nonce, entry.until);
        db.exec("COMMIT");
        return info.changes === 1 ? "claimed" : "duplicate";
      } catch (error) {
        try {
          db.exec("ROLLBACK");
        } catch {
          // The original failure is the one callers need.
        }
        throw tapError("store_unavailable", error instanceof Error ? error.message : "replay store failed");
      }
    },
    close() {
      db.close();
    },
  };
}

function claimInMap(claims: Map<string, number>, entry: ReplayClaim, now: number): ClaimResult {
  if (!Number.isInteger(entry.until) || entry.until <= now) return "expired";
  if (entry.trustSource.length === 0 || entry.keyId.length === 0 || entry.nonce.length === 0) {
    throw tapError("store_unavailable", "replay claim is missing an identity");
  }
  const id = `${entry.trustSource}\0${entry.keyId}\0${entry.nonce}`;
  const existing = claims.get(id);
  if (existing !== undefined && existing > now) return "duplicate";
  claims.set(id, entry.until);
  return "claimed";
}

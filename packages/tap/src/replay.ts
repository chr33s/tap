import { DatabaseSync } from "node:sqlite";

import { throwIfAborted } from "./abort.js";
import { systemClock } from "./clock.js";
import { tapError } from "./errors.js";
import type { ClaimResult, Clock, ReplayClaim, ReplayStore } from "./types.js";

export function createMemoryReplayStore(clock: Clock = systemClock): ReplayStore {
  const claims = new Map<string, number>();
  // Claim ids grouped by deadline second. Each claim only drops the buckets
  // that expired since the last one, so no request scans every live claim.
  const buckets = new Map<number, string[]>();
  let sweptThrough: number | undefined;
  const sweep = (now: number): void => {
    if (sweptThrough === undefined) {
      sweptThrough = now;
      return;
    }
    if (now <= sweptThrough) return;
    const drop = (until: number): void => {
      for (const id of buckets.get(until) ?? []) {
        if (claims.get(id) === until) claims.delete(id);
      }
      buckets.delete(until);
    };
    if (now - sweptThrough <= buckets.size) {
      for (let until = sweptThrough + 1; until <= now; until += 1) drop(until);
    } else {
      for (const until of [...buckets.keys()]) if (until <= now) drop(until);
    }
    sweptThrough = now;
  };
  return {
    async claim(entry, signal) {
      throwIfAborted(signal);
      const now = clock.now();
      sweep(now);
      const result = claimInMap(claims, entry, now);
      if (result === "claimed") {
        const id = claimId(entry);
        const bucket = buckets.get(entry.until);
        if (bucket) bucket.push(id);
        else buckets.set(entry.until, [id]);
      }
      return result;
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
    db.exec("CREATE INDEX IF NOT EXISTS replay_nonce_until ON replay_nonce (until_unix)");
  } catch (error) {
    db.close();
    throw tapError("store_unavailable", error instanceof Error ? error.message : "unable to open replay store");
  }
  const deleteExpired = db.prepare("DELETE FROM replay_nonce WHERE until_unix <= ?");
  // A row whose deadline has passed is reclaimable even before it is pruned.
  const insert = db.prepare(`
    INSERT INTO replay_nonce (trust_source, key_id, nonce, until_unix) VALUES (?, ?, ?, ?)
    ON CONFLICT (trust_source, key_id, nonce) DO UPDATE SET until_unix = excluded.until_unix WHERE replay_nonce.until_unix <= ?
  `);
  let prunedAt = Number.NEGATIVE_INFINITY;
  return {
    async claim(entry, signal) {
      throwIfAborted(signal);
      const now = clock.now();
      const early = validateClaim(entry, now);
      if (early) return early;
      try {
        db.exec("BEGIN IMMEDIATE");
        if (now > prunedAt) {
          deleteExpired.run(now);
          prunedAt = now;
        }
        const info = insert.run(entry.trustSource, entry.keyId, entry.nonce, entry.until, now);
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

/**
 * Shared `ReplayStore` contract: a claim whose deadline has passed is
 * `expired` without touching storage, and a claim missing any part of its
 * identity is a store failure. Returns the early result, or `undefined` when
 * the store should go on to record the claim.
 */
function validateClaim(entry: ReplayClaim, now: number): ClaimResult | undefined {
  if (!Number.isInteger(entry.until) || entry.until <= now) return "expired";
  if (entry.trustSource.length === 0 || entry.keyId.length === 0 || entry.nonce.length === 0) {
    throw tapError("store_unavailable", "replay claim is missing an identity");
  }
  return undefined;
}

function claimInMap(claims: Map<string, number>, entry: ReplayClaim, now: number): ClaimResult {
  const early = validateClaim(entry, now);
  if (early) return early;
  const id = claimId(entry);
  const existing = claims.get(id);
  if (existing !== undefined && existing > now) return "duplicate";
  claims.set(id, entry.until);
  return "claimed";
}

function claimId(entry: ReplayClaim): string {
  return `${entry.trustSource}\0${entry.keyId}\0${entry.nonce}`;
}

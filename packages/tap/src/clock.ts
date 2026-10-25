import type { Clock } from "./types.js";

export const systemClock: Clock = {
  nowMs: () => Date.now(),
  now: () => Math.floor(Date.now() / 1000),
};

export interface ManualClock extends Clock {
  set(ms: number): void;
  advance(ms: number): void;
}

export function createManualClock(startMs = 1_700_000_000_000): ManualClock {
  let now = startMs;
  return {
    nowMs: () => now,
    now: () => Math.floor(now / 1000),
    set(ms: number) {
      now = ms;
    },
    advance(ms: number) {
      now += ms;
    },
  };
}

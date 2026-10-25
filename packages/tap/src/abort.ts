import { tapError } from "./errors.js";

export function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) {
    throw tapError("cancelled", "operation aborted");
  }
}

export function isAbortError(value: unknown): boolean {
  if (typeof value !== "object" || value === null) return false;
  const name = "name" in value ? String(value.name) : "";
  const code = "code" in value ? value.code : undefined;
  return name === "AbortError" || code === 20 || code === "ABORT_ERR";
}

export function mergeSignals(signals: Array<AbortSignal | undefined>): AbortSignal | undefined {
  const present = signals.filter((signal): signal is AbortSignal => signal !== undefined);
  if (present.length === 0) return undefined;
  if (present.length === 1) return present[0];
  return AbortSignal.any(present);
}

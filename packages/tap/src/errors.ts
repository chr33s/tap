/**
 * Stable verifier and client failures. Every code prevents a request from
 * being treated as verified.
 */
export const TAP_ERROR_CODES = [
  "malformed",
  "policy",
  "trust",
  "invalid_signature",
  "invalid_time",
  "replay",
  "resolver_unavailable",
  "store_unavailable",
  "cancelled",
] as const;

export type TapErrorCode = (typeof TAP_ERROR_CODES)[number];

export class TapError extends Error {
  readonly code: TapErrorCode;
  readonly reason: string;

  constructor(code: TapErrorCode, reason: string) {
    super(`${code}: ${reason}`);
    this.name = "TapError";
    this.code = code;
    this.reason = reason;
  }
}

export function isTapError(value: unknown): value is TapError {
  return value instanceof TapError;
}

export function tapError(code: TapErrorCode, reason: string): TapError {
  return new TapError(code, reason);
}

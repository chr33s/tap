import { Data } from "effect";
import { isAbortError, isTapError, type TapErrorCode } from "tap";

export class TapFailure extends Data.TaggedError("TapFailure")<{
  readonly code: TapErrorCode;
  readonly reason: string;
}> {}

/** Maps a core `TapError` into the Effect error channel. Unexpected exceptions stay defects. */
export function toTapFailure(cause: unknown): TapFailure {
  if (cause instanceof TapFailure) return cause;
  if (isTapError(cause)) return new TapFailure({ code: cause.code, reason: cause.reason });
  if (isAbortError(cause)) return new TapFailure({ code: "cancelled", reason: "operation aborted" });
  throw cause;
}

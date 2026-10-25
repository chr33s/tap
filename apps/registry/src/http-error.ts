import { Data } from "effect";

export class HttpReply extends Data.TaggedError("HttpReply")<{
  readonly status: number;
  readonly body: { readonly error: string; readonly message: string };
}> {}

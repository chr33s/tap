import { Data } from "effect";

export class HttpReply extends Data.TaggedError("HttpReply")<{
  readonly status: number;
  readonly body: { readonly error: string; readonly message: string };
}> {}

export function reply(status: number, error: string, message: string): never {
  throw new HttpReply({ status, body: { error, message } });
}

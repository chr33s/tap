/**
 * RFC 8941 structured field parser and canonical serializer.
 * Covers the dictionary, inner-list, item, and parameter forms used by
 * HTTP message signatures. Duplicate keys are rejected as ambiguous.
 */

export type SfBareItem =
  | { readonly type: "integer"; readonly value: number }
  | { readonly type: "decimal"; readonly value: number }
  | { readonly type: "string"; readonly value: string }
  | { readonly type: "token"; readonly value: string }
  | { readonly type: "binary"; readonly value: Uint8Array }
  | { readonly type: "boolean"; readonly value: boolean };

export interface SfParameter {
  readonly key: string;
  readonly value: SfBareItem;
}

export interface SfItem {
  readonly type: "item";
  readonly bare: SfBareItem;
  readonly params: readonly SfParameter[];
}

export interface SfInnerList {
  readonly type: "inner-list";
  readonly items: readonly SfItem[];
  readonly params: readonly SfParameter[];
}

export type SfMember = SfItem | SfInnerList;

export interface SfDictEntry {
  readonly key: string;
  readonly value: SfMember;
}

export interface SfDictionary {
  readonly entries: readonly SfDictEntry[];
}

export class SfParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SfParseError";
  }
}

const KEY = /^[a-z*][a-z0-9_.*-]*$/;

class Parser {
  private index = 0;

  constructor(private readonly input: string) {}

  parseDictionary(): SfDictionary {
    this.skipOws();
    if (this.eof()) throw new SfParseError("empty dictionary");
    const entries: SfDictEntry[] = [];
    const seen = new Set<string>();
    while (!this.eof()) {
      const key = this.parseKey();
      if (seen.has(key)) throw new SfParseError(`duplicate dictionary key ${key}`);
      seen.add(key);
      let value: SfMember;
      if (this.peek() === "=") {
        this.consume("=");
        value = this.parseMember();
      } else {
        value = { type: "item", bare: { type: "boolean", value: true }, params: this.parseParams() };
      }
      entries.push({ key, value });
      this.skipOws();
      if (this.eof()) break;
      if (this.peek() !== ",") throw new SfParseError("expected comma between dictionary members");
      this.consume(",");
      this.skipOws();
      if (this.eof()) throw new SfParseError("trailing comma");
    }
    return { entries };
  }

  private parseMember(): SfMember {
    if (this.peek() === "(") return this.parseInnerList();
    return this.parseItem();
  }

  private parseInnerList(): SfInnerList {
    this.consume("(");
    this.skipSp();
    const items: SfItem[] = [];
    if (this.peek() !== ")") {
      items.push(this.parseItem());
      while (this.peek() === " ") {
        this.skipSp();
        if (this.peek() === ")") break;
        items.push(this.parseItem());
      }
    }
    this.consume(")");
    return { type: "inner-list", items, params: this.parseParams() };
  }

  private parseItem(): SfItem {
    return { type: "item", bare: this.parseBare(), params: this.parseParams() };
  }

  private parseParams(): SfParameter[] {
    const params: SfParameter[] = [];
    const seen = new Set<string>();
    while (this.peek() === ";") {
      this.consume(";");
      this.skipSp();
      const key = this.parseKey();
      if (seen.has(key)) throw new SfParseError(`duplicate parameter ${key}`);
      seen.add(key);
      let value: SfBareItem = { type: "boolean", value: true };
      if (this.peek() === "=") {
        this.consume("=");
        value = this.parseBare();
      }
      params.push({ key, value });
    }
    return params;
  }

  private parseBare(): SfBareItem {
    const ch = this.peek();
    if (ch === "\"") return { type: "string", value: this.parseString() };
    if (ch === ":") return { type: "binary", value: this.parseBinary() };
    if (ch === "?") return { type: "boolean", value: this.parseBoolean() };
    if (ch === "-" || isDigit(ch)) return this.parseNumber();
    if (isTokenStart(ch)) return { type: "token", value: this.parseToken() };
    throw new SfParseError(`unexpected character ${JSON.stringify(ch)}`);
  }

  private parseKey(): string {
    const start = this.index;
    if (!isKeyStart(this.peek())) throw new SfParseError("expected parameter or member key");
    this.index += 1;
    while (isKeyChar(this.peek())) this.index += 1;
    const key = this.input.slice(start, this.index);
    if (!KEY.test(key)) throw new SfParseError(`invalid key ${key}`);
    return key;
  }

  private parseString(): string {
    this.consume("\"");
    let out = "";
    while (!this.eof()) {
      const ch = this.peek();
      if (ch === "\"") {
        this.index += 1;
        return out;
      }
      if (ch === "\\") {
        this.index += 1;
        const escaped = this.peek();
        if (escaped !== "\"" && escaped !== "\\") throw new SfParseError("invalid string escape");
        out += escaped;
        this.index += 1;
        continue;
      }
      const code = ch.charCodeAt(0);
      if (code < 0x20 || code > 0x7e) throw new SfParseError("string contains a non-printable character");
      out += ch;
      this.index += 1;
    }
    throw new SfParseError("unterminated string");
  }

  private parseBinary(): Uint8Array {
    this.consume(":");
    const start = this.index;
    while (!this.eof() && this.peek() !== ":") this.index += 1;
    if (this.peek() !== ":") throw new SfParseError("unterminated byte sequence");
    const raw = this.input.slice(start, this.index);
    this.consume(":");
    return decodeBase64(raw);
  }

  private parseBoolean(): boolean {
    this.consume("?");
    const ch = this.peek();
    if (ch !== "0" && ch !== "1") throw new SfParseError("invalid boolean");
    this.index += 1;
    return ch === "1";
  }

  private parseNumber(): SfBareItem {
    const start = this.index;
    if (this.peek() === "-") this.index += 1;
    if (!isDigit(this.peek())) throw new SfParseError("invalid number");
    if (this.peek() === "0") {
      this.index += 1;
      if (isDigit(this.peek())) throw new SfParseError("leading zero");
    } else {
      while (isDigit(this.peek())) this.index += 1;
    }
    const digits = this.index - start - (this.input[start] === "-" ? 1 : 0);
    if (digits < 1 || digits > 15) throw new SfParseError("integer has too many digits");
    if (this.peek() === ".") {
      this.index += 1;
      const fracStart = this.index;
      while (isDigit(this.peek())) this.index += 1;
      const frac = this.index - fracStart;
      if (frac < 1 || frac > 3) throw new SfParseError("invalid decimal");
      const value = Number(this.input.slice(start, this.index));
      if (!Number.isFinite(value)) throw new SfParseError("invalid decimal");
      return { type: "decimal", value };
    }
    const text = this.input.slice(start, this.index);
    if (text === "-0") throw new SfParseError("negative zero");
    const value = Number(text);
    if (!Number.isSafeInteger(value)) throw new SfParseError("integer is not a safe integer");
    return { type: "integer", value };
  }

  private parseToken(): string {
    const start = this.index;
    if (!isTokenStart(this.peek())) throw new SfParseError("invalid token");
    this.index += 1;
    while (isTokenChar(this.peek())) this.index += 1;
    return this.input.slice(start, this.index);
  }

  private skipOws(): void {
    while (this.peek() === " " || this.peek() === "\t") this.index += 1;
  }

  private skipSp(): void {
    while (this.peek() === " ") this.index += 1;
  }

  private peek(): string {
    return this.input[this.index] ?? "";
  }

  private eof(): boolean {
    return this.index >= this.input.length;
  }

  private consume(expected: string): void {
    if (this.peek() !== expected) throw new SfParseError(`expected ${JSON.stringify(expected)}`);
    this.index += 1;
  }
}

export function parseDictionary(input: string): SfDictionary {
  if (input.length > 16_384) throw new SfParseError("structured field exceeds 16 KiB");
  return new Parser(input).parseDictionary();
}

export function serializeDictionary(dictionary: SfDictionary): string {
  return dictionary.entries.map((entry) => `${entry.key}=${serializeMember(entry.value)}`).join(", ");
}

export function serializeMember(member: SfMember): string {
  if (member.type === "inner-list") {
    const items = member.items.map((item) => serializeItem(item)).join(" ");
    return `(${items})${serializeParams(member.params)}`;
  }
  return serializeItem(member);
}

function serializeItem(item: SfItem): string {
  return `${serializeBare(item.bare)}${serializeParams(item.params)}`;
}

function serializeParams(params: readonly SfParameter[]): string {
  return params.map((param) => {
    if (param.value.type === "boolean" && param.value.value === true) return `;${param.key}`;
    return `;${param.key}=${serializeBare(param.value)}`;
  }).join("");
}

export function serializeBare(item: SfBareItem): string {
  switch (item.type) {
    case "integer":
      if (!Number.isSafeInteger(item.value)) throw new SfParseError("integer is not a safe integer");
      return String(item.value);
    case "decimal":
      return item.value.toFixed(Math.min(3, decimalPlaces(item.value)));
    case "string":
      return `"${item.value.replace(/\\/g, "\\\\").replace(/"/g, "\\\"")}"`;
    case "token":
      return item.value;
    case "binary":
      return `:${Buffer.from(item.value).toString("base64")}:`;
    case "boolean":
      return item.value ? "?1" : "?0";
    default: {
      const _exhaustive: never = item;
      return _exhaustive;
    }
  }
}

function decimalPlaces(value: number): number {
  const text = String(value);
  const index = text.indexOf(".");
  return index < 0 ? 1 : text.length - index - 1;
}

function decodeBase64(raw: string): Uint8Array {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(raw) || raw.length % 4 === 1) {
    throw new SfParseError("invalid byte sequence");
  }
  const buf = Buffer.from(raw, "base64");
  const canonical = buf.toString("base64").replace(/=+$/, "");
  if (raw.replace(/=+$/, "") !== canonical) throw new SfParseError("invalid byte sequence");
  return buf;
}

function isDigit(ch: string): boolean {
  return ch >= "0" && ch <= "9";
}

function isKeyStart(ch: string): boolean {
  return (ch >= "a" && ch <= "z") || ch === "*";
}

function isKeyChar(ch: string): boolean {
  return isKeyStart(ch) || isDigit(ch) || ch === "_" || ch === "-" || ch === "." || ch === "*";
}

function isTokenStart(ch: string): boolean {
  return (ch >= "A" && ch <= "Z") || (ch >= "a" && ch <= "z") || ch === "*";
}

function isTokenChar(ch: string): boolean {
  // `peek()` returns "" at end of input, and every string includes "".
  return ch.length === 1 && (isTokenStart(ch) || isDigit(ch) || "!#$%&'*+-.^_`|~:/".includes(ch));
}

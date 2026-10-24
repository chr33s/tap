import { tapError } from "./errors.js";
import type { ProfileName, RequestData } from "./types.js";

export interface ParsedTarget {
  scheme: "http" | "https";
  /** Authority as it appears in the URL, without userinfo. */
  rawAuthority: string;
  /** RFC 9421 authority: lowercase host, default port omitted. */
  normalizedAuthority: string;
  /** Path as it appears, without query. Empty when the URL has no path. */
  rawPath: string;
  /** `@path` for the `tap` profile. Empty paths are `/`. */
  tapPath: string;
  /** Query without `?`, or null when the URL has no query. */
  query: string | null;
  /** `@query` value, including the leading `?`. Absent queries are `?`. */
  queryComponent: string;
  /** `@path` for `legacySample`: path plus raw query, matching the sample signer. */
  legacyPath: string;
}

const URL_RE = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#]*)([^?#]*)(?:\?([^#]*))?$/;

/**
 * Rejects request targets whose path is not the path a normalizing server
 * would route. Fragments and backslashes are not part of an origin-form
 * target. `.` and `..` segments, including `%2e`, change meaning under
 * WHATWG URL parsing.
 */
export function assertSafeRequestTarget(requestTarget: string): void {
  if (requestTarget.length === 0 || requestTarget.length > 8_192) {
    throw tapError("malformed", "invalid request target");
  }
  if (!requestTarget.startsWith("/")) throw tapError("malformed", "invalid request target");
  if (requestTarget.includes("#") || requestTarget.includes("\\")) {
    throw tapError("malformed", "request target contains a fragment or backslash");
  }
  const path = requestTarget.split("?")[0] ?? requestTarget;
  assertNoDotSegments(path);
}

export function parseTarget(url: string): ParsedTarget {
  if (url.length > 8_192) throw tapError("malformed", "url is too long");
  if (url.includes("#") || url.includes("\\")) {
    throw tapError("malformed", "request target contains a fragment or backslash");
  }
  const match = URL_RE.exec(url);
  if (!match) throw tapError("malformed", "url must be an absolute http(s) URL");
  const schemeRaw = match[1];
  const authority = match[2];
  const path = match[3] ?? "";
  const query = match[4];
  if (!schemeRaw || authority === undefined) throw tapError("malformed", "url must be an absolute http(s) URL");
  const scheme = schemeRaw.toLowerCase();
  if (scheme !== "http" && scheme !== "https") throw tapError("malformed", "url scheme must be http or https");
  if (authority.includes("@")) throw tapError("malformed", "url userinfo is not allowed");
  if (authority.length === 0) throw tapError("malformed", "url is missing an authority");
  if (/[\u0000-\u0020\u007f]/.test(authority) || /[\u0000-\u001f\u007f]/.test(path) || (query !== undefined && /[\u0000-\u001f\u007f]/.test(query))) {
    throw tapError("malformed", "url contains a control character or space");
  }
  if (path !== "" && !path.startsWith("/")) throw tapError("malformed", "url path must be empty or absolute");
  assertNoDotSegments(path);
  return {
    scheme,
    rawAuthority: authority,
    normalizedAuthority: normalizeAuthority(authority, scheme),
    rawPath: path,
    tapPath: path === "" ? "/" : path,
    query: query === undefined ? null : query,
    queryComponent: query === undefined ? "?" : `?${query}`,
    legacyPath: query === undefined ? path : `${path}?${query}`,
  };
}

export function normalizeAuthority(authority: string, scheme: "http" | "https"): string {
  let host: string;
  let portText: string | undefined;
  if (authority.startsWith("[")) {
    const end = authority.indexOf("]");
    if (end < 1) throw tapError("malformed", "invalid IPv6 authority");
    host = authority.slice(0, end + 1).toLowerCase();
    const rest = authority.slice(end + 1);
    if (rest === "") portText = undefined;
    else if (rest.startsWith(":")) portText = rest.slice(1);
    else throw tapError("malformed", "invalid IPv6 authority");
  } else {
    if (/[^\u0021-\u007e]/.test(authority)) throw tapError("malformed", "authority must be ASCII");
    const colon = authority.lastIndexOf(":");
    if (colon >= 0) {
      if (authority.indexOf(":") !== colon) throw tapError("malformed", "unbracketed IPv6 authority");
      host = authority.slice(0, colon);
      portText = authority.slice(colon + 1);
    } else {
      host = authority;
    }
  }
  if (host.length === 0 || host === "[]") throw tapError("malformed", "empty host");
  host = host.toLowerCase();
  if (/[^\u0021-\u007e]/.test(host)) throw tapError("malformed", "authority must be ASCII");
  if (portText !== undefined) {
    if (!/^[0-9]+$/.test(portText)) throw tapError("malformed", "invalid port");
    const port = Number(portText);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw tapError("malformed", "invalid port");
    const defaultPort = scheme === "https" ? 443 : 80;
    if (port === defaultPort) return host;
    return `${host}:${port}`;
  }
  return host;
}

const HEADER_NAME = /^[!#$%&'*+\-.^_`|~0-9a-z]+$/;
const DERIVED = new Set(["@method", "@authority", "@path", "@query"]);

export function assertCoveredComponents(components: readonly string[]): void {
  if (components.length < 1 || components.length > 16) {
    throw tapError("policy", "covered component count is out of range");
  }
  const seen = new Set<string>();
  for (const component of components) {
    if (seen.has(component)) throw tapError("malformed", `duplicate covered component ${component}`);
    seen.add(component);
    if (DERIVED.has(component)) continue;
    if (component.startsWith("@")) throw tapError("policy", `unsupported component ${component}`);
    if (!HEADER_NAME.test(component)) throw tapError("malformed", `invalid component ${component}`);
  }
  if (!seen.has("@authority") || !seen.has("@path")) {
    throw tapError("policy", "coverage must include @authority and @path");
  }
}

export function componentValue(request: RequestData, target: ParsedTarget, name: string, profile: ProfileName): string {
  switch (name) {
    case "@method":
      if (!/^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/.test(request.method)) {
        throw tapError("malformed", "invalid method");
      }
      return request.method;
    case "@authority":
      return profile === "legacySample" ? target.rawAuthority : target.normalizedAuthority;
    case "@path":
      return profile === "legacySample" ? target.legacyPath : target.tapPath;
    case "@query":
      return target.queryComponent;
    default:
      return headerComponent(request.headers, name);
  }
}

export function headerValues(headers: ReadonlyArray<readonly [string, string]>, name: string): string[] {
  const wanted = name.toLowerCase();
  const values: string[] = [];
  for (const [rawName, rawValue] of headers) {
    if (rawName.toLowerCase() === wanted) values.push(rawValue);
  }
  return values;
}

function headerComponent(headers: ReadonlyArray<readonly [string, string]>, name: string): string {
  const values = headerValues(headers, name);
  if (values.length === 0) throw tapError("policy", `missing covered header ${name}`);
  const normalized = values.map((value) => {
    if (/[\r\n]/.test(value)) throw tapError("malformed", `header ${name} contains a line break`);
    return value.replace(/^[ \t]+|[ \t]+$/g, "");
  });
  return normalized.join(", ");
}

function assertNoDotSegments(path: string): void {
  for (const segment of path.split("/")) {
    if (segment.length === 0) continue;
    const decoded = segment.replace(/%([0-9A-Fa-f]{2})/g, (_match, hex: string) =>
      String.fromCharCode(Number.parseInt(hex, 16)),
    );
    if (decoded === "." || decoded === "..") {
      throw tapError("malformed", "request target contains a dot segment");
    }
  }
}

export function buildSignatureBase(components: ReadonlyArray<readonly [string, string]>, signatureParams: string): string {
  const lines = components.map(([name, value]) => `"${name}": ${value}`);
  lines.push(`"@signature-params": ${signatureParams}`);
  return lines.join("\n");
}

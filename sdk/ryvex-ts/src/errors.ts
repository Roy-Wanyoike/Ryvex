/**
 * Error handling for the Ryvex REST API.
 *
 * Every non-2xx response carries the frozen error envelope
 * (docs/api-contracts.md):
 *
 *   {"error":{"code":"conflict","message":"…","request_id":"…","details":[]}}
 *
 * {@link RyvexError} parses it and exposes the parts as typed fields.
 * When the body is not the expected envelope (proxy HTML, empty body,
 * plain text), the error still constructs with a code inferred from the
 * HTTP status, so callers can always branch on `code` / `status`.
 */

/** Stable wire error codes emitted by the /v1 face. */
export type ErrorCode =
  | "validation_failed"
  | "bad_request"
  | "unauthorized"
  | "not_found"
  | "method_not_allowed"
  | "already_exists"
  | "conflict"
  | "internal_error";

/** Error detail payload from the envelope (`error` key). */
export interface ErrorDetail {
  code: ErrorCode | string;
  message: string;
  request_id?: string;
  details?: string[];
}

/**
 * Default error code for a given HTTP status, used when the response
 * body is not a parseable envelope.
 */
export const DEFAULT_CODE_BY_STATUS: Readonly<Record<number, ErrorCode>> = {
  400: "bad_request",
  401: "unauthorized",
  404: "not_found",
  405: "method_not_allowed",
  409: "conflict",
  500: "internal_error",
};

/** The canonical HTTP status for each wire error code. */
export const STATUS_BY_CODE: Readonly<Record<ErrorCode, number>> = {
  validation_failed: 400,
  bad_request: 400,
  unauthorized: 401,
  not_found: 404,
  method_not_allowed: 405,
  already_exists: 409,
  conflict: 409,
  internal_error: 500,
};

export class RyvexError extends Error {
  /** HTTP status of the failed response (0 for transport-level failures). */
  readonly status: number;
  /** Wire error code from the envelope (status-derived fallback if absent). */
  readonly code: ErrorCode | string;
  /** Server-side request id — quote it when filing bug reports. */
  readonly requestId?: string;
  /** Optional structured details (e.g. the offending field). */
  readonly details: string[];

  constructor(
    status: number,
    code: ErrorCode | string,
    message: string,
    options: { requestId?: string; details?: string[]; cause?: unknown } = {},
  ) {
    super(message, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = "RyvexError";
    this.status = status;
    this.code = code;
    this.requestId = options.requestId;
    this.details = options.details ?? [];
  }

  /**
   * Build an error from a raw (non-2xx) HTTP response body. Parses the
   * frozen envelope when possible; falls back to a status-derived code
   * otherwise.
   */
  static fromResponse(status: number, body: string): RyvexError {
    const fallback = DEFAULT_CODE_BY_STATUS[status] ?? "internal_error";
    let parsed: unknown;
    try {
      parsed = body.length > 0 ? JSON.parse(body) : undefined;
    } catch {
      parsed = undefined;
    }

    const detail =
      isRecord(parsed) && isRecord(parsed["error"])
        ? normalizeDetail(parsed["error"] as Record<string, unknown>)
        : undefined;

    if (detail) {
      return new RyvexError(status, detail.code ?? fallback, detail.message ?? fallbackMessage(status), {
        requestId: detail.request_id,
        details: detail.details,
      });
    }

    const snippet = body.trim().slice(0, 200);
    const message =
      snippet.length > 0 && !snippet.startsWith("<")
        ? `${fallbackMessage(status)}: ${snippet}`
        : fallbackMessage(status);
    return new RyvexError(status, fallback, message);
  }

  /**
   * Wrap a transport-level failure (DNS, connection refused, abort) so
   * callers have one error type to catch.
   */
  static fromTransport(cause: unknown, url: string): RyvexError {
    const reason = cause instanceof Error ? cause.message : String(cause);
    return new RyvexError(0, "internal_error", `request to ${url} failed: ${reason}`, { cause });
  }

  /** Type guard for `catch (e)` blocks. */
  static is(value: unknown): value is RyvexError {
    return value instanceof RyvexError;
  }
}

function normalizeDetail(raw: Record<string, unknown>): Partial<ErrorDetail> {
  const out: Partial<ErrorDetail> = {};
  if (typeof raw["code"] === "string") out.code = raw["code"];
  if (typeof raw["message"] === "string") out.message = raw["message"];
  if (typeof raw["request_id"] === "string") out.request_id = raw["request_id"];
  if (Array.isArray(raw["details"])) {
    out.details = raw["details"].map(String);
  }
  return out;
}

function fallbackMessage(status: number): string {
  switch (status) {
    case 400:
      return "bad request";
    case 401:
      return "unauthorized: missing or invalid bearer token";
    case 404:
      return "not found";
    case 405:
      return "method not allowed";
    case 409:
      return "conflict";
    case 500:
      return "internal error";
    default:
      return `request failed with status ${status}`;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

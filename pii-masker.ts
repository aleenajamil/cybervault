/**
 * PII Masking Engine — SBP Technology Risk Management Framework
 *
 * Scans JSON payloads (objects, arrays, or strings) and masks:
 *   - Pakistani CNICs       13501-1234567-1  →  13501-*******-1
 *   - Bank account numbers  00210012345644   →  0021********44
 *
 * Safe to use in logging middleware, audit trails, and error reporters.
 */

// ─── Regex Patterns ───────────────────────────────────────────────────────────

/**
 * Pakistani CNIC: 5 digits, hyphen, 7 digits, hyphen, 1 digit
 * e.g.  42101-1234567-0
 *
 * Capture groups:
 *   [1] prefix  (5 digits)
 *   [2] middle  (7 digits) — MASKED
 *   [3] suffix  (1 digit)
 */
const CNIC_REGEX = /\b(\d{5})-(\d{7})-(\d)\b/g;

/**
 * Pakistani bank account numbers: 14–16 consecutive digits.
 * We intentionally exclude numbers already matched as part of a CNIC
 * by requiring the run is NOT surrounded by hyphens.
 *
 * Capture groups:
 *   [1] first 4 digits  — kept visible
 *   [2] middle digits   — MASKED
 *   [3] last 2 digits   — kept visible
 *
 * Lookahead/lookbehind ensure we don't match inside a CNIC
 * or inside longer numeric strings (credit card etc. handled separately).
 */
const ACCOUNT_REGEX = /(?<![0-9-])(\d{4})(\d{8,10})(\d{2})(?![0-9-])/g;

// ─── Masking Helpers ──────────────────────────────────────────────────────────

/**
 * Mask a single CNIC string.
 * "42101-1234567-0" → "42101-*******-0"
 */
export function maskCnic(value: string): string {
  return value.replace(CNIC_REGEX, (_match, prefix, _middle, suffix) => {
    return `${prefix}-${"*".repeat(7)}-${suffix}`;
  });
}

/**
 * Mask a single bank account number string.
 * "00210012345644" → "0021********44"
 */
export function maskAccountNumber(value: string): string {
  return value.replace(
    ACCOUNT_REGEX,
    (_match, first4, middle, last2) => {
      return `${first4}${"*".repeat(middle.length)}${last2}`;
    }
  );
}

/**
 * Apply all masking rules to a plain string.
 * Order matters: CNIC first (more specific), then account numbers.
 */
export function maskString(value: string): string {
  // Reset lastIndex on each call (safety for global regexes used outside replace)
  CNIC_REGEX.lastIndex = 0;
  ACCOUNT_REGEX.lastIndex = 0;
  return maskAccountNumber(maskCnic(value));
}

// ─── Deep JSON Masker ─────────────────────────────────────────────────────────

type JsonPrimitive = string | number | boolean | null;
type JsonValue = JsonPrimitive | JsonObject | JsonArray;
interface JsonObject { [key: string]: JsonValue }
type JsonArray = JsonValue[];

/**
 * Recursively walk any JSON-compatible value and mask PII in every string.
 *
 * - Strings   → masked in place
 * - Numbers   → converted to string, masked, returned as string if changed
 * - Objects   → each value recursively masked
 * - Arrays    → each element recursively masked
 * - null/bool → unchanged
 */
export function maskJson(value: JsonValue): JsonValue {
  if (value === null) return null;

  if (typeof value === "string") {
    return maskString(value);
  }

  if (typeof value === "number") {
    // Numbers like 4210112345670 could be raw CNICs/accounts stored as numbers
    const asStr = String(value);
    const masked = maskString(asStr);
    return masked !== asStr ? masked : value;
  }

  if (typeof value === "boolean") return value;

  if (Array.isArray(value)) {
    return value.map(maskJson);
  }

  if (typeof value === "object") {
    const result: JsonObject = {};
    for (const [k, v] of Object.entries(value)) {
      result[k] = maskJson(v);
    }
    return result;
  }

  return value;
}

/**
 * Parse a JSON string, mask it, and re-serialise.
 * Throws if the input is not valid JSON.
 */
export function maskJsonString(raw: string): string {
  const parsed = JSON.parse(raw) as JsonValue;
  const masked = maskJson(parsed);
  return JSON.stringify(masked, null, 2);
}

// ─── Detection-only Utilities (for audit logging) ────────────────────────────

export interface PiiMatch {
  type: "CNIC" | "BANK_ACCOUNT";
  path: string;       // JSON key path, e.g. "customer.accounts[0].number"
  original: string;
  masked: string;
}

/**
 * Scan a JSON value and return a report of every PII field found.
 * Does NOT modify the value — use this for audit/alerting.
 */
export function detectPii(
  value: JsonValue,
  path = "$"
): PiiMatch[] {
  const matches: PiiMatch[] = [];

  if (typeof value === "string") {
    // CNICs
    for (const m of value.matchAll(new RegExp(CNIC_REGEX.source, "g"))) {
      matches.push({
        type: "CNIC",
        path,
        original: m[0],
        masked: `${m[1]}-${"*".repeat(7)}-${m[3]}`,
      });
    }
    // Account numbers (only if not part of a CNIC)
    const cnicStripped = value.replace(new RegExp(CNIC_REGEX.source, "g"), "");
    for (const m of cnicStripped.matchAll(new RegExp(ACCOUNT_REGEX.source, "g"))) {
      matches.push({
        type: "BANK_ACCOUNT",
        path,
        original: m[0],
        masked: `${m[1]}${"*".repeat(m[2].length)}${m[3]}`,
      });
    }
  } else if (Array.isArray(value)) {
    value.forEach((el, i) => matches.push(...detectPii(el, `${path}[${i}]`)));
  } else if (typeof value === "object" && value !== null) {
    for (const [k, v] of Object.entries(value)) {
      matches.push(...detectPii(v, `${path}.${k}`));
    }
  }

  return matches;
}

// ─── Express Logging Middleware ───────────────────────────────────────────────

import type { Request, Response, NextFunction } from "express";

/**
 * Express middleware that masks PII in req.body before it reaches
 * any downstream logger (Morgan, Winston, etc.).
 *
 * Usage:
 *   app.use(piiMaskingMiddleware);
 *   app.use(morgan("combined"));  // body is already masked
 */
export function piiMaskingMiddleware(
  req: Request,
  _res: Response,
  next: NextFunction
): void {
  if (req.body && typeof req.body === "object") {
    req.body = maskJson(req.body as JsonValue);
  }
  next();
}

// ─── Quick self-test (run with: npx ts-node pii-masker.ts) ───────────────────

if (require.main === module) {
  const sample = {
    transaction: {
      reference: "TXN-2024-001",
      customer: {
        name: "Ali Hassan",
        cnic: "42101-1234567-0",
        cnicAlt: "13501-9876543-1",
      },
      accounts: [
        { label: "savings",  number: "00210098765432" },
        { label: "current",  number: "1234567890123456" },
      ],
      notes: "Transfer from 42101-1111111-9 account 00540087654312 processed.",
    },
  };

  console.log("─── Original ────────────────────────────────");
  console.log(JSON.stringify(sample, null, 2));

  console.log("\n─── Masked ──────────────────────────────────");
  console.log(JSON.stringify(maskJson(sample as unknown as JsonValue), null, 2));

  console.log("\n─── PII Audit Report ────────────────────────");
  const report = detectPii(sample as unknown as JsonValue);
  report.forEach(({ type, path, original, masked }) => {
    console.log(`  [${type}] ${path}`);
    console.log(`    ${original}  →  ${masked}`);
  });
}

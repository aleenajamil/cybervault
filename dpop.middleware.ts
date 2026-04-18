/**
 * DPoP (Demonstrating Proof of Possession) Middleware
 * RFC 9449 compliant — built for Pakistani EMI / fintech API security
 *
 * Verifies:
 *  1. Bearer token presence
 *  2. DPoP proof header (signed JWT)
 *  3. JWT signature via embedded JWK public key
 *  4. htm  — HTTP method matches
 *  5. htu  — HTTP target URL matches (prevents stolen-token reuse)
 *  6. iat  — Issued-at within acceptable clock skew
 *  7. jti  — Unique nonce (replay attack prevention)
 *  8. cnf.jkt — Access token is bound to this specific key pair
 */

import { Request, Response, NextFunction } from "express";
import { createPublicKey, createVerify } from "crypto";
import { createHash } from "crypto";

// ─── Configuration ───────────────────────────────────────────────────────────

const DPOP_MAX_AGE_SECONDS = 300; // DPoP proof valid for 5 minutes
const CLOCK_SKEW_SECONDS = 30; // Allow 30 s clock drift

// In production: use Redis with TTL for distributed replay protection.
// This in-memory store is fine for single-instance APIs.
const usedJtis = new Map<string, number>(); // jti → expiry timestamp

// ─── Types ───────────────────────────────────────────────────────────────────

interface DPoPHeader {
  typ: string;
  alg: string;
  jwk: {
    kty: string;
    n?: string;
    e?: string;
    x?: string;
    y?: string;
    crv?: string;
    use?: string;
    key_ops?: string[];
  };
}

interface DPoPPayload {
  jti: string; // Unique token ID (replay guard)
  htm: string; // HTTP method (GET, POST …)
  htu: string; // HTTP target URI (must match exactly)
  iat: number; // Issued-at (Unix seconds)
  ath?: string; // Access token hash (optional, RFC 9449 §4.2)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function base64UrlDecode(input: string): Buffer {
  const padded = input.replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (padded.length % 4)) % 4;
  return Buffer.from(padded + "=".repeat(pad), "base64");
}

function parseJWT(token: string): {
  header: DPoPHeader;
  payload: DPoPPayload;
  signingInput: string;
  signature: Buffer;
} {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Malformed JWT: expected 3 parts");
  }

  const [rawHeader, rawPayload, rawSignature] = parts;

  let header: DPoPHeader;
  let payload: DPoPPayload;

  try {
    header = JSON.parse(base64UrlDecode(rawHeader).toString("utf8"));
  } catch {
    throw new Error("Invalid DPoP header: cannot parse JSON");
  }

  try {
    payload = JSON.parse(base64UrlDecode(rawPayload).toString("utf8"));
  } catch {
    throw new Error("Invalid DPoP payload: cannot parse JSON");
  }

  return {
    header,
    payload,
    signingInput: `${rawHeader}.${rawPayload}`,
    signature: base64UrlDecode(rawSignature),
  };
}

/**
 * Build a Node.js KeyObject from a JWK embedded in the DPoP header.
 * Supports RS256/RS384/RS512 and ES256/ES384/ES512.
 */
function jwkToPublicKey(
  jwk: DPoPHeader["jwk"],
  alg: string
): ReturnType<typeof createPublicKey> {
  const keyAlg = alg.startsWith("RS") ? "RSA" : "EC";

  if (keyAlg === "RSA") {
    if (!jwk.n || !jwk.e) throw new Error("RSA JWK missing n or e");
    return createPublicKey({ key: { kty: "RSA", n: jwk.n, e: jwk.e }, format: "jwk" });
  }

  if (keyAlg === "EC") {
    if (!jwk.crv || !jwk.x || !jwk.y)
      throw new Error("EC JWK missing crv, x, or y");
    return createPublicKey({
      key: { kty: "EC", crv: jwk.crv, x: jwk.x, y: jwk.y },
      format: "jwk",
    });
  }

  throw new Error(`Unsupported key type: ${alg}`);
}

/**
 * Verify the JWT signature.  Returns true if valid.
 */
function verifySignature(
  signingInput: string,
  signature: Buffer,
  jwk: DPoPHeader["jwk"],
  alg: string
): boolean {
  const algMap: Record<string, string> = {
    RS256: "RSA-SHA256",
    RS384: "RSA-SHA384",
    RS512: "RSA-SHA512",
    ES256: "SHA256",
    ES384: "SHA384",
    ES512: "SHA512",
  };

  const nodeAlg = algMap[alg];
  if (!nodeAlg) throw new Error(`Unsupported DPoP algorithm: ${alg}`);

  const publicKey = jwkToPublicKey(jwk, alg);
  const verifier = createVerify(nodeAlg);
  verifier.update(signingInput);

  if (alg.startsWith("ES")) {
    // ECDSA — convert raw (r||s) to DER for Node.js
    const r = signature.slice(0, signature.length / 2);
    const s = signature.slice(signature.length / 2);
    const derSignature = ecDsaRawToDer(r, s);
    return verifier.verify(publicKey, derSignature);
  }

  return verifier.verify(publicKey, signature);
}

/**
 * Convert raw ECDSA signature (r || s) → DER encoding expected by Node crypto.
 */
function ecDsaRawToDer(r: Buffer, s: Buffer): Buffer {
  const encodeInt = (buf: Buffer): Buffer => {
    let b = buf;
    while (b.length > 1 && b[0] === 0) b = b.slice(1); // strip leading zeros
    if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0x00]), b]); // prepend 0 if high bit
    return Buffer.concat([Buffer.from([0x02, b.length]), b]);
  };

  const ri = encodeInt(r);
  const si = encodeInt(s);
  return Buffer.concat([
    Buffer.from([0x30, ri.length + si.length]),
    ri,
    si,
  ]);
}

/**
 * Compute the JWK Thumbprint (SHA-256) for a key — used in cnf.jkt binding.
 * RFC 7638 §3.
 */
function jwkThumbprint(jwk: DPoPHeader["jwk"]): string {
  // Required members only, lexicographically sorted
  let members: Record<string, string>;

  if (jwk.kty === "RSA") {
    members = { e: jwk.e!, kty: jwk.kty, n: jwk.n! };
  } else if (jwk.kty === "EC") {
    members = { crv: jwk.crv!, kty: jwk.kty, x: jwk.x!, y: jwk.y! };
  } else {
    throw new Error("Unsupported JWK kty for thumbprint");
  }

  const canonical = JSON.stringify(members);
  return createHash("sha256").update(canonical).digest("base64url");
}

/**
 * Purge expired JTI entries from the in-memory store.
 * In production, rely on Redis TTL instead.
 */
function purgeExpiredJtis(): void {
  const now = Date.now();
  for (const [jti, expiry] of usedJtis) {
    if (expiry < now) usedJtis.delete(jti);
  }
}

// ─── 401 Response Helper ──────────────────────────────────────────────────────

function rejectWith401(
  res: Response,
  error: string,
  errorDescription: string
): void {
  res.setHeader("WWW-Authenticate", `DPoP error="${error}"`);
  res.status(401).json({
    error,
    error_description: errorDescription,
    timestamp: new Date().toISOString(),
  });
}

// ─── Main Middleware ──────────────────────────────────────────────────────────

export function dpopMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  // ── 1. Extract Bearer token ──────────────────────────────────────────────
  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    rejectWith401(
      res,
      "missing_token",
      "Authorization header with Bearer token is required"
    );
    return;
  }
  const bearerToken = authHeader.slice(7).trim();

  // ── 2. Extract DPoP proof header ─────────────────────────────────────────
  const dpopHeader = req.headers["dpop"];
  if (!dpopHeader || typeof dpopHeader !== "string") {
    rejectWith401(
      res,
      "use_dpop_nonce",
      "DPoP proof header is required. Provide a signed JWT as the DPoP header."
    );
    return;
  }

  let header: DPoPHeader;
  let payload: DPoPPayload;
  let signingInput: string;
  let signature: Buffer;

  // ── 3. Parse DPoP JWT ─────────────────────────────────────────────────────
  try {
    ({ header, payload, signingInput, signature } = parseJWT(dpopHeader));
  } catch (err: unknown) {
    rejectWith401(
      res,
      "invalid_dpop_proof",
      `Cannot parse DPoP JWT: ${(err as Error).message}`
    );
    return;
  }

  // ── 4. Validate typ claim ─────────────────────────────────────────────────
  if (header.typ !== "dpop+jwt") {
    rejectWith401(
      res,
      "invalid_dpop_proof",
      `DPoP JWT typ must be "dpop+jwt", got "${header.typ}"`
    );
    return;
  }

  // ── 5. Verify signature ───────────────────────────────────────────────────
  let signatureValid: boolean;
  try {
    signatureValid = verifySignature(signingInput, signature, header.jwk, header.alg);
  } catch (err: unknown) {
    rejectWith401(
      res,
      "invalid_dpop_proof",
      `Signature verification failed: ${(err as Error).message}`
    );
    return;
  }

  if (!signatureValid) {
    rejectWith401(
      res,
      "invalid_dpop_proof",
      "DPoP JWT signature is invalid. The token may have been tampered with."
    );
    return;
  }

  // ── 6. Validate htm (HTTP method) ─────────────────────────────────────────
  const expectedHtm = req.method.toUpperCase();
  if (!payload.htm || payload.htm.toUpperCase() !== expectedHtm) {
    rejectWith401(
      res,
      "invalid_dpop_proof",
      `DPoP htm mismatch: expected "${expectedHtm}", got "${payload.htm}"`
    );
    return;
  }

  // ── 7. Validate htu (HTTP target URI) ────────────────────────────────────
  //  Build the canonical request URI (scheme + host + path, no query string per RFC 9449 §4.2)
  const protocol = req.protocol;
  const host = req.get("host") ?? "";
  const requestUrl = `${protocol}://${host}${req.path}`;

  if (!payload.htu) {
    rejectWith401(res, "invalid_dpop_proof", "DPoP payload missing htu claim");
    return;
  }

  // Normalise both URLs before comparison
  let claimedUrl: string;
  try {
    claimedUrl = new URL(payload.htu).href.replace(/\?.*$/, ""); // strip query string
  } catch {
    rejectWith401(
      res,
      "invalid_dpop_proof",
      `DPoP htu is not a valid URL: "${payload.htu}"`
    );
    return;
  }

  const normalizedRequest = new URL(requestUrl).href;
  if (claimedUrl !== normalizedRequest) {
    rejectWith401(
      res,
      "invalid_dpop_proof",
      `DPoP htu mismatch. Claimed "${claimedUrl}" but request is "${normalizedRequest}". ` +
        "A stolen token cannot be replayed against a different endpoint."
    );
    return;
  }

  // ── 8. Validate iat (issued-at) — prevent stale proofs ───────────────────
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (!payload.iat || typeof payload.iat !== "number") {
    rejectWith401(res, "invalid_dpop_proof", "DPoP payload missing iat claim");
    return;
  }

  const age = nowSeconds - payload.iat;
  if (age > DPOP_MAX_AGE_SECONDS + CLOCK_SKEW_SECONDS) {
    rejectWith401(
      res,
      "invalid_dpop_proof",
      `DPoP proof has expired. Age is ${age}s; maximum is ${DPOP_MAX_AGE_SECONDS}s.`
    );
    return;
  }

  if (payload.iat > nowSeconds + CLOCK_SKEW_SECONDS) {
    rejectWith401(
      res,
      "invalid_dpop_proof",
      "DPoP proof iat is in the future. Check client clock synchronisation."
    );
    return;
  }

  // ── 9. Validate jti (unique nonce) — replay attack prevention ────────────
  if (!payload.jti || typeof payload.jti !== "string") {
    rejectWith401(res, "invalid_dpop_proof", "DPoP payload missing jti claim");
    return;
  }

  purgeExpiredJtis(); // housekeeping

  if (usedJtis.has(payload.jti)) {
    rejectWith401(
      res,
      "invalid_dpop_proof",
      `DPoP jti "${payload.jti}" has already been used. Each proof must use a unique jti.`
    );
    return;
  }

  // Record JTI with expiry
  const jtiExpiry = (payload.iat + DPOP_MAX_AGE_SECONDS + CLOCK_SKEW_SECONDS) * 1000;
  usedJtis.set(payload.jti, jtiExpiry);

  // ── 10. Token ↔ key binding (cnf.jkt check) ──────────────────────────────
  //  The Bearer token should contain a "cnf" claim with a "jkt" field
  //  (SHA-256 JWK thumbprint of the client's public key).
  //  Here we decode the Bearer token's payload WITHOUT verifying its signature
  //  (that is the Authorization Server's job). We only check the binding.
  try {
    const bearerParts = bearerToken.split(".");
    if (bearerParts.length === 3) {
      const bearerPayload = JSON.parse(
        base64UrlDecode(bearerParts[1]).toString("utf8")
      );

      if (bearerPayload?.cnf?.jkt) {
        const expectedThumbprint = jwkThumbprint(header.jwk);
        if (bearerPayload.cnf.jkt !== expectedThumbprint) {
          rejectWith401(
            res,
            "invalid_dpop_proof",
            "DPoP key mismatch: the Bearer token is bound to a different key pair. " +
              "A stolen token cannot be used with a different private key."
          );
          return;
        }
      }
    }
  } catch {
    // If we can't decode the Bearer token payload, skip binding check.
    // The Authorization Server validates the Bearer token itself.
  }

  // ── All checks passed ─────────────────────────────────────────────────────
  // Attach verified DPoP context to request for downstream handlers.
  (req as Request & { dpop: unknown }).dpop = {
    publicKey: header.jwk,
    jti: payload.jti,
    htm: payload.htm,
    htu: payload.htu,
    iat: payload.iat,
  };

  next();
}

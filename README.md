# DPoP Middleware — Fintech / Pakistani EMI APIs

RFC 9449 compliant **Demonstrating Proof of Possession** middleware for Express.js.

## Why DPoP?

A standard Bearer token is like a hotel key card left on a table — anyone who picks it up can use it. DPoP **binds** the token to the client's private key. Even if an attacker steals the token from your EMI's database, they cannot use it because they don't have the private key that signed it.

## What This Middleware Checks

| Check | What it prevents |
|---|---|
| Bearer token presence | Unauthenticated requests |
| DPoP header presence | Requests without proof-of-possession |
| JWT signature (via embedded JWK) | Tampered or forged proofs |
| `htm` claim matches request method | Method confusion attacks |
| `htu` claim matches request URL | Stolen tokens replayed to a different endpoint |
| `iat` within 5 minutes | Stale proof reuse |
| `jti` uniqueness | Replay attacks (same proof sent twice) |
| `cnf.jkt` thumbprint | Token bound to a different key pair |

## Quick Start

```bash
npm install
npm run dev       # start API on :3000
npm run test      # run DPoP proof generation + attack simulations
```

## Integration

```typescript
import { dpopMiddleware } from "./dpop.middleware";

// Apply to all protected routes
app.use("/api", dpopMiddleware);
```

## Client-Side Usage

Every request to `/api/*` must include:

```http
Authorization: Bearer <access_token>
DPoP: <dpop_proof_jwt>
```

The DPoP proof JWT (signed with the client's private key) must contain:

```json
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": { /* client public key */ }
}
{
  "jti": "<unique-uuid>",
  "htm": "POST",
  "htu": "https://api.youremi.pk/api/transfers",
  "iat": 1700000000
}
```

## Production Hardening

### Replace in-memory JTI store with Redis

```typescript
import { createClient } from "redis";
const redis = createClient({ url: process.env.REDIS_URL });

// In middleware, replace usedJtis.has / usedJtis.set with:
const exists = await redis.exists(`dpop:jti:${payload.jti}`);
if (exists) { /* reject */ }
await redis.set(`dpop:jti:${payload.jti}`, "1", { EX: DPOP_MAX_AGE_SECONDS });
```

### SBP / EMI Compliance Notes (Pakistan)

- SBP's EMI Regulations 2019 require strong authentication for payment APIs. DPoP satisfies the "strong customer authentication" binding requirement.
- Enforce HTTPS — DPoP does not protect against MITM on plain HTTP.
- Log all 401 rejections (jti, htu, reason) to your SIEM for fraud monitoring.
- Rotate client key pairs periodically and revoke compromised keys via your Authorization Server.
- Consider adding `ath` (access token hash) claim for additional binding strength (RFC 9449 §4.2).

## Supported Algorithms

| Algorithm | Type | Notes |
|---|---|---|
| ES256 | ECDSA P-256 | Recommended — small key, fast verify |
| ES384 | ECDSA P-384 | Higher security margin |
| ES512 | ECDSA P-521 | Maximum EC security |
| RS256 | RSA-SHA256 | Larger keys, wider compatibility |
| RS384 | RSA-SHA384 | — |
| RS512 | RSA-SHA512 | — |

/**
 * test-dpop.ts — generates a real DPoP proof and fires it at the local API.
 * Run after starting app.ts:
 *   npx ts-node test-dpop.ts
 *
 * Requires:  npm install node-fetch@2 jose
 */

import { generateKeyPair, exportJWK, SignJWT } from "jose";

const API_BASE = "http://localhost:3000";
const ACCOUNT_ID = "PK-EMI-00123";

async function buildDPoPProof(
  privateKey: CryptoKey,
  publicKeyJwk: Record<string, unknown>,
  method: string,
  url: string
): Promise<string> {
  const jti = crypto.randomUUID();
  return new SignJWT({ htm: method, htu: url, jti, iat: Math.floor(Date.now() / 1000) })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: publicKeyJwk })
    .sign(privateKey);
}

async function main() {
  console.log("Generating EC P-256 key pair …");
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const publicKeyJwk = await exportJWK(publicKey);

  const method = "GET";
  const url = `${API_BASE}/api/accounts/${ACCOUNT_ID}`;

  console.log(`\nBuilding DPoP proof for ${method} ${url}`);
  const dpopProof = await buildDPoPProof(privateKey, publicKeyJwk, method, url);

  // Fake Bearer token — in production this comes from your Authorization Server
  // and MUST contain cnf.jkt bound to the same key pair.
  const fakeBearerToken = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyXzEyMyJ9.fake";

  console.log("\nSending request …");
  const { default: fetch } = await import("node-fetch");
  const response = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${fakeBearerToken}`,
      DPoP: dpopProof,
    },
  });

  const body = await response.json();
  console.log(`\nStatus: ${response.status}`);
  console.log("Response:", JSON.stringify(body, null, 2));

  // ── Test: replay the same proof → should get 401 ──────────────────────────
  console.log("\nReplaying the same DPoP proof (should get 401) …");
  const replay = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${fakeBearerToken}`,
      DPoP: dpopProof, // same proof, same jti
    },
  });
  const replayBody = await replay.json();
  console.log(`Status: ${replay.status}`);
  console.log("Response:", JSON.stringify(replayBody, null, 2));

  // ── Test: wrong URL in htu → should get 401 ───────────────────────────────
  const wrongProof = await buildDPoPProof(
    privateKey,
    publicKeyJwk,
    method,
    `${API_BASE}/api/accounts/DIFFERENT-ACCOUNT` // attacker replays to different resource
  );

  console.log("\nUsing proof with wrong htu (should get 401) …");
  const wrongUrl = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${fakeBearerToken}`,
      DPoP: wrongProof,
    },
  });
  const wrongBody = await wrongUrl.json();
  console.log(`Status: ${wrongUrl.status}`);
  console.log("Response:", JSON.stringify(wrongBody, null, 2));
}

main().catch(console.error);

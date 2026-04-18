/**
 * Express app — wires DPoP middleware onto protected routes.
 * Run: npx ts-node app.ts
 */

import express, { Request, Response } from "express";
import { dpopMiddleware } from "./dpop.middleware";

const app = express();
app.use(express.json());

// ─── Public routes (no DPoP) ─────────────────────────────────────────────────
app.get("/health", (_req: Request, res: Response) => {
  res.json({ status: "ok" });
});

// ─── Protected routes (DPoP required) ────────────────────────────────────────
app.use("/api", dpopMiddleware);

app.get("/api/accounts/:id", (req: Request, res: Response) => {
  res.json({
    accountId: req.params.id,
    balance: "PKR 50,000",
    dpopBound: true,
    message: "This response is only reachable with a valid DPoP proof.",
  });
});

app.post("/api/transfers", (req: Request, res: Response) => {
  res.json({
    transferId: "txn_" + Date.now(),
    status: "queued",
    dpopBound: true,
    body: req.body,
  });
});

app.listen(3000, () => {
  console.log("EMI API listening on http://localhost:3000");
  console.log("All /api/* routes are DPoP-protected.");
});

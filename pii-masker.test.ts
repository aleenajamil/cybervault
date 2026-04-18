/**
 * pii-masker.test.ts — test suite (Jest or ts-node-friendly)
 * Run:  npx jest pii-masker.test.ts
 */

import {
  maskCnic,
  maskAccountNumber,
  maskString,
  maskJson,
  maskJsonString,
  detectPii,
} from "./pii-masker";

// ─── CNIC masking ─────────────────────────────────────────────────────────────
describe("maskCnic", () => {
  it("masks the 7-digit middle segment", () => {
    expect(maskCnic("42101-1234567-0")).toBe("42101-*******-0");
  });

  it("preserves prefix and suffix", () => {
    expect(maskCnic("13501-9876543-1")).toBe("13501-*******-1");
  });

  it("masks multiple CNICs in one string", () => {
    const input = "From 42101-1111111-9 to 13501-2222222-5";
    expect(maskCnic(input)).toBe("From 42101-*******-9 to 13501-*******-5");
  });

  it("does not mask strings that look like CNICs but have wrong format", () => {
    expect(maskCnic("4210-1234567-0")).toBe("4210-1234567-0");   // prefix too short
    expect(maskCnic("42101-123456-0")).toBe("42101-123456-0");   // middle too short
    expect(maskCnic("42101-12345678-0")).toBe("42101-12345678-0"); // middle too long
  });

  it("handles CNIC with no surrounding text", () => {
    expect(maskCnic("42101-0000000-0")).toBe("42101-*******-0");
  });
});

// ─── Account number masking ───────────────────────────────────────────────────
describe("maskAccountNumber", () => {
  it("masks 14-digit account (keeps first 4 and last 2)", () => {
    expect(maskAccountNumber("00210012345644")).toBe("0021********44");
  });

  it("masks 15-digit account", () => {
    expect(maskAccountNumber("002100123456789")).toBe("0021*********89");
  });

  it("masks 16-digit account", () => {
    expect(maskAccountNumber("1234567890123456")).toBe("1234**********56");
  });

  it("does not mask 13-digit number (too short)", () => {
    expect(maskAccountNumber("1234567890123")).toBe("1234567890123");
  });

  it("does not mask 17-digit number (too long)", () => {
    expect(maskAccountNumber("12345678901234567")).toBe("12345678901234567");
  });

  it("masks account number embedded in a sentence", () => {
    const input = "Account 00210012345644 was debited.";
    expect(maskAccountNumber(input)).toBe("Account 0021********44 was debited.");
  });
});

// ─── Combined maskString ──────────────────────────────────────────────────────
describe("maskString", () => {
  it("masks both CNIC and account in the same string", () => {
    const input = "CNIC 42101-1234567-0 account 00210098765432 processed";
    expect(maskString(input)).toBe(
      "CNIC 42101-*******-0 account 0021********32 processed"
    );
  });

  it("does not double-mask CNIC digits as an account number", () => {
    // A CNIC's digits without hyphens could be 13 chars — below minimum 14
    const input = "42101-1234567-0";
    const result = maskString(input);
    expect(result).toBe("42101-*******-0");
    expect(result).not.toContain("****-");
  });
});

// ─── Deep JSON masking ────────────────────────────────────────────────────────
describe("maskJson", () => {
  it("masks string values in a flat object", () => {
    const input = { cnic: "42101-1234567-0", name: "Ali Hassan" };
    expect(maskJson(input)).toEqual({ cnic: "42101-*******-0", name: "Ali Hassan" });
  });

  it("recursively masks nested objects", () => {
    const input = {
      customer: {
        id: "42101-9999999-1",
        account: { number: "00210012345644" },
      },
    };
    expect(maskJson(input)).toEqual({
      customer: {
        id: "42101-*******-1",
        account: { number: "0021********44" },
      },
    });
  });

  it("masks values inside arrays", () => {
    const input = { accounts: ["00210012345644", "00210087654322"] };
    expect(maskJson(input)).toEqual({
      accounts: ["0021********44", "0021********22"],
    });
  });

  it("leaves non-PII values unchanged", () => {
    const input = { amount: 50000, currency: "PKR", status: true, meta: null };
    expect(maskJson(input)).toEqual(input);
  });

  it("masks PII mixed into free-text strings", () => {
    const input = {
      notes: "Customer CNIC is 42101-1234567-0 and account is 00210012345644.",
    };
    const result = maskJson(input) as { notes: string };
    expect(result.notes).toContain("42101-*******-0");
    expect(result.notes).toContain("0021********44");
  });
});

// ─── maskJsonString round-trip ────────────────────────────────────────────────
describe("maskJsonString", () => {
  it("parses, masks, and re-serialises", () => {
    const raw = JSON.stringify({ cnic: "42101-1234567-0" });
    const result = JSON.parse(maskJsonString(raw));
    expect(result.cnic).toBe("42101-*******-0");
  });

  it("throws on invalid JSON", () => {
    expect(() => maskJsonString("{bad json}")).toThrow();
  });
});

// ─── PII detection audit ──────────────────────────────────────────────────────
describe("detectPii", () => {
  it("reports CNIC with correct path and masked value", () => {
    const input = { customer: { cnic: "42101-1234567-0" } };
    const report = detectPii(input);
    expect(report).toHaveLength(1);
    expect(report[0].type).toBe("CNIC");
    expect(report[0].path).toBe("$.customer.cnic");
    expect(report[0].original).toBe("42101-1234567-0");
    expect(report[0].masked).toBe("42101-*******-0");
  });

  it("reports bank account with correct path", () => {
    const input = { accounts: [{ number: "00210012345644" }] };
    const report = detectPii(input);
    expect(report).toHaveLength(1);
    expect(report[0].type).toBe("BANK_ACCOUNT");
    expect(report[0].path).toBe("$.accounts[0].number");
  });

  it("returns empty array when no PII is found", () => {
    expect(detectPii({ name: "Ali", amount: 100 })).toHaveLength(0);
  });

  it("reports multiple PII items across a complex payload", () => {
    const input = {
      a: { cnic: "42101-1111111-1" },
      b: [{ acc: "00210012345644" }, { acc: "1234567890123456" }],
    };
    const report = detectPii(input);
    expect(report).toHaveLength(3);
    const types = report.map((r) => r.type);
    expect(types.filter((t) => t === "CNIC")).toHaveLength(1);
    expect(types.filter((t) => t === "BANK_ACCOUNT")).toHaveLength(2);
  });
});

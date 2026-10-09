import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";

// Use the existing compiler to test pure presentation logic without extra packages or network calls.
const source = await readFile(new URL("../src/lib/bank-assistant.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
});
const { bankReceipt, bankRunStats, bankStatusLabel, eventEstimate } = await import(
  `data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`
);

test("model claims and proposed actions are never presented as execution receipts", () => {
  for (const kind of ["model", "proposal", "approval", "warning"]) {
    assert.equal(bankReceipt({ kind, label: "get_balance", result: { balance_eur: 48250.75 } }), null);
    assert.equal(bankReceipt({ kind, label: "initiate_transfer", result: { status: "accepted", payment_id: "PAY-1", amount: 5000 } }), null);
  }
});

test("balance highlights use the verified result, including a zero balance", () => {
  assert.deepEqual(bankReceipt({ kind: "tool", label: "get_balance", result: { balance_eur: 0, iban: "DEMO-IBAN" } }),
    { title: "Account balance", value: 0, money: true, detail: "DEMO-IBAN" });
  for (const balance_eur of ["5000", NaN, Infinity, null]) {
    assert.equal(bankReceipt({ kind: "tool", label: "get_balance", result: { balance_eur } }), null);
  }
});

test("payment highlights require an accepted, identified, positive-amount receipt", () => {
  const event = { kind: "tool", label: "initiate_transfer", result: { status: "accepted", payment_id: "PAY-1", amount: 5000 } };
  assert.equal(bankReceipt(event)?.value, 5000);
  for (const result of [{ ...event.result, status: "pending" }, { status: "accepted", amount: 5000 }, { ...event.result, amount: 0 }]) {
    assert.equal(bankReceipt({ ...event, result }), null);
  }
});

test("KYC and address highlights require their actual success fields", () => {
  assert.equal(bankReceipt({ kind: "tool", label: "verify_document", result: { verified: false } }), null);
  assert.equal(bankReceipt({ kind: "tool", label: "verify_document", result: { verified: "true" } }), null);
  assert.equal(bankReceipt({ kind: "tool", label: "verify_document", result: { verified: true, document_id: "D-77" } })?.detail, "D-77");
  assert.equal(bankReceipt({ kind: "tool", label: "update_address", result: { status: "proposed", address: "Demo Street" } }), null);
  assert.equal(bankReceipt({ kind: "tool", label: "update_address", result: { status: "updated", address: "Demo Street" } })?.value, "Demo Street");
});

test("malformed or unknown tool results cannot create a highlight", () => {
  for (const result of [null, undefined, [], "verified", 42]) {
    assert.equal(bankReceipt({ kind: "tool", label: "get_balance", result }), null);
  }
  assert.equal(bankReceipt({ kind: "tool", label: "unknown", result: { balance_eur: 5000 } }), null);
});

test("missing and invalid cost metadata stays unknown; valid zero remains zero", () => {
  for (const value of [undefined, "", "  ", "unknown", "NaN", "Infinity", "-1"]) {
    assert.equal(eventEstimate({ kind: "model", label: "Azure", metadata: { "x-aegis-llm-estimated-cost-eur": value } }), null);
  }
  assert.equal(eventEstimate({ kind: "model", label: "Azure", metadata: { "x-aegis-llm-estimated-cost-eur": "0" } }), 0);
});

test("run totals count only model estimates and actual tool results", () => {
  const model = cost => ({ kind: "model", label: "Azure", metadata: { "x-aegis-llm-estimated-cost-eur": cost } });
  assert.deepEqual(bankRunStats([
    model("0.001"), model(undefined),
    { kind: "proposal", label: "get_balance", result: { balance_eur: 100 } },
    { kind: "tool", label: "get_balance", result: { balance_eur: 100 } },
    { kind: "tool", label: "get_profile" },
    { kind: "tool", label: "get_profile", result: null },
  ]), { modelCalls: 2, receipts: 1, estimatedCost: 0.001, partialEstimate: true });
  assert.deepEqual(bankRunStats([]), { modelCalls: 0, receipts: 0, estimatedCost: null, partialEstimate: false });
  assert.equal(bankRunStats([model("0.001"), model("0.002")]).estimatedCost, 0.003);
});

test("waiting and stopped states have readable, non-success labels", () => {
  assert.equal(bankStatusLabel("confirmation_required"), "Your confirmation needed");
  assert.equal(bankStatusLabel("approval_required"), "Risk approval required");
  assert.equal(bankStatusLabel("interrupted"), "Interrupted");
  assert.equal(bankStatusLabel("future_state"), "future state");
});

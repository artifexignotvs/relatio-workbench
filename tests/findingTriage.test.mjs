import assert from "node:assert/strict";
import test from "node:test";
import { createDemoCase } from "../src/features/security-workspace/fixtures.ts";
import { buildReportMarkdown, parseCase, serializeCase, updateFindingReview } from "../src/features/security-workspace/model.ts";

test("triage changes only the selected finding and leaves its source evidence untouched", async () => {
  const source = await createDemoCase();
  const original = structuredClone(source);
  const id = source.findings[0].id;
  const changed = updateFindingReview(source, id, "acknowledged", "Synthetic decision: inspect the supplied trace.");
  assert.deepEqual(source, original);
  assert.equal(changed.findings[0].status, "acknowledged");
  assert.equal(changed.findings[0].analystNote, "Synthetic decision: inspect the supplied trace.");
  assert.deepEqual(changed.findings.slice(1), source.findings.slice(1));
  assert.deepEqual(changed.evidence, source.evidence);
  for (const name of ["id", "title", "source", "detail", "recommendation", "severity", "evidenceIds"])
    assert.deepEqual(changed.findings[0][name], source.findings[0][name]);
  assert.deepEqual(await parseCase(serializeCase(changed)), changed);
});

test("invalid status, absent finding, oversized note and broken Unicode cannot mutate a saved case", async () => {
  const source = await createDemoCase();
  const original = serializeCase(source);
  for (const [id, status, note] of [
    ["missing-finding", "resolved", "note"],
    [source.findings[0].id, "closed", "note"],
    [source.findings[0].id, "resolved", "x".repeat(4001)],
    [source.findings[0].id, "resolved", "broken\ud800"],
  ]) {
    assert.throws(() => updateFindingReview(source, id, status, note));
    assert.equal(serializeCase(source), original);
  }
});

test("older cases without triage fields default to open without inventing a review", async () => {
  const source = await createDemoCase();
  for (const finding of source.findings) {
    delete finding.status;
    delete finding.analystNote;
  }
  const restored = await parseCase(serializeCase(source));
  assert.equal(restored.findings[0].status, undefined);
  assert.equal(restored.findings[0].analystNote, undefined);
  assert.match(buildReportMarkdown(restored), /Review status: open/);
  assert.match(buildReportMarkdown(restored), /No finding note recorded/);
});

test("analyst notes remain literal text in report exports", async () => {
  const source = await createDemoCase();
  const note = '<script>alert(1)</script>\n[link](javascript:alert(1))\n# invented heading';
  const changed = updateFindingReview(source, source.findings[0].id, "resolved", note);
  const report = buildReportMarkdown(changed);
  assert.equal(report.includes("<script>"), false);
  assert.equal(report.includes("\n# invented heading"), false);
  assert.equal(report.includes("[link](javascript:"), false);
  assert.match(report, /Review status: resolved/);
  assert.match(report, /not independent verification of remediation/);
  assert.equal(changed.findings[0].analystNote, note);
});

test("a review can return to open and deliberately clear its note", async () => {
  const source = await createDemoCase();
  const id = source.findings[0].id;
  const resolved = updateFindingReview(source, id, "resolved", "Synthetic resolution.");
  const reopened = updateFindingReview(resolved, id, "open", "");
  assert.equal(reopened.findings[0].status, "open");
  assert.equal(reopened.findings[0].analystNote, "");
  assert.equal(resolved.findings[0].status, "resolved");
});

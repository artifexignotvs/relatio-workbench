import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createDemoCase } from "../src/features/security-workspace/fixtures.ts";
import {
  buildReportMarkdown,
  importReport,
  parseAccessSnapshot,
  parseCase,
  serializeCase,
} from "../src/features/security-workspace/model.ts";

test("the synthetic case joins tool, action and access evidence and survives verified export", async () => {
  const item = await createDemoCase();
  assert.match(item.scope, /^Synthetic example/);
  assert.equal(item.evidence.length, 4);
  for (const evidence of item.evidence) {
    assert.equal(
      evidence.sha256,
      createHash("sha256").update(evidence.content, "utf8").digest("hex"),
    );
    assert.equal(evidence.bytes, Buffer.byteLength(evidence.content, "utf8"));
  }
  const sources = new Set(item.findings.map((finding) => finding.source));
  assert.ok(sources.has("action-review"));
  assert.ok(sources.has("access-diff"));
  assert.ok(
    item.findings.some((finding) => finding.title.includes("cookie")) ||
      item.findings.some((finding) => finding.source.includes("vallum")),
  );
  const evidenceIds = new Set(item.evidence.map((evidence) => evidence.id));
  assert.ok(
    item.findings.every(
      (finding) =>
        finding.evidenceIds.length > 0 &&
        finding.evidenceIds.every((id) => evidenceIds.has(id)),
    ),
  );
  assert.deepEqual(await parseCase(serializeCase(item)), item);
  const report = buildReportMarkdown(item);
  assert.match(report, /Evidence inventory/);
  assert.match(report, /does not execute actions/);
  assert.ok(!report.includes('"allowShell"'));
});

test("the shipped inputs use the same parsers as user imports", async () => {
  for (const name of ["access-before.json", "access-after.json"]) {
    const text = await readFile(
      new URL(`../examples/${name}`, import.meta.url),
      "utf8",
    );
    assert.equal(parseAccessSnapshot(text).length, 3);
  }
  const http = await readFile(
    new URL("../examples/http-review.json", import.meta.url),
    "utf8",
  );
  assert.equal(
    importReport(http, "http-review.json", "fixture-http").length,
    10,
  );
});

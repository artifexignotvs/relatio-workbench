import assert from "node:assert/strict";
import { File } from "node:buffer";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  createCase,
  importReport,
  parseCase,
  serializeCase,
} from "../src/features/security-workspace/model.ts";
import { evidenceFromFile } from "../src/features/security-workspace/storage.ts";

const examples = [
  { file: "limen-review.json", source: "limen-mcp", findings: 5 },
  { file: "http-review.json", source: "vallum-http", findings: 10 },
  { file: "lucerna-inventory.json", source: "lucerna-osint", findings: 4 },
  { file: "vestigium-verify.json", source: "vestigium-integrity", findings: 3 },
];

async function readExample(name) {
  return readFile(new URL(`../examples/${name}`, import.meta.url), "utf8");
}

for (const example of examples) {
  test(`the shipped ${example.source} report imports with its source and evidence reference`, async () => {
    const text = await readExample(example.file);
    const evidenceId = `fixture-${example.source}`;
    const findings = importReport(text, example.file, evidenceId);
    assert.equal(findings.length, example.findings);
    assert.ok(findings.every((item) => item.source === example.source));
    assert.ok(
      findings.every(
        (item) =>
          item.evidenceIds.length === 1 && item.evidenceIds[0] === evidenceId,
      ),
    );
    assert.ok(
      findings.every(
        (item) => item.title && item.detail && item.recommendation,
      ),
    );
    assert.equal(
      new Set(findings.map((item) => item.id)).size,
      findings.length,
    );
  });
}

test("the real integrity comparison retains added, missing and changed entries separately", async () => {
  const findings = importReport(
    await readExample("vestigium-verify.json"),
    "vestigium-verify.json",
    "integrity-source",
  );
  assert.equal(
    findings.find((item) => item.title === "Entry added").detail,
    "added.txt",
  );
  assert.equal(
    findings.find((item) => item.title === "Entry missing").detail,
    "obsolete.txt",
  );
  assert.match(
    findings.find((item) => item.title === "Entry changed").detail,
    /^record\.txt: sha256, size$/,
  );
});

test("the real configuration report preserves critical source severity in its observations", async () => {
  const findings = importReport(
    await readExample("limen-review.json"),
    "limen-review.json",
    "configuration-source",
  );
  for (const rule of ["LM040", "LM045"]) {
    const finding = findings.find((item) => item.title === rule);
    assert.equal(finding.severity, "high");
    assert.match(finding.detail, /Source severity: critical/);
  }
});

test("the saved-page fixture remains an inventory with an explicit unverified source boundary", async () => {
  const findings = importReport(
    await readExample("lucerna-inventory.json"),
    "lucerna-inventory.json",
    "page-source",
  );
  assert.ok(findings.every((item) => item.severity === "info"));
  assert.equal(
    findings.filter((item) => item.title === "Referenced host").length,
    3,
  );
  assert.match(
    findings.find((item) => item.title === "Saved-page inventory scope").detail,
    /not independently verified/,
  );
});

test("all four shipped report files survive a combined case export with exact evidence content", async () => {
  const item = createCase(
    "Synthetic tool interoperability",
    "Four offline fixture reports only.",
  );
  for (const example of examples) {
    const text = await readExample(example.file);
    const evidence = await evidenceFromFile(new File([text], example.file));
    item.evidence.push(evidence);
    item.findings.push(...importReport(text, example.file, evidence.id));
  }
  const restored = await parseCase(serializeCase(item));
  assert.deepEqual(restored, item);
  assert.equal(restored.evidence.length, 4);
  assert.equal(restored.findings.length, 22);
});

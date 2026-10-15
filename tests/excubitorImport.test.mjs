import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { importReport, createCase, parseCase, serializeCase, buildReportMarkdown, updateFindingReview, WORKSPACE_LIMITS } from "../src/features/security-workspace/model.ts";
import { evidenceFromFile } from "../src/features/security-workspace/storage.ts";
const text = await readFile(new URL("../examples/excubitor-alerts.json", import.meta.url), "utf8");
const stream = await readFile(new URL("../examples/excubitor-demo.jsonl", import.meta.url), "utf8");
const wrapper = JSON.parse(text);
const imported = (value) => importReport(JSON.stringify(value), "alerts.json", "evidence-1");
const alert = () => structuredClone(wrapper.alerts.find(a => a.rule === "auth_success_after_fail"));

test("actual emitted JSON and JSONL retain all nine rules plus collection scope", () => {
  for (const findings of [imported(wrapper), importReport(stream, "demo.jsonl", "evidence-1")]) {
    assert.equal(findings.length, 10);
    assert.ok(findings.every(f => f.source === "excubitor" && f.evidenceIds[0] === "evidence-1"));
    const success = findings.find(f => f.detail.includes("auth_success_after_fail"));
    assert.match(success.detail, /operator/);
    assert.match(success.detail, /Observations: 8/);
    assert.match(success.detail, /window_seconds.*300/);
    assert.match(findings.find(f => f.detail.includes("upstream_alert")).detail, /not independent confirmation/);
  }
});

test("source critical severity and acknowledgement remain explicit without implying resolution", () => {
  const item = alert(); item.severity = "critical"; item.acknowledged = true;
  const finding = imported({ schema: wrapper.schema, alerts: [item] })[0];
  assert.equal(finding.severity, "high");
  assert.equal(finding.status, "acknowledged");
  assert.match(finding.detail, /Source severity: critical/);
  assert.match(finding.detail, /not proof of compromise/);
});

test("empty exports and partial streams report their limits rather than clean security", () => {
  const empty = imported({ schema: wrapper.schema, alerts: [] });
  assert.equal(empty.length, 1);
  assert.match(empty[0].detail, /does not establish a clean network/);
  const partial = importReport(JSON.stringify(alert()), "partial.ndjson", "evidence-1");
  assert.match(partial.at(-1).detail, /partial or live stream/);
  assert.match(partial.at(-1).detail, /not a clean security assessment/);
});

test("discarded observations, parser errors, cancellation and partial capture remain high review findings", () => {
  const lines = stream.trim().split("\n").map(JSON.parse);
  for (const mutate of [s => s.input_errors++, s => s.skipped_records++, s => s.replay_cancelled = true, s => { s.engine.late_events++; s.engine.received_events++; }, s => s.engine.keys_evicted++, s => s.engine.events_evicted++, s => { s.engine.alerts++; s.retained_alerts++; }]) {
    const values = structuredClone(lines); mutate(values.at(-1));
    const findings = importReport(values.map(JSON.stringify).join("\n"), "partial.jsonl", "evidence-1");
    assert.equal(findings.at(-1).severity, "high");
    assert.match(findings.at(-1).detail, /require review/);
  }
});

test("unknown schemas, duplicate IDs, inconsistent windows and unexpected alert fields fail atomically", () => {
  for (const mutate of [w => w.schema = "excubitor.alerts.v2", w => w.alerts.push(structuredClone(w.alerts[0])), w => w.alerts[0].evidence.window_end++, w => w.alerts[0].count = -1, w => w.alerts[0].ts = 1e99, w => w.alerts[0].extra = true, w => w.alerts[0].evidence.nested = { unbounded: true }, w => w.alerts[0].acknowledged = "false"]) {
    const value = structuredClone(wrapper); mutate(value); assert.throws(() => imported(value));
  }
  assert.throws(() => importReport(stream + '{"unrecognized":true}\n', "bad.jsonl", "evidence-1"));
  assert.throws(() => importReport('{"id":"one","id":"two"}', "bad.jsonl", "evidence-1"));
  assert.throws(() => importReport("x".repeat(WORKSPACE_LIMITS.reportBytes + 1), "large.jsonl", "evidence-1"), /size/);
});

test("the full retained-alert boundary keeps 1,000 alerts and scope without silently dropping records", () => {
  const alerts = Array.from({ length: 1000 }, (_, i) => ({ ...alert(), id: `alert-${i}` }));
  const findings = imported({ schema: wrapper.schema, alerts });
  assert.equal(findings.length, 1000);
  assert.match(findings[0].detail, /Collection scope:/);
  assert.match(findings.at(-1).detail, /alert-999/);
  assert.throws(() => imported({ schema: wrapper.schema, alerts: [...alerts, { ...alert(), id: "too-many" }] }));
});

test("finding triage survives plaintext and report export while legacy fields remain absent", async () => {
  let item = createCase("Synthetic investigation", "Synthetic example: exact import");
  const evidence = await evidenceFromFile(new File([text], "alerts.json"));
  item.evidence = [evidence]; item.findings = importReport(text, evidence.name, evidence.id);
  const first = item.findings[0];
  item = updateFindingReview(item, first.id, "resolved", "Expected scan by the authorized scanner. <img>\n# forged");
  assert.deepEqual(await parseCase(serializeCase(item)), item);
  assert.equal(item.findings[0].status, "resolved");
  assert.match(buildReportMarkdown(item), /Review status: resolved/);
  assert.equal(buildReportMarkdown(item).includes("<img>"), false);
  assert.match(buildReportMarkdown(item), /not independent verification of remediation/);
  assert.throws(() => updateFindingReview(item, "missing", "open", ""), /no longer exists/);
  assert.throws(() => updateFindingReview(item, first.id, "approved", ""));
  assert.throws(() => updateFindingReview(item, first.id, "open", "x".repeat(4001)));
  const legacy = structuredClone(item); delete legacy.findings[0].status; delete legacy.findings[0].analystNote;
  assert.deepEqual(await parseCase(serializeCase(legacy)), legacy);
});


test("contradictory collection counters and advertised retention are rejected", () => {
  for (const mutate of [s => s.engine.accepted_events++, s => s.retained_alerts--]) {
    const values = stream.trim().split("\n").map(JSON.parse); mutate(values.at(-1));
    assert.throws(() => importReport(values.map(JSON.stringify).join("\n"), "bad.jsonl", "evidence-1"));
  }
});

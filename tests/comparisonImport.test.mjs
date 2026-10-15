import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { importReport } from "../src/features/security-workspace/model.ts";
const fixtures = [
  ["limen-comparison.json", "limen-mcp"],
  ["http-comparison.json", "vallum-http"],
];
const loaded = await Promise.all(fixtures.map(async ([name, tool]) => ({ name, tool, source: JSON.parse(await readFile(new URL(`../examples/${name}`, import.meta.url), "utf8")) })));
const imported = value => importReport(JSON.stringify(value), "comparison.json", "comparison-evidence");

for (const { name, tool, source } of loaded) {
  test(`${name}: actual CLI comparison preserves every aggregate count and severity transition`, () => {
    const findings = imported(source);
    const groups = ["added", "resolved", "unchanged", "severity_changed"];
    assert.equal(findings.length, source.findings.length + 1 + groups.reduce((sum, key) => sum + source.comparison[key].length, 0));
    assert.ok(findings.every(f => f.source === tool && f.evidenceIds[0] === "comparison-evidence"));
    const overview = findings.find(f => f.title === "Supplied aggregate baseline comparison");
    for (const key of groups) assert.ok(overview.detail.includes(`${source.comparison.summary[key]} ${key}`));
    assert.match(overview.detail, /same-count replacement may be invisible/);
    for (const category of groups) for (const entry of source.comparison[category]) {
      const finding = findings.find(f => f.title === `Baseline ${category}: ${entry.rule_id}` && f.detail.includes(`Scope: ${entry.scope}.`) && f.detail.includes(`Observations: ${entry.count}.`));
      assert.ok(finding);
      assert.match(finding.detail, /not independent verification/);
      if (category === "severity_changed") assert.ok(finding.detail.includes(`${entry.from} -> ${entry.to}`));
      else assert.ok(finding.detail.includes(`Source severity: ${entry.severity}.`));
      if (category === "resolved" || category === "unchanged") assert.equal(finding.severity, "info");
      assert.equal(finding.status, undefined);
    }
  });

  test(`${name}: malformed, inconsistent and extra comparison fields fail atomically`, () => {
    const mutations = [
      value => value.comparison.extra = true,
      value => value.comparison.scope = "individual-identity",
      value => value.comparison.summary.added++,
      value => value.comparison.added[0].count = 0,
      value => value.comparison.added[0].count = true,
      value => value.comparison.added[0].count = 100001,
      value => value.comparison.added[0].scope = "/private/path",
      value => value.comparison.added[0].rule_id = "unrecognized.rule",
      value => value.comparison.added[0].severity = "unknown",
      value => value.comparison.added[0].extra = "ignored",
      value => value.comparison.added.push(structuredClone(value.comparison.added[0])),
      value => value.comparison.severity_changed[0].to = value.comparison.severity_changed[0].from,
      value => value.comparison.unchanged = {},
      value => value.comparison.summary.extra = 1,
      value => { value.comparison.added[0].count++; value.comparison.summary.added++; },
    ];
    for (const mutate of mutations) {
      const modified = structuredClone(source); mutate(modified);
      assert.throws(() => imported(modified), /Unsupported|inconsistent/);
    }
  });

  test(`${name}: current counts cannot be relabeled as new and resolved to manufacture a regression`, () => {
    const modified = structuredClone(source);
    const entry = modified.comparison.unchanged.shift();
    modified.comparison.summary.unchanged -= entry.count;
    modified.comparison.added.push(structuredClone(entry));
    modified.comparison.resolved.push(structuredClone(entry));
    modified.comparison.summary.added += entry.count;
    modified.comparison.summary.resolved += entry.count;
    assert.throws(() => imported(modified), /Unsupported|inconsistent/);
  });

  test(`${name}: input order is irrelevant but counts and severity transitions remain exact`, () => {
    const modified = structuredClone(source);
    for (const key of ["added", "resolved", "unchanged", "severity_changed"]) modified.comparison[key].reverse();
    modified.findings.reverse();
    const findings = imported(modified);
    assert.equal(findings.length, imported(source).length);
  });
}

test("standalone baselines and SARIF fail with an explicit format boundary", () => {
  assert.throws(() => imported({ schema_version: 1, comparison_scope: "aggregate-rule-scope", findings: [] }), /Baseline snapshots and SARIF/);
  assert.throws(() => imported({ version: "2.1.0", runs: [] }), /Baseline snapshots and SARIF/);
});

test("a comparison cannot make an incomplete Limen report look complete", () => {
  const modified = structuredClone(loaded[0].source);
  modified.errors.push("Synthetic input error"); modified.summary.errors++;
  assert.throws(() => imported(modified), /Unsupported|inconsistent/);
});

test("aggregate observation bounds apply to reconstructed previous counts", () => {
  const modified = structuredClone(loaded[1].source);
  modified.comparison.resolved[0].count = 100000;
  modified.comparison.summary.resolved = 100000;
  assert.throws(() => imported(modified), /Unsupported|inconsistent/);
});

test("too many comparison groups are rejected rather than truncated", () => {
  const seed = loaded[0].source;
  const rules = ["LM001", "LM002", "LM010", "LM011", "LM020", "LM030", "LM031", "LM040", "LM041", "LM042", "LM043", "LM044", "LM045", "LM046", "LM047", "LM048", "LM049", "LM090"];
  const entries = [];
  for (const root of ["mcpServers", "servers"]) for (const field of ["args", "args[*]", "url", "url.query", "env.entry[*]", "headers.entry[*]", "command", "transport"])
    for (const rule of rules) for (const severity of ["low", "medium", "high", "critical"])
      entries.push({ rule_id: rule, scope: `${root}.server[*].${field}`, severity, count: 1 });
  const value = {
    schema_version: 1, summary: { servers: 0, findings: 0, errors: 0 }, findings: [], errors: [],
    comparison: { scope: seed.comparison.scope, added: [], resolved: entries.slice(0, 1000), unchanged: [], severity_changed: [], summary: { added: 0, resolved: 1000, unchanged: 0, severity_changed: 0 } },
  };
  assert.throws(() => imported(value), /Unsupported|inconsistent/);
});

test("combined source findings and comparison observations honor the workspace limit", () => {
  const source = loaded[0].source;
  const template = source.findings[0];
  const many = {
    schema_version: 1, summary: { servers: 900, findings: 900, errors: 0 }, errors: [],
    findings: Array.from({ length: 900 }, (_, index) => ({ ...template, rule_id: "LM030", severity: "medium", location: `mcpServers.server[${index + 1}].args[0]` })),
    comparison: { scope: "aggregate-rule-scope", added: [], resolved: [], unchanged: [{ rule_id: "LM030", scope: "mcpServers.server[*].args[*]", severity: "medium", count: 900 }], severity_changed: [], summary: { added: 0, resolved: 0, unchanged: 900, severity_changed: 0 } },
  };
  const rules = ["LM001", "LM002", "LM010", "LM011", "LM020", "LM031", "LM040", "LM041", "LM042", "LM043", "LM044", "LM045", "LM046", "LM047", "LM048", "LM049", "LM090"];
  for (const field of ["args", "url", "env.entry[*]", "headers.entry[*]", "command", "transport"])
    for (const rule of rules) many.comparison.resolved.push({ rule_id: rule, scope: `servers.server[*].${field}`, severity: "low", count: 1 });
  many.comparison.summary.resolved = many.comparison.resolved.length;
  assert.throws(() => imported(many), /too many findings/);
});

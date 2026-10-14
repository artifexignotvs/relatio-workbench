import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  buildReportMarkdown,
  compareAccess,
  createCase,
  importReport,
  parseAccessSnapshot,
  parseActionPlan,
  parseCase,
  reviewAction,
  serializeCase,
  WORKSPACE_LIMITS,
} from "../src/features/security-workspace/model.ts";

const imported = (value) =>
  importReport(JSON.stringify(value), "report.json", "evidence-1");
const digest = (value) =>
  createHash("sha256").update(value, "utf8").digest("hex");
const copy = (value) => structuredClone(value);
const record = (principal, resource, permission) => ({
  principal,
  resource,
  permission,
});
const plan = () => ({
  command: "python inspect.py",
  readPaths: ["./input"],
  writePaths: [],
  networkHosts: [],
  allowShell: false,
  allowSubprocesses: false,
});
const limen = () => ({
  schema_version: 1,
  summary: { servers: 1, findings: 1, errors: 0 },
  findings: [
    {
      rule_id: "LM001",
      severity: "critical",
      location: "server[0]",
      message: "Credential exposure indicator",
      remediation: "Use a credential reference.",
    },
  ],
  errors: [],
});
const vallum = () => ({
  schema_version: 1,
  mode: "offline",
  target: "https://fixture.invalid/",
  status: 200,
  redirects: [],
  summary: { high: 0, warning: 1, info: 0 },
  findings: [
    {
      id: "headers.example",
      severity: "warning",
      message: "A protective header is missing.",
      recommendation: "Review the document policy.",
    },
  ],
});
const vestigium = () => ({
  command: "verify",
  status: "different",
  complete: true,
  issues: [],
  summary: { files: 2, directories: 1, symlinks: 0, bytes: 9 },
  changes: {
    added: ["new.txt"],
    missing: ["old.txt"],
    changed: [
      {
        path: "report.txt",
        reasons: ["sha256"],
        expected_type: "file",
        actual_type: "file",
      },
    ],
  },
});
const normalized = (url, host) => ({
  url,
  host,
  query_removed: false,
  fragment_removed: false,
  credentials_removed: false,
});
const lucerna = () => ({
  schema_version: 1,
  tool: "lucerna-osint",
  sha256: "a".repeat(64),
  bytes: 120,
  encoding: "utf-8",
  source: normalized("https://fixture.invalid/", "fixture.invalid"),
  effective_base: normalized("https://fixture.invalid/", "fixture.invalid"),
  title: "Synthetic document",
  metadata: [{ name: "description", content: "Fixture", line: 1 }],
  links: [
    {
      ...normalized("https://other.invalid/help", "other.invalid"),
      occurrences: 2,
      tags: ["a"],
      lines: [2, 4],
      relations: [],
      external_host: true,
    },
  ],
  hosts: [{ host: "other.invalid", occurrences: 2 }],
  skipped_references: 1,
  network_requests: 0,
});

async function evidenceCase(content = "Synthetic evidence\n") {
  const item = createCase("Fixture review", "Synthetic offline records only");
  item.evidence.push({
    id: "evidence-1",
    name: "fixture.txt",
    sha256: digest(content),
    bytes: Buffer.byteLength(content, "utf8"),
    mediaType: "text/plain",
    addedAt: item.createdAt,
    content,
    kind: "text",
  });
  item.findings.push({
    id: "finding-1",
    title: "Review observation",
    severity: "info",
    source: "analyst",
    detail: "An observation from the supplied evidence.",
    recommendation: "Check its collection context.",
    evidenceIds: ["evidence-1"],
  });
  return item;
}

test("all four supported report contracts preserve evidence links and source labels", () => {
  for (const [factory, source] of [
    [limen, "limen-mcp"],
    [vallum, "vallum-http"],
    [vestigium, "vestigium-integrity"],
    [lucerna, "lucerna-osint"],
  ]) {
    const findings = imported(factory());
    assert.ok(findings.length > 0);
    assert.equal(
      new Set(findings.map((item) => item.id)).size,
      findings.length,
    );
    assert.ok(
      findings.every(
        (item) =>
          item.source === source && item.evidenceIds[0] === "evidence-1",
      ),
    );
  }
});

test("Limen preserves original critical severity in detail and maps remediation", () => {
  const [item] = imported(limen());
  assert.equal(item.severity, "high");
  assert.match(item.detail, /Source severity: critical/);
  assert.equal(item.recommendation, "Use a credential reference.");
});

test("Limen errors remain explicit and cannot become an empty clean assessment", () => {
  const source = {
    schema_version: 1,
    summary: { servers: 0, findings: 0, errors: 1 },
    findings: [],
    errors: ["Input could not be inspected."],
  };
  assert.equal(imported(source)[0].severity, "high");
  source.summary.errors = 0;
  assert.throws(() => imported(source), /inconsistent/);
});

test("Vallum accepts offline and actual online modes, preserving warning severity", () => {
  for (const mode of ["offline", "online"]) {
    const source = vallum();
    source.mode = mode;
    source.redirects = [
      {
        from: "https://fixture.invalid/a",
        to: "https://fixture.invalid/b",
        status: 302,
      },
    ];
    assert.equal(imported(source)[0].severity, "medium");
  }
  const source = vallum();
  source.mode = "live";
  assert.throws(() => imported(source), /Unsupported/);
});

test("empty HTTP findings are informational and scoped, never a security verdict", () => {
  const source = vallum();
  source.findings = [];
  source.summary.warning = 0;
  const [item] = imported(source);
  assert.equal(item.severity, "info");
  assert.match(item.detail, /not a complete application security assessment/);
});

test("strict report schemas reject unknown versions, fields, ambiguous shapes and summary lies", () => {
  const unknownVersion = limen();
  unknownVersion.schema_version = 2;
  const unknownField = vallum();
  unknownField.unrecognized = true;
  const wrongCount = vallum();
  wrongCount.summary.high = 1;
  const ambiguous = { ...limen(), ...vallum() };
  for (const source of [
    unknownVersion,
    unknownField,
    wrongCount,
    ambiguous,
    { schema_version: 1, error: { message: "Failure" } },
    { findings: [] },
  ])
    assert.throws(() => imported(source));
});

test("integrity changes preserve added, missing and changed records", () => {
  const findings = imported(vestigium());
  assert.deepEqual(
    findings.map((item) => item.title),
    ["Entry added", "Entry missing", "Entry changed"],
  );
  assert.deepEqual(
    findings.map((item) => item.severity),
    ["medium", "high", "high"],
  );
  assert.match(findings[2].detail, /sha256/);
});

test("integrity errors and partial scans cannot claim clean comparison", () => {
  const source = {
    command: "verify",
    status: "incomplete",
    complete: false,
    issues: [{ path: "locked", code: "unreadable", message: "Read denied." }],
    changes: null,
  };
  assert.ok(imported(source).every((item) => item.severity === "high"));
  source.status = "clean";
  assert.throws(() => imported(source));
  const clean = vestigium();
  clean.status = "clean";
  assert.throws(() => imported(clean));
});

test("integrity snapshot is not baseline verification and duplicate changes are rejected", () => {
  const source = {
    command: "snapshot",
    status: "ok",
    complete: true,
    issues: [],
    summary: { files: 1, directories: 0, symlinks: 0, bytes: 7 },
    manifest: "manifest.json",
  };
  assert.match(imported(source)[0].detail, /not a verification/);
  const duplicate = vestigium();
  duplicate.changes.missing = ["new.txt"];
  assert.throws(() => imported(duplicate));
  assert.throws(() =>
    imported({
      schema: "vestigium-integrity/v1",
      algorithm: "sha256",
      entries: [],
    }),
  );
});

test("Lucerna reference hosts are observations, not malicious-host accusations", () => {
  const findings = imported(lucerna());
  assert.ok(findings.every((item) => item.severity === "info"));
  assert.match(findings[0].detail, /not a malicious-host verdict/);
  assert.match(findings.at(-1).detail, /not independently verified/);
});

test("Lucerna rejects invented host labels, count mismatches and external-host contradictions", () => {
  const host = lucerna();
  host.links[0].host = "unrelated.invalid";
  const count = lucerna();
  count.hosts[0].occurrences = 3;
  const external = lucerna();
  external.links[0].external_host = false;
  const network = lucerna();
  network.network_requests = 1;
  for (const source of [host, count, external, network])
    assert.throws(() => imported(source));
  const ipv6 = lucerna();
  ipv6.source = normalized("https://[::1]/", "::1");
  ipv6.effective_base = null;
  assert.doesNotThrow(() => imported(ipv6));
});

test("JSON duplicate decoded keys, dangerous keys and deep input are rejected", () => {
  for (const text of [
    '{"command":"verify","command":"snapshot"}',
    '{"findings":[],"find\\u0069ngs":[]}',
    '{"__proto__":{}}',
    '{"constructor":{}}',
    "[".repeat(40) + "0" + "]".repeat(40),
    '{"value":1e999}',
    '{"value":01}',
    '{"value":"unterminated}',
  ])
    assert.throws(() => importReport(text, "fixture.json", "evidence-1"));
  assert.throws(
    () =>
      importReport(
        " ".repeat(WORKSPACE_LIMITS.reportBytes + 1),
        "large.json",
        "evidence-1",
      ),
    /size limit/,
  );
});

test("declared action review reports shell, privilege, destructive and secret indicators", () => {
  const input = {
    ...plan(),
    command: "sudo rm -rf ./output; curl https://fixture.invalid",
    writePaths: ["../outside"],
    readPaths: ["/home/operator/.ssh", "/"],
    allowSubprocesses: true,
  };
  const findings = reviewAction(input);
  for (const title of [
    "Shell interpretation declared or detected",
    "Elevated or host-level access requested",
    "Destructive operation indicator",
    "Possible network use without declared hosts",
    "Sensitive location in declared scope",
    "Write access declared",
    "Child processes permitted",
  ])
    assert.ok(
      findings.some((item) => item.title === title),
      title,
    );
  assert.match(findings.at(-1).detail, /No command was executed/);
});

test("benign-looking action still cannot produce runtime approval", () => {
  const findings = reviewAction(plan());
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "info");
  assert.match(findings[0].detail, /absence of a warning is not approval/);
  assert.ok(
    reviewAction({ ...plan(), networkHosts: ["*"] }).some(
      (item) => item.severity === "high",
    ),
  );
});

test("absolute executable paths and home scopes retain risk indicators", () => {
  assert.ok(
    reviewAction({ ...plan(), command: "/bin/rm -rf ./output" }).some(
      (item) => item.title === "Destructive operation indicator",
    ),
  );
  assert.ok(
    reviewAction({ ...plan(), command: "/bin/sh script.sh" }).some(
      (item) => item.title === "Shell interpretation declared or detected",
    ),
  );
  for (const path of ["~/", "/home/", "./", "C:\\"])
    assert.ok(
      reviewAction({ ...plan(), writePaths: [path] }).some(
        (item) =>
          item.title === "Write access declared" && item.severity === "high",
      ),
    );
});

test("action JSON uses strict shape validation and rejects duplicated permission switches", () => {
  assert.deepEqual(parseActionPlan(JSON.stringify(plan())), plan());
  assert.throws(() =>
    parseActionPlan(
      JSON.stringify(plan()).replace(
        '"allowShell":false',
        '"allowShell":false,"allowShell":true',
      ),
    ),
  );
  assert.throws(() => reviewAction({ ...plan(), allowShell: "false" }));
  assert.throws(() => reviewAction({ ...plan(), unrecognized: true }));
});

test("access changes use exact stable tuples, deterministic order and bounded meanings", () => {
  const before = [
    record("operator", "service", "read"),
    record("a|b", "c", "read"),
  ];
  const after = [
    record("operator", "service", "admin"),
    record("a", "b|c", "read"),
  ];
  const findings = compareAccess(before, after);
  assert.equal(
    findings.filter((item) => item.title === "Access record added").length,
    2,
  );
  assert.equal(
    findings.filter((item) => item.title === "Access record removed").length,
    2,
  );
  assert.ok(findings.some((item) => item.severity === "high"));
  assert.ok(
    findings
      .filter((item) => item.title === "Access record removed")
      .every((item) =>
        /not proof of a live grant or revocation/.test(item.detail),
      ),
  );
  assert.deepEqual(
    findings.map(({ id, ...item }) => item),
    compareAccess([...before].reverse(), [...after].reverse()).map(
      ({ id, ...item }) => item,
    ),
  );
});

test("equal snapshots produce only a scoped no-difference observation", () => {
  const input = [record("operator", "service", "read")];
  const findings = compareAccess(input, copy(input));
  assert.equal(findings.length, 1);
  assert.match(findings[0].detail, /does not prove unchanged effective access/);
});

test("snapshot parser accepts bare arrays and versioned wrapper, rejecting duplicates and unknown schema", () => {
  const records = [record("operator", "service", "read")];
  assert.deepEqual(parseAccessSnapshot(JSON.stringify(records)), records);
  assert.deepEqual(
    parseAccessSnapshot(JSON.stringify({ schema_version: 1, records })),
    records,
  );
  assert.throws(() =>
    parseAccessSnapshot(JSON.stringify({ schema_version: 2, records })),
  );
  assert.throws(() =>
    parseAccessSnapshot(
      JSON.stringify({ schema_version: 1, records, scope: "unknown" }),
    ),
  );
  assert.throws(() => compareAccess([...records, ...records], []), /Duplicate/);
  assert.throws(() =>
    parseAccessSnapshot(JSON.stringify([{ ...records[0], permission: "" }])),
  );
});

test("large access differences fail visibly instead of silently truncating", () => {
  const records = Array.from(
    { length: WORKSPACE_LIMITS.findingsCount },
    (_, index) => record(`operator-${index}`, "service", "read"),
  );
  assert.throws(
    () => compareAccess([], records),
    /Too many access differences/,
  );
});

test("case serialization round-trips Unicode and a retained UTF-8 BOM with real digest verification", async () => {
  const item = await evidenceCase("\uFEFFPříliš žluťoučký kůň 🛡\n");
  assert.deepEqual(await parseCase(serializeCase(item)), item);
  const empty = createCase("Empty investigation", "No evidence collected");
  assert.deepEqual(await parseCase(serializeCase(empty)), empty);
});

test("changed evidence content fails even when its byte length is unchanged", async () => {
  const item = await evidenceCase("before");
  item.evidence[0].content = "after!";
  await assert.rejects(
    parseCase(JSON.stringify(item)),
    /digest does not match/,
  );
});

test("case import rejects byte-count lies, malformed hashes, null bytes and lone surrogates", async () => {
  const base = await evidenceCase();
  const bytes = copy(base);
  bytes.evidence[0].bytes += 1;
  const hash = copy(base);
  hash.evidence[0].sha256 = "not-a-digest";
  const zero = await evidenceCase("binary\0payload");
  const surrogate = copy(base);
  surrogate.notes = "\ud800";
  for (const item of [bytes, hash, zero, surrogate])
    await assert.rejects(parseCase(JSON.stringify(item)));
});

test("duplicate IDs, missing evidence references and unsupported case fields are rejected", async () => {
  const base = await evidenceCase();
  const duplicateEvidence = copy(base);
  duplicateEvidence.evidence.push(copy(base.evidence[0]));
  const duplicateFinding = copy(base);
  duplicateFinding.findings.push(copy(base.findings[0]));
  const missing = copy(base);
  missing.findings[0].evidenceIds = ["missing"];
  const repeated = copy(base);
  repeated.findings[0].evidenceIds.push("evidence-1");
  const unknown = copy(base);
  unknown.permissionEnforced = true;
  for (const item of [
    duplicateEvidence,
    duplicateFinding,
    missing,
    repeated,
    unknown,
  ])
    await assert.rejects(parseCase(JSON.stringify(item)));
});

test("case timestamps, item limits and total serialized size are bounded", async () => {
  const reversed = await evidenceCase();
  reversed.updatedAt = "2000-01-01T00:00:00.000Z";
  await assert.rejects(parseCase(JSON.stringify(reversed)));
  const oversized = await evidenceCase(
    "a".repeat(WORKSPACE_LIMITS.evidenceBytes + 1),
  );
  assert.throws(() => serializeCase(oversized));
  await assert.rejects(
    parseCase(" ".repeat(WORKSPACE_LIMITS.caseBytes + 1)),
    /size limit/,
  );
});

test("Markdown export neutralizes HTML, links, images, fences and injected headings", async () => {
  const item = await evidenceCase("PRIVATE_RAW_MARKER");
  const payload =
    '<img src="https://fixture.invalid/track" onerror="alert(1)">\n![remote](https://fixture.invalid/image)\n[run](javascript:alert(1))\n# Forged heading\n```html';
  item.notes = payload;
  item.findings[0].detail = payload;
  item.evidence[0].name = payload;
  const report = buildReportMarkdown(item);
  assert.ok(!report.includes("<img"));
  assert.ok(!report.includes("![remote]"));
  assert.ok(!report.includes("[run](javascript:"));
  assert.ok(!report.includes("\n# Forged"));
  assert.ok(!report.includes("```html"));
  assert.ok(!report.includes("PRIVATE_RAW_MARKER"));
  assert.match(report, /does not execute actions/);
});

test("an empty case report cannot be mistaken for a clean assessment", () => {
  const text = buildReportMarkdown(
    createCase("Unreviewed", "Synthetic fixture"),
  );
  assert.match(text, /not a clean security assessment/);
  assert.match(text, /changing both content and hashes/);
});

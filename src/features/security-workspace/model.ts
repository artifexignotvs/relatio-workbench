import { WORKSPACE_LIMITS } from "./types.ts";
import type {
  AccessRecord,
  ActionPlan,
  Evidence,
  Finding,
  FindingStatus,
  Severity,
  WorkspaceCase,
} from "./types.ts";

export { WORKSPACE_LIMITS } from "./types.ts";
export type {
  AccessRecord,
  ActionPlan,
  Evidence,
  Finding,
  FindingStatus,
  Severity,
  WorkspaceCase,
} from "./types.ts";

type Row = Record<string, unknown>;
const encoder = new TextEncoder();
const severities: Severity[] = ["high", "medium", "low", "info"];
const digestPattern = /^[a-f0-9]{64}$/;
const idPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

function invalid(message = "Invalid or unsupported input."): never {
  throw new Error(message);
}
function check(value: unknown, message?: string): asserts value {
  if (!value) invalid(message);
}
function object(value: unknown): Row {
  check(value !== null && typeof value === "object" && !Array.isArray(value));
  return value as Row;
}
function keys(value: Row, required: string[], optional: string[] = []): void {
  check(
    required.every((key) => Object.prototype.hasOwnProperty.call(value, key)),
  );
  check(
    Object.keys(value).every(
      (key) => required.includes(key) || optional.includes(key),
    ),
  );
}
function string(
  value: unknown,
  max: number = WORKSPACE_LIMITS.textLength,
  empty = false,
): string {
  check(
    typeof value === "string" &&
      value.length <= max &&
      (empty || value.trim().length > 0),
  );
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      check(next >= 0xdc00 && next <= 0xdfff);
      index += 1;
    } else check(unit < 0xdc00 || unit > 0xdfff);
  }
  return value;
}
function integer(value: unknown, max = Number.MAX_SAFE_INTEGER): number {
  check(
    typeof value === "number" &&
      Number.isSafeInteger(value) &&
      value >= 0 &&
      value <= max,
  );
  return value;
}
function boolean(value: unknown): boolean {
  check(typeof value === "boolean");
  return value;
}
function array(
  value: unknown,
  max: number = WORKSPACE_LIMITS.findingsCount,
): unknown[] {
  check(Array.isArray(value) && value.length <= max);
  return value;
}
function strings(value: unknown, max = 1000, itemMax = 4096): string[] {
  return array(value, max).map((item) => string(item, itemMax));
}
function unique(values: string[]): void {
  check(
    new Set(values).size === values.length,
    "Duplicate identifiers or records are not accepted.",
  );
}
function identifier(value: unknown): string {
  const result = string(value, 128);
  check(idPattern.test(result));
  return result;
}
function date(value: unknown): string {
  const result = string(value, 32);
  check(
    Number.isFinite(Date.parse(result)) &&
      new Date(result).toISOString() === result,
  );
  return result;
}
function choice<T extends string>(value: unknown, choices: readonly T[]): T {
  check(typeof value === "string" && choices.includes(value as T));
  return value as T;
}

// Claves geminatae et profunditas immoderata ante interpretationem recusantur.
function parseJson(text: string, max: number): unknown {
  check(
    typeof text === "string" &&
      text.length <= max &&
      encoder.encode(text).length <= max,
    "Input exceeds the supported size limit.",
  );
  let position = text.charCodeAt(0) === 0xfeff ? 1 : 0;
  let tokens = 0;
  const whitespace = () => {
    while (/[\t\n\r ]/.test(text[position] || "x")) position += 1;
  };
  const quoted = (): string => {
    const start = position++;
    while (position < text.length) {
      const char = text[position++];
      if (char === "\\") position += 1;
      else if (char === '"')
        return JSON.parse(text.slice(start, position)) as string;
    }
    return invalid();
  };
  const value = (depth: number): unknown => {
    check(depth <= 32 && ++tokens <= 200000);
    whitespace();
    const char = text[position];
    if (char === '"') return quoted();
    if (char === "{" || char === "[") {
      const isObject = char === "{";
      const result: Row | unknown[] = isObject
        ? (Object.create(null) as Row)
        : [];
      const names = new Set<string>();
      const close = isObject ? "}" : "]";
      position += 1;
      whitespace();
      if (text[position] === close) {
        position += 1;
        return result;
      }
      for (;;) {
        whitespace();
        if (isObject) {
          check(text[position] === '"');
          const key = quoted();
          check(
            !names.has(key) &&
              !["__proto__", "constructor", "prototype"].includes(key),
          );
          names.add(key);
          whitespace();
          check(text[position++] === ":");
          (result as Row)[key] = value(depth + 1);
        } else (result as unknown[]).push(value(depth + 1));
        whitespace();
        const next = text[position++];
        if (next === close) return result;
        check(next === ",");
      }
    }
    for (const [token, result] of [
      ["true", true],
      ["false", false],
      ["null", null],
    ] as const) {
      if (text.startsWith(token, position)) {
        position += token.length;
        return result;
      }
    }
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(
      text.slice(position),
    );
    check(match);
    position += match[0].length;
    const number = Number(match[0]);
    check(Number.isFinite(number));
    return number;
  };
  try {
    const result = value(0);
    whitespace();
    check(position === text.length);
    return result;
  } catch {
    return invalid(
      "Invalid JSON, duplicate keys, or unsupported input structure.",
    );
  }
}

export { parseJson as parseBoundedJson };

function finding(
  source: string,
  title: string,
  severity: Severity,
  detail: string,
  recommendation: string,
  evidenceIds: string[] = [],
): Finding {
  return {
    id: crypto.randomUUID(),
    title,
    severity,
    source,
    detail,
    recommendation,
    evidenceIds: [...evidenceIds],
  };
}

export function createCase(title: string, scope: string): WorkspaceCase {
  const now = new Date().toISOString();
  return {
    id: crypto.randomUUID(),
    title: string(title, 200),
    scope: string(scope, 4000),
    createdAt: now,
    updatedAt: now,
    findings: [],
    evidence: [],
    notes: "",
  };
}

// Forma, nexus et octeti probantur; fides originis ex signo locali non sequitur.
function validateCase(value: unknown): WorkspaceCase {
  const row = object(value);
  keys(row, [
    "id",
    "title",
    "scope",
    "createdAt",
    "updatedAt",
    "findings",
    "evidence",
    "notes",
  ]);
  const evidence: Evidence[] = array(
    row.evidence,
    WORKSPACE_LIMITS.evidenceCount,
  ).map((item) => {
    const entry = object(item);
    keys(entry, [
      "id",
      "name",
      "sha256",
      "bytes",
      "mediaType",
      "addedAt",
      "content",
      "kind",
    ]);
    const content = string(entry.content, WORKSPACE_LIMITS.evidenceBytes, true);
    check(
      !content.includes("\0"),
      "Evidence must contain UTF-8 text without null bytes.",
    );
    const bytes = integer(entry.bytes, WORKSPACE_LIMITS.evidenceBytes);
    check(
      encoder.encode(content).length === bytes,
      "Evidence byte count does not match its content.",
    );
    const sha256 = string(entry.sha256, 64);
    check(digestPattern.test(sha256));
    return {
      id: identifier(entry.id),
      name: string(entry.name, 255),
      sha256,
      bytes,
      mediaType: string(entry.mediaType, 128),
      addedAt: date(entry.addedAt),
      content,
      kind: string(entry.kind, 128),
    };
  });
  unique(evidence.map((entry) => entry.id));
  check(
    evidence.reduce((total, item) => total + item.bytes, 0) <=
      WORKSPACE_LIMITS.evidenceTotalBytes,
    "The case contains too much evidence.",
  );
  const evidenceIds = new Set(evidence.map((entry) => entry.id));
  const findings = array(row.findings).map((item) => {
    const entry = object(item);
    keys(entry, [
      "id",
      "title",
      "severity",
      "source",
      "detail",
      "recommendation",
      "evidenceIds",
    ], ["status", "analystNote"]);
    const references = array(
      entry.evidenceIds,
      WORKSPACE_LIMITS.evidenceCount,
    ).map(identifier);
    unique(references);
    check(
      references.every((id) => evidenceIds.has(id)),
      "A finding refers to missing evidence.",
    );
    return {
      id: identifier(entry.id),
      title: string(entry.title, 500),
      severity: choice(entry.severity, severities),
      source: string(entry.source, 128),
      detail: string(entry.detail),
      recommendation: string(entry.recommendation),
      evidenceIds: references,
      ...(entry.status === undefined ? {} : { status: choice(entry.status, ["open", "acknowledged", "resolved"] as const) }),
      ...(entry.analystNote === undefined ? {} : { analystNote: string(entry.analystNote, 4000, true) }),
    };
  });
  unique(findings.map((entry) => entry.id));
  const createdAt = date(row.createdAt);
  const updatedAt = date(row.updatedAt);
  check(Date.parse(updatedAt) >= Date.parse(createdAt));
  return {
    id: identifier(row.id),
    title: string(row.title, 200),
    scope: string(row.scope, 4000),
    createdAt,
    updatedAt,
    findings,
    evidence,
    notes: string(row.notes, WORKSPACE_LIMITS.textLength, true),
  };
}

export function updateFindingReview(value: WorkspaceCase, id: string, status: FindingStatus, analystNote: string): WorkspaceCase {
  check(value.findings.some((entry) => entry.id === id), "The finding no longer exists in this case.");
  const reviewed = choice(status, ["open", "acknowledged", "resolved"] as const);
  const note = string(analystNote, 4000, true);
  return validateCase({ ...value, findings: value.findings.map((entry) => entry.id === id ? { ...entry, status: reviewed, analystNote: note } : entry) });
}

export function serializeCase(value: WorkspaceCase): string {
  const result = JSON.stringify(validateCase(value), null, 2);
  check(
    encoder.encode(result).length <= WORKSPACE_LIMITS.caseBytes,
    "The serialized case exceeds the size limit.",
  );
  return result;
}

export async function parseCase(text: string): Promise<WorkspaceCase> {
  const result = validateCase(parseJson(text, WORKSPACE_LIMITS.caseBytes));
  // Digestum omnium octetorum verificatur; subscriptio vel custodia non asseritur.
  for (const item of result.evidence) {
    const bytes = new Uint8Array(
      await crypto.subtle.digest("SHA-256", encoder.encode(item.content)),
    );
    const digest = Array.from(bytes, (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
    check(
      digest === item.sha256,
      "Evidence digest does not match its content.",
    );
  }
  return result;
}


const comparisonCategories = ["added", "resolved", "unchanged", "severity_changed"] as const;
type ComparisonCategory = typeof comparisonCategories[number];
type ComparisonEntry = { rule_id: string; scope: string; count: number; severity?: string; from?: string; to?: string };
function importComparison(value: unknown, tool: "limen-mcp" | "vallum-http", observations: unknown[], evidenceId: string): Finding[] {
  const row = object(value);
  keys(row, ["scope", ...comparisonCategories, "summary"]);
  check(row.scope === "aggregate-rule-scope");
  const levels = tool === "limen-mcp" ? ["low", "medium", "high", "critical"] : ["info", "warning", "high"];
  const rules = new Set(tool === "limen-mcp" ? ["LM001", "LM002", "LM010", "LM011", "LM020", "LM030", "LM031", "LM040", "LM041", "LM042", "LM043", "LM044", "LM045", "LM046", "LM047", "LM048", "LM049", "LM090"] : ["content_type.missing", "content_type.nosniff_invalid", "content_type.nosniff_missing", "cookie.host_prefix", "cookie.httponly_missing", "cookie.malformed", "cookie.samesite_invalid", "cookie.samesite_missing", "cookie.samesite_none_insecure", "cookie.secure_missing", "cookie.secure_prefix", "csp.broad_scripts", "csp.duplicate_directive", "csp.eval", "csp.inline_scripts", "csp.missing", "csp.report_only", "framing.invalid_xfo", "framing.missing", "framing.wildcard", "hsts.disabled", "hsts.insecure", "hsts.invalid", "hsts.ip_literal", "hsts.missing", "hsts.multiple", "hsts.subdomains", "redirect.cross_host", "redirect.downgrade", "redirect.invalid_location", "redirect.limit", "redirect.loop", "referrer.invalid", "referrer.missing", "referrer.permissive", "response.error", "response.redirect", "transport.http", "transport.http_hop"]);
  const scopePattern = tool === "limen-mcp"
    ? /^(?:mcpServers|servers)\.server\[\*\](?:\.(?:command|transport|url(?:\.query)?|args(?:\[\*\])?|(?:env|headers)\.entry\[\*\]))?$/
    : /^response$/;
  const summary = object(row.summary);
  keys(summary, [...comparisonCategories]);
  const entries = {} as Record<ComparisonCategory, ComparisonEntry[]>;
  let groups = 0;
  for (const category of comparisonCategories) {
    const seen = new Set<string>();
    entries[category] = array(row[category], WORKSPACE_LIMITS.findingsCount).map((raw) => {
      const entry = object(raw);
      const shifted = category === "severity_changed";
      keys(entry, ["rule_id", "scope", "count", ...(shifted ? ["from", "to"] : ["severity"])]);
      const rule = string(entry.rule_id, 100), scope = string(entry.scope, 200);
      check(rules.has(rule) && scopePattern.test(scope));
      const count = integer(entry.count, 100000);
      check(count > 0);
      const severity = shifted ? undefined : choice(entry.severity, levels);
      const from = shifted ? choice(entry.from, levels) : undefined;
      const to = shifted ? choice(entry.to, levels) : undefined;
      check(!shifted || from !== to);
      const identity = JSON.stringify([rule, scope, severity, from, to]);
      check(!seen.has(identity)); seen.add(identity);
      return { rule_id: rule, scope, count, ...(shifted ? { from, to } : { severity }) };
    });
    groups += entries[category].length;
    check(integer(summary[category], 100000) === entries[category].reduce((sum, entry) => sum + entry.count, 0));
  }
  check(groups <= WORKSPACE_LIMITS.findingsCount - 1, "The comparison contains too many groups; narrow its scope.");
  const before = new Map<string, number>(), after = new Map<string, number>(), actual = new Map<string, number>();
  const key = (rule: string, scope: string, severity: string) => JSON.stringify([rule, scope, severity]);
  const increment = (map: Map<string, number>, name: string, count: number) => map.set(name, (map.get(name) ?? 0) + count);
  for (const category of comparisonCategories) for (const entry of entries[category]) {
    if (category !== "added") increment(before, key(entry.rule_id, entry.scope, entry.from ?? entry.severity!), entry.count);
    if (category !== "resolved") increment(after, key(entry.rule_id, entry.scope, entry.to ?? entry.severity!), entry.count);
  }
  check([...before.values()].reduce((sum, count) => sum + count, 0) <= 100000);
  check([...after.values()].reduce((sum, count) => sum + count, 0) <= 100000);
  for (const raw of observations) {
    const entry = object(raw);
    const rule = string(entry[tool === "limen-mcp" ? "rule_id" : "id"], 100);
    const scope = tool === "limen-mcp" ? string(entry.location, 4096).replace(/\[\d+\]/g, "[*]") : "response";
    const severity = choice(entry.severity, levels);
    check(rules.has(rule) && scopePattern.test(scope));
    increment(actual, key(rule, scope, severity), 1);
  }
  check(actual.size === after.size && [...actual].every(([name, count]) => after.get(name) === count));
  // Numeri integri cum relatione praesenti concordent; identitates singulae non finguntur.
  const expected: Record<ComparisonCategory, ComparisonEntry[]> = { added: [], resolved: [], unchanged: [], severity_changed: [] };
  const scopes = new Set([...before.keys(), ...after.keys()].map((name) => JSON.stringify(JSON.parse(name).slice(0, 2))));
  for (const name of [...scopes].sort()) {
    const [rule, scope] = JSON.parse(name) as [string, string];
    const oldCounts = new Map<string, number>(), newCounts = new Map<string, number>();
    for (const severity of levels) {
      const a = before.get(key(rule, scope, severity)) ?? 0, b = after.get(key(rule, scope, severity)) ?? 0;
      const count = Math.min(a, b);
      if (count) expected.unchanged.push({ rule_id: rule, scope, count, severity });
      oldCounts.set(severity, a - count); newCounts.set(severity, b - count);
    }
    for (const from of levels) for (const to of levels) {
      const count = Math.min(oldCounts.get(from)!, newCounts.get(to)!);
      if (count) {
        expected.severity_changed.push({ rule_id: rule, scope, count, from, to });
        oldCounts.set(from, oldCounts.get(from)! - count); newCounts.set(to, newCounts.get(to)! - count);
      }
    }
    for (const severity of levels) {
      if (oldCounts.get(severity)) expected.resolved.push({ rule_id: rule, scope, count: oldCounts.get(severity)!, severity });
      if (newCounts.get(severity)) expected.added.push({ rule_id: rule, scope, count: newCounts.get(severity)!, severity });
    }
  }
  const canonical = (values: ComparisonEntry[]) => values.map((entry) => JSON.stringify(entry)).sort().join("\n");
  for (const category of comparisonCategories) check(canonical(entries[category]) === canonical(expected[category]));
  const result: Finding[] = [finding(tool, "Supplied aggregate baseline comparison", "info",
    `Observation counts: ${comparisonCategories.map((category) => `${summary[category]} ${category}`).join(", ")}. Counts were reconciled with current findings. These are aggregate rule/scope changes, not stable server or cookie identities. The original baseline and collection context are not verified here; a same-count replacement may be invisible.`,
    "Review the original baseline, scope label and collection conditions. A removed finding does not verify remediation or establish security.", [evidenceId])];
  for (const category of comparisonCategories) for (const entry of entries[category]) {
    const level = entry.to ?? entry.severity!;
    const severity: Severity = category === "resolved" || category === "unchanged" ? "info" : level === "critical" ? "high" : level === "warning" ? "medium" : level as Severity;
    result.push(finding(tool, `Baseline ${category}: ${entry.rule_id}`, severity,
      `Scope: ${entry.scope}. Observations: ${entry.count}. ${category === "severity_changed" ? `Source severity shift: ${entry.from} -> ${entry.to}.` : `Source severity: ${entry.severity}.`} This records the supplied aggregate comparison, not independent verification of individual remediation.`,
      "Use the retained source report and original baseline to investigate the count change; do not infer identity from ordinal positions.", [evidenceId]));
  }
  return result;
}

function importLimen(row: Row, evidenceId: string): Finding[] {
  keys(row, ["schema_version", "summary", "findings", "errors"], ["comparison"]);
  check(row.schema_version === 1);
  const summary = object(row.summary);
  keys(summary, ["servers", "findings", "errors"]);
  integer(summary.servers);
  const items = array(row.findings, 900);
  const errors = strings(row.errors, 50, 20000);
  check(
    integer(summary.findings) === items.length &&
      integer(summary.errors) === errors.length,
  );
  const result = items.map((item) => {
    const entry = object(item);
    keys(entry, ["rule_id", "severity", "location", "message", "remediation"]);
    const severity = choice(entry.severity, [
      "critical",
      "high",
      "medium",
      "low",
    ]);
    const rule = string(entry.rule_id, 100);
    return finding(
      "limen-mcp",
      rule,
      severity === "critical" ? "high" : severity,
      `${string(entry.location, 4096)}: ${string(entry.message)}${severity === "critical" ? " (Source severity: critical.)" : ""}`,
      string(entry.remediation),
      [evidenceId],
    );
  });
  errors.forEach((error) =>
    result.push(
      finding(
        "limen-mcp",
        "Source scan error",
        "high",
        error,
        "Resolve the source scan error before drawing conclusions from its findings.",
        [evidenceId],
      ),
    ),
  );
  if (!result.length)
    result.push(
      finding(
        "limen-mcp",
        "No findings in supplied configuration report",
        "info",
        "The supplied report contains no findings. It does not establish runtime safety or complete coverage.",
        "Review the original configuration, tool version and declared scope.",
        [evidenceId],
      ),
    );
  if (row.comparison !== undefined) {
    check(errors.length === 0);
    result.push(...importComparison(row.comparison, "limen-mcp", items, evidenceId));
  }
  return result;
}

function importVallum(row: Row, evidenceId: string): Finding[] {
  keys(row, [
    "schema_version",
    "mode",
    "target",
    "status",
    "redirects",
    "summary",
    "findings",
  ], ["comparison"]);
  check(row.schema_version === 1);
  choice(row.mode, ["offline", "online"]);
  string(row.target, 8192);
  check(integer(row.status, 599) >= 100);
  array(row.redirects, 30).forEach((item) => {
    const entry = object(item);
    keys(entry, ["from", "to", "status"]);
    string(entry.from, 8192);
    string(entry.to, 8192);
    check(integer(entry.status, 599) >= 100);
  });
  const summary = object(row.summary);
  keys(summary, ["high", "warning", "info"]);
  const counts = { high: 0, warning: 0, info: 0 };
  const result = array(row.findings, 950).map((item) => {
    const entry = object(item);
    keys(entry, ["id", "severity", "message", "recommendation"]);
    const severity = choice(entry.severity, ["high", "warning", "info"]);
    counts[severity] += 1;
    return finding(
      "vallum-http",
      string(entry.id, 200),
      severity === "warning" ? "medium" : severity,
      string(entry.message),
      string(entry.recommendation),
      [evidenceId],
    );
  });
  for (const level of ["high", "warning", "info"] as const)
    check(integer(summary[level]) === counts[level]);
  if (!result.length)
    result.push(
      finding(
        "vallum-http",
        "No findings in supplied HTTP report",
        "info",
        "The supplied HTTP response report contains no findings. It is not a complete application security assessment.",
        "Confirm response scope, freshness and policy context.",
        [evidenceId],
      ),
    );
  if (row.comparison !== undefined) result.push(...importComparison(row.comparison, "vallum-http", array(row.findings, 950), evidenceId));
  return result;
}

function importVestigium(row: Row, evidenceId: string): Finding[] {
  keys(
    row,
    ["command", "status", "complete", "issues"],
    ["summary", "changes", "manifest"],
  );
  const command = choice(row.command, ["snapshot", "verify"]);
  const status = choice(row.status, [
    "ok",
    "clean",
    "different",
    "incomplete",
    "error",
  ]);
  const complete = boolean(row.complete);
  const result: Finding[] = [];
  const issues = array(row.issues, 400);
  issues.forEach((item) => {
    const entry = object(item);
    keys(entry, ["path", "code", "message"]);
    result.push(
      finding(
        "vestigium-integrity",
        string(entry.code, 200),
        "high",
        `${string(entry.path, 4096)}: ${string(entry.message)}`,
        "Resolve the scan issue; an incomplete scan cannot establish unchanged content.",
        [evidenceId],
      ),
    );
  });
  if (row.summary !== undefined) {
    const summary = object(row.summary);
    keys(summary, ["files", "directories", "symlinks", "bytes"]);
    Object.values(summary).forEach((value) => integer(value));
  }
  if (row.manifest !== undefined) string(row.manifest, 4096);
  check(complete === ["ok", "clean", "different"].includes(status));
  if (!complete) {
    check(row.changes === undefined || row.changes === null);
    result.push(
      finding(
        "vestigium-integrity",
        "Incomplete integrity operation",
        "high",
        `The source reported ${status}; no clean comparison is available.`,
        "Repeat the operation after resolving errors and preserving the original evidence.",
        [evidenceId],
      ),
    );
    return result;
  }
  check(issues.length === 0 && row.summary !== undefined);
  if (command === "snapshot") {
    check(
      status === "ok" &&
        row.manifest !== undefined &&
        row.changes === undefined,
    );
    return [
      finding(
        "vestigium-integrity",
        "Integrity snapshot created",
        "info",
        "The supplied report records manifest creation; it is not a verification against an earlier trusted baseline.",
        "Preserve the manifest separately and run a later comparison.",
        [evidenceId],
      ),
    ];
  }
  check(status === "clean" || status === "different");
  const changes = object(row.changes);
  keys(changes, ["added", "missing", "changed"]);
  const allPaths: string[] = [];
  for (const kind of ["added", "missing"] as const) {
    strings(changes[kind], 950).forEach((path) => {
      allPaths.push(path);
      result.push(
        finding(
          "vestigium-integrity",
          `Entry ${kind}`,
          kind === "missing" ? "high" : "medium",
          path,
          "Review the difference against a separately trusted manifest; a difference alone does not identify its cause.",
          [evidenceId],
        ),
      );
    });
  }
  array(changes.changed, 950).forEach((item) => {
    const entry = object(item);
    keys(entry, ["path", "reasons", "expected_type", "actual_type"]);
    const path = string(entry.path, 4096);
    allPaths.push(path);
    const reasons = array(entry.reasons, 4).map((value) =>
      choice(value, ["type", "sha256", "size", "target"]),
    );
    unique(reasons);
    check(reasons.length > 0);
    choice(entry.expected_type, ["file", "directory", "symlink"]);
    choice(entry.actual_type, ["file", "directory", "symlink"]);
    result.push(
      finding(
        "vestigium-integrity",
        "Entry changed",
        "high",
        `${path}: ${reasons.join(", ")}`,
        "Inspect the changed entry and verify the baseline's provenance.",
        [evidenceId],
      ),
    );
  });
  unique(allPaths);
  check((status === "different") === result.length > 0);
  if (!result.length)
    result.push(
      finding(
        "vestigium-integrity",
        "No differences in supplied comparison",
        "info",
        "The supplied comparison reports no differences. Editing both files and their baseline can remain undetected.",
        "Retain a separately trusted baseline and confirm the compared scope.",
        [evidenceId],
      ),
    );
  return result;
}

function normalizedUrl(value: unknown): Row {
  const entry = object(value);
  keys(entry, [
    "url",
    "host",
    "query_removed",
    "fragment_removed",
    "credentials_removed",
  ]);
  const url = new URL(string(entry.url, 8192));
  check(
    ["https:", "http:"].includes(url.protocol) &&
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash,
  );
  check(
    string(entry.host, 255) ===
      url.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, ""),
  );
  for (const field of [
    "query_removed",
    "fragment_removed",
    "credentials_removed",
  ])
    boolean(entry[field]);
  return entry;
}

function importLucerna(row: Row, evidenceId: string): Finding[] {
  keys(row, [
    "schema_version",
    "tool",
    "sha256",
    "bytes",
    "encoding",
    "source",
    "effective_base",
    "title",
    "metadata",
    "links",
    "hosts",
    "skipped_references",
    "network_requests",
  ]);
  check(
    row.schema_version === 1 &&
      row.tool === "lucerna-osint" &&
      row.network_requests === 0,
  );
  check(digestPattern.test(string(row.sha256, 64)));
  integer(row.bytes);
  string(row.encoding, 100);
  string(row.title, 2000, true);
  integer(row.skipped_references);
  if (row.source !== null) normalizedUrl(row.source);
  if (row.effective_base !== null) normalizedUrl(row.effective_base);
  array(row.metadata, 5000).forEach((item) => {
    const entry = object(item);
    keys(entry, ["name", "content", "line"]);
    string(entry.name, 100);
    string(entry.content, 2000, true);
    check(integer(entry.line) > 0);
  });
  const links = array(row.links, 10000);
  const hostCounts = new Map<string, number>();
  const urls: string[] = [];
  links.forEach((item) => {
    const entry = object(item);
    keys(entry, [
      "url",
      "host",
      "query_removed",
      "fragment_removed",
      "credentials_removed",
      "occurrences",
      "tags",
      "lines",
      "relations",
      "external_host",
    ]);
    normalizedUrl(
      Object.fromEntries(
        [
          "url",
          "host",
          "query_removed",
          "fragment_removed",
          "credentials_removed",
        ].map((key) => [key, entry[key]]),
      ),
    );
    const host = string(entry.host, 255);
    const count = integer(entry.occurrences);
    check(count > 0);
    strings(entry.tags, 100, 100);
    strings(entry.relations, 1000, 200);
    array(entry.lines, 10000).forEach((line) => check(integer(line) > 0));
    check(
      entry.external_host ===
        (row.source === null ? null : host !== (row.source as Row).host),
    );
    urls.push(string(entry.url, 8192));
    hostCounts.set(host, (hostCounts.get(host) || 0) + count);
  });
  unique(urls);
  const hosts = array(row.hosts, 950).map((item) => {
    const entry = object(item);
    keys(entry, ["host", "occurrences"]);
    const host = string(entry.host, 255);
    check(integer(entry.occurrences) === hostCounts.get(host));
    return host;
  });
  unique(hosts);
  check(hosts.length === hostCounts.size);
  const result = hosts.map((host) =>
    finding(
      "lucerna-osint",
      "Referenced host",
      "info",
      `${host}: ${hostCounts.get(host)} references in the supplied saved-page inventory. This is not a malicious-host verdict.`,
      "Review source lines and context before attributing meaning to a reference.",
      [evidenceId],
    ),
  );
  result.push(
    finding(
      "lucerna-osint",
      "Saved-page inventory scope",
      "info",
      `${links.length} distinct URLs; ${row.skipped_references} skipped references. The source HTML is not included by this report, so its declared hash is not independently verified here.`,
      "Retain the original HTML as separate evidence. Dynamic content and unfetched pages are outside this inventory.",
      [evidenceId],
    ),
  );
  return result;
}

const excubitorRules = ["vertical_scan", "horizontal_scan", "auth_bruteforce", "password_spray", "distributed_auth", "auth_success_after_fail", "web_path_scan", "web_denial_burst", "upstream_alert"] as const;
function timestamp(value: unknown): number {
  check(typeof value === "number" && Number.isFinite(value) && Math.abs(value) <= 8640000000000);
  return value;
}
function importExcubitorAlert(value: unknown, evidenceId: string): Finding {
  const item = object(value);
  keys(item, ["id", "rule", "severity", "ts", "first_seen", "src", "dst", "count", "summary", "evidence", "recommendation"], ["acknowledged"]);
  const originalId = identifier(item.id);
  const rule = choice(item.rule, excubitorRules);
  const severity = choice(item.severity, ["critical", "high", "medium", "low", "info"] as const);
  const ts = timestamp(item.ts);
  const first = timestamp(item.first_seen);
  check(first <= ts);
  const count = integer(item.count);
  check(count > 0);
  const detail = object(item.evidence);
  check(Object.keys(detail).length <= 32);
  for (const [key, value] of Object.entries(detail)) {
    check(/^[a-z][a-z0-9_]{0,63}$/.test(key));
    const primitive = (entry: unknown) => {
      if (typeof entry === "string") string(entry, 4096, true);
      else if (typeof entry === "number") timestamp(entry);
      else check(typeof entry === "boolean" || entry === null);
    };
    if (Array.isArray(value)) array(value, 64).forEach(primitive);
    else primitive(value);
  }
  const threshold = integer(detail.threshold);
  const window = integer(detail.window_seconds);
  check(threshold > 0 && count >= threshold && first >= timestamp(detail.window_start) && timestamp(detail.window_end) === ts &&
    Math.abs(timestamp(detail.window_start) - (ts - window)) < 0.000001);
  const acknowledged = item.acknowledged === undefined ? false : boolean(item.acknowledged);
  const result = finding("excubitor", string(item.summary, 500), severity === "critical" ? "high" : severity,
    `Rule: ${rule}. Source alert: ${originalId}. Source severity: ${severity}. Source: ${string(item.src, 256)}. Target: ${string(item.dst, 256, true)}. Observations: ${count}. First seen: ${new Date(first * 1000).toISOString()}. Alert time: ${new Date(ts * 1000).toISOString()}. Source acknowledged: ${acknowledged}. Evidence: ${JSON.stringify(detail)}. ${rule === "upstream_alert" ? "This preserves an upstream sensor alert; it is not independent confirmation." : "This is a heuristic investigation lead, not proof of compromise."}`,
    string(item.recommendation), [evidenceId]);
  string(result.detail);
  result.status = acknowledged ? "acknowledged" : "open";
  return result;
}
function excubitorFindings(values: unknown[], evidenceId: string): Finding[] {
  unique(values.map((value) => identifier(object(value).id)));
  return values.map((value) => importExcubitorAlert(value, evidenceId));
}
function addCoverage(result: Finding[], coverage: Finding): Finding[] {
  if (result.length < WORKSPACE_LIMITS.findingsCount) result.push(coverage);
  else {
    const first = result[0];
    first.detail = string(`${first.detail} Collection scope: ${coverage.detail}`);
  }
  return result;
}
function importExcubitor(row: Row, evidenceId: string): Finding[] {
  keys(row, ["schema", "alerts"]);
  check(row.schema === "excubitor.alerts.v1");
  const result = excubitorFindings(array(row.alerts, 1000), evidenceId);
  return addCoverage(result, finding("excubitor", "Supplied alert export coverage", "info",
    `${result.length} alerts are included in this export. The dashboard and final export retain at most 1,000 alerts; history queries are limited. No collection counters are supplied. An empty or partial export does not establish a clean network or complete collection.`,
    "Retain the original logs and collection counters; review time range, query limits, dropped events and capacity evictions.", [evidenceId]));
}
function importExcubitorLines(text: string, evidenceId: string): Finding[] {
  check(encoder.encode(text).length <= WORKSPACE_LIMITS.reportBytes, "Input exceeds the supported size limit.");
  const lines = text.split(/\r?\n/).filter((line) => line.trim());
  check(lines.length > 0 && lines.length <= 1001, "The stream exceeds the finding limit.");
  const values = lines.map((line) => object(parseJson(line, 256 * 1024)));
  let summary: Row | undefined;
  if (Object.hasOwn(values[values.length - 1], "engine")) summary = values.pop();
  const result = excubitorFindings(array(values, 1000), evidenceId);
  let coverage = "No final collection summary was supplied; this may be a partial or live stream.";
  let severity: Severity = "info";
  if (summary) {
    keys(summary, ["engine", "input_errors", "skipped_records", "retained_alerts", "replay_cancelled"]);
    const engine = object(summary.engine);
    const counters = ["received_events", "accepted_events", "late_events", "invalid_events", "duplicate_events", "allowlisted_events", "alerts", "cooldown_suppressed", "keys_evicted", "events_evicted", "keys_expired", "dedup_evicted", "cooldowns_evicted", "state_keys", "buffered_events", "dedup_keys", "cooldown_keys"];
    keys(engine, counters);
    counters.forEach((key) => integer(engine[key]));
    integer(summary.input_errors); integer(summary.skipped_records); integer(summary.retained_alerts, 1000);
    boolean(summary.replay_cancelled);
    const accounted = ["accepted_events", "late_events", "invalid_events", "duplicate_events", "allowlisted_events"].reduce((sum, key) => sum + Number(engine[key]), 0);
    check(Number.isSafeInteger(accounted) && Number(engine.received_events) === accounted);
    check(Number(engine.alerts) >= values.length && Number(summary.retained_alerts) === Math.min(1000, Number(engine.alerts)));
    const incomplete = summary.replay_cancelled || summary.input_errors || summary.skipped_records || engine.late_events || engine.invalid_events || engine.keys_evicted || engine.events_evicted || engine.dedup_evicted || engine.cooldowns_evicted || Number(engine.alerts) !== values.length;
    severity = incomplete ? "high" : "info";
    coverage = `${incomplete ? "Collection gaps, discarded observations, or a partial stream require review." : "Supplied counters report no collection gaps; this is not proof of complete detection."} Counters: ${JSON.stringify(summary)}`;
  }
  return addCoverage(result, finding("excubitor", "Supplied alert stream coverage", severity,
    `${values.length} alerts imported. ${coverage} An empty stream is not a clean security assessment.`,
    "Review original logs and collection limits. Source acknowledgement is not resolution. This workspace does not rerun detection.", [evidenceId]));
}

export function importReport(
  text: string,
  name: string,
  evidenceId: string,
): Finding[] {
  string(name, 255);
  identifier(evidenceId);
  if (/\.(?:jsonl|ndjson)$/i.test(name)) return importExcubitorLines(text, evidenceId);
  const row = object(parseJson(text, WORKSPACE_LIMITS.reportBytes));
  if (row.comparison_scope === "aggregate-rule-scope" || row.version === "2.1.0")
    return invalid("Baseline snapshots and SARIF are not finding reports. Import an ordinary tool JSON report, optionally including its comparison.");
  let result: Finding[];
  try {
    if (row.schema === "excubitor.alerts.v1") result = importExcubitor(row, evidenceId);
    else if (row.tool === "lucerna-osint") result = importLucerna(row, evidenceId);
    else if (row.command === "verify" || row.command === "snapshot")
      result = importVestigium(row, evidenceId);
    else if (Object.prototype.hasOwnProperty.call(row, "mode"))
      result = importVallum(row, evidenceId);
    else if (Object.prototype.hasOwnProperty.call(row, "errors"))
      result = importLimen(row, evidenceId);
    else return invalid();
  } catch {
    return invalid(
      "Unsupported or inconsistent tool report. Supported reports: Limen MCP, Vallum HTTP, Vestigium Integrity CLI, Lucerna OSINT and EXCUBITOR alert exports.",
    );
  }
  check(
    result.length <= WORKSPACE_LIMITS.findingsCount,
    "The report contains too many findings; narrow its scope.",
  );
  for (const item of result) {
    string(item.title, 500);
    string(item.detail);
    string(item.recommendation);
  }
  return result;
}

function validateActionPlan(input: unknown): ActionPlan {
  const value = object(input);
  keys(value, [
    "command",
    "readPaths",
    "writePaths",
    "networkHosts",
    "allowShell",
    "allowSubprocesses",
  ]);
  return {
    command: string(value.command, 8000),
    readPaths: strings(value.readPaths, 100, 2048),
    writePaths: strings(value.writePaths, 100, 2048),
    networkHosts: strings(value.networkHosts, 100, 255),
    allowShell: boolean(value.allowShell),
    allowSubprocesses: boolean(value.allowSubprocesses),
  };
}

export function parseActionPlan(text: string): ActionPlan {
  return validateActionPlan(parseJson(text, WORKSPACE_LIMITS.reportBytes));
}

export function reviewAction(input: ActionPlan): Finding[] {
  const plan = validateActionPlan(input);
  const { command, readPaths, writePaths, networkHosts: hosts } = plan;
  const result: Finding[] = [];
  const add = (
    title: string,
    severity: Severity,
    detail: string,
    recommendation: string,
  ) =>
    result.push(
      finding("action-review", title, severity, detail, recommendation),
    );
  if (
    plan.allowShell ||
    /[|;&`\n]|\$\(|(?:^|\s)(?:[^\s;&|]*[\\/])?(?:bash|sh|zsh|cmd|powershell|pwsh)(?:\.exe)?(?:\s|$)/i.test(
      command,
    )
  )
    add(
      "Shell interpretation declared or detected",
      "high",
      "A shell permission or shell-like syntax can introduce expansion, pipelines and multiple commands.",
      "Prefer an explicit executable and argument list; review shell behavior and enforce permissions outside this workspace.",
    );
  if (plan.allowSubprocesses)
    add(
      "Child processes permitted",
      "medium",
      "The declared plan allows child processes, which can enlarge the action scope.",
      "List required child executables and constrain them in the actual execution environment.",
    );
  if (
    /(?:^|\s|[;&|])(?:sudo|doas|su)(?:\s|$)|--privileged|docker\.sock|--pid(?:=|\s+)host|--network(?:=|\s+)host/i.test(
      command,
    )
  )
    add(
      "Elevated or host-level access requested",
      "high",
      "The command contains a privileged execution or host-access indicator.",
      "Remove unnecessary privilege and explicitly review the host boundary.",
    );
  if (
    /(?:^|\s|[;&|])(?:[^\s;&|]*[\\/])?(?:rm|rmdir|del|erase|format|mkfs(?:\.[a-z0-9]+)?|dd)(?:\.exe)?(?:\s|$)|git\s+(?:reset\s+--hard|clean\s+-[a-z]*f)/i.test(
      command,
    )
  )
    add(
      "Destructive operation indicator",
      "high",
      "The command contains a deletion, overwrite or destructive reset indicator.",
      "Confirm exact targets and recovery options before any separate execution.",
    );
  if (
    /\b(?:curl|wget|fetch|ssh|scp|git\s+(?:clone|push|fetch|pull)|npm\s+(?:install|exec)|npx|pip\s+install)\b|https?:\/\//i.test(
      command,
    ) &&
    hosts.length === 0
  )
    add(
      "Possible network use without declared hosts",
      "high",
      "The command suggests network activity, but the plan declares no destination hosts.",
      "Declare required destinations and enforce an actual outbound policy.",
    );
  if (hosts.length)
    add(
      "Network destinations declared",
      hosts.some((host) => /[*\/]|^0\.0\.0\.0$|^::$/.test(host))
        ? "high"
        : "medium",
      `${hosts.length} destination entries are declared. This review does not resolve hosts or inspect network traffic.`,
      "Use exact hostnames and independently constrain outbound access, redirects and resolved addresses.",
    );
  const broad = (path: string) =>
    /[*?]|(?:^|[\\/])\.\.(?:[\\/]|$)/.test(path) ||
    /^(?:[\\/]+|[A-Za-z]:[\\/]*|~[\\/]*|\.[\\/]*|\/(?:home|Users)\/*)$/.test(
      path,
    );
  if (writePaths.length)
    add(
      "Write access declared",
      writePaths.some(broad) ? "high" : "medium",
      `${writePaths.length} writable paths are declared${writePaths.some(broad) ? ", including a broad or traversing path" : ""}.`,
      "Restrict writes to explicit task outputs and enforce canonical path boundaries externally.",
    );
  if (readPaths.some(broad))
    add(
      "Broad read access declared",
      "medium",
      "The read scope includes a wildcard, root, home or traversal entry.",
      "Use the smallest required input directories and account for symbolic links in enforcement.",
    );
  if (
    [...readPaths, ...writePaths].some((path) =>
      /(?:^|[\\/])(?:\.env(?:\..*)?|\.ssh|\.aws|\.gnupg|credentials|secrets)(?:[\\/]|$)/i.test(
        path,
      ),
    )
  )
    add(
      "Sensitive location in declared scope",
      "high",
      "A declared path names a common credential or secret location.",
      "Remove secret locations unless explicitly required and separately controlled.",
    );
  add(
    "Declaration review only",
    "info",
    "These are heuristic observations over the supplied text and permissions. No command was executed, filesystem inspected, traffic observed or permission enforced; absence of a warning is not approval.",
    "Retain this proposal as evidence and use independent execution controls and human review where appropriate.",
  );
  return result;
}

function accessRecords(value: unknown): AccessRecord[] {
  const records = array(value, WORKSPACE_LIMITS.accessRecords).map((item) => {
    const entry = object(item);
    keys(entry, ["principal", "resource", "permission"]);
    return {
      principal: string(entry.principal, 512),
      resource: string(entry.resource, 2048),
      permission: string(entry.permission, 512),
    };
  });
  unique(
    records.map((record) =>
      JSON.stringify([record.principal, record.resource, record.permission]),
    ),
  );
  return records;
}

export function parseAccessSnapshot(text: string): AccessRecord[] {
  const value = parseJson(text, WORKSPACE_LIMITS.reportBytes);
  if (Array.isArray(value)) return accessRecords(value);
  const row = object(value);
  keys(row, ["schema_version", "records"]);
  check(row.schema_version === 1);
  return accessRecords(row.records);
}

export function compareAccess(
  before: AccessRecord[],
  after: AccessRecord[],
): Finding[] {
  const key = (record: AccessRecord) =>
    JSON.stringify([record.principal, record.resource, record.permission]);
  const oldRecords = new Map(
    accessRecords(before).map((record) => [key(record), record]),
  );
  const newRecords = new Map(
    accessRecords(after).map((record) => [key(record), record]),
  );
  const result: Finding[] = [];
  for (const [entries, comparison, added] of [
    [newRecords, oldRecords, true],
    [oldRecords, newRecords, false],
  ] as const) {
    for (const id of [...entries.keys()].sort()) {
      if (comparison.has(id)) continue;
      const record = entries.get(id)!;
      const elevated =
        /(?:^|[\s:._/-])(?:admin|administrator|owner|root|superuser)(?:$|[\s:._/-])|\*/i.test(
          record.permission,
        );
      result.push(
        finding(
          "access-diff",
          added ? "Access record added" : "Access record removed",
          added ? (elevated ? "high" : "medium") : "info",
          `${JSON.stringify(record.principal)} → ${JSON.stringify(record.resource)}: ${JSON.stringify(record.permission)}. This is a difference between supplied records, not proof of a live grant or revocation.`,
          added
            ? "Confirm the added permission is expected and justified for this principal and resource."
            : "Verify current authorization and existing sessions or tokens at the actual enforcement point.",
        ),
      );
    }
  }
  check(
    result.length < WORKSPACE_LIMITS.findingsCount,
    "Too many access differences; narrow the snapshot scope.",
  );
  result.push(
    finding(
      "access-diff",
      "Snapshot comparison boundary",
      "info",
      result.length
        ? "The comparison uses exact principal, resource and permission values. Snapshot completeness, collection times and effective access were not independently verified."
        : "No differences exist in the supplied records. This does not prove unchanged effective access, complete inventory or revoked sessions.",
      "Keep both snapshots and their collection context as evidence; verify live access separately.",
    ),
  );
  return result;
}

// Textus externus in relatione ut textus tantum redditur, numquam ut HTML.
function markdown(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/([\\`*_{}\[\]()#+.!|~\-])/g, "\\$1")
    .replace(/\r/g, "")
    .replace(/\n/g, "  \n");
}

export function buildReportMarkdown(value: WorkspaceCase): string {
  const item = validateCase(value);
  const lines = [
    `# ${markdown(item.title)}`,
    "",
    `Scope: ${markdown(item.scope)}`,
    "",
    `Case: ${markdown(item.id)}`,
    `Created: ${item.createdAt}`,
    `Updated: ${item.updatedAt}`,
    "",
    "## Findings",
    "",
  ];
  if (!item.findings.length)
    lines.push(
      "No findings have been recorded. This is not a clean security assessment.",
      "",
    );
  for (const entry of item.findings) {
    lines.push(
      `### ${entry.severity.toUpperCase()} — ${markdown(entry.title)}`,
      "",
      `Source: ${markdown(entry.source)}`,
      `Review status: ${entry.status ?? "open"}`,
      `Analyst note: ${markdown(entry.analystNote || "No finding note recorded.")}`,
      "",
      markdown(entry.detail),
      "",
      `Recommendation: ${markdown(entry.recommendation)}`,
      "",
      `Evidence: ${entry.evidenceIds.length ? entry.evidenceIds.map(markdown).join(", ") : "No evidence linked"}`,
      "",
    );
  }
  lines.push(
    "## Evidence inventory",
    "",
    "Raw evidence content is intentionally omitted from this report. The case JSON includes it and may contain private data.",
    "",
  );
  for (const entry of item.evidence)
    lines.push(
      `- ${markdown(entry.name)} — ${entry.bytes} bytes — SHA-256: ${entry.sha256} — ID: ${markdown(entry.id)}`,
    );
  lines.push(
    "",
    "## Notes",
    "",
    markdown(item.notes || "No analyst notes recorded."),
    "",
    "## Limits",
    "",
    "Review status records an analyst decision, not independent verification of remediation. This offline workspace records supplied evidence and heuristic observations. It does not execute actions, enforce permissions, establish source authenticity, verify digital signatures or prove live access revocation. Matching content hashes detect inconsistency with recorded hashes; they do not establish provenance or prevent an editor from changing both content and hashes.",
    "",
  );
  return lines.join("\n");
}

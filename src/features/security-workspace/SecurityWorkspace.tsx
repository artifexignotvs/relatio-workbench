import { useEffect, useMemo, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import {
  buildReportMarkdown,
  compareAccess,
  createCase,
  importReport,
  parseAccessSnapshot,
  parseCase,
  reviewAction,
  serializeCase,
} from "./model";
import { WORKSPACE_LIMITS } from "./types";
import type {
  ActionPlan,
  Evidence,
  Finding,
  Severity,
  WorkspaceCase,
} from "./types";
import { createDemoCase } from "./fixtures";
import { downloadText, evidenceFromFile, loadCases, saveCase } from "./storage";
import "./security-workspace.css";

type Section = "overview" | "evidence" | "actions" | "access" | "report";
type IconName =
  | Section
  | "plus"
  | "arrow"
  | "upload"
  | "download"
  | "shield"
  | "check"
  | "close"
  | "file";
const sections: { id: Section; label: string; caption: string }[] = [
  { id: "overview", label: "Overview", caption: "The whole case" },
  { id: "evidence", label: "Evidence", caption: "Files & observations" },
  { id: "actions", label: "Action review", caption: "Declared permissions" },
  { id: "access", label: "Access review", caption: "Snapshot comparison" },
  { id: "report", label: "Report", caption: "Notes & handover" },
];
const order: Severity[] = ["high", "medium", "low", "info"];
const lines = (text: string) =>
  text
    .split(/\r?\n/)
    .map((value) => value.trim())
    .filter(Boolean);
const date = (value: string) =>
  new Date(value).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
const size = (bytes: number) =>
  bytes < 1024 ? bytes + " B" : (bytes / 1024).toFixed(1) + " KB";
const stem = (title: string) =>
  title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 60) || "security-case";

function Icon({
  name,
  size: dimension = 20,
}: {
  name: IconName;
  size?: number;
}) {
  const paths: Record<IconName, ReactNode> = {
    overview: (
      <>
        <rect x="3" y="3" width="7" height="7" rx="1" />
        <rect x="14" y="3" width="7" height="7" rx="1" />
        <rect x="3" y="14" width="7" height="7" rx="1" />
        <rect x="14" y="14" width="7" height="7" rx="1" />
      </>
    ),
    evidence: (
      <>
        <path d="M4 5h6l2 3h8v12H4zM8 12h8M8 16h5" />
      </>
    ),
    actions: <path d="m4 7 5 5-5 5M12 18h8M13 5h7" />,
    access: (
      <>
        <circle cx="8" cy="7" r="3" />
        <path d="M2 20v-2a6 6 0 0 1 12 0v2M16 5h5M18.5 2.5v5M16 14h5M16 18h5" />
      </>
    ),
    report: <path d="M5 3h9l5 5v13H5zM14 3v5h5M9 12h6M9 16h6" />,
    plus: <path d="M12 5v14M5 12h14" />,
    arrow: <path d="M5 12h14m-5-5 5 5-5 5" />,
    upload: <path d="M12 16V3m-5 5 5-5 5 5M4 16v5h16v-5" />,
    download: <path d="M12 3v13m-5-5 5 5 5-5M4 18v3h16v-3" />,
    shield: <path d="m12 3 8 3v6c0 4-3 7-8 9-5-2-8-5-8-9V6zm-4 9 3 3 5-6" />,
    check: <path d="m5 12 4 4L19 6" />,
    close: <path d="m6 6 12 12M18 6 6 18" />,
    file: <path d="M5 3h9l5 5v13H5zM14 3v5h5" />,
  };
  return (
    <svg
      width={dimension}
      height={dimension}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {paths[name]}
    </svg>
  );
}
function Badge({ severity }: { severity: Severity }) {
  return (
    <span className={"sw-severity sw-severity-" + severity}>
      {severity === "info"
        ? "Info"
        : severity[0].toUpperCase() + severity.slice(1)}
    </span>
  );
}
function Boundary({ children }: { children: ReactNode }) {
  return (
    <p className="sw-boundary">
      <strong>Review boundary</strong>
      <span>{children}</span>
    </p>
  );
}
function Empty({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="sw-empty">
      <h3>{title}</h3>
      <div>{children}</div>
    </div>
  );
}

export function SecurityWorkspace() {
  const [cases, setCases] = useState<WorkspaceCase[]>([]);
  const [caseId, setCaseId] = useState("");
  const [section, setSection] = useState<Section>("overview");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [severity, setSeverity] = useState("all");
  const [source, setSource] = useState("all");
  const [query, setQuery] = useState("");
  const [findingId, setFindingId] = useState("");
  const [evidenceId, setEvidenceId] = useState("");
  const [notes, setNotes] = useState("");
  const [titleDraft, setTitleDraft] = useState("");
  const [scopeDraft, setScopeDraft] = useState("");
  const [editing, setEditing] = useState(false);
  const [command, setCommand] = useState("");
  const [readPaths, setReadPaths] = useState("");
  const [writePaths, setWritePaths] = useState("");
  const [hosts, setHosts] = useState("");
  const [shell, setShell] = useState(false);
  const [subprocesses, setSubprocesses] = useState(false);
  const [beforeFile, setBeforeFile] = useState<File | null>(null);
  const [afterFile, setAfterFile] = useState<File | null>(null);
  const [actionResult, setActionResult] = useState<number | null>(null);
  const [accessResult, setAccessResult] = useState<number | null>(null);
  const dialog = useRef<HTMLDialogElement>(null);
  const caseInput = useRef<HTMLInputElement>(null);
  const findingInput = useRef<HTMLInputElement>(null);
  const evidenceInput = useRef<HTMLInputElement>(null);
  const operationLock = useRef(false);
  const noteDrafts = useRef<Record<string, string>>(Object.create(null));
  const current = cases.find((item) => item.id === caseId);
  const sample = current?.scope.startsWith("Synthetic example") ?? false;
  const sources = useMemo(
    () =>
      [...new Set(current?.findings.map((item) => item.source) ?? [])].sort(),
    [current],
  );
  const visible = useMemo(
    () =>
      (current?.findings ?? [])
        .filter(
          (item) =>
            (severity === "all" || item.severity === severity) &&
            (source === "all" || item.source === source) &&
            (!query ||
              (item.title + " " + item.detail + " " + item.source)
                .toLowerCase()
                .includes(query.toLowerCase())),
        )
        .sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity)),
    [current, severity, source, query],
  );
  const finding = current?.findings.find((item) => item.id === findingId);
  const evidence = current?.evidence.find((item) => item.id === evidenceId);

  useEffect(() => {
    let active = true;
    async function initialize() {
      try {
        let stored = await loadCases();
        if (!active) return;
        if (!stored.length) {
          const demo = await createDemoCase();
          if (!active) return;
          await saveCase(demo);
          stored = [demo];
        }
        if (active) {
          setCases(stored);
          setCaseId(stored[0].id);
        }
      } catch (reason) {
        if (active)
          setError(
            reason instanceof Error
              ? reason.message
              : "The local workspace could not be opened.",
          );
      } finally {
        if (active) setLoading(false);
      }
    }
    void initialize();
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    setNotes(noteDrafts.current[caseId] ?? current?.notes ?? "");
    setFindingId("");
    setEvidenceId("");
    setSeverity("all");
    setSource("all");
    setQuery("");
    setActionResult(null);
    setAccessResult(null);
    setBeforeFile(null);
    setAfterFile(null);
    setCommand("");
    setReadPaths("");
    setWritePaths("");
    setHosts("");
    setShell(false);
    setSubprocesses(false);
  }, [caseId]);

  useEffect(() => {
    setActionResult(null);
  }, [command, readPaths, writePaths, hosts, shell, subprocesses]);

  // Notae nondum servatae in omnibus casibus ante discessum monentur.
  useEffect(() => {
    const unsaved = cases.some(
      (item) =>
        Object.prototype.hasOwnProperty.call(noteDrafts.current, item.id) &&
        noteDrafts.current[item.id] !== item.notes,
    );
    if (!unsaved) return;
    const warnBeforeLeaving = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", warnBeforeLeaving);
    return () => window.removeEventListener("beforeunload", warnBeforeLeaving);
  }, [cases, notes]);

  // Mutatio memoriae tantum post transactionem felicem ostenditur.
  async function persist(next: WorkspaceCase) {
    const previous = cases.find((item) => item.id === next.id);
    const updated = {
      ...next,
      updatedAt: new Date(
        Math.max(
          Date.now(),
          Date.parse(previous?.updatedAt ?? next.createdAt) + 1,
        ),
      ).toISOString(),
    };
    await saveCase(updated, previous?.updatedAt);
    setCases((previous) => [
      updated,
      ...previous.filter((item) => item.id !== updated.id),
    ]);
  }
  async function task(label: string, action: () => Promise<void>) {
    if (operationLock.current) return;
    operationLock.current = true;
    setBusy(label);
    setError("");
    setNotice("");
    try {
      await action();
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "The operation could not be completed. The saved case has been kept.",
      );
    } finally {
      operationLock.current = false;
      setBusy("");
    }
  }
  function openCase(edit = false) {
    setEditing(edit);
    setTitleDraft(edit && current ? current.title : "");
    setScopeDraft(edit && current ? current.scope : "");
    dialog.current?.showModal();
  }
  function submitCase(event: FormEvent) {
    event.preventDefault();
    void task(editing ? "Saving case" : "Creating case", async () => {
      const next =
        editing && current
          ? { ...current, title: titleDraft.trim(), scope: scopeDraft.trim() }
          : createCase(titleDraft.trim(), scopeDraft.trim());
      await persist(next);
      setCaseId(next.id);
      dialog.current?.close();
      setNotice(
        editing
          ? "Case details saved locally."
          : "Case created. Add evidence or start a review.",
      );
    });
  }
  function importFiles(files: FileList | null, withFindings: boolean) {
    if (!current || !files?.length) return;
    const selected = Array.from(files);
    void task(
      withFindings ? "Importing findings" : "Adding evidence",
      async () => {
        if (
          current.evidence.length + selected.length >
          WORKSPACE_LIMITS.evidenceCount
        )
          throw new Error("A case supports up to 50 evidence files.");
        if (selected.some((file) => file.size > WORKSPACE_LIMITS.evidenceBytes))
          throw new Error("Each evidence file must be 2 MB or smaller.");
        const totalBytes =
          current.evidence.reduce((total, item) => total + item.bytes, 0) +
          selected.reduce((total, file) => total + file.size, 0);
        if (totalBytes > WORKSPACE_LIMITS.evidenceTotalBytes)
          throw new Error(
            "The combined evidence exceeds the 16 MB case limit.",
          );
        const added: Evidence[] = [];
        const findings: Finding[] = [];
        for (const file of selected) {
          const record = await evidenceFromFile(file);
          if (withFindings) {
            const imported = importReport(
              record.content,
              record.name,
              record.id,
            );
            if (
              current.findings.length + findings.length + imported.length >
              WORKSPACE_LIMITS.findingsCount
            )
              throw new Error("A case supports up to 1,000 findings.");
            findings.push(...imported);
          }
          added.push(record);
        }
        await persist({
          ...current,
          evidence: [...current.evidence, ...added],
          findings: [...current.findings, ...findings],
        });
        setNotice(
          added.length +
            " file(s) saved" +
            (withFindings
              ? " with " + findings.length + " imported findings."
              : " as evidence."),
        );
        setSection(withFindings ? "overview" : "evidence");
      },
    );
  }
  function importCase(file?: File) {
    if (!file) return;
    void task("Importing case", async () => {
      if (file.size > WORKSPACE_LIMITS.caseBytes)
        throw new Error("Case file exceeds the supported size limit.");
      const bytes = await file.arrayBuffer();
      if (bytes.byteLength > WORKSPACE_LIMITS.caseBytes)
        throw new Error("Case file exceeds the supported size limit.");
      let text: string;
      try {
        text = new TextDecoder("utf-8", {
          fatal: true,
          ignoreBOM: true,
        }).decode(bytes);
      } catch {
        throw new Error("Case files must contain valid UTF-8 text.");
      }
      const parsed = await parseCase(text);
      if (cases.some((item) => item.id === parsed.id))
        throw new Error(
          "This case already exists in the workspace. Your existing copy has been kept.",
        );
      await persist(parsed);
      setCaseId(parsed.id);
      setSection("overview");
      setNotice(
        "Case imported. Included evidence digests were checked against their contents.",
      );
    });
  }
  function submitAction(event: FormEvent) {
    event.preventDefault();
    if (!current) return;
    void task("Reviewing declared action", async () => {
      const plan: ActionPlan = {
        command: command.trim(),
        readPaths: lines(readPaths),
        writePaths: lines(writePaths),
        networkHosts: lines(hosts),
        allowShell: shell,
        allowSubprocesses: subprocesses,
      };
      const reviewed = reviewAction(plan);
      const record = await evidenceFromFile(
        new File(
          [JSON.stringify(plan, null, 2)],
          "action-plan-" + Date.now() + ".json",
          { type: "application/json" },
        ),
      );
      record.kind = "action-plan";
      const findings = reviewed.map((item) => ({
        ...item,
        evidenceIds: [record.id],
      }));
      await persist({
        ...current,
        evidence: [...current.evidence, record],
        findings: [...current.findings, ...findings],
      });
      setActionResult(findings.length);
      setNotice("Review saved with its input. No command was executed.");
    });
  }
  function submitAccess(event: FormEvent) {
    event.preventDefault();
    if (!current || !beforeFile || !afterFile) return;
    void task("Comparing snapshots", async () => {
      const before = await evidenceFromFile(beforeFile);
      const after = await evidenceFromFile(afterFile);
      const findings = compareAccess(
        parseAccessSnapshot(before.content),
        parseAccessSnapshot(after.content),
      ).map((item) => ({ ...item, evidenceIds: [before.id, after.id] }));
      before.kind = "access-before";
      after.kind = "access-after";
      await persist({
        ...current,
        evidence: [...current.evidence, before, after],
        findings: [...current.findings, ...findings],
      });
      setAccessResult(findings.length);
      setNotice("Comparison saved with both source snapshots.");
    });
  }
  function exportCase(report: boolean) {
    if (!current) return;
    try {
      if (notes !== current.notes)
        throw new Error(
          "Save your analyst notes before exporting the case or report.",
        );
      downloadText(
        stem(current.title) + (report ? "-report.md" : ".json"),
        report ? buildReportMarkdown(current) : serializeCase(current),
        report ? "text/markdown;charset=utf-8" : "application/json",
      );
      setNotice(
        report
          ? "Markdown report download prepared."
          : "Case download prepared, including evidence contents.",
      );
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "The export could not be prepared.",
      );
    }
  }
  function showFindings(reviewSource: string) {
    setSource(reviewSource);
    setSeverity("all");
    setQuery("");
    setSection("overview");
  }
  function showEvidence(id: string) {
    setEvidenceId(id);
    setSection("evidence");
  }
  const sectionHeading =
    section === "evidence"
      ? "Evidence register"
      : section === "actions"
        ? "Declared action review"
        : section === "access"
          ? "Access comparison"
          : "Case report";
  const sectionDescription =
    section === "evidence"
      ? "Keep source files and observations connected to every finding."
      : section === "actions"
        ? "Inspect the permissions declared for a proposed developer or agent action."
        : section === "access"
          ? "Compare two supplied access snapshots within this case."
          : "Capture your reasoning and export a readable handover.";

  return (
    <div className="security-workspace">
      <a className="sw-skip" href="#sw-main">
        Skip to workspace
      </a>
      <aside className="sw-sidebar">
        <div className="sw-brand">
          <strong>RELATIO WORKBENCH</strong>
          <span lang="la">Quaere. Examina. Proba.</span>
        </div>
        <div className="sw-side-section">
          <span className="sw-overline">Case sections</span>
          <nav aria-label="Workspace sections">
            {sections.map((item) => (
              <button
                type="button"
                key={item.id}
                className={
                  "sw-nav-item " + (section === item.id ? "is-active" : "")
                }
                aria-current={section === item.id ? "page" : undefined}
                onClick={() => setSection(item.id)}
              >
                <span>{item.label}</span>
              </button>
            ))}
          </nav>
        </div>
      </aside>
      <div className="sw-body">
        <header className="sw-topbar">
          <div className="sw-breadcrumb">
            Casebook <span>/</span>{" "}
            <strong>
              {sections.find((item) => item.id === section)?.label}
            </strong>
          </div>
          <div className="sw-top-actions">
            <span className="sw-local-label">Browser session</span>
            <button
              className="sw-button sw-button-quiet"
              type="button"
              onClick={() => caseInput.current?.click()}
              disabled={Boolean(busy) || loading}
            >
              <Icon name="upload" size={16} />
              Import case
            </button>
            <button
              className="sw-button sw-button-dark"
              type="button"
              onClick={() => openCase()}
              disabled={Boolean(busy) || loading}
            >
              <Icon name="plus" size={16} />
              New case
            </button>
          </div>
        </header>
        <input
          ref={caseInput}
          className="sw-hidden-input"
          type="file"
          accept=".json,application/json"
          aria-label="Import case JSON"
          onChange={(event) => {
            importCase(event.currentTarget.files?.[0]);
            event.currentTarget.value = "";
          }}
        />
        <input
          ref={findingInput}
          className="sw-hidden-input"
          type="file"
          accept=".json,application/json"
          multiple
          aria-label="Import findings JSON"
          onChange={(event) => {
            importFiles(event.currentTarget.files, true);
            event.currentTarget.value = "";
          }}
        />
        <input
          ref={evidenceInput}
          className="sw-hidden-input"
          type="file"
          accept=".json,.txt,.md,.csv,.log,.html,application/json,text/*"
          multiple
          aria-label="Add evidence files"
          onChange={(event) => {
            importFiles(event.currentTarget.files, false);
            event.currentTarget.value = "";
          }}
        />
        <main id="sw-main" className="sw-main">
          {error && (
            <div className="sw-alert sw-alert-error" role="alert">
              <strong>Action needs attention</strong>
              <span>{error}</span>
              <button
                type="button"
                aria-label="Dismiss error"
                onClick={() => setError("")}
              >
                <Icon name="close" size={16} />
              </button>
            </div>
          )}
          <div aria-live="polite" aria-atomic="true">
            {busy ? (
              <div className="sw-alert sw-alert-status">
                <span className="sw-spinner" />
                {busy}…
              </div>
            ) : (
              notice && (
                <div className="sw-alert sw-alert-success">
                  <Icon name="check" size={17} />
                  <span>{notice}</span>
                  <button
                    type="button"
                    aria-label="Dismiss notification"
                    onClick={() => setNotice("")}
                  >
                    <Icon name="close" size={16} />
                  </button>
                </div>
              )
            )}
          </div>
          {loading ? (
            <div className="sw-loading">
              <span className="sw-spinner" />
              <p>Opening your local workspace…</p>
            </div>
          ) : !current ? (
            <Empty title="Start with a question">
              <p>
                Create a case to bring evidence, permission reviews and access
                changes into one place.
              </p>
              <button
                className="sw-button sw-button-primary"
                type="button"
                onClick={() => openCase()}
              >
                Create your first case
              </button>
            </Empty>
          ) : (
            <>
              <div className="sw-case-bar">
                <div>
                  <label htmlFor="sw-case-select">Current case</label>
                  <select
                    id="sw-case-select"
                    value={caseId}
                    disabled={Boolean(busy)}
                    onChange={(event) => {
                      setCaseId(event.target.value);
                      setNotice("");
                    }}
                  >
                    {cases.map((item) => (
                      <option key={item.id} value={item.id}>
                        {item.title}
                      </option>
                    ))}
                  </select>
                </div>
                <span>Saved {date(current.updatedAt)}</span>
                {sample && (
                  <span className="sw-sample-badge">[ Synthetic sample ]</span>
                )}
              </div>
              <section className="sw-heading">
                <div>
                  <span className="sw-overline">
                    {section === "overview"
                      ? "Case file"
                      : sections.find((item) => item.id === section)?.label}
                  </span>
                  <h1>
                    {section === "overview" ? current.title : sectionHeading}
                  </h1>
                  <p>
                    {section === "overview"
                      ? current.scope
                      : sectionDescription}
                  </p>
                </div>
                <div className="sw-heading-action">
                  {section === "overview" ? (
                    <button
                      className="sw-button sw-button-outline"
                      type="button"
                      onClick={() => openCase(true)}
                      disabled={Boolean(busy)}
                    >
                      Edit case
                    </button>
                  ) : null}
                </div>
              </section>
              {sample && (
                <div className="sw-sample-note">
                  <span>
                    <strong>Example case.</strong> The initial example is
                    fictional. Files you add later may contain real evidence.
                    Create a fresh case for your own review.
                  </span>
                  <button
                    type="button"
                    onClick={() => openCase()}
                    disabled={Boolean(busy)}
                  >
                    Start a case <Icon name="arrow" size={15} />
                  </button>
                </div>
              )}

              {section === "overview" && (
                <>
                  <dl className="sw-case-ledger">
                    <div>
                      <dt>Recorded findings</dt>
                      <dd>{current.findings.length}</dd>
                      <span>Imported or locally reviewed</span>
                    </div>
                    <div>
                      <dt>High severity</dt>
                      <dd>
                        {
                          current.findings.filter(
                            (item) => item.severity === "high",
                          ).length
                        }
                      </dd>
                      <span>Review in context</span>
                    </div>
                    <div>
                      <dt>Evidence files</dt>
                      <dd>{current.evidence.length}</dd>
                      <span>Content + SHA-256 digest</span>
                    </div>
                    <div>
                      <dt>Review sources</dt>
                      <dd>{sources.length}</dd>
                      <span>Connected to this case</span>
                    </div>
                  </dl>
                  <div className="sw-workflow-strip">
                    <span className="sw-overline">Add to this case</span>
                    <button
                      type="button"
                      onClick={() => findingInput.current?.click()}
                      disabled={Boolean(busy)}
                    >
                      <span>
                        Import findings<small>Supported tool reports</small>
                      </span>
                      <Icon name="arrow" size={16} />
                    </button>
                    <button type="button" onClick={() => setSection("actions")}>
                      <span>
                        Review an action<small>Declared permissions</small>
                      </span>
                      <Icon name="arrow" size={16} />
                    </button>
                    <button type="button" onClick={() => setSection("access")}>
                      <span>
                        Compare access<small>Before and after</small>
                      </span>
                      <Icon name="arrow" size={16} />
                    </button>
                  </div>
                  <section className="sw-panel">
                    <div className="sw-panel-heading">
                      <div>
                        <h2>
                          Findings{" "}
                          <span className="sw-count">
                            {current.findings.length}
                          </span>
                        </h2>
                        <p>
                          A finding is an observation to review, not a final
                          verdict.
                        </p>
                      </div>
                      <span className="sw-subtle-label">
                        Source judgments preserved
                      </span>
                    </div>
                    <div className="sw-filters">
                      <label className="sw-search">
                        <span className="sw-sr-only">Search findings</span>
                        <input
                          type="search"
                          placeholder="Search findings…"
                          value={query}
                          onChange={(event) => setQuery(event.target.value)}
                        />
                      </label>
                      <label>
                        <span className="sw-sr-only">Filter by severity</span>
                        <select
                          value={severity}
                          onChange={(event) => setSeverity(event.target.value)}
                        >
                          <option value="all">All severities</option>
                          {order.map((item) => (
                            <option key={item} value={item}>
                              {item[0].toUpperCase() + item.slice(1)}
                            </option>
                          ))}
                        </select>
                      </label>
                      <label>
                        <span className="sw-sr-only">Filter by source</span>
                        <select
                          value={source}
                          onChange={(event) => setSource(event.target.value)}
                        >
                          <option value="all">All sources</option>
                          {sources.map((item) => (
                            <option key={item} value={item}>
                              {item}
                            </option>
                          ))}
                        </select>
                      </label>
                      <span>{visible.length} shown</span>
                    </div>
                    {visible.length ? (
                      <div className="sw-table-scroll">
                        <table className="sw-findings-table">
                          <thead>
                            <tr>
                              <th>Severity</th>
                              <th>Finding</th>
                              <th>Source</th>
                              <th>Evidence</th>
                              <th>
                                <span className="sw-sr-only">Details</span>
                              </th>
                            </tr>
                          </thead>
                          <tbody>
                            {visible.map((item) => (
                              <tr
                                key={item.id}
                                className={
                                  findingId === item.id ? "is-selected" : ""
                                }
                              >
                                <td>
                                  <Badge severity={item.severity} />
                                </td>
                                <td>
                                  <button
                                    className="sw-finding-title"
                                    type="button"
                                    onClick={() =>
                                      setFindingId(
                                        findingId === item.id ? "" : item.id,
                                      )
                                    }
                                    aria-expanded={findingId === item.id}
                                  >
                                    {item.title}
                                  </button>
                                </td>
                                <td>
                                  <span className="sw-source">
                                    {item.source}
                                  </span>
                                </td>
                                <td>
                                  <span className="sw-evidence-count">
                                    <Icon name="file" size={14} />
                                    {item.evidenceIds.length}
                                  </span>
                                </td>
                                <td>
                                  <button
                                    className="sw-icon-button"
                                    type="button"
                                    aria-label={"View finding: " + item.title}
                                    onClick={() => setFindingId(item.id)}
                                  >
                                    <Icon name="arrow" size={16} />
                                  </button>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <Empty
                        title={
                          current.findings.length
                            ? "No matching findings"
                            : "No findings recorded yet"
                        }
                      >
                        <p>
                          {current.findings.length
                            ? "Adjust the filters to see more of the case."
                            : "Import a supported report or run a review. An empty list does not establish that a system is secure."}
                        </p>
                      </Empty>
                    )}
                  </section>
                  {finding && (
                    <section className="sw-panel sw-finding-detail">
                      <div className="sw-panel-heading">
                        <div>
                          <span className="sw-overline">Finding detail</span>
                          <h2>{finding.title}</h2>
                        </div>
                        <button
                          className="sw-icon-button"
                          type="button"
                          aria-label="Close finding detail"
                          onClick={() => setFindingId("")}
                        >
                          <Icon name="close" />
                        </button>
                      </div>
                      <div className="sw-detail-meta">
                        <Badge severity={finding.severity} />
                        <span>{finding.source}</span>
                      </div>
                      <div className="sw-detail-columns">
                        <div>
                          <h3>Observation</h3>
                          <p>{finding.detail}</p>
                        </div>
                        <div>
                          <h3>Suggested next step</h3>
                          <p>
                            {finding.recommendation ||
                              "Review the source evidence and document your assessment."}
                          </p>
                        </div>
                      </div>
                      <div className="sw-linked-evidence">
                        <span>Linked evidence</span>
                        {finding.evidenceIds.length ? (
                          finding.evidenceIds.map((id) => (
                            <button
                              type="button"
                              key={id}
                              onClick={() => showEvidence(id)}
                            >
                              <Icon name="file" size={15} />
                              {current.evidence.find((item) => item.id === id)
                                ?.name ?? "Evidence record"}
                              <Icon name="arrow" size={14} />
                            </button>
                          ))
                        ) : (
                          <small>
                            No source file linked to this observation.
                          </small>
                        )}
                      </div>
                    </section>
                  )}
                </>
              )}

              {section === "evidence" && (
                <>
                  <div className="sw-upload-grid">
                    <div className="sw-panel sw-upload-card">
                      <h2>Import tool findings</h2>
                      <p>
                        Bring JSON reports from Limen, Vallum, Lucerna or
                        Vestigium into this case. The original report is
                        retained.
                      </p>
                      <button
                        className="sw-button sw-button-primary"
                        type="button"
                        onClick={() => findingInput.current?.click()}
                        disabled={Boolean(busy)}
                      >
                        Choose JSON reports <Icon name="arrow" size={16} />
                      </button>
                      <small>Supported schemas · UTF-8 · 2 MB per file</small>
                    </div>
                    <div className="sw-panel sw-upload-card">
                      <h2>Add supporting evidence</h2>
                      <p>
                        Keep logs, notes, JSON or other text files beside the
                        analysis. Uploaded files are stored as text and never
                        executed.
                      </p>
                      <button
                        className="sw-button sw-button-outline"
                        type="button"
                        onClick={() => evidenceInput.current?.click()}
                        disabled={Boolean(busy)}
                      >
                        Choose text files <Icon name="plus" size={16} />
                      </button>
                      <small>UTF-8 text only · 2 MB per file</small>
                    </div>
                  </div>
                  <Boundary>
                    SHA-256 records the integrity of the bytes you supply. A
                    digest does not establish authenticity, authorship or a
                    chain of custody.
                  </Boundary>
                  <section className="sw-panel">
                    <div className="sw-panel-heading">
                      <div>
                        <h2>
                          Evidence register{" "}
                          <span className="sw-count">
                            {current.evidence.length}
                          </span>
                        </h2>
                        <p>
                          Source files remain attached when you export the case.
                        </p>
                      </div>
                    </div>
                    {current.evidence.length ? (
                      <div className="sw-evidence-list">
                        {current.evidence.map((item) => (
                          <article
                            key={item.id}
                            className={
                              "sw-evidence-item " +
                              (evidenceId === item.id ? "is-selected" : "")
                            }
                          >
                            <div className="sw-evidence-info">
                              <button
                                type="button"
                                onClick={() =>
                                  setEvidenceId(
                                    evidenceId === item.id ? "" : item.id,
                                  )
                                }
                                aria-expanded={evidenceId === item.id}
                              >
                                {item.name}
                              </button>
                              <span>
                                {size(item.bytes)} · {item.kind} ·{" "}
                                {date(item.addedAt)}
                              </span>
                              <code>SHA-256 {item.sha256}</code>
                            </div>
                            <button
                              className="sw-button sw-button-small sw-button-quiet"
                              type="button"
                              onClick={() =>
                                setEvidenceId(
                                  evidenceId === item.id ? "" : item.id,
                                )
                              }
                            >
                              {evidenceId === item.id ? "Close" : "Inspect"}
                            </button>
                          </article>
                        ))}
                      </div>
                    ) : (
                      <Empty title="The evidence register is empty">
                        <p>
                          Add a source file or run a review to keep its input in
                          this case.
                        </p>
                      </Empty>
                    )}
                  </section>
                  {evidence && (
                    <section className="sw-panel sw-evidence-preview">
                      <div className="sw-panel-heading">
                        <div>
                          <span className="sw-overline">
                            Read-only text preview
                          </span>
                          <h2>{evidence.name}</h2>
                        </div>
                        <button
                          className="sw-icon-button"
                          type="button"
                          aria-label="Close evidence preview"
                          onClick={() => setEvidenceId("")}
                        >
                          <Icon name="close" />
                        </button>
                      </div>
                      <pre>{evidence.content.slice(0, 24000)}</pre>
                      {evidence.content.length > 24000 && (
                        <p className="sw-preview-limit">
                          Preview limited to 24,000 characters. The full file is
                          retained in the case export.
                        </p>
                      )}
                    </section>
                  )}
                </>
              )}

              {section === "actions" && (
                <div className="sw-review-grid">
                  <section className="sw-panel sw-form-panel">
                    <div className="sw-panel-heading">
                      <div>
                        <h2>Declared action</h2>
                        <p>
                          Describe the command and permissions proposed for it.
                        </p>
                      </div>
                    </div>
                    <form onSubmit={submitAction}>
                      <fieldset
                        className="sw-form-lock"
                        disabled={Boolean(busy)}
                      >
                        <label className="sw-field">
                          Proposed command
                          <textarea
                            value={command}
                            onChange={(event) => setCommand(event.target.value)}
                            required
                            maxLength={8000}
                            rows={3}
                            placeholder="Example: python scripts/check.py"
                            spellCheck={false}
                          />
                          <small>
                            The command is treated as text. It will not run.
                          </small>
                        </label>
                        <div className="sw-form-columns">
                          <label className="sw-field">
                            Readable paths
                            <textarea
                              value={readPaths}
                              onChange={(event) =>
                                setReadPaths(event.target.value)
                              }
                              rows={4}
                              maxLength={20000}
                              placeholder="/workspace/project"
                              spellCheck={false}
                            />
                            <small>One declared path per line</small>
                          </label>
                          <label className="sw-field">
                            Writable paths
                            <textarea
                              value={writePaths}
                              onChange={(event) =>
                                setWritePaths(event.target.value)
                              }
                              rows={4}
                              maxLength={20000}
                              placeholder="/workspace/project/reports"
                              spellCheck={false}
                            />
                            <small>One declared path per line</small>
                          </label>
                        </div>
                        <label className="sw-field">
                          Network hosts
                          <textarea
                            value={hosts}
                            onChange={(event) => setHosts(event.target.value)}
                            rows={3}
                            maxLength={12000}
                            placeholder="Leave empty when no network access is declared"
                            spellCheck={false}
                          />
                          <small>
                            One host per line. No hosts are contacted.
                          </small>
                        </label>
                        <div className="sw-check-options">
                          <label>
                            <input
                              type="checkbox"
                              checked={shell}
                              onChange={(event) =>
                                setShell(event.target.checked)
                              }
                            />
                            <span>
                              Shell access allowed
                              <small>
                                The proposed permissions include a shell.
                              </small>
                            </span>
                          </label>
                          <label>
                            <input
                              type="checkbox"
                              checked={subprocesses}
                              onChange={(event) =>
                                setSubprocesses(event.target.checked)
                              }
                            />
                            <span>
                              Subprocesses allowed
                              <small>
                                The proposed permissions allow child processes.
                              </small>
                            </span>
                          </label>
                        </div>
                        <Boundary>
                          This is a preflight review of declared inputs. It does
                          not execute commands, enforce permissions or block an
                          agent at runtime.
                        </Boundary>
                        <div className="sw-form-footer">
                          <span>Input + findings saved to this case</span>
                          <button
                            className="sw-button sw-button-primary"
                            type="submit"
                            disabled={Boolean(busy)}
                          >
                            Review declared action{" "}
                            <Icon name="arrow" size={16} />
                          </button>
                        </div>
                      </fieldset>
                    </form>
                  </section>
                  <aside className="sw-review-aside">
                    <div className="sw-aside-note">
                      <span className="sw-overline">Review notes</span>
                      <h2>Scope before execution.</h2>
                      <p>
                        Broad write access, unrestricted hosts and shell
                        permissions deserve a deliberate review before an action
                        proceeds.
                      </p>
                      <div className="sw-rule-line" />
                      <h3>What is retained</h3>
                      <ul>
                        <li>The exact declared action</li>
                        <li>A digest of the saved input</li>
                        <li>Findings linked to that input</li>
                      </ul>
                    </div>
                    {actionResult !== null && (
                      <div className="sw-result-card" role="status">
                        <h3>Review recorded</h3>
                        <p>
                          {actionResult} finding(s) attached to the case. Review
                          their details and limits before drawing conclusions.
                        </p>
                        <button
                          className="sw-button sw-button-outline"
                          type="button"
                          onClick={() => showFindings("action-review")}
                        >
                          View action findings <Icon name="arrow" size={15} />
                        </button>
                      </div>
                    )}
                  </aside>
                </div>
              )}

              {section === "access" && (
                <div className="sw-review-grid">
                  <section className="sw-panel sw-form-panel">
                    <div className="sw-panel-heading">
                      <div>
                        <h2>Compare access snapshots</h2>
                        <p>
                          Choose two JSON files containing declared access
                          records.
                        </p>
                      </div>
                    </div>
                    <form onSubmit={submitAccess}>
                      <fieldset
                        className="sw-form-lock"
                        disabled={Boolean(busy)}
                      >
                        <div className="sw-snapshot-grid">
                          <label className="sw-snapshot-upload">
                            <strong>Before</strong>
                            <span>The earlier access snapshot</span>
                            <input
                              type="file"
                              accept=".json,application/json"
                              required
                              onChange={(event) => {
                                setBeforeFile(event.target.files?.[0] ?? null);
                                setAccessResult(null);
                              }}
                              key={"before-" + caseId}
                            />
                            <small>
                              {beforeFile
                                ? beforeFile.name +
                                  " · " +
                                  size(beforeFile.size)
                                : "Select a JSON file · up to 2 MB"}
                            </small>
                          </label>
                          <span className="sw-snapshot-arrow">
                            <Icon name="arrow" />
                          </span>
                          <label className="sw-snapshot-upload">
                            <strong>After</strong>
                            <span>The later access snapshot</span>
                            <input
                              type="file"
                              accept=".json,application/json"
                              required
                              onChange={(event) => {
                                setAfterFile(event.target.files?.[0] ?? null);
                                setAccessResult(null);
                              }}
                              key={"after-" + caseId}
                            />
                            <small>
                              {afterFile
                                ? afterFile.name + " · " + size(afterFile.size)
                                : "Select a JSON file · up to 2 MB"}
                            </small>
                          </label>
                        </div>
                        <div className="sw-schema-example">
                          <h3>Expected JSON shape</h3>
                          <p>
                            An array of exact principal, resource and permission
                            values.
                          </p>
                          <pre>
                            {JSON.stringify(
                              [
                                {
                                  principal: "analyst@example.test",
                                  resource: "reports",
                                  permission: "read",
                                },
                              ],
                              null,
                              2,
                            )}
                          </pre>
                        </div>
                        <Boundary>
                          Differences describe only the supplied snapshots. A
                          removed entry does not prove that access was revoked
                          in a live system.
                        </Boundary>
                        <div className="sw-form-footer">
                          <span>Both source files retained</span>
                          <button
                            className="sw-button sw-button-primary"
                            type="submit"
                            disabled={
                              Boolean(busy) || !beforeFile || !afterFile
                            }
                          >
                            Compare snapshots <Icon name="arrow" size={16} />
                          </button>
                        </div>
                      </fieldset>
                    </form>
                  </section>
                  <aside className="sw-review-aside">
                    <div className="sw-aside-note">
                      <span className="sw-overline">Review notes</span>
                      <h2>Two snapshots. One comparison.</h2>
                      <p>
                        Compare records by principal, resource and permission.
                        Keep the original snapshots beside the resulting
                        observations.
                      </p>
                      <div className="sw-rule-line" />
                      <h3>Before you compare</h3>
                      <ul>
                        <li>Use the same scope for both files.</li>
                        <li>Check who collected each snapshot.</li>
                        <li>Record timing and gaps in case notes.</li>
                      </ul>
                    </div>
                    {accessResult !== null && (
                      <div className="sw-result-card" role="status">
                        <h3>Comparison recorded</h3>
                        <p>
                          {accessResult} observation(s) attached to the case,
                          with both source files.
                        </p>
                        <button
                          className="sw-button sw-button-outline"
                          type="button"
                          onClick={() => showFindings("access-diff")}
                        >
                          View access findings <Icon name="arrow" size={15} />
                        </button>
                      </div>
                    )}
                  </aside>
                </div>
              )}

              {section === "report" && (
                <>
                  <div className="sw-report-grid">
                    <section className="sw-panel sw-form-panel">
                      <div className="sw-panel-heading">
                        <div>
                          <h2>Analyst notes</h2>
                          <p>
                            Capture context, uncertainty and next steps for this
                            case.
                          </p>
                        </div>
                        {notes !== current.notes && (
                          <span className="sw-unsaved">Unsaved changes</span>
                        )}
                      </div>
                      <label className="sw-field">
                        <span className="sw-sr-only">Analyst notes</span>
                        <textarea
                          disabled={Boolean(busy)}
                          value={notes}
                          onChange={(event) => {
                            noteDrafts.current[caseId] = event.target.value;
                            setNotes(event.target.value);
                          }}
                          maxLength={WORKSPACE_LIMITS.textLength}
                          rows={13}
                          placeholder="What was reviewed? What remains uncertain? What should happen next?"
                        />
                      </label>
                      <div className="sw-notes-footer">
                        <span>Saved notes appear in the report.</span>
                        <button
                          className="sw-button sw-button-primary"
                          type="button"
                          disabled={Boolean(busy) || notes === current.notes}
                          onClick={() =>
                            void task("Saving notes", async () => {
                              await persist({ ...current, notes });
                              delete noteDrafts.current[caseId];
                              setNotice("Analyst notes saved locally.");
                            })
                          }
                        >
                          Save notes <Icon name="check" size={16} />
                        </button>
                      </div>
                    </section>
                    <aside className="sw-report-exports">
                      <div className="sw-panel sw-export-card">
                        <h2>Readable report</h2>
                        <p>
                          Case scope, findings, evidence digests and saved notes
                          in a portable Markdown document.
                        </p>
                        <button
                          className="sw-button sw-button-primary"
                          type="button"
                          disabled={Boolean(busy) || notes !== current.notes}
                          onClick={() => exportCase(true)}
                        >
                          <Icon name="download" size={16} />
                          Download report
                        </button>
                        {notes !== current.notes && (
                          <small className="sw-unsaved-note">
                            Save your notes to include the latest edits.
                          </small>
                        )}
                      </div>
                      <div className="sw-panel sw-export-card sw-export-secondary">
                        <h2>Complete case backup</h2>
                        <p>
                          Export JSON to move or restore the case, including the
                          full contents of its evidence files.
                        </p>
                        <button
                          className="sw-button sw-button-outline"
                          type="button"
                          disabled={Boolean(busy) || notes !== current.notes}
                          onClick={() => exportCase(false)}
                        >
                          <Icon name="download" size={16} />
                          Export case JSON
                        </button>
                      </div>
                    </aside>
                  </div>
                  <Boundary>
                    Local storage is not encrypted by this workspace. Save notes
                    before exporting. Case exports contain evidence contents;
                    review them before sharing. Keep a backup before clearing
                    browser data.
                  </Boundary>
                  <section className="sw-panel sw-report-preview">
                    <div className="sw-panel-heading">
                      <div>
                        <span className="sw-overline">Report preview</span>
                        <h2>Saved report contents</h2>
                      </div>
                      <span className="sw-subtle-label">
                        Plain Markdown · saved content
                      </span>
                    </div>
                    <pre>{buildReportMarkdown(current)}</pre>
                  </section>
                </>
              )}
            </>
          )}
        </main>
      </div>
      <dialog ref={dialog} className="sw-dialog">
        <form onSubmit={submitCase}>
          <fieldset className="sw-form-lock" disabled={Boolean(busy)}>
            <div className="sw-dialog-heading">
              <span className="sw-overline">
                {editing ? "Case details" : "A new investigation"}
              </span>
              <button
                className="sw-icon-button"
                type="button"
                aria-label="Close case dialog"
                onClick={() => dialog.current?.close()}
                disabled={Boolean(busy)}
              >
                <Icon name="close" />
              </button>
            </div>
            <h2>
              {editing ? "Define the review." : "Start with a clear scope."}
            </h2>
            <p>
              Bring evidence, action reviews and access changes into one case.
            </p>
            <label className="sw-field">
              Case title
              <input
                autoFocus
                value={titleDraft}
                onChange={(event) => setTitleDraft(event.target.value)}
                required
                maxLength={160}
                placeholder="Example: Deployment access review"
              />
            </label>
            <label className="sw-field">
              Scope
              <textarea
                value={scopeDraft}
                onChange={(event) => setScopeDraft(event.target.value)}
                required
                maxLength={4000}
                rows={4}
                placeholder="What are you reviewing, and what is outside the scope?"
              />
            </label>
            {error && (
              <p className="sw-dialog-error" role="alert">
                {error}
              </p>
            )}
            <div className="sw-dialog-actions">
              <button
                className="sw-button sw-button-outline"
                type="button"
                onClick={() => dialog.current?.close()}
                disabled={Boolean(busy)}
              >
                Cancel
              </button>
              <button
                className="sw-button sw-button-primary"
                type="submit"
                disabled={Boolean(busy)}
              >
                {busy
                  ? "Saving…"
                  : editing
                    ? "Save case details"
                    : "Create case"}
                <Icon name="arrow" size={16} />
              </button>
            </div>
          </fieldset>
        </form>
      </dialog>
    </div>
  );
}
export default SecurityWorkspace;

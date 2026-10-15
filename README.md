# Relatio Workbench

**One case. Traceable evidence. A report you can inspect.**

Relatio is a local workspace for cybersecurity, OSINT, software development and defensive security. Bring a tool report, review a proposed action, compare access snapshots and keep the results in the same investigation.

**Quaere. Examina. Proba.**

**Version 0.2.0** adds encrypted case backups, EXCUBITOR alert imports and finding triage.

## What you can do

| Work | Result |
| --- | --- |
| Import supported security-tool JSON and EXCUBITOR JSON/JSONL | Findings linked to the exact imported file and its SHA-256 digest |
| Review a declared tool or agent action | Explainable observations about the command and requested file, process and network permissions |
| Compare access snapshots | Added and removed principal/resource/permission tuples |
| Keep an investigation together | Scope, notes, source evidence, findings and recommendations in one case |
| Export and reopen a case | An encrypted or plaintext portable backup with evidence digests checked on import |
| Triage findings | Open, acknowledged or resolved status with a saved analyst note |
| Write a report | A Markdown report with scope, findings, recommendations and an evidence index |

The included example uses fictional identities and a real offline HTTP-header report against synthetic input. It is clearly marked as sample data.

## Run locally

Use Node.js 24.18 or a later Node.js 24 release:

```sh
npm ci
npm run build
npm run preview
```

Open **http://127.0.0.1:5188**. The server listens on loopback. No account, credentials, database server or external connector is required.

For development, use `npm run dev`. Run `npm test` for the model and evidence-boundary tests, and `npm run typecheck` for TypeScript checks.

## A first investigation

1. Open the labelled example to see a completed case, or create a case with a title and explicit scope.
2. Import a supported JSON report or EXCUBITOR JSONL stream in Evidence. Other UTF-8 text files can be retained as evidence without becoming findings.
3. In Action review, describe the proposed command and its requested permissions. Review the observations before deciding what to run elsewhere.
4. In Access review, select before/after JSON snapshots. Keep the identity source, observation time and coverage limits in your notes.
5. Open a finding, select its review status, add an analyst note and save the review. Filter by review state to prepare a handover.
6. Save case notes, export the Markdown report, and choose an encrypted or plaintext case backup.

Example inputs live in [`examples/`](examples/). Access snapshots may be a bare array or an object with `schema_version: 1` and a `records` array of `{ "principal", "resource", "permission" }` objects. Use consistent, case-sensitive identifiers in both snapshots.

## Evidence and privacy

Processing happens in the browser after the local application loads. The production preview blocks application network connections. There are no external fonts, analytics, remote model calls or automatic URL lookups.

Cases are stored in this browser's IndexedDB, which is **not encrypted by this application**. The default backup choice is encrypted; plaintext JSON and Markdown reports remain readable. Complete backups include original evidence text. Use an appropriate browser profile and review plaintext exports before sharing them. Clearing browser storage removes the local copy; keep downloaded backups.

### Protected backups

In Report, choose **Encrypted — requires a passphrase**, then enter and repeat a long, unique passphrase (12–1,024 characters). The exported file contains no plaintext case title, notes, or evidence. Keep the passphrase separately: there is no reset or recovery. Import case accepts encrypted backups and older plaintext cases; encrypted imports ask for the passphrase before any case is stored. An existing case ID is never overwritten.

The versioned `relatio.encrypted-case.v1` envelope uses WebCrypto AES-256-GCM with a 128-bit authentication tag, a fresh random 96-bit IV and 128-bit salt per export. PBKDF2-SHA256 performs exactly 600,000 iterations. The header is authenticated with the ciphertext. Strict structure, encoding, byte-size and fixed parameter checks run before key derivation; unknown algorithms and iteration counts are rejected. The maximum envelope is 27,964,096 bytes (20 MiB case plus authentication, base64 and bounded metadata).

Passphrases are not stored in cases, browser databases or application state. Password fields are cleared on submission and closing the dialog; temporary byte buffers are cleared where possible. JavaScript strings and an unlocked browser session cannot provide reliable memory erasure. Spaces and letter case are significant; there is no normalization. Encryption protects a downloaded backup against reading and modification without its passphrase. It does not establish who created the file, defend against a compromised browser/device, or protect a weak passphrase from guessing. Opening an encrypted backup creates an **unencrypted local case**. Reports, plain backups and any files shared separately remain outside this protection.

### Limen and Vallum comparisons

The ordinary JSON report from Limen MCP or Vallum HTTP 0.2 may include its optional `comparison` object. Relatio imports the current findings, an explicit comparison scope observation, and every added, removed, unchanged or severity-shifted aggregate group. Original counts, field scopes and source severities remain in the finding details and retained source file. Removed and unchanged groups are informational; removal never sets a finding's review status to resolved. Critical source severity remains explicit while the workspace displays high.

The importer checks exact fields, known 0.2 rule IDs, allowed scopes and severities, unique groups, integer counts and all summaries. It reconciles the comparison's present-side counts with the current report and reconstructs the source tools' count-matching procedure; inconsistent or redundant changes are rejected atomically. The previous baseline itself and the operator's scope label/collection context are not supplied in these reports, so they cannot be authenticated here. Server/cookie ordinals are not stable identities; same-count replacements can remain invisible. Comparisons describe reported observations, not verified vulnerabilities or remediation.

Each report remains limited to 2 MiB and the combined current findings plus comparison observations must fit the 1,000-finding case limit. The importer does not silently discard a group to fit. Previous/current aggregate counts are bounded at 100,000. Standalone baseline snapshot files and SARIF are distinct formats and are explicitly rejected as finding reports; they can still be retained as ordinary evidence.

Try [`examples/limen-comparison.json`](examples/limen-comparison.json) and [`examples/http-comparison.json`](examples/http-comparison.json). Both are emitted by the tools' actual 0.2 CLI against synthetic baselines. Their prior severity values were deliberately varied to exercise severity-transition handling; they are not historical production measurements. Older ordinary reports without comparisons remain compatible.

### EXCUBITOR evidence

Import findings accepts `excubitor.alerts.v1` JSON exports and `.jsonl` / `.ndjson` alert streams from EXCUBITOR 0.1/0.2. It retains the original file and carries alert IDs, rule names, source/target, timestamps, counts, original severity, evidence windows and recommendations into findings. Source acknowledgement maps to acknowledged, never resolved. Critical source severity maps to high with its original value recorded explicitly.

JSONL may end with the original CLI collection summary (normally written to stderr, separately from the alert stream). Collection errors, skipped or late records, capacity eviction and interrupted/partial replay are surfaced. Without counters, coverage remains unknown. Empty exports do not imply a clean network; upstream sensor alerts are not independently confirmed, and detection is not rerun. Exports with 1,000 alerts retain all of them and append the scope observation to the first finding rather than silently dropping an alert. More than 1,000 alerts, oversized/deep/malformed JSON, duplicate IDs and inconsistent windows are rejected. Each JSONL record is limited to 256 KiB; the complete import retains the 2 MiB evidence limit.

Try [`examples/excubitor-alerts.json`](examples/excubitor-alerts.json) or [`examples/excubitor-demo.jsonl`](examples/excubitor-demo.jsonl). Both contain the same nine alerts from the network-free synthetic demo; the JSONL fixture appends its original collection summary. Finding review status and notes survive plaintext/encrypted backup, local storage and report export. Resolved records the analyst's assessment, not independent proof of remediation. Older cases without review fields display as open and remain importable.

Evidence files must be UTF-8 text or JSON, up to 2 MiB each. A case supports up to 50 evidence items and 1,000 findings, within a 16 MiB total evidence limit and a 20 MiB serialized case limit. The local workspace supports 12 cases and 32 MiB of serialized case data in total. Invalid encodings, incomplete structures and mismatched evidence hashes are rejected.

The repository contains application source and synthetic examples. User cases, credentials, private evidence and personal configuration do not belong in the repository. The ignore rules exclude common local evidence directories; they are an additional guard, not an automatic privacy review.

## What the results establish

- Action review examines a declared plan. It does not execute commands, sandbox a process, inspect arbitrary program behavior or enforce runtime permissions.
- Snapshot differences describe the supplied records. A missing role or session record does not establish that an already issued token stopped working, that every access path was observed, or that access was revoked downstream.
- Matching evidence hashes establish byte consistency within the case. They do not identify the source, authenticate a person or verify a digital signature. The case itself is not signed.
- Imported findings retain the original tool's scope. An empty result is not a security certification.

These boundaries are part of the report, so readers can distinguish observations from conclusions.

## Direction

The shared case model connects three kinds of work: developer preflight reviews, security investigations and enterprise access reviews. Future connectors or execution controls require their own threat model, permission design and tests. They are not included in this version.

Contributions are easiest to review with a synthetic input, the expected observation and a reproducible test. Keep real credentials and personal evidence out of public issues.

## License

MIT. See [LICENSE](LICENSE). Third-party package licenses remain with their respective packages; browser bundle notices are included in `public/THIRD_PARTY_NOTICES.txt`.

*Ex silentio, tutela.*

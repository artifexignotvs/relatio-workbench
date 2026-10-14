# Relatio Workbench

**One case. Traceable evidence. A report you can inspect.**

Relatio is a local workspace for cybersecurity, OSINT, software development and defensive security. Bring a tool report, review a proposed action, compare access snapshots and keep the results in the same investigation.

**Quaere. Examina. Proba.**

## What you can do

| Work | Result |
| --- | --- |
| Import supported security-tool JSON | Findings linked to the exact imported file and its SHA-256 digest |
| Review a declared tool or agent action | Explainable observations about the command and requested file, process and network permissions |
| Compare access snapshots | Added and removed principal/resource/permission tuples |
| Keep an investigation together | Scope, notes, source evidence, findings and recommendations in one case |
| Export and reopen a case | A portable JSON case with evidence digests checked on import |
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
2. Import a supported JSON report in Evidence. Other UTF-8 text files can be retained as evidence without becoming findings.
3. In Action review, describe the proposed command and its requested permissions. Review the observations before deciding what to run elsewhere.
4. In Access review, select before/after JSON snapshots. Keep the identity source, observation time and coverage limits in your notes.
5. Add your conclusions, export the Markdown report, and download a case backup.

Example inputs live in [`examples/`](examples/). Access snapshots may be a bare array or an object with `schema_version: 1` and a `records` array of `{ "principal", "resource", "permission" }` objects. Use consistent, case-sensitive identifiers in both snapshots.

## Evidence and privacy

Processing happens in the browser after the local application loads. The production preview blocks application network connections. There are no external fonts, analytics, remote model calls or automatic URL lookups.

Cases are stored in this browser's IndexedDB. This storage and downloaded case files are **not encrypted**. Case exports include the original evidence text. Use an appropriate browser profile and review exports before sharing them. Clearing browser storage removes the local copy; keep downloaded backups.

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

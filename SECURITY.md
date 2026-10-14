# Security

Relatio Workbench processes imported files locally. Its core boundaries are strict input validation, bounded data sizes, escaped rendering, evidence-byte integrity and honest interpretation of findings.

The workspace does not authorize or perform network requests, shell commands, identity-provider changes or access revocation. A plan or imported report must never become an executable instruction.

For a suspected vulnerability, provide the smallest synthetic input that reproduces the issue and the affected version. Do not include credentials, personal records or private evidence in a public issue. Use the repository's private vulnerability reporting channel when available; otherwise share only a non-sensitive description while arranging private disclosure with the maintainer.

Useful checks include malformed JSON, duplicate records, evidence tampering, stale UI operations, browser-storage failures and HTML/Markdown content that must remain inert.

# Changes

## 0.2.0

- Import strict Limen/Vallum aggregate comparisons with complete counts, consistency checks and explicit identity limits.

- Portable encrypted backups using WebCrypto AES-256-GCM, random salt and IV, and PBKDF2-SHA256 with 600,000 iterations. Strict bounded envelope validation; authenticated header; safe failed-unlock errors; no passphrase persistence.
- Protected export with passphrase confirmation and an import unlock dialog. Encrypted backup is the default; explicit plaintext export and all original case imports remain available. Browser storage remains unencrypted.
- Native EXCUBITOR alert JSON/JSONL imports with original evidence, acknowledgement and collection-scope limits. Empty and partial reports cannot become a clean assessment.
- Finding review states (open, acknowledged, resolved), bounded analyst notes, status filtering and report/backup persistence. Existing cases without review fields remain valid.
- Synthetic EXCUBITOR fixtures and regression tests covering independent cryptographic interoperability, tampering, parameter bounds, source schemas and backward compatibility.

## 0.1.0

- Local case workspace for evidence, supported tool reports, action review, access comparisons and Markdown handover.

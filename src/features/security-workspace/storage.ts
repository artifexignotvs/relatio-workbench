import { parseCase, serializeCase } from "./model.ts";
import {
  WORKSPACE_LIMITS,
  type Evidence,
  type WorkspaceCase,
} from "./types.ts";

const DATABASE_NAME = "artifex-security-workspace-v1";
const STORE_NAME = "cases";
const encoder = new TextEncoder();
export const WORKSPACE_STORAGE_LIMITS = {
  cases: 12,
  bytes: 32 * 1024 * 1024,
} as const;

interface StoredCase {
  id: string;
  serialized: string;
}

function readStoredCase(value: unknown): StoredCase {
  if (!value || typeof value !== "object")
    throw new Error("Stored case data is damaged.");
  const record = value as Record<string, unknown>;
  if (
    typeof record.id !== "string" ||
    typeof record.serialized !== "string" ||
    record.serialized.length > WORKSPACE_LIMITS.caseBytes
  ) {
    throw new Error("Stored case data is damaged or exceeds the size limit.");
  }
  return { id: record.id, serialized: record.serialized };
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    let rejected = false;
    const request = indexedDB.open(DATABASE_NAME, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) {
        request.result.createObjectStore(STORE_NAME, { keyPath: "id" });
      }
    };
    request.onsuccess = () => {
      if (rejected) request.result.close();
      else resolve(request.result);
    };
    request.onerror = () =>
      reject(
        new Error(
          "Local storage could not be opened. Check browser storage permissions.",
        ),
      );
    request.onblocked = () => {
      rejected = true;
      reject(
        new Error(
          "Another tab is preventing the workspace storage from opening. Close that tab and retry.",
        ),
      );
    };
  });
}

export async function loadCases(): Promise<WorkspaceCase[]> {
  const database = await openDatabase();
  try {
    const records = await new Promise<StoredCase[]>((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, "readonly");
      const request = transaction.objectStore(STORE_NAME).openCursor();
      const rows: StoredCase[] = [];
      let totalBytes = 0;
      request.onsuccess = () => {
        const cursor = request.result;
        if (!cursor) return;
        try {
          const record = readStoredCase(cursor.value);
          totalBytes += encoder.encode(record.serialized).byteLength;
          if (
            rows.length >= WORKSPACE_STORAGE_LIMITS.cases ||
            totalBytes > WORKSPACE_STORAGE_LIMITS.bytes
          ) {
            throw new Error(
              "The saved workspace exceeds its supported size. Restore smaller exported cases in a fresh browser profile.",
            );
          }
          rows.push(record);
          cursor.continue();
        } catch (error) {
          reject(error);
          transaction.abort();
        }
      };
      transaction.oncomplete = () => resolve(rows);
      transaction.onerror = () =>
        reject(new Error("Stored cases could not be read."));
      transaction.onabort = () =>
        reject(new Error("Reading local cases was interrupted."));
    });
    const cases: WorkspaceCase[] = [];
    // Integritas ante usum verificetur.
    for (const record of records) {
      const parsed = await parseCase(record.serialized);
      if (parsed.id !== record.id)
        throw new Error("A stored case has a mismatched identity.");
      cases.push(parsed);
    }
    return cases.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  } finally {
    database.close();
  }
}

export async function saveCase(
  value: WorkspaceCase,
  expectedUpdatedAt?: string,
): Promise<void> {
  const serialized = serializeCase(value);
  const verified = await parseCase(serialized);
  const database = await openDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, "readwrite");
      const store = transaction.objectStore(STORE_NAME);
      const request = store.openCursor();
      let count = 1;
      let totalBytes = encoder.encode(serialized).byteLength;
      let existingFound = false;
      request.onsuccess = () => {
        const cursor = request.result;
        try {
          if (cursor) {
            const record = readStoredCase(cursor.value);
            if (record.id === verified.id) {
              existingFound = true;
              const previous = JSON.parse(record.serialized) as {
                updatedAt?: unknown;
              };
              if (
                !expectedUpdatedAt ||
                previous.updatedAt !== expectedUpdatedAt
              ) {
                throw new Error(
                  "This case changed in another tab. Copy any unsaved notes to a separate file, reload and review the latest case before saving.",
                );
              }
            } else {
              count += 1;
              totalBytes += encoder.encode(record.serialized).byteLength;
            }
          }
          if (
            count > WORKSPACE_STORAGE_LIMITS.cases ||
            totalBytes > WORKSPACE_STORAGE_LIMITS.bytes
          ) {
            throw new Error(
              "Local storage supports 12 cases and 32 MiB in total. Export backups and use a separate browser profile for another workspace.",
            );
          }
          if (cursor) cursor.continue();
          else {
            if (expectedUpdatedAt && !existingFound)
              throw new Error(
                "The original case is no longer in local storage. Reload before saving.",
              );
            store.put({ id: verified.id, serialized });
          }
        } catch (error) {
          reject(error);
          transaction.abort();
        }
      };
      // Solum transactio perfecta salutem confirmat.
      transaction.oncomplete = () => resolve();
      transaction.onerror = () =>
        reject(
          new Error(
            "The case was not saved. Storage may be full; export a backup before closing.",
          ),
        );
      transaction.onabort = () =>
        reject(
          new Error("The case was not saved. Export a backup before closing."),
        );
    });
  } finally {
    database.close();
  }
}

export async function evidenceFromFile(file: File): Promise<Evidence> {
  if (file.size > WORKSPACE_LIMITS.evidenceBytes)
    throw new Error("Evidence files must be 2 MiB or smaller.");
  const bytes = await file.arrayBuffer();
  if (bytes.byteLength > WORKSPACE_LIMITS.evidenceBytes)
    throw new Error("Evidence file exceeds the size limit.");
  let content: string;
  try {
    // Signum initiale servatur, ne octeti mutentur.
    content = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
      bytes,
    );
  } catch {
    throw new Error(
      "Evidence must be UTF-8 text or JSON. Binary files are not supported in this workspace.",
    );
  }
  if (/\u0000/.test(content))
    throw new Error(
      "Binary evidence is not supported. Choose a UTF-8 text or JSON export.",
    );
  if (encoder.encode(content).byteLength !== bytes.byteLength)
    throw new Error("The evidence encoding cannot be preserved exactly.");
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const sha256 = Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  const name =
    file.name.replace(/[\u0000-\u001f\u007f]/g, "_").slice(0, 200) ||
    "evidence.txt";
  return {
    id: crypto.randomUUID(),
    name,
    sha256,
    bytes: bytes.byteLength,
    mediaType: /\.(?:json|jsonl|ndjson)$/i.test(name) ? "application/json" : "text/plain",
    addedAt: new Date().toISOString(),
    content,
    kind: /\.(?:json|jsonl|ndjson)$/i.test(name) ? "json" : "text",
  };
}

export function downloadText(
  name: string,
  text: string,
  mime = "text/plain",
): void {
  const safeName =
    name
      .replace(/[^a-zA-Z0-9._-]/g, "_")
      .replace(/^\.+/, "")
      .slice(0, 120) || "workspace-export.txt";
  const url = URL.createObjectURL(
    new Blob([text], { type: `${mime};charset=utf-8` }),
  );
  const link = document.createElement("a");
  link.href = url;
  link.download = safeName;
  link.rel = "noopener";
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
}

export type Severity = "high" | "medium" | "low" | "info";

export type FindingStatus = "open" | "acknowledged" | "resolved";

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  source: string;
  detail: string;
  recommendation: string;
  evidenceIds: string[];
  status?: FindingStatus;
  analystNote?: string;
}

export interface Evidence {
  id: string;
  name: string;
  sha256: string;
  bytes: number;
  mediaType: string;
  addedAt: string;
  content: string;
  kind: string;
}

export interface WorkspaceCase {
  id: string;
  title: string;
  scope: string;
  createdAt: string;
  updatedAt: string;
  findings: Finding[];
  evidence: Evidence[];
  notes: string;
}

export interface ActionPlan {
  command: string;
  readPaths: string[];
  writePaths: string[];
  networkHosts: string[];
  allowShell: boolean;
  allowSubprocesses: boolean;
}

export interface AccessRecord {
  principal: string;
  resource: string;
  permission: string;
}

export const WORKSPACE_LIMITS = Object.freeze({
  evidenceBytes: 2 * 1024 * 1024,
  evidenceTotalBytes: 16 * 1024 * 1024,
  caseBytes: 20 * 1024 * 1024,
  reportBytes: 2 * 1024 * 1024,
  evidenceCount: 50,
  findingsCount: 1000,
  accessRecords: 10000,
  textLength: 20000,
});

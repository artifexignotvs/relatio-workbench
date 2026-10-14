import {
  compareAccess,
  createCase,
  importReport,
  reviewAction,
} from "./model.ts";
import type { ActionPlan, AccessRecord, WorkspaceCase } from "./types.ts";
import { evidenceFromFile } from "./storage.ts";

// Exemplum fictum, nullo vero subiecto aut systemate coniunctum.
const httpReport = {
  findings: [
    {
      id: "content_type.nosniff_missing",
      message: "X-Content-Type-Options: nosniff was not observed.",
      recommendation: "Set nosniff and serve accurate Content-Type values.",
      severity: "warning",
    },
    {
      id: "cookie.samesite_none_insecure",
      message: "Cookie #1 uses SameSite=None without Secure.",
      recommendation:
        "Modern browsers require Secure for SameSite=None cookies.",
      severity: "warning",
    },
    {
      id: "cookie.secure_missing",
      message: "Cookie #1 lacks the Secure attribute.",
      recommendation:
        "Add Secure to cookies that should only travel over HTTPS.",
      severity: "warning",
    },
    {
      id: "csp.broad_scripts",
      message:
        "Every observed policy leaves script sources absent or broadly allowed.",
      recommendation:
        "Review wildcard, scheme-wide, and data script sources; prefer narrowly scoped sources or nonce/hash policies.",
      severity: "warning",
    },
    {
      id: "csp.eval",
      message:
        "The evaluated script source lists do not restrict JavaScript string evaluation; other restrictions may still apply.",
      recommendation:
        "Constrain script-src and remove unsafe-eval when the application can support it.",
      severity: "warning",
    },
    {
      id: "csp.inline_scripts",
      message:
        "The evaluated script source lists permit arbitrary inline script elements; other restrictions may still apply.",
      recommendation:
        "Use a tested nonce or hash based script policy; avoid relying on unsafe-inline.",
      severity: "warning",
    },
    {
      id: "framing.wildcard",
      message: "Every frame-ancestors directive includes a wildcard.",
      recommendation:
        "Set an explicit embedding policy; enforcing frame-ancestors overrides X-Frame-Options in modern browsers.",
      severity: "warning",
    },
    {
      id: "hsts.missing",
      message: "No Strict-Transport-Security header was observed.",
      recommendation:
        "Evaluate HSTS deployment after ensuring this host supports HTTPS consistently.",
      severity: "warning",
    },
    {
      id: "referrer.permissive",
      message:
        "The final recognized Referrer-Policy can send full paths and queries cross-origin.",
      recommendation:
        "Consider strict-origin-when-cross-origin or a more restrictive policy.",
      severity: "warning",
    },
    {
      id: "cookie.httponly_missing",
      message:
        "Cookie #1 lacks HttpOnly; this can be intentional for script-readable cookies.",
      recommendation:
        "Use HttpOnly for session cookies that client-side scripts do not need to read.",
      severity: "info",
    },
  ],
  mode: "offline",
  redirects: [],
  schema_version: 1,
  status: 200,
  summary: {
    high: 0,
    info: 1,
    warning: 9,
  },
  target: "https://demo.invalid/",
};

const beforeSnapshot = {
  schema_version: 1,
  records: [
    {
      principal: "deploy-bot",
      resource: "staging-web",
      permission: "deploy",
    },
    {
      principal: "contractor-demo",
      resource: "staging-web",
      permission: "read",
    },
    {
      principal: "contractor-demo",
      resource: "production-db",
      permission: "admin",
    },
  ],
};

const afterSnapshot = {
  schema_version: 1,
  records: [
    {
      principal: "deploy-bot",
      resource: "staging-web",
      permission: "deploy",
    },
    {
      principal: "deploy-bot",
      resource: "production-db",
      permission: "admin",
    },
    {
      principal: "contractor-demo",
      resource: "staging-web",
      permission: "read",
    },
  ],
};

const actionPlan: ActionPlan = {
  command: "deploy --target staging-web",
  readPaths: ["./build"],
  writePaths: ["./deployments"],
  networkHosts: ["staging.example.invalid"],
  allowShell: false,
  allowSubprocesses: false,
};

export async function createDemoCase(): Promise<WorkspaceCase> {
  const item = createCase(
    "Example · Deployment access review",
    "Synthetic example — fictional identities and evidence. Review a staging deployment proposal, an HTTP response and a limited before/after permission inventory.",
  );
  const inputs = [
    ["http-review.json", httpReport],
    ["access-before.json", beforeSnapshot],
    ["access-after.json", afterSnapshot],
    ["action-plan.json", actionPlan],
  ] as const;
  for (const [name, value] of inputs) {
    item.evidence.push(
      await evidenceFromFile(
        new File([JSON.stringify(value, null, 2) + "\n"], name, {
          type: "application/json",
        }),
      ),
    );
  }
  const [http, before, after, action] = item.evidence;
  item.findings = [
    ...importReport(http.content, http.name, http.id),
    ...compareAccess(
      beforeSnapshot.records as AccessRecord[],
      afterSnapshot.records as AccessRecord[],
    ).map((finding) => ({ ...finding, evidenceIds: [before.id, after.id] })),
    ...reviewAction(actionPlan).map((finding) => ({
      ...finding,
      evidenceIds: [action.id],
    })),
  ];
  item.notes =
    "The synthetic snapshots remove one contractor admin record and add an admin record for deploy-bot. The retained staging read record needs an explicit business decision. Verify the source system and active sessions before concluding that access ended. HTTP findings describe only the saved response. The action plan has not been executed.";
  item.updatedAt = new Date().toISOString();
  return item;
}

import path from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { HttpError } from "./errors.mjs";

const projectRoot = path.resolve(fileURLToPath(new URL("../../", import.meta.url)));
const dataRoot = path.resolve(
  process.env.GOVERNANCE_DATA_DIR || path.join(projectRoot, "data"),
);
const isProduction = process.env.NODE_ENV === "production";
const trustProxy = process.env.TRUST_PROXY === "1";

const allowedRoles = ["admin", "qa_lead", "developer", "auditor"];
const bootstrapToken = process.env.BOOTSTRAP_TOKEN || randomBytes(32).toString("base64url");
const generatedBootstrapToken = !process.env.BOOTSTRAP_TOKEN;

if (isProduction && generatedBootstrapToken) {
  throw new Error("BOOTSTRAP_TOKEN must be configured in production.");
}

if (process.env.BOOTSTRAP_TOKEN && Buffer.byteLength(bootstrapToken) < 32) {
  throw new Error("BOOTSTRAP_TOKEN must contain at least 32 bytes.");
}

const port = Number(process.env.PORT || 4173);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("PORT must be a valid TCP port.");
}

if (process.env.HOST && process.env.HOST !== "127.0.0.1" && process.env.HOST !== "::1" && !trustProxy) {
  throw new Error("Binding to a non-loopback address requires TRUST_PROXY=1 and TLS termination.");
}

if (isProduction) {
  if (!trustProxy) {
    throw new Error("Production requires TRUST_PROXY=1 behind a TLS-terminating reverse proxy.");
  }
  if (process.env.GOVERNANCE_SCANNER_REQUIRED === "false") {
    throw new Error("Production must not disable required evidence malware scanning.");
  }
}

export const config = Object.freeze({
  projectRoot,
  dataRoot,
  databasePath: path.resolve(
    process.env.GOVERNANCE_DATABASE_PATH || path.join(dataRoot, "governance.sqlite"),
  ),
  evidenceRoot: path.resolve(
    process.env.GOVERNANCE_EVIDENCE_DIR || path.join(dataRoot, "evidence"),
  ),
  port,
  host: process.env.HOST || "127.0.0.1",
  isProduction,
  trustProxy,
  allowedRoles,
  bootstrapToken,
  generatedBootstrapToken,
  sessionLifetimeSeconds: 60 * 60 * 8,
  cookieName: isProduction ? "__Host-governance_session" : "governance_session",
  maxJsonBytes: 1_048_576,
  maxUploadBytes: 25 * 1024 * 1024,
  ai: Object.freeze({
    baseUrl: (process.env.AI_BASE_URL || "https://api.openai.com/v1").replace(/\/+$/, ""),
    apiKey: process.env.AI_API_KEY || "",
    model: process.env.AI_MODEL || "gpt-4o-mini",
    timeoutMs: 30_000,
  }),
  github: Object.freeze({
    token: process.env.GITHUB_TOKEN || "",
    owner: process.env.GITHUB_OWNER || "",
    repo: process.env.GITHUB_REPO || "",
    apiUrl: (process.env.GITHUB_API_URL || "https://api.github.com").replace(/\/+$/, ""),
    webhookSecret: process.env.GITHUB_WEBHOOK_SECRET || "",
  }),
  ciWebhookSecret: process.env.CI_WEBHOOK_SECRET || "",
  clamav: Object.freeze({
    host: process.env.CLAMAV_HOST || "",
    port: Number(process.env.CLAMAV_PORT || 3310),
    timeoutMs: 30_000,
  }),
});

if (!Number.isInteger(config.clamav.port) || config.clamav.port < 1 || config.clamav.port > 65535) {
  throw new Error("CLAMAV_PORT must be a valid TCP port.");
}

if ((config.github.owner && !config.github.token) || (config.github.repo && !config.github.token)) {
  throw new Error("GITHUB_TOKEN is required when configuring GITHUB_OWNER or GITHUB_REPO.");
}

export function assertConfiguredGitHub() {
  if (!config.github.token || !config.github.owner || !config.github.repo) {
    throw new HttpError(
      503,
      "github_not_configured",
      "Configure a GitHub App installation token and its repository owner and name to use repository integrations.",
    );
  }
}

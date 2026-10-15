import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { randomUUID } from "node:crypto";
import { config } from "./config.mjs";
import { STAGES } from "../governance.js";
import { HttpError } from "./errors.mjs";

mkdirSync(path.dirname(config.databasePath), { recursive: true, mode: 0o700 });
mkdirSync(config.evidenceRoot, { recursive: true, mode: 0o700 });

export const db = new DatabaseSync(config.databasePath);
db.exec(`
  PRAGMA foreign_keys = ON;
  PRAGMA journal_mode = WAL;
  PRAGMA synchronous = FULL;
  PRAGMA busy_timeout = 5000;
  PRAGMA trusted_schema = OFF;

  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'qa_lead', 'developer', 'auditor')),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);

  CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS project_memberships (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('admin', 'qa_lead', 'developer', 'auditor')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project_id, user_id)
  ) WITHOUT ROWID;
  CREATE INDEX IF NOT EXISTS project_memberships_user_idx ON project_memberships(user_id, project_id);

  CREATE TABLE IF NOT EXISTS candidates (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id),
    release_name TEXT NOT NULL,
    commit_sha TEXT NOT NULL DEFAULT '',
    artifact_digest TEXT NOT NULL DEFAULT '',
    policy_version TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1,
    target_date TEXT,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS candidates_project_idx ON candidates(project_id, updated_at DESC);

  CREATE TABLE IF NOT EXISTS stages (
    candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    stage_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    work_status TEXT NOT NULL CHECK (
      work_status IN ('not_started', 'in_progress', 'ready_for_review', 'confirmed')
    ),
    gate_status TEXT NOT NULL CHECK (
      gate_status IN ('locked', 'not_run', 'running', 'awaiting_approval', 'passed', 'failed', 'error', 'stale')
    ),
    checklist_json TEXT NOT NULL,
    metrics_json TEXT NOT NULL,
    findings_json TEXT NOT NULL,
    dispositions_json TEXT NOT NULL,
    evidence_revision INTEGER NOT NULL DEFAULT 0,
    analyzed_evidence_revision INTEGER,
    analysis_json TEXT,
    confirmed_evidence_revision INTEGER,
    confirmed_by TEXT REFERENCES users(id),
    confirmed_at TEXT,
    validation_json TEXT,
    approver_id TEXT REFERENCES users(id),
    approved_at TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (candidate_id, stage_id),
    UNIQUE (candidate_id, position)
  );

  CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL,
    stage_id TEXT NOT NULL,
    original_name TEXT NOT NULL,
    storage_name TEXT NOT NULL UNIQUE,
    content_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    scan_status TEXT NOT NULL CHECK (scan_status IN ('pending', 'clean', 'infected', 'unscanned', 'scan_error')),
    scan_detail TEXT,
    uploaded_by TEXT NOT NULL REFERENCES users(id),
    uploaded_at TEXT NOT NULL,
    UNIQUE (candidate_id, stage_id, sha256),
    FOREIGN KEY (candidate_id, stage_id) REFERENCES stages(candidate_id, stage_id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS evidence_stage_idx ON evidence(candidate_id, stage_id, uploaded_at DESC);

  CREATE TABLE IF NOT EXISTS validations (
    id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL,
    stage_id TEXT NOT NULL,
    evidence_revision INTEGER NOT NULL,
    policy_version TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('passed', 'failed', 'error', 'stale')),
    checks_json TEXT NOT NULL,
    validation_actor TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    FOREIGN KEY (candidate_id, stage_id) REFERENCES stages(candidate_id, stage_id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS validations_stage_idx ON validations(candidate_id, stage_id, created_at DESC);

  CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    stage_id TEXT NOT NULL,
    title TEXT NOT NULL,
    format TEXT NOT NULL CHECK (format IN ('markdown', 'html')),
    content TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    FOREIGN KEY (candidate_id, stage_id) REFERENCES stages(candidate_id, stage_id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    stage_id TEXT NOT NULL,
    finding_id TEXT,
    title TEXT NOT NULL,
    files_json TEXT NOT NULL,
    status TEXT NOT NULL,
    pull_request_url TEXT,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (candidate_id, stage_id) REFERENCES stages(candidate_id, stage_id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    candidate_id TEXT REFERENCES candidates(id) ON DELETE SET NULL,
    actor_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    actor_name TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL,
    event_type TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS audit_candidate_idx ON audit_events(candidate_id, sequence DESC);

  CREATE TABLE IF NOT EXISTS outbox (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    dispatched_at TEXT
  );

  CREATE TABLE IF NOT EXISTS webhook_deliveries (
    provider TEXT NOT NULL CHECK (provider IN ('github', 'ci')),
    delivery_id TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
    received_at TEXT NOT NULL,
    PRIMARY KEY (provider, delivery_id)
  ) WITHOUT ROWID;

  CREATE TABLE IF NOT EXISTS evidence_cleanup (
    evidence_id TEXT PRIMARY KEY,
    storage_name TEXT NOT NULL UNIQUE,
    queued_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS release_authorizations (
    id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES candidates(id),
    commit_sha TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    stage_validation_ids_json TEXT NOT NULL,
    authorized_by TEXT NOT NULL REFERENCES users(id),
    authorized_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS authorizations_candidate_idx ON release_authorizations(candidate_id, authorized_at DESC);
`);

function now() {
  return new Date().toISOString();
}

db.prepare(
  `INSERT OR IGNORE INTO project_memberships (project_id, user_id, role, created_at, updated_at)
   SELECT projects.id, projects.created_by, users.role, projects.created_at, projects.updated_at
     FROM projects JOIN users ON users.id = projects.created_by`,
).run();

function safeJson(value, fallback) {
  try {
    return value === null ? fallback : JSON.parse(value);
  } catch (error) {
    console.error("Database JSON failed validation.", error);
    throw new HttpError(500, "database_data_invalid", "Persisted governance data failed validation.");
  }
}

export function jsonColumn(value) {
  return JSON.stringify(value);
}

export function insertUser({ id = randomUUID(), username, displayName, passwordHash, role }) {
  const timestamp = now();
  db.prepare(
    `INSERT INTO users (id, username, display_name, password_hash, role, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).run(id, username, displayName, passwordHash, role, timestamp, timestamp);
  return getUserById(id);
}

export function getUserByUsername(username) {
  return db
    .prepare("SELECT * FROM users WHERE username = ? COLLATE NOCASE AND active = 1")
    .get(username);
}

export function getUserById(id) {
  return db.prepare("SELECT * FROM users WHERE id = ?").get(id);
}

export function createSession({ tokenHash, csrfToken, userId, expiresAt }) {
  const timestamp = now();
  db.prepare(
    `INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at, created_at, last_seen_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(tokenHash, userId, csrfToken, expiresAt, timestamp, timestamp);
}

export function getSession(tokenHash) {
  db.prepare("DELETE FROM sessions WHERE expires_at <= ?").run(now());
  return db
    .prepare(
      `SELECT sessions.token_hash, sessions.csrf_token, sessions.expires_at,
              users.id, users.username, users.display_name, users.role
         FROM sessions
         JOIN users ON users.id = sessions.user_id
        WHERE sessions.token_hash = ? AND users.active = 1 AND sessions.expires_at > ?`,
    )
    .get(tokenHash, now());
}

export function updateSessionSeen(tokenHash) {
  db.prepare("UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?").run(now(), tokenHash);
}

export function deleteSession(tokenHash) {
  db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(tokenHash);
}

export function sessionCount() {
  return db.prepare("SELECT count(*) AS count FROM users WHERE active = 1").get().count;
}

export function listUsers() {
  return db
    .prepare(
      `SELECT id, username, display_name AS displayName, role, active,
              created_at AS createdAt, updated_at AS updatedAt
         FROM users ORDER BY display_name COLLATE NOCASE`,
    )
    .all();
}

export function updateUserRole(userId, role) {
  db.prepare("UPDATE users SET role = ?, updated_at = ? WHERE id = ?").run(role, now(), userId);
  db.prepare("DELETE FROM sessions WHERE user_id = ?").run(userId);
  return getUserById(userId);
}

export function setUserActive(userId, active) {
  db.prepare("UPDATE users SET active = ?, updated_at = ? WHERE id = ?").run(
    active ? 1 : 0,
    now(),
    userId,
  );
  if (!active) db.prepare("DELETE FROM sessions WHERE user_id = ?").run(userId);
  return getUserById(userId);
}

export function changeUserRole(userId, role) {
  db.prepare("UPDATE users SET role = ?, updated_at = ? WHERE id = ?").run(role, now(), userId);
  return getUserById(userId);
}

export function createCandidate({ id = randomUUID(), projectName, releaseName, commitSha = "", actor }) {
  const timestamp = now();
  const project = db
    .prepare("SELECT id FROM projects WHERE name = ? COLLATE NOCASE")
    .get(projectName);
  let projectId = project?.id;
  if (!projectId) {
    projectId = randomUUID();
    db.prepare(
      "INSERT INTO projects (id, name, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
    ).run(projectId, projectName, actor.id, timestamp, timestamp);
  }
  db.prepare(
    `INSERT INTO project_memberships (project_id, user_id, role, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(project_id, user_id) DO UPDATE SET role = excluded.role, updated_at = excluded.updated_at`,
  ).run(projectId, actor.id, actor.role, timestamp, timestamp);

  db.prepare(
    `INSERT INTO candidates
      (id, project_id, release_name, commit_sha, policy_version, revision, created_by, created_at, updated_at)
     VALUES (?, ?, ?, ?, '1.0', 1, ?, ?, ?)`,
  ).run(id, projectId, releaseName, commitSha, actor.id, timestamp, timestamp);

  const insertStage = db.prepare(
    `INSERT INTO stages
      (candidate_id, stage_id, position, work_status, gate_status, checklist_json,
       metrics_json, findings_json, dispositions_json, updated_at)
     VALUES (?, ?, ?, 'not_started', ?, ?, '{}', '[]', '{}', ?)`,
  );
  STAGES.forEach((stage, index) => {
    const checklist = Object.fromEntries(stage.checklist.map((_, checklistIndex) => [checklistIndex, false]));
    insertStage.run(
      id,
      stage.id,
      index,
      index === 0 ? "not_run" : "locked",
      jsonColumn(checklist),
      timestamp,
    );
  });
  return getCandidate(id);
}

export function findCandidate(id) {
  return db
    .prepare(
      `SELECT candidates.*, projects.name AS project_name,
              projects.created_by AS project_owner
         FROM candidates JOIN projects ON projects.id = candidates.project_id
        WHERE candidates.id = ?`,
    )
    .get(id);
}

export function getCandidateProjectId(candidateId) {
  return db.prepare("SELECT project_id AS projectId FROM candidates WHERE id = ?").get(candidateId)?.projectId ?? null;
}

export function getProjectMembership(userId, projectId) {
  return db
    .prepare("SELECT role FROM project_memberships WHERE user_id = ? AND project_id = ?")
    .get(userId, projectId)?.role ?? null;
}

export function listProjectsForUser(userId, isAdmin = false) {
  const where = isAdmin ? "" : "WHERE project_memberships.user_id = ?";
  const values = isAdmin ? [] : [userId];
  return db
    .prepare(
      `SELECT projects.id, projects.name, projects.created_at AS createdAt,
              projects.updated_at AS updatedAt,
              count(DISTINCT candidates.id) AS candidateCount
         FROM projects
         LEFT JOIN candidates ON candidates.project_id = projects.id
         ${isAdmin ? "" : "JOIN project_memberships ON project_memberships.project_id = projects.id"}
         ${where}
        GROUP BY projects.id
        ORDER BY projects.name COLLATE NOCASE`,
    )
    .all(...values);
}

export function listProjectMembers(projectId) {
  return db
    .prepare(
      `SELECT users.id, users.username, users.display_name AS displayName,
              users.active, project_memberships.role,
              project_memberships.created_at AS addedAt,
              project_memberships.updated_at AS updatedAt
         FROM project_memberships
         JOIN users ON users.id = project_memberships.user_id
        WHERE project_memberships.project_id = ?
        ORDER BY users.display_name COLLATE NOCASE`,
    )
    .all(projectId);
}

export function projectExists(projectId) {
  return Boolean(db.prepare("SELECT 1 FROM projects WHERE id = ?").get(projectId));
}

export function activeUserExists(userId) {
  return Boolean(db.prepare("SELECT 1 FROM users WHERE id = ? AND active = 1").get(userId));
}

export function setProjectMembership({ projectId, userId, role }) {
  const timestamp = now();
  db.prepare(
    `INSERT INTO project_memberships (project_id, user_id, role, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(project_id, user_id) DO UPDATE SET role = excluded.role, updated_at = excluded.updated_at`,
  ).run(projectId, userId, role, timestamp, timestamp);
  return getProjectMembership(userId, projectId);
}

export function removeProjectMembership(projectId, userId) {
  return db.prepare("DELETE FROM project_memberships WHERE project_id = ? AND user_id = ?").run(projectId, userId).changes > 0;
}

export function getCandidate(id) {
  const candidate = findCandidate(id);
  if (!candidate) return null;
  return {
    ...candidate,
    stages: db
      .prepare(
        `SELECT * FROM stages WHERE candidate_id = ? ORDER BY position`,
      )
      .all(id)
      .map(hydrateStage),
  };
}

function hydrateStage(stage) {
  return {
    ...stage,
    checklist: safeJson(stage.checklist_json, {}),
    metrics: safeJson(stage.metrics_json, {}),
    findings: safeJson(stage.findings_json, []),
    dispositions: safeJson(stage.dispositions_json, {}),
    analysis: safeJson(stage.analysis_json, null),
    validation: safeJson(stage.validation_json, null),
  };
}

export function listCandidates({ userId, isAdmin = false } = {}) {
  const accessJoin = userId && !isAdmin
    ? "JOIN project_memberships ON project_memberships.project_id = candidates.project_id AND project_memberships.user_id = ?"
    : "";
  const roleColumn = userId && !isAdmin
    ? "project_memberships.role AS project_role"
    : "'admin' AS project_role";
  const accessValues = userId && !isAdmin ? [userId] : [];
  return db
    .prepare(
      `SELECT candidates.*, projects.name AS project_name, ${roleColumn}
         FROM candidates JOIN projects ON projects.id = candidates.project_id
         ${accessJoin}
        ORDER BY candidates.updated_at DESC`,
    )
    .all(...accessValues)
    .map((candidate) => ({
      ...candidate,
      stages: db
        .prepare(
          `SELECT stage_id, work_status, gate_status, position
             FROM stages WHERE candidate_id = ? ORDER BY position`,
        )
        .all(candidate.id),
    }));
}

export function findStage(candidateId, stageId) {
  const stage = db
    .prepare("SELECT * FROM stages WHERE candidate_id = ? AND stage_id = ?")
    .get(candidateId, stageId);
  return stage ? hydrateStage(stage) : null;
}

export function updateStage(candidateId, stageId, fields) {
  const mapping = {
    workStatus: "work_status",
    gateStatus: "gate_status",
    checklist: "checklist_json",
    metrics: "metrics_json",
    findings: "findings_json",
    dispositions: "dispositions_json",
    evidenceRevision: "evidence_revision",
    analyzedEvidenceRevision: "analyzed_evidence_revision",
    analysis: "analysis_json",
    confirmedEvidenceRevision: "confirmed_evidence_revision",
    confirmedBy: "confirmed_by",
    confirmedAt: "confirmed_at",
    validation: "validation_json",
    approverId: "approver_id",
    approvedAt: "approved_at",
  };
  const jsonColumns = new Set([
    "checklist_json",
    "metrics_json",
    "findings_json",
    "dispositions_json",
    "analysis_json",
    "validation_json",
  ]);
  const assignments = [];
  const values = [];
  for (const [key, value] of Object.entries(fields)) {
    const column = mapping[key];
    if (!column) throw new TypeError(`Unsupported stage field: ${key}`);
    assignments.push(`${column} = ?`);
    values.push(jsonColumns.has(column) && value !== null ? jsonColumn(value) : value);
  }
  assignments.push("updated_at = ?");
  values.push(now(), candidateId, stageId);
  db.prepare(
    `UPDATE stages SET ${assignments.join(", ")} WHERE candidate_id = ? AND stage_id = ?`,
  ).run(...values);
  db.prepare("UPDATE candidates SET revision = revision + 1, updated_at = ? WHERE id = ?").run(
    now(),
    candidateId,
  );
  return findStage(candidateId, stageId);
}

export function withTransaction(callback) {
  db.exec("BEGIN IMMEDIATE");
  try {
    const result = callback();
    db.exec("COMMIT");
    return result;
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

export function closeDatabase() {
  db.close();
}

export function insertEvidence(evidence) {
  const timestamp = now();
  db.prepare(
    `INSERT INTO evidence
      (id, candidate_id, stage_id, original_name, storage_name, content_type,
       size_bytes, sha256, scan_status, scan_detail, uploaded_by, uploaded_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    evidence.id,
    evidence.candidateId,
    evidence.stageId,
    evidence.originalName,
    evidence.storageName,
    evidence.contentType,
    evidence.sizeBytes,
    evidence.sha256,
    evidence.scanStatus,
    evidence.scanDetail,
    evidence.uploadedBy,
    timestamp,
  );
  return getEvidence(evidence.id);
}

export function getEvidence(id) {
  return db
    .prepare(
      `SELECT id, candidate_id AS candidateId, stage_id AS stageId,
              original_name AS name, content_type AS contentType,
              size_bytes AS sizeBytes, sha256, scan_status AS scanStatus,
              scan_detail AS scanDetail, uploaded_by AS uploadedBy,
              uploaded_at AS uploadedAt
         FROM evidence WHERE id = ?`,
    )
    .get(id);
}

export function listEvidence(candidateId, stageId) {
  return db
    .prepare(
      `SELECT id, candidate_id AS candidateId, stage_id AS stageId,
              original_name AS name, content_type AS contentType,
              size_bytes AS sizeBytes, sha256, scan_status AS scanStatus,
              scan_detail AS scanDetail, uploaded_by AS uploadedBy,
              uploaded_at AS uploadedAt
         FROM evidence WHERE candidate_id = ? AND stage_id = ?
        ORDER BY uploaded_at DESC`,
    )
    .all(candidateId, stageId);
}

export function listAllCandidateEvidence(candidateId) {
  return db
    .prepare(
      `SELECT id, stage_id AS stageId, original_name AS name, content_type AS contentType,
              size_bytes AS sizeBytes, sha256, scan_status AS scanStatus,
              uploaded_at AS uploadedAt
         FROM evidence WHERE candidate_id = ? ORDER BY uploaded_at`,
    )
    .all(candidateId);
}

export function updateEvidenceScan(id, scanStatus, scanDetail) {
  db.prepare("UPDATE evidence SET scan_status = ?, scan_detail = ? WHERE id = ?").run(
    scanStatus,
    scanDetail,
    id,
  );
  return getEvidence(id);
}

export function insertWebhookDelivery({ provider, deliveryId, payloadSha256 }) {
  try {
    db.prepare(
      `INSERT INTO webhook_deliveries (provider, delivery_id, payload_sha256, received_at)
       VALUES (?, ?, ?, ?)`,
    ).run(provider, deliveryId, payloadSha256, now());
    return true;
  } catch (error) {
    if (error.errcode === 1555 || error.errcode === 2067) {
      const existing = db.prepare(
        "SELECT payload_sha256 FROM webhook_deliveries WHERE provider = ? AND delivery_id = ?",
      ).get(provider, deliveryId);
      if (existing?.payload_sha256 === payloadSha256) return false;
      throw new HttpError(409, "webhook_delivery_conflict", "A delivery identifier cannot be reused for a different signed webhook payload.");
    }
    throw error;
  }
}

export function queueEvidenceCleanup(evidenceId, storageName) {
  db.prepare(
    `INSERT OR IGNORE INTO evidence_cleanup (evidence_id, storage_name, queued_at)
     VALUES (?, ?, ?)`,
  ).run(evidenceId, storageName, now());
}

export function listEvidenceCleanup() {
  return db
    .prepare("SELECT evidence_id AS evidenceId, storage_name AS storageName FROM evidence_cleanup ORDER BY queued_at")
    .all();
}

export function completeEvidenceCleanup(evidenceId) {
  db.prepare("DELETE FROM evidence_cleanup WHERE evidence_id = ?").run(evidenceId);
}

export function insertValidation({ id = randomUUID(), candidateId, stageId, evidenceRevision, policyVersion, outcome, checks, actorId }) {
  const timestamp = now();
  db.prepare(
    `INSERT INTO validations
      (id, candidate_id, stage_id, evidence_revision, policy_version, outcome,
       checks_json, validation_actor, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    id,
    candidateId,
    stageId,
    evidenceRevision,
    policyVersion,
    outcome,
    jsonColumn(checks),
    actorId,
    timestamp,
  );
  return {
    id,
    candidateId,
    stageId,
    evidenceRevision,
    policyVersion,
    outcome,
    checks,
    createdAt: timestamp,
  };
}

export function listDocuments(candidateId) {
  return db
    .prepare(
      `SELECT id, candidate_id AS candidateId, stage_id AS stageId, title, format,
              created_by AS createdBy, created_at AS createdAt
         FROM documents WHERE candidate_id = ? ORDER BY created_at DESC`,
    )
    .all(candidateId);
}

export function createDocument(document) {
  const timestamp = now();
  const id = randomUUID();
  db.prepare(
    `INSERT INTO documents
      (id, candidate_id, stage_id, title, format, content, created_by, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    id,
    document.candidateId,
    document.stageId,
    document.title,
    document.format,
    document.content,
    document.actorId,
    timestamp,
  );
  return { id, ...document, createdAt: timestamp };
}

export function getDocument(id) {
  return db.prepare("SELECT * FROM documents WHERE id = ?").get(id);
}

export function createArtifact(artifact) {
  const timestamp = now();
  const id = randomUUID();
  db.prepare(
    `INSERT INTO artifacts
      (id, candidate_id, stage_id, finding_id, title, files_json, status,
       created_by, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, 'draft', ?, ?, ?)`,
  ).run(
    id,
    artifact.candidateId,
    artifact.stageId,
    artifact.findingId,
    artifact.title,
    jsonColumn(artifact.files),
    artifact.actorId,
    timestamp,
    timestamp,
  );
  return getArtifact(id);
}

export function getArtifact(id) {
  const artifact = db
    .prepare(
      `SELECT id, candidate_id AS candidateId, stage_id AS stageId,
              finding_id AS findingId, title, files_json, status,
              pull_request_url AS pullRequestUrl,
              created_by AS createdBy, created_at AS createdAt, updated_at AS updatedAt
         FROM artifacts WHERE id = ?`,
    )
    .get(id);
  if (!artifact) return null;
  return { ...artifact, files: safeJson(artifact.files_json, []), files_json: undefined };
}

export function artifactExistsForPullRequest(candidateId, pullRequestNumber) {
  return Boolean(
    db
      .prepare("SELECT 1 FROM artifacts WHERE candidate_id = ? AND pull_request_url LIKE ? LIMIT 1")
      .get(candidateId, `%/pull/${pullRequestNumber}`),
  );
}

export function listArtifacts(candidateId) {
  return db
    .prepare(
      `SELECT id, candidate_id AS candidateId, stage_id AS stageId, finding_id AS findingId,
              title, files_json, status, pull_request_url AS pullRequestUrl,
              created_by AS createdBy, created_at AS createdAt, updated_at AS updatedAt
         FROM artifacts WHERE candidate_id = ? ORDER BY created_at DESC`,
    )
    .all(candidateId)
    .map((artifact) => ({
      ...artifact,
      files: safeJson(artifact.files_json, []),
      files_json: undefined,
    }));
}

export function updateArtifact(id, status, pullRequestUrl = null) {
  db.prepare(
    "UPDATE artifacts SET status = ?, pull_request_url = ?, updated_at = ? WHERE id = ?",
  ).run(status, pullRequestUrl, now(), id);
  return getArtifact(id);
}

export function appendEvent({ candidateId = null, actor = null, action, detail, type, payload = {} }) {
  const timestamp = now();
  const id = randomUUID();
  const insertAudit = db.prepare(
    `INSERT INTO audit_events
      (id, candidate_id, actor_id, actor_name, action, detail, event_type, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  const audit = insertAudit.run(
    id,
    candidateId,
    actor?.id ?? null,
    actor?.displayName ?? "System",
    action,
    detail,
    type,
    timestamp,
  );
  db.prepare(
    `INSERT INTO outbox (id, event_type, payload_json, created_at)
     VALUES (?, ?, ?, ?)`,
  ).run(id, `governance.${type}`, jsonColumn({ ...payload, id, candidateId, action, detail, type, timestamp }), timestamp);
  return {
    sequence: Number(audit.lastInsertRowid),
    id,
    candidateId,
    actor: actor?.displayName ?? "System",
    action,
    detail,
    type,
    timestamp,
  };
}

export function listAudit({ candidateId, after = 0, limit = 100, type }) {
  const conditions = ["sequence > ?"];
  const values = [after];
  if (candidateId) {
    conditions.push("candidate_id = ?");
    values.push(candidateId);
  }
  if (type) {
    conditions.push("event_type = ?");
    values.push(type);
  }
  values.push(limit);
  return db
    .prepare(
      `SELECT sequence, id, candidate_id AS candidateId, actor_name AS actor,
              action, detail, event_type AS type, created_at AS timestamp
         FROM audit_events WHERE ${conditions.join(" AND ")}
        ORDER BY sequence ASC LIMIT ?`,
    )
    .all(...values);
}

export function pendingEvents({ after = 0, candidateId, limit = 100 } = {}) {
  const conditions = ["audit_events.sequence > ?"];
  const values = [after];
  if (candidateId) {
    conditions.push("audit_events.candidate_id = ?");
    values.push(candidateId);
  }
  values.push(limit);
  return db
    .prepare(
      `SELECT audit_events.sequence, audit_events.id, audit_events.candidate_id AS candidateId,
              audit_events.actor_name AS actor, audit_events.action, audit_events.detail,
              audit_events.event_type AS type, audit_events.created_at AS timestamp
         FROM outbox
         JOIN audit_events ON audit_events.id = outbox.id
        WHERE ${conditions.join(" AND ")}
        ORDER BY audit_events.sequence ASC LIMIT ?`,
    )
    .all(...values);
}

export function markOutboxDispatched(id) {
  db.prepare("UPDATE outbox SET dispatched_at = ? WHERE id = ? AND dispatched_at IS NULL").run(
    now(),
    id,
  );
}

export function insertReleaseAuthorization({ id, candidateId, commitSha, artifactDigest, policyVersion, validationIds, actorId }) {
  const timestamp = now();
  db.prepare(
    `INSERT INTO release_authorizations
      (id, candidate_id, commit_sha, artifact_digest, policy_version,
       stage_validation_ids_json, authorized_by, authorized_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(id, candidateId, commitSha, artifactDigest, policyVersion, jsonColumn(validationIds), actorId, timestamp);
  return {
    id,
    candidateId,
    commitSha,
    artifactDigest,
    policyVersion,
    validationIds,
    actorId,
    authorizedAt: timestamp,
  };
}

export function getReleaseAuthorization(candidateId) {
  const row = db
    .prepare(
      `SELECT release_authorizations.id, release_authorizations.candidate_id AS candidateId,
              release_authorizations.commit_sha AS commitSha,
              release_authorizations.artifact_digest AS artifactDigest,
              release_authorizations.policy_version AS policyVersion,
              release_authorizations.stage_validation_ids_json AS validationIds,
              release_authorizations.authorized_by AS actorId,
              users.display_name AS authorizedBy,
              release_authorizations.authorized_at AS authorizedAt
         FROM release_authorizations
         JOIN users ON users.id = release_authorizations.authorized_by
        WHERE release_authorizations.candidate_id = ?
        ORDER BY release_authorizations.authorized_at DESC LIMIT 1`,
    )
    .get(candidateId);
  return row ? { ...row, validationIds: safeJson(row.validationIds, []) } : null;
}

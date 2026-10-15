import { randomUUID } from "node:crypto";
import path from "node:path";
import {
  STAGES,
  calculateProgress,
  evaluateStage,
} from "../governance.js";
import {
  appendEvent,
  createArtifact,
  createCandidate,
  createDocument,
  db,
  findCandidate,
  findStage,
  getEvidence,
  getReleaseAuthorization,
  getCandidate,
  getDocument,
  insertEvidence,
  insertValidation,
  insertReleaseAuthorization,
  jsonColumn,
  listAllCandidateEvidence,
  listArtifacts,
  listAudit,
  listDocuments,
  listEvidence,
  updateArtifact,
  updateEvidenceScan,
  updateStage,
  withTransaction,
} from "./database.mjs";
import { config } from "./config.mjs";
import { analyzeEvidence } from "./ai.mjs";
import { assert, HttpError } from "./errors.mjs";
import { loadEvidenceFile } from "./storage.mjs";
import {
  checkCommitStatus,
  createPullRequest,
  createReleaseTag,
  setCommitStatus,
} from "./github.mjs";

const severities = new Set(["critical", "high", "medium", "low", "info"]);

function assertCandidate(candidateId) {
  const candidate = findCandidate(candidateId);
  assert(candidate, 404, "candidate_not_found", "The requested release candidate was not found.");
  return candidate;
}

function assertStage(candidateId, stageId) {
  assert(STAGES.some((stage) => stage.id === stageId), 404, "stage_not_found", "The requested governance stage does not exist.");
  const stage = findStage(candidateId, stageId);
  assert(stage, 404, "stage_not_found", "The requested governance stage does not belong to this candidate.");
  return stage;
}

function isUnlocked(candidateId, position) {
  return position === 0 || findStage(candidateId, STAGES[position - 1]?.id)?.gate_status === "passed";
}

function verifyRevision(request, candidate) {
  const expected = request.headers["if-match"];
  assert(
    typeof expected === "string" && expected.length > 0,
    428,
    "revision_required",
    "Mutations must include the candidate revision in the If-Match header.",
  );
  assert(
    expected === `"${candidate.revision}"`,
    412,
    "stale_revision",
    "The candidate changed since it was loaded. Refresh the workspace before trying again.",
    { currentRevision: candidate.revision },
  );
}

function invalidateDownstream(candidateId, stageId) {
  const start = STAGES.findIndex((definition) => definition.id === stageId);
  for (let index = start; index < STAGES.length; index += 1) {
    const current = findStage(candidateId, STAGES[index].id);
    if (!current) continue;
    const updates = {};
    if (index === start) {
      updates.confirmedEvidenceRevision = null;
      updates.confirmedBy = null;
      updates.confirmedAt = null;
      updates.validation = null;
      updates.gateStatus = current.gateStatus === "locked" ? "locked" : "not_run";
      updates.workStatus = "in_progress";
    } else if (current.gateStatus === "passed" || current.gateStatus === "awaiting_approval") {
      updates.validation = current.validation
        ? { ...current.validation, outcome: "stale" }
        : null;
      updates.gateStatus = "stale";
      updates.workStatus = "in_progress";
      updates.approverId = null;
      updates.approvedAt = null;
    }
    if (Object.keys(updates).length) updateStage(candidateId, STAGES[index].id, updates);
  }
}

export function publicCandidate(candidateId) {
  const candidate = getCandidate(candidateId);
  assert(candidate, 404, "candidate_not_found", "The requested release candidate was not found.");
  const evidence = listAllCandidateEvidence(candidateId);
  const documents = listDocuments(candidateId);
  const artifacts = listArtifacts(candidateId);
  const storedAuthorization = getReleaseAuthorization(candidateId);
  const allAudit = listAudit({ candidateId, limit: 30 }).reverse();
  const stages = candidate.stages.map((stage) => {
    const definition = STAGES.find((item) => item.id === stage.stage_id);
    const stageEvidence = evidence.filter((item) => item.stageId === stage.stage_id);
    const findings = stage.findings.map((finding) => ({
      ...finding,
      status: stage.dispositions[finding.id]?.status ?? "open",
    }));
    const checklist = Object.fromEntries(
      Object.entries(stage.checklist).map(([index, value]) => [index, value === true]),
    );
    return {
      id: stage.stage_id,
      position: stage.position,
      name: definition.name,
      shortName: definition.shortName,
      description: definition.description,
      objective: definition.objective,
      evidenceRequirements: definition.evidence,
      checklistItems: definition.checklist.map((label, index) => ({
        key: index,
        label,
        completed: checklist[index] === true,
      })),
      workStatus: stage.work_status,
      gateStatus: stage.gate_status,
      checklist,
      metrics: stage.metrics,
      findings,
      analysis: stage.analysis,
      analyzedEvidenceRevision: stage.analyzed_evidence_revision,
      evidenceRevision: stage.evidence_revision,
      evidenceFiles: stageEvidence,
      confirmedEvidenceRevision: stage.confirmed_evidence_revision,
      validation: stage.validation,
      approvals: stage.approver_id
        ? [{ actor: stage.approver_id, status: stage.gate_status, timestamp: stage.approved_at }]
        : [],
      gateTimestamp: stage.approved_at,
      completion: stageProgress(stage, stageEvidence, findings, definition),
    };
  });
  const progress = calculateProgress(
    stages.map((stage) => ({
      gateStatus: stage.gateStatus,
      checklist: stage.checklist,
    })),
  );
  const releaseAuthorization = storedAuthorization
    ? {
        authorized:
          storedAuthorization.commitSha === candidate.commit_sha &&
          storedAuthorization.artifactDigest === candidate.artifact_digest &&
          storedAuthorization.policyVersion === candidate.policy_version &&
          stages.every((stage) => stage.gateStatus === "passed"),
        authorizedAt: storedAuthorization.authorizedAt,
        commitSha: storedAuthorization.commitSha,
        artifactDigest: storedAuthorization.artifactDigest,
        policyVersion: storedAuthorization.policyVersion,
      }
    : null;
  return {
    candidate: {
      id: candidate.id,
      projectId: candidate.project_id,
      projectName: candidate.project_name,
      releaseName: candidate.release_name,
      commitSha: candidate.commit_sha,
      artifactDigest: candidate.artifact_digest,
      policyVersion: candidate.policy_version,
      revision: candidate.revision,
      targetDate: candidate.target_date,
      createdAt: candidate.created_at,
      updatedAt: candidate.updated_at,
    },
    stages,
    overallProgress: progress,
    releaseConfidence: calculateConfidence(stages),
    defectEscapeRate: null,
    securityVulnerabilityCount: null,
    regressionRisk: calculateRisk(stages),
    productionReadiness: stages[5]?.completion ?? 0,
    releaseAuthorization,
    evidence,
    documents: documents.map(({ id, candidateId: _, stageId, title, format, createdAt, createdBy }) => ({
      id,
      stageId,
      title,
      format,
      createdAt,
      createdBy,
    })),
    artifacts,
    auditEvents: allAudit,
  };
}

function stageProgress(stage, evidence, findings, definition) {
  if (stage.gate_status === "passed") return 100;
  const controls = Object.values(stage.checklist).filter(Boolean).length;
  const checklistProgress = definition.checklist.length
    ? controls / definition.checklist.length
    : 0;
  const evidenceProgress = Math.min(1, evidence.length / definition.evidence.length);
  const findingProgress = findings.length
    ? findings.filter((finding) => finding.status === "resolved").length / findings.length
    : 1;
  return Math.round(((checklistProgress + evidenceProgress + findingProgress) / 3) * 100);
}

function calculateConfidence(stages) {
  const eligibleStages = stages.filter((stage) => stage.gateStatus === "passed");
  if (!stages.length) return { score: null, status: "unavailable", releaseEligible: false };
  const score = Math.round((eligibleStages.length / stages.length) * 100);
  return {
    score,
    status: eligibleStages.length === stages.length ? "final" : "provisional",
    releaseEligible: eligibleStages.length === stages.length,
    passedStages: eligibleStages.length,
    totalStages: stages.length,
    explanation:
      eligibleStages.length === stages.length
        ? "All six evidence-bound governance gates passed. Final authorization remains a separate action."
        : `${stages.length - eligibleStages.length} governance gate(s) have not passed. The score is an index, not a probability.`,
  };
}

function calculateRisk(stages) {
  const findings = stages.flatMap((stage) => stage.findings);
  if (!findings.length && !stages.some((stage) => stage.analysis)) return null;
  const weights = { critical: 25, high: 12, medium: 5, low: 1, info: 0 };
  const outstanding = findings
    .filter((finding) => finding.status !== "resolved")
    .reduce((total, finding) => total + (weights[finding.severity] ?? 0), 0);
  return Math.min(100, outstanding);
}

export function createFirstCandidate(actor) {
  return withTransaction(() => {
    const candidate = createCandidate({
      projectName: "Software Governance",
      releaseName: "First release",
      actor,
    });
    const event = appendEvent({
      candidateId: candidate.id,
      actor,
      action: "Created initial release candidate",
      detail: "The workspace is empty; upload and validate actual evidence to begin.",
      type: "candidate",
    });
    return { candidate: candidate.id, event };
  });
}

export function createNewCandidate({ projectName, releaseName, commitSha, actor }) {
  assert(typeof projectName === "string" && projectName.trim().length >= 2 && projectName.length <= 120, 400, "invalid_project_name", "Project name must be 2 to 120 characters.");
  assert(typeof releaseName === "string" && releaseName.trim().length >= 1 && releaseName.length <= 120, 400, "invalid_release_name", "Release name must be 1 to 120 characters.");
  assert(
    !commitSha || /^[a-f0-9]{40}$/i.test(commitSha),
    400,
    "invalid_commit_sha",
    "Provide either no commit SHA or a full 40-character Git commit SHA.",
  );
  const candidate = withTransaction(() => {
    const created = createCandidate({
      projectName: projectName.trim(),
      releaseName: releaseName.trim(),
      commitSha: commitSha || "",
      actor,
    });
    appendEvent({
      candidateId: created.id,
      actor,
      action: "Created release candidate",
      detail: `${created.project_name} · ${created.release_name}`,
      type: "candidate",
    });
    return created;
  });
  return publicCandidate(candidate.id);
}

export function setCoverageMetrics({ candidateId, commitSha, metrics, signatureActor }) {
  const candidate = assertCandidate(candidateId);
  assert(
    candidate.commit_sha &&
      candidate.commit_sha.toLowerCase() === commitSha.toLowerCase(),
    409,
    "coverage_commit_mismatch",
    "Coverage can only be recorded for the exact pinned candidate commit.",
  );
  assert(metrics && typeof metrics === "object" && !Array.isArray(metrics), 400, "invalid_coverage_metrics", "Coverage metrics must be an object.");
  const bounded = {};
  for (const [key, value] of Object.entries(metrics)) {
    assert(
      ["lineCoverage", "branchCoverage", "criticalPathCoverage"].includes(key),
      400,
      "unsupported_coverage_metric",
      `The metric "${key}" is not supported.`,
    );
    assert(
      typeof value === "number" &&
        Number.isFinite(value) &&
        value >= 0 &&
        value <= 100,
      400,
      "invalid_coverage_value",
      `The metric "${key}" must be between 0 and 100.`,
    );
    bounded[key] = value;
  }
  assert(
    bounded.lineCoverage !== undefined &&
      bounded.branchCoverage !== undefined &&
      bounded.criticalPathCoverage !== undefined,
    400,
    "incomplete_coverage_metrics",
    "Line, branch, and critical-path coverage metrics are all required.",
  );
  const stage = assertStage(candidateId, "tests");
  assert(
    stage.gate_status !== "passed",
    409,
    "stage_already_passed",
    "Create a new candidate before changing coverage evidence for a passed gate.",
  );
  let emitted;
  withTransaction(() => {
    const updated = findStage(candidateId, "tests");
    invalidateDownstream(candidateId, "tests");
    updateStage(candidateId, "tests", {
      metrics: {
        ...updated.metrics,
        ...bounded,
        coverageProvenance: {
          source: "hmac-authenticated-ci-webhook",
          commitSha,
          submittedAt: new Date().toISOString(),
          submitter: signatureActor,
        },
      },
      evidenceRevision: updated.evidence_revision + 1,
      confirmedEvidenceRevision: null,
      confirmedBy: null,
      confirmedAt: null,
      validation: null,
      gateStatus: "not_run",
      workStatus: "in_progress",
    });
    emitted = appendEvent({
      candidateId,
      action: "Recorded authenticated CI coverage metrics",
      detail: `${commitSha} · Line ${bounded.lineCoverage}% · Branch ${bounded.branchCoverage}% · Critical paths ${bounded.criticalPathCoverage}%`,
      type: "coverage",
      payload: { stageId: "tests", commitSha, metrics: bounded, actor: signatureActor },
    });
  });
  eventBusPublish(emitted);
  return publicCandidate(candidateId);
}

export function changeCandidateIdentity(candidateId, request, { commitSha, artifactDigest, targetDate }, actor) {
  const candidate = assertCandidate(candidateId);
  verifyRevision(request, candidate);
  assert(actor.role === "admin", 403, "role_forbidden", "Only an administrator may change the pinned release-candidate identity.");
  assert(typeof commitSha === "string" && /^[a-f0-9]{40}$/i.test(commitSha), 400, "invalid_commit_sha", "A full 40-character Git commit SHA is required.");
  assert(
    !artifactDigest || /^sha256:[a-f0-9]{64}$/i.test(artifactDigest),
    400,
    "invalid_artifact_digest",
    "The artifact digest must be a SHA-256 digest.",
  );
  assert(
    !targetDate || /^\d{4}-\d{2}-\d{2}$/.test(targetDate),
    400,
    "invalid_target_date",
    "Target dates must use the YYYY-MM-DD format.",
  );
  withTransaction(() => {
    db.prepare(
      `UPDATE candidates
          SET commit_sha = ?, artifact_digest = ?, target_date = ?,
              revision = revision + 1, updated_at = ?
        WHERE id = ?`,
    ).run(commitSha, artifactDigest || "", targetDate || null, new Date().toISOString(), candidateId);
    for (const definition of STAGES) {
      const stage = findStage(candidateId, definition.id);
      updateStage(candidateId, definition.id, {
        gateStatus: stage.gate_status === "locked" ? "locked" : "not_run",
        workStatus: stage.gate_status === "locked" ? "not_started" : "in_progress",
        analyzedEvidenceRevision: null,
        analysis: null,
        confirmedEvidenceRevision: null,
        confirmedBy: null,
        confirmedAt: null,
        validation: null,
        approverId: null,
        approvedAt: null,
      });
    }
    const event = appendEvent({
      candidateId,
      actor,
      action: "Changed pinned release candidate",
      detail: `Commit ${commitSha} · SHA-256 artifact ${artifactDigest || "not provided"} · All previous validations invalidated`,
      type: "candidate",
    });
    eventBusPublish(event);
  });
  return publicCandidate(candidateId);
}

let broadcaster = () => {};
export function setEventBroadcaster(fn) {
  broadcaster = fn;
}
function eventBusPublish(event) {
  broadcaster(event);
}

function commitIfMatch(candidateId, request) {
  const candidate = assertCandidate(candidateId);
  verifyRevision(request, candidate);
  return candidate;
}

export function updateChecklist({ candidateId, stageId, index, checked, actor, request }) {
  const candidate = commitIfMatch(candidateId, request);
  assert(actor.role !== "auditor", 403, "role_forbidden", "Auditors cannot modify review checklists.");
  const definition = STAGES.find((stage) => stage.id === stageId);
  const stage = assertStage(candidateId, stageId);
  assert(isUnlocked(candidateId, stage.position), 409, "stage_locked", "The previous governance gate must pass before this stage can be edited.");
  assert(stage.gate_status !== "passed", 409, "stage_already_passed", "Passed stages are immutable. Open a new release candidate to reassess them.");
  assert(Number.isSafeInteger(index) && index >= 0 && index < definition.checklist.length, 400, "invalid_checklist_item", "The checklist control does not exist.");
  assert(typeof checked === "boolean", 400, "invalid_checklist_value", "Checklist state must be a boolean.");
  const checklist = { ...stage.checklist, [index]: checked };
  let emitted;
  withTransaction(() => {
    invalidateDownstream(candidateId, stageId);
    const updated = findStage(candidateId, stageId);
    updateStage(candidateId, stageId, {
      checklist,
      workStatus: "in_progress",
    });
    emitted = appendEvent({
      candidateId,
      actor,
      action: checked ? "Completed review control" : "Reopened review control",
      detail: `${definition.shortName} · ${definition.checklist[index]}`,
      type: "checklist",
      payload: { stageId },
    });
  });
  eventBusPublish(emitted);
  return publicCandidate(candidateId);
}

export function addFindingDisposition({ candidateId, stageId, findingId, request, actor, status, rationale, evidenceId }) {
  const candidate = commitIfMatch(candidateId, request);
  const stage = assertStage(candidateId, stageId);
  assert(isUnlocked(candidateId, stage.position), 409, "stage_locked", "This stage is locked.");
  assert(stage.gate_status !== "passed", 409, "stage_already_passed", "Passed stages are immutable.");
  assert(status === "resolved", 400, "invalid_finding_disposition", "Blocking findings must be explicitly resolved with linked evidence; risk acceptance is not supported.");
  assert(typeof rationale === "string" && rationale.trim().length >= 20 && rationale.length <= 2000, 400, "invalid_finding_rationale", "Provide a 20 to 2,000 character resolution rationale.");
  const finding = stage.findings.find((item) => item.id === findingId);
  assert(finding, 404, "finding_not_found", "The requested finding does not belong to this stage.");
  const evidence = listEvidence(candidateId, stageId).find((item) => item.id === evidenceId);
  assert(evidence && evidence.scanStatus === "clean", 409, "clean_evidence_required", "A resolved finding must link to clean, malware-scanned stage evidence.");
  const dispositions = {
    ...stage.dispositions,
    [findingId]: {
      status,
      rationale: rationale.trim(),
      evidenceId,
      resolvedBy: actor.id,
      resolvedAt: new Date().toISOString(),
    },
  };
  let emitted;
  withTransaction(() => {
    invalidateDownstream(candidateId, stageId);
    updateStage(candidateId, stageId, { dispositions });
    emitted = appendEvent({
      candidateId,
      actor,
      action: "Recorded finding resolution",
      detail: `${findingId} · Clean evidence ${evidence.name}`,
      type: "finding",
      payload: { stageId, findingId },
    });
  });
  eventBusPublish(emitted);
  return publicCandidate(candidateId);
}

export async function createEvidence({ candidateId, stageId, filename, bytes, actor, request }) {
  const candidate = commitIfMatch(candidateId, request);
  const stage = assertStage(candidateId, stageId);
  assert(actor.role !== "auditor", 403, "role_forbidden", "Auditors cannot upload or change evidence.");
  assert(isUnlocked(candidateId, stage.position), 409, "stage_locked", "The previous governance gate must pass before adding evidence.");
  assert(stage.gate_status !== "passed", 409, "stage_already_passed", "Passed stages are immutable. Create a new candidate to change evidence.");
  const { saveEvidenceFile } = await import("./storage.mjs");
  const data = await saveEvidenceFile({ filename, bytes, candidateId, stageId, actor });
  let evidence;
  let emitted;
  try {
    withTransaction(() => {
      evidence = insertEvidence(data);
      invalidateDownstream(candidateId, stageId);
      const refreshed = findStage(candidateId, stageId);
      updateStage(candidateId, stageId, {
        evidenceRevision: refreshed.evidence_revision + 1,
        metrics: { ...refreshed.metrics },
      });
      emitted = appendEvent({
        candidateId,
        actor,
        action: "Uploaded evidence",
        detail: `${data.originalName} · ${data.sizeBytes} bytes · Scanner: ${data.scanStatus}`,
        type: "evidence",
        payload: { stageId, evidenceId: data.id, scanStatus: data.scanStatus },
      });
    });
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
      const { rm } = await import("node:fs/promises");
      await rm(path.join(config.evidenceRoot, data.storageName), { force: true });
      throw new HttpError(409, "duplicate_evidence", "An identical file is already attached to this stage.");
    }
    throw error;
  }
  eventBusPublish(emitted);
  return evidence;
}

export function evidenceForStage(candidateId, stageId) {
  assertCandidate(candidateId);
  assertStage(candidateId, stageId);
  return listEvidence(candidateId, stageId);
}

export function evidenceDetails(id) {
  return db
    .prepare("SELECT * FROM evidence WHERE id = ?")
    .get(id);
}

export function removeEvidence({ candidateId, evidenceId, request, actor }) {
  const candidate = commitIfMatch(candidateId, request);
  const evidence = evidenceDetails(evidenceId);
  assert(evidence && evidence.candidate_id === candidateId, 404, "evidence_not_found", "The requested evidence does not belong to this candidate.");
  assert(actor.role === "admin" || actor.role === "qa_lead", 403, "role_forbidden", "Only administrators and QA leads may remove evidence.");
  const stage = assertStage(candidateId, evidence.stage_id);
  assert(isUnlocked(candidateId, stage.position) && stage.gate_status !== "passed", 409, "stage_immutable", "Evidence for locked or passed stages cannot be removed.");
  return (async () => {
    const { rm } = await import("node:fs/promises");
    await rm(path.join(config.evidenceRoot, evidence.storage_name), { force: true });
    let emitted;
    withTransaction(() => {
      db.prepare("DELETE FROM evidence WHERE id = ?").run(evidenceId);
      invalidateDownstream(candidateId, evidence.stage_id);
      const updated = findStage(candidateId, evidence.stage_id);
      updateStage(candidateId, evidence.stage_id, {
        evidenceRevision: updated.evidence_revision + 1,
      });
      emitted = appendEvent({
        candidateId,
        actor,
        action: "Removed stage evidence",
        detail: evidence.original_name,
        type: "evidence",
        payload: { stageId: evidence.stage_id, evidenceId },
      });
    });
    eventBusPublish(emitted);
    return publicCandidate(candidateId);
  })();
}

export async function runStageAnalysis({ candidateId, stageId, actor, request, evidenceIds }) {
  const candidate = commitIfMatch(candidateId, request);
  assert(actor.role === "admin" || actor.role === "qa_lead", 403, "role_forbidden", "Only administrators and QA leads may run stage analysis.");
  const definition = STAGES.find((stage) => stage.id === stageId);
  const stage = assertStage(candidateId, stageId);
  assert(isUnlocked(candidateId, stage.position), 409, "stage_locked", "The previous governance gate must pass before stage analysis.");
  assert(stage.gate_status !== "passed", 409, "stage_already_passed", "Passed stages are immutable.");
  assert(
    Array.isArray(evidenceIds) &&
      evidenceIds.length > 0 &&
      evidenceIds.length <= 12 &&
      evidenceIds.every((id) => typeof id === "string"),
    400,
    "invalid_analysis_evidence",
    "Select 1 to 12 source evidence IDs for analysis.",
  );
  const allEvidence = listEvidence(candidateId, stageId);
  const selected = evidenceIds.map((id) => allEvidence.find((item) => item.id === id));
  assert(selected.every(Boolean), 400, "invalid_analysis_evidence", "Every analyzed evidence ID must belong to this stage.");
  const distinctEvidence = [...new Set(selected.map((item) => item.id))].map(
    (id) => selected.find((item) => item.id === id),
  );
  const aiResult = await analyzeEvidence({
    definition,
    evidence: distinctEvidence,
    readFile: async (item) => {
      const internal = evidenceDetails(item.id);
      return loadEvidenceFile(internal);
    },
  });
  let emitted;
  withTransaction(() => {
    const existingStage = findStage(candidateId, stageId);
    assert(
      existingStage.evidence_revision === stage.evidence_revision,
      412,
      "evidence_changed_during_analysis",
      "Evidence changed during analysis. Run the analysis again against the current evidence.",
    );
    updateStage(candidateId, stageId, {
      findings: aiResult.findings,
      dispositions: {},
      analysis: aiResult,
      analyzedEvidenceRevision: existingStage.evidence_revision,
      confirmedEvidenceRevision: null,
      confirmedBy: null,
      confirmedAt: null,
      validation: null,
      gateStatus: "not_run",
      workStatus: "in_progress",
    });
    emitted = appendEvent({
      candidateId,
      actor,
      action: `Completed AI analysis · ${definition.shortName}`,
      detail: `${aiResult.findings.length} cited advisory finding(s) · Evidence revision ${stage.evidence_revision}`,
      type: "analysis",
      payload: { stageId, analysisId: aiResult.id },
    });
  });
  eventBusPublish(emitted);
  return publicCandidate(candidateId);
}

function cleanEvidenceCount(candidateId, stageId) {
  return listEvidence(candidateId, stageId).filter((evidence) => evidence.scanStatus === "clean").length;
}

function hasReadyUpstreamStages(candidateId, index) {
  return STAGES.slice(0, index).every(
    (definition) => findStage(candidateId, definition.id)?.gate_status === "passed",
  );
}

function runChecks({ candidate, definition, stage, evidence, commitChecks, candidateStages }) {
  const checks = [];
  const push = (id, label, expected, actual, passed, evidenceIds = []) =>
    checks.push({ id, label, expected, actual: actual ?? null, status: passed ? "passed" : "failed", evidenceIds });

  const cleanEvidence = evidence.filter((item) => item.scanStatus === "clean");
  const pendingEvidence = evidence.filter((item) => !["clean", "infected"].includes(item.scanStatus));
  const infectedEvidence = evidence.filter((item) => item.scanStatus === "infected");
  const blockingFindings = stage.findings.filter(
    (finding) =>
      ["critical", "high"].includes(finding.severity) &&
      stage.dispositions[finding.id]?.status !== "resolved",
  );
  const definitionIndex = STAGES.findIndex((item) => item.id === definition.id);

  push("required-evidence", "At least one stage evidence item", "≥ 1 file", `${evidence.length} uploaded`, evidence.length > 0, evidence.map((item) => item.id));
  push("malware-scan", "Evidence malware scan", "Every file clean", pendingEvidence.length ? `${pendingEvidence.length} unscanned` : infectedEvidence.length ? `${infectedEvidence.length} malicious` : `${cleanEvidence.length}/${evidence.length} clean`, evidence.length > 0 && pendingEvidence.length === 0 && infectedEvidence.length === 0 && cleanEvidence.length === evidence.length, evidence.map((item) => item.id));
  push("review-checklist", "Required review controls", "All completed", `${Object.values(stage.checklist).filter(Boolean).length}/${definition.checklist.length} complete`, definition.checklist.every((_, index) => stage.checklist[index] === true));
  push("ai-analysis", "Evidence-cited AI analysis", "Current analysis", stage.analyzed_evidence_revision === stage.evidence_revision && stage.analysis !== null ? "Completed" : "Missing or stale", stage.analyzed_evidence_revision === stage.evidence_revision && stage.analysis !== null);
  push("blocking-findings", "Critical/high findings", "All resolved", blockingFindings.length ? `${blockingFindings.length} unresolved` : "None unresolved", blockingFindings.length === 0, blockingFindings.map((finding) => finding.evidenceId).filter(Boolean));
  push("previous-gates", "Required upstream gates", "All passed", hasReadyUpstreamStages(candidate.id, definitionIndex) ? "Passed" : "Pending", hasReadyUpstreamStages(candidate.id, definitionIndex));

  if (definition.id === "tests") {
    const line = Number(stage.metrics.lineCoverage);
    const branch = Number(stage.metrics.branchCoverage);
    const critical = Number(stage.metrics.criticalPathCoverage);
    push("line-coverage", "Line coverage", "≥ 85%", Number.isFinite(line) ? `${line.toFixed(2)}%` : "Not available", Number.isFinite(line) && line >= 85);
    push("branch-coverage", "Branch coverage", "≥ 80%", Number.isFinite(branch) ? `${branch.toFixed(2)}%` : "Not available", Number.isFinite(branch) && branch >= 80);
    push("critical-path-coverage", "Critical path coverage", "100%", Number.isFinite(critical) ? `${critical.toFixed(2)}%` : "Not available", Number.isFinite(critical) && critical >= 100);
    const passingTestCheck = commitChecks?.checks?.filter((check) => /test|coverage|quality/i.test(check.name ?? "")) ?? [];
    push("test-runner", "Automated test and coverage CI", "Successful checks", passingTestCheck.length ? `${passingTestCheck.filter((check) => check.status === "completed" && check.conclusion === "success").length}/${passingTestCheck.length} passed` : "Not available", passingTestCheck.length > 0 && passingTestCheck.every((check) => check.status === "completed" && check.conclusion === "success"));
  }

  if (definition.id === "code" || definition.id === "cicd" || definition.id === "production") {
    push("candidate-commit", "Pinned full release commit", "Full Git SHA", candidate.commit_sha || "Not configured", /^[a-f0-9]{40}$/i.test(candidate.commit_sha));
    push("artifact-digest", "Immutable build artifact digest", "SHA-256 digest", candidate.artifact_digest || "Not configured", /^sha256:[a-f0-9]{64}$/i.test(candidate.artifact_digest));
  }

  if (definition.id === "code" || definition.id === "cicd" || definition.id === "production") {
    const checks = commitChecks?.checks ?? [];
    const requiredChecks = checks.filter((check) =>
      ["QUEUED", "IN_PROGRESS", "COMPLETED"].includes(check.status),
    );
    const allCompleted = requiredChecks.length > 0 && requiredChecks.every(
      (check) => check.status === "COMPLETED" && check.conclusion === "SUCCESS",
    );
    push("github-check-runs", "GitHub Actions quality checks", "Every required check passed", requiredChecks.length ? `${requiredChecks.filter((check) => check.status === "COMPLETED" && check.conclusion === "SUCCESS").length}/${requiredChecks.length} passed` : "Not configured or no checks", allCompleted);
  }

  if (definition.id === "production") {
    const missing = candidateStages.filter((item) => item.gate_status !== "passed");
    push("all-governance-gates", "All required governance stages", "6 / 6 passed", `${6 - missing.length} / 6 passed`, missing.length === 0);
  }

  return checks;
}

async function collectGithubChecks(candidate) {
  if (!config.github.token) return null;
  try {
    const status = await checkCommitStatus(candidate.commit_sha);
    const runs = await fetch(
      `${config.github.apiUrl}/repos/${encodeURIComponent(config.github.owner)}/${encodeURIComponent(config.github.repo)}/commits/${candidate.commit_sha}/check-runs?per_page=100`,
      {
        headers: {
          Authorization: `Bearer ${config.github.token}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
        },
        signal: AbortSignal.timeout(15_000),
      },
    );
    if (!runs.ok) return { status, checks: [] };
    const body = await runs.json();
    return { status, checks: body.check_runs ?? [] };
  } catch (error) {
    console.error("Unable to fetch commit quality checks.", error.message);
    throw new HttpError(502, "github_check_runs_unavailable", "CI checks could not be verified. The validation was not completed.");
  }
}

export async function confirmStage({ candidateId, stageId, request, actor }) {
  const candidate = commitIfMatch(candidateId, request);
  const stage = assertStage(candidateId, stageId);
  assert(actor.role === "admin" || actor.role === "qa_lead", 403, "role_forbidden", "Only an administrator or QA lead may confirm a governance review.");
  assert(isUnlocked(candidateId, stage.position), 409, "stage_locked", "Pass the previous gate before confirming this review.");
  assert(stage.gate_status !== "passed", 409, "stage_already_passed", "A passed stage is immutable.");
  const definition = STAGES.find((item) => item.id === stageId);
  const evidence = listEvidence(candidateId, stageId);
  assert(evidence.length > 0, 409, "stage_evidence_required", "Upload actual, malware-scanned evidence before confirming a review.");
  assert(evidence.every((item) => item.scanStatus === "clean"), 409, "evidence_not_clean", "Every stage evidence item must pass malware scanning before a review is confirmed.");
  assert(definition.checklist.every((_, index) => stage.checklist[index] === true), 409, "review_checklist_incomplete", "Complete all required review checklist items before confirming.");
  assert(stage.analysis !== null && stage.analyzed_evidence_revision === stage.evidence_revision, 409, "analysis_required", "Run a cited AI analysis for the current evidence revision before confirming.");
  const unresolvedFindings = stage.findings.filter(
    (finding) =>
      ["critical", "high"].includes(finding.severity) &&
      stage.dispositions[finding.id]?.status !== "resolved",
  );
  assert(unresolvedFindings.length === 0, 409, "blocking_findings_unresolved", "Resolve all critical and high findings using linked, clean evidence before confirming.", { findingIds: unresolvedFindings.map((finding) => finding.id) });
  const timestamp = new Date().toISOString();
  let emitted;
  withTransaction(() => {
    updateStage(candidateId, stageId, {
      workStatus: "confirmed",
      confirmedEvidenceRevision: stage.evidence_revision,
      confirmedBy: actor.id,
      confirmedAt: timestamp,
      gateStatus: "not_run",
      validation: null,
    });
    emitted = appendEvent({
      candidateId,
      actor,
      action: `Confirmed ${definition.shortName} review`,
      detail: `Evidence revision ${stage.evidence_revision} · Policy v${candidate.policy_version}`,
      type: "confirmation",
      payload: { stageId, evidenceRevision: stage.evidence_revision },
    });
  });
  eventBusPublish(emitted);
  return publicCandidate(candidateId);
}

export async function validateStage({ candidateId, stageId, request, actor }) {
  const candidate = commitIfMatch(candidateId, request);
  const stage = assertStage(candidateId, stageId);
  assert(actor.role === "admin" || actor.role === "qa_lead", 403, "role_forbidden", "Only an administrator or QA lead may validate a governance gate.");
  assert(isUnlocked(candidateId, stage.position), 409, "stage_locked", "The previous stage must pass before validation.");
  assert(stage.gate_status !== "passed", 409, "stage_already_passed", "Passed stages are immutable.");
  assert(
    stage.confirmed_evidence_revision === stage.evidence_revision,
    409,
    "review_confirmation_required",
    "Confirm the current evidence revision before running policy validation.",
  );
  const definition = STAGES.find((item) => item.id === stageId);
  const candidateStages = getCandidate(candidateId).stages;
  const evidence = listEvidence(candidateId, stageId);
  const commitChecks =
    ["code", "tests", "cicd", "production"].includes(stageId)
      ? await collectGithubChecks(candidate)
      : null;
  const checks = runChecks({ candidate, definition, stage, evidence, commitChecks, candidateStages });
  const outcome = checks.every((check) => check.status === "passed") ? "passed" : "failed";
  let validation;
  let emitted;
  withTransaction(() => {
    const refreshed = findStage(candidateId, stageId);
    assert(
      refreshed.evidence_revision === stage.evidence_revision &&
        refreshed.confirmed_evidence_revision === stage.evidence_revision,
      412,
      "evidence_changed_during_validation",
      "Stage evidence changed during validation. Confirm it again and rerun validation.",
    );
    validation = insertValidation({
      candidateId,
      stageId,
      evidenceRevision: stage.evidence_revision,
      policyVersion: candidate.policy_version,
      outcome,
      checks,
      actorId: actor.id,
    });
    updateStage(candidateId, stageId, {
      gateStatus: outcome === "passed" ? "awaiting_approval" : "failed",
      validation: {
        ...validation,
        evidenceRevision: stage.evidence_revision,
        evidenceIds: evidence.map((item) => item.id),
        commitSha: candidate.commit_sha || null,
        artifactDigest: candidate.artifact_digest || null,
      },
    });
    emitted = appendEvent({
      candidateId,
      actor,
      action: `${outcome === "passed" ? "Passed" : "Failed"} ${definition.shortName} validation`,
      detail: `${checks.filter((check) => check.status === "passed").length}/${checks.length} deterministic policy checks passed · Policy v${candidate.policy_version}`,
      type: "validation",
      payload: { stageId, validationId: validation.id, outcome },
    });
  });
  eventBusPublish(emitted);

  if (candidate.commit_sha && config.github.token) {
    try {
      await setCommitStatus({
        sha: candidate.commit_sha,
        outcome: outcome === "passed" ? "success" : "failure",
        description: `${definition.shortName}: ${checks.filter((check) => check.status === "passed").length}/${checks.length} governance checks passed`,
        stageId,
      });
    } catch (error) {
      console.error("GitHub commit status could not be synchronized.", error.message);
    }
  }
  return publicCandidate(candidateId);
}

export function approveStage({ candidateId, stageId, request, actor }) {
  const candidate = commitIfMatch(candidateId, request);
  const stage = assertStage(candidateId, stageId);
  assert(actor.role === "admin" || actor.role === "qa_lead", 403, "role_forbidden", "Only an administrator or QA lead may approve a governance gate.");
  assert(isUnlocked(candidateId, stage.position), 409, "stage_locked", "The previous governance gate must pass before approving this one.");
  assert(stage.gate_status === "awaiting_approval", 409, "validation_not_passed", "A current, passing validation is required before approval.");
  assert(
    stage.validation &&
      stage.validation.outcome === "passed" &&
      stage.validation.evidenceRevision === stage.evidence_revision &&
      stage.confirmed_evidence_revision === stage.evidence_revision,
    409,
    "validation_stale",
    "The validation is stale or scoped to different evidence. Confirm and validate again.",
  );
  assert(stage.confirmed_by !== actor.id, 403, "separation_of_duties_violation", "A different authorized reviewer must approve a validation; the reviewer who confirmed it cannot approve it.");
  assert(
    !(
      stage.validation.commitSha &&
      stage.validation.commitSha !== candidate.commit_sha
    ),
    409,
    "candidate_changed_after_validation",
    "The pinned source commit changed after validation. Validate the current candidate again.",
  );
  const timestamp = new Date().toISOString();
  let emitted;
  withTransaction(() => {
    updateStage(candidateId, stageId, {
      gateStatus: "passed",
      workStatus: "confirmed",
      approverId: actor.id,
      approvedAt: timestamp,
    });
    if (stage.position + 1 < STAGES.length) {
      const next = findStage(candidateId, STAGES[stage.position + 1].id);
      if (next.gate_status === "locked") {
        updateStage(candidateId, next.stage_id, {
          gateStatus: "not_run",
          workStatus: "in_progress",
        });
      }
    }
    emitted = appendEvent({
      candidateId,
      actor,
      action: `Approved ${STAGES[stage.position].shortName} gate`,
      detail: `Validation ${stage.validation.id} · Evidence revision ${stage.evidence_revision} · Policy v${candidate.policy_version}`,
      type: "approval",
      payload: { stageId, validationId: stage.validation.id },
    });
  });
  eventBusPublish(emitted);
  return publicCandidate(candidateId);
}

export function authorizeRelease({ candidateId, request, actor }) {
  const candidate = commitIfMatch(candidateId, request);
  assert(actor.role === "admin" || actor.role === "qa_lead", 403, "role_forbidden", "A release manager or QA lead must request release authorization.");
  assert(
    /^[a-f0-9]{40}$/i.test(candidate.commit_sha) &&
      /^sha256:[a-f0-9]{64}$/i.test(candidate.artifact_digest),
    409,
    "release_identity_unpinned",
    "Pin the exact reviewed source commit and SHA-256 build artifact before release authorization.",
  );
  const current = getCandidate(candidateId);
  const stages = current.stages;
  assert(
    stages.length === STAGES.length && stages.every((stage) => stage.gate_status === "passed"),
    409,
    "release_gates_incomplete",
    "All six governance gates must pass before production release authorization.",
    { gates: stages.map(({ stage_id, gate_status }) => ({ stageId: stage_id, status: gate_status })) },
  );
  const totalClean = listAllCandidateEvidence(candidateId).every((item) => item.scanStatus === "clean");
  assert(totalClean, 409, "release_evidence_not_clean", "All candidate evidence must pass configured malware scanning.");

  let emitted;
  const authorization = randomUUID();
  let persistedAuthorization;
  withTransaction(() => {
    const latestCandidate = findCandidate(candidateId);
    assert(latestCandidate.revision === candidate.revision, 412, "stale_revision", "The release candidate changed while authorization was being checked.");
    persistedAuthorization = insertReleaseAuthorization({
      id: authorization,
      candidateId,
      commitSha: candidate.commit_sha,
      artifactDigest: candidate.artifact_digest,
      policyVersion: candidate.policy_version,
      validationIds: stages.map((stage) => stage.validation?.id),
      actorId: actor.id,
    });
    emitted = appendEvent({
      candidateId,
      actor,
      action: "Authorized production release",
      detail: `Authorization ${authorization} · Commit ${candidate.commit_sha} · Artifact ${candidate.artifact_digest} · Six gates passed`,
      type: "release",
      payload: {
        authorizationId: authorization,
        commitSha: candidate.commit_sha,
        artifactDigest: candidate.artifact_digest,
        stageIds: STAGES.map((stage) => stage.id),
      },
    });
  });
  eventBusPublish(emitted);
  return {
    authorizationId: authorization,
    authorized: true,
    deploymentPerformed: false,
    commitSha: candidate.commit_sha,
    artifactDigest: candidate.artifact_digest,
    policyVersion: candidate.policy_version,
    authorizedBy: actor.displayName,
    authorizedAt: persistedAuthorization.authorizedAt,
  };
}

export async function createAuthorizedReleaseTag({ candidateId, tag, message, actor }) {
  const candidate = assertCandidate(candidateId);
  assert(actor.role === "admin", 403, "role_forbidden", "Only an administrator may create a release tag.");
  const authorization = getReleaseAuthorization(candidateId);
  assert(authorization, 409, "release_not_authorized", "Record final production authorization before creating a release tag.");
  assert(
    authorization.commitSha === candidate.commit_sha &&
      authorization.artifactDigest === candidate.artifact_digest,
    409,
    "release_candidate_changed",
    "The pinned source or artifact changed after release authorization. Authorize the current candidate again.",
  );
  const snapshot = getCandidate(candidateId);
  assert(snapshot.stages.every((stage) => stage.gate_status === "passed"), 409, "release_gates_incomplete", "All six governance gates must remain valid before creating a release tag.");
  const result = await createReleaseTag({
    tag,
    targetSha: candidate.commit_sha,
    message: message || `Governance-authorized release ${candidate.release_name}\nAuthorization ${authorization.id}\nArtifact ${candidate.artifact_digest}`,
  });
  let event;
  withTransaction(() => {
    event = appendEvent({
      candidateId,
      actor,
      action: "Created authorized GitHub release tag",
      detail: `${result.tag} · ${result.targetSha}`,
      type: "release",
      payload: result,
    });
  });
  eventBusPublish(event);
  return result;
}

export async function rescanEvidence({ candidateId, evidenceId, request, actor }) {
  const candidate = commitIfMatch(candidateId, request);
  assert(actor.role === "admin" || actor.role === "qa_lead", 403, "role_forbidden", "Only administrators and QA leads may retry an evidence scan.");
  const internal = evidenceDetails(evidenceId);
  assert(internal && internal.candidate_id === candidateId, 404, "evidence_not_found", "The evidence does not belong to this candidate.");
  const stage = assertStage(candidateId, internal.stage_id);
  assert(stage.gate_status !== "passed", 409, "stage_already_passed", "Passed stages are immutable; create a new candidate to reassess evidence.");
  const { rescanEvidenceFile } = await import("./storage.mjs");
  const result = await rescanEvidenceFile(internal);
  if (result.status === "infected") {
    const { rm } = await import("node:fs/promises");
    await rm(path.join(config.evidenceRoot, internal.storage_name), { force: true });
  }
  let emitted;
  withTransaction(() => {
    updateEvidenceScan(evidenceId, result.status, result.detail);
    invalidateDownstream(candidateId, internal.stage_id);
    const current = findStage(candidateId, internal.stage_id);
    updateStage(candidateId, internal.stage_id, {
      evidenceRevision: current.evidence_revision + 1,
    });
    emitted = appendEvent({
      candidateId,
      actor,
      action: "Retried evidence malware scan",
      detail: `${internal.original_name} · Scanner status: ${result.status}`,
      type: "evidence",
      payload: { stageId: internal.stage_id, evidenceId, scanStatus: result.status },
    });
  });
  eventBusPublish(emitted);
  return getEvidence(evidenceId);
}

export function releaseConfidence(candidateId) {
  const snapshot = publicCandidate(candidateId);
  const stageFindings = snapshot.stages.flatMap((stage) => stage.findings);
  const blockingFindings = stageFindings.filter(
    (finding) =>
      ["critical", "high"].includes(finding.severity) &&
      finding.status !== "resolved",
  );
  return {
    releaseConfidence: {
      ...snapshot.releaseConfidence,
      blockingFindingCount: blockingFindings.length,
      evidenceItemCount: snapshot.evidence.length,
      unscannedEvidenceCount: snapshot.evidence.filter((item) => item.scanStatus !== "clean").length,
      riskScore: snapshot.regressionRisk,
      coverageScore: {
        line: snapshot.stages[3].metrics.lineCoverage ?? null,
        branch: snapshot.stages[3].metrics.branchCoverage ?? null,
        criticalPath: snapshot.stages[3].metrics.criticalPathCoverage ?? null,
      },
      calculatedAt: new Date().toISOString(),
      source: "deterministic-policy-engine",
      policyVersion: snapshot.candidate.policyVersion,
    },
    overallProgress: snapshot.overallProgress,
    stages: snapshot.stages.map(({ id, name, completion, gateStatus, findings, evidenceFiles }) => ({
      id,
      name,
      completion,
      gateStatus,
      openFindingCount: findings.filter((finding) => finding.status !== "resolved").length,
      evidenceCount: evidenceFiles.length,
    })),
  };
}

export function createStageDocument({ candidateId, stageId, format, actor }) {
  assert(actor.role !== "auditor", 403, "role_forbidden", "Auditors cannot generate or modify review documents.");
  assert(format === "markdown" || format === "html", 400, "invalid_document_format", "Document format must be markdown or html.");
  const snapshot = publicCandidate(candidateId);
  const stage = snapshot.stages.find((item) => item.id === stageId);
  assert(stage, 404, "stage_not_found", "The requested governance stage does not exist.");
  const title = `${stage.name} · ${snapshot.candidate.releaseName} · Governance Report`;
  const report = [
    `# ${title}`,
    "",
    `- Project: ${snapshot.candidate.projectName}`,
    `- Release candidate: ${snapshot.candidate.releaseName}`,
    `- Source commit: ${snapshot.candidate.commitSha || "Not configured"}`,
    `- Policy version: ${snapshot.candidate.policyVersion}`,
    `- Stage status: ${stage.gateStatus}`,
    `- Created at: ${new Date().toISOString()}`,
    "",
    "## Evidence",
    ...(stage.evidenceFiles.length
      ? stage.evidenceFiles.map((item) => `- ${item.name} · SHA-256 ${item.sha256} · Scanner ${item.scanStatus}`)
      : ["- No evidence attached"]),
    "",
    "## AI analysis",
    stage.analysis?.summary ?? "AI analysis has not been run against the current evidence.",
    "",
    "## Findings",
    ...(stage.findings.length
      ? stage.findings.map((item) => `- **${item.severity.toUpperCase()} · ${item.id} · ${item.status}** ${item.title}. ${item.detail} Citation: ${item.source} ${item.citation} (evidence ${item.evidenceId}).`)
      : ["- No findings recorded"]),
    "",
    "## Review checklist",
    ...stage.checklistItems.map((item) => `- [${item.completed ? "x" : " "}] ${item.label}`),
    "",
    "## Latest deterministic validation",
    stage.validation
      ? `${stage.validation.outcome} · Policy v${stage.validation.policyVersion} · Evidence revision ${stage.validation.evidenceRevision}`
      : "No validation run.",
    "",
    "> This report is generated from current candidate evidence. It is not a release approval or deployment record.",
  ].join("\n");
  const content =
    format === "html"
      ? `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${escapeHtml(title)}</title><style>body{max-width:900px;margin:48px auto;padding:0 24px;font:16px/1.7 system-ui,sans-serif;color:#17233b}pre{white-space:pre-wrap}h1{font-size:26px}</style></head><body><main><pre>${escapeHtml(report)}</pre></main></body></html>`
      : report;
  const document = createDocument({
    candidateId,
    stageId,
    title,
    format,
    content,
    actorId: actor.id,
  });
  const event = appendEvent({
    candidateId,
    actor,
    action: "Generated governance document",
    detail: `${title} · ${format} · Current evidence revision ${stage.evidenceRevision}`,
    type: "document",
    payload: { documentId: document.id, stageId },
  });
  eventBusPublish(event);
  return {
    id: document.id,
    candidateId,
    stageId,
    title,
    format,
    createdAt: document.createdAt,
  };
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

export function readStageDocument(candidateId, documentId) {
  const document = getDocument(documentId);
  assert(
    document && document.candidate_id === candidateId,
    404,
    "document_not_found",
    "The requested governance document was not found.",
  );
  return document;
}

export function generateCodeProposal({ candidateId, stageId, findingId, title, files, actor }) {
  assert(actor.role !== "auditor", 403, "role_forbidden", "Auditors cannot generate code proposals.");
  assert(Array.isArray(files) && files.length > 0 && files.length <= 20, 400, "invalid_code_proposal", "A code proposal must contain between one and twenty files.");
  const candidate = assertCandidate(candidateId);
  const stage = assertStage(candidateId, stageId);
  const finding = stage.findings.find((item) => item.id === findingId);
  assert(finding, 404, "finding_not_found", "Code proposals must reference an existing, evidence-grounded finding.");
  const artifact = createArtifact({
    candidateId,
    stageId,
    findingId,
    title: String(title || "").slice(0, 200),
    files,
    actorId: actor.id,
  });
  const event = appendEvent({
    candidateId,
    actor,
    action: "Created code artifact proposal",
    detail: `${artifact.title} · Source finding ${findingId} · ${files.length} proposed file(s)`,
    type: "artifact",
    payload: { artifactId: artifact.id, stageId },
  });
  eventBusPublish(event);
  return { ...artifact, candidateCommitSha: candidate.commit_sha };
}

export async function pushArtifact({ candidateId, artifactId, request, actor }) {
  const candidate = commitIfMatch(candidateId, request);
  assert(actor.role === "admin" || actor.role === "developer", 403, "role_forbidden", "Only administrators and developers may propose repository pull requests.");
  const artifact = db.prepare("SELECT * FROM artifacts WHERE id = ? AND candidate_id = ?").get(artifactId, candidateId);
  assert(artifact, 404, "artifact_not_found", "The code artifact does not belong to this candidate.");
  assert(artifact.status === "draft" || artifact.status === "failed", 409, "artifact_already_submitted", "This artifact has already been submitted or is currently being processed.");
  assert(/^[a-f0-9]{40}$/i.test(candidate.commit_sha), 409, "candidate_commit_unpinned", "Pin the reviewed full source commit SHA before opening a pull request.");
  const stage = assertStage(candidateId, artifact.stage_id);
  const finding = stage.findings.find((item) => item.id === artifact.finding_id);
  assert(finding, 409, "artifact_finding_stale", "The source finding is no longer available.");
  const fileTree = JSON.parse(artifact.files_json);
  assert(fileTree.every((file) => typeof file.content === "string"), 409, "artifact_files_invalid", "The proposed code artifact failed its content validation.");
  let pr;
  try {
    pr = await createPullRequest({
      title: artifact.title,
      body: `AI-generated proposal from ${finding.id}: ${finding.title}\n\nEvidence: ${finding.source} · ${finding.citation}`,
      files: fileTree,
      baseSha: candidate.commit_sha,
      artifactId,
    });
  } catch (error) {
    withTransaction(() => {
      updateArtifact(artifactId, "failed");
      appendEvent({
        candidateId,
        actor,
        action: "Repository proposal failed",
        detail: `${artifact.title} · ${error.code ?? "github_error"}`,
        type: "artifact",
        payload: { artifactId },
      });
    });
    throw error;
  }
  let event;
  withTransaction(() => {
    updateArtifact(artifactId, "pull_request_open", pr.htmlUrl);
    event = appendEvent({
      candidateId,
      actor,
      action: "Opened draft pull request",
      detail: `PR #${pr.number} · ${pr.branch} · ${pr.commitSha}`,
      type: "artifact",
      payload: { artifactId, pullRequestUrl: pr.htmlUrl },
    });
  });
  eventBusPublish(event);
  return { artifactId, ...pr };
}

export function auditRecords({ candidateId, actor, after, limit, type }) {
  if (candidateId) assertCandidate(candidateId);
  assert(actor.role !== "auditor" || !type || ["approval", "release", "validation"].includes(type), 403, "role_forbidden", "This audit filter is not available for the auditor role.");
  return listAudit({ candidateId, after, limit, type });
}

export function validatedStageIds() {
  return STAGES.map(({ id, name }) => ({ id, name }));
}

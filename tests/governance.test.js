import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  STAGES,
  calculateProgress,
  evaluateStage,
  formatMetric,
  isReleaseAuthorizationCurrent,
} from "../src/governance.js";
import { validateProposal } from "../src/server/github.mjs";

const candidateSchema = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("../schemas/governance-state.schema.json", import.meta.url)),
    "utf8",
  ),
);

function completedState(stage) {
  return {
    checklist: Object.fromEntries(stage.checklist.map((_, index) => [index, true])),
    metrics: { ...stage.metrics },
    resolvedFindings: stage.findings.map((finding) => finding.id),
  };
}

test("the governance workflow has six ordered stages", () => {
  assert.deepEqual(
    STAGES.map(({ id }) => id),
    ["requirements", "architecture", "code", "tests", "cicd", "production"],
  );
});

test("the API schema requires exactly the six governed stages", () => {
  assert.equal(candidateSchema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.equal(candidateSchema.properties.stages.minItems, STAGES.length);
  assert.equal(candidateSchema.properties.stages.maxItems, STAGES.length);
  assert.deepEqual(
    candidateSchema.$defs.stageId.enum,
    STAGES.map(({ id }) => id),
  );
});

test("repository proposals reject traversal, secrets, workflow changes, and duplicate paths", () => {
  assert.deepEqual(
    validateProposal([{ path: "src/tests/report.test.js", content: "export const ready = true;\n" }]),
    [{ path: "src/tests/report.test.js", content: "export const ready = true;\n" }],
  );
  for (const filePath of ["../outside.txt", "/absolute.txt"]) {
    assert.throws(
      () => validateProposal([{ path: filePath, content: "unsafe" }]),
      { code: "invalid_proposal_path" },
      `${filePath} should not be allowed`,
    );
  }
  for (const filePath of [".env", "config/secrets.yaml"]) {
    assert.throws(
      () => validateProposal([{ path: filePath, content: "unsafe" }]),
      { code: "sensitive_artifact_path" },
      `${filePath} should not be allowed`,
    );
  }
  assert.throws(
    () => validateProposal([{ path: ".github/workflows/release.yml", content: "unsafe" }]),
    { code: "restricted_artifact_path" },
  );
  assert.throws(
    () => validateProposal([
      { path: "src/a.js", content: "one" },
      { path: "src/a.js", content: "two" },
    ]),
    { code: "duplicate_artifact_path" },
  );
  assert.throws(
    () => validateProposal([{ path: "src/a.js", content: "contains\0null" }]),
    { code: "invalid_proposal_file" },
  );
});

test("ready evidence passes each stage except the intentionally blocked sample coverage gate", () => {
  for (const stage of STAGES) {
    const sample = completedState(stage);
    const result = evaluateStage(stage, sample);
    assert.equal(result.checklistComplete, true);
    assert.equal(result.unresolvedBlockers, 0);
    if (stage.id === "tests") {
      assert.equal(result.passed, false, "sample coverage must remain below policy");
      assert.deepEqual(
        result.checks.filter((check) => check.status === "failed").map((check) => check.key),
        ["lineCoverage", "branchCoverage", "criticalCoverage"],
      );
    } else {
      assert.equal(result.passed, true, `${stage.name} should pass its sample evidence`);
      assert.ok(result.checks.every((check) => check.status === "passed"));
    }
  }
});

test("refreshed test evidence passes only after all coverage thresholds are met", () => {
  const stage = STAGES.find(({ id }) => id === "tests");
  const state = completedState(stage);
  state.metrics = {
    ...state.metrics,
    lineCoverage: 89,
    branchCoverage: 84,
    criticalCoverage: 100,
  };

  assert.equal(evaluateStage(stage, state).passed, true);
});

test("test coverage remains blocked below any mandatory threshold", () => {
  const stage = STAGES.find(({ id }) => id === "tests");
  const state = completedState(stage);
  state.metrics.branchCoverage = 79;

  const result = evaluateStage(stage, state);

  assert.equal(result.passed, false);
  assert.equal(result.checks.find(({ key }) => key === "branchCoverage").status, "failed");
});

test("an unresolved high-severity finding blocks validation", () => {
  const stage = STAGES.find(({ id }) => id === "requirements");
  const state = completedState(stage);
  state.resolvedFindings = [];

  const result = evaluateStage(stage, state);

  assert.equal(result.passed, false);
  assert.equal(result.unresolvedBlockers, 1);
});

test("incomplete review checklist blocks validation even when policy checks pass", () => {
  const stage = STAGES.find(({ id }) => id === "code");
  const state = completedState(stage);
  state.checklist[1] = false;

  const result = evaluateStage(stage, state);

  assert.equal(result.passed, false);
  assert.equal(result.checklistComplete, false);
  assert.ok(result.checks.every((check) => check.status === "passed"));
});

test("project progress is derived from stage status and review completion", () => {
  const stages = [
    { gateStatus: "passed", checklist: { 0: true } },
    { gateStatus: "not_run", checklist: { 0: true, 1: false } },
    { gateStatus: "locked", checklist: { 0: false, 1: false } },
  ];

  assert.equal(calculateProgress(stages), 50);
  assert.equal(calculateProgress([]), 0);
});

test("missing numeric evidence fails closed and formats without fabricating zero", () => {
  const stage = STAGES.find(({ id }) => id === "tests");
  const state = completedState(stage);
  delete state.metrics.lineCoverage;
  const result = evaluateStage(stage, state);

  assert.equal(result.passed, false);
  assert.equal(result.checks.find(({ key }) => key === "lineCoverage").status, "failed");
  assert.equal(formatMetric(null, { percent: true }), "Not available");
});

test("the stage validator rejects missing stage definitions and state", () => {
  assert.throws(() => evaluateStage(undefined, {}), TypeError);
  assert.throws(() => evaluateStage(STAGES[0], undefined), TypeError);
});

test("release authorization stays current only for the exact approved validation set", () => {
  const candidate = {
    commit_sha: "a".repeat(40),
    artifact_digest: `sha256:${"b".repeat(64)}`,
    policy_version: "1.0",
    stages: STAGES.map((stage, index) => ({
      stage_id: stage.id,
      gate_status: "passed",
      evidence_revision: 3,
      confirmed_evidence_revision: 3,
      validation: {
        id: `validation-${index}`,
        outcome: "passed",
        evidenceRevision: 3,
        policyVersion: "1.0",
      },
      approver_id: `approver-${index}`,
      approved_at: "2026-10-15T00:00:00.000Z",
    })),
  };
  const authorization = {
    commitSha: candidate.commit_sha,
    artifactDigest: candidate.artifact_digest,
    policyVersion: candidate.policy_version,
    validationIds: candidate.stages.map((stage) => stage.validation.id),
  };

  assert.equal(isReleaseAuthorizationCurrent(candidate, authorization), true);
  assert.equal(
    isReleaseAuthorizationCurrent(candidate, { ...authorization, validationIds: [] }),
    false,
  );
  const changedEvidence = structuredClone(candidate);
  changedEvidence.stages[0].evidence_revision += 1;
  assert.equal(isReleaseAuthorizationCurrent(changedEvidence, authorization), false);
  const changedPolicy = structuredClone(candidate);
  changedPolicy.policy_version = "2.0";
  assert.equal(isReleaseAuthorizationCurrent(changedPolicy, authorization), false);
  const missingApproval = structuredClone(candidate);
  missingApproval.stages[0].approver_id = null;
  assert.equal(isReleaseAuthorizationCurrent(missingApproval, authorization), false);
});

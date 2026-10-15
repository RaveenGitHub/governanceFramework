export const STAGES = [
  {
    id: "requirements",
    name: "Requirements Validation",
    shortName: "Requirements",
    description:
      "Validate that functional and non-functional requirements are clear, measurable, and traceable before implementation begins.",
    objective: "Establish a complete, testable baseline for the release.",
    evidence: ["Requirements document", "Acceptance criteria", "Backlog export"],
    checklist: [
      "Every requirement has an owner and unique identifier",
      "Acceptance criteria are measurable and testable",
      "Security, privacy, and performance requirements are documented",
      "Critical requirements link to a verification method",
    ],
    findings: [
      {
        id: "REQ-014",
        severity: "high",
        title: "Payment retry behavior needs a limit",
        detail:
          "The retry policy does not specify a maximum attempt count or the backoff strategy.",
        source: "Business Requirements v4 · §3.2",
      },
      {
        id: "REQ-021",
        severity: "medium",
        title: "Data retention period is not measurable",
        detail:
          "The retention requirement should define a specific duration and deletion behavior.",
        source: "Privacy Requirements · §5.1",
      },
    ],
    evidenceFiles: [
      "Business Requirements v4.pdf",
      "Acceptance Criteria.md",
      "Backlog Traceability.csv",
    ],
    metrics: { requirementCoverage: 98, ambiguityCount: 0 },
    checks: [
      {
        key: "requirementCoverage",
        label: "Requirement traceability",
        expected: "≥ 95%",
        percent: true,
        threshold: 95,
      },
      { key: "ambiguityCount", label: "Unresolved ambiguities", expected: "0" },
    ],
  },
  {
    id: "architecture",
    name: "Architecture Review",
    shortName: "Architecture",
    description:
      "Review system design, data flows, resilience, and security boundaries against the approved requirements.",
    objective: "Prove the proposed design can meet the release requirements safely.",
    evidence: ["Architecture diagram", "Architecture decisions", "API specification"],
    checklist: [
      "Requirements map to architectural components",
      "Trust boundaries and data flows are documented",
      "Resilience and recovery objectives have supporting evidence",
      "Service dependencies and API contracts are reviewed",
    ],
    findings: [
      {
        id: "ARC-008",
        severity: "medium",
        title: "Recovery objective needs an owner",
        detail:
          "The payment service recovery objective is documented but has no accountable service owner.",
        source: "Payments Architecture v2 · §6",
      },
    ],
    evidenceFiles: [
      "Payments Architecture v2.pdf",
      "Service Topology.svg",
      "API Specification.yaml",
    ],
    metrics: { architectureCoverage: 97, unmitigatedRisks: 0 },
    checks: [
      {
        key: "architectureCoverage",
        label: "Architecture coverage",
        expected: "≥ 95%",
        percent: true,
        threshold: 95,
      },
      { key: "unmitigatedRisks", label: "Unmitigated high risks", expected: "0" },
    ],
  },
  {
    id: "code",
    name: "Code Quality Review",
    shortName: "Code quality",
    description:
      "Review the exact source revision, scan results, proposed changes, and conformance to the approved architecture.",
    objective: "Ensure the release candidate is reviewed, secure, and maintainable.",
    evidence: ["Repository commit", "Static analysis", "Dependency scan"],
    checklist: [
      "Required code reviewers approved the release candidate",
      "Static analysis and dependency scans completed",
      "Critical findings are resolved or formally dispositioned",
      "Architecture deviations have documented approval",
    ],
    findings: [
      {
        id: "CODE-112",
        severity: "low",
        title: "Consider simplifying retry policy branching",
        detail:
          "The payment retry handler has nested branches that could make future changes harder to review.",
        source: "Code analysis · src/payments/retry-handler.ts",
      },
    ],
    evidenceFiles: [
      "Commit a83f72c · 248 files scanned",
      "Dependency Scan · 09:42",
      "Static Analysis · Passed",
    ],
    metrics: { criticalFindings: 0, scansComplete: true, reviewApproved: true },
    checks: [
      { key: "scansComplete", label: "Required security and quality scans", expected: "Complete" },
      { key: "criticalFindings", label: "Open critical findings", expected: "0" },
      { key: "reviewApproved", label: "Required code review", expected: "Approved" },
    ],
  },
  {
    id: "tests",
    name: "Test Coverage Validation",
    shortName: "Test coverage",
    description:
      "Verify the release candidate has adequate, current test evidence for critical paths and changed code.",
    objective: "Demonstrate that important behavior is tested and regression risk is controlled.",
    evidence: ["Coverage report", "Test run results", "Requirement-to-test map"],
    checklist: [
      "Critical requirements map to executed tests",
      "Line and branch coverage meet policy thresholds",
      "Required test suites passed against this commit",
      "Failed and quarantined tests have an approved disposition",
      "Critical payment paths have complete test coverage",
    ],
    findings: [
      {
        id: "TEST-042",
        severity: "high",
        title: "Coverage is below the release threshold",
        detail:
          "Line coverage is 82% against an 85% minimum. Three critical payment paths need tests.",
        source: "Coverage Report · a83f72c · 09:18",
      },
      {
        id: "TEST-056",
        severity: "medium",
        title: "Three payment paths need additional tests",
        detail:
          "Refund retry, declined-card recovery, and duplicate authorization are not fully exercised.",
        source: "Requirement Traceability · 12 of 15 paths",
      },
    ],
    evidenceFiles: [
      "Coverage Report · a83f72c",
      "Jest Results · 842 tests",
      "Requirement-to-Test Map.csv",
    ],
    metrics: {
      lineCoverage: 82,
      branchCoverage: 78,
      criticalCoverage: 92,
      suitesPassed: true,
    },
    checks: [
      { key: "lineCoverage", label: "Line coverage", expected: "≥ 85%", percent: true, threshold: 85 },
      {
        key: "branchCoverage",
        label: "Branch coverage",
        expected: "≥ 80%",
        percent: true,
        threshold: 80,
      },
      {
        key: "criticalCoverage",
        label: "Critical path coverage",
        expected: "100%",
        percent: true,
        threshold: 100,
      },
      { key: "suitesPassed", label: "Required test suites", expected: "All passed" },
    ],
  },
  {
    id: "cicd",
    name: "CI/CD Quality Gate",
    shortName: "CI/CD gate",
    description:
      "Verify the approved source revision produces a traceable, signed artifact through a compliant delivery pipeline.",
    objective: "Establish integrity from reviewed source to deployable artifact.",
    evidence: ["Pipeline run", "Build provenance", "Artifact signature"],
    checklist: [
      "Required pipeline jobs passed for the approved commit",
      "Build provenance links source, build, and artifact",
      "Artifact signature is valid and verifiable",
      "Deployment and rollback controls meet release policy",
    ],
    findings: [
      {
        id: "CICD-007",
        severity: "low",
        title: "Deployment workflow can publish clearer provenance",
        detail:
          "Publishing the artifact digest in the deployment summary would improve operator traceability.",
        source: "Delivery Pipeline · payments-release.yml",
      },
    ],
    evidenceFiles: [
      "Release Pipeline · run #1842",
      "Container signature · Verified",
      "Build Provenance · Verified",
    ],
    metrics: {
      pipelinePassed: true,
      provenanceVerified: true,
      signatureVerified: true,
      deploymentControls: true,
    },
    checks: [
      { key: "pipelinePassed", label: "Required pipeline jobs", expected: "All passed" },
      { key: "provenanceVerified", label: "Build provenance", expected: "Verified" },
      { key: "signatureVerified", label: "Artifact signature", expected: "Verified" },
      { key: "deploymentControls", label: "Deployment controls", expected: "Compliant" },
    ],
  },
  {
    id: "production",
    name: "Production Readiness Gate",
    shortName: "Production",
    description:
      "Review operational readiness, release approvals, rollback evidence, and residual risk before authorizing release.",
    objective: "Confirm the organization is ready to operate and support this release.",
    evidence: ["Runbook", "Rollback rehearsal", "Monitoring and SLOs"],
    checklist: [
      "A named service owner and on-call rotation are confirmed",
      "Runbook, alerts, and service objectives are verified",
      "Backup, recovery, and rollback evidence is current",
      "Release notes and required approvals are complete",
    ],
    findings: [
      {
        id: "PROD-011",
        severity: "medium",
        title: "Attach the latest rollback rehearsal",
        detail:
          "The rollback runbook is present, but this release candidate does not yet have a linked rehearsal.",
        source: "Release Operations · Evidence required",
      },
    ],
    evidenceFiles: [
      "Payments Runbook v7.pdf",
      "On-call Rotation · Current",
      "Monitoring & SLOs · Reviewed",
    ],
    metrics: {
      ownerConfirmed: true,
      monitoringVerified: true,
      rollbackVerified: true,
      approvalsComplete: true,
    },
    checks: [
      { key: "ownerConfirmed", label: "Operational ownership", expected: "Confirmed" },
      { key: "monitoringVerified", label: "Monitoring and SLOs", expected: "Verified" },
      { key: "rollbackVerified", label: "Rollback rehearsal", expected: "Verified" },
      { key: "approvalsComplete", label: "Required release approvals", expected: "Complete" },
    ],
  },
];

const FINAL_GATE_STATUSES = new Set(["passed"]);

export function calculateProgress(stages) {
  if (!stages.length) return 0;
  const completion = stages.reduce((total, stage) => {
    if (FINAL_GATE_STATUSES.has(stage.gateStatus)) return total + 100;
    const checklist = Object.values(stage.checklist ?? {});
    const fraction = checklist.length
      ? checklist.filter(Boolean).length / checklist.length
      : 0;
    return total + Math.round(fraction * 100);
  }, 0);
  return Math.round(completion / stages.length);
}

export function evaluateStage(stageDefinition, stageState) {
  if (!stageDefinition || !stageState) {
    throw new TypeError("A stage definition and state are required.");
  }

  const checks = stageDefinition.checks.map((check) => {
    const actual = stageState.metrics[check.key];
    const passed = check.percent
      ? Number.isFinite(actual) && actual >= check.threshold
      : check.expected === "0"
        ? actual === 0
        : actual === true;
    return {
      key: check.key,
      label: check.label,
      expected: check.expected,
      actual: actual ?? null,
      status: passed ? "passed" : "failed",
    };
  });

  const checklistComplete = stageDefinition.checklist.every(
    (_, index) => stageState.checklist[index] === true,
  );
  const unresolvedBlockers = stageDefinition.findings
    .filter((finding) => ["critical", "high"].includes(finding.severity))
    .filter((finding) => !stageState.resolvedFindings.includes(finding.id)).length;

  return {
    checks,
    checklistComplete,
    unresolvedBlockers,
    passed:
      checklistComplete &&
      unresolvedBlockers === 0 &&
      checks.every((check) => check.status === "passed"),
  };
}

export function formatMetric(value, check) {
  if (value === null || value === undefined) return "Not available";
  if (check?.percent) return `${value}%`;
  if (typeof value === "boolean") return value ? "Verified" : "Not verified";
  return String(value);
}

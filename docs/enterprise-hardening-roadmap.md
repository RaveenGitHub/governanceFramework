# Enterprise hardening roadmap

## Target architecture

Retain the current modular monolith and browser workflow while strengthening its boundaries:

```text
Enterprise IdP ── OIDC/SAML + provisioning ──┐
                                            v
CI/CD ── signed provenance/metrics ──> Governance API ──> Policy decision
                                            │                  │
                                            ├── relational DB  └── deploy allow/deny
                                            ├── durable worker/outbox
                                            ├── private object storage
                                            └── immutable audit export
```

Do not split into microservices until independent scaling, ownership, or availability needs justify the operational cost. Keep the policy evaluator and release decision service authoritative; AI findings remain advisory.

## Delivery plan

### Phase 0 — access and decision integrity (implemented in this change)

- Scope candidate, evidence, document, artifact, audit, and live-event access to project membership.
- Use a project-specific role for each membership; keep global administrator access available for control-plane operations.
- Provide administrator APIs and workspace UI to create accounts, list projects, and manage project membership.
- Require candidate context for non-admin audit and event queries.
- Bind release authorization to the exact current stage validation IDs, evidence revisions, confirmations, approver records, policy version, source commit, and artifact digest.
- Reject release tagging when the authorization no longer matches current governance state.

Acceptance: cross-project reads fail closed; role-specific permissions are evaluated in project context; stale authorization cannot be used for release tagging.

### Phase 1 — identity lifecycle and authorization governance

- Integrate enterprise OIDC or SAML; use MFA and conditional-access policy from the identity provider.
- Add automated user provisioning/deprovisioning and group-to-project-role mapping.
- Define break-glass administrator procedures, session revocation, access reviews, and joiner/mover/leaver controls.
- Show identity claims and effective project roles in the UI; audit membership changes and role mapping decisions.

Acceptance: identity changes and group changes revoke or refresh access predictably; inactive identities cannot retain access; authorization tests cover every role and project boundary.

### Phase 2 — immutable policy lifecycle

- Replace the hard-coded policy version with immutable, validated policy bundles and a canonical policy digest.
- Record policy digest, evaluator version, rule outcomes, evidence hashes, and approval identities for every gate and release decision.
- Define policy publication, approval, rollback, migration, and treatment of in-flight candidates.
- Require deliberate revalidation when policy changes; do not silently re-interpret historical approvals.

Acceptance: a release decision can be reproduced from the exact policy/evaluator versions and evidence references that produced it.

### Phase 3 — durable workflow and integration execution

- Promote the database outbox into a leased worker queue with retry/backoff, idempotency keys, dead-letter handling, cancellation, and operational replay.
- Move long-running antivirus, AI, repository, and CI operations out of request handlers.
- Keep SSE as a client notification mechanism; reconnect from a durable event cursor and handle worker restarts.
- Add connector-specific rate limits, timeout budgets, circuit breakers, and actionable integration health.

Acceptance: process restart does not lose accepted work; transient provider errors recover without duplicate external effects; terminal failures are visible and auditable.

### Phase 4 — release enforcement and software supply chain

- Add a CI/CD decision-check contract that accepts a candidate, commit, artifact digest, and provenance reference and returns an authenticated, time-bounded allow/deny decision.
- Verify signed build provenance against an approved repository, ref, workflow, builder, commit, and immutable artifact digest.
- Make deployment pipelines fail closed on missing, stale, mismatched, or denied decisions.
- Record deployment identity and outcome; distinguish authorization, tagging, promotion, and production deployment.

Acceptance: a denied or stale decision demonstrably prevents promotion; accepted decisions cannot be replayed for another artifact or environment.

### Phase 5 — evidence, audit, and operational resilience

- Introduce encrypted object storage, malware quarantine, retention/legal-hold controls, quotas, and verified deletion.
- Define key management, secret rotation, and evidence/AI data classification and residency rules.
- Export signed or hash-chained audit records to independently administered immutable storage.
- Deploy managed relational storage where availability/concurrency needs require it; automate backup and prove restore against recovery-point and recovery-time objectives.

Acceptance: an operator can restore service and evidence consistently; audit records survive application/database compromise; retention and deletion are testable.

### Phase 6 — observability, assurance, and scale

- Add structured service metrics, traces, dashboards, alerting, SLOs, and incident playbooks.
- Add schema migrations, deployment/rollback automation, dependency and container scanning, and signed release artifacts.
- Test concurrency, load, failover, backup restoration, connector outages, and disaster recovery.
- Source defect escape, security findings, regression risk, and production readiness from authoritative systems; publish provenance and freshness for each metric.

Acceptance: service objectives are measured; production readiness is based on current source data and tested operational controls rather than unavailable placeholders.

## Current boundary

The application remains a single-process Node.js service using SQLite and local private-filesystem evidence storage. Release authorization is an application decision, not a deployment control. The dashboard's release-confidence value is a deterministic governance-stage index, not a probability; defect escape rate and security vulnerability count remain unavailable until authoritative integrations are configured. Enterprise identity, distributed workers, object storage, immutable audit export, managed availability, and production recovery objectives remain deployment work.

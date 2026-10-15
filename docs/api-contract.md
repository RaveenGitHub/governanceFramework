# Governance API and integration contract

This document describes the routes implemented by the local service. The API is same-origin under `/api` (not `/api/v1`). JSON errors use:

```json
{
  "error": { "code": "stale_revision", "message": "Reload the current release candidate." },
  "requestId": "request-identifier"
}
```

Mutating browser requests use the `governance_session` HttpOnly cookie, `X-CSRF-Token`, and, for candidate mutations, the current candidate ETag in `If-Match`. A successful state-changing candidate response returns an updated `ETag`. Do not retry a stale mutation without reloading the candidate. The first administrator setup uses `X-Bootstrap-Token` instead of a session.

## Authentication and health

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/health` | Readiness and public connector status |
| `GET` | `/api/session` | Session, setup-required state, CSRF token, capabilities and roles |
| `POST` | `/api/auth/setup` | Create the initial administrator using the one-time bootstrap token |
| `POST` | `/api/auth/login` | Authenticate a local user and establish a session |
| `POST` | `/api/auth/logout` | Revoke current session |
| `POST` | `/api/auth/password` | Change password and revoke other sessions |
| `GET` | `/api/auth/roles` | Admin-only user and role listing |
| `POST` | `/api/auth/users` | Admin-only user creation |
| `PATCH` | `/api/auth/roles/{userId}` | Admin-only role change; revokes target sessions |
| `DELETE` | `/api/auth/users/{userId}` | Admin-only user deactivation |

## Candidates and workflow

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/candidates` | List candidates available to the authenticated workspace |
| `POST` | `/api/candidates` | Admin-only candidate creation |
| `GET` | `/api/candidates/{candidateId}/state` | Candidate, stages, findings, evidence metadata, documents, artifacts, and audit state |
| `PATCH` | `/api/candidates/{candidateId}/identity` | Change pinned commit/artifact identity; invalidates affected review state |
| `PUT` | `/api/candidates/{candidateId}/stages/{stageId}/checklist` | Update a review checklist item |
| `POST` | `/api/candidates/{candidateId}/stages/{stageId}/analyses` | Run optional evidence-cited AI analysis |
| `POST` | `/api/candidates/{candidateId}/stages/{stageId}/confirmations` | Confirm the current evidence revision |
| `POST` | `/api/candidates/{candidateId}/stages/{stageId}/validations` | Evaluate deterministic policy checks |
| `POST` | `/api/candidates/{candidateId}/stages/{stageId}/approvals` | Record a separate reviewer approval |
| `PATCH` | `/api/candidates/{candidateId}/stages/{stageId}/findings/{findingId}` | Resolve a finding with clean evidence and a rationale |
| `POST` | `/api/requirements/validate` | Requirements-stage validation alias |
| `POST` | `/api/architecture/review` | Architecture-stage validation alias |
| `POST` | `/api/code/review` | Code-stage validation alias |
| `POST` | `/api/tests/coverage` | Test-stage validation alias |
| `POST` | `/api/cicd/quality-gate` | CI/CD-stage validation alias |
| `POST` | `/api/production/readiness` | Production-stage validation alias |
| `GET` | `/api/release/confidence?candidateId={id}` | Policy-derived confidence, eligibility, and risk |
| `POST` | `/api/release/authorize` | Record final authorization after all release conditions pass |
| `POST` | `/api/release/tag` | Admin-only creation of an authorized GitHub release tag |

The six stage IDs are `requirements`, `architecture`, `code`, `tests`, `cicd`, and `production`. A gate cannot pass unless prerequisites, required evidence, evidence cleanliness, current confirmation, checklist, validation, and reviewer policy pass. Approval is separate from validation. Release confidence is a deterministic policy index, **not** an AI probability; the optional AI integration only provides advisory analysis.

## Evidence, documents and artifacts

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/evidence/upload?candidateId={id}&stageId={stage}` | Upload an octet-stream body; UTF-8 filename is base64url in `X-Evidence-Filename` |
| `GET` | `/api/evidence/list?candidateId={id}&stageId={stage}` | List evidence metadata and scanner requirement |
| `GET` | `/api/evidence/{evidenceId}` | Download clean evidence owned by the candidate |
| `DELETE` | `/api/evidence/{evidenceId}?candidateId={id}` | Remove evidence while stage is editable |
| `POST` | `/api/evidence/{evidenceId}/scan?candidateId={id}` | Authorized evidence rescan |
| `POST` | `/api/candidates/{candidateId}/stages/{stageId}/documents` | Generate and persist Markdown or HTML governance report |
| `GET` | `/api/documents/{documentId}?candidateId={id}` | Read generated report content |
| `POST` | `/api/candidates/{candidateId}/stages/{stageId}/artifacts` | Store a reviewable repository-relative code proposal |

Uploads are stored privately and quarantined until the configured scanner reports clean. The production configuration must not bypass required malware scanning.

## Repository, CI and live updates

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/ai/status` | AI connector status |
| `GET` | `/api/repo/status` | Configured GitHub repository status |
| `GET` | `/api/repo/commit-status?sha={sha}` | GitHub commit status |
| `POST` | `/api/repo/push` | Submit a stored artifact as a review pull request (never direct push) |
| `POST` | `/api/repo/pull-request-comment` | Add a permissioned PR review comment |
| `POST` | `/api/github/webhook` | Verify configured GitHub HMAC-signed webhook |
| `POST` | `/api/cicd/coverage` | Verify HMAC-signed CI coverage report and unique delivery identifier |
| `GET` | `/api/events?candidateId={id}` | Server-Sent Events stream for governance/audit updates |
| `GET` | `/api/audit/logs?candidateId={id}&limit={n}&after={cursor}&type={type}` | Cursor-paginated audit records; page size 1–200 |

Webhook senders must sign the exact raw request body with HMAC-SHA256. CI deliveries include the same unique ID in the signed JSON body and `X-CI-Delivery` header. Configure and test webhook source restrictions, secret rotation, replay handling, and delivery retry behavior before exposing the service to an external network.

## Local state and production boundary

SQLite is the local persistence engine; evidence uses a private local filesystem directory. Local password login is not enterprise SSO. The application does not provide a distributed workflow queue, object-store backend, multi-region availability, or managed database. Production deployment must add and validate appropriate infrastructure, TLS and proxy settings, backup/restore, monitoring, availability, retention, identity lifecycle, and connector credentials. Connector status is returned from `/api/session` and `/api/health`; an unconfigured integration fails closed rather than pretending success.

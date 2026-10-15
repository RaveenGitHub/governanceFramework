# Govern AI · Quality Governance Workspace

An evidence-led, six-stage governance workspace with a persistent Node.js API, SQLite workflow state, authenticated sessions, private evidence storage, an audit trail, and an enterprise dashboard.

## Run locally

Requirements: Node.js 22.13 or newer. The application has no third-party runtime dependencies.

```powershell
npm run dev
```

Open <http://127.0.0.1:4173>. On first startup, copy the one-time bootstrap token from the server console into the setup screen to create the administrator account. The service creates the initial empty release candidate automatically. Keep the console token private; it is not saved in the repository.

Persistent local data is stored under `data\` by default. Set `GOVERNANCE_DATA_DIR`, `GOVERNANCE_DATABASE_PATH`, or `GOVERNANCE_EVIDENCE_DIR` to move it. Configure `BOOTSTRAP_TOKEN` before production startup. See [`.env.example`](./.env.example) for optional connector settings; Node does not automatically load that file, so provide variables through your process manager or deployment environment.

Run tests with:

```powershell
npm test
```

Check service readiness at <http://127.0.0.1:4173/api/health>.

## Workflow

1. Requirements Validation.
2. Architecture Review.
3. Code Quality Review.
4. Test Coverage Validation.
5. CI/CD Quality Gate.
6. Production Readiness Gate and explicit release authorization.

Every stage is persisted server-side. Evidence changes invalidate downstream review state. A stage requires the current evidence to be cleanly scanned, checklist review, confirmation, passing policy validation, and a separate authorized approval. Release authorization additionally requires all six gates, a pinned commit, and a pinned SHA-256 artifact digest. The UI never deploys; GitHub release tagging is a distinct, separately permissioned operation.

## Service architecture

```text
Browser UI (HTML/CSS/ES modules)
  ├── Same-origin REST API + opaque HttpOnly session + CSRF
  ├── Server-Sent Events for audit/workflow updates
  └── Allowlisted static assets
          │
Node.js modular monolith
  ├── Session authentication, RBAC, rate limiting, request validation
  ├── SQLite workflow state, policy checks, revisions, audit/outbox
  ├── Private local evidence storage + optional ClamAV scanning
  ├── Optional governed AI provider for evidence-cited analysis
  ├── Optional signed CI coverage and GitHub integrations
  └── Release authorization enforcement
          │
      SQLite + private evidence directory
```

The default local configuration binds only to loopback. Production deployment requires TLS termination, `TRUST_PROXY=1`, a strong configured bootstrap token, durable backups, monitoring, and configured external identity, scanning, AI, CI, and repository services as required by organizational policy. The built-in local user/password authentication is not enterprise SSO. External connectors are optional and report unavailable when not configured; they are not simulated.

## Integrations

See [`.env.example`](./.env.example) for supported variables:

- `AI_BASE_URL`, `AI_API_KEY`, `AI_MODEL`: OpenAI-compatible analysis endpoint. AI findings are advisory; deterministic policy gates remain authoritative.
- `CLAMAV_HOST`, `CLAMAV_PORT`: malware scanning. Evidence remains ineligible until scanning reports clean.
- `CI_WEBHOOK_SECRET`: HMAC-SHA256 authenticated CI coverage submissions with unique delivery IDs.
- `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO`, `GITHUB_WEBHOOK_SECRET`: GitHub repository status, pull request, comments, tags, and signed webhooks.
- `GOVERNANCE_DATA_DIR`, `GOVERNANCE_DATABASE_PATH`, `GOVERNANCE_EVIDENCE_DIR`: persistence locations.

Review [the API contract](./docs/api-contract.md) and [the candidate-state response schema](./schemas/governance-state.schema.json) for implemented interfaces and workflow semantics.

## Repository layout

```text
governanceFramework\
├── src\
│   ├── app.js                 # API-connected browser UI
│   ├── governance.js          # Shared stage definitions and policy model
│   └── server\                # API, workflow, auth, storage, connectors, SQLite
├── tests\                     # Policy and backend integration tests
├── docs\                      # API and integration contract
├── schemas\                   # Candidate API JSON Schema
├── index.html
├── styles.css
└── server.mjs                 # Local service launcher
```

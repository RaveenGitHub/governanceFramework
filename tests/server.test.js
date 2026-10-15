import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHmac } from "node:crypto";
import { createServer } from "node:http";
import { access, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { once } from "node:events";
import { createServer as createNetServer } from "node:net";
import { DatabaseSync } from "node:sqlite";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

async function availablePort() {
  const reservation = createServer();
  reservation.listen(0, "127.0.0.1");
  await once(reservation, "listening");
  const { port } = reservation.address();
  await new Promise((resolve, reject) =>
    reservation.close((error) => (error ? reject(error) : resolve())),
  );
  return port;
}

async function startServer(dataDirectory, extraEnv = {}) {
  const port = await availablePort();
  const child = spawn(
    process.execPath,
    [fileURLToPath(new URL("../server.mjs", import.meta.url))],
    {
      env: {
        ...process.env,
        ...extraEnv,
        PORT: String(port),
        HOST: "127.0.0.1",
        BOOTSTRAP_TOKEN: "test-bootstrap-token-with-at-least-32-bytes",
        GOVERNANCE_DATA_DIR: dataDirectory,
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let output = "";
  child.stdout.setEncoding("utf8").on("data", (chunk) => (output += chunk));
  child.stderr.setEncoding("utf8").on("data", (chunk) => (output += chunk));
  const baseUrl = `http://127.0.0.1:${port}`;
  for (let attempt = 0; attempt < 80; attempt += 1) {
    try {
      const response = await fetch(`${baseUrl}/api/health`, {
        signal: AbortSignal.timeout(250),
      });
      if (response.ok) return { baseUrl, child, output: () => output };
    } catch {
      if (child.exitCode !== null) throw new Error(`Server exited early: ${output}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  child.kill();
  throw new Error(`Server did not start: ${output}`);
}

async function stopServer(child) {
  if (child.exitCode !== null) return;
  const exited = once(child, "exit");
  child.kill();
  await Promise.race([exited, new Promise((resolve) => setTimeout(resolve, 1500))]);
  if (child.exitCode === null) {
    const forceExit = once(child, "exit");
    child.kill("SIGKILL");
    await Promise.race([forceExit, new Promise((resolve) => setTimeout(resolve, 500))]);
  }
}

function requestJson(baseUrl, route, { method = "GET", cookie, csrf, etag, body, headers = {} } = {}) {
  return fetch(`${baseUrl}${route}`, {
    method,
    signal: AbortSignal.timeout(5000),
    headers: {
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(cookie ? { Cookie: cookie } : {}),
      ...(csrf ? { "X-CSRF-Token": csrf } : {}),
      ...(etag ? { "If-Match": etag } : {}),
      ...headers,
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
}

test("the local server serves only public assets with safe response headers", async () => {
  const port = await availablePort();
  const child = spawn(
    process.execPath,
    [fileURLToPath(new URL("../server.mjs", import.meta.url))],
    {
      env: { ...process.env, PORT: String(port) },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let serverOutput = "";
  child.stdout.setEncoding("utf8").on("data", (chunk) => (serverOutput += chunk));
  child.stderr.setEncoding("utf8").on("data", (chunk) => (serverOutput += chunk));
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    let response;
    for (let attempt = 0; attempt < 50; attempt += 1) {
      try {
        response = await fetch(baseUrl, { signal: AbortSignal.timeout(250) });
        break;
      } catch (error) {
        if (child.exitCode !== null) throw new Error(`Static server exited early: ${serverOutput}`);
        if (attempt === 49) throw error;
        await new Promise((resolve) => setTimeout(resolve, 40));
      }
    }

    assert.equal(response.status, 200);
    assert.match(response.headers.get("content-type"), /text\/html/);
    assert.match(response.headers.get("content-security-policy"), /default-src 'self'/);
    assert.equal(response.headers.get("x-content-type-options"), "nosniff");
    assert.match(await response.text(), /Quality Governance Workspace/);

    for (const asset of ["/styles.css", "/src/app.js", "/src/governance.js", "/favicon.svg"]) {
      const assetResponse = await fetch(`${baseUrl}${asset}`);
      assert.equal(assetResponse.status, 200, `${asset} should be served`);
    }

    for (const privatePath of ["/server.mjs", "/package.json", "/README.md", "/.git/config"]) {
      const privateResponse = await fetch(`${baseUrl}${privatePath}`);
      assert.equal(privateResponse.status, 404, `${privatePath} must remain private`);
    }

    const headResponse = await fetch(baseUrl, { method: "HEAD" });
    assert.equal(headResponse.status, 200);
    assert.equal(await headResponse.text(), "");

    const postResponse = await fetch(baseUrl, { method: "POST" });
    assert.equal(postResponse.status, 405);
    assert.equal(postResponse.headers.get("allow"), "GET, HEAD");
  } finally {
    child.kill();
    if (child.exitCode === null) {
      await Promise.race([
        once(child, "exit"),
        new Promise((resolve) => setTimeout(resolve, 1000)),
      ]);
    }
  }
});

test("authenticated API persists candidates and enforces RBAC, CSRF, revisions, and quarantine", { timeout: 20_000 }, async (context) => {
  const dataDirectory = await mkdtemp(path.join(os.tmpdir(), "governance-api-"));
  const { baseUrl, child, output } = await startServer(dataDirectory);
  let activeChild = child;
  context.after(async () => {
    await stopServer(activeChild);
    await rm(dataDirectory, { recursive: true, force: true });
  });

  const sessionResponse = await requestJson(baseUrl, "/api/session");
  assert.equal(sessionResponse.status, 200);
  assert.equal((await sessionResponse.json()).setupRequired, true);

  const unauthenticated = await requestJson(baseUrl, "/api/candidates");
  assert.equal(unauthenticated.status, 401);

  const invalidSetup = await requestJson(baseUrl, "/api/auth/setup", {
    method: "POST",
    headers: { "X-Bootstrap-Token": "wrong-bootstrap-token" },
    body: { username: "governance-admin", displayName: "Governance Admin", password: "correct horse battery staple" },
  });
  assert.equal(invalidSetup.status, 401);

  const setup = await requestJson(baseUrl, "/api/auth/setup", {
    method: "POST",
    headers: { "X-Bootstrap-Token": "test-bootstrap-token-with-at-least-32-bytes" },
    body: { username: "governance-admin", displayName: "Governance Admin", password: "correct horse battery staple" },
  });
  assert.equal(setup.status, 201, output());
  const setupPayload = await setup.json();
  const adminCookie = setup.headers.get("set-cookie").split(";")[0];
  assert.match(setup.headers.get("set-cookie"), /HttpOnly/);
  assert.match(setup.headers.get("set-cookie"), /SameSite=Lax/);
  assert.equal(setupPayload.user.role, "admin");

  const candidatesResponse = await requestJson(baseUrl, "/api/candidates", { cookie: adminCookie });
  assert.equal(candidatesResponse.status, 200);
  const { candidates } = await candidatesResponse.json();
  assert.equal(candidates.length, 1);
  const candidateId = candidates[0].id;
  const workspaceResponse = await requestJson(baseUrl, `/api/candidates/${candidateId}/state`, { cookie: adminCookie });
  assert.equal(workspaceResponse.status, 200);
  const workspace = await workspaceResponse.json();
  const currentEtag = workspaceResponse.headers.get("etag");
  assert.equal(workspace.releaseAuthorization, null);
  assert.equal(workspace.candidate.revision, Number(currentEtag.replaceAll('"', "")));
  assert.equal(workspace.stages[0].gateStatus, "not_run");
  assert.equal(workspace.stages[1].gateStatus, "locked");

  const otherCandidateResponse = await requestJson(baseUrl, "/api/candidates", {
    method: "POST",
    cookie: adminCookie,
    csrf: setupPayload.csrfToken,
    body: { projectName: "Restricted Project", releaseName: "2.0" },
  });
  assert.equal(otherCandidateResponse.status, 201, output());
  const otherCandidate = await otherCandidateResponse.json();
  const otherEvidenceUpload = await fetch(
    `${baseUrl}/api/evidence/upload?candidateId=${otherCandidate.candidate.id}&stageId=requirements`,
    {
      method: "POST",
      headers: {
        Cookie: adminCookie,
        "X-CSRF-Token": setupPayload.csrfToken,
        "If-Match": otherCandidateResponse.headers.get("etag"),
        "Content-Type": "application/octet-stream",
        "X-Evidence-Filename": Buffer.from("restricted-requirements.md").toString("base64url"),
      },
      body: Buffer.from("# Restricted project evidence\nPrivate requirements.", "utf8"),
    },
  );
  assert.equal(otherEvidenceUpload.status, 201, output());
  const otherEvidence = await otherEvidenceUpload.json();
  const otherDocumentResponse = await requestJson(
    baseUrl,
    `/api/candidates/${otherCandidate.candidate.id}/stages/requirements/documents`,
    {
      method: "POST",
      cookie: adminCookie,
      csrf: setupPayload.csrfToken,
      etag: otherEvidenceUpload.headers.get("etag"),
      body: { format: "markdown" },
    },
  );
  assert.equal(otherDocumentResponse.status, 201, output());
  const otherDocument = await otherDocumentResponse.json();

  const checklistPath = `/api/candidates/${candidateId}/stages/requirements/checklist`;
  const missingCsrf = await requestJson(baseUrl, checklistPath, {
    method: "PUT",
    cookie: adminCookie,
    etag: currentEtag,
    body: { index: 0, checked: true },
  });
  assert.equal(missingCsrf.status, 403, `${await missingCsrf.text()}\n${output()}`);

  const updated = await requestJson(baseUrl, checklistPath, {
    method: "PUT",
    cookie: adminCookie,
    csrf: setupPayload.csrfToken,
    etag: currentEtag,
    body: { index: 0, checked: true },
  });
  assert.equal(updated.status, 200, output());
  const updatedPayload = await updated.json();
  const updatedEtag = updated.headers.get("etag");
  assert.equal(updatedPayload.stages[0].checklistItems[0].completed, true);
  assert.notEqual(updatedEtag, currentEtag);

  const staleRevision = await requestJson(baseUrl, checklistPath, {
    method: "PUT",
    cookie: adminCookie,
    csrf: setupPayload.csrfToken,
    etag: currentEtag,
    body: { index: 1, checked: true },
  });
  assert.equal(staleRevision.status, 412);

  const upload = await fetch(
    `${baseUrl}/api/evidence/upload?candidateId=${candidateId}&stageId=requirements`,
    {
      method: "POST",
      headers: {
        Cookie: adminCookie,
        "X-CSRF-Token": setupPayload.csrfToken,
        "If-Match": updatedEtag,
        "Content-Type": "application/octet-stream",
        "X-Evidence-Filename": Buffer.from("requirements.md").toString("base64url"),
      },
      body: Buffer.from("# Requirements\nRelease safety requirements.", "utf8"),
    },
  );
  assert.equal(upload.status, 201, output());
  const uploadPayload = await upload.json();
  assert.equal(uploadPayload.scanStatus, "unscanned");
  assert.equal(uploadPayload.releaseEligible, false);

  const quarantined = await requestJson(baseUrl, `/api/evidence/${uploadPayload.evidence.id}`, { cookie: adminCookie });
  assert.equal(quarantined.status, 423);

  const refresh = await requestJson(baseUrl, `/api/candidates/${candidateId}/state`, { cookie: adminCookie });
  const refreshedEtag = refresh.headers.get("etag");
  const confirm = await requestJson(baseUrl, `/api/candidates/${candidateId}/stages/requirements/confirmations`, {
    method: "POST",
    cookie: adminCookie,
    csrf: setupPayload.csrfToken,
    etag: refreshedEtag,
    body: {},
  });
  assert.equal(confirm.status, 409);
  const refreshedState = await requestJson(baseUrl, `/api/candidates/${candidateId}/state`, { cookie: adminCookie });
  const evidenceFile = path.join(dataDirectory, "evidence", `${uploadPayload.evidence.id}.md`);
  const removeEvidenceResponse = await requestJson(baseUrl, `/api/evidence/${uploadPayload.evidence.id}?candidateId=${candidateId}`, {
    method: "DELETE",
    cookie: adminCookie,
    csrf: setupPayload.csrfToken,
    etag: refreshedState.headers.get("etag"),
    body: {},
  });
  assert.equal(removeEvidenceResponse.status, 200, output());
  assert.equal((await removeEvidenceResponse.json()).evidenceCleanupPending, false);
  await assert.rejects(access(evidenceFile), { code: "ENOENT" });

  const addDeveloper = await requestJson(baseUrl, "/api/auth/users", {
    method: "POST",
    cookie: adminCookie,
    csrf: setupPayload.csrfToken,
    body: {
      username: "governance-dev",
      displayName: "Governance Developer",
      role: "developer",
      password: "correct horse battery staple",
    },
  });

  assert.equal(addDeveloper.status, 201, output());

  const logout = await requestJson(baseUrl, "/api/auth/logout", {
    method: "POST",
    cookie: adminCookie,
    csrf: setupPayload.csrfToken,
    body: {},
  });
  assert.equal(logout.status, 200);
  const staleSession = await requestJson(baseUrl, "/api/candidates", { cookie: adminCookie });
  assert.equal(staleSession.status, 401);

  const login = await requestJson(baseUrl, "/api/auth/login", {
    method: "POST",
    body: { username: "governance-dev", password: "correct horse battery staple" },
  });
  assert.equal(login.status, 200, output());
  const loginPayload = await login.json();
  const developerCookie = login.headers.get("set-cookie").split(";")[0];
  assert.deepEqual(
    (await (await requestJson(baseUrl, "/api/candidates", { cookie: developerCookie })).json()).candidates,
    [],
  );

  const adminReauth = await requestJson(baseUrl, "/api/auth/login", {
    method: "POST",
    body: { username: "governance-admin", password: "correct horse battery staple" },
  });
  assert.equal(adminReauth.status, 200);
  const adminReauthPayload = await adminReauth.json();
  const adminReauthCookie = adminReauth.headers.get("set-cookie").split(";")[0];
  const projectsResponse = await requestJson(baseUrl, "/api/projects", { cookie: adminReauthCookie });
  const projects = (await projectsResponse.json()).projects;
  const workspaceProject = projects.find((project) => project.name === workspace.candidate.projectName);
  assert.ok(workspaceProject);
  const createScopedAccount = await requestJson(baseUrl, "/api/auth/users", {
    method: "POST",
    cookie: adminReauthCookie,
    csrf: adminReauthPayload.csrfToken,
    body: {
      username: "scoped-auditor",
      displayName: "Scoped Auditor",
      role: "developer",
      projectId: workspaceProject.id,
      projectRole: "auditor",
      password: "another secure governance password",
    },
  });
  assert.equal(createScopedAccount.status, 201, output());
  assert.deepEqual((await createScopedAccount.json()).projectMembership, {
    projectId: workspaceProject.id,
    role: "auditor",
  });
  const addProjectMember = await requestJson(
    baseUrl,
    `/api/projects/${workspaceProject.id}/members/${loginPayload.user.id}`,
    {
      method: "PUT",
      cookie: adminReauthCookie,
      csrf: adminReauthPayload.csrfToken,
      body: { role: "developer" },
    },
  );
  assert.equal(addProjectMember.status, 200, output());
  const scopedCandidates = await requestJson(baseUrl, "/api/candidates", { cookie: developerCookie });
  assert.deepEqual(
    (await scopedCandidates.json()).candidates.map((candidate) => candidate.id),
    [candidateId],
  );
  assert.equal((await (await requestJson(baseUrl, "/api/projects", { cookie: developerCookie })).json()).projects.length, 1);
  const projectRoleState = await requestJson(baseUrl, `/api/candidates/${candidateId}/state`, { cookie: developerCookie });
  assert.equal((await projectRoleState.json()).candidate.projectRole, "developer");
  const crossProjectState = await requestJson(
    baseUrl,
    `/api/candidates/${otherCandidate.candidate.id}/state`,
    { cookie: developerCookie },
  );
  assert.equal(crossProjectState.status, 404);
  for (const route of [
    `/api/release/confidence?candidateId=${otherCandidate.candidate.id}`,
    `/api/evidence/list?candidateId=${otherCandidate.candidate.id}&stageId=requirements`,
    `/api/evidence/${otherEvidence.evidence.id}`,
    `/api/documents/${otherDocument.id}?candidateId=${otherCandidate.candidate.id}`,
    `/api/audit/logs?candidateId=${otherCandidate.candidate.id}`,
    `/api/events?candidateId=${otherCandidate.candidate.id}`,
  ]) {
    const denied = await requestJson(baseUrl, route, { cookie: developerCookie });
    assert.equal(denied.status, 404, `${route} must remain project-scoped`);
  }
  assert.equal((await requestJson(baseUrl, "/api/events", { cookie: developerCookie })).status, 400);
  assert.equal((await requestJson(baseUrl, "/api/audit/logs", { cookie: developerCookie })).status, 400);

  const setProjectAuditor = await requestJson(
    baseUrl,
    `/api/projects/${workspaceProject.id}/members/${loginPayload.user.id}`,
    {
      method: "PUT",
      cookie: adminReauthCookie,
      csrf: adminReauthPayload.csrfToken,
      body: { role: "auditor" },
    },
  );
  assert.equal(setProjectAuditor.status, 200);
  const auditorState = await requestJson(baseUrl, `/api/candidates/${candidateId}/state`, { cookie: developerCookie });
  const projectAuditorMutation = await requestJson(
    baseUrl,
    `/api/candidates/${candidateId}/stages/requirements/checklist`,
    {
      method: "PUT",
      cookie: developerCookie,
      csrf: loginPayload.csrfToken,
      etag: auditorState.headers.get("etag"),
      body: { index: 1, checked: true },
    },
  );
  assert.equal(projectAuditorMutation.status, 403);
  const projectEventStream = await fetch(`${baseUrl}/api/events?candidateId=${candidateId}`, {
    headers: { Cookie: developerCookie },
  });
  assert.equal(projectEventStream.status, 200);
  const streamClosed = (async () => {
    for await (const _chunk of projectEventStream.body) {
      // Drain queued governance events until membership revocation closes the stream.
    }
    return true;
  })();
  const removeProjectMember = await requestJson(
    baseUrl,
    `/api/projects/${workspaceProject.id}/members/${loginPayload.user.id}`,
    {
      method: "DELETE",
      cookie: adminReauthCookie,
      csrf: adminReauthPayload.csrfToken,
    },
  );
  assert.equal(removeProjectMember.status, 204);
  assert.equal(await Promise.race([
    streamClosed,
    new Promise((resolve) => setTimeout(() => resolve(false), 1000)),
  ]), true);
  assert.equal(
    (await requestJson(baseUrl, `/api/candidates/${candidateId}/state`, { cookie: developerCookie })).status,
    404,
  );

  const forbiddenCandidate = await requestJson(baseUrl, "/api/candidates", {
    method: "POST",
    cookie: developerCookie,
    csrf: loginPayload.csrfToken,
    body: { projectName: "Restricted Project", releaseName: "1.0" },
  });
  assert.equal(forbiddenCandidate.status, 403);

  const logoutDeveloper = await requestJson(baseUrl, "/api/auth/logout", {
    method: "POST",
    cookie: developerCookie,
    csrf: loginPayload.csrfToken,
    body: {},
  });
  assert.equal(logoutDeveloper.status, 200);

  await stopServer(child);
  const restarted = await startServer(dataDirectory);
  activeChild = restarted.child;
  const persistedSession = await requestJson(restarted.baseUrl, "/api/session");
  const persisted = await persistedSession.json();
  assert.equal(persisted.setupRequired, false);
  assert.equal(persisted.authenticated, false);
  const persistedLogin = await requestJson(restarted.baseUrl, "/api/auth/login", {
    method: "POST",
    body: { username: "governance-admin", password: "correct horse battery staple" },
  });
  assert.equal(persistedLogin.status, 200, restarted.output());
});

test("signed CI and GitHub webhook retries are acknowledged without duplicate processing", { timeout: 20_000 }, async (context) => {
  const dataDirectory = await mkdtemp(path.join(os.tmpdir(), "governance-webhooks-"));
  const ciSecret = "ci-test-secret-that-is-long-enough";
  const githubSecret = "github-test-secret-that-is-long-enough";
  const { baseUrl, child, output } = await startServer(dataDirectory, {
    CI_WEBHOOK_SECRET: ciSecret,
    GITHUB_TOKEN: "test-token-not-used-for-webhooks",
    GITHUB_OWNER: "governance-test",
    GITHUB_REPO: "sample-project",
    GITHUB_WEBHOOK_SECRET: githubSecret,
  });
  context.after(async () => {
    await stopServer(child);
    await rm(dataDirectory, { recursive: true, force: true });
  });

  const setup = await requestJson(baseUrl, "/api/auth/setup", {
    method: "POST",
    headers: { "X-Bootstrap-Token": "test-bootstrap-token-with-at-least-32-bytes" },
    body: { username: "webhook-admin", displayName: "Webhook Admin", password: "correct horse battery staple" },
  });
  assert.equal(setup.status, 201, output());
  const { csrfToken } = await setup.json();
  const cookie = setup.headers.get("set-cookie").split(";")[0];
  const candidates = await requestJson(baseUrl, "/api/candidates", { cookie });
  const [{ id: candidateId }] = (await candidates.json()).candidates;
  const initial = await requestJson(baseUrl, `/api/candidates/${candidateId}/state`, { cookie });
  const commitSha = "a".repeat(40);
  const pin = await requestJson(baseUrl, `/api/candidates/${candidateId}/identity`, {
    method: "PATCH",
    cookie,
    csrf: csrfToken,
    etag: initial.headers.get("etag"),
    body: { commitSha },
  });
  assert.equal(pin.status, 200, output());

  const githubDelivery = "3b12f1df-5232-4e3f-9a7a-2b89d04f4c31";
  const githubBody = JSON.stringify({
    repository: { full_name: "governance-test/sample-project" },
    after: commitSha,
  });
  const githubSignature = createHmac("sha256", githubSecret).update(githubBody).digest("hex");
  const postGithub = () => fetch(`${baseUrl}/api/github/webhook`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-GitHub-Event": "push",
      "X-GitHub-Delivery": githubDelivery,
      "X-Hub-Signature-256": `sha256=${githubSignature}`,
    },
    body: githubBody,
  });
  const githubAccepted = await postGithub();
  assert.equal(githubAccepted.status, 202, output());
  const githubReplay = await postGithub();
  const githubReplayPayload = await githubReplay.json();
  assert.equal(githubReplay.status, 202);
  assert.equal(githubReplayPayload.duplicateDelivery, true);

  const ciDelivery = "5f8ca9f0-c346-4e18-8b43-335ea9698b95";
  const ciBody = JSON.stringify({
    candidateId,
    commitSha,
    deliveryId: ciDelivery,
    workflow: "integration-test",
    metrics: { lineCoverage: 91, branchCoverage: 86, criticalPathCoverage: 100 },
  });
  const ciSignature = createHmac("sha256", ciSecret).update(ciBody).digest("hex");
  const postCi = () => fetch(`${baseUrl}/api/cicd/coverage`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CI-Delivery": ciDelivery,
      "X-CI-Signature": `sha256=${ciSignature}`,
    },
    body: ciBody,
  });
  const ciAccepted = await postCi();
  assert.equal(ciAccepted.status, 200, output());
  const ciAcceptedPayload = await ciAccepted.json();
  assert.equal(ciAcceptedPayload.stages[3].metrics.lineCoverage, 91);
  const ciReplay = await postCi();
  const ciReplayPayload = await ciReplay.json();
  assert.equal(ciReplay.status, 200);
  assert.equal(ciReplayPayload.duplicateDelivery, true);
  const conflictingBody = JSON.stringify({
    candidateId,
    commitSha,
    deliveryId: ciDelivery,
    workflow: "integration-test",
    metrics: { lineCoverage: 99, branchCoverage: 99, criticalPathCoverage: 100 },
  });
  const conflictingSignature = createHmac("sha256", ciSecret).update(conflictingBody).digest("hex");
  const conflictingReplay = await fetch(`${baseUrl}/api/cicd/coverage`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CI-Delivery": ciDelivery,
      "X-CI-Signature": `sha256=${conflictingSignature}`,
    },
    body: conflictingBody,
  });
  assert.equal(conflictingReplay.status, 409);
  assert.equal((await conflictingReplay.json()).error.code, "webhook_delivery_conflict");

  const audit = await requestJson(baseUrl, `/api/audit/logs?candidateId=${candidateId}&limit=200`, { cookie });
  const auditEvents = (await audit.json()).events;
  assert.equal(auditEvents.filter((item) => item.detail.includes(`Delivery ${githubDelivery}`)).length, 1);
  assert.equal(
    auditEvents.filter((item) => item.action === "Recorded authenticated CI coverage metrics").length,
    1,
  );
});

test("GitHub status failures are visible after a persisted gate validation", { timeout: 20_000 }, async (context) => {
  const dataDirectory = await mkdtemp(path.join(os.tmpdir(), "governance-github-status-"));
  const scanner = createNetServer((socket) => {
    socket.once("data", () => socket.end("stream: OK\0"));
  });
  scanner.listen(0, "127.0.0.1");
  await once(scanner, "listening");
  const scannerPort = scanner.address().port;

  let onCommitStatus;
  const githubApi = createServer(async (request, response) => {
    if (request.url?.includes("/statuses/") && onCommitStatus) {
      const hook = onCommitStatus;
      onCommitStatus = null;
      await hook();
    }
    response.writeHead(500, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ message: "test status endpoint unavailable" }));
  });
  githubApi.listen(0, "127.0.0.1");
  await once(githubApi, "listening");
  const githubPort = githubApi.address().port;

  const aiApi = createServer((_request, response) => {
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify({
      choices: [{ message: { content: JSON.stringify({ summary: "Evidence reviewed.", findings: [] }) } }],
    }));
  });
  aiApi.listen(0, "127.0.0.1");
  await once(aiApi, "listening");
  const aiPort = aiApi.address().port;

  const { baseUrl, child, output } = await startServer(dataDirectory, {
    CLAMAV_HOST: "127.0.0.1",
    CLAMAV_PORT: String(scannerPort),
    GITHUB_TOKEN: "test-token",
    GITHUB_OWNER: "governance-test",
    GITHUB_REPO: "sample-project",
    GITHUB_API_URL: `http://127.0.0.1:${githubPort}`,
    AI_API_KEY: "test-ai-key",
    AI_BASE_URL: `http://127.0.0.1:${aiPort}/v1`,
  });
  context.after(async () => {
    await stopServer(child);
    await Promise.all([
      new Promise((resolve) => scanner.close(resolve)),
      new Promise((resolve) => githubApi.close(resolve)),
      new Promise((resolve) => aiApi.close(resolve)),
    ]);
    await rm(dataDirectory, { recursive: true, force: true });
  });

  const setup = await requestJson(baseUrl, "/api/auth/setup", {
    method: "POST",
    headers: { "X-Bootstrap-Token": "test-bootstrap-token-with-at-least-32-bytes" },
    body: { username: "status-admin", displayName: "Status Admin", password: "correct horse battery staple" },
  });
  assert.equal(setup.status, 201, output());
  const { csrfToken } = await setup.json();
  const cookie = setup.headers.get("set-cookie").split(";")[0];
  const candidates = await requestJson(baseUrl, "/api/candidates", { cookie });
  const [{ id: candidateId }] = (await candidates.json()).candidates;
  let stateResponse = await requestJson(baseUrl, `/api/candidates/${candidateId}/state`, { cookie });
  let etag = stateResponse.headers.get("etag");
  const commitSha = "b".repeat(40);
  const identity = await requestJson(baseUrl, `/api/candidates/${candidateId}/identity`, {
    method: "PATCH",
    cookie,
    csrf: csrfToken,
    etag,
    body: { commitSha },
  });
  assert.equal(identity.status, 200, output());
  etag = identity.headers.get("etag");

  for (let index = 0; index < 4; index += 1) {
    const checklist = await requestJson(baseUrl, `/api/candidates/${candidateId}/stages/requirements/checklist`, {
      method: "PUT",
      cookie,
      csrf: csrfToken,
      etag,
      body: { index, checked: true },
    });
    assert.equal(checklist.status, 200, output());
    etag = checklist.headers.get("etag");
  }
  const upload = await fetch(`${baseUrl}/api/evidence/upload?candidateId=${candidateId}&stageId=requirements`, {
    method: "POST",
    headers: {
      Cookie: cookie,
      "X-CSRF-Token": csrfToken,
      "If-Match": etag,
      "Content-Type": "application/octet-stream",
      "X-Evidence-Filename": Buffer.from("requirements.md").toString("base64url"),
    },
    body: Buffer.from("# Requirements\nMeasurable release requirements.", "utf8"),
  });
  assert.equal(upload.status, 201, output());
  const evidence = (await upload.json()).evidence;
  etag = upload.headers.get("etag");

  const analysis = await requestJson(baseUrl, `/api/candidates/${candidateId}/stages/requirements/analyses`, {
    method: "POST",
    cookie,
    csrf: csrfToken,
    etag,
    body: { evidenceIds: [evidence.id] },
  });
  assert.equal(analysis.status, 200, output());
  etag = analysis.headers.get("etag");

  const confirmation = await requestJson(baseUrl, `/api/candidates/${candidateId}/stages/requirements/confirmations`, {
    method: "POST",
    cookie,
    csrf: csrfToken,
    etag,
    body: {},
  });
  assert.equal(confirmation.status, 200, output());

  onCommitStatus = async () => {
    const beforeRace = await requestJson(baseUrl, `/api/candidates/${candidateId}/state`, { cookie });
    const changedDuringSync = await requestJson(baseUrl, `/api/candidates/${candidateId}/identity`, {
      method: "PATCH",
      cookie,
      csrf: csrfToken,
      etag: beforeRace.headers.get("etag"),
      body: { commitSha: "c".repeat(40) },
    });
    assert.equal(changedDuringSync.status, 200, output());
  };
  const validation = await requestJson(baseUrl, `/api/candidates/${candidateId}/stages/requirements/validations`, {
    method: "POST",
    cookie,
    csrf: csrfToken,
    etag: confirmation.headers.get("etag"),
    body: {},
  });
  assert.equal(validation.status, 200, output());
  const validationPayload = await validation.json();
  assert.equal(validationPayload.stages[0].validation, null);
  assert.equal(validationPayload.stages[0].gateStatus, "not_run");
  assert.equal(validationPayload.integrations.githubCommitStatus.status, "failed");
  assert.equal(validationPayload.integrations.candidateChangedDuringSync, true);
  assert.ok(validationPayload.integrations.githubCommitStatus.errorCode);
  assert.ok(validationPayload.auditEvents.some((entry) =>
    entry.action === "GitHub governance status synchronization failed",
  ));
  assert.ok(validationPayload.auditEvents.some((entry) =>
    entry.action === "Passed Requirements validation",
  ));
});

test("failed evidence-file deletion remains queued and retries after service restart", { timeout: 20_000 }, async (context) => {
  const dataDirectory = await mkdtemp(path.join(os.tmpdir(), "governance-evidence-cleanup-"));
  let { baseUrl, child, output } = await startServer(dataDirectory);
  let activeChild = child;
  context.after(async () => {
    await stopServer(activeChild);
    await rm(dataDirectory, { recursive: true, force: true });
  });

  const setup = await requestJson(baseUrl, "/api/auth/setup", {
    method: "POST",
    headers: { "X-Bootstrap-Token": "test-bootstrap-token-with-at-least-32-bytes" },
    body: { username: "cleanup-admin", displayName: "Cleanup Admin", password: "correct horse battery staple" },
  });
  assert.equal(setup.status, 201, output());
  const { csrfToken } = await setup.json();
  const cookie = setup.headers.get("set-cookie").split(";")[0];
  const candidates = await requestJson(baseUrl, "/api/candidates", { cookie });
  const [{ id: candidateId }] = (await candidates.json()).candidates;
  const candidateState = await requestJson(baseUrl, `/api/candidates/${candidateId}/state`, { cookie });
  const upload = await fetch(`${baseUrl}/api/evidence/upload?candidateId=${candidateId}&stageId=requirements`, {
    method: "POST",
    headers: {
      Cookie: cookie,
      "X-CSRF-Token": csrfToken,
      "If-Match": candidateState.headers.get("etag"),
      "Content-Type": "application/octet-stream",
      "X-Evidence-Filename": Buffer.from("requirements.md").toString("base64url"),
    },
    body: Buffer.from("# Requirements\nCleanup retry test.", "utf8"),
  });
  assert.equal(upload.status, 201, output());
  const evidence = (await upload.json()).evidence;
  const evidenceFile = path.join(dataDirectory, "evidence", `${evidence.id}.md`);

  await rm(evidenceFile);
  await mkdir(path.join(evidenceFile, "blocked"), { recursive: true });
  await writeFile(path.join(evidenceFile, "blocked", "retain.txt"), "non-empty directory prevents unlink");
  const current = await requestJson(baseUrl, `/api/candidates/${candidateId}/state`, { cookie });
  const removal = await requestJson(baseUrl, `/api/evidence/${evidence.id}?candidateId=${candidateId}`, {
    method: "DELETE",
    cookie,
    csrf: csrfToken,
    etag: current.headers.get("etag"),
    body: {},
  });
  assert.equal(removal.status, 200, output());
  assert.equal((await removal.json()).evidenceCleanupPending, true);

  await stopServer(child);
  await rm(evidenceFile, { recursive: true, force: true });
  const restarted = await startServer(dataDirectory);
  activeChild = restarted.child;
  output = restarted.output;
  const db = new DatabaseSync(path.join(dataDirectory, "governance.sqlite"), { readOnly: true });
  try {
    assert.equal(db.prepare("SELECT count(*) AS count FROM evidence_cleanup").get().count, 0);
  } finally {
    db.close();
  }
});

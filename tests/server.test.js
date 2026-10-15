import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { once } from "node:events";
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

async function startServer(dataDirectory) {
  const port = await availablePort();
  const child = spawn(
    process.execPath,
    [fileURLToPath(new URL("../server.mjs", import.meta.url))],
    {
      env: {
        ...process.env,
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

import { createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { createServer as createHttpServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { config } from "./config.mjs";
import { HttpError, assert } from "./errors.mjs";
import {
  appendEvent,
  closeDatabase,
  changeUserRole,
  createSession,
  deleteSession,
  getCandidate,
  getDocument,
  getEvidence,
  getReleaseAuthorization,
  getSession,
  getUserById,
  getUserByUsername,
  insertUser,
  listAudit,
  listCandidates,
  listUsers,
  markOutboxDispatched,
  pendingEvents,
  sessionCount,
  setUserActive,
  updateUserRole,
  withTransaction,
} from "./database.mjs";
import {
  checkLoginRateLimit,
  clearSessionCookie,
  hashPassword,
  isAllowedRole,
  newOpaqueSession,
  parseCookies,
  resetLoginRateLimit,
  sessionCookie,
  sha256,
  verifyCsrf,
  verifyPassword,
  verifyOrigin,
} from "./security.mjs";
import {
  addFindingDisposition,
  approveStage,
  auditRecords,
  authorizeRelease,
  changeCandidateIdentity,
  confirmStage,
  createAuthorizedReleaseTag,
  createEvidence,
  createFirstCandidate,
  createNewCandidate,
  createStageDocument,
  evidenceDetails,
  evidenceForStage,
  generateCodeProposal,
  publicCandidate,
  pushArtifact,
  readStageDocument,
  releaseConfidence,
  removeEvidence,
  rescanEvidence,
  runStageAnalysis,
  setCoverageMetrics,
  setEventBroadcaster,
  updateChecklist,
  validateStage,
} from "./workflow.mjs";
import { aiStatus } from "./ai.mjs";
import {
  inspectWebhookDelivery,
  checkCommitStatus,
  commentOnPullRequest,
  githubStatus,
  setCommitStatus,
} from "./github.mjs";
import {
  loadEvidenceFile,
  scannerAvailable,
} from "./storage.mjs";

const root = path.resolve(fileURLToPath(new URL("../../", import.meta.url)));
const publicFiles = new Set([
  "index.html",
  "styles.css",
  "favicon.svg",
  "src/app.js",
  "src/governance.js",
]);
const contentTypes = new Map([
  [".html", "text/html; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".mjs", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".svg", "image/svg+xml"],
]);
const sseClients = new Set();
const sseCandidateLimit = 100;
const serverStartedAt = new Date().toISOString();

function publicUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    username: user.username,
    displayName: user.display_name ?? user.displayName,
    role: user.role,
  };
}

function responseHeaders(request, { contentType, contentLength, download, policy } = {}) {
  const headers = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Content-Security-Policy":
      policy ||
      "default-src 'self'; script-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
    "X-Request-Id": request.requestId,
  };
  if (contentType) headers["Content-Type"] = contentType;
  if (contentLength !== undefined) headers["Content-Length"] = String(contentLength);
  if (download) {
    const safeName = download.replace(/[\r\n"\\]/g, "_");
    headers["Content-Disposition"] = `attachment; filename*=UTF-8''${encodeURIComponent(safeName)}`;
    headers["Content-Type"] = "application/octet-stream";
  }
  const forwardedProtocol = config.trustProxy
    ? request.headers["x-forwarded-proto"]?.split(",")[0].trim()
    : null;
  if (config.isProduction && forwardedProtocol === "https") {
    headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains";
  }
  return headers;
}

function sendJson(request, response, status, payload, extra = {}) {
  if (response.headersSent) return;
  const body = Buffer.from(JSON.stringify(payload));
  response.writeHead(status, {
    ...responseHeaders(request, {
      contentType: "application/json; charset=utf-8",
      contentLength: body.length,
    }),
    ...extra,
  });
  response.end(body);
}

function sendEmpty(request, response, status, extra = {}) {
  response.writeHead(status, responseHeaders(request, { contentLength: 0, ...extra }));
  response.end();
}

function actorFor(session) {
  return {
    id: session.id,
    username: session.username,
    displayName: session.display_name,
    role: session.role,
  };
}

function cookieToken(request) {
  return parseCookies(request).get(config.cookieName) || null;
}

function resolveOptionalSession(request) {
  const token = cookieToken(request);
  if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
  return getSession(sha256(token));
}

function requireSession(request) {
  const session = resolveOptionalSession(request);
  assert(session, 401, "authentication_required", "Log in to access the governance workspace.");
  return session;
}

function assertCsrf(request, session) {
  verifyCsrf(request, session.csrf_token);
}

function requireRoles(session, roles) {
  assert(roles.includes(session.role), 403, "role_forbidden", "Your governance role is not authorized for this action.", {
    requiredRoles: roles,
  });
}

function requireRevision(request, session, candidateId) {
  const candidate = getCandidate(candidateId);
  assert(candidate, 404, "candidate_not_found", "The requested release candidate was not found.");
  const candidateRevision = request.headers["if-match"];
  assert(
    typeof candidateRevision === "string" &&
      candidateRevision === `"${candidate.revision}"`,
    candidateRevision ? 412 : 428,
    candidateRevision ? "stale_revision" : "revision_required",
    candidateRevision
      ? "The release candidate changed. Refresh and review the latest evidence before continuing."
      : "Include the loaded candidate ETag in the If-Match request header.",
    { currentRevision: candidate.revision },
  );
  assert(session, 401, "authentication_required", "Log in to perform this action.");
  return candidate;
}

function requireRevisionAndCsrf(request, session, candidateId) {
  const candidate = requireRevision(request, session, candidateId);
  assertCsrf(request, session);
  return candidate;
}

async function readBody(request, limit, { contentType = "application/json" } = {}) {
  const receivedType = String(request.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
  assert(
    receivedType === contentType,
    415,
    "unsupported_content_type",
    `This endpoint requires ${contentType}.`,
  );
  const declaredLength = Number(request.headers["content-length"]);
  if (Number.isFinite(declaredLength) && declaredLength > limit) {
    request.resume();
    throw new HttpError(413, "request_too_large", "The request body exceeds the permitted size.");
  }
  const chunks = [];
  let receivedBytes = 0;
  for await (const chunk of request) {
    receivedBytes += chunk.length;
    if (receivedBytes > limit) {
      request.destroy();
      throw new HttpError(413, "request_too_large", "The request body exceeds the permitted size.");
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function readJson(request, bodyReader) {
  const body = await bodyReader(config.maxJsonBytes, "application/json");
  try {
    const result = JSON.parse(body.toString("utf8"));
    assert(result && typeof result === "object" && !Array.isArray(result), 400, "invalid_request_body", "A JSON object is required.");
    return result;
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(400, "invalid_json", "The request body contains invalid JSON.");
  }

  const DUMMY_PASSWORD_HASH = await hashPassword(randomBytes(32).toString("hex"));
}

function requireString(value, field, maxLength = 255) {
  assert(
    typeof value === "string" && value.trim().length > 0 && Buffer.byteLength(value) <= maxLength,
    400,
    "invalid_field",
    `"${field}" must be a nonempty string no longer than ${maxLength} bytes.`,
  );
  return value.trim();
}

function decodeFilename(header) {
  assert(
    typeof header === "string" && /^[A-Za-z0-9_-]{1,800}$/.test(header),
    400,
    "evidence_filename_required",
    "Provide the URL-safe base64 encoded UTF-8 filename in X-Evidence-Filename.",
  );
  let filename;
  try {
    filename = Buffer.from(header, "base64url").toString("utf8");
    if (Buffer.from(filename, "utf8").toString("base64url") !== header) throw new Error("Noncanonical filename");
  } catch {
    throw new HttpError(400, "invalid_filename_encoding", "The evidence filename is invalid.");
  }
  return filename;
}

function parseEventId(value) {
  const parsed = Number(value || 0);
  assert(Number.isSafeInteger(parsed) && parsed >= 0, 400, "invalid_event_cursor", "The event cursor must be a non-negative integer.");
  return parsed;
}

function setInitialSession(request, response, userId) {
  const secrets = newOpaqueSession();
  const expiresAt = new Date(Date.now() + config.sessionLifetimeSeconds * 1000).toISOString();
  createSession({
    tokenHash: secrets.tokenHash,
    csrfToken: secrets.csrfToken,
    userId,
    expiresAt,
  });
  return {
    cookie: sessionCookie(secrets.sessionToken, request),
    csrfToken: secrets.csrfToken,
    user: publicUser(getUserById(userId)),
    expiresAt,
  };
}

function makeBodyReader(request) {
  let cachedPromise = null;
  let signature = "";
  return (limit, contentType = "application/json") => {
    const requestedSignature = `${limit}:${contentType}`;
    if (cachedPromise) {
      assert(
        requestedSignature === signature,
        400,
        "duplicate_request_body_read",
        "The request body cannot be read with conflicting content-type or size limits.",
      );
      return cachedPromise;
    }
    signature = requestedSignature;
    cachedPromise = readBody(request, limit, { contentType });
    return cachedPromise;
  };
}

function publicCapabilities() {
  return {
    storage: { provider: "local-private-filesystem", available: true },
    malwareScanner: { configured: scannerAvailable(), status: scannerAvailable() ? "available" : "not_configured" },
    ai: aiStatus(),
    github: {
      configured: Boolean(
        config.github.token && config.github.owner && config.github.repo,
      ),
      repository:
        config.github.owner && config.github.repo
          ? `${config.github.owner}/${config.github.repo}`
          : null,
    },
    metricsSource: config.ciWebhookSecret ? "HMAC-authenticated CI webhooks" : "not_configured",
  };
}

function broadcast(event) {
  const serialized = `id: ${event.sequence}\nevent: governance\ndata: ${JSON.stringify(event)}\n\n`;
  for (const client of sseClients) {
    if (client.candidateId && client.candidateId !== event.candidateId) continue;
    try {
      client.response.write(serialized);
      markOutboxDispatched(event.id);
    } catch {
      client.response.destroy();
      sseClients.delete(client);
    }
  }
}
setEventBroadcaster(broadcast);

async function staticFile(request, response, pathname) {
  const relativePath = pathname === "/" ? "index.html" : pathname.slice(1);
  if (!publicFiles.has(relativePath)) {
    sendJson(request, response, 404, { error: { code: "not_found", message: "The requested resource was not found." } });
    return;
  }
  const filename = path.resolve(root, relativePath);
  if (path.dirname(filename) !== root && !filename.startsWith(`${root}${path.sep}`)) {
    sendJson(request, response, 404, { error: { code: "not_found", message: "The requested resource was not found." } });
    return;
  }
  let data;
  try {
    const metadata = await stat(filename);
    if (!metadata.isFile() || metadata.size > 5 * 1024 * 1024) {
      sendJson(request, response, 404, { error: { code: "not_found", message: "The requested resource was not found." } });
      return;
    }
    data = await readFile(filename);
  } catch (error) {
    if (error.code === "ENOENT") {
      sendJson(request, response, 404, { error: { code: "not_found", message: "The requested resource was not found." } });
      return;
    }
    throw error;
  }
  const type = contentTypes.get(path.extname(filename)) || "application/octet-stream";
  response.writeHead(200, responseHeaders(request, { contentType: type, contentLength: data.length }));
  response.end(data);
}

function initializeFirstCandidate(actor) {
  if (listCandidates().length === 0) createFirstCandidate(actor);
}

async function handleApi(request, response, url, rawBodyPromise) {
  const pathname = url.pathname;
  let parts;
  try {
    parts = pathname.split("/").filter(Boolean).map((part) => decodeURIComponent(part));
  } catch {
    throw new HttpError(400, "invalid_path", "The request path is invalid.");
  }
  const method = request.method;

  if (pathname === "/api/health" && method === "GET") {
    sendJson(request, response, 200, {
      status: "ok",
      startedAt: serverStartedAt,
      authenticated: sessionCount() > 0,
      capabilities: publicCapabilities(),
    });
    return true;
  }

  if (pathname === "/api/session" && method === "GET") {
    verifyOrigin(request);
    const session = resolveOptionalSession(request);
    sendJson(request, response, 200, {
      authenticated: Boolean(session),
      setupRequired: sessionCount() === 0,
      user: session ? publicUser(session) : null,
      csrfToken: session?.csrf_token ?? null,
      capabilities: publicCapabilities(),
      roles: config.allowedRoles,
    });
    return true;
  }

  if (pathname === "/api/auth/setup" && method === "POST") {
    verifyOrigin(request);
    assert(sessionCount() === 0, 409, "setup_already_complete", "Initial administrator setup has already been completed.");
    const body = await readJson(request, rawBodyPromise);
    const provided = request.headers["x-bootstrap-token"];
    assert(
      typeof provided === "string" &&
        Buffer.byteLength(provided) === Buffer.byteLength(config.bootstrapToken) &&
        timingSafeEqual(Buffer.from(provided), Buffer.from(config.bootstrapToken)),
      401,
      "invalid_setup_token",
      "Provide the bootstrap token printed by the local server or configured with BOOTSTRAP_TOKEN.",
    );
    const username = requireString(body.username, "username", 128);
    const displayName = requireString(body.displayName, "displayName", 160);
    assert(/^[A-Za-z0-9._@+-]{3,128}$/.test(username), 400, "invalid_username", "Usernames must contain 3 to 128 letters, digits, periods, underscores, or @+-. characters.");
    const passwordHash = await hashPassword(body.password);
    let user;
    try {
      withTransaction(() => {
        assert(sessionCount() === 0, 409, "setup_already_complete", "Administrator setup has already been completed.");
        user = insertUser({
          username,
          displayName,
          passwordHash,
          role: "admin",
        });
      });
    } catch (error) {
      if (error.code === "ERR_SQLITE_CONSTRAINT_UNIQUE") {
        throw new HttpError(409, "username_exists", "The username is already in use.");
      }
      throw error;
    }
    initializeFirstCandidate({
      id: user.id,
      username: user.username,
      displayName: user.display_name,
      role: user.role,
    });
    const login = setInitialSession(request, response, user.id);
    sendJson(request, response, 201, {
      authenticated: true,
      user: login.user,
      csrfToken: login.csrfToken,
      expiresAt: login.expiresAt,
      workspace: publicCapabilities(),
    }, { "Set-Cookie": login.cookie });
    return true;
  }

  if (pathname === "/api/auth/login" && method === "POST") {
    verifyOrigin(request);
    checkLoginRateLimit(request);
    const body = await readJson(request, rawBodyPromise);
    const username = requireString(body.username, "username", 128);
    assert(typeof body.password === "string" && Buffer.byteLength(body.password) <= 1024, 400, "invalid_password", "Provide your account password.");
    const user = getUserByUsername(username);
    const verified = await verifyPassword(
      body.password,
      user?.password_hash || DUMMY_PASSWORD_HASH,
    );
    if (!user || !verified) {
      throw new HttpError(401, "invalid_credentials", "The username or password is incorrect.");
    }
    resetLoginRateLimit(request);
    const login = setInitialSession(request, response, user.id);
    sendJson(request, response, 200, {
      authenticated: true,
      user: login.user,
      csrfToken: login.csrfToken,
      expiresAt: login.expiresAt,
      workspace: publicCapabilities(),
    }, { "Set-Cookie": login.cookie });
    return true;
  }

  const session = requireSession(request);
  const actor = actorFor(session);

  if (pathname === "/api/auth/logout" && method === "POST") {
    assertCsrf(request, session);
    deleteSession(session.token_hash);
    sendJson(request, response, 200, { authenticated: false }, {
      "Set-Cookie": clearSessionCookie(request),
    });
    return true;
  }

  if (pathname === "/api/auth/password" && method === "POST") {
    assertCsrf(request, session);
    const body = await readJson(request, rawBodyPromise);
    assert(typeof body.currentPassword === "string" && typeof body.newPassword === "string", 400, "invalid_password", "Provide the current password and new password.");
    const user = getUserById(session.id);
    assert(await verifyPassword(body.currentPassword, user.password_hash), 401, "invalid_current_password", "The current password is incorrect.");
    const passwordHash = await hashPassword(body.newPassword);
    withTransaction(() => {
      db.prepare("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?").run(
        passwordHash,
        new Date().toISOString(),
        actor.id,
      );
      db.prepare("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?").run(
        actor.id,
        session.token_hash,
      );
      appendEvent({
        actor,
        action: "Changed account password",
        detail: "Existing sessions were revoked.",
        type: "security",
      });
    });
    sendJson(request, response, 200, { changed: true, otherSessionsRevoked: true });
    return true;
  }

  if (pathname === "/api/auth/roles" && method === "GET") {
    requireRoles(session, ["admin"]);
    sendJson(request, response, 200, {
      allowedRoles: config.allowedRoles,
      users: listUsers(),
    });
    return true;
  }

  if (pathname === "/api/auth/users" && method === "POST") {
    requireRoles(session, ["admin"]);
    assertCsrf(request, session);
    const body = await readJson(request, rawBodyPromise);
    const username = requireString(body.username, "username", 128);
    const displayName = requireString(body.displayName, "displayName", 160);
    const role = requireString(body.role, "role", 32);
    assert(/^[A-Za-z0-9._@+-]{3,128}$/.test(username), 400, "invalid_username", "The username contains invalid characters.");
    assert(isAllowedRole(role), 400, "invalid_role", "Choose an allowed governance role.");
    const passwordHash = await hashPassword(body.password);
    let user;
    try {
      user = insertUser({ username, displayName, passwordHash, role });
    } catch (error) {
      if (error.code === "ERR_SQLITE_CONSTRAINT_UNIQUE") {
        throw new HttpError(409, "username_exists", "The username is already in use.");
      }
      throw error;
    }
    appendEvent({
      actor,
      action: "Created governance user",
      detail: `${username} · ${role}`,
      type: "security",
    });
    sendJson(request, response, 201, { user: publicUser(user) });
    return true;
  }

  if (pathname.startsWith("/api/auth/roles/") && method === "PATCH") {
    requireRoles(session, ["admin"]);
    assertCsrf(request, session);
    const userId = parts[3];
    assert(userId && /^[a-f0-9-]{36}$/i.test(userId), 400, "invalid_user_id", "A valid user ID is required.");
    assert(userId !== actor.id, 409, "self_role_change_forbidden", "Administrators cannot change their own role.");
    const target = getUserById(userId);
    assert(target && target.active === 1, 404, "user_not_found", "The active user was not found.");
    const body = await readJson(request, rawBodyPromise);
    assert(isAllowedRole(body.role), 400, "invalid_role", "Choose one of the four supported governance roles.");
    if (body.role === "admin" && target.role !== "admin") {
      assert(listUsers().filter((user) => user.active && user.role === "admin").length <= 10, 409, "admin_role_limit", "Configure enterprise identity provisioning for additional administrative accounts.");
    }
    const updated = updateUserRole(userId, body.role);
    appendEvent({
      actor,
      action: "Changed governance role",
      detail: `${target.username} · ${target.role} → ${body.role} · All of their sessions revoked`,
      type: "security",
    });
    sendJson(request, response, 200, { user: publicUser(updated), sessionsRevoked: true });
    return true;
  }

  if (pathname.startsWith("/api/auth/users/") && method === "DELETE") {
    requireRoles(session, ["admin"]);
    assertCsrf(request, session);
    const userId = parts[3];
    assert(userId && /^[a-f0-9-]{36}$/i.test(userId), 400, "invalid_user_id", "A valid user ID is required.");
    assert(userId !== actor.id, 409, "self_deactivation_forbidden", "Administrators cannot deactivate their own account.");
    const target = getUserById(userId);
    assert(target && target.active === 1, 404, "user_not_found", "The active user was not found.");
    assert(!(target.role === "admin" && listUsers().filter((user) => user.active && user.role === "admin").length <= 1), 409, "last_admin_cannot_be_disabled", "The last active administrator cannot be disabled.");
    setUserActive(userId, false);
    appendEvent({
      actor,
      action: "Deactivated governance user",
      detail: `${target.username} · ${target.role} · Sessions revoked`,
      type: "security",
    });
    sendEmpty(request, response, 204);
    return true;
  }

  if (pathname === "/api/candidates" && method === "GET") {
    sendJson(request, response, 200, { candidates: listCandidates() });
    return true;
  }

  if (pathname === "/api/candidates" && method === "POST") {
    requireRoles(session, ["admin"]);
    assertCsrf(request, session);
    const body = await readJson(request, rawBodyPromise);
    const candidate = createNewCandidate({
      projectName: body.projectName,
      releaseName: body.releaseName,
      commitSha: body.commitSha || "",
      actor,
    });
    sendJson(request, response, 201, candidate, { ETag: `"${candidate.candidate.revision}"` });
    return true;
  }

  if (parts[1] === "candidates" && parts[2] && parts[3] === "state" && method === "GET") {
    const candidate = publicCandidate(parts[2]);
    sendJson(request, response, 200, candidate, { ETag: `"${candidate.candidate.revision}"` });
    return true;
  }

  if (
    parts[1] === "candidates" &&
    parts[2] &&
    parts[3] === "identity" &&
    method === "PATCH"
  ) {
    const existing = requireRevision(request, session, parts[2]);
    assertCsrf(request, session);
    const body = await readJson(request, rawBodyPromise);
    const candidate = changeCandidateIdentity(parts[2], request, body, actor);
    sendJson(request, response, 200, candidate, { ETag: `"${candidate.candidate.revision}"` });
    return true;
  }

  if (pathname === "/api/events" && method === "GET") {
    const candidateId = url.searchParams.get("candidateId") || null;
    if (candidateId) publicCandidate(candidateId);
    assert(sseClients.size < sseCandidateLimit, 503, "event_stream_capacity", "The live event stream is at capacity; retry shortly.");
    const cursor = parseEventId(request.headers["last-event-id"] || url.searchParams.get("after"));
    response.writeHead(200, {
      ...responseHeaders(request, {
        contentType: "text/event-stream; charset=utf-8",
      }),
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    });
    response.write("retry: 3000\n\n");
    let lastSequence = cursor;
    const initial = listAudit({ candidateId, after: cursor, limit: 100 });
    for (const item of initial) {
      response.write(`id: ${item.sequence}\nevent: governance\ndata: ${JSON.stringify(item)}\n\n`);
      lastSequence = item.sequence;
    }
    const client = { response, candidateId, userId: actor.id };
    sseClients.add(client);
    const heartbeat = setInterval(() => {
      if (!resolveOptionalSession(request)) {
        response.end();
        sseClients.delete(client);
        clearInterval(heartbeat);
        return;
      }
      const nextEvents = pendingEvents({ candidateId, after: lastSequence, limit: 100 });
      if (nextEvents.length === 100) {
        response.write("event: reset\ndata: {\"reason\":\"cursor_gap\"}\n\n");
      }
      for (const item of nextEvents) {
        response.write(`id: ${item.sequence}\nevent: governance\ndata: ${JSON.stringify(item)}\n\n`);
        lastSequence = item.sequence;
        markOutboxDispatched(item.id);
      }
      if (nextEvents.length === 0) response.write(`: heartbeat ${Date.now()}\n\n`);
    }, 15_000);
    response.on("close", () => {
      clearInterval(heartbeat);
      sseClients.delete(client);
    });
    return true;
  }

  if (pathname === "/api/evidence/upload" && method === "POST") {
    const candidateId = requireString(url.searchParams.get("candidateId"), "candidateId", 64);
    const stageId = requireString(url.searchParams.get("stageId"), "stageId", 32);
    const existing = requireRevision(request, session, candidateId);
    assertCsrf(request, session);
    requireRoles(session, ["admin", "qa_lead", "developer"]);
    const filename = decodeFilename(request.headers["x-evidence-filename"]);
    const bytes = await rawBodyPromise(config.maxUploadBytes, "application/octet-stream");
    const evidence = await createEvidence({
      candidateId,
      stageId,
      filename,
      bytes,
      actor,
      request,
    });
    const workspace = publicCandidate(candidateId);
    sendJson(request, response, 201, {
      evidence,
      scanStatus: evidence.scanStatus,
      releaseEligible: evidence.scanStatus === "clean",
      candidate: workspace.candidate,
    }, { ETag: `"${workspace.candidate.revision}"` });
    return true;
  }

  if (pathname === "/api/evidence/list" && method === "GET") {
    const candidateId = requireString(url.searchParams.get("candidateId"), "candidateId", 64);
    const stageId = requireString(url.searchParams.get("stageId"), "stageId", 32);
    sendJson(request, response, 200, {
      evidence: evidenceForStage(candidateId, stageId),
      scanner: { available: scannerAvailable(), required: true },
    });
    return true;
  }

  if (parts[1] === "evidence" && parts.length === 3 && parts[2] !== "upload" && parts[2] !== "list" && method === "GET") {
    const evidence = getEvidence(parts[2]);
    assert(evidence, 404, "evidence_not_found", "The requested evidence does not exist.");
    assert(evidence.scanStatus === "clean", 423, "evidence_quarantined", "Evidence is quarantined and cannot be opened until malware scanning marks it clean.");
    const internal = evidenceDetails(evidence.id);
    const data = await loadEvidenceFile(internal);
    const safeFilename = evidence.name.replace(/[\r\n"\\]/g, "_");
    response.writeHead(200, responseHeaders(request, {
      contentLength: data.length,
      download: safeFilename,
    }));
    response.end(data);
    return true;
  }

  if (parts[1] === "evidence" && parts.length === 4 && parts[3] === "scan" && method === "POST") {
    const existing = requireRevision(request, session, parts[2]);
    assertCsrf(request, session);
    const body = await readJson(request, rawBodyPromise);
    const result = await rescanEvidence({
      candidateId: parts[2],
      evidenceId: body.evidenceId,
      request,
      actor,
    });
    const refreshed = publicCandidate(parts[2]);
    sendJson(request, response, 200, { evidence: result, candidate: refreshed.candidate }, { ETag: `"${refreshed.candidate.revision}"` });
    return true;
  }

  if (parts[1] === "evidence" && parts.length === 3 && method === "DELETE") {
    const candidateId = url.searchParams.get("candidateId") || request.headers["x-candidate-id"];
    requireRevision(request, session, candidateId);
    assertCsrf(request, session);
    const body = await readJson(request, rawBodyPromise);
    const updated = await removeEvidence({
      candidateId,
      evidenceId: parts[2],
      request,
      actor,
    });
    sendJson(request, response, 200, updated, { ETag: `"${updated.candidate.revision}"` });
    return true;
  }

  if (parts[1] === "candidates" && parts[2] && parts[3] === "stages" && parts[4]) {
    const candidateId = parts[2];
    const stageId = parts[4];

    if (parts.length === 6 && parts[5] === "checklist" && method === "PUT") {
      requireRevision(request, session, candidateId);
      assertCsrf(request, session);
      const body = await readJson(request, rawBodyPromise);
      const candidate = updateChecklist({
        candidateId,
        stageId,
        index: Number(body.index),
        checked: body.checked,
        actor,
        request,
      });
      sendJson(request, response, 200, candidate, { ETag: `"${candidate.candidate.revision}"` });
      return true;
    }

    if (parts.length === 6 && parts[5] === "analyses" && method === "POST") {
      requireRevision(request, session, candidateId);
      assertCsrf(request, session);
      const body = await readJson(request, rawBodyPromise);
      const candidate = await runStageAnalysis({
        candidateId,
        stageId,
        actor,
        request,
        evidenceIds: body.evidenceIds,
      });
      sendJson(request, response, 200, candidate, { ETag: `"${candidate.candidate.revision}"` });
      return true;
    }

    if (parts.length === 6 && parts[5] === "confirmations" && method === "POST") {
      requireRevision(request, session, candidateId);
      assertCsrf(request, session);
      const candidate = await confirmStage({ candidateId, stageId, request, actor });
      sendJson(request, response, 200, candidate, { ETag: `"${candidate.candidate.revision}"` });
      return true;
    }

    if (parts.length === 6 && parts[5] === "validations" && method === "POST") {
      requireRevision(request, session, candidateId);
      assertCsrf(request, session);
      const candidate = await validateStage({ candidateId, stageId, request, actor });
      sendJson(request, response, 200, candidate, { ETag: `"${candidate.candidate.revision}"` });
      return true;
    }

    if (parts.length === 6 && parts[5] === "approvals" && method === "POST") {
      requireRevision(request, session, candidateId);
      assertCsrf(request, session);
      const candidate = await approveStage({ candidateId, stageId, request, actor });
      sendJson(request, response, 200, candidate, { ETag: `"${candidate.candidate.revision}"` });
      return true;
    }

    if (parts.length === 7 && parts[5] === "findings" && parts[6] && method === "PATCH") {
      requireRevision(request, session, candidateId);
      assertCsrf(request, session);
      const body = await readJson(request, rawBodyPromise);
      const candidate = addFindingDisposition({
        candidateId,
        stageId,
        findingId: parts[6],
        request,
        actor,
        status: body.status,
        rationale: body.rationale,
        evidenceId: body.evidenceId,
      });
      sendJson(request, response, 200, candidate, { ETag: `"${candidate.candidate.revision}"` });
      return true;
    }

    if (parts.length === 6 && parts[5] === "documents" && method === "POST") {
      assertCsrf(request, session);
      const body = await readJson(request, rawBodyPromise);
      const document = createStageDocument({
        candidateId,
        stageId,
        format: body.format,
        actor,
      });
      sendJson(request, response, 201, document);
      return true;
    }

    if (parts.length === 6 && parts[5] === "artifacts" && method === "POST") {
      assertCsrf(request, session);
      const body = await readJson(request, rawBodyPromise);
      const artifact = generateCodeProposal({
        candidateId,
        stageId,
        findingId: body.findingId,
        title: body.title,
        files: body.files,
        actor,
      });
      sendJson(request, response, 201, artifact);
      return true;
    }
  }

  if (parts[1] === "documents" && parts[2] && method === "GET") {
    const document = readStageDocument(url.searchParams.get("candidateId"), parts[2]);
    response.writeHead(200, responseHeaders(request, {
      contentType: document.format === "html" ? "text/html; charset=utf-8" : "text/markdown; charset=utf-8",
      contentLength: Buffer.byteLength(document.content),
      policy: "default-src 'none'; style-src 'unsafe-inline'; sandbox",
    }));
    response.end(document.content);
    return true;
  }

  if (parts[1] === "release" && parts[2] === "confidence" && method === "GET") {
    const candidateId = url.searchParams.get("candidateId");
    sendJson(request, response, 200, releaseConfidence(candidateId));
    return true;
  }

  if (pathname === "/api/release/authorize" && method === "POST") {
    const body = await readJson(request, rawBodyPromise);
    requireRevision(request, session, body.candidateId);
    assertCsrf(request, session);
    const authorization = authorizeRelease({
      candidateId: body.candidateId,
      request,
      actor,
    });
    sendJson(request, response, 201, authorization);
    return true;
  }

  if (pathname === "/api/release/tag" && method === "POST") {
    requireRoles(session, ["admin"]);
    assertCsrf(request, session);
    const body = await readJson(request, rawBodyPromise);
    const tag = await createAuthorizedReleaseTag({
      candidateId: body.candidateId,
      tag: body.tag,
      message: body.message,
      actor,
    });
    sendJson(request, response, 201, tag);
    return true;
  }

  if (pathname === "/api/requirements/validate" && method === "POST") {
    const body = await readJson(request, rawBodyPromise);
    requireRevision(request, session, body.candidateId);
    assertCsrf(request, session);
    const candidate = await validateStage({
      candidateId: body.candidateId,
      stageId: "requirements",
      request,
      actor,
    });
    sendJson(request, response, 200, candidate, { ETag: `"${candidate.candidate.revision}"` });
    return true;
  }

  if (pathname === "/api/architecture/review" && method === "POST") {
    const body = await readJson(request, rawBodyPromise);
    requireRevision(request, session, body.candidateId);
    assertCsrf(request, session);
    const candidate = await validateStage({
      candidateId: body.candidateId,
      stageId: "architecture",
      request,
      actor,
    });
    sendJson(request, response, 200, candidate, { ETag: `"${candidate.candidate.revision}"` });
    return true;
  }

  if (pathname === "/api/code/review" && method === "POST") {
    const body = await readJson(request, rawBodyPromise);
    requireRevision(request, session, body.candidateId);
    assertCsrf(request, session);
    const candidate = await validateStage({
      candidateId: body.candidateId,
      stageId: "code",
      request,
      actor,
    });
    sendJson(request, response, 200, candidate, { ETag: `"${candidate.candidate.revision}"` });
    return true;
  }

  if (pathname === "/api/tests/coverage" && method === "POST") {
    const body = await readJson(request, rawBodyPromise);
    requireRevision(request, session, body.candidateId);
    assertCsrf(request, session);
    const candidate = await validateStage({
      candidateId: body.candidateId,
      stageId: "tests",
      request,
      actor,
    });
    sendJson(request, response, 200, candidate, { ETag: `"${candidate.candidate.revision}"` });
    return true;
  }

  if (pathname === "/api/cicd/quality-gate" && method === "POST") {
    const body = await readJson(request, rawBodyPromise);
    requireRevision(request, session, body.candidateId);
    assertCsrf(request, session);
    const candidate = await validateStage({
      candidateId: body.candidateId,
      stageId: "cicd",
      request,
      actor,
    });
    sendJson(request, response, 200, candidate, { ETag: `"${candidate.candidate.revision}"` });
    return true;
  }

  if (pathname === "/api/production/readiness" && method === "POST") {
    const body = await readJson(request, rawBodyPromise);
    requireRevision(request, session, body.candidateId);
    assertCsrf(request, session);
    const candidate = await validateStage({
      candidateId: body.candidateId,
      stageId: "production",
      request,
      actor,
    });
    sendJson(request, response, 200, candidate, { ETag: `"${candidate.candidate.revision}"` });
    return true;
  }

  if (pathname === "/api/cicd/coverage" && method === "POST") {
    assert(Boolean(config.ciWebhookSecret), 503, "ci_webhook_not_configured", "Configure CI_WEBHOOK_SECRET before accepting CI coverage reports.");
    const body = await readJson(request, rawBodyPromise);
    const signature = request.headers["x-ci-signature"];
    const delivery = request.headers["x-ci-delivery"];
    assert(typeof signature === "string" && /^sha256=[a-f0-9]{64}$/.test(signature), 401, "invalid_ci_signature", "Provide the CI_WEBHOOK_SECRET HMAC-SHA256 signature.");
    assert(typeof delivery === "string" && /^[A-Za-z0-9-]{16,100}$/.test(delivery), 400, "invalid_ci_delivery", "A unique CI delivery identifier is required.");
    const rawBody = await rawBodyPromise(config.maxJsonBytes, "application/json");
    const expected = Buffer.from(`sha256=${createHmac("sha256", config.ciWebhookSecret).update(rawBody).digest("hex")}`);
    const provided = Buffer.from(signature);
    assert(expected.length === provided.length && timingSafeEqual(expected, provided), 401, "invalid_ci_signature", "The CI coverage report signature is invalid.");
    assert(body.deliveryId === delivery, 400, "ci_delivery_mismatch", "The signed CI payload must include its delivery identifier.");
    assert(body.metrics && typeof body.metrics === "object", 400, "invalid_coverage_metrics", "Provide signed coverage metrics.");
    const applied = setCoverageMetrics({
      candidateId: body.candidateId,
      commitSha: body.commitSha,
      metrics: body.metrics,
      signatureActor: body.workflow || "authenticated CI runner",
    });
    sendJson(request, response, 200, applied, { ETag: `"${applied.candidate.revision}"` });
    return true;
  }

  if (pathname === "/api/github/webhook" && method === "POST") {
    const rawBody = await rawBodyPromise(config.maxJsonBytes, "application/json");
    const webhook = await inspectWebhookDelivery(request, rawBody);
    const repoName = webhook.body.repository?.full_name;
    assert(
      repoName &&
        config.github.owner &&
        repoName.toLowerCase() === `${config.github.owner}/${config.github.repo}`.toLowerCase(),
      403,
      "webhook_repository_mismatch",
      "This GitHub event is not from the configured repository.",
    );
    const commit = webhook.body.after || webhook.body.check_run?.head_sha || webhook.body.pull_request?.head?.sha;
    const matching = commit
      ? listCandidates().find(
          (candidate) =>
            candidate.commit_sha &&
            candidate.commit_sha.toLowerCase() === commit.toLowerCase(),
        )
      : null;
    if (matching) {
      const event = appendEvent({
        candidateId: matching.id,
        action: `Received signed GitHub ${webhook.event} event`,
        detail: `Delivery ${webhook.deliveryId} · Commit ${commit}`,
        type: "github",
        payload: { event: webhook.event, deliveryId: webhook.deliveryId, commitSha: commit },
      });
      broadcast(event);
    }
    sendJson(request, response, 202, {
      accepted: true,
      matchingCandidate: matching?.id ?? null,
      event: webhook.event,
    });
    return true;
  }

  if (pathname === "/api/ai/status" && method === "GET") {
    sendJson(request, response, 200, { ai: aiStatus() });
    return true;
  }

  if (pathname === "/api/repo/status" && method === "GET") {
    requireRoles(session, ["admin", "qa_lead"]);
    sendJson(request, response, 200, await githubStatus());
    return true;
  }

  if (pathname === "/api/repo/commit-status" && method === "GET") {
    requireRoles(session, ["admin", "qa_lead", "developer"]);
    const sha = requireString(url.searchParams.get("sha"), "sha", 40);
    sendJson(request, response, 200, await checkCommitStatus(sha));
    return true;
  }

  if (pathname === "/api/repo/push" && method === "POST") {
    const body = await readJson(request, rawBodyPromise);
    requireRevision(request, session, body.candidateId);
    assertCsrf(request, session);
    const pullRequest = await pushArtifact({
      candidateId: body.candidateId,
      artifactId: requireString(body.artifactId, "artifactId", 64),
      request,
      actor,
    });
    sendJson(request, response, 201, pullRequest);
    return true;
  }

  if (pathname === "/api/repo/pull-request-comment" && method === "POST") {
    requireRoles(session, ["admin", "qa_lead"]);
    assertCsrf(request, session);
    const body = await readJson(request, rawBodyPromise);
    const comment = await commentOnPullRequest(body.number, body.body);
    sendJson(request, response, 201, { id: comment.id, htmlUrl: comment.html_url });
    return true;
  }

  if (pathname === "/api/audit/logs" && method === "GET") {
    const rawLimit = Number(url.searchParams.get("limit") || 50);
    assert(Number.isInteger(rawLimit) && rawLimit >= 1 && rawLimit <= 200, 400, "invalid_audit_limit", "Audit page size must be between 1 and 200.");
    const after = parseEventId(url.searchParams.get("after"));
    const type = url.searchParams.get("type") || undefined;
    const candidateId = url.searchParams.get("candidateId") || undefined;
    const logs = auditRecords({ candidateId, actor, after, limit: rawLimit, type });
    sendJson(request, response, 200, {
      events: logs,
      nextCursor: logs.length === rawLimit ? logs.at(-1).sequence : null,
    });
    return true;
  }

  if (pathname.startsWith("/api/")) {
    return false;
  }
  return false;
}

const server = createHttpServer({ maxHeaderSize: 16 * 1024 }, async (request, response) => {
  request.requestId = randomUUID();
  const startedAt = Date.now();
  let pathname = "/";
  try {
    const url = new URL(request.url || "/", "http://localhost");
    pathname = url.pathname;
    if (pathname.startsWith("/api/")) {
      const rawBodyPromise = makeBodyReader(request);
      const handled = await handleApi(request, response, url, rawBodyPromise);
      if (!handled && !response.headersSent) {
        sendJson(request, response, 404, {
          error: { code: "not_found", message: "The requested API resource was not found." },
          requestId: request.requestId,
        });
      }
    } else if (request.method === "GET" || request.method === "HEAD") {
      await staticFile(request, response, pathname);
    } else {
      sendJson(
        request,
        response,
        405,
        { error: { code: "method_not_allowed", message: "The requested method is not allowed." } },
        { Allow: "GET, HEAD" },
      );
    }
  } catch (error) {
    if (response.headersSent) {
      response.destroy(error);
      return;
    }
    const handled = error instanceof HttpError;
    const status = handled ? error.status : 500;
    const code = handled ? error.code : "internal_error";
    const message = handled ? error.message : "An unexpected service error occurred.";
    if (!handled || status >= 500) {
      console.error(`[${request.requestId}] ${request.method} ${pathname} failed:`, error);
    }
    const payload = {
      error: {
        code,
        message,
        ...(handled && error.details ? { details: error.details } : {}),
      },
      requestId: request.requestId,
    };
    sendJson(request, response, status, payload, {
      ...(status === 401
        ? { "Set-Cookie": clearSessionCookie(request) }
        : {}),
      ...(status === 405 ? { Allow: "GET, HEAD" } : {}),
    });
  } finally {
    if (response.headersSent && !response.writableEnded && !pathname.startsWith("/api/events")) {
      response.on("finish", () => {
        const durationMs = Date.now() - startedAt;
        if (durationMs > 5000) console.warn(`[${request.requestId}] ${request.method} ${pathname} took ${durationMs}ms`);
      });
    }
  }
});

server.on("clientError", (error, socket) => {
  console.warn("Rejected malformed HTTP client request.", error.message);
  if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
});

server.headersTimeout = 10_000;
server.requestTimeout = 45_000;
server.keepAliveTimeout = 5_000;

export function listen() {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.port, config.host, () => {
      server.removeListener("error", reject);
      resolve(server);
    });
  });
}

export async function close() {
  for (const client of sseClients) {
    client.response.end();
  }
  sseClients.clear();
  if (server.listening) {
    const closed = new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
    server.closeAllConnections();
    await closed;
  }
  closeDatabase();
}

export { server };

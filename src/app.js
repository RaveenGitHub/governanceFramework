import {
  STAGES,
  calculateProgress,
  evaluateStage,
  formatMetric,
} from "./governance.js";

const VIEW_KEY = "govern-ai-view-v1";
const $ = (selector, context = document) => context.querySelector(selector);
const app = $("#app");
const liveRegion = $("#live-region");
function loadViewPreferences() {
  try {
    const saved = JSON.parse(sessionStorage.getItem(VIEW_KEY) || "{}");
    return {
      activeView: ["overview", "stage", "documents", "artifacts", "timeline", "audit", "search", "access"].includes(saved.activeView)
        ? saved.activeView
        : "overview",
      activeStageId: STAGES.some((stage) => stage.id === saved.activeStageId)
        ? saved.activeStageId
        : STAGES[0].id,
      candidateId: typeof saved.candidateId === "string" ? saved.candidateId : null,
    };
  } catch {
    return { activeView: "overview", activeStageId: STAGES[0].id, candidateId: null };
  }
}

const state = {
  ...loadViewPreferences(),
  authenticated: false,
  setupRequired: false,
  loading: true,
  user: null,
  csrfToken: null,
  capabilities: null,
  candidate: null,
  regressionRisk: null,
  candidates: [],
  releaseConfidence: null,
  releaseAuthorized: false,
  documentFilter: "all",
  auditFilter: "all",
  currentModal: null,
  searchQuery: "",
  generatedDocuments: [],
  artifacts: [],
  auditEvents: [],
  projectMembers: [],
  projectUsers: [],
  projectAccessLoadedFor: null,
  stages: STAGES.map((definition, index) => ({
    id: definition.id,
    workStatus: index ? "not_started" : "in_progress",
    gateStatus: index ? "locked" : "not_run",
    checklist: Object.fromEntries(definition.checklist.map((_, itemIndex) => [itemIndex, false])),
    evidenceFiles: [],
    requiredEvidenceCount: definition.evidence.length,
    unverifiedEvidence: [],
    resolvedFindings: [],
    findings: [],
    metrics: {},
    confirmedSnapshotId: null,
    validation: null,
    approval: null,
    gateTimestamp: null,
  })),
  toast: null,
};

let eventStream = null;
let pendingRequestCount = 0;

function persist() {
  try {
    sessionStorage.setItem(
      VIEW_KEY,
      JSON.stringify({
        activeView: state.activeView,
        activeStageId: state.activeStageId,
        candidateId: state.candidateId,
      }),
    );
  } catch (error) {
    console.error("Could not save workspace navigation preferences.", error);
  }
}

async function apiRequest(route, { method = "GET", body, headers = {}, raw = false } = {}) {
  const requestHeaders = new Headers(headers);
  const mutating = !["GET", "HEAD"].includes(method.toUpperCase());
  if (mutating && !["/api/auth/setup", "/api/auth/login"].includes(route)) {
    if (state.csrfToken) requestHeaders.set("X-CSRF-Token", state.csrfToken);
    if (state.candidate?.revision !== undefined && !requestHeaders.has("If-Match")) {
      requestHeaders.set("If-Match", `"${state.candidate.revision}"`);
    }
  }
  let requestBody = body;
  if (body !== undefined && !raw && !(body instanceof FormData)) {
    requestHeaders.set("Content-Type", "application/json");
    requestBody = JSON.stringify(body);
  }
  pendingRequestCount += 1;
  render();
  try {
    const response = await fetch(route, {
      method,
      credentials: "same-origin",
      headers: requestHeaders,
      ...(requestBody !== undefined ? { body: requestBody } : {}),
    });
    const payload = response.status === 204
      ? null
      : response.headers.get("content-type")?.includes("application/json")
        ? await response.json()
        : await response.text();
    if (!response.ok) {
      const error = new Error(payload?.error?.message || `Request failed (${response.status}).`);
      error.status = response.status;
      error.code = payload?.error?.code;
      error.details = payload?.error?.details;
      if (response.status === 401 && !route.startsWith("/api/auth/")) {
        state.authenticated = false;
        state.user = null;
        state.csrfToken = null;
        eventStream?.close();
        render();
      }
      throw error;
    }
    return { data: payload, etag: response.headers.get("etag") };
  } finally {
    pendingRequestCount = Math.max(0, pendingRequestCount - 1);
    render();
  }
}

function applyWorkspace(workspace) {
  state.candidate = {
    ...workspace.candidate,
    projectRole:
      workspace.candidate.projectRole ??
      state.candidates.find((candidate) => candidate.id === workspace.candidate.id)?.project_role ??
      state.user?.role,
  };
  state.regressionRisk = workspace.regressionRisk;
  state.stages = workspace.stages.map((stage, index) => ({
    ...stage,
    id: stage.id,
    checklist: stage.checklist,
    evidenceFiles: stage.evidenceFiles,
    requiredEvidenceCount: stage.evidenceRequirements.length,
    unverifiedEvidence: stage.evidenceFiles.filter((item) => item.scanStatus !== "clean").map((item) => item.id),
    resolvedFindings: stage.findings.filter((finding) => finding.status === "resolved").map((finding) => finding.id),
    confirmedSnapshotId: stage.confirmedEvidenceRevision === stage.evidenceRevision
      ? `revision-${stage.evidenceRevision}`
      : null,
    validation: stage.validation
      ? { ...stage.validation, stale: stage.gateStatus === "stale" || stage.validation.outcome === "stale" }
      : null,
    approval: stage.approvals?.[0] ?? null,
    gateTimestamp: stage.gateTimestamp,
    workStatus: stage.workStatus,
    gateStatus: stage.gateStatus,
    metrics: stage.metrics,
    findings: stage.findings,
    definitionIndex: index,
  }));
  state.generatedDocuments = workspace.documents.map((item) => ({
    ...item,
    format: item.format === "markdown" ? "Markdown" : "HTML",
    createdAt: new Date(item.createdAt).toLocaleString(),
    status: state.stages.find((stage) => stage.id === item.stageId)?.gateStatus === "passed" ? "Approved" : "Draft",
  }));
  state.artifacts = workspace.artifacts.map((item) => ({
    ...item,
    type: "Code proposal",
    source: item.findingId || "Human-authored",
    updatedAt: new Date(item.updatedAt).toLocaleString(),
    files: item.files.map((file) => file.path),
  }));
  state.auditEvents = workspace.auditEvents.map((item) => ({
    ...item,
    time: new Date(item.timestamp).toLocaleString(),
  }));
  state.releaseConfidence = workspace.releaseConfidence;
  state.releaseAuthorized = Boolean(workspace.releaseAuthorization?.authorized);
}

async function loadCandidate() {
  if (!state.candidateId) {
    state.candidate = null;
    render();
    return;
  }
  const { data } = await apiRequest(`/api/candidates/${encodeURIComponent(state.candidateId)}/state`);
  applyWorkspace(data);
  const confidence = await apiRequest(`/api/release/confidence?candidateId=${encodeURIComponent(state.candidateId)}`);
  state.releaseConfidence = confidence.data.releaseConfidence;
  render();
}

async function refreshCandidates() {
  const { data } = await apiRequest("/api/candidates");
  state.candidates = data.candidates;
  const current = state.candidates.find((item) => item.id === state.candidateId);
  if (!current) state.candidateId = state.candidates[0]?.id ?? null;
  if (state.candidateId) await loadCandidate();
  else render();
}

async function loadProjectAccess() {
  if (state.user?.role !== "admin" || !state.candidate?.projectId) return;
  const projectId = state.candidate.projectId;
  const [membersResponse, usersResponse] = await Promise.all([
    apiRequest(`/api/projects/${encodeURIComponent(projectId)}/members`),
    apiRequest("/api/auth/roles"),
  ]);
  state.projectMembers = membersResponse.data.members;
  state.projectUsers = usersResponse.data.users.filter((user) => user.active);
  state.projectAccessLoadedFor = projectId;
  render();
}

async function saveProjectMember(userId, role) {
  const projectId = state.candidate?.projectId;
  if (!projectId) return;
  await apiRequest(`/api/projects/${encodeURIComponent(projectId)}/members/${encodeURIComponent(userId)}`, {
    method: "PUT",
    body: { role },
  });
  await loadProjectAccess();
  showToast("Project membership updated.");
}

async function removeProjectMember(userId) {
  const projectId = state.candidate?.projectId;
  if (!projectId) return;
  await apiRequest(`/api/projects/${encodeURIComponent(projectId)}/members/${encodeURIComponent(userId)}`, {
    method: "DELETE",
  });
  await loadProjectAccess();
  showToast("Project access removed.");
}

async function createProjectAccount(form) {
  const formData = new FormData(form);
  const projectId = state.candidate?.projectId;
  if (!projectId) return;
  await apiRequest("/api/auth/users", {
    method: "POST",
    body: {
      username: String(formData.get("username")),
      displayName: String(formData.get("displayName")),
      password: String(formData.get("password")),
      role: "developer",
      projectId,
      projectRole: String(formData.get("projectRole")),
    },
  });
  await loadProjectAccess();
  showToast("Account created and granted project access.");
}

function connectEvents() {
  eventStream?.close();
  if (!state.authenticated || !state.candidateId || !("EventSource" in window)) return;
  eventStream = new EventSource(`/api/events?candidateId=${encodeURIComponent(state.candidateId)}`);
  eventStream.addEventListener("governance", () => {
    if (!pendingRequestCount) void loadCandidate().catch(reportError);
  });
  eventStream.addEventListener("reset", () => void loadCandidate().catch(reportError));
  eventStream.addEventListener("error", () => {
    eventStream?.close();
    eventStream = null;
    void refreshCandidates().then(connectEvents).catch(reportError);
  });
}

function reportError(error) {
  if (error?.name === "AbortError") return;
  showToast(error instanceof Error ? error.message : "The request could not be completed.", "error");
}

async function initialize() {
  try {
    const { data } = await apiRequest("/api/session");
    state.authenticated = data.authenticated;
    state.setupRequired = data.setupRequired;
    state.user = data.user;
    state.csrfToken = data.csrfToken;
    state.capabilities = data.capabilities;
    if (state.authenticated) {
      const { data: candidatesPayload } = await apiRequest("/api/candidates");
      state.candidates = candidatesPayload.candidates;
      if (!state.candidates.some((item) => item.id === state.candidateId)) {
        state.candidateId = state.candidates[0]?.id ?? null;
      }
      await loadCandidate();
      if (state.activeView === "access" && state.user?.role === "admin") {
        await loadProjectAccess();
      }
      connectEvents();
    }
  } catch (error) {
    state.startupError = error.message;
  } finally {
    state.loading = false;
    render();
  }
}

function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, (character) => {
    const entities = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    };
    return entities[character];
  });
}

const iconPaths = {
  activity:
    '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  alert:
    '<path d="M12 9v4m0 4h.01"/><path d="M10.3 3.9 1.8 18.1A2 2 0 0 0 3.5 21h17a2 2 0 0 0 1.7-2.9L13.7 3.9a2 2 0 0 0-3.4 0Z"/>',
  arrowDown:
    '<path d="M12 5v14m-7-7 7 7 7-7"/>',
  arrowLeft:
    '<path d="m12 19-7-7 7-7"/><path d="M19 12H5"/>',
  arrowRight:
    '<path d="M5 12h14m-7-7 7 7-7 7"/>',
  arrows:
    '<path d="M7 7h14l-4-4"/><path d="M17 17H3l4 4"/>',
  check:
    '<path d="m5 12 4 4L19 6"/>',
  chevron:
    '<path d="m9 18 6-6-6-6"/>',
  clock:
    '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  close:
    '<path d="m18 6-12 12M6 6l12 12"/>',
  code:
    '<path d="m16 18 6-6-6-6M8 6l-6 6 6 6m6-16-4 20"/>',
  document:
    '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6m-4 5H8m8 4H8"/>',
  download:
    '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4m4-5 5 5 5-5m-5 5V3"/>',
  external:
    '<path d="M15 3h6v6m-11 5L21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
  file:
    '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>',
  filter:
    '<path d="M4 7h16M7 12h10m-7 5h4"/>',
  grid:
    '<rect x="3" y="3" width="8" height="8" rx="2"/><rect x="13" y="3" width="8" height="8" rx="2"/><rect x="3" y="13" width="8" height="8" rx="2"/><rect x="13" y="13" width="8" height="8" rx="2"/>',
  help:
    '<circle cx="12" cy="12" r="10"/><path d="M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3m.1 4h.01"/>',
  lock:
    '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 1 1 8 0v4"/>',
  menu:
    '<path d="M4 6h16M4 12h16M4 18h16"/>',
  more:
    '<circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/>',
  notification:
    '<path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9m-8 13h4"/>',
  plus:
    '<path d="M12 5v14m-7-7h14"/>',
  search:
    '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>',
  shield:
    '<path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11"/><path d="m9 12 2 2 4-4"/>',
  sparkles:
    '<path d="m12 3-1.9 5.8L4 11l6.1 2.2L12 19l2-5.8L20 11l-6-2.2L12 3Zm7 12-.9 2.1L16 18l2.1.9L19 21l.9-2.1L22 18l-2.1-.9L19 15Z"/>',
  upload:
    '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4m4-5 5-5 5 5m-5-5v12"/>',
  users:
    '<path d="M16 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2m16 0v-2a4 4 0 0 0-3-3.9M14 3.1a4 4 0 0 1 0 7.8"/><circle cx="10" cy="7" r="4"/>',
  logout:
    '<path d="M10 17l5-5-5-5m5 5H3"/><path d="M12 3h6a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-6"/>',
};

function icon(name, size = 18, extraClass = "") {
  return `<svg class="icon ${extraClass}" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${iconPaths[name] ?? iconPaths.grid}</svg>`;
}

function stageDefinition(id) {
  return STAGES.find((stage) => stage.id === id);
}

function stageState(id) {
  return state.stages.find((stage) => stage.id === id);
}

function currentStageIndex() {
  return state.stages.findIndex((stage) => stage.id === state.activeStageId);
}

function isUnlocked(index) {
  return index === 0 || state.stages[index - 1]?.gateStatus === "passed";
}

function progressPercent(stage, stageInfo) {
  if (stage.gateStatus === "passed") return 100;
  const checks = stageInfo.checklist.length;
  const completed = Object.values(stage.checklist).filter(Boolean).length;
  return checks ? Math.round((completed / checks) * 100) : 0;
}

function showToast(message, type = "success", rerender = true) {
  state.toast = { message, type };
  liveRegion.textContent = message;
  if (rerender) render();
  window.clearTimeout(showToast.timeout);
  showToast.timeout = window.setTimeout(() => {
    if (state.toast?.message === message) {
      state.toast = null;
      render();
    }
  }, 3400);
}

function setView(view, stageId = state.activeStageId) {
  state.activeView = view;
  if (STAGES.some((stage) => stage.id === stageId)) state.activeStageId = stageId;
  state.currentModal = null;
  persist();
  render();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function renderStageNavigation() {
  return STAGES.map((definition, index) => {
    const workflow = stageState(definition.id);
    const active = state.activeView === "stage" && state.activeStageId === definition.id;
    const completed = workflow.gateStatus === "passed";
    const locked = !isUnlocked(index);
    const stateLabel = completed ? "Passed" : locked ? "Locked" : "In progress";
    return `
      <button class="stage-nav ${active ? "is-active" : ""} ${completed ? "is-complete" : ""}"
        data-action="open-stage" data-stage="${definition.id}"
        ${locked ? `aria-label="${escapeHTML(definition.name)}, locked until previous stage passes"` : `aria-label="Open ${escapeHTML(definition.name)}"`}>
        <span class="stage-nav-marker ${completed ? "is-complete" : locked ? "is-locked" : active ? "is-current" : ""}">
          ${completed ? icon("check", 13) : locked ? icon("lock", 12) : `<span>${index + 1}</span>`}
        </span>
        <span class="stage-nav-copy">
          <span class="stage-nav-name">${escapeHTML(definition.shortName)}</span>
          <span class="stage-nav-state">${stateLabel}</span>
        </span>
        ${workflow.gateStatus === "failed" ? '<span class="nav-alert-dot"></span>' : ""}
      </button>
    `;
  }).join("");
}

function renderSidebar() {
  const candidateLabel = state.candidate?.projectName || "No release candidate";
  return `
    <aside class="sidebar" id="sidebar" aria-label="Main navigation">
      <a href="#overview" class="brand" data-action="navigate" data-view="overview">
        <span class="brand-mark">${icon("shield", 21)}</span>
        <span class="brand-name">govern<span>ai</span></span>
        <span class="brand-plan">ENTERPRISE</span>
      </a>
      <div class="sidebar-project-label">WORKSPACE</div>
      <label class="workspace-switcher workspace-switcher-select">
        <span class="workspace-avatar">${escapeHTML(candidateLabel.slice(0, 1).toUpperCase())}</span>
        <span class="workspace-name">${escapeHTML(candidateLabel)}<small>${escapeHTML(state.candidate?.releaseName || "Select a release")}</small></span>
        <select id="candidate-select" aria-label="Select release candidate">
          ${state.candidates.map((candidate) => `<option value="${escapeHTML(candidate.id)}" ${candidate.id === state.candidateId ? "selected" : ""}>${escapeHTML(candidate.release_name)} · ${escapeHTML(candidate.project_name)}</option>`).join("")}
        </select>
      </label>
      <div class="nav-section-label">WORKSPACE</div>
      <button class="primary-nav ${state.activeView === "overview" ? "is-active" : ""}" data-action="navigate" data-view="overview">
        ${icon("grid", 17)}<span>Overview</span>
      </button>
      <div class="nav-section-heading"><span>GOVERNANCE FLOW</span><span>06</span></div>
      <nav class="stage-nav-list" aria-label="Governance stages">${renderStageNavigation()}</nav>
      <div class="nav-divider"></div>
      <div class="nav-section-label">RESOURCES</div>
      <button class="primary-nav ${state.activeView === "documents" ? "is-active" : ""}" data-action="navigate" data-view="documents">
        ${icon("document", 17)}<span>Documents</span><span class="nav-count">${state.generatedDocuments.length}</span>
      </button>
      <button class="primary-nav ${state.activeView === "artifacts" ? "is-active" : ""}" data-action="navigate" data-view="artifacts">
        ${icon("code", 17)}<span>Code artifacts</span>
      </button>
      <button class="primary-nav ${state.activeView === "timeline" ? "is-active" : ""}" data-action="navigate" data-view="timeline">
        ${icon("clock", 17)}<span>Timeline</span>
      </button>
      <button class="primary-nav ${state.activeView === "audit" ? "is-active" : ""}" data-action="navigate" data-view="audit">
        ${icon("activity", 17)}<span>Activity &amp; audit</span>
      </button>
      ${state.user?.role === "admin" ? `<button class="primary-nav ${state.activeView === "access" ? "is-active" : ""}" data-action="manage-project-access">
        ${icon("users", 17)}<span>Project access</span>
      </button>` : ""}
      <div class="sidebar-bottom">
        <div class="sidebar-policy">${icon("shield", 15)}<span>Policy <strong>v${escapeHTML(state.candidate?.policyVersion || "1.0")}</strong></span><span class="policy-status"></span></div>
        <div class="demo-label">${icon("activity", 12)} ${escapeHTML(state.capabilities?.ai?.status || "AI not configured")} · ${escapeHTML(state.capabilities?.malwareScanner?.status || "scanner status unavailable")}</div>
        <div class="user-switcher">
          <span class="user-avatar">${escapeHTML((state.user?.displayName || "U").split(/\s+/).map((part) => part[0]).join("").slice(0, 2).toUpperCase())}</span>
          <span class="user-copy"><strong>${escapeHTML(state.user?.displayName || "Signed in")}</strong><small>${escapeHTML(state.candidate?.projectRole || state.user?.role || "")} · project role</small></span>
          <button class="user-copy-action" data-action="logout" aria-label="Sign out">${icon("logout", 16)}</button>
        </div>
      </div>
    </aside>`;
}

function renderTopbar() {
  const projectName = state.candidate?.projectName || "Governance workspace";
  const initials = (state.user?.displayName || "U").split(/\s+/).map((part) => part[0]).join("").slice(0, 2).toUpperCase();
  return `
    <header class="topbar">
      <button class="icon-button mobile-menu" aria-label="Toggle navigation" data-action="toggle-sidebar">${icon("menu", 19)}</button>
      <div class="breadcrumb"><span>${escapeHTML(projectName)}</span>${icon("chevron", 14)}<strong>${escapeHTML(pageTitle())}</strong></div>
      <div class="topbar-actions">
        <form class="search-form" id="search-form" role="search" data-action="focus-search">
          ${icon("search", 16)}
          <input aria-label="Search governance workspace" id="global-search" placeholder="Search anything..." value="${escapeHTML(state.searchQuery)}" />
          <kbd>⌘ K</kbd>
        </form>
        <span class="topbar-divider"></span>
        <button class="icon-button notification-button" aria-label="Open notifications" data-action="notifications">
          ${icon("notification", 19)}<span class="notification-dot"></span>
        </button>
        <span class="topbar-avatar" title="${escapeHTML(state.user?.displayName || "")}">${escapeHTML(initials)}</span>
      </div>
    </header>`;
}

function pageTitle() {
  if (state.activeView === "overview") return "Overview";
  if (state.activeView === "stage") return stageDefinition(state.activeStageId).shortName;
  return {
    documents: "Documents",
    artifacts: "Code artifacts",
    timeline: "Timeline",
    audit: "Activity & audit",
    search: "Search results",
    access: "Project access",
  }[state.activeView] ?? "Overview";
}

function renderMetricCard({ label, value, suffix = "", detail, iconName, tone = "blue", progress }) {
  const available = value !== null && value !== undefined;
  return `
    <article class="metric-card">
      <div class="metric-card-top"><span>${escapeHTML(label)}</span><span class="metric-icon metric-icon-${tone}">${icon(iconName, 16)}</span></div>
      <div class="metric-value">${available ? escapeHTML(value) : "—"}${available && suffix ? `<span>${escapeHTML(suffix)}</span>` : ""}</div>
      ${progress !== undefined && available ? `<div class="metric-progress"><span style="width:${Math.max(0, Math.min(100, progress))}%"></span></div>` : ""}
      <div class="metric-detail">${detail}</div>
    </article>`;
}

function renderConfidenceCard() {
  const progress = calculateProgress(state.stages);
  const coverage = stageState("tests").metrics.lineCoverage;
  const confidence = state.releaseConfidence?.score;
  const passed = state.stages.filter((stage) => stage.gateStatus === "passed").length;
  const status = state.releaseConfidence?.status || "unavailable";
  return `
    <section class="overview-hero" aria-label="Release confidence">
      <div class="hero-copy">
        <div class="eyebrow"><span class="eyebrow-dot"></span> RELEASE CONFIDENCE</div>
        <h2>Ship with <span>confidence.</span></h2>
        <p>Evidence-backed governance for ${escapeHTML(state.candidate?.releaseName || "this release candidate")}.</p>
        <div class="hero-status-row">
          <span class="status-chip ${status === "final" ? "status-positive" : "status-warning"}">${icon("activity", 14)} ${escapeHTML(status.toUpperCase())} ASSESSMENT</span>
          <span class="hero-updated">${icon("clock", 14)} Server-calculated · Policy v${escapeHTML(state.candidate?.policyVersion || "1.0")}</span>
        </div>
      </div>
      <div class="confidence-ring-wrap">
        <div class="confidence-ring" style="--score:${confidence ?? 0}" role="img" aria-label="${confidence === null || confidence === undefined ? "Release confidence not available" : `Release confidence ${confidence} out of 100`}">
          <div class="confidence-ring-inner"><span>${confidence ?? "—"}</span><small>${confidence === null || confidence === undefined ? "not scored" : "/ 100"}</small></div>
        </div>
        <div class="confidence-ring-caption">Release confidence</div>
        <span class="confidence-label">${escapeHTML(status.toUpperCase())} · ${state.releaseConfidence?.releaseEligible ? "GATES PASSED" : "EVIDENCE INCOMPLETE"}</span>
      </div>
      <div class="hero-progress">
        <div class="hero-progress-header"><span>Release progress</span><strong>${progress}%</strong></div>
        <div class="progress-track"><span style="width:${progress}%"></span></div>
        <div class="progress-foot"><span>${passed} of 6 gates complete</span><span>Target: ${escapeHTML(state.candidate?.targetDate || "Not set")}</span></div>
        <button class="hero-link" data-action="navigate" data-view="timeline">View delivery timeline ${icon("arrowRight", 15)}</button>
      </div>
      <div class="hero-orb hero-orb-one"></div><div class="hero-orb hero-orb-two"></div>
      <span class="sr-only">${coverage ?? "Not available"}% line coverage. ${passed} of 6 gates passed.</span>
    </section>`;
}

function renderOverviewStages() {
  return `
    <section class="panel stage-overview-panel">
      <div class="panel-heading">
        <div><div class="section-kicker">GOVERNANCE WORKFLOW</div><h2>Release journey</h2></div>
        <button class="subtle-button" data-action="navigate" data-view="timeline">Full timeline ${icon("arrowRight", 15)}</button>
      </div>
      <div class="overview-stage-list">
        ${STAGES.map((definition, index) => {
          const workflow = stageState(definition.id);
          const done = workflow.gateStatus === "passed";
          const locked = !isUnlocked(index);
          const active = !done && !locked;
          const progress = progressPercent(workflow, definition);
          const status = done ? "Gate passed" : locked ? "Awaiting prerequisites" : workflow.gateStatus === "failed" ? "Action required" : "In progress";
          return `
            <button class="overview-stage-row ${active ? "row-current" : ""} ${locked ? "row-locked" : ""}"
              data-action="open-stage" data-stage="${definition.id}">
              <span class="overview-stage-icon ${done ? "stage-icon-done" : active ? "stage-icon-active" : "stage-icon-locked"}">
                ${done ? icon("check", 15) : locked ? icon("lock", 13) : `<span>${String(index + 1).padStart(2, "0")}</span>`}
              </span>
              <span class="overview-stage-name"><strong>${escapeHTML(definition.name)}</strong><small>${status}</small></span>
              <span class="overview-stage-progress">
                <span class="mini-progress"><span style="width:${progress}%"></span></span>
                <small>${progress}%</small>
              </span>
              <span class="overview-stage-action">${done ? '<span class="passed-badge">Passed</span>' : active ? '<span class="current-badge">Continue</span>' : icon("chevron", 16, "muted-icon")}</span>
            </button>`;
        }).join("")}
      </div>
      <div class="stage-legend"><span><i class="legend-dot legend-done"></i>Passed</span><span><i class="legend-dot legend-active"></i>In progress</span><span><i class="legend-dot legend-locked"></i>Locked</span></div>
    </section>`;
}

function renderRiskHeatmap() {
  const findings = state.stages.flatMap((stage) => stage.findings);
  const counts = Object.fromEntries(["critical", "high", "medium", "low"].map((severity) => [
    severity,
    findings.filter((finding) => finding.severity === severity && finding.status !== "resolved").length,
  ]));
  const cells = [
    ["critical", "heat-high"],
    ["high", "heat-high"],
    ["medium", "heat-medium"],
    ["low", "heat-low"],
  ];
  return `
    <section class="panel risk-panel">
      <div class="panel-heading compact-heading"><div><div class="section-kicker">RISK LANDSCAPE</div><h2>Risk heatmap</h2></div><button class="icon-button small-icon-button" aria-label="View risk findings" data-action="navigate" data-view="search">${icon("external", 15)}</button></div>
      <div class="risk-severity-grid">${cells.map(([severity, tone]) => `<div class="risk-severity-cell ${tone}"><span>${escapeHTML(severity)}</span><strong>${counts[severity]}</strong></div>`).join("")}</div>
      <div class="heatmap-legend"><span>Open AI findings only · advisory, not a probability estimate.</span><span class="heatmap-risk-count">${findings.length} total findings</span></div>
    </section>`;
}

function renderActionPanel() {
  const nextIndex = state.stages.findIndex((stage) => stage.gateStatus !== "passed" && stage.gateStatus !== "locked");
  const index = nextIndex < 0 ? state.stages.findIndex((stage) => stage.gateStatus !== "passed") : nextIndex;
  const definition = stageDefinition(STAGES[Math.max(index, 0)].id);
  const workflow = stageState(definition.id);
  const openBlockers = workflow.findings.filter(
    (finding) => ["critical", "high"].includes(finding.severity) && finding.status !== "resolved",
  ).length;
  const failedChecks = workflow.validation?.checks?.filter((check) => check.status !== "passed") ?? [];
  const summary = failedChecks[0]?.label || (workflow.findings.length
    ? `${workflow.findings.length} AI finding(s) need human review.`
    : "Attach current source evidence and complete the review checklist.");
  return `
    <section class="next-action-card">
      <div class="action-card-top"><span class="action-pulse"></span> NEXT GOVERNANCE ACTION</div>
      <div class="action-stage-label">${icon("activity", 15)} ${escapeHTML(definition.name.toUpperCase())}</div>
      <h3>${workflow.gateStatus === "locked" ? "Complete the preceding gate" : "Continue the stage review"}</h3>
      <p>${escapeHTML(summary)}</p>
      <div class="action-meta"><span>${icon("users", 15)} ${escapeHTML(state.user?.displayName || "Workspace reviewer")} · ${escapeHTML(state.user?.role || "")}</span><span class="risk-pill">${openBlockers} blocking ${openBlockers === 1 ? "finding" : "findings"}</span></div>
      <div class="action-buttons"><button class="button button-primary" data-action="open-stage" data-stage="${definition.id}">Open stage ${icon("arrowRight", 16)}</button><button class="text-icon-button" data-action="open-stage" data-stage="${definition.id}" data-tab="evidence">${icon("document", 15)} Evidence</button></div>
    </section>`;
}

function renderDeliveryPanel() {
  const passed = state.stages.filter((stage) => stage.gateStatus === "passed").length;
  const target = state.candidate?.targetDate;
  return `
    <section class="panel delivery-panel">
      <div class="panel-heading compact-heading"><div><div class="section-kicker">DELIVERY TRACKING</div><h2>Release timeline</h2></div><span class="forecast-chip">${icon("activity", 13)} ${passed === 6 ? "Ready for authorization" : "In progress"}</span></div>
      <div class="delivery-dates"><div><span>TARGET RELEASE</span><strong>${target ? escapeHTML(new Date(`${target}T00:00:00Z`).toLocaleDateString(undefined, { day: "2-digit" })) : "—"} <small>${target ? escapeHTML(new Date(`${target}T00:00:00Z`).toLocaleDateString(undefined, { month: "short" }).toUpperCase()) : "NOT SET"}</small></strong></div><div class="date-divider"></div><div><span>GATES PASSED</span><strong class="forecast-date">${passed} <small>/ 06</small></strong></div></div>
      <div class="delivery-bar"><span style="width:${Math.round((passed / STAGES.length) * 100)}%"></span></div>
      <div class="delivery-caption"><span>${passed} of 6 release gates passed</span><span>${state.auditEvents.length} audit events</span></div>
      <button class="delivery-link" data-action="navigate" data-view="timeline">See delivery milestones ${icon("arrowRight", 15)}</button>
    </section>`;
}

function renderOverview() {
  const progress = calculateProgress(state.stages);
  const coverage = stageState("tests").metrics.lineCoverage;
  const openFindings = state.stages.flatMap((stage) => stage.findings)
    .filter((finding) => ["critical", "high"].includes(finding.severity) && finding.status !== "resolved").length;
  const candidateName = state.candidate?.releaseName || "Release candidate";
  return `
    <main class="main-content">
      <div class="page-header overview-header">
        <div><div class="page-eyebrow">${new Date().toLocaleDateString(undefined, { dateStyle: "full" })} <span class="header-dot"></span> ${escapeHTML(candidateName.toUpperCase())}</div><h1>Welcome, ${escapeHTML(state.user?.displayName || "reviewer")} <span class="wave">✳</span></h1><p>Live governance status for ${escapeHTML(state.candidate?.projectName || "your project")}.</p></div>
        <div class="page-header-actions"><span class="candidate-chip">${icon("code", 15)} <span>${escapeHTML(state.candidate?.commitSha ? state.candidate.commitSha.slice(0, 8) : "Commit not pinned")}</span> <span class="candidate-divider"></span> ${escapeHTML(candidateName)}</span><button class="button button-primary button-small" data-action="open-stage" data-stage="${escapeHTML(state.stages.find((stage) => stage.gateStatus !== "passed" && stage.gateStatus !== "locked")?.id || state.stages[0].id)}">Continue review ${icon("arrowRight", 15)}</button></div>
      </div>
      <div class="metric-grid">
        ${renderMetricCard({ label: "Project progress", value: progress, suffix: "%", iconName: "activity", tone: "blue", progress, detail: '<span class="detail-quiet">Across 6 governance stages</span>' })}
        ${renderMetricCard({ label: "Test coverage", value: coverage, suffix: "%", iconName: "grid", tone: "violet", progress: coverage, detail: '<span class="detail-quiet">HMAC-authenticated CI evidence</span>' })}
        ${renderMetricCard({ label: "Open high / critical findings", value: openFindings, iconName: "shield", tone: "amber", detail: '<span class="detail-quiet">AI findings require human review</span>' })}
        ${renderMetricCard({ label: "Defect escape rate", value: null, suffix: "%", iconName: "activity", tone: "green", detail: '<span class="detail-quiet">No production defect feed configured</span>' })}
      </div>
      ${renderConfidenceCard()}
      <div class="overview-grid">
        <div class="overview-main-column">${renderOverviewStages()}${renderRiskHeatmap()}</div>
        <div class="overview-side-column">${renderActionPanel()}${renderDeliveryPanel()}${renderProductionScore()}</div>
      </div>
      <div class="overview-footer-note">${icon("shield", 14)} Server-backed policy evaluation · scores are unavailable when source evidence is missing. <button data-action="navigate" data-view="audit">View audit history</button></div>
    </main>`;
}

function renderProductionScore() {
  const readiness = stageState("production").completion;
  const risk = state.regressionRisk;
  const blockers = state.releaseConfidence?.blockingFindingCount;
  return `
    <section class="panel readiness-panel">
      <div class="panel-heading compact-heading"><div><div class="section-kicker">RELEASE HEALTH</div><h2>Readiness snapshot</h2></div>${icon("shield", 17, "muted-icon")}</div>
      ${[
        ["Regression risk", risk === null || risk === undefined ? "Not available" : `${risk} / 100`, "regression", "amber"],
        ["Production readiness", `${readiness} / 100`, "readiness", "blue"],
        ["Open blocking findings", blockers === null || blockers === undefined ? "Not available" : `${blockers}`, "security", "green"],
      ].map(([label, value, id, tone]) => {
        const numeric = Number.parseInt(value, 10);
        const percentage = id === "regression" ? 100 - numeric : numeric;
        return `<div class="readiness-row"><span>${label}</span><strong>${value}</strong>${Number.isFinite(numeric) ? `<div class="readiness-bar ${tone}"><span style="width:${percentage}%"></span></div>` : ""}</div>`;
      }).join("")}
      <div class="readiness-disclaimer">Assessment only — release remains blocked until required gates pass.</div>
    </section>`;
}

function statusBadge(status) {
  const labels = {
    passed: "Passed",
    failed: "Failed",
    locked: "Locked",
    not_run: "Not run",
    running: "Running",
    awaiting_approval: "Awaiting approval",
    stale: "Evidence stale",
  };
  return `<span class="gate-badge gate-${escapeHTML(status)}"><i></i>${escapeHTML(labels[status] ?? status)}</span>`;
}

function scorePanel(workflow) {
  const cleanEvidence = workflow.evidenceFiles.filter((item) => item.scanStatus === "clean").length;
  const required = workflow.requiredEvidenceCount;
  const evidenceCount = Math.min(cleanEvidence, required);
  const evidenceCompleteness = required
    ? Math.round((evidenceCount / required) * 100)
    : 0;
  const coverage = workflow.id === "tests"
    ? workflow.metrics.lineCoverage
    : required ? evidenceCompleteness : null;
  const risk = state.regressionRisk;
  const confidence = state.releaseConfidence?.score;
  return `
    <aside class="assessment-card">
      <div class="assessment-heading"><span>${icon("sparkles", 17)} QUALITY ASSESSMENT</span><span class="assessment-live">${state.capabilities?.ai?.configured ? "AI READY" : "POLICY ONLY"}</span></div>
      ${renderScoreRow("Risk score", risk, "/ 100", "risk", "Evidence-derived index; lower is better")}
      ${renderScoreRow("Coverage score", coverage, "%", "coverage", workflow.id === "tests" ? "Line coverage from signed CI evidence" : "Clean evidence items / required evidence items")}
      ${renderScoreRow("Security score", null, "/ 100", "security", "No normalized security score is configured")}
      ${renderScoreRow("Release confidence", confidence, "/ 100", "confidence", "Passed-gate index; not a probability")}
      <div class="assessment-divider"></div>
      <div class="assessment-evidence"><span>Evidence completeness</span><strong>${evidenceCount}<span> / ${required}</span></strong></div>
      <div class="evidence-meter"><span style="width:${evidenceCompleteness}%"></span></div>
      <div class="assessment-updated">${icon("clock", 13)} Calculated from persisted server state</div>
      <div class="assessment-policy">${icon("shield", 14)} Policy <strong>${escapeHTML(state.candidate?.policyVersion || "1.0")}</strong><span class="policy-verified">ACTIVE</span></div>
      <button class="assessment-method-link" data-action="explain-score">How are scores calculated? ${icon("arrowRight", 13)}</button>
    </aside>`;
}

function renderScoreRow(label, value, unit, id, help) {
  const displayValue = value === null || value === undefined ? "—" : value;
  const progressValue = Number.isFinite(value) ? value : 0;
  const progress = id === "risk" ? 100 - progressValue : progressValue;
  return `
    <div class="score-row">
      <div class="score-row-title"><span>${escapeHTML(label)}</span><button class="info-button" aria-label="${escapeHTML(help)}" title="${escapeHTML(help)}">i</button></div>
      <div class="score-row-value">${escapeHTML(displayValue)}<span>${value === null || value === undefined ? "" : unit}</span></div>
      <div class="score-bar"><span class="score-bar-${id}" style="width:${Math.max(0, Math.min(100, progress))}%"></span></div>
      <div class="score-row-help">${escapeHTML(help)}</div>
    </div>`;
}

function renderFindingCard(finding, stageWorkflow, interactive) {
  const resolved = finding.status === "resolved";
  return `
    <article class="finding-card finding-${escapeHTML(finding.severity)} ${resolved ? "finding-resolved" : ""}">
      <div class="finding-severity"><span class="severity-icon">${resolved ? icon("check", 13) : icon(finding.severity === "critical" || finding.severity === "high" ? "alert" : "activity", 13)}</span><span>${escapeHTML(finding.severity)}${resolved ? " · Resolved" : ""}</span><span class="finding-id">${escapeHTML(finding.id)}</span></div>
      <h3>${escapeHTML(finding.title)}</h3>
      <p>${escapeHTML(finding.detail)}</p>
      <div class="finding-footer"><span>${icon("document", 13)} ${escapeHTML(finding.source || "No citation source")}</span>${!resolved && interactive && ["critical", "high"].includes(finding.severity) ? `<button data-action="resolve-finding" data-finding="${escapeHTML(finding.id)}" data-stage="${stageWorkflow.id}">Resolve with evidence ${icon("check", 13)}</button>` : !resolved ? '<span class="resolved-label">Advisory · human review</span>' : '<span class="resolved-label">Disposition recorded</span>'}</div>
    </article>`;
}

function renderEvidenceSection(definition, workflow, interactive) {
  const scanStatusLabel = (status) => ({
    clean: "Malware scan passed",
    pending: "Scan pending",
    unscanned: "Quarantined · scanner unavailable",
    scan_error: "Quarantined · scan error",
    infected: "Malware detected · quarantined",
  }[status] || "Unknown scan status");
  return `
    <section class="panel stage-panel evidence-panel">
      <div class="panel-heading">
        <div><div class="section-kicker">SOURCE OF TRUTH</div><h2>Evidence &amp; documents</h2><p class="panel-subtitle">Evidence linked to ${escapeHTML(definition.shortName.toLowerCase())}.</p></div>
        ${interactive ? `<button class="button button-outline button-small" data-action="choose-file">${icon("upload", 15)} Upload evidence</button>` : ""}
      </div>
      ${interactive ? `<label for="evidence-upload" class="drop-zone">
        <span class="drop-icon">${icon("upload", 19)}</span><span class="drop-copy"><strong>Drop files here or <span>browse</span></strong><small>PDF, Markdown, HTML, PNG, SVG, JSON <span>·</span> Up to 25 MB per file</small></span><span class="drop-secure">${icon("shield", 14)} Private · malware-scanned</span>
      </label><input type="file" id="evidence-upload" class="visually-hidden" accept=".pdf,.md,.markdown,.html,.htm,.png,.jpg,.jpeg,.svg,.json,.txt,.csv" multiple />` : ""}
      <div class="evidence-list">${workflow.evidenceFiles.map((file) => `
        <div class="evidence-row">
          <span class="file-type-icon ${fileTypeClass(file.name)}">${icon("file", 17)}</span>
          <span class="evidence-file-name"><strong>${escapeHTML(file.name)}</strong><small>${escapeHTML(file.sizeBytes.toLocaleString())} bytes · SHA-256 ${escapeHTML(file.sha256.slice(0, 12))}…</small></span>
          <span class="evidence-verified ${file.scanStatus === "clean" ? "" : "evidence-pending"}">${file.scanStatus === "clean" ? icon("check", 12) : icon("lock", 12)} ${escapeHTML(scanStatusLabel(file.scanStatus))}</span>
          ${interactive ? `<button class="icon-button small-icon-button" aria-label="Download ${escapeHTML(file.name)}" data-action="preview-evidence" data-evidence="${escapeHTML(file.id)}" ${file.scanStatus !== "clean" ? "disabled" : ""}>${icon("download", 15)}</button><button class="text-icon-button" data-action="remove-evidence" data-evidence="${escapeHTML(file.id)}">Remove</button>` : ""}
        </div>`).join("")}</div>
      ${interactive ? `<p class="upload-note">${icon("shield", 13)} Uploaded evidence is stored outside the public web root. ${escapeHTML(state.capabilities?.malwareScanner?.configured ? "Malware scanning is configured." : "The malware scanner is not configured; files remain quarantined and cannot satisfy release gates.")}</p>` : ""}
    </section>`;
}

function fileTypeClass(filename) {
  const extension = filename.split(".").pop().toLowerCase();
  return ["png", "jpg", "jpeg", "svg"].includes(extension) ? "file-image" : extension === "pdf" ? "file-pdf" : "file-doc";
}

function renderChecklist(definition, workflow, interactive) {
  return `
    <section class="panel stage-panel checklist-panel">
      <div class="panel-heading"><div><div class="section-kicker">REVIEW WORKSPACE</div><h2>Review checklist</h2><p class="panel-subtitle">Confirm each control using linked, current evidence.</p></div><span class="checklist-count">${Object.values(workflow.checklist).filter(Boolean).length} / ${definition.checklist.length} complete</span></div>
      <div class="checklist-items">${definition.checklist.map((item, index) => `
        <label class="checklist-item ${workflow.checklist[index] ? "is-checked" : ""} ${!interactive ? "is-disabled" : ""}">
          <input type="checkbox" data-action="checklist" data-index="${index}" data-stage="${definition.id}" ${workflow.checklist[index] ? "checked" : ""} ${interactive ? "" : "disabled"} />
          <span class="custom-checkbox">${workflow.checklist[index] ? icon("check", 13) : ""}</span>
          <span class="checklist-text">${escapeHTML(item)}<small>Required control · Owner: ${escapeHTML(state.user?.displayName || "Unassigned")}</small></span>
          <span class="checklist-evidence-link">${icon("document", 14)} Evidence</span>
        </label>`).join("")}</div>
    </section>`;
}

function renderValidation(definition, workflow, interactive) {
  const latest = workflow.validation;
  const preview = latest?.checks?.length ? latest.checks : null;
  return `
    <section class="panel stage-panel validation-panel">
      <div class="panel-heading"><div><div class="section-kicker">POLICY ENGINE · V${escapeHTML(state.candidate?.policyVersion || "1.0")}</div><h2>Validation results</h2><p class="panel-subtitle">Deterministic checks for this release candidate.</p></div>${latest ? statusBadge(latest.stale ? "stale" : latest.outcome) : statusBadge(workflow.gateStatus === "locked" ? "locked" : "not_run")}</div>
      ${preview ? `<div class="validation-checks">${preview.map((check) => `
        <div class="validation-check"><span class="validation-check-status ${check.status}">${check.status === "passed" ? icon("check", 13) : icon("alert", 13)}</span><span class="validation-check-name"><strong>${escapeHTML(check.label)}</strong><small>Expected ${escapeHTML(check.expected)} · Actual ${escapeHTML(check.actual ?? "Not available")}</small></span><span class="check-result check-${check.status}">${check.status === "passed" ? "Pass" : "Fail"}</span></div>`).join("")}</div>` :
        `<div class="validation-empty"><span class="validation-empty-icon">${icon("shield", 20)}</span><strong>No validation run yet</strong><span>Confirm your review to run deterministic checks against policy v${escapeHTML(state.candidate?.policyVersion || "1.0")}.</span></div>`}
      ${latest?.outcome === "passed" && !latest.stale && workflow.gateStatus !== "passed" && interactive ? `<div class="approval-callout">${icon("shield", 17)}<span><strong>Validation passed.</strong><small>A reviewer must approve this gate before work can advance.</small></span><span class="approval-callout-badge">ACTION REQUIRED</span></div>` : ""}
      ${workflow.gateStatus === "passed" ? `<div class="passed-validation-note">${icon("check", 14)} Gate approved${workflow.gateTimestamp ? ` · ${escapeHTML(workflow.gateTimestamp)}` : ""} · Evidence snapshot is bound to this decision.</div>` : ""}
    </section>`;
}

function renderFindings(definition, workflow, interactive) {
  return `
    <section class="panel stage-panel findings-panel">
      <div class="panel-heading"><div><div class="section-kicker">EVIDENCE-CITED ANALYSIS</div><h2>Findings &amp; recommendations</h2><p class="panel-subtitle">${workflow.analysis ? `Analysis ran ${escapeHTML(new Date(workflow.analysis.completedAt).toLocaleString())} · ${escapeHTML(workflow.analysis.provider || "AI provider")}` : "No analysis is available for the current evidence revision."}</p></div><span class="finding-count">${workflow.findings.length} findings</span></div>
      ${interactive && workflow.evidenceFiles.some((file) => file.scanStatus === "clean") ? `<button class="button button-outline button-small" data-action="run-analysis" data-stage="${workflow.id}">${icon("sparkles", 15)} Run AI analysis</button>` : ""}
      <div class="findings-list">${workflow.findings.length ? workflow.findings.map((finding) => renderFindingCard(finding, workflow, interactive)).join("") : `<div class="small-empty-state">Run AI analysis against clean evidence to generate findings. AI analysis is not configured until an authorized provider is connected.</div>`}</div>
      <div class="ai-disclaimer">${icon("sparkles", 14)} AI-generated analysis is advisory. Each finding must cite attached source evidence; humans own review and disposition.</div>
    </section>`;
}

function renderGeneratedDocuments(definition) {
  const documents = state.generatedDocuments.filter((document) => document.stageId === definition.id);
  return `
    <section class="panel stage-panel generated-documents-panel">
      <div class="panel-heading"><div><div class="section-kicker">AUDIT-READY OUTPUTS</div><h2>Generated documents</h2><p class="panel-subtitle">Versioned reports with evidence citations and review status.</p></div><button class="button button-outline button-small" data-action="generate-report" data-stage="${definition.id}">${icon("plus", 15)} Generate report</button></div>
      ${documents.length ? `<div class="generated-document-list">${documents.map((document) => `
        <button class="generated-document-row" data-action="open-document" data-document="${escapeHTML(document.id)}">
          <span class="document-preview-icon">${icon("document", 18)}</span><span class="document-preview-name"><strong>${escapeHTML(document.title)}</strong><small>${escapeHTML(document.format)} · ${escapeHTML(document.createdAt)} · Evidence-linked</small></span><span class="doc-status doc-${escapeHTML(document.status.toLowerCase())}">${escapeHTML(document.status)}</span>${icon("chevron", 16, "muted-icon")}
        </button>`).join("")}</div>` : `<div class="small-empty-state">No report yet for this stage. Generate one from the current evidence and findings.</div>`}
    </section>`;
}

function renderStageWorkspace() {
  const definition = stageDefinition(state.activeStageId);
  const workflow = stageState(state.activeStageId);
  const index = currentStageIndex();
  const interactive = isUnlocked(index) && workflow.gateStatus !== "passed";
  const isLast = index === STAGES.length - 1;
  const findingsResolved = workflow.findings.every(
    (finding) => !["critical", "high"].includes(finding.severity) || finding.status === "resolved",
  );
  const allChecklistComplete = definition.checklist.every(
    (_, itemIndex) => workflow.checklist[itemIndex] === true,
  );
  const hasUpload = workflow.evidenceFiles.length > 0;
  return `
    <main class="main-content stage-main">
      <div class="page-header stage-page-header">
        <div class="stage-title-block"><div class="page-eyebrow">${icon("shield", 13)} GOVERNANCE FRAMEWORK <span class="header-dot"></span> STAGE ${String(index + 1).padStart(2, "0")} OF 06</div><div class="stage-title-row"><h1>${escapeHTML(definition.name)}</h1>${statusBadge(workflow.gateStatus)}</div><p>${escapeHTML(definition.description)}</p></div>
        <button class="button button-outline button-small" data-action="navigate" data-view="timeline">${icon("clock", 15)} View timeline</button>
      </div>
      ${workflow.gateStatus === "locked" ? `<div class="locked-banner">${icon("lock", 16)}<span><strong>This gate is locked.</strong> Complete and pass the previous stage to unlock this review.</span><button class="text-icon-button" data-action="open-stage" data-stage="${STAGES[index - 1]?.id}">Go to previous stage ${icon("arrowRight", 14)}</button></div>` : ""}
      ${workflow.gateStatus === "passed" ? `<div class="passed-banner">${icon("check", 17)}<span><strong>Gate passed.</strong> This decision is bound to an immutable release evidence snapshot.</span><span class="passed-banner-right">APPROVED</span></div>` : ""}
      <div class="stage-context-bar"><span class="candidate-chip">${icon("code", 14)} <span>${escapeHTML(state.candidate?.commitSha ? state.candidate.commitSha.slice(0, 12) : "Commit not pinned")}</span> <span class="candidate-divider"></span> ${escapeHTML(state.candidate?.releaseName || "Release candidate")}</span><span class="context-dot"></span><span>Policy v${escapeHTML(state.candidate?.policyVersion || "1.0")}</span><span class="context-dot"></span><span>${workflow.evidenceFiles.length} evidence items</span><span class="context-right">${pendingRequestCount ? icon("clock", 14) + " Syncing…" : icon("activity", 14) + " Server-backed"}</span></div>
      <div class="stage-layout">
        <div class="stage-workspace">
          ${renderEvidenceSection(definition, workflow, interactive)}
          ${renderFindings(definition, workflow, interactive)}
          ${renderChecklist(definition, workflow, interactive)}
          ${renderValidation(definition, workflow, interactive)}
          ${renderGeneratedDocuments(definition)}
        </div>
        <div class="stage-aside">${scorePanel({ ...workflow, id: workflow.id })}${renderGateRequirements(definition, workflow, interactive, allChecklistComplete, findingsResolved, hasUpload)}</div>
      </div>
      ${renderStageActionBar(definition, workflow, index, interactive, allChecklistComplete, findingsResolved, hasUpload, isLast)}
    </main>`;
}

function renderGateRequirements(definition, workflow, interactive, allChecklistComplete, findingsResolved, hasUpload) {
  const confirmed = Boolean(workflow.confirmedSnapshotId);
  const requirements = [
    ["Evidence attached", hasUpload],
    ["Evidence malware-scanned", workflow.unverifiedEvidence.length === 0],
    ["Checklist complete", allChecklistComplete],
    ["Findings reviewed", findingsResolved],
    ["Review confirmed", confirmed],
    ["Validation passed", workflow.validation?.outcome === "passed"],
    ["Gate approval", workflow.gateStatus === "passed"],
  ];
  return `
    <section class="panel gate-requirements">
      <div class="section-kicker">GATE REQUIREMENTS</div><h3>Before you advance</h3>
      <div class="gate-requirement-list">${requirements.map(([label, done]) => `<div class="gate-requirement ${done ? "requirement-done" : ""}"><span>${done ? icon("check", 13) : '<i></i>'}</span><span>${label}</span></div>`).join("")}</div>
      <div class="gate-owner"><span class="user-avatar small-user-avatar">${escapeHTML((state.user?.displayName || "U").slice(0, 2).toUpperCase())}</span><span>Stage owner<small>${escapeHTML(state.user?.displayName || "Unassigned")} · ${escapeHTML(state.user?.role || "")}</small></span><button class="icon-button small-icon-button" aria-label="Stage owner information" data-action="profile-info">${icon("more", 15)}</button></div>
      ${workflow.gateStatus === "failed" ? `<div class="gate-blocker">${icon("alert", 14)} One or more policy checks require action.</div>` : ""}
      ${!interactive && workflow.gateStatus === "locked" ? `<div class="locked-requirement-note">${icon("lock", 13)} Complete the previous gate to begin.</div>` : ""}
      ${definition.id === "tests" ? `<div class="threshold-note">${icon("activity", 14)} Line coverage threshold <strong>≥ 85%</strong></div>` : ""}
    </section>`;
}

function renderStageActionBar(definition, workflow, index, interactive, allChecklistComplete, findingsResolved, hasUpload, isLast) {
  const confirmed = Boolean(workflow.confirmedSnapshotId);
  const canConfirm =
    interactive &&
    allChecklistComplete &&
    findingsResolved &&
    hasUpload &&
    workflow.unverifiedEvidence.length === 0;
  const canValidate = interactive && confirmed && workflow.gateStatus !== "running";
  const isPassed = workflow.gateStatus === "passed";
  let footerActions;
  if (isPassed && isLast) {
    footerActions = state.releaseAuthorized
      ? `<span class="release-authorized">${icon("shield", 16)} RELEASE AUTHORIZED</span>`
      : `<button class="button button-primary" data-action="authorize-release">${icon("shield", 15)} Request release authorization ${icon("arrowRight", 15)}</button>`;
  } else if (isPassed) {
    footerActions = `<button class="button button-primary" data-action="move-next" data-stage="${STAGES[index + 1].id}">Move to ${escapeHTML(STAGES[index + 1].shortName)} ${icon("arrowRight", 15)}</button>`;
  } else if (workflow.validation?.outcome === "passed" && !workflow.validation.stale) {
    footerActions = `<span class="footer-hint">${icon("check", 14)} Validation passed · Gate approval required</span><button class="button button-primary" data-action="approve-gate" data-stage="${definition.id}">Approve gate ${icon("arrowRight", 15)}</button>`;
  } else {
    footerActions = `
      <button class="button button-outline" data-action="confirm-review" data-stage="${definition.id}" ${canConfirm ? "" : "disabled"}>
        ${confirmed ? icon("check", 15) : icon("shield", 15)} ${confirmed ? "Review confirmed" : "Confirm review"}
      </button>
      <button class="button button-primary" data-action="run-validation" data-stage="${definition.id}" ${canValidate ? "" : "disabled"}>
        ${icon("activity", 15)} Run validation ${icon("arrowRight", 15)}
      </button>`;
  }

  return `<footer class="stage-action-bar">
    <div class="action-bar-info">${isPassed ? `${icon("check", 16)} This gate has passed` : `<span class="action-bar-state-dot ${interactive ? "state-dot-active" : ""}"></span><span>${interactive ? "Review in progress" : "Stage unavailable"}</span><span class="action-bar-separator">·</span><span>Changes auto-saved</span>`}</div>
    <div class="action-bar-buttons">${footerActions}</div>
  </footer>`;
}

function renderDocumentPreview(document) {
  return document.content || "";
}

function renderDocumentsPage() {
  const documents = state.generatedDocuments.filter(
    (document) =>
      state.documentFilter === "all" ||
      document.status.toLowerCase() === state.documentFilter,
  );
  return `
    <main class="main-content resource-main">
      <div class="page-header resource-page-header"><div><div class="page-eyebrow">EVIDENCE &amp; KNOWLEDGE</div><h1>Governance documents</h1><p>Versioned, evidence-linked reports for every stage of your release journey.</p></div><button class="button button-primary" data-action="generate-report" data-stage="${state.activeStageId}">${icon("plus", 16)} Generate document</button></div>
      <section class="document-feature-banner"><div class="document-banner-icon">${icon("document", 23)}</div><div><div class="section-kicker">AUDIT-READY BY DESIGN</div><h2>Every decision, clearly documented.</h2><p>Generate source-cited reports from reviewed evidence. Preview, verify citations, then export as Markdown, HTML, or PDF.</p></div><span class="document-banner-badge">${icon("shield", 14)} EVIDENCE-LINKED</span></section>
      <div class="resource-toolbar"><div class="resource-tab-list"><button class="resource-tab ${state.documentFilter === "all" ? "is-selected" : ""}" data-action="documents-filter" data-filter="all">All documents <span>${state.generatedDocuments.length}</span></button><button class="resource-tab ${state.documentFilter === "approved" ? "is-selected" : ""}" data-action="documents-filter" data-filter="approved">Approved</button><button class="resource-tab ${state.documentFilter === "draft" ? "is-selected" : ""}" data-action="documents-filter" data-filter="draft">Drafts</button></div><button class="button button-outline button-small" data-action="navigate" data-view="audit">${icon("clock", 15)} Version history</button></div>
      <section class="document-list panel">${documents.map((document) => {
        const definition = stageDefinition(document.stageId);
        return `<article class="document-list-row"><span class="document-type-large type-${escapeHTML(document.format.toLowerCase())}">${icon("document", 21)}</span><div class="document-list-info"><strong>${escapeHTML(document.title)}</strong><span>${escapeHTML(definition.shortName)} <i>·</i> ${escapeHTML(document.format)} <i>·</i> ${escapeHTML(document.createdAt)}</span></div><span class="doc-status doc-${escapeHTML(document.status.toLowerCase())}">${escapeHTML(document.status)}</span><button class="button button-outline button-small" data-action="open-document" data-document="${escapeHTML(document.id)}">Preview ${icon("external", 14)}</button><button class="icon-button small-icon-button" aria-label="Download ${escapeHTML(document.title)}" data-action="download-document" data-document="${escapeHTML(document.id)}">${icon("download", 16)}</button></article>`;
      }).join("")}</section>
      <div class="resource-tip">${icon("help", 15)} Reports are persisted by the server. Print to PDF from a report preview.</div>
    </main>`;
}

function renderArtifactPage() {
  return `
    <main class="main-content resource-main">
      <div class="page-header resource-page-header"><div><div class="page-eyebrow">REPOSITORY INTEGRATION</div><h1>Code artifacts</h1><p>Human-authored proposals are traceable to findings and submitted as reviewable pull requests.</p></div><button class="button button-primary" data-action="new-artifact">${icon("code", 16)} Propose artifact</button></div>
      <section class="repo-connect-banner"><div class="repo-icon">${icon("code", 23)}</div><div><div class="section-kicker">CONFIGURED REPOSITORY</div><h2>${escapeHTML(state.capabilities?.github?.repository || "Repository integration not configured")}</h2><p>Candidate commit <code>${escapeHTML(state.candidate?.commitSha || "Not pinned")}</code> <span>·</span> ${state.capabilities?.github?.configured ? "GitHub API configured" : "Set GITHUB_TOKEN, GITHUB_OWNER, and GITHUB_REPO to enable provider actions"}</p></div><span class="repo-connection-status ${state.capabilities?.github?.configured ? "repo-connected" : "repo-demo-status"}"><i></i>${state.capabilities?.github?.configured ? "Configured" : "Unavailable"}</span></section>
      <div class="artifact-policy-note">${icon("shield", 16)} Generated artifacts are proposals — changes require a human-reviewed pull request. Protected branches are never modified directly.</div>
      <div class="section-heading-row"><div><div class="section-kicker">PROPOSED CHANGES</div><h2>Artifact workspace <span class="heading-count">${state.artifacts.length}</span></h2></div><button class="button button-outline button-small" data-action="navigate" data-view="audit">View activity ${icon("arrowRight", 14)}</button></div>
      <section class="artifact-list">${state.artifacts.map((artifact) => `<article class="artifact-card"><div class="artifact-card-top"><span class="artifact-file-icon">${icon("code", 18)}</span><span class="artifact-status status-${escapeHTML(artifact.status.toLowerCase().replaceAll("_", "-").replaceAll(" ", "-"))}">${escapeHTML(artifact.status.replaceAll("_", " "))}</span></div><h3>${escapeHTML(artifact.title)}</h3><p>Proposed from finding <strong>${escapeHTML(artifact.source)}</strong>${artifact.status === "stale_candidate" ? " · Candidate identity changed; review this pull request against the current release before proceeding." : ""}</p><div class="artifact-file-list">${artifact.files.map((file) => `<span>${icon("file", 14)} ${escapeHTML(file)}</span>`).join("")}</div><div class="artifact-card-footer"><span>${icon("clock", 14)} Updated ${escapeHTML(artifact.updatedAt)}</span><button class="button button-outline button-small" data-action="preview-artifact" data-artifact="${escapeHTML(artifact.id)}">Review diff ${icon("arrowRight", 14)}</button></div></article>`).join("") || '<div class="small-empty-state">No code artifact proposals have been saved to this candidate.</div>'}</section>
      <div class="artifact-disclaimer">${icon("sparkles", 15)} Generated code is not verified until it passes repository checks, required human reviews, and tests.</div>
    </main>`;
}

function renderTimelinePage() {
  return `
    <main class="main-content resource-main">
      <div class="page-header resource-page-header"><div><div class="page-eyebrow">DELIVERY TRACKING · ${escapeHTML(state.candidate?.releaseName || "RELEASE CANDIDATE")}</div><h1>Release timeline</h1><p>Track persisted governance gates, evidence readiness, owners, and delivery milestones.</p></div><span class="forecast-chip large-forecast">${icon("activity", 14)} ${state.stages.every((stage) => stage.gateStatus === "passed") ? "Gates complete" : "In progress"}</span></div>
      <div class="timeline-summary-grid"><div class="timeline-summary-card"><span>GATES PASSED</span><strong>${state.stages.filter((stage) => stage.gateStatus === "passed").length}<small> / 6</small></strong></div><div class="timeline-summary-card"><span>TARGET RELEASE</span><strong>${escapeHTML(state.candidate?.targetDate || "Not set")}</strong></div><div class="timeline-summary-card"><span>CONFIDENCE INDEX</span><strong>${state.releaseConfidence?.score ?? "Not available"}${state.releaseConfidence?.score === null || state.releaseConfidence?.score === undefined ? "" : " / 100"}</strong></div><div class="timeline-summary-card"><span>AUDIT EVENTS</span><strong>${state.auditEvents.length}</strong></div></div>
      <section class="panel timeline-panel"><div class="panel-heading"><div><div class="section-kicker">GOVERNANCE MILESTONES</div><h2>Release progression</h2></div><span class="context-right">Commit ${escapeHTML(state.candidate?.commitSha || "not pinned")}</span></div>
        <div class="timeline-list">${STAGES.map((definition, index) => {
          const workflow = stageState(definition.id);
          const done = workflow.gateStatus === "passed";
          const current = isUnlocked(index) && !done;
          const locked = !done && !current;
          return `<div class="timeline-item"><div class="timeline-marker-column"><span class="timeline-marker ${done ? "marker-done" : current ? "marker-current" : "marker-locked"}">${done ? icon("check", 14) : locked ? icon("lock", 12) : index + 1}</span>${index < 5 ? `<span class="timeline-connector ${done ? "connector-done" : ""}"></span>` : ""}</div><div class="timeline-item-body"><div class="timeline-item-head"><div><span class="timeline-stage-index">STAGE 0${index + 1}</span><h3>${escapeHTML(definition.name)}</h3></div>${statusBadge(workflow.gateStatus)}</div><p>${escapeHTML(definition.objective)}</p><div class="timeline-meta"><span>${icon("users", 14)} ${escapeHTML(workflow.approval?.actor || state.user?.displayName || "No approver")}</span><span>${icon("document", 14)} ${workflow.evidenceFiles.length} evidence items</span><span>${icon("clock", 14)} ${workflow.gateTimestamp ? escapeHTML(new Date(workflow.gateTimestamp).toLocaleString()) : locked ? "Awaiting prerequisites" : "In progress"}</span><button class="text-icon-button" data-action="open-stage" data-stage="${definition.id}">${locked ? "View stage" : done ? "View decision" : "Continue"} ${icon("arrowRight", 14)}</button></div></div></div>`;
        }).join("")}</div>
        <div class="release-milestone"><span class="milestone-star">${icon("shield", 18)}</span><div><strong>Target production release</strong><small>${escapeHTML(state.candidate?.targetDate || "Target date not set")} · Production authorization required</small></div><span class="milestone-pending">${state.releaseAuthorized ? "AUTHORIZED" : "PENDING"}</span></div>
      </section>
    </main>`;
}

function renderAuditPage() {
  const events = state.auditEvents.filter(
    (entry) =>
      state.auditFilter === "all" ||
      entry.type === state.auditFilter ||
      (state.auditFilter === "evidence" && entry.type === "document") ||
      (state.auditFilter === "scan" && ["finding", "artifact"].includes(entry.type)),
  );
  return `
    <main class="main-content resource-main">
      <div class="page-header resource-page-header"><div><div class="page-eyebrow">PERSISTED EVENT LOG</div><h1>Activity &amp; audit</h1><p>Review server-recorded evidence changes, gate decisions, and release-candidate activity.</p></div><span class="audit-integrity">${icon("shield", 15)} SQLite audit trail</span></div>
      <div class="audit-filter-bar"><button class="resource-tab ${state.auditFilter === "all" ? "is-selected" : ""}" data-action="audit-filter" data-filter="all">${icon("activity", 15)} All activity</button><button class="resource-tab ${state.auditFilter === "approval" ? "is-selected" : ""}" data-action="audit-filter" data-filter="approval">${icon("check", 14)} Approvals</button><button class="resource-tab ${state.auditFilter === "evidence" ? "is-selected" : ""}" data-action="audit-filter" data-filter="evidence">${icon("document", 14)} Evidence</button><button class="resource-tab ${state.auditFilter === "scan" ? "is-selected" : ""}" data-action="audit-filter" data-filter="scan">${icon("shield", 14)} Scans &amp; validation</button><span class="audit-time-filter">${icon("clock", 14)} Last 30 days</span></div>
      <section class="panel audit-panel"><div class="panel-heading"><div><div class="section-kicker">${escapeHTML(state.candidate?.releaseName || "RELEASE CANDIDATE")}</div><h2>Activity log</h2></div><button class="button button-outline button-small" data-action="download-audit">${icon("download", 15)} Export activity</button></div><div class="audit-event-list">${events.length ? events.map((event) => `<article class="audit-event-row"><span class="audit-event-icon event-${escapeHTML(event.type)}">${icon(event.type === "approval" ? "check" : event.type === "validation" ? "shield" : "document", 16)}</span><div class="audit-event-copy"><strong>${escapeHTML(event.action)}</strong><p>${escapeHTML(event.detail)}</p><small>${escapeHTML(event.actor)}</small></div><time>${escapeHTML(event.time)}</time><span class="audit-event-verified">${icon("activity", 13)} Audited</span></article>`).join("") : '<div class="small-empty-state">No events in this category yet.</div>'}</div><div class="audit-integrity-footer">${icon("shield", 15)} Events are persisted in the application database and are not editable through the UI.</div></section>
    </main>`;
}

function renderProjectAccessPage() {
    const projectId = state.candidate?.projectId;
    if (state.user?.role !== "admin") return renderOverview();
    if (state.projectAccessLoadedFor !== projectId) {
      return `<main class="main-content resource-main"><section class="panel"><h1>Loading project access…</h1></section></main>`;
    }
    const members = state.projectMembers.filter((member) => member.active);
    const availableUsers = state.projectUsers.filter(
      (user) => !members.some((member) => member.id === user.id),
    );
    return `
      <main class="main-content resource-main">
        <div class="page-header resource-page-header">
          <div><div class="page-eyebrow">PROJECT GOVERNANCE</div><h1>Project access</h1>
          <p>Assign least-privilege roles for <strong>${escapeHTML(state.candidate?.projectName || "this project")}</strong>. Candidate, evidence, and audit access follows this membership.</p></div>
          <span class="audit-integrity">${icon("shield", 15)} Membership-scoped access</span>
        </div>
        <section class="panel audit-panel">
          <div class="panel-heading"><div><div class="section-kicker">${members.length} ACTIVE MEMBERS</div><h2>Project members</h2></div></div>
          ${members.length ? `<div class="project-member-list">${members.map((member) => `
            <article class="project-member-row">
              <div class="project-member-copy"><strong>${escapeHTML(member.displayName)}</strong><small>${escapeHTML(member.username)}</small></div>
              <label class="project-role-control"><span class="sr-only">Role for ${escapeHTML(member.displayName)}</span>
                <select id="project-role-${escapeHTML(member.id)}" aria-label="Role for ${escapeHTML(member.displayName)}">
                  ${["admin", "qa_lead", "developer", "auditor"].map((role) => `<option value="${role}" ${member.role === role ? "selected" : ""}>${role.replace("_", " ")}</option>`).join("")}
                </select>
              </label>
              <button class="button button-outline button-small" data-action="update-project-member" data-user="${escapeHTML(member.id)}">Save role</button>
              <button class="button button-outline button-small danger-button" data-action="remove-project-member" data-user="${escapeHTML(member.id)}">Remove</button>
            </article>`).join("")}</div>` : `<div class="small-empty-state">No active members are assigned to this project.</div>`}
        </section>
        <section class="panel project-member-add-panel">
          <div class="section-kicker">GRANT PROJECT ACCESS</div><h2>Add a member</h2>
          ${availableUsers.length ? `<form id="project-member-form" data-project="${escapeHTML(projectId || "")}">
            <label>User<select name="userId" required>${availableUsers.map((user) => `<option value="${escapeHTML(user.id)}">${escapeHTML(user.displayName)} · ${escapeHTML(user.username)}</option>`).join("")}</select></label>
            <label>Project role<select name="role" required>${["qa_lead", "developer", "auditor", "admin"].map((role) => `<option value="${role}">${role.replace("_", " ")}</option>`).join("")}</select></label>
            <button class="button button-primary button-small" type="submit" ${pendingRequestCount ? "disabled" : ""}>${icon("plus", 15)} Add member</button>
          </form>` : `<p class="small-empty-state">All active users are already members, or no other active accounts exist. Create an account before assigning access.</p>`}
        </section>
        <section class="panel project-member-add-panel">
          <div class="section-kicker">NEW ACCOUNT</div><h2>Create an account for this project</h2>
          <form id="project-account-form">
            <label>Display name<input name="displayName" required maxlength="160" autocomplete="name" /></label>
            <label>Username<input name="username" required maxlength="128" autocomplete="username" /></label>
            <label>Temporary password<input name="password" type="password" required minlength="12" maxlength="1024" autocomplete="new-password" /></label>
            <label>Project role<select name="projectRole" required>${["qa_lead", "developer", "auditor", "admin"].map((role) => `<option value="${role}">${role.replace("_", " ")}</option>`).join("")}</select></label>
            <button class="button button-primary button-small" type="submit" ${pendingRequestCount ? "disabled" : ""}>Create account</button>
          </form>
          <p class="audit-integrity-footer">The account starts with the developer baseline role; its project membership determines its effective project permissions. The temporary password is sent once and is not retained in the browser.</p>
        </section>
        <p class="audit-integrity-footer">Global administrators retain control-plane access. Project roles do not grant access to other projects or global user administration.</p>
      </main>`;
}

function renderSearchPage() {
  const query = state.searchQuery.trim().toLowerCase();
  const matches = [];
  for (const definition of STAGES) {
    if (`${definition.name} ${definition.description}`.toLowerCase().includes(query)) {
      matches.push({
        type: "Stage",
        title: definition.name,
        detail: definition.objective,
        action: "open-stage",
        stageId: definition.id,
      });
    }
    for (const finding of stageState(definition.id).findings) {
      if (`${finding.id} ${finding.title} ${finding.detail}`.toLowerCase().includes(query)) {
        matches.push({
          type: "Finding",
          title: finding.title,
          detail: `${finding.id} · ${definition.shortName}`,
          action: "open-stage",
          stageId: definition.id,
        });
      }
    }
  }
  for (const document of state.generatedDocuments) {
    if (`${document.title} ${document.format}`.toLowerCase().includes(query)) {
      matches.push({
        type: "Document",
        title: document.title,
        detail: `${document.format} · ${document.status}`,
        action: "open-document",
        id: document.id,
      });
    }
  }
  return `<main class="main-content resource-main"><div class="page-header resource-page-header"><div><div class="page-eyebrow">SEARCH WORKSPACE</div><h1>Search results</h1><p>Results for <strong>&ldquo;${escapeHTML(state.searchQuery)}&rdquo;</strong></p></div></div><section class="panel search-results-panel">${matches.length ? matches.map((match) => `<button class="search-result" data-action="${match.action}" ${match.stageId ? `data-stage="${match.stageId}"` : `data-document="${match.id}"`}><span class="search-result-type">${escapeHTML(match.type)}</span><span class="search-result-copy"><strong>${escapeHTML(match.title)}</strong><small>${escapeHTML(match.detail)}</small></span>${icon("arrowRight", 15)}</button>`).join("") : `<div class="small-empty-state">No matching stages, findings, or documents. Try a different search term.</div>`}</section></main>`;
}

function renderModal() {
  if (!state.currentModal) return "";
  if (state.currentModal.type === "document") {
    const document = state.generatedDocuments.find((item) => item.id === state.currentModal.id);
    if (!document) return "";
    const body = state.currentModal.content || "Loading the server-generated report…";
    return `<div class="modal-backdrop" data-action="dismiss-modal"><section class="modal document-modal" role="dialog" aria-modal="true" aria-labelledby="modal-title"><header class="modal-header"><div><div class="section-kicker">DOCUMENT PREVIEW · ${escapeHTML(document.format)}</div><h2 id="modal-title">${escapeHTML(document.title)}</h2></div><button class="icon-button" data-action="close-modal" aria-label="Close preview">${icon("close", 18)}</button></header><div class="document-preview-meta">${icon("shield", 14)} Server-generated <span>·</span> ${escapeHTML(document.createdAt)} <span>·</span> Policy v${escapeHTML(state.candidate?.policyVersion || "1.0")}</div><article class="document-preview-content"><pre>${escapeHTML(body)}</pre></article><footer class="modal-footer"><span class="modal-footer-note">Print to PDF from this report preview.</span><button class="button button-outline button-small" data-action="download-document" data-format="md" data-document="${escapeHTML(document.id)}">${icon("download", 15)} Markdown</button><button class="button button-outline button-small" data-action="download-document" data-format="html" data-document="${escapeHTML(document.id)}">${icon("download", 15)} HTML</button><button class="button button-primary button-small" data-action="print-document">${icon("document", 15)} Export PDF</button></footer></section></div>`;
  }
  if (state.currentModal.type === "artifact") {
    const artifact = state.artifacts.find((item) => item.id === state.currentModal.id);
    if (!artifact) return "";
    const files = artifact.files_json ? JSON.parse(artifact.files_json) : artifact.files.map((file) => ({ path: file, content: "" }));
    const canSubmit = ["draft", "failed"].includes(artifact.status);
    return `<div class="modal-backdrop" data-action="dismiss-modal"><section class="modal artifact-modal" role="dialog" aria-modal="true" aria-labelledby="modal-title"><header class="modal-header"><div><div class="section-kicker">PROPOSED CODE CHANGE · REVIEW REQUIRED</div><h2 id="modal-title">${escapeHTML(artifact.title)}</h2></div><button class="icon-button" data-action="close-modal" aria-label="Close preview">${icon("close", 18)}</button></header><div class="artifact-review-meta"><span>${icon("code", 15)} ${escapeHTML(state.capabilities?.github?.repository || "Repository integration not configured")}</span><span>Base commit <code>${escapeHTML(state.candidate?.commitSha || "Not pinned")}</code></span><span>Source finding <strong>${escapeHTML(artifact.source)}</strong></span></div>${files.map((file) => `<div class="diff-view"><div class="diff-file-header">${icon("file", 15)} ${escapeHTML(file.path)}<span>Proposed addition · Human review required</span></div><pre>${escapeHTML(file.content)}</pre></div>`).join("")}<div class="artifact-review-warning">${icon("alert", 15)} Proposed code is unverified until reviewed, submitted through a pull request, and tested in your repository.</div><footer class="modal-footer"><span class="modal-footer-note">${canSubmit ? "Protected branches are never modified directly." : artifact.status === "stale_candidate" ? `Pull request ${escapeHTML(artifact.pullRequestUrl || "created")} targets a prior candidate identity.` : `Repository proposal status: ${escapeHTML(artifact.status.replaceAll("_", " "))}.`}</span><button class="button button-outline button-small" data-action="close-modal">Close</button>${canSubmit ? `<button class="button button-primary button-small" data-action="create-pr" data-artifact="${escapeHTML(artifact.id)}">${icon("external", 15)} ${artifact.status === "failed" ? "Retry pull request" : "Create review pull request"}</button>` : ""}</footer></section></div>`;
  }
  if (state.currentModal.type === "new-artifact") {
    const findings = state.stages.flatMap((stage) => stage.findings.map((finding) => ({ ...finding, stageId: stage.id })));
    return `<div class="modal-backdrop" data-action="dismiss-modal"><section class="modal info-modal form-modal" role="dialog" aria-modal="true" aria-labelledby="modal-title"><header class="modal-header"><div><div class="section-kicker">REPOSITORY PROPOSAL</div><h2 id="modal-title">Create a reviewable code artifact</h2></div><button class="icon-button" data-action="close-modal" aria-label="Close">${icon("close", 18)}</button></header><form id="artifact-form"><label>Title<input name="title" required minlength="4" maxlength="200" /></label><label>Source finding<select name="findingId" required>${findings.map((finding) => `<option value="${escapeHTML(finding.id)}" data-stage="${escapeHTML(finding.stageId)}">${escapeHTML(finding.id)} · ${escapeHTML(finding.title)}</option>`).join("")}</select></label><label>Repository-relative file path<input name="filePath" required maxlength="200" placeholder="src/example.test.ts" /></label><label>Proposed UTF-8 file content<textarea name="content" required rows="12" maxlength="200000" spellcheck="false"></textarea></label><div class="modal-footer"><span class="modal-footer-note">This creates a draft; it does not change the repository.</span><button type="button" class="button button-outline button-small" data-action="close-modal">Cancel</button><button type="submit" class="button button-primary button-small">Save proposal</button></div></form></section></div>`;
  }
  if (state.currentModal.type === "disposition") {
    const workflow = stageState(state.currentModal.stageId);
    const finding = workflow?.findings.find((item) => item.id === state.currentModal.findingId);
    if (!finding) return "";
    const clean = workflow.evidenceFiles.filter((item) => item.scanStatus === "clean");
    return `<div class="modal-backdrop" data-action="dismiss-modal"><section class="modal info-modal form-modal" role="dialog" aria-modal="true" aria-labelledby="modal-title"><header class="modal-header"><div><div class="section-kicker">BLOCKING FINDING</div><h2 id="modal-title">Resolve ${escapeHTML(finding.id)}</h2></div><button class="icon-button" data-action="close-modal" aria-label="Close">${icon("close", 18)}</button></header><p>${escapeHTML(finding.title)} — ${escapeHTML(finding.detail)}</p><form id="disposition-form" data-stage="${escapeHTML(workflow.id)}" data-finding="${escapeHTML(finding.id)}"><label>Clean evidence<select name="evidenceId" required>${clean.map((item) => `<option value="${escapeHTML(item.id)}">${escapeHTML(item.name)}</option>`).join("")}</select></label><label>Resolution rationale<textarea name="rationale" required minlength="20" maxlength="2000" rows="5"></textarea></label><div class="modal-footer"><span class="modal-footer-note">Risk acceptance is not supported by this policy.</span><button type="button" class="button button-outline button-small" data-action="close-modal">Cancel</button><button type="submit" class="button button-primary button-small" ${clean.length ? "" : "disabled"}>Record resolution</button></div></form></section></div>`;
  }
  if (state.currentModal.type === "new-candidate") {
    return `<div class="modal-backdrop" data-action="dismiss-modal"><section class="modal info-modal form-modal" role="dialog" aria-modal="true" aria-labelledby="modal-title"><header class="modal-header"><div><div class="section-kicker">RELEASE WORKSPACE</div><h2 id="modal-title">Create a release candidate</h2></div><button class="icon-button" data-action="close-modal" aria-label="Close">${icon("close", 18)}</button></header><form id="candidate-form"><label>Project name<input name="projectName" required minlength="2" maxlength="120" /></label><label>Release name<input name="releaseName" required maxlength="120" placeholder="2.4.0" /></label><label>Reviewed Git commit SHA (optional)<input name="commitSha" maxlength="40" pattern="[a-fA-F0-9]{40}" /></label><div class="modal-footer"><span class="modal-footer-note">New candidate starts with all six gates unvalidated.</span><button type="button" class="button button-outline button-small" data-action="close-modal">Cancel</button><button type="submit" class="button button-primary button-small">Create candidate</button></div></form></section></div>`;
  }
  return `<div class="modal-backdrop" data-action="dismiss-modal"><section class="modal info-modal" role="dialog" aria-modal="true" aria-labelledby="modal-title"><header class="modal-header"><div><div class="section-kicker">SCORE METHODOLOGY</div><h2 id="modal-title">Explain release confidence</h2></div><button class="icon-button" data-action="close-modal" aria-label="Close">${icon("close", 18)}</button></header><p>Scores summarize persisted evidence for the selected release candidate and policy version. Risk is an index (lower is better); coverage is reported only when a trusted evidence source provides it.</p><ul><li>Release confidence is provisional until required policy gates pass.</li><li>Mandatory failed controls block advancement regardless of the numeric score.</li><li>Missing evidence is shown as unavailable rather than treated as a passing score.</li><li>Optional AI-generated analysis is advisory; deterministic server-side policy controls advancement.</li></ul><div class="methodology-disclaimer">${icon("shield", 15)} The release confidence index is derived from passed governance gates and is not an AI prediction or probability.</div><footer class="modal-footer"><span></span><button class="button button-primary button-small" data-action="close-modal">Got it</button></footer></section></div>`;
}

function renderToast() {
  return state.toast ? `<div class="toast toast-${escapeHTML(state.toast.type)}" role="status">${icon(state.toast.type === "error" ? "alert" : "check", 16)}${escapeHTML(state.toast.message)}<button aria-label="Dismiss notification" data-action="dismiss-toast">${icon("close", 15)}</button></div>` : "";
}

function renderAuthentication() {
  if (state.startupError) {
    return `<main class="auth-shell"><section class="auth-card"><div class="brand-mark">${icon("shield", 21)}</div><h1>Governance service unavailable</h1><p>${escapeHTML(state.startupError)}</p><button class="button button-primary" data-action="retry-session">Retry connection</button></section></main>`;
  }
  const setup = state.setupRequired;
  return `<main class="auth-shell"><section class="auth-card"><div class="brand-mark">${icon("shield", 21)}</div><div class="eyebrow">AI QUALITY GOVERNANCE</div><h1>${setup ? "Create your administrator" : "Sign in to your workspace"}</h1><p>${setup ? "Use the one-time bootstrap token printed by the local service. Choose a strong password; governance evidence is stored on this server." : "Authenticate with your governance workspace account."}</p><form id="auth-form">${setup ? `<label>Bootstrap token<input name="bootstrapToken" type="password" required autocomplete="off" /></label><label>Display name<input name="displayName" required maxlength="160" autocomplete="name" /></label>` : ""}<label>Username<input name="username" required maxlength="128" autocomplete="username" /></label><label>Password<input name="password" type="password" required maxlength="1024" autocomplete="${setup ? "new-password" : "current-password"}" /></label>${setup ? '<small class="auth-password-note">At least 12 UTF-8 bytes. It is never stored in the browser.</small>' : ""}<button class="button button-primary auth-submit" type="submit" ${pendingRequestCount ? "disabled" : ""}>${pendingRequestCount ? "Connecting…" : setup ? "Create administrator" : "Sign in"}</button></form><div class="auth-capabilities">${icon("shield", 15)} ${escapeHTML(state.capabilities?.storage?.provider || "Private server-side evidence storage")} · No demo credentials are configured</div></section></main>${renderToast()}`;
}

function renderNoCandidate() {
  const isAdmin = state.user?.role === "admin";
  return `<main class="main-content empty-workspace"><section class="panel"><div class="section-kicker">RELEASE WORKSPACE</div><h1>${isAdmin ? "No release candidates" : "No project access"}</h1><p>${isAdmin ? "Create a candidate to start the six-stage governance flow. Candidate state is persisted on this server." : "You do not have access to a project yet. Ask an administrator to add you to a project before starting governance work."}</p>${isAdmin ? `<button class="button button-primary" data-action="new-candidate">${icon("plus", 16)} Create release candidate</button>` : ""}</section></main>`;
}

function render() {
  if (state.loading) {
    app.innerHTML = `<main class="auth-shell"><section class="auth-card"><div class="brand-mark">${icon("shield", 21)}</div><h1>Connecting to governance service…</h1></section></main>`;
    return;
  }
  if (!state.authenticated) {
    app.innerHTML = renderAuthentication();
    return;
  }
  if (!state.candidate) {
    app.innerHTML = `${renderSidebar()}<div class="app-shell">${renderTopbar()}${renderNoCandidate()}</div>${renderModal()}${renderToast()}`;
    return;
  }
  const view =
    state.activeView === "overview"
      ? renderOverview()
      : state.activeView === "stage"
        ? renderStageWorkspace()
        : state.activeView === "documents"
          ? renderDocumentsPage()
          : state.activeView === "artifacts"
            ? renderArtifactPage()
            : state.activeView === "timeline"
              ? renderTimelinePage()
              : state.activeView === "audit"
                ? renderAuditPage()
                : state.activeView === "access"
                  ? renderProjectAccessPage()
                  : renderSearchPage();
  app.innerHTML = `${renderSidebar()}<div class="app-shell">${renderTopbar()}${view}</div>${renderModal()}${renderToast()}`;
  if (state.currentModal) {
    const dialog = $(".modal");
    if (dialog) {
      const focusable = dialog.querySelector("button");
      focusable?.focus();
    }
  }
}

function markFindingResolved(stageId, findingId) {
  const workflow = stageState(stageId);
  const index = STAGES.findIndex((stage) => stage.id === stageId);
  if (!workflow || !isUnlocked(index) || workflow.gateStatus === "passed") {
    showToast("This stage is not currently available for editing.", "error");
    return;
  }
  if (!workflow.findings.some((finding) => finding.id === findingId)) {
    showToast("That finding is no longer available.", "error");
    return;
  }
  state.currentModal = { type: "disposition", stageId, findingId };
  render();
}

async function runStageAnalysis(stageId) {
  const workflow = stageState(stageId);
  const evidenceIds = workflow.evidenceFiles.filter((item) => item.scanStatus === "clean").map((item) => item.id);
  try {
    await apiRequest(`/api/candidates/${encodeURIComponent(state.candidateId)}/stages/${encodeURIComponent(stageId)}/analyses`, {
      method: "POST",
      body: { evidenceIds },
    });
    await loadCandidate();
    showToast("Evidence-cited AI analysis completed.");
  } catch (error) {
    reportError(error);
  }
}

async function runValidation(stageId) {
  try {
    const { data } = await apiRequest(`/api/candidates/${encodeURIComponent(state.candidateId)}/stages/${encodeURIComponent(stageId)}/validations`, {
      method: "POST",
      body: {},
    });
    await loadCandidate();
    const result = stageState(stageId).validation?.outcome;
    const sync = data.integrations?.githubCommitStatus;
    if (data.integrations?.candidateChangedDuringSync) {
      showToast("The candidate changed while validation status was synchronizing. The workspace has been reloaded; review the current stage before proceeding.", "error");
      return;
    }
    if (sync?.status === "failed") {
      showToast(`Policy validation ${result === "passed" ? "passed" : "failed"}, but GitHub commit status synchronization failed (${sync.errorCode}). Review the audit log.`, "error");
      return;
    }
    showToast(result === "passed"
      ? "Validation passed. A different authorized reviewer must approve this gate."
      : "Validation failed. Review the server policy checks before continuing.",
    result === "passed" ? "success" : "error");
  } catch (error) {
    reportError(error);
  }
}

async function confirmReview(stageId) {
  try {
    await apiRequest(`/api/candidates/${encodeURIComponent(state.candidateId)}/stages/${encodeURIComponent(stageId)}/confirmations`, {
      method: "POST",
      body: {},
    });
    await loadCandidate();
    showToast("Review confirmed against the current evidence revision.");
  } catch (error) {
    reportError(error);
  }
}

async function approveGate(stageId) {
  try {
    await apiRequest(`/api/candidates/${encodeURIComponent(state.candidateId)}/stages/${encodeURIComponent(stageId)}/approvals`, {
      method: "POST",
      body: {},
    });
    await loadCandidate();
    showToast(`${stageDefinition(stageId).shortName} gate approval recorded.`);
  } catch (error) {
    reportError(error);
  }
}

async function generateDocument(stageId, format = "markdown") {
  try {
    const { data } = await apiRequest(`/api/candidates/${encodeURIComponent(state.candidateId)}/stages/${encodeURIComponent(stageId)}/documents`, {
      method: "POST",
      body: { format },
    });
    await loadCandidate();
    await openDocument(data.id);
    showToast("Governance report generated from the persisted candidate evidence.");
  } catch (error) {
    reportError(error);
  }
}

function downloadTextFile(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function downloadDocument(documentId, format = "md") {
  const generated = state.generatedDocuments.find((item) => item.id === documentId);
  if (!generated) {
    showToast("That document could not be found.", "error");
    return;
  }
  try {
    const { data } = await apiRequest(`/api/documents/${encodeURIComponent(documentId)}?candidateId=${encodeURIComponent(state.candidateId)}`);
    const safeFilename = generated.title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
    const isHtml = format === "html";
    const content = isHtml
      ? generated.format === "HTML"
        ? data
        : `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${escapeHTML(generated.title)}</title></head><body><pre>${escapeHTML(data)}</pre></body></html>`
      : data;
    downloadTextFile(`${safeFilename}.${isHtml ? "html" : "md"}`, content, isHtml ? "text/html;charset=utf-8" : "text/markdown;charset=utf-8");
    showToast(`${isHtml ? "HTML" : "Markdown"} document downloaded.`);
  } catch (error) {
    reportError(error);
  }
}

function previewArtifact(artifactId) {
  if (!state.artifacts.some((item) => item.id === artifactId)) {
    showToast("That code artifact could not be found.", "error");
    return;
  }
  state.currentModal = { type: "artifact", id: artifactId };
  render();
}

async function openDocument(documentId) {
  const generated = state.generatedDocuments.find((item) => item.id === documentId);
  if (!generated) return showToast("That document could not be found.", "error");
  state.currentModal = { type: "document", id: documentId, content: null };
  render();
  try {
    const { data } = await apiRequest(`/api/documents/${encodeURIComponent(documentId)}?candidateId=${encodeURIComponent(state.candidateId)}`);
    if (state.currentModal?.type === "document" && state.currentModal.id === documentId) {
      state.currentModal.content = data;
      render();
    }
  } catch (error) {
    state.currentModal = null;
    render();
    reportError(error);
  }
}

async function createPullRequest(artifactId) {
  try {
    const { data } = await apiRequest("/api/repo/push", {
      method: "POST",
      body: { candidateId: state.candidateId, artifactId },
    });
    state.currentModal = null;
    await loadCandidate();
    showToast(data.staleCandidate
      ? `Pull request #${data.number} opened against the prior candidate identity. Review it before considering the current release.`
      : `Pull request #${data.number} opened for human review.`,
    data.staleCandidate ? "error" : "success");
  } catch (error) {
    reportError(error);
  }
}

async function addEvidence(files) {
  const workflow = stageState(state.activeStageId);
  const stageIndex = STAGES.findIndex((definition) => definition.id === state.activeStageId);
  if (!workflow || !isUnlocked(stageIndex) || workflow.gateStatus === "passed") {
    showToast("Evidence cannot be changed while this stage is locked or already passed.", "error");
    return;
  }
  const acceptedExtensions = /\.(pdf|md|markdown|html?|png|jpe?g|svg|json|txt|csv)$/i;
  const maxFileSize = 25 * 1024 * 1024;
  const fileList = [...files];
  const rejected = fileList.filter(
    (file) => !acceptedExtensions.test(file.name) || file.size > maxFileSize,
  );
  const accepted = fileList.filter(
    (file) => acceptedExtensions.test(file.name) && file.size <= maxFileSize,
  );
  if (rejected.length) {
    showToast(
      `${rejected.map((file) => file.name).join(", ")} rejected. Files must be supported types no larger than 25 MB.`,
      "error",
    );
    return;
  }
  for (const file of accepted) {
    try {
      const filename = btoa(String.fromCharCode(...new TextEncoder().encode(file.name)))
        .replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/g, "");
      await apiRequest(`/api/evidence/upload?candidateId=${encodeURIComponent(state.candidateId)}&stageId=${encodeURIComponent(workflow.id)}`, {
        method: "POST",
        body: file,
        raw: true,
        headers: {
          "Content-Type": "application/octet-stream",
          "X-Evidence-Filename": filename,
        },
      });
      await loadCandidate();
    } catch (error) {
      reportError(error);
      return;
    }
  }
  showToast(`${accepted.length} evidence file${accepted.length === 1 ? "" : "s"} uploaded. Gate eligibility depends on malware scan results.`);
}

async function removeEvidence(evidenceId) {
  try {
    const { data } = await apiRequest(`/api/evidence/${encodeURIComponent(evidenceId)}?candidateId=${encodeURIComponent(state.candidateId)}`, {
      method: "DELETE",
      body: {},
    });
    await loadCandidate();
    showToast(data.evidenceCleanupPending
      ? "Evidence was detached from this candidate, but its private file could not yet be deleted. Cleanup will be retried and is recorded in the server log."
      : "Evidence removed from this release candidate.");
  } catch (error) {
    reportError(error);
  }
}

async function submitArtifact(form) {
  const data = new FormData(form);
  const findingId = String(data.get("findingId"));
  const stage = state.stages.find((item) => item.findings.some((finding) => finding.id === findingId));
  if (!stage) throw new Error("Select a finding from the current release candidate.");
  const { data: artifact } = await apiRequest(`/api/candidates/${encodeURIComponent(state.candidateId)}/stages/${encodeURIComponent(stage.id)}/artifacts`, {
    method: "POST",
    body: {
      findingId,
      title: String(data.get("title")),
      files: [{ path: String(data.get("filePath")), content: String(data.get("content")) }],
    },
  });
  await loadCandidate();
  state.currentModal = { type: "artifact", id: artifact.id };
  render();
  showToast("Code proposal saved for review.");
}

async function submitDisposition(form) {
  const { stage: stageId, finding: findingId } = form.dataset;
  const data = new FormData(form);
  await apiRequest(`/api/candidates/${encodeURIComponent(state.candidateId)}/stages/${encodeURIComponent(stageId)}/findings/${encodeURIComponent(findingId)}`, {
    method: "PATCH",
    body: {
      status: "resolved",
      rationale: String(data.get("rationale")),
      evidenceId: String(data.get("evidenceId")),
    },
  });
  state.currentModal = null;
  await loadCandidate();
  showToast("Finding resolution and clean supporting evidence recorded.");
}

async function createCandidate(form) {
  const values = Object.fromEntries(new FormData(form));
  const { data } = await apiRequest("/api/candidates", { method: "POST", body: values });
  state.candidateId = data.candidate.id;
  state.currentModal = null;
  await refreshCandidates();
  connectEvents();
  setView("overview");
  showToast("Release candidate created. All gates require current evidence and review.");
}

async function authorizeRelease() {
  try {
    const { data } = await apiRequest("/api/release/authorize", {
      method: "POST",
      body: { candidateId: state.candidateId },
    });
    await loadCandidate();
    showToast(`Release authorization recorded for ${data.commitSha}. Deployment remains a separate operation.`);
  } catch (error) {
    reportError(error);
  }
}

async function setChecklist(stageId, index, checked) {
  try {
    await apiRequest(`/api/candidates/${encodeURIComponent(state.candidateId)}/stages/${encodeURIComponent(stageId)}/checklist`, {
      method: "PUT",
      body: { index: Number(index), checked },
    });
    await loadCandidate();
  } catch (error) {
    reportError(error);
    await loadCandidate().catch(reportError);
  }
}

function handleAction(button) {
  const action = button.dataset.action;
  const stageId = button.dataset.stage;
  switch (action) {
    case "navigate":
      if (button.dataset.view === "search") {
        state.activeView = "search";
        render();
      } else {
        setView(button.dataset.view);
      }
      break;
    case "open-stage": {
      const targetIndex = STAGES.findIndex((stage) => stage.id === button.dataset.stage);
      if (targetIndex < 0) return;
      state.activeStageId = button.dataset.stage;
      state.activeView = "stage";
      persist();
      render();
      window.scrollTo({ top: 0, behavior: "smooth" });
      if (button.dataset.tab === "evidence") {
        $(".evidence-panel")?.scrollIntoView({ behavior: "smooth", block: "center" });
      }
      break;
    }
    case "manage-project-access":
      setView("access");
      void loadProjectAccess().catch(reportError);
      break;
    case "update-project-member": {
      const role = document.getElementById(`project-role-${button.dataset.user}`)?.value;
      if (role) void saveProjectMember(button.dataset.user, role).catch(reportError);
      break;
    }
    case "remove-project-member":
      void removeProjectMember(button.dataset.user).catch(reportError);
      break;
    case "toggle-sidebar":
      $("#sidebar")?.classList.toggle("sidebar-open");
      break;
    case "focus-search":
      $("#global-search")?.focus();
      break;
    case "workspace-info":
      state.currentModal = { type: "new-candidate" };
      render();
      break;
    case "profile-info":
      showToast(`Signed in as ${state.user?.displayName} · ${state.user?.role}`);
      break;
    case "logout":
      void apiRequest("/api/auth/logout", { method: "POST", body: {} })
        .then(() => {
          eventStream?.close();
          state.authenticated = false;
          state.user = null;
          state.csrfToken = null;
          state.candidate = null;
          state.setupRequired = false;
          render();
        })
        .catch(reportError);
      break;
    case "retry-session":
      state.startupError = null;
      state.loading = true;
      render();
      void initialize();
      break;
    case "new-candidate":
      state.currentModal = { type: "new-candidate" };
      render();
      break;
    case "notifications":
      setView("audit");
      break;
    case "explain-score":
      state.currentModal = { type: "methodology" };
      render();
      break;
    case "resolve-finding":
      markFindingResolved(button.dataset.stage, button.dataset.finding);
      break;
    case "checklist": {
      void setChecklist(button.dataset.stage, button.dataset.index, button.checked);
      break;
    }
    case "choose-file":
      $("#evidence-upload")?.click();
      break;
    case "preview-evidence":
      void downloadEvidence(button.dataset.evidence);
      break;
    case "remove-evidence":
      void removeEvidence(button.dataset.evidence);
      break;
    case "run-analysis":
      void runStageAnalysis(stageId);
      break;
    case "confirm-review":
      confirmReview(stageId);
      break;
    case "run-validation":
      runValidation(stageId);
      break;
    case "approve-gate":
      approveGate(stageId);
      break;
    case "move-next":
      if (stageState(state.activeStageId).gateStatus !== "passed") {
        showToast("Pass the current gate before advancing.", "error");
        return;
      }
      setView("stage", button.dataset.stage);
      break;
    case "authorize-release":
      void authorizeRelease();
      break;
    case "generate-report":
      void generateDocument(button.dataset.stage, button.dataset.format || "markdown");
      break;
    case "open-document":
      void openDocument(button.dataset.document);
      break;
    case "download-document":
      void downloadDocument(button.dataset.document, button.dataset.format);
      break;
    case "print-document":
      window.print();
      break;
    case "new-artifact":
      state.currentModal = { type: "new-artifact" };
      render();
      break;
    case "preview-artifact":
      previewArtifact(button.dataset.artifact);
      break;
    case "create-pr":
      createPullRequest(button.dataset.artifact);
      break;
    case "documents-filter":
      state.documentFilter = button.dataset.filter;
      persist();
      render();
      break;
    case "audit-filter":
      state.auditFilter = button.dataset.filter;
      persist();
      render();
      break;
    case "heatmap-filter":
      state.searchQuery = button.dataset.risk || "";
      state.activeView = "search";
      render();
      break;
    case "download-audit": {
      void downloadAudit();
      break;
    }
    case "close-modal":
    case "dismiss-modal":
      state.currentModal = null;
      render();
      break;
    case "dismiss-toast":
      state.toast = null;
      render();
      break;
    default:
      break;
  }

  async function downloadEvidence(evidenceId) {
    try {
      const response = await fetch(`/api/evidence/${encodeURIComponent(evidenceId)}`, { credentials: "same-origin" });
      if (!response.ok) {
        const payload = await response.json();
        throw new Error(payload.error?.message || `Evidence download failed (${response.status}).`);
      }
      const file = state.stages.flatMap((stage) => stage.evidenceFiles).find((item) => item.id === evidenceId);
      downloadTextFile(file?.name || "governance-evidence", await response.blob(), "application/octet-stream");
    } catch (error) {
      reportError(error);
    }
  }

  async function downloadAudit() {
    try {
      const { data } = await apiRequest(`/api/audit/logs?candidateId=${encodeURIComponent(state.candidateId)}&limit=200`);
      const text = data.events
        .map((event) => `${event.timestamp} | ${event.actor} | ${event.action} | ${event.detail}`)
        .join("\n");
      downloadTextFile(`${state.candidate?.releaseName || "governance"}-audit-log.txt`, text, "text/plain;charset=utf-8");
    } catch (error) {
      reportError(error);
    }
  }
}

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-action]");
  if (!button) return;
  if (button.matches('input[type="checkbox"]')) return;
  if (button.dataset.action === "dismiss-modal" && event.target !== button) return;
  event.preventDefault();
  handleAction(button);
});

document.addEventListener("change", (event) => {
  if (event.target.matches("#evidence-upload")) {
    void addEvidence(event.target.files);
    event.target.value = "";
  } else if (event.target.matches("#candidate-select")) {
    state.candidateId = event.target.value;
    persist();
    void loadCandidate().then(async () => {
      connectEvents();
      if (state.activeView === "access") await loadProjectAccess();
    }).catch(reportError);
  } else if (event.target.matches('input[type="checkbox"][data-action="checklist"]')) {
    handleAction(event.target);
  }
});

document.addEventListener("dragover", (event) => {
  const dropZone = event.target.closest(".drop-zone");
  if (!dropZone) return;
  event.preventDefault();
  dropZone.classList.add("is-dragging");
});

document.addEventListener("dragleave", (event) => {
  const dropZone = event.target.closest(".drop-zone");
  if (dropZone && !dropZone.contains(event.relatedTarget)) {
    dropZone.classList.remove("is-dragging");
  }
});

document.addEventListener("drop", (event) => {
  const dropZone = event.target.closest(".drop-zone");
  if (!dropZone) return;
  event.preventDefault();
  dropZone.classList.remove("is-dragging");
  void addEvidence(event.dataTransfer?.files ?? []);
});

document.addEventListener("submit", (event) => {
  const form = event.target;
  if (!["search-form", "auth-form", "artifact-form", "disposition-form", "candidate-form", "project-member-form", "project-account-form"].includes(form.id)) return;
  event.preventDefault();
  if (form.id === "search-form") {
    state.searchQuery = $("#global-search")?.value.trim() ?? "";
    state.activeView = "search";
    render();
  } else if (form.id === "auth-form") {
    void submitAuthentication(form).catch(reportError);
  } else if (form.id === "artifact-form") {
    void submitArtifact(form).catch(reportError);
  } else if (form.id === "disposition-form") {
    void submitDisposition(form).catch(reportError);
  } else if (form.id === "candidate-form") {
    void createCandidate(form).catch(reportError);
  } else if (form.id === "project-member-form") {
    const formData = new FormData(form);
    void saveProjectMember(String(formData.get("userId")), String(formData.get("role"))).catch(reportError);
  } else if (form.id === "project-account-form") {
    void createProjectAccount(form).catch(reportError);
  }
});

document.addEventListener("keydown", (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
    event.preventDefault();
    $("#global-search")?.focus();
  }
  if (event.key === "Escape" && state.currentModal) {
    state.currentModal = null;
    render();
  }
  if (event.key === "Tab" && state.currentModal) {
    const modal = $(".modal");
    if (!modal) return;
    const focusable = [...modal.querySelectorAll("button:not([disabled]), a[href], input:not([disabled])")];
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }
});

async function submitAuthentication(form) {
  const values = Object.fromEntries(new FormData(form));
  if (state.setupRequired) {
    const { data } = await apiRequest("/api/auth/setup", {
      method: "POST",
      body: {
        username: values.username,
        displayName: values.displayName,
        password: values.password,
      },
      headers: { "X-Bootstrap-Token": String(values.bootstrapToken) },
    });
    state.authenticated = data.authenticated;
    state.user = data.user;
    state.csrfToken = data.csrfToken;
  } else {
    const { data } = await apiRequest("/api/auth/login", {
      method: "POST",
      body: { username: values.username, password: values.password },
    });
    state.authenticated = data.authenticated;
    state.user = data.user;
    state.csrfToken = data.csrfToken;
  }
  state.setupRequired = false;
  const session = await apiRequest("/api/session");
  state.capabilities = session.data.capabilities;
  await refreshCandidates();
  connectEvents();
  showToast("Authenticated governance workspace loaded.");
}

void initialize();

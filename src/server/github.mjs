import { config, assertConfiguredGitHub } from "./config.mjs";
import { assert, HttpError } from "./errors.mjs";

function apiBase() {
  return `${config.github.apiUrl}/repos/${encodeURIComponent(config.github.owner)}/${encodeURIComponent(config.github.repo)}`;
}

async function githubRequest(route, { method = "GET", body, expectedStatuses = [200] } = {}) {
  assertConfiguredGitHub();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20_000);
  let response;
  try {
    response = await fetch(`${apiBase()}${route}`, {
      method,
      signal: controller.signal,
      headers: {
        Authorization: `Bearer ${config.github.token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        ...(body ? { "Content-Type": "application/json" } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
  } catch (error) {
    throw new HttpError(
      error.name === "AbortError" ? 504 : 502,
      error.name === "AbortError" ? "github_timeout" : "github_unavailable",
      "The configured GitHub integration could not complete the request.",
    );
  } finally {
    clearTimeout(timeout);
  }
  const text = await response.text();
  let data = {};
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      throw new HttpError(502, "github_response_invalid", "GitHub returned an invalid API response.");
    }
  }
  if (!expectedStatuses.includes(response.status)) {
    const message = typeof data.message === "string" ? data.message.slice(0, 300) : "request rejected";
    console.error(`GitHub API returned ${response.status}: ${message}`);
    if (response.status === 401 || response.status === 403) {
      throw new HttpError(502, "github_authorization_failed", "The GitHub installation token lacks required repository permissions or has expired.");
    }
    if (response.status === 404) {
      throw new HttpError(502, "github_repository_unavailable", "The configured repository is unavailable to the GitHub installation.");
    }
    if (response.status === 422) {
      throw new HttpError(409, "github_change_rejected", `GitHub rejected the proposed repository change: ${message}`);
    }
    throw new HttpError(502, "github_api_error", `GitHub rejected the integration request (${response.status}).`);
  }
  return data;
}

export async function githubStatus() {
  const repo = await githubRequest("");
  return {
    provider: "github",
    connected: true,
    repository: repo.full_name,
    defaultBranch: repo.default_branch,
    htmlUrl: repo.html_url,
  };
}

export async function checkCommitStatus(sha) {
  assert(
    typeof sha === "string" && /^[a-f0-9]{40}$/i.test(sha),
    400,
    "invalid_commit_sha",
    "A full 40-character Git commit SHA is required.",
  );
  const result = await githubRequest(`/commits/${sha}/status`);
  return { sha, state: result.state, statuses: result.statuses };
}

export async function setCommitStatus({ sha, outcome, description, stageId, targetUrl }) {
  assert(
    typeof sha === "string" && /^[a-f0-9]{40}$/i.test(sha),
    400,
    "invalid_commit_sha",
    "A full 40-character Git commit SHA is required for status updates.",
  );
  assert(
    ["pending", "success", "failure", "error"].includes(outcome),
    400,
    "invalid_commit_status",
    "Commit status must be pending, success, failure, or error.",
  );
  return githubRequest(`/statuses/${sha}`, {
    method: "POST",
    expectedStatuses: [201],
    body: {
      state: outcome,
      context: `govern-ai/${stageId}`,
      description: description.slice(0, 140),
      ...(targetUrl ? { target_url: targetUrl } : {}),
    },
  });
}

export function validateProposal(files) {
  assert(Array.isArray(files) && files.length > 0 && files.length <= 50, 400, "invalid_proposal_files", "Supply 1 to 50 reviewable artifact files.");
  const names = new Set();
  const tree = files.map((file) => {
    assert(
      file && typeof file.path === "string" && typeof file.content === "string",
      400,
      "invalid_proposal_file",
      "Every artifact file needs a path and UTF-8 content.",
    );
    assert(
      file.path.length > 0 &&
        file.path.length <= 200 &&
        file.content.length > 0 &&
        !file.content.includes("\0"),
      400,
      "invalid_proposal_file",
      "Artifact paths and UTF-8 file contents must be non-empty and within their size limits.",
    );
    const safePath = file.path.replaceAll("\\", "/");
    assert(
      safePath.length <= 200 &&
        !safePath.startsWith("/") &&
        !safePath.split("/").some((part) => !part || part === "." || part === "..") &&
        !/[\u0000-\u001f\u007f]/.test(safePath),
      400,
      "invalid_proposal_path",
      "Artifact paths must remain inside the repository and may not contain traversal or empty path components.",
    );
    assert(
      !/(^|\/)(\.env(?:\..*)?|id_rsa|id_ed25519|credentials(?:\.json)?|secrets?\.ya?ml|[^/]*\.pem)$/i.test(safePath),
      400,
      "sensitive_artifact_path",
      "Proposed changes may not write credential or secret files.",
    );
    assert(
      !/\.github\/workflows\//i.test(safePath) &&
        !/^(?:.git|node_modules|vendor)\//i.test(safePath),
      400,
      "restricted_artifact_path",
      "Automated proposals may not modify pipeline workflows, Git metadata, dependencies, or vendored code.",
    );
    assert(!names.has(safePath), 400, "duplicate_artifact_path", "Artifact file paths must be unique.");
    names.add(safePath);
    assert(Buffer.byteLength(file.content, "utf8") <= 200_000, 413, "artifact_file_too_large", "Artifact files must not exceed 200 KB.");
    return { path: safePath, content: file.content };
  });
  return tree;
}

export async function createPullRequest({ title, body, files, baseSha, artifactId }) {
  assert(typeof title === "string" && title.trim().length >= 4 && title.length <= 200, 400, "invalid_pr_title", "Pull request title must be 4 to 200 characters.");
  assert(typeof body === "string" && body.length <= 10_000, 400, "invalid_pr_body", "Pull request description may not exceed 10,000 characters.");
  assert(typeof baseSha === "string" && /^[a-f0-9]{40}$/i.test(baseSha), 400, "invalid_base_sha", "A full 40-character reviewed base commit SHA is required.");
  const validatedFiles = validateProposal(files);
  const defaultBranch = (await githubRequest("")).default_branch;
  const branchName = `govern-ai/${artifactId.replace(/[^a-f0-9-]/gi, "").slice(0, 32)}`;

  const baseCommit = await githubRequest(`/git/commits/${baseSha}`);
  const blobs = [];
  for (const file of validatedFiles) {
    const blob = await githubRequest("/git/blobs", {
      method: "POST",
      expectedStatuses: [201],
      body: { content: file.content, encoding: "utf-8" },
    });
    blobs.push({
      path: file.path,
      mode: "100644",
      type: "blob",
      sha: blob.sha,
    });
  }
  const tree = await githubRequest("/git/trees", {
    method: "POST",
    expectedStatuses: [201],
    body: { base_tree: baseCommit.tree.sha, tree: blobs },
  });
  const commit = await githubRequest("/git/commits", {
    method: "POST",
    expectedStatuses: [201],
    body: {
      message: `${title.trim()}\n\nGenerated proposal ${artifactId}; human review required.`,
      tree: tree.sha,
      parents: [baseSha],
    },
  });
  await githubRequest("/git/refs", {
    method: "POST",
    expectedStatuses: [201],
    body: {
      ref: `refs/heads/${branchName}`,
      sha: commit.sha,
    },
  });
  const pullRequest = await githubRequest("/pulls", {
    method: "POST",
    expectedStatuses: [201],
    body: {
      title: title.trim(),
      body: `${body.trim()}\n\n---\n**AI-generated proposal.** Human review and successful CI checks are required before merge. Governance will reassess the merged release candidate.`,
      head: branchName,
      base: defaultBranch,
      draft: true,
    },
  });
  return {
    branch: branchName,
    commitSha: commit.sha,
    htmlUrl: pullRequest.html_url,
    number: pullRequest.number,
    state: pullRequest.state,
  };
}

export async function commentOnPullRequest(number, body) {
  assert(Number.isSafeInteger(number) && number > 0, 400, "invalid_pr_number", "A positive pull request number is required.");
  assert(typeof body === "string" && body.trim().length > 0 && body.length <= 10_000, 400, "invalid_pr_comment", "A comment between 1 and 10,000 characters is required.");
  return githubRequest(`/issues/${number}/comments`, {
    method: "POST",
    expectedStatuses: [201],
    body: { body },
  });
}

export async function createReleaseTag({ tag, targetSha, message }) {
  assert(typeof tag === "string" && /^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$/i.test(tag), 400, "invalid_release_tag", "Release tag must use the vMAJOR.MINOR.PATCH format.");
  assert(typeof targetSha === "string" && /^[a-f0-9]{40}$/i.test(targetSha), 400, "invalid_commit_sha", "A full 40-character target commit SHA is required.");
  assert(typeof message === "string" && message.length > 0 && message.length <= 1000, 400, "invalid_release_message", "A release description is required.");
  const createdTag = await githubRequest("/git/tags", {
    method: "POST",
    expectedStatuses: [201],
    body: {
      tag,
      message,
      object: { sha: targetSha, type: "commit" },
      type: "commit",
    },
  });
  const reference = await githubRequest("/git/refs", {
    method: "POST",
    expectedStatuses: [201],
    body: { ref: `refs/tags/${tag}`, sha: createdTag.sha },
  });
  return { tag, sha: createdTag.sha, targetSha: reference.object.sha };
}

export async function inspectWebhookDelivery(request, rawBody) {
  assert(Boolean(config.github.webhookSecret), 503, "github_webhook_not_configured", "A GitHub webhook secret must be configured before accepting webhooks.");
  const signature = request.headers["x-hub-signature-256"];
  assert(typeof signature === "string" && /^sha256=[a-f0-9]{64}$/.test(signature), 401, "invalid_webhook_signature", "A valid GitHub webhook signature is required.");
  const { createHmac, timingSafeEqual } = await import("node:crypto");
  const expected = Buffer.from(
    `sha256=${createHmac("sha256", config.github.webhookSecret).update(rawBody).digest("hex")}`,
  );
  const received = Buffer.from(signature);
  assert(expected.length === received.length && timingSafeEqual(expected, received), 401, "invalid_webhook_signature", "The GitHub webhook signature is invalid.");
  const event = request.headers["x-github-event"];
  const deliveryId = request.headers["x-github-delivery"];
  assert(typeof event === "string" && /^[a-z_]{1,100}$/.test(event), 400, "invalid_webhook_event", "A valid GitHub webhook event name is required.");
  assert(typeof deliveryId === "string" && /^[a-f0-9-]{16,100}$/i.test(deliveryId), 400, "invalid_webhook_delivery", "A valid GitHub delivery identifier is required.");
  let body;
  try {
    body = JSON.parse(rawBody.toString("utf8"));
  } catch {
    throw new HttpError(400, "invalid_webhook_json", "The signed GitHub webhook body must contain valid JSON.");
  }
  assert(body && typeof body === "object" && !Array.isArray(body), 400, "invalid_webhook_body", "The signed GitHub webhook body must be a JSON object.");
  return { event, deliveryId, body };
}

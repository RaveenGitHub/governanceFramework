import {
  createHash,
  randomBytes,
  scrypt as nodeScrypt,
  timingSafeEqual,
} from "node:crypto";
import { promisify } from "node:util";
import { config } from "./config.mjs";
import { HttpError, assert } from "./errors.mjs";

const scrypt = promisify(nodeScrypt);
const SCRYPT_OPTIONS = { N: 32_768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const csrfValuePattern = /^[A-Za-z0-9_-]{43}$/;

export async function hashPassword(password) {
  assert(
    typeof password === "string" && Buffer.byteLength(password, "utf8") >= 12,
    400,
    "weak_password",
    "Passwords must be at least 12 UTF-8 bytes long.",
  );
  assert(
    Buffer.byteLength(password, "utf8") <= 1024,
    400,
    "password_too_long",
    "Passwords may not exceed 1,024 UTF-8 bytes.",
  );
  const salt = randomBytes(16);
  const key = await scrypt(password, salt, 64, SCRYPT_OPTIONS);
  return `scrypt$32768$8$1$${salt.toString("base64url")}$${key.toString("base64url")}`;
}

export async function verifyPassword(password, encoded) {
  if (typeof password !== "string" || typeof encoded !== "string") return false;
  const [algorithm, cost, blockSize, parallelism, encodedSalt, encodedKey, extra] =
    encoded.split("$");
  if (
    algorithm !== "scrypt" ||
    cost !== "32768" ||
    blockSize !== "8" ||
    parallelism !== "1" ||
    !encodedSalt ||
    !encodedKey ||
    extra !== undefined ||
    Buffer.byteLength(password, "utf8") > 1024
  ) {
    return false;
  }
  try {
    const salt = Buffer.from(encodedSalt, "base64url");
    const expected = Buffer.from(encodedKey, "base64url");
    if (salt.length !== 16 || expected.length !== 64) return false;
    const actual = await scrypt(password, salt, 64, SCRYPT_OPTIONS);
    return timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

export function newSecret() {
  return randomBytes(32).toString("base64url");
}

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function newOpaqueSession() {
  const sessionToken = randomBytes(32).toString("base64url");
  return { sessionToken, tokenHash: sha256(sessionToken), csrfToken: newSecret() };
}

export function parseCookies(request) {
  const result = new Map();
  for (const part of (request.headers.cookie || "").split(";")) {
    const delimiter = part.indexOf("=");
    if (delimiter < 1) continue;
    const key = part.slice(0, delimiter).trim();
    const value = part.slice(delimiter + 1).trim();
    if (/^[A-Za-z0-9_-]+$/.test(key) && /^[A-Za-z0-9_-]+$/.test(value)) {
      result.set(key, value);
    }
  }
  return result;
}

function isSecureRequest(request) {
  const forwardedProtocol = config.trustProxy
    ? request.headers["x-forwarded-proto"]?.split(",")[0].trim()
    : null;
  return forwardedProtocol === "https";
}

export function sessionCookie(token, request, maxAge = config.sessionLifetimeSeconds) {
  const flags = [
    `${config.cookieName}=${token}`,
    "Path=/",
    "HttpOnly",
    `SameSite=${config.isProduction ? "Strict" : "Lax"}`,
    `Max-Age=${maxAge}`,
  ];
  if (config.isProduction || isSecureRequest(request)) flags.push("Secure");
  return flags.join("; ");
}

export function clearSessionCookie(request) {
  return sessionCookie("", request, 0);
}

function publicOrigin(request) {
  const forwardedProtocol = config.trustProxy
    ? request.headers["x-forwarded-proto"]?.split(",")[0].trim()
    : null;
  const protocol = forwardedProtocol || "http";
  const forwardedHost = config.trustProxy
    ? request.headers["x-forwarded-host"]?.split(",")[0].trim()
    : null;
  const host = forwardedHost || request.headers.host || "";
  if (!/^[A-Za-z0-9.[\]:-]+$/.test(host) || !["http", "https"].includes(protocol)) {
    return null;
  }
  return `${protocol}://${host}`;
}

export function verifyOrigin(request) {
  const fetchSite = request.headers["sec-fetch-site"];
  assert(
    !fetchSite || fetchSite === "same-origin" || fetchSite === "none",
    403,
    "cross_origin_request",
    "Cross-origin requests are not accepted.",
  );
  const origin = request.headers.origin;
  if (!origin) return;
  const expectedOrigin = publicOrigin(request);
  assert(
    expectedOrigin !== null && origin === expectedOrigin,
    403,
    "invalid_origin",
    "The request origin does not match the governance application.",
  );
}

export function verifyCsrf(request, csrfToken) {
  verifyOrigin(request);
  const supplied = request.headers["x-csrf-token"];
  assert(
    typeof supplied === "string" &&
      csrfValuePattern.test(supplied) &&
      csrfToken &&
    Buffer.byteLength(supplied) === Buffer.byteLength(csrfToken) &&
    timingSafeEqual(Buffer.from(supplied), Buffer.from(csrfToken)),
    403,
    "csrf_token_required",
    "A valid anti-CSRF token is required for this operation.",
  );
}

const LOGIN_BUCKET_MS = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 10;
const loginAttempts = new Map();

export function checkLoginRateLimit(request) {
  const forwarded = config.trustProxy
    ? request.headers["x-forwarded-for"]?.split(",")[0].trim()
    : null;
  const address = forwarded || request.socket.remoteAddress || "unknown";
  const now = Date.now();
  const bucket = loginAttempts.get(address);
  if (!bucket || bucket.expiresAt <= now) {
    loginAttempts.set(address, { count: 1, expiresAt: now + LOGIN_BUCKET_MS });
    return;
  }
  bucket.count += 1;
  if (bucket.count > LOGIN_MAX_ATTEMPTS) {
    throw new HttpError(
      429,
      "login_rate_limited",
      "Too many login attempts. Try again in 15 minutes.",
    );
  }
}

export function resetLoginRateLimit(request) {
  const forwarded = config.trustProxy
    ? request.headers["x-forwarded-for"]?.split(",")[0].trim()
    : null;
  loginAttempts.delete(forwarded || request.socket.remoteAddress || "unknown");
}

export function isAllowedRole(role) {
  return config.allowedRoles.includes(role);
}

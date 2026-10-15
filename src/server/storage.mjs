import { createHash, randomUUID } from "node:crypto";
import { mkdir, open, readFile, rm, stat } from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import { config } from "./config.mjs";
import { assert, HttpError } from "./errors.mjs";

const allowedExtensions = new Map([
  [".pdf", "application/pdf"],
  [".md", "text/markdown"],
  [".markdown", "text/markdown"],
  [".txt", "text/plain"],
  [".csv", "text/csv"],
  [".json", "application/json"],
  [".xml", "application/xml"],
  [".yaml", "application/yaml"],
  [".yml", "application/yaml"],
  [".svg", "image/svg+xml"],
  [".png", "image/png"],
  [".jpg", "image/jpeg"],
  [".jpeg", "image/jpeg"],
]);
const textExtensions = new Set([
  ".md",
  ".markdown",
  ".txt",
  ".csv",
  ".json",
  ".xml",
  ".yaml",
  ".yml",
]);
const signatureHex = /^[a-f0-9]{64}$/;

function extensionOf(filename) {
  return path.extname(filename).toLowerCase();
}

function contentSignature(extension, data) {
  if (extension === ".pdf") return data.subarray(0, 5).toString("ascii") === "%PDF-";
  if (extension === ".png") return data.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
  if (extension === ".jpg" || extension === ".jpeg") return data[0] === 0xff && data[1] === 0xd8 && data[2] === 0xff;
  if (extension === ".svg" || textExtensions.has(extension)) {
    if (data.includes(0)) return false;
    try {
      new TextDecoder("utf-8", { fatal: true }).decode(data);
      return true;
    } catch {
      return false;
    }
  }
  return false;
}

export function validateEvidenceName(filename) {
  assert(
    typeof filename === "string" && Buffer.byteLength(filename) <= 255,
    400,
    "invalid_filename",
    "A valid filename no longer than 255 bytes is required.",
  );
  const basename = path.basename(filename.replaceAll("\\", "/"));
  assert(
    basename === filename &&
      basename !== "." &&
      basename !== ".." &&
      !/[\u0000-\u001f\u007f]/.test(basename),
    400,
    "invalid_filename",
    "Path separators, traversal, and control characters are not permitted in filenames.",
  );
  const extension = extensionOf(basename);
  assert(
    allowedExtensions.has(extension),
    415,
    "unsupported_evidence_type",
    "Allowed evidence formats are PDF, Markdown, plain text, CSV, JSON, XML, YAML, SVG, PNG, and JPEG.",
  );
  return { originalName: basename, extension, contentType: allowedExtensions.get(extension) };
}

async function clamAvScan(data) {
  if (!config.clamav.host) {
    return { status: "unscanned", detail: "ClamAV is not configured; the evidence remains ineligible for release." };
  }
  return new Promise((resolve) => {
    const socket = net.createConnection({
      host: config.clamav.host,
      port: config.clamav.port,
    });
    let response = Buffer.alloc(0);
    let settled = false;
    const timer = setTimeout(() => {
      socket.destroy(new Error("Antivirus scanner timed out."));
    }, config.clamav.timeoutMs);

    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(result);
    };

    socket.on("connect", () => {
      socket.write(Buffer.from("zINSTREAM\0"));
      for (let offset = 0; offset < data.length; offset += 64 * 1024) {
        const chunk = data.subarray(offset, offset + 64 * 1024);
        const header = Buffer.allocUnsafe(4);
        header.writeUInt32BE(chunk.length);
        socket.write(header);
        socket.write(chunk);
      }
      socket.write(Buffer.alloc(4));
    });

    socket.on("data", (chunk) => {
      response = Buffer.concat([response, chunk]);
      if (response.length > 8192) {
        finish({ status: "scan_error", detail: "Antivirus scanner returned an oversized response." });
        return;
      }
      if (!response.includes(0)) return;
      const message = response.toString("utf8").replace(/\0.*$/s, "").trim();
      if (/\bOK$/.test(message)) {
        finish({ status: "clean", detail: "ClamAV verified this file as free of detected malware." });
      } else if (/\bFOUND$/.test(message)) {
        finish({ status: "infected", detail: "ClamAV detected malware in this file." });
      } else {
        finish({ status: "scan_error", detail: "Antivirus scanner returned an unrecognized result." });
      }
    });

    socket.on("error", (error) => {
      finish({
        status: "scan_error",
        detail: "Evidence scanner is unavailable. Restore the configured scanner before release.",
      });
      console.error("Evidence scanner connection failed.", error.message);
    });

    socket.on("close", () => {
      if (!settled && response.length) {
        finish({ status: "scan_error", detail: "Antivirus scanner closed without a final response." });
      }
    });
  });
}

export async function rescanEvidenceFile(evidence) {
  assert(
    evidence &&
      /^[0-9a-f-]{36}\.[a-z0-9]+$/.test(evidence.storage_name),
    400,
    "evidence_storage_path_invalid",
    "The stored evidence reference is invalid.",
  );
  const filename = path.join(config.evidenceRoot, evidence.storage_name);
  let data;
  try {
    data = await readFile(filename);
  } catch (error) {
    if (error.code === "ENOENT") {
      throw new HttpError(404, "evidence_file_missing", "The stored evidence file is unavailable.");
    }
    throw error;
  }
  assert(
    data.length === evidence.size_bytes &&
      createHash("sha256").update(data).digest("hex") === evidence.sha256,
    500,
    "evidence_integrity_failed",
    "The evidence file failed its integrity check; the file cannot be rescanned.",
  );
  return clamAvScan(data);
}

export function scannerAvailable() {
  return Boolean(config.clamav.host);
}

export async function saveEvidenceFile({ filename, bytes, candidateId, stageId, actor }) {
  assert(Buffer.isBuffer(bytes), 500, "invalid_file_buffer", "The evidence upload was not a valid byte stream.");
  assert(
    bytes.length > 0 && bytes.length <= config.maxUploadBytes,
    413,
    "evidence_size_exceeded",
    "Evidence must contain between 1 byte and 25 MiB.",
  );

  const { originalName, extension, contentType } = validateEvidenceName(filename);
  assert(
    contentSignature(extension, bytes),
    415,
    "evidence_content_type_mismatch",
    "The file contents do not match its declared format.",
  );

  const id = randomUUID();
  const storageName = `${id}${extension}`;
  const target = path.join(config.evidenceRoot, storageName);
  assert(
    path.dirname(target) === config.evidenceRoot,
    400,
    "invalid_storage_path",
    "The requested evidence path is invalid.",
  );

  await mkdir(config.evidenceRoot, { recursive: true, mode: 0o700 });
  const handle = await open(target, "wx", 0o600);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } catch (error) {
    await handle.close();
    await rm(target, { force: true });
    throw error;
  }
  await handle.close();

  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const scan = await clamAvScan(bytes);
  if (scan.status === "infected") {
    await rm(target, { force: true });
  }
  return {
    id,
    candidateId,
    stageId,
    originalName,
    storageName,
    contentType,
    sizeBytes: bytes.length,
    sha256,
    scanStatus: scan.status,
    scanDetail: scan.detail,
    uploadedBy: actor.id,
  };
}

export async function loadEvidenceFile(evidence) {
  assert(evidence, 404, "evidence_not_found", "The requested evidence was not found.");
  assert(signatureHex.test(evidence.sha256), 500, "evidence_integrity_invalid", "The stored evidence integrity record is invalid.");
  assert(/^[0-9a-f-]{36}\.[a-z0-9]+$/.test(evidence.storage_name), 500, "evidence_storage_path_invalid", "The evidence storage reference is invalid.");
  const filePath = path.join(config.evidenceRoot, evidence.storage_name);
  assert(
    path.dirname(filePath) === config.evidenceRoot,
    500,
    "evidence_storage_path_invalid",
    "The evidence storage reference is invalid.",
  );
  try {
    const fileStat = await stat(filePath);
    assert(fileStat.isFile(), 404, "evidence_file_missing", "The stored evidence file is unavailable.");
  } catch (error) {
    if (error.code === "ENOENT") {
      throw new HttpError(404, "evidence_file_missing", "The stored evidence file is unavailable.");
    }
    throw error;
  }
  let contents;
  try {
    contents = await readFile(filePath);
  } catch (error) {
    if (error.code === "ENOENT") {
      throw new HttpError(404, "evidence_file_missing", "The stored evidence file is unavailable.");
    }
    throw error;
  }
  assert(
    createHash("sha256").update(contents).digest("hex") === evidence.sha256,
    500,
    "evidence_integrity_failed",
    "The evidence file failed its integrity check.",
  );
  return contents;
}

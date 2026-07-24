import { ScanInputError, scanDomain } from "../lib/scan-service.mjs";

const MAX_BODY_BYTES = 32_000;

export default async function handler(request, response) {
  applyApiHeaders(response);

  if (request.method === "OPTIONS") {
    return response.status(204).end();
  }

  if (request.method !== "POST") {
    response.setHeader("Allow", "POST, OPTIONS");
    return response.status(405).json({ error: "Method not allowed." });
  }

  try {
    const body = await readJsonBody(request);
    const result = await scanDomain(body?.domain);
    return response.status(200).json(result);
  } catch (error) {
    if (error instanceof ScanInputError) {
      return response.status(error.statusCode).json({ error: error.message });
    }

    console.error("Rootline scan failed", error);
    return response.status(502).json({
      error:
        error instanceof Error
          ? error.message
          : "The public inventory service is temporarily unavailable.",
    });
  }
}

function applyApiHeaders(response) {
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Cache-Control", "no-store, max-age=0");
  response.setHeader("Access-Control-Allow-Origin", "*");
  response.setHeader("Access-Control-Allow-Headers", "Content-Type");
  response.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  response.setHeader("X-Content-Type-Options", "nosniff");
}

async function readJsonBody(request) {
  const declaredLength = Number(request.headers?.["content-length"] || 0);
  if (declaredLength > MAX_BODY_BYTES) {
    throw new ScanInputError("Request body is too large.", 413);
  }

  if (request.body && typeof request.body === "object" && !Buffer.isBuffer(request.body)) {
    return request.body;
  }

  if (typeof request.body === "string" || Buffer.isBuffer(request.body)) {
    return parseJson(String(request.body));
  }

  const chunks = [];
  let size = 0;

  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      throw new ScanInputError("Request body is too large.", 413);
    }
    chunks.push(chunk);
  }

  return parseJson(Buffer.concat(chunks).toString("utf8"));
}

function parseJson(value) {
  try {
    return JSON.parse(value || "{}");
  } catch {
    throw new ScanInputError("Request body must contain valid JSON.");
  }
}

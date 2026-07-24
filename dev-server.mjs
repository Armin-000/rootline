import http from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ScanInputError, scanDomain } from "./lib/scan-service.mjs";

const root = path.dirname(fileURLToPath(import.meta.url));
const publicRoot = path.join(root, "public");
const port = Number(process.env.PORT || 4173);
const host = process.env.HOST || "0.0.0.0";
const MAX_BODY_BYTES = 32_000;

const publicFiles = new Set([
  "/index.html",
  "/styles.css",
  "/app.js",
  "/theme-init.js",
  "/sw.js",
  "/manifest.webmanifest",
]);

const mimeTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".webmanifest": "application/manifest+json; charset=utf-8",
};

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);

  try {
    if (url.pathname === "/api/health") {
      if (request.method !== "GET") {
        return sendJson(response, 405, { error: "Method not allowed." }, { Allow: "GET" });
      }

      return sendJson(response, 200, {
        ok: true,
        service: "rootline-api",
        runtime: process.version,
        timestamp: new Date().toISOString(),
      });
    }

    if (url.pathname === "/api/scan") {
      if (request.method === "OPTIONS") {
        return sendJson(response, 204, null);
      }

      if (request.method !== "POST") {
        return sendJson(response, 405, { error: "Method not allowed." }, { Allow: "POST, OPTIONS" });
      }

      const body = parseJson(await readRequestBody(request));
      const result = await scanDomain(body?.domain);
      return sendJson(response, 200, result);
    }

    if (url.pathname.startsWith("/api/")) {
      return sendJson(response, 404, { error: "API route not found." });
    }

    const requestPath = url.pathname === "/" ? "/index.html" : decodeURIComponent(url.pathname);
    const isAsset = requestPath.startsWith("/assets/");

    if (!publicFiles.has(requestPath) && !isAsset) {
      return sendText(response, 404, "Not found");
    }

    const filePath = path.resolve(publicRoot, `.${requestPath}`);
    if (!filePath.startsWith(publicRoot)) {
      return sendText(response, 403, "Forbidden");
    }

    const content = await readFile(filePath);
    const extension = path.extname(filePath).toLowerCase();
    response.writeHead(200, {
      "Content-Type": mimeTypes[extension] || "application/octet-stream",
      "Cache-Control": extension === ".html" || requestPath === "/sw.js" ? "no-cache" : "public, max-age=60",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "strict-origin-when-cross-origin",
    });
    response.end(content);
  } catch (error) {
    if (error instanceof ScanInputError) {
      return sendJson(response, error.statusCode, { error: error.message });
    }

    console.error("Local server error", error);
    return sendJson(response, 500, { error: "Internal server error." });
  }
});

server.listen(port, host, () => {
  console.log(`Rootline is running at http://localhost:${port}`);
  console.log(`Phone access: http://<your-computer-ip>:${port}`);
  console.log(`API health: http://localhost:${port}/api/health`);
});

function readRequestBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;

    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new ScanInputError("Request body is too large.", 413));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });

    request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    request.on("error", reject);
  });
}

function parseJson(value) {
  try {
    return JSON.parse(value || "{}");
  } catch {
    throw new ScanInputError("Request body must contain valid JSON.");
  }
}

function sendJson(response, statusCode, body, extraHeaders = {}) {
  response.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store, max-age=0",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "X-Content-Type-Options": "nosniff",
    ...extraHeaders,
  });
  response.end(body === null ? "" : JSON.stringify(body));
}

function sendText(response, statusCode, body) {
  response.writeHead(statusCode, {
    "Content-Type": "text/plain; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  response.end(body);
}

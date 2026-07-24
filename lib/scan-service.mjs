import dns from "node:dns/promises";
import net from "node:net";

const MAX_HOSTS = 48;
const DNS_CONCURRENCY = 12;
const HTTPS_CONCURRENCY = 12;
const DISCOVERY_TIMEOUT_MS = 8_000;
const HTTPS_TIMEOUT_MS = 4_500;
const USER_AGENT = "Rootline/4.0 (+public-domain-inventory)";

export class ScanInputError extends Error {
  constructor(message, statusCode = 400) {
    super(message);
    this.name = "ScanInputError";
    this.statusCode = statusCode;
  }
}

export async function scanDomain(rawDomain) {
  const startedAt = Date.now();
  const domain = normalizeDomain(rawDomain);
  const validation = validateDomain(domain);

  if (!validation.ok) {
    throw new ScanInputError(validation.message);
  }

  const discovery = await discoverHostnames(domain);
  const names = discovery.names.slice(0, MAX_HOSTS);

  const dnsResults = await mapWithConcurrency(names, DNS_CONCURRENCY, resolveHost);
  const hosts = await mapWithConcurrency(dnsResults, HTTPS_CONCURRENCY, enrichHttps);

  hosts.sort((a, b) => {
    if (a.hostname === domain) return -1;
    if (b.hostname === domain) return 1;
    return a.hostname.localeCompare(b.hostname);
  });

  return {
    domain,
    source: discovery.source,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    truncated: discovery.names.length > MAX_HOSTS,
    limit: MAX_HOSTS,
    hosts,
  };
}

async function discoverHostnames(domain) {
  const results = new Set([domain]);

  try {
    const certSpotterUrl = new URL("https://api.certspotter.com/v1/issuances");
    certSpotterUrl.searchParams.set("domain", domain);
    certSpotterUrl.searchParams.set("include_subdomains", "true");
    certSpotterUrl.searchParams.set("expand", "dns_names");

    const records = await fetchJson(certSpotterUrl, 2);

    for (const record of Array.isArray(records) ? records : []) {
      for (const name of Array.isArray(record?.dns_names) ? record.dns_names : []) {
        addCandidate(results, name, domain);
      }
    }

    if (results.size > 1) {
      return { names: sortNames(results, domain), source: "Cert Spotter" };
    }
  } catch (error) {
    console.warn("Cert Spotter failed", error instanceof Error ? error.message : error);
  }

  try {
    const crtUrl = new URL("https://crt.sh/");
    crtUrl.searchParams.set("q", `%.${domain}`);
    crtUrl.searchParams.set("output", "json");

    const records = await fetchJson(crtUrl, 1);

    for (const record of Array.isArray(records) ? records : []) {
      for (const name of String(record?.name_value || "").split("\n")) {
        addCandidate(results, name, domain);
      }
    }

    return {
      names: sortNames(results, domain),
      source: results.size > 1 ? "crt.sh" : "DNS root check",
    };
  } catch (error) {
    console.warn("crt.sh failed", error instanceof Error ? error.message : error);
  }

  return { names: [domain], source: "DNS root check" };
}

function addCandidate(set, rawName, rootDomain) {
  const name = String(rawName || "")
    .trim()
    .toLowerCase()
    .replace(/^\*\./, "")
    .replace(/\.$/, "");

  if (!name || name.length > 253) return;
  if (!(name === rootDomain || name.endsWith(`.${rootDomain}`))) return;
  if (!isValidHostname(name)) return;

  set.add(name);
}

async function resolveHost(hostname) {
  const [ipv4, ipv6, cname] = await Promise.all([
    resolveSafe(() => dns.resolve4(hostname)),
    resolveSafe(() => dns.resolve6(hostname)),
    resolveSafe(() => dns.resolveCname(hostname)),
  ]);

  const uniqueIpv4 = unique(ipv4);
  const uniqueIpv6 = unique(ipv6);
  const uniqueCname = unique(cname.map((value) => value.replace(/\.$/, "")));
  const allIps = [...uniqueIpv4, ...uniqueIpv6];
  const hasPrivateAddress = allIps.some(isPrivateIp);

  return {
    hostname,
    ipv4: uniqueIpv4,
    ipv6: uniqueIpv6,
    cname: uniqueCname,
    dnsResolved: Boolean(uniqueIpv4.length || uniqueIpv6.length || uniqueCname.length),
    safeToProbe: Boolean(allIps.length) && !hasPrivateAddress,
  };
}

async function enrichHttps(host) {
  if (!host.dnsResolved) {
    return withHttpsResult(host, {
      ok: false,
      status: null,
      responseTime: null,
      finalUrl: null,
      error: "No public DNS record resolved.",
    });
  }

  if (!host.safeToProbe) {
    return withHttpsResult(host, {
      ok: false,
      status: null,
      responseTime: null,
      finalUrl: null,
      error: "HTTPS probing was skipped because the hostname did not resolve to a public IP address.",
    });
  }

  const lookupAddresses = await resolveSafe(() =>
    dns.lookup(host.hostname, { all: true, verbatim: true }),
  );
  const reboundToPrivate = lookupAddresses.some((entry) => isPrivateIp(entry.address));

  if (reboundToPrivate) {
    return withHttpsResult(host, {
      ok: false,
      status: null,
      responseTime: null,
      finalUrl: null,
      error: "HTTPS probing was blocked because DNS resolved to a private address.",
    });
  }

  const target = `https://${host.hostname}/`;
  const startedAt = Date.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), HTTPS_TIMEOUT_MS);

  try {
    let result = await fetch(target, {
      method: "HEAD",
      redirect: "follow",
      signal: controller.signal,
      headers: requestHeaders(),
    });

    if (result.status === 405 || result.status === 501) {
      result = await fetch(target, {
        method: "GET",
        redirect: "follow",
        signal: controller.signal,
        headers: {
          ...requestHeaders(),
          Range: "bytes=0-0",
        },
      });
    }

    return withHttpsResult(host, {
      ok: true,
      status: result.status,
      responseTime: Date.now() - startedAt,
      finalUrl: result.url || target,
      error: null,
    });
  } catch (error) {
    return withHttpsResult(host, {
      ok: false,
      status: null,
      responseTime: Date.now() - startedAt,
      finalUrl: null,
      error: humanizeFetchError(error),
    });
  } finally {
    clearTimeout(timeout);
  }
}

function withHttpsResult(host, https) {
  const { safeToProbe: _safeToProbe, ...publicHost } = host;
  return { ...publicHost, https };
}

async function fetchJson(url, attempts) {
  let lastError;

  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), DISCOVERY_TIMEOUT_MS);

    try {
      const result = await fetch(url, {
        signal: controller.signal,
        headers: {
          "User-Agent": USER_AGENT,
          Accept: "application/json",
        },
      });

      if (!result.ok) {
        throw new Error(`${url.hostname} returned HTTP ${result.status}.`);
      }

      return await result.json();
    } catch (error) {
      lastError = error;
      if (attempt < attempts) {
        await delay(300 * attempt);
      }
    } finally {
      clearTimeout(timeout);
    }
  }

  throw lastError || new Error("The certificate source did not respond.");
}

async function resolveSafe(operation) {
  try {
    const result = await operation();
    return Array.isArray(result) ? result : [];
  } catch {
    return [];
  }
}

async function mapWithConcurrency(items, concurrency, worker) {
  const results = new Array(items.length);
  let cursor = 0;

  async function run() {
    while (true) {
      const index = cursor;
      cursor += 1;
      if (index >= items.length) return;
      results[index] = await worker(items[index], index);
    }
  }

  const workerCount = Math.min(concurrency, Math.max(items.length, 1));
  await Promise.all(Array.from({ length: workerCount }, run));
  return results;
}

export function normalizeDomain(value) {
  let domain = String(value || "").trim().toLowerCase();
  domain = domain.replace(/^https?:\/\//, "");
  domain = domain.split(/[/?#]/)[0];
  domain = domain.replace(/^www\./, "");
  domain = domain.replace(/\.$/, "");
  return domain;
}

export function validateDomain(domain) {
  if (!domain) return { ok: false, message: "Enter a root domain." };
  if (!isValidHostname(domain)) {
    return { ok: false, message: "Enter a valid public root domain." };
  }
  if (!domain.includes(".")) {
    return { ok: false, message: "Include a public suffix such as .com or .hr." };
  }

  const blockedSuffixes = [".local", ".internal", ".lan", ".home", ".localhost"];
  if (domain === "localhost" || blockedSuffixes.some((suffix) => domain.endsWith(suffix))) {
    return { ok: false, message: "Private and local domains are not supported." };
  }

  return { ok: true };
}

function isValidHostname(value) {
  return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(value);
}

export function isPrivateIp(address) {
  const version = net.isIP(address);
  if (!version) return true;

  if (version === 4) {
    const [a, b, c] = address.split(".").map(Number);

    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 0) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 88 && c === 99) ||
      (a === 198 && (b === 18 || b === 19)) ||
      (a === 192 && b === 0 && c === 2) ||
      (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113) ||
      a >= 224
    );
  }

  const normalized = address.toLowerCase();
  if (normalized.startsWith("::ffff:")) {
    return isPrivateIp(normalized.slice(7));
  }

  return (
    normalized === "::" ||
    normalized === "::1" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe8") ||
    normalized.startsWith("fe9") ||
    normalized.startsWith("fea") ||
    normalized.startsWith("feb") ||
    normalized.startsWith("ff") ||
    normalized.startsWith("2001:db8")
  );
}

function requestHeaders() {
  return {
    "User-Agent": USER_AGENT,
    Accept: "text/html,application/xhtml+xml,*/*;q=0.8",
  };
}

function humanizeFetchError(error) {
  if (error?.name === "AbortError") return "HTTPS request timed out.";
  const message = error instanceof Error ? error.message : "HTTPS request failed.";
  if (/certificate|tls|ssl/i.test(message)) return "TLS or certificate negotiation failed.";
  if (/fetch failed/i.test(message)) return "The HTTPS endpoint did not accept the connection.";
  return message.slice(0, 180);
}

function sortNames(set, rootDomain) {
  return [...set].sort((a, b) => {
    if (a === rootDomain) return -1;
    if (b === rootDomain) return 1;
    return a.localeCompare(b);
  });
}

function unique(values) {
  return [...new Set(values.filter(Boolean).map(String))];
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

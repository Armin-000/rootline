import dns from "node:dns/promises";
import net from "node:net";
import { randomBytes } from "node:crypto";
import { SUBDOMAIN_WORDLIST } from "./subdomain-wordlist.mjs";

const MAX_HOSTS = 64;
const DNS_CONCURRENCY = 16;
const HTTPS_CONCURRENCY = 12;
const DISCOVERY_TIMEOUT_MS = 8_000;
const HTTPS_TIMEOUT_MS = 4_500;
const CERT_SPOTTER_MAX_PAGES = 4;
const MAX_REDIRECTS = 5;
const PUBLIC_WEB_MAX_DOCUMENTS = 8;
const PUBLIC_WEB_MAX_BYTES = 256_000;
const PUBLIC_WEB_MAX_LABELS = 480;
const ACTIVE_DNS_MAX_CANDIDATES = 1_800;
const ACTIVE_DNS_BATCH_SIZE = 120;
const USER_AGENT = "Rootline/4.4 (+public-domain-inventory)";

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
  const enrichedHosts = await mapWithConcurrency(dnsResults, HTTPS_CONCURRENCY, enrichHttps);
  const hosts = enrichedHosts.map((host) => ({
    ...host,
    sources: discovery.hostSources[host.hostname] || [],
  }));

  hosts.sort((a, b) => {
    if (a.hostname === domain) return -1;
    if (b.hostname === domain) return 1;
    return a.hostname.localeCompare(b.hostname);
  });

  return {
    domain,
    source: discovery.source,
    sources: discovery.sources,
    wildcardDetected: discovery.wildcardDetected,
    dnsWildcardDetected: discovery.dnsWildcardDetected,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    truncated: discovery.names.length > MAX_HOSTS,
    limit: MAX_HOSTS,
    hosts,
  };
}

async function discoverHostnames(domain) {
  const results = new Set([domain]);
  const hostSources = new Map();
  const sources = [];
  let wildcardDetected = false;

  addHostSource(hostSources, domain, "Root domain");

  try {
    const certSpotterResult = await discoverFromCertSpotter(domain, results, hostSources);
    wildcardDetected ||= certSpotterResult.wildcardDetected;
    if (certSpotterResult.recordsSeen > 0 || certSpotterResult.wildcardDetected) sources.push("Cert Spotter");
  } catch (error) {
    console.warn("Cert Spotter failed", error instanceof Error ? error.message : error);
  }

  try {
    const crtResult = await discoverFromCrtSh(domain, results, hostSources);
    wildcardDetected ||= crtResult.wildcardDetected;
    if (crtResult.recordsSeen > 0 || crtResult.wildcardDetected) sources.push("crt.sh");
  } catch (error) {
    console.warn("crt.sh failed", error instanceof Error ? error.message : error);
  }

  try {
    const hackerTargetResult = await discoverFromHackerTarget(domain, results, hostSources);
    if (hackerTargetResult.recordsSeen > 0) sources.push("HackerTarget");
  } catch (error) {
    console.warn("HackerTarget failed", error instanceof Error ? error.message : error);
  }

  try {
    const dnsRelationResult = await discoverFromRootDnsRelations(domain, results, hostSources);
    if (dnsRelationResult.recordsSeen > 0) sources.push("DNS records");
  } catch (error) {
    console.warn("DNS relation discovery failed", error instanceof Error ? error.message : error);
  }

  // Mine the public root site before Active DNS. Besides direct hostnames,
  // branded product/project words can become DNS candidates automatically.
  let publicWebLabels = [];
  try {
    const webResult = await discoverFromPublicWeb(domain, results, hostSources);
    publicWebLabels = webResult.labels;
    if (webResult.observed > 0) sources.push("Public web");
  } catch (error) {
    console.warn("Public web discovery failed", error instanceof Error ? error.message : error);
  }

  // Active DNS is bounded and batch-based. Wildcard DNS is checked first to
  // prevent an authoritative wildcard from turning every candidate into a
  // false positive.
  const dnsWildcardDetected = await detectWildcardDns(domain);
  let activeDnsMatches = 0;

  if (!dnsWildcardDetected) {
    activeDnsMatches = await discoverWordlistDnsNames(
      domain,
      results,
      hostSources,
      publicWebLabels,
    );
    if (activeDnsMatches > 0) sources.push("Active DNS");
  }

  const hostEvidenceSources = [...hostSources.values()]
    .flatMap((values) => [...values])
    .filter((value) => value !== "Root domain");
  const uniqueSources = unique([...sources, ...hostEvidenceSources]);
  const source = uniqueSources.length ? uniqueSources.join(" + ") : "DNS root check";

  return {
    names: sortNames(results, domain),
    source,
    sources: uniqueSources,
    hostSources: Object.fromEntries(
      [...hostSources.entries()].map(([hostname, values]) => [hostname, [...values]]),
    ),
    wildcardDetected,
    dnsWildcardDetected,
    activeDnsMatches,
  };
}

async function discoverFromCertSpotter(domain, results, hostSources) {
  const url = new URL("https://api.certspotter.com/v1/issuances");
  url.searchParams.set("domain", domain);
  url.searchParams.set("include_subdomains", "true");
  url.searchParams.set("expand", "dns_names");

  const initialSize = results.size;
  let after = "";
  let pages = 0;
  let recordsSeen = 0;
  let wildcardDetected = false;

  while (pages < CERT_SPOTTER_MAX_PAGES) {
    if (after) url.searchParams.set("after", after);
    else url.searchParams.delete("after");

    let records;
    try {
      records = await fetchJson(url, 2);
    } catch (error) {
      if (recordsSeen === 0) throw error;
      console.warn(
        "Cert Spotter pagination stopped after partial success",
        error instanceof Error ? error.message : error,
      );
      break;
    }

    const page = Array.isArray(records) ? records : [];
    pages += 1;

    if (!page.length) break;

    recordsSeen += page.length;

    for (const record of page) {
      for (const name of Array.isArray(record?.dns_names) ? record.dns_names : []) {
        wildcardDetected = addCandidate(results, name, domain, hostSources, "Cert Spotter") || wildcardDetected;
      }
    }

    const lastId = page.at(-1)?.id;
    if (!lastId || String(lastId) === after) break;
    after = String(lastId);
  }

  return { recordsSeen, wildcardDetected, added: results.size - initialSize };
}

async function discoverFromCrtSh(domain, results, hostSources) {
  const url = new URL("https://crt.sh/");
  url.searchParams.set("q", `%.${domain}`);
  url.searchParams.set("output", "json");

  const initialSize = results.size;
  const records = await fetchJson(url, 1);
  const rows = Array.isArray(records) ? records : [];
  let wildcardDetected = false;

  for (const record of rows) {
    for (const name of String(record?.name_value || "").split("\n")) {
      wildcardDetected = addCandidate(results, name, domain, hostSources, "crt.sh") || wildcardDetected;
    }
  }

  return { recordsSeen: rows.length, wildcardDetected, added: results.size - initialSize };
}

async function discoverFromHackerTarget(domain, results, hostSources) {
  const initialSize = results.size;
  const url = new URL("https://api.hackertarget.com/hostsearch/");
  url.searchParams.set("q", domain);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DISCOVERY_TIMEOUT_MS);

  try {
    const headers = {
      "User-Agent": USER_AGENT,
      Accept: "text/plain",
    };

    if (process.env.HACKERTARGET_API_KEY) {
      headers["X-API-Key"] = process.env.HACKERTARGET_API_KEY;
    }

    const response = await fetch(url, {
      signal: controller.signal,
      headers,
    });

    if (!response.ok) {
      throw new Error(`api.hackertarget.com returned HTTP ${response.status}.`);
    }

    const body = (await response.text()).trim();

    if (!body || /^error\b/i.test(body) || /api count exceeded/i.test(body)) {
      return { added: 0, recordsSeen: 0 };
    }

    let recordsSeen = 0;

    for (const line of body.split(/\r?\n/)) {
      const [hostname] = line.split(",", 1);
      const normalized = String(hostname || "").trim().toLowerCase().replace(/\.$/, "");
      if (normalized === domain || normalized.endsWith(`.${domain}`)) recordsSeen += 1;
      addCandidate(results, hostname, domain, hostSources, "HackerTarget");
    }

    return { added: results.size - initialSize, recordsSeen };
  } finally {
    clearTimeout(timeout);
  }
}

async function discoverFromRootDnsRelations(domain, results, hostSources) {
  const initialSize = results.size;
  const [mx, ns, cname] = await Promise.all([
    resolveSafe(() => dns.resolveMx(domain)),
    resolveSafe(() => dns.resolveNs(domain)),
    resolveSafe(() => dns.resolveCname(domain)),
  ]);

  for (const record of mx) {
    addCandidate(results, record?.exchange, domain, hostSources, "DNS records");
  }

  for (const hostname of ns) {
    addCandidate(results, hostname, domain, hostSources, "DNS records");
  }

  for (const hostname of cname) {
    addCandidate(results, hostname, domain, hostSources, "DNS records");
  }

  const recordsSeen = [...mx.map((record) => record?.exchange), ...ns, ...cname]
    .map((value) => String(value || "").toLowerCase().replace(/\.$/, ""))
    .filter((value) => value === domain || value.endsWith(`.${domain}`)).length;

  return { added: results.size - initialSize, recordsSeen };
}

function addCandidate(set, rawName, rootDomain, hostSources, source) {
  const raw = String(rawName || "").trim().toLowerCase().replace(/\.$/, "");
  const wildcard = raw.startsWith("*.");
  const name = wildcard ? raw.slice(2) : raw;

  if (!name || name.length > 253) return wildcard;
  if (!(name === rootDomain || name.endsWith(`.${rootDomain}`))) return wildcard;
  if (!isValidHostname(name)) return wildcard;

  if (!wildcard) {
    set.add(name);
    addHostSource(hostSources, name, source);
  }

  return wildcard;
}

function addHostSource(hostSources, hostname, source) {
  if (!source) return;

  if (!hostSources.has(hostname)) {
    hostSources.set(hostname, new Set());
  }

  hostSources.get(hostname).add(source);
}

async function detectWildcardDns(domain) {
  const probes = Array.from(
    { length: 2 },
    () => `rootline-${randomBytes(8).toString("hex")}.${domain}`,
  );

  const checks = await Promise.all(probes.map(hostnameHasPublicDns));
  return checks.every(Boolean);
}

async function discoverWordlistDnsNames(domain, results, hostSources, publicWebLabels = []) {
  const labels = buildSubdomainLabels(domain, publicWebLabels);
  const remainingSlots = Math.max(MAX_HOSTS - results.size, 0);

  if (!remainingSlots) return 0;

  const candidates = labels
    .map((label) => `${label}.${domain}`)
    .filter((hostname) => !results.has(hostname))
    .slice(0, ACTIVE_DNS_MAX_CANDIDATES);

  let matches = 0;

  for (let offset = 0; offset < candidates.length; offset += ACTIVE_DNS_BATCH_SIZE) {
    const batch = candidates.slice(offset, offset + ACTIVE_DNS_BATCH_SIZE);
    const checks = await mapWithConcurrency(
      batch,
      DNS_CONCURRENCY,
      async (hostname) => ({
        hostname,
        resolved: await hostnameHasPublicDns(hostname),
      }),
    );

    for (const check of checks) {
      if (!check.resolved) continue;

      results.add(check.hostname);
      addHostSource(hostSources, check.hostname, "Active DNS");
      matches += 1;

      if (matches >= remainingSlots) return matches;
    }
  }

  return matches;
}

function buildSubdomainLabels(domain, publicWebLabels = []) {
  const rootLabel = String(domain || "")
    .split(".")
    .filter(Boolean)[0]
    ?.toLowerCase();

  const rootDerived = [];

  if (rootLabel && /^[a-z0-9-]{2,40}$/.test(rootLabel)) {
    const suffixes = [
      "ai",
      "app",
      "api",
      "admin",
      "cloud",
      "dev",
      "labs",
      "studio",
      "portal",
      "hub",
      "console",
      "platform",
      "status",
    ];

    for (const suffix of suffixes) {
      rootDerived.push(`${rootLabel}${suffix}`);
      rootDerived.push(`${rootLabel}-${suffix}`);
      rootDerived.push(`${suffix}-${rootLabel}`);
    }
  }

  const compoundPrefixes = [
    "root",
    "cloud",
    "data",
    "dev",
    "code",
    "app",
    "web",
    "net",
    "core",
    "open",
    "smart",
    "live",
    "auto",
    "secure",
    "clear",
    "deep",
    "hyper",
    "meta",
    "cyber",
    "tech",
    "edge",
    "ocean",
  ];
  const compoundSuffixes = [
    "line",
    "hub",
    "lab",
    "labs",
    "box",
    "base",
    "stack",
    "works",
    "flow",
    "cloud",
    "net",
    "link",
    "node",
    "zone",
    "space",
    "studio",
    "ai",
    "app",
    "api",
    "dev",
    "ops",
    "data",
    "tech",
    "one",
    "pro",
    "portal",
  ];
  const compounds = [];

  for (const prefix of compoundPrefixes) {
    for (const suffix of compoundSuffixes) {
      if (prefix === suffix) continue;
      compounds.push(`${prefix}${suffix}`);
      compounds.push(`${prefix}-${suffix}`);
    }
  }

  return unique([
    ...publicWebLabels,
    ...SUBDOMAIN_WORDLIST,
    ...rootDerived,
    ...compounds,
  ])
    .filter((value) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(value))
    .slice(0, ACTIVE_DNS_MAX_CANDIDATES);
}

async function discoverFromPublicWeb(domain, results, hostSources) {
  const initialSize = results.size;
  const initialHosts = sortNames(results, domain).slice(0, 6);
  const documents = [];
  const labels = new Map();
  let observed = 0;

  // Root metadata files often reference canonical application hosts.
  documents.push(`https://${domain}/`);
  documents.push(`https://${domain}/robots.txt`);
  documents.push(`https://${domain}/sitemap.xml`);

  if (!initialHosts.includes(`www.${domain}`)) {
    documents.push(`https://www.${domain}/`);
  }

  for (const hostname of initialHosts) {
    if (hostname === domain) continue;
    documents.push(`https://${hostname}/`);
  }

  const urls = unique(documents).slice(0, PUBLIC_WEB_MAX_DOCUMENTS);

  for (const target of urls) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), HTTPS_TIMEOUT_MS);

      try {
        const { response } = await fetchWithSafeRedirects(target, {
          method: "GET",
          signal: controller.signal,
          headers: {
            ...requestHeaders(),
            Accept: "text/html,text/plain,application/xml,text/xml,*/*;q=0.2",
            Range: `bytes=0-${PUBLIC_WEB_MAX_BYTES - 1}`,
          },
        });

        if (!response.ok) continue;

        const contentType = String(response.headers.get("content-type") || "").toLowerCase();
        if (
          contentType &&
          !contentType.includes("text/") &&
          !contentType.includes("html") &&
          !contentType.includes("xml") &&
          !contentType.includes("json")
        ) {
          continue;
        }

        const body = await readResponseTextLimited(response, PUBLIC_WEB_MAX_BYTES);
        const hostnames = extractRootDomainHostnames(body, domain);
        observed += hostnames.length;

        for (const hostname of hostnames) {
          addCandidate(results, hostname, domain, hostSources, "Public web");
        }

        // Headings and document titles usually contain product/project names.
        // Give those labels a large ranking boost so one-off branded names are
        // not pushed out by more frequent generic body copy.
        for (const label of extractPriorityDiscoveryLabels(body)) {
          labels.set(label, (labels.get(label) || 0) + 1_000);
        }

        for (const [label, score] of extractDiscoveryLabels(body)) {
          labels.set(label, (labels.get(label) || 0) + score);
        }
      } finally {
        clearTimeout(timeout);
      }
    } catch {
      // Public-web discovery is best effort. One unavailable document should
      // never fail the domain inventory.
    }
  }

  const rankedLabels = [...labels.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, PUBLIC_WEB_MAX_LABELS)
    .map(([label]) => label);

  return { added: results.size - initialSize, observed, labels: rankedLabels };
}

function extractPriorityDiscoveryLabels(text) {
  const source = String(text || "");
  const fragments = [];
  const elementPattern = /<(title|h[1-6])\b[^>]*>([\s\S]*?)<\/\1>/gi;

  for (const match of source.matchAll(elementPattern)) {
    fragments.push(
      String(match[2] || "")
        .replace(/<[^>]+>/g, " ")
        .replace(/&[a-z0-9#]+;/gi, " "),
    );
  }

  const labels = [];

  for (const fragment of fragments) {
    for (const [label] of extractDiscoveryLabels(fragment)) {
      labels.push(label);
    }
  }

  return unique(labels);
}

function extractDiscoveryLabels(text) {
  const ignored = new Set([
    "about", "after", "again", "also", "and", "aria", "assets", "before", "build",
    "button", "canonical", "case", "class", "click", "codarox", "content", "could",
    "data", "description", "domain", "each", "engineering", "example", "features",
    "from", "have", "help", "href", "html", "https", "image", "into", "javascript",
    "link", "main", "meta", "more", "name", "page", "portfolio", "project", "public",
    "real", "rel", "script", "section", "software", "span", "style", "that", "their",
    "this", "title", "type", "using", "with", "your",
  ]);

  const cleaned = String(text || "")
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .toLowerCase();
  const counts = new Map();

  for (const match of cleaned.matchAll(/\b[a-z][a-z0-9-]{2,31}\b/g)) {
    const token = match[0].replace(/^-+|-+$/g, "");
    if (!token || ignored.has(token)) continue;
    if (/^\d+$/.test(token)) continue;
    counts.set(token, (counts.get(token) || 0) + 1);
  }

  return [...counts.entries()];
}

function extractRootDomainHostnames(text, domain) {
  const escapedDomain = escapeRegExp(domain);
  const pattern = new RegExp(
    `(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+${escapedDomain}`,
    "gi",
  );

  return unique(
    (String(text || "").match(pattern) || [])
      .map((value) => value.toLowerCase().replace(/\.$/, ""))
      .filter((value) => value === domain || value.endsWith(`.${domain}`)),
  );
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function readResponseTextLimited(response, maxBytes) {
  if (!response.body) return "";

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;

  try {
    while (total < maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value?.length) continue;

      const remaining = maxBytes - total;
      const chunk = value.length > remaining ? value.slice(0, remaining) : value;
      chunks.push(chunk);
      total += chunk.length;

      if (chunk.length < value.length) break;
    }
  } finally {
    try {
      await reader.cancel();
    } catch {
      // Nothing to do.
    }
  }

  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.length;
  }

  return new TextDecoder("utf-8", { fatal: false }).decode(merged);
}

async function hostnameHasPublicDns(hostname) {
  const addresses = await resolveSafe(() =>
    dns.lookup(hostname, { all: true, verbatim: true }),
  );

  if (addresses.length) return true;

  const cname = await resolveSafe(() => dns.resolveCname(hostname));
  return cname.length > 0;
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

  const target = `https://${host.hostname}/`;
  const startedAt = Date.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), HTTPS_TIMEOUT_MS);

  try {
    let { response: result, finalUrl } = await fetchWithSafeRedirects(target, {
      method: "HEAD",
      signal: controller.signal,
      headers: requestHeaders(),
    });

    if (result.status === 405 || result.status === 501) {
      ({ response: result, finalUrl } = await fetchWithSafeRedirects(target, {
        method: "GET",
        signal: controller.signal,
        headers: {
          ...requestHeaders(),
          Range: "bytes=0-0",
        },
      }));
    }

    return withHttpsResult(host, {
      ok: true,
      status: result.status,
      responseTime: Date.now() - startedAt,
      finalUrl,
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

async function fetchWithSafeRedirects(startUrl, init) {
  let currentUrl = new URL(startUrl);

  for (let redirectCount = 0; redirectCount <= MAX_REDIRECTS; redirectCount += 1) {
    await assertPublicFetchTarget(currentUrl);

    const response = await fetch(currentUrl, {
      ...init,
      redirect: "manual",
    });

    if (!isRedirectStatus(response.status)) {
      return { response, finalUrl: currentUrl.toString() };
    }

    const location = response.headers.get("location");

    if (!location) {
      return { response, finalUrl: currentUrl.toString() };
    }

    if (redirectCount === MAX_REDIRECTS) {
      throw new Error("HTTPS endpoint exceeded the redirect limit.");
    }

    currentUrl = new URL(location, currentUrl);
  }

  throw new Error("HTTPS endpoint exceeded the redirect limit.");
}

async function assertPublicFetchTarget(url) {
  if (!(url.protocol === "https:" || url.protocol === "http:")) {
    throw new Error("Redirect target used an unsupported protocol.");
  }

  if (net.isIP(url.hostname)) {
    if (isPrivateIp(url.hostname)) {
      throw new Error("Redirect target resolved to a private or reserved address.");
    }
    return;
  }

  if (!isValidHostname(url.hostname)) {
    throw new Error("Redirect target hostname is invalid.");
  }

  const addresses = await resolveSafe(() =>
    dns.lookup(url.hostname, { all: true, verbatim: true }),
  );

  if (!addresses.length) {
    throw new Error("Redirect target did not resolve in public DNS.");
  }

  if (addresses.some((entry) => isPrivateIp(entry.address))) {
    throw new Error("Redirect target resolved to a private or reserved address.");
  }
}

function isRedirectStatus(status) {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
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

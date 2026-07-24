const STORAGE_KEYS = {
  theme: "rootline-theme-v3",
  history: "rootline-history-v3",
};

const THEMES = Object.freeze({
  light: "light",
  dark: "dark",
});

const THEME_COLORS = Object.freeze({
  light: "#f6f7f4",
  dark: "#171a18",
});

const state = {
  scan: null,
  filter: "all",
  search: "",
  sort: "hostname",
  history: loadHistory(),
  progressTimer: null,
};

const dom = {
  root: document.documentElement,
  scanForm: document.querySelector("#scanForm"),
  domainInput: document.querySelector("#domainInput"),
  domainField: document.querySelector("#domainField"),
  domainError: document.querySelector("#domainError"),
  clearDomainButton: document.querySelector("#clearDomainButton"),
  scanSubmit: document.querySelector("#scanSubmit"),
  newScanButton: document.querySelector("#newScanButton"),
  mobileScanButton: document.querySelector("#mobileScanButton"),
  themeToggles: [...document.querySelectorAll("[data-theme-toggle]")],
  themeColorMeta: document.querySelector('meta[name="theme-color"]'),
  openHistoryButton: document.querySelector("#openHistoryButton"),
  closeHistoryButton: document.querySelector("#closeHistoryButton"),
  historyPanel: document.querySelector("#historyPanel"),
  historyList: document.querySelector("#historyList"),
  clearHistoryButton: document.querySelector("#clearHistoryButton"),
  drawerBackdrop: document.querySelector("#drawerBackdrop"),
  detailsDrawer: document.querySelector("#detailsDrawer"),
  drawerTitle: document.querySelector("#drawerTitle"),
  drawerBody: document.querySelector("#drawerBody"),
  closeDrawerButton: document.querySelector("#closeDrawerButton"),
  loadingOverlay: document.querySelector("#loadingOverlay"),
  loadingTitle: document.querySelector("#loadingTitle"),
  loadingMessage: document.querySelector("#loadingMessage"),
  loadingProgressBar: document.querySelector("#loadingProgressBar"),
  metricHosts: document.querySelector("#metricHosts"),
  metricHostsDelta: document.querySelector("#metricHostsDelta"),
  metricHttps: document.querySelector("#metricHttps"),
  metricHttpsMeta: document.querySelector("#metricHttpsMeta"),
  hostsMeter: document.querySelector("#hostsMeter"),
  httpsMeter: document.querySelector("#httpsMeter"),
  resultsSection: document.querySelector("#resultsSection"),
  resultsTitle: document.querySelector("#resultsTitle"),
  resultsSubtitle: document.querySelector("#resultsSubtitle"),
  resultsTableBody: document.querySelector("#resultsTableBody"),
  mobileResults: document.querySelector("#mobileResults"),
  filteredEmpty: document.querySelector("#filteredEmpty"),
  hostSearch: document.querySelector("#hostSearch"),
  sortSelect: document.querySelector("#sortSelect"),
  exportCsvButton: document.querySelector("#exportCsvButton"),
  exportJsonButton: document.querySelector("#exportJsonButton"),
  copyReportButton: document.querySelector("#copyReportButton"),
  clearResultsButton: document.querySelector("#clearResultsButton"),
  resultsExportButton: document.querySelector("#resultsExportButton"),
  filterAllCount: document.querySelector("#filterAllCount"),
  filterSecureCount: document.querySelector("#filterSecureCount"),
  filterDnsCount: document.querySelector("#filterDnsCount"),
  filterUnresolvedCount: document.querySelector("#filterUnresolvedCount"),
  toastRegion: document.querySelector("#toastRegion"),
};

initialize();

function initialize() {
  initializeTheme();
  buildMeter(dom.hostsMeter);
  buildMeter(dom.httpsMeter);
  bindEvents();
  renderHistory();

  if ("serviceWorker" in navigator && location.protocol === "https:") {
    navigator.serviceWorker.register("/sw.js").catch(() => undefined);
  }
}

function bindEvents() {
  dom.scanForm.addEventListener("submit", handleScanSubmit);

  dom.domainInput.addEventListener("input", () => {
    clearDomainError();
    dom.clearDomainButton.hidden = dom.domainInput.value.length === 0;
  });

  dom.domainInput.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      dom.domainInput.value = "";
      dom.clearDomainButton.hidden = true;
      clearDomainError();
    }
  });

  dom.clearDomainButton.addEventListener("click", () => {
    dom.domainInput.value = "";
    dom.clearDomainButton.hidden = true;
    clearDomainError();
    dom.domainInput.focus();
  });

  document.querySelectorAll("[data-domain]").forEach((button) => {
    button.addEventListener("click", () => {
      dom.domainInput.value = button.dataset.domain || "";
      dom.clearDomainButton.hidden = false;
      clearDomainError();
      dom.domainInput.focus();
    });
  });

  [dom.newScanButton, dom.mobileScanButton].filter(Boolean).forEach((button) => {
    button.addEventListener("click", focusDomainInput);
  });

  dom.themeToggles.forEach((button) => button.addEventListener("click", toggleTheme));
  dom.openHistoryButton.addEventListener("click", openHistory);
  dom.closeHistoryButton.addEventListener("click", closePanels);
  dom.closeDrawerButton.addEventListener("click", closePanels);
  dom.drawerBackdrop.addEventListener("click", closePanels);

  dom.clearHistoryButton.addEventListener("click", () => {
    state.history = [];
    saveHistory();
    renderHistory();
    showToast("Local history cleared.");
  });

  dom.exportCsvButton.addEventListener("click", exportCsv);
  dom.exportJsonButton.addEventListener("click", exportJson);
  dom.resultsExportButton.addEventListener("click", exportCsv);
  dom.copyReportButton.addEventListener("click", copyReport);
  dom.clearResultsButton.addEventListener("click", clearWorkspace);

  dom.hostSearch.addEventListener("input", () => {
    state.search = dom.hostSearch.value.trim().toLowerCase();
    renderResults();
  });

  dom.sortSelect.addEventListener("change", () => {
    state.sort = dom.sortSelect.value;
    renderResults();
  });

  document.querySelectorAll("[data-filter]").forEach((button) => {
    button.addEventListener("click", () => {
      state.filter = button.dataset.filter || "all";
      document.querySelectorAll("[data-filter]").forEach((item) => {
        item.classList.toggle("is-active", item === button);
      });
      renderResults();
    });
  });

  document.querySelectorAll("[data-section]").forEach((button) => {
    button.addEventListener("click", () => navigateSection(button.dataset.section, button));
  });

  document.querySelectorAll("[data-view]").forEach((button) => {
    button.addEventListener("click", () => navigateView(button.dataset.view, button));
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closePanels();
  });
}

async function handleScanSubmit(event) {
  event.preventDefault();

  const domain = normalizeDomain(dom.domainInput.value);
  const validation = validateDomain(domain);

  if (!validation.ok) {
    showDomainError(validation.message);
    return;
  }

  dom.domainInput.value = domain;
  dom.clearDomainButton.hidden = false;
  setLoading(true, domain);

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
    });

    const payload = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(payload.error || `The scan failed with HTTP ${response.status}.`);
    }

    const scan = normalizeScanPayload(payload, domain);
    state.scan = scan;
    state.filter = "all";
    state.search = "";
    state.sort = "hostname";

    dom.hostSearch.value = "";
    dom.sortSelect.value = "hostname";
    document.querySelectorAll("[data-filter]").forEach((button) => {
      button.classList.toggle("is-active", button.dataset.filter === "all");
    });

    rememberScan(scan);
    renderDashboard();
    renderResults();
    setResultActionsEnabled(true);
    dom.resultsSection.hidden = false;

    requestAnimationFrame(() => {
      dom.resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
    });

    showToast(`Inventory built for ${scan.domain}.`);
  } catch (error) {
    showDomainError(error instanceof Error ? error.message : "The inventory could not be built.");
    showToast("The inventory could not be built.", "error");
  } finally {
    setLoading(false);
  }
}

function normalizeScanPayload(payload, fallbackDomain) {
  const hosts = Array.isArray(payload.hosts)
    ? payload.hosts.map((host) => ({
        hostname: String(host.hostname || "").toLowerCase(),
        ipv4: toStringArray(host.ipv4),
        ipv6: toStringArray(host.ipv6),
        cname: toStringArray(host.cname),
        dnsResolved: Boolean(host.dnsResolved || toStringArray(host.ipv4).length || toStringArray(host.ipv6).length || toStringArray(host.cname).length),
        https: {
          ok: Boolean(host.https?.ok),
          status: Number.isFinite(Number(host.https?.status)) ? Number(host.https.status) : null,
          responseTime: Number.isFinite(Number(host.https?.responseTime)) ? Number(host.https.responseTime) : null,
          finalUrl: typeof host.https?.finalUrl === "string" ? host.https.finalUrl : null,
          error: typeof host.https?.error === "string" ? host.https.error : null,
        },
      }))
    : [];

  const sortedHosts = hosts.filter((host) => host.hostname).sort((a, b) => a.hostname.localeCompare(b.hostname));

  return {
    domain: String(payload.domain || fallbackDomain).toLowerCase(),
    scannedAt: payload.scannedAt || new Date().toISOString(),
    source: String(payload.source || "Public certificate records"),
    hosts: sortedHosts,
    durationMs: Number.isFinite(Number(payload.durationMs)) ? Number(payload.durationMs) : null,
  };
}

function renderDashboard() {
  if (!state.scan) return;

  const summary = getSummary(state.scan.hosts);
  const percentage = summary.total ? Math.round((summary.secure / summary.total) * 100) : 0;

  dom.metricHosts.textContent = formatNumber(summary.total);
  dom.metricHostsDelta.textContent = `${summary.resolved} resolve in DNS`;
  dom.metricHttps.textContent = `${percentage}%`;
  dom.metricHttpsMeta.textContent = `${summary.secure} of ${summary.total} hosts`;

  fillMeter(dom.hostsMeter, summary.total ? summary.resolved / summary.total : 0);
  fillMeter(dom.httpsMeter, summary.total ? summary.secure / summary.total : 0);
}

function renderResults() {
  if (!state.scan) return;

  const allHosts = state.scan.hosts;
  const summary = getSummary(allHosts);
  const visibleHosts = getVisibleHosts(allHosts);

  dom.resultsTitle.textContent = state.scan.domain;
  dom.resultsSubtitle.textContent = `${allHosts.length} public host${allHosts.length === 1 ? "" : "s"} discovered via ${state.scan.source}.`;
  dom.filterAllCount.textContent = String(summary.total);
  dom.filterSecureCount.textContent = String(summary.secure);
  dom.filterDnsCount.textContent = String(summary.dnsOnly);
  dom.filterUnresolvedCount.textContent = String(summary.unresolved);

  dom.resultsTableBody.innerHTML = visibleHosts.map(renderTableRow).join("");
  dom.mobileResults.innerHTML = visibleHosts.map(renderMobileCard).join("");
  dom.filteredEmpty.hidden = visibleHosts.length > 0;

  bindResultActions();
}

function renderTableRow(host) {
  const classification = classifyHost(host);
  const primaryIp = host.ipv4[0] || host.ipv6[0] || host.cname[0] || "No public record";
  const statusText = host.https.ok ? `HTTP ${host.https.status || 200}` : host.dnsResolved ? "No HTTPS" : "Unresolved";
  const responseText = typeof host.https.responseTime === "number" ? `${host.https.responseTime} ms` : "—";
  const initial = host.hostname.replace(/^www\./, "").charAt(0) || "•";

  return `
    <tr>
      <td>
        <div class="host-cell">
          <span class="host-cell__mark">${escapeHtml(initial)}</span>
          <span class="host-cell__copy">
            <strong>${escapeHtml(host.hostname)}</strong>
            <small>${escapeHtml(primaryIp)}</small>
          </span>
        </div>
      </td>
      <td>${host.dnsResolved ? `${host.ipv4.length + host.ipv6.length + host.cname.length} record${host.ipv4.length + host.ipv6.length + host.cname.length === 1 ? "" : "s"}` : "—"}</td>
      <td><span class="status-pill status-pill--${classification}">${escapeHtml(statusText)}</span></td>
      <td>${escapeHtml(responseText)}</td>
      <td>
        <div class="row-actions">
          <button class="row-action" type="button" data-action="copy" data-host="${escapeAttribute(host.hostname)}" aria-label="Copy hostname">
            <svg viewBox="0 0 24 24" aria-hidden="true"><rect x="8" y="8" width="10" height="10" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/></svg>
          </button>
          <button class="row-action" type="button" data-action="details" data-host="${escapeAttribute(host.hostname)}" aria-label="View details">
            <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8"/><path d="M12 11v5M12 8h.01"/></svg>
          </button>
          ${host.https.ok ? `<button class="row-action" type="button" data-action="open" data-host="${escapeAttribute(host.hostname)}" aria-label="Open website"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 17 17 7M9 7h8v8"/></svg></button>` : ""}
        </div>
      </td>
    </tr>
  `;
}

function renderMobileCard(host) {
  const classification = classifyHost(host);
  const primaryIp = host.ipv4[0] || host.ipv6[0] || host.cname[0] || "No public record";
  const statusText = host.https.ok ? `HTTP ${host.https.status || 200}` : host.dnsResolved ? "DNS only" : "Unresolved";
  const responseText = typeof host.https.responseTime === "number" ? `${host.https.responseTime} ms` : "—";

  return `
    <article class="host-card">
      <div class="host-card__top">
        <div class="host-card__title">
          <strong>${escapeHtml(host.hostname)}</strong>
          <small>${escapeHtml(primaryIp)}</small>
        </div>
        <span class="status-pill status-pill--${classification}">${escapeHtml(statusText)}</span>
      </div>
      <div class="host-card__stats">
        <div class="host-card__stat"><span>IPv4</span><strong>${host.ipv4.length || "—"}</strong></div>
        <div class="host-card__stat"><span>DNS records</span><strong>${host.ipv4.length + host.ipv6.length + host.cname.length || "—"}</strong></div>
        <div class="host-card__stat"><span>Response</span><strong>${escapeHtml(responseText)}</strong></div>
      </div>
      <div class="host-card__actions">
        ${host.https.ok ? `<button class="host-card__open" type="button" data-action="open" data-host="${escapeAttribute(host.hostname)}">Open website</button>` : `<button class="host-card__open" type="button" data-action="copy" data-host="${escapeAttribute(host.hostname)}">Copy hostname</button>`}
        <button class="host-card__details" type="button" data-action="details" data-host="${escapeAttribute(host.hostname)}" aria-label="View details">
          <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8"/><path d="M12 11v5M12 8h.01"/></svg>
        </button>
      </div>
    </article>
  `;
}

function bindResultActions() {
  document.querySelectorAll("[data-action][data-host]").forEach((button) => {
    button.addEventListener("click", () => {
      const host = state.scan?.hosts.find((item) => item.hostname === button.dataset.host);
      if (!host) return;

      switch (button.dataset.action) {
        case "copy":
          copyText(host.hostname, "Hostname copied.");
          break;
        case "open":
          window.open(host.https.finalUrl || `https://${host.hostname}`, "_blank", "noopener,noreferrer");
          break;
        case "details":
          openDetails(host);
          break;
        default:
          break;
      }
    });
  });
}

function openDetails(host) {
  dom.drawerTitle.textContent = host.hostname;
  dom.drawerBody.innerHTML = `
    <section class="detail-section">
      <div class="detail-grid">
        <div class="detail-item"><span>DNS status</span><strong>${host.dnsResolved ? "Resolved" : "Unresolved"}</strong></div>
        <div class="detail-item"><span>HTTPS status</span><strong>${host.https.ok ? `HTTP ${host.https.status || 200}` : "Unavailable"}</strong></div>
        <div class="detail-item"><span>Response time</span><strong>${typeof host.https.responseTime === "number" ? `${host.https.responseTime} ms` : "Not measured"}</strong></div>
        <div class="detail-item"><span>Final URL</span><strong>${escapeHtml(host.https.finalUrl || "—")}</strong></div>
      </div>
    </section>
    ${renderRecordSection("IPv4 records", host.ipv4)}
    ${renderRecordSection("IPv6 records", host.ipv6)}
    ${renderRecordSection("CNAME records", host.cname)}
    ${host.https.error ? `<section class="detail-section"><h3>HTTPS note</h3><ul class="record-list"><li>${escapeHtml(host.https.error)}</li></ul></section>` : ""}
    <section class="detail-section">
      <div class="drawer-actions">
        <button class="drawer-action drawer-action--primary" type="button" id="drawerCopyHost">Copy hostname</button>
        <button class="drawer-action" type="button" id="drawerOpenHost" ${host.https.ok ? "" : "disabled"}>Open website</button>
      </div>
    </section>
  `;

  document.querySelector("#drawerCopyHost")?.addEventListener("click", () => copyText(host.hostname, "Hostname copied."));
  document.querySelector("#drawerOpenHost")?.addEventListener("click", () => {
    window.open(host.https.finalUrl || `https://${host.hostname}`, "_blank", "noopener,noreferrer");
  });

  openPanel(dom.detailsDrawer);
}

function renderRecordSection(title, values) {
  const records = values.length ? values.map((value) => `<li>${escapeHtml(value)}</li>`).join("") : "<li>No public record returned</li>";
  return `<section class="detail-section"><h3>${escapeHtml(title)}</h3><ul class="record-list">${records}</ul></section>`;
}

function getVisibleHosts(hosts) {
  const filtered = hosts.filter((host) => {
    const className = classifyHost(host);
    const matchesFilter =
      state.filter === "all" ||
      (state.filter === "secure" && className === "secure") ||
      (state.filter === "dns" && className === "dns") ||
      (state.filter === "unresolved" && className === "unresolved");

    if (!matchesFilter) return false;
    if (!state.search) return true;

    const haystack = [host.hostname, ...host.ipv4, ...host.ipv6, ...host.cname].join(" ").toLowerCase();
    return haystack.includes(state.search);
  });

  return filtered.sort((a, b) => {
    if (state.sort === "status") {
      const order = { secure: 0, dns: 1, unresolved: 2 };
      return order[classifyHost(a)] - order[classifyHost(b)] || a.hostname.localeCompare(b.hostname);
    }

    if (state.sort === "response") {
      const aTime = a.https.responseTime ?? Number.POSITIVE_INFINITY;
      const bTime = b.https.responseTime ?? Number.POSITIVE_INFINITY;
      return aTime - bTime || a.hostname.localeCompare(b.hostname);
    }

    return a.hostname.localeCompare(b.hostname);
  });
}

function classifyHost(host) {
  if (host.https.ok) return "secure";
  if (host.dnsResolved) return "dns";
  return "unresolved";
}

function getSummary(hosts) {
  const summary = {
    total: hosts.length,
    secure: 0,
    dnsOnly: 0,
    unresolved: 0,
    resolved: 0,
  };

  for (const host of hosts) {
    if (host.dnsResolved) summary.resolved += 1;
    if (host.https.ok) summary.secure += 1;
    else if (host.dnsResolved) summary.dnsOnly += 1;
    else summary.unresolved += 1;
  }

  return summary;
}

function rememberScan(scan) {
  const summary = getSummary(scan.hosts);
  const entry = {
    id: `${scan.domain}-${scan.scannedAt}`,
    domain: scan.domain,
    scannedAt: scan.scannedAt,
    source: scan.source,
    hosts: scan.hosts.slice(0, 80),
    summary,
  };

  state.history = [entry, ...state.history.filter((item) => item.domain !== scan.domain)].slice(0, 8);
  saveHistory();
  renderHistory();
}

function renderHistory() {
  if (!state.history.length) {
    dom.historyList.innerHTML = `<div class="history-empty"><p>Your recent inventories stay on this device.</p></div>`;
    dom.clearHistoryButton.disabled = true;
    return;
  }

  dom.clearHistoryButton.disabled = false;
  dom.historyList.innerHTML = state.history
    .map(
      (entry) => `
        <button class="history-entry" type="button" data-history-id="${escapeAttribute(entry.id)}">
          <span><strong>${escapeHtml(entry.domain)}</strong><small>${escapeHtml(formatDate(entry.scannedAt))} · ${escapeHtml(entry.source || "Public records")}</small></span>
          <span class="history-entry__count">${entry.summary?.total ?? entry.hosts?.length ?? 0}</span>
        </button>
      `,
    )
    .join("");

  document.querySelectorAll("[data-history-id]").forEach((button) => {
    button.addEventListener("click", () => {
      const entry = state.history.find((item) => item.id === button.dataset.historyId);
      if (!entry) return;

      state.scan = normalizeScanPayload(entry, entry.domain);
      state.filter = "all";
      state.search = "";
      state.sort = "hostname";
      dom.hostSearch.value = "";
      dom.sortSelect.value = "hostname";
      dom.domainInput.value = entry.domain;
      dom.clearDomainButton.hidden = false;
      dom.resultsSection.hidden = false;
      setResultActionsEnabled(true);
      renderDashboard();
      renderResults();
      closePanels();
      requestAnimationFrame(() => dom.resultsSection.scrollIntoView({ behavior: "smooth", block: "start" }));
    });
  });
}

function exportCsv() {
  if (!state.scan) return;

  const header = ["hostname", "ipv4", "ipv6", "cname", "dns_resolved", "https_ok", "http_status", "response_time_ms", "final_url"];
  const rows = state.scan.hosts.map((host) => [
    host.hostname,
    host.ipv4.join(" | "),
    host.ipv6.join(" | "),
    host.cname.join(" | "),
    host.dnsResolved,
    host.https.ok,
    host.https.status ?? "",
    host.https.responseTime ?? "",
    host.https.finalUrl ?? "",
  ]);

  const csv = [header, ...rows].map((row) => row.map(csvValue).join(",")).join("\n");
  downloadFile(`${state.scan.domain}-inventory.csv`, csv, "text/csv;charset=utf-8");
  showToast("CSV export created.");
}

function exportJson() {
  if (!state.scan) return;
  downloadFile(`${state.scan.domain}-inventory.json`, JSON.stringify(state.scan, null, 2), "application/json;charset=utf-8");
  showToast("JSON export created.");
}

function copyReport() {
  if (!state.scan) return;
  const summary = getSummary(state.scan.hosts);
  const report = [
    `Rootline inventory — ${state.scan.domain}`,
    `Scanned: ${formatDate(state.scan.scannedAt)}`,
    `Source: ${state.scan.source}`,
    `Discovered hosts: ${summary.total}`,
    `DNS resolved: ${summary.resolved}`,
    `HTTPS active: ${summary.secure}`,
    `Unresolved: ${summary.unresolved}`,
    "",
    ...state.scan.hosts.map((host) => `${host.hostname} | ${host.ipv4.join(", ") || host.cname.join(", ") || "unresolved"} | ${host.https.ok ? `HTTP ${host.https.status || 200}` : "no HTTPS"}`),
  ].join("\n");

  copyText(report, "Report copied.");
}

function clearWorkspace() {
  state.scan = null;
  state.filter = "all";
  state.search = "";
  state.sort = "hostname";
  dom.domainInput.value = "";
  dom.clearDomainButton.hidden = true;
  dom.hostSearch.value = "";
  dom.metricHosts.textContent = "—";
  dom.metricHostsDelta.textContent = "Waiting for scan";
  dom.metricHttps.textContent = "—";
  dom.metricHttpsMeta.textContent = "No data";
  fillMeter(dom.hostsMeter, 0);
  fillMeter(dom.httpsMeter, 0);
  dom.resultsSection.hidden = true;
  setResultActionsEnabled(false);
  focusDomainInput();
}

function navigateSection(section, clickedButton) {
  document.querySelectorAll("[data-section]").forEach((button) => button.classList.toggle("is-active", button === clickedButton));

  if (section === "overview") {
    document.querySelector("#overviewSection")?.scrollIntoView({ behavior: "smooth", block: "start" });
    return;
  }


  if (!state.scan) {
    showToast("Build an inventory first.");
    focusDomainInput();
    return;
  }

  state.filter = section === "dns" ? "dns" : "all";
  document.querySelectorAll("[data-filter]").forEach((button) => {
    button.classList.toggle("is-active", button.dataset.filter === state.filter);
  });
  renderResults();
  dom.resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
}

function navigateView(view, clickedButton) {
  document.querySelectorAll(`[data-view]`).forEach((button) => {
    if (button.closest(".sidebar") || button.closest(".mobile-nav")) {
      button.classList.toggle("is-active", button.dataset.view === view);
    }
  });

  if (view === "history") {
    openHistory();
    return;
  }

  if (view === "overview") {
    document.querySelector("#overviewSection")?.scrollIntoView({ behavior: "smooth", block: "start" });
    return;
  }

  if (!state.scan) {
    showToast("Build an inventory first.");
    focusDomainInput();
    return;
  }

  state.filter = view === "records" ? "dns" : "all";
  document.querySelectorAll("[data-filter]").forEach((button) => {
    button.classList.toggle("is-active", button.dataset.filter === state.filter);
  });
  renderResults();
  dom.resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
}

function focusDomainInput() {
  closePanels();
  document.querySelector(".scan-card")?.scrollIntoView({ behavior: "smooth", block: "center" });
  window.setTimeout(() => dom.domainInput.focus({ preventScroll: true }), 380);
}

function openHistory() {
  renderHistory();
  openPanel(dom.historyPanel);
}

function openPanel(panel) {
  closePanels();
  dom.drawerBackdrop.hidden = false;
  panel.classList.add("is-open");
  panel.setAttribute("aria-hidden", "false");
  document.body.style.overflow = "hidden";
}

function closePanels() {
  [dom.detailsDrawer, dom.historyPanel].forEach((panel) => {
    panel.classList.remove("is-open");
    panel.setAttribute("aria-hidden", "true");
  });
  dom.drawerBackdrop.hidden = true;
  document.body.style.overflow = "";
}

function setLoading(isLoading, domain = "") {
  dom.scanSubmit.disabled = isLoading;
  dom.scanSubmit.classList.toggle("is-loading", isLoading);
  dom.loadingOverlay.hidden = !isLoading;

  if (!isLoading) {
    window.clearInterval(state.progressTimer);
    state.progressTimer = null;
    dom.loadingProgressBar.style.width = "20%";
    return;
  }

  const stages = [
    ["Discovering public hosts", `Reading certificate transparency records for ${domain}.`, 28],
    ["Resolving DNS records", "Checking IPv4, IPv6 and canonical names.", 54],
    ["Probing HTTPS", "Measuring reachability and response behavior.", 78],
    ["Preparing inventory", "Structuring the final host report.", 92],
  ];

  let index = 0;
  const update = () => {
    const [title, message, progress] = stages[Math.min(index, stages.length - 1)];
    dom.loadingTitle.textContent = title;
    dom.loadingMessage.textContent = message;
    dom.loadingProgressBar.style.width = `${progress}%`;
    index += 1;
  };

  update();
  state.progressTimer = window.setInterval(update, 1150);
}

function setResultActionsEnabled(enabled) {
  [dom.exportCsvButton, dom.exportJsonButton, dom.copyReportButton, dom.clearResultsButton].forEach((button) => {
    button.disabled = !enabled;
  });
}

function initializeTheme() {
  applyTheme(readStoredTheme());
}

function readStoredTheme() {
  try {
    return localStorage.getItem(STORAGE_KEYS.theme) === THEMES.dark
      ? THEMES.dark
      : THEMES.light;
  } catch {
    return THEMES.light;
  }
}

function toggleTheme() {
  const nextTheme = dom.root.dataset.theme === THEMES.dark
    ? THEMES.light
    : THEMES.dark;

  applyTheme(nextTheme, { persist: true });
}

function applyTheme(theme, { persist = false } = {}) {
  const resolvedTheme = theme === THEMES.dark ? THEMES.dark : THEMES.light;
  const isDark = resolvedTheme === THEMES.dark;
  const nextThemeLabel = isDark ? "Switch to light mode" : "Switch to dark mode";

  dom.root.dataset.theme = resolvedTheme;

  if (dom.themeColorMeta) {
    dom.themeColorMeta.content = THEME_COLORS[resolvedTheme];
  }

  dom.themeToggles.forEach((button) => {
    button.setAttribute("aria-label", nextThemeLabel);
    button.setAttribute("title", nextThemeLabel);
    button.setAttribute("aria-pressed", String(isDark));
  });

  if (!persist) {
    return;
  }

  try {
    localStorage.setItem(STORAGE_KEYS.theme, resolvedTheme);
  } catch {
    // The selected theme remains active for the current session.
  }
}

function buildMeter(element) {
  element.innerHTML = Array.from({ length: 8 }, () => "<span></span>").join("");
}

function fillMeter(element, ratio) {
  const filled = Math.round(Math.max(0, Math.min(1, ratio)) * 8);
  [...element.children].forEach((segment, index) => segment.classList.toggle("is-filled", index < filled));
}

function normalizeDomain(value) {
  let domain = String(value || "").trim().toLowerCase();
  domain = domain.replace(/^https?:\/\//, "");
  domain = domain.split(/[/?#]/)[0];
  domain = domain.replace(/^www\./, "");
  domain = domain.replace(/\.$/, "");
  return domain;
}

function validateDomain(domain) {
  if (!domain) return { ok: false, message: "Enter a root domain such as example.com." };
  if (domain.length > 253) return { ok: false, message: "The domain is too long." };
  if (!domain.includes(".")) return { ok: false, message: "Include a public suffix such as .com or .hr." };
  if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) {
    return { ok: false, message: "Enter a valid public root domain without a path." };
  }

  const blocked = ["localhost", ".local", ".internal", ".lan", ".home"];
  if (blocked.some((suffix) => domain === suffix.replace(/^\./, "") || domain.endsWith(suffix))) {
    return { ok: false, message: "Private and local domains are not supported." };
  }

  return { ok: true };
}

function showDomainError(message) {
  dom.domainError.textContent = message;
  dom.domainError.hidden = false;
  dom.domainField.classList.add("has-error");
  dom.domainInput.setAttribute("aria-invalid", "true");
}

function clearDomainError() {
  dom.domainError.hidden = true;
  dom.domainError.textContent = "";
  dom.domainField.classList.remove("has-error");
  dom.domainInput.removeAttribute("aria-invalid");
}

function loadHistory() {
  try {
    const parsed = JSON.parse(localStorage.getItem(STORAGE_KEYS.history) || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function saveHistory() {
  try {
    localStorage.setItem(STORAGE_KEYS.history, JSON.stringify(state.history));
  } catch {
    showToast("History could not be saved on this device.", "error");
  }
}

function downloadFile(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

async function copyText(text, message) {
  try {
    await navigator.clipboard.writeText(text);
    showToast(message);
  } catch {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.append(textarea);
    textarea.select();
    document.execCommand("copy");
    textarea.remove();
    showToast(message);
  }
}

function showToast(message, type = "success") {
  const toast = document.createElement("div");
  toast.className = `toast${type === "error" ? " toast--error" : ""}`;
  toast.innerHTML = `<p>${escapeHtml(message)}</p>`;
  dom.toastRegion.append(toast);
  window.setTimeout(() => toast.remove(), 3600);
}

function formatNumber(value) {
  return new Intl.NumberFormat("en-US").format(value);
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown date";
  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function shortenHostname(hostname, rootDomain) {
  if (hostname === rootDomain) return "root";
  const suffix = `.${rootDomain}`;
  return hostname.endsWith(suffix) ? hostname.slice(0, -suffix.length) : hostname;
}

function toStringArray(value) {
  return Array.isArray(value) ? [...new Set(value.map((item) => String(item)).filter(Boolean))] : [];
}

function csvValue(value) {
  const stringValue = String(value ?? "");
  return /[",\n]/.test(stringValue) ? `"${stringValue.replaceAll('"', '""')}"` : stringValue;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function escapeAttribute(value) {
  return escapeHtml(value).replaceAll("`", "&#096;");
}

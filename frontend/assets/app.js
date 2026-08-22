(() => {
  "use strict";

  const CONNECTOR_LABELS = {
    crtsh: "crt.sh (subdomains)",
    dns: "DNS records",
    wappalyzer: "Tech fingerprint",
    tls_audit: "TLS audit",
    whois: "WHOIS",
    security_headers: "Security headers",
    shodan: "Shodan",
    nmap: "Nmap (live) [active]",
    content_discovery: "Content discovery [active]",
    nikto: "Nikto [active]",
    sqlmap: "sqlmap [active]",
  };

  const state = {
    assets: [],
    currentAssetId: null,
    connectorsAvailable: {},
  };

  async function api(path, options = {}) {
    const response = await fetch(path, {
      ...options,
      headers: { Accept: "application/json", ...(options.headers || {}) },
    });
    if (!response.ok) {
      let detail = response.statusText;
      try {
        const body = await response.json();
        detail = body.detail || detail;
      } catch (_) {}
      throw new Error(detail || `Request failed (${response.status})`);
    }
    if (response.status === 202 || response.status === 200 || response.status === 201) {
      try {
        return await response.json();
      } catch (_) {
        return null;
      }
    }
    return null;
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function formatDate(value) {
    if (!value) return "-";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "-";
    return date.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
  }

  function switchView(view) {
    document.querySelectorAll(".nav-item").forEach((el) => el.classList.toggle("active", el.dataset.view === view));
    document.querySelectorAll("section.view").forEach((el) => el.classList.toggle("active", el.id === `view-${view}`));
    document.getElementById("page-title").textContent = view === "assets" ? "Tracked Assets" : "Asset Detail";
  }

  async function checkHealth() {
    const dot = document.querySelector(".status-dot");
    const label = document.getElementById("footer-status");
    try {
      const response = await fetch("/health");
      if (!response.ok) throw new Error("unhealthy");
      const body = await response.json();
      state.connectorsAvailable = body.connectors || {};
      dot.classList.remove("offline");
      dot.classList.add("online");
      label.textContent = "API Online";
      renderConnectorOptions();
    } catch (_) {
      dot.classList.remove("online");
      dot.classList.add("offline");
      label.textContent = "API Offline";
    }
  }

  function renderConnectorOptions() {
    const select = document.getElementById("connector-select");
    const available = state.connectorsAvailable;
    select.innerHTML = Object.entries(CONNECTOR_LABELS)
      .map(([key, label]) => {
        const enabled = available[key] !== false;
        const selected = ["crtsh", "dns", "wappalyzer", "tls_audit", "whois", "security_headers"].includes(key) ? "selected" : "";
        return `<option value="${key}" ${selected} ${enabled ? "" : "disabled"}>${label}${enabled ? "" : " (unavailable)"}</option>`;
      })
      .join("");
  }

  async function loadStats() {
    const grid = document.getElementById("stats-grid");
    try {
      const stats = await api("/stats");
      const cards = [
        { label: "Tracked Assets", value: stats.total_assets, cls: "" },
        { label: "Subdomains Discovered", value: stats.total_subdomains, cls: "" },
        { label: "Total Findings", value: stats.total_findings, cls: "" },
        { label: "High Severity", value: stats.findings_by_severity.high || 0, cls: "danger" },
        { label: "Medium Severity", value: stats.findings_by_severity.medium || 0, cls: "warn" },
      ];
      grid.innerHTML = cards.map((c) => `
        <div class="stat-card ${c.cls}">
          <div class="stat-label">${c.label}</div>
          <div class="stat-value">${c.value}</div>
        </div>`).join("");
    } catch (error) {
      grid.innerHTML = `<div class="empty-state">Failed to load stats: ${escapeHtml(error.message)}</div>`;
    }
  }

  async function loadAssets() {
    const tbody = document.querySelector("#assets-table tbody");
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state">Loading...</td></tr>';
    try {
      const assets = await api("/assets");
      state.assets = assets;
      if (!assets.length) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No domains tracked yet. Click "Add Domain" to start.</td></tr>';
        return;
      }
      tbody.innerHTML = assets.map((a) => `
        <tr data-id="${a.id}">
          <td class="mono">${escapeHtml(a.root_domain)}</td>
          <td>${escapeHtml(a.label || "-")}</td>
          <td>${a.authorized_for_active_testing
            ? '<span class="auth-badge authorized">Authorized</span>'
            : '<span class="auth-badge passive-only">Passive only</span>'}</td>
          <td>${a.subdomain_count}</td>
          <td>${a.finding_count}</td>
          <td>${formatDate(a.created_at)}</td>
          <td><button class="btn secondary open-asset-btn" data-id="${a.id}">Open</button></td>
        </tr>`).join("");
      tbody.querySelectorAll("tr[data-id]").forEach((row) => {
        row.addEventListener("click", (e) => {
          if (e.target.closest(".open-asset-btn")) return;
          openAsset(row.dataset.id);
        });
      });
      tbody.querySelectorAll(".open-asset-btn").forEach((btn) => {
        btn.addEventListener("click", (e) => {
          e.stopPropagation();
          openAsset(btn.dataset.id);
        });
      });
    } catch (error) {
      tbody.innerHTML = `<tr><td colspan="7" class="empty-state">Failed to load assets: ${escapeHtml(error.message)}</td></tr>`;
    }
  }

  async function openAsset(assetId) {
    state.currentAssetId = assetId;
    switchView("detail");
    try {
      const asset = await api(`/assets/${assetId}`);
      document.getElementById("detail-domain").textContent = asset.root_domain;
      document.getElementById("detail-id").textContent = asset.id;
      document.getElementById("auth-badge-wrap").innerHTML = asset.authorized_for_active_testing
        ? '<span class="auth-badge authorized">Active testing authorized</span>'
        : '<span class="auth-badge passive-only">Passive recon only</span>';
    } catch (error) {
      document.getElementById("detail-domain").textContent = "Error loading asset";
    }
    await Promise.all([loadScans(assetId), loadSubdomains(assetId), loadFindings(assetId)]);
  }

  async function loadScans(assetId) {
    const container = document.getElementById("scans-list");
    try {
      const scans = await api(`/assets/${assetId}/scans`);
      if (!scans.length) {
        container.innerHTML = '<div class="empty-state">No scans yet.</div>';
        return;
      }
      container.innerHTML = scans.map((s) => `
        <div class="scan-row">
          <span>${s.connectors_requested.join(", ")}</span>
          <span class="scan-status ${s.status}">${s.status}</span>
          <span>${formatDate(s.started_at)}</span>
        </div>`).join("");
    } catch (error) {
      container.innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
    }
  }

  async function loadSubdomains(assetId) {
    const container = document.getElementById("subdomains-list");
    try {
      const subdomains = await api(`/assets/${assetId}/subdomains`);
      container.innerHTML = subdomains.length
        ? subdomains.map((s) => `<span class="chip" title="${escapeHtml(s.source)}">${escapeHtml(s.hostname)}</span>`).join("")
        : '<div class="empty-state">No subdomains discovered yet. Run a scan with crt.sh enabled.</div>';
    } catch (error) {
      container.innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
    }
  }

  async function loadFindings(assetId) {
    const tbody = document.querySelector("#findings-table tbody");
    try {
      const findings = await api(`/assets/${assetId}/findings`);
      tbody.innerHTML = findings.length
        ? findings.map((f) => `
          <tr>
            <td><span class="badge ${f.severity}">${escapeHtml(f.severity)}</span></td>
            <td>${escapeHtml(f.title)}</td>
            <td>${escapeHtml(f.source)}</td>
            <td class="hash-cell">${escapeHtml(f.subdomain || "-")}</td>
            <td>${formatDate(f.created_at)}</td>
          </tr>`).join("")
        : '<tr><td colspan="5" class="empty-state">No findings yet.</td></tr>';
    } catch (error) {
      tbody.innerHTML = `<tr><td colspan="5" class="empty-state">${escapeHtml(error.message)}</td></tr>`;
    }
  }

  function initNav() {
    document.querySelectorAll(".nav-item").forEach((el) => {
      el.addEventListener("click", () => {
        if (el.dataset.view === "detail" && !state.currentAssetId) return;
        switchView(el.dataset.view);
      });
    });
  }

  function initAddAsset() {
    const modal = document.getElementById("add-asset-modal");
    document.getElementById("add-asset-btn").addEventListener("click", () => {
      document.getElementById("new-domain").value = "";
      document.getElementById("new-label").value = "";
      document.getElementById("new-authorized").checked = false;
      document.getElementById("create-asset-error").textContent = "";
      modal.classList.remove("hidden");
    });
    document.getElementById("modal-close").addEventListener("click", () => modal.classList.add("hidden"));
    modal.addEventListener("click", (e) => { if (e.target.id === "add-asset-modal") modal.classList.add("hidden"); });

    document.getElementById("create-asset-btn").addEventListener("click", async () => {
      const domain = document.getElementById("new-domain").value.trim().toLowerCase();
      const label = document.getElementById("new-label").value.trim();
      const authorized = document.getElementById("new-authorized").checked;
      const errorEl = document.getElementById("create-asset-error");
      if (!domain || domain.length < 3) {
        errorEl.textContent = "Enter a valid domain.";
        return;
      }
      try {
        const asset = await api("/assets", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ root_domain: domain, label: label || null, authorized_for_active_testing: authorized }),
        });
        modal.classList.add("hidden");
        await loadAssets();
        await loadStats();
        openAsset(asset.id);
      } catch (error) {
        errorEl.textContent = error.message;
      }
    });
  }

  function initScanAndImports() {
    document.getElementById("run-scan-btn").addEventListener("click", async () => {
      if (!state.currentAssetId) return;
      const select = document.getElementById("connector-select");
      const connectors = Array.from(select.selectedOptions).map((o) => o.value);
      if (!connectors.length) return;
      try {
        await api(`/assets/${state.currentAssetId}/scans`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ connectors }),
        });
        await loadScans(state.currentAssetId);
        setTimeout(async () => {
          await Promise.all([loadScans(state.currentAssetId), loadSubdomains(state.currentAssetId), loadFindings(state.currentAssetId), loadStats(), loadAssets()]);
        }, 3000);
      } catch (error) {
        window.alert(`Scan failed to start: ${error.message}`);
      }
    });

    async function uploadImport(fileInputId, endpoint) {
      const input = document.getElementById(fileInputId);
      input.addEventListener("change", async () => {
        const file = input.files[0];
        if (!file || !state.currentAssetId) return;
        const statusEl = document.getElementById("import-status");
        statusEl.textContent = "Uploading...";
        const formData = new FormData();
        formData.append("file", file);
        try {
          const result = await fetch(`/assets/${state.currentAssetId}/imports/${endpoint}`, { method: "POST", body: formData });
          const body = await result.json();
          if (!result.ok) throw new Error(body.detail || "Import failed");
          statusEl.textContent = `Imported ${body.findings_created} findings.`;
          await Promise.all([loadFindings(state.currentAssetId), loadStats(), loadAssets()]);
        } catch (error) {
          statusEl.textContent = `Error: ${error.message}`;
        }
        input.value = "";
      });
    }
    uploadImport("nmap-file", "nmap");
    uploadImport("burp-file", "burp");
  }

  function init() {
    initNav();
    initAddAsset();
    initScanAndImports();
    checkHealth();
    loadStats();
    loadAssets();
    setInterval(checkHealth, 30000);
  }

  document.addEventListener("DOMContentLoaded", init);
})();

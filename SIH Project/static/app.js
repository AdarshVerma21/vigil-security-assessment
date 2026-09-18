const toast = document.getElementById("toast");
const scanForm = document.getElementById("scan-form");
const scanButton = document.getElementById("scan-button");
const resultsCard = document.getElementById("findings");
const navLinks = [...document.querySelectorAll("[data-view]")];
const sections = [...document.querySelectorAll("[data-section]")];
const defaultTarget = document.getElementById("target-url").value;
const storedTarget = window.localStorage.getItem("vigil.targetUrl");

function selectView(view) {
  const selected = view === "findings" && resultsCard.hidden ? "scans" : view;
  const section = selected === "findings" ? "scans" : selected;
  sections.forEach((viewSection) => {
    viewSection.hidden = viewSection.dataset.section !== section;
  });
  navLinks.forEach((link) => link.classList.toggle("active", link.dataset.view === selected));
  window.history.replaceState(null, "", `#${selected}`);
  if (selected === "history") loadHistory().catch((error) => showToast(error.message));
  if (selected === "overview") loadHistory().then(updateOverview).catch((error) => showToast(error.message));
  if (selected === "findings") resultsCard.scrollIntoView({ behavior: "smooth", block: "start" });
}

navLinks.forEach((link) => {
  link.addEventListener("click", (event) => {
    event.preventDefault();
    selectView(link.dataset.view);
    window.history.replaceState(null, "", `#${link.dataset.view}`);
  });
});

document.querySelectorAll("[data-view='scans']").forEach((button) => {
  button.addEventListener("click", () => selectView("scans"));
});

function applyStoredSettings() {
  const target = storedTarget || defaultTarget;
  document.getElementById("target-url").value = target;
  document.getElementById("settings-target-url").value = target;
}

async function loadHistory() {
  const response = await fetch("/api/scans");
  if (!response.ok) throw new Error("Unable to load scan history");
  const data = await response.json();
  renderHistory(data.scans || []);
  return data.scans || [];
}

function renderHistory(scans) {
  const list = document.getElementById("history-list");
  if (!scans.length) {
    list.innerHTML = '<p class="panel-copy">No scans have been completed yet.</p>';
    return;
  }
  list.innerHTML = scans.map((scan) => `
    <button class="history-row" type="button" data-history-index="${scans.indexOf(scan)}">
      <span><strong>${escapeHtml(scan.mode.toUpperCase())}</strong><small>${escapeHtml(scan.target_url || "Unknown target")}</small></span>
      <span><b>${scan.finding_count}</b><small>${formatDate(scan.completed_at)}</small></span>
    </button>
  `).join("");
  list.querySelectorAll("[data-history-index]").forEach((row) => row.addEventListener("click", () => {
    const scan = scans[Number(row.dataset.historyIndex)];
    renderFindings(scan.findings || []);
    selectView("findings");
  }));
}

function updateOverview(scans) {
  const findings = scans.reduce((total, scan) => total + Number(scan.finding_count || 0), 0);
  const last = scans[0];
  document.getElementById("overview-scans").textContent = scans.length;
  document.getElementById("overview-findings").textContent = findings;
  document.getElementById("overview-status").textContent = last ? "Completed" : "Ready";
  document.getElementById("overview-target").textContent = last ? formatDate(last.completed_at) : "No scan run yet";
}

function formatDate(value) {
  if (!value) return "Unknown time";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "Unknown time" : date.toLocaleString();
}

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("show");
  window.setTimeout(() => toast.classList.remove("show"), 4200);
}

scanForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  scanButton.disabled = true;
  scanButton.innerHTML = "<span>◌</span> Running Analysis...";
  try {
    const response = await fetch("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        mode: "all",
        target_url: document.getElementById("target-url").value.trim(),
      }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.message || "Scan failed");
    renderFindings(result.findings);
    updateOverview(await loadHistory());
    showToast(`Assessment complete: ${result.finding_count} finding(s).`);
  } catch (error) {
    showToast(error.message);
  } finally {
    scanButton.disabled = false;
    scanButton.innerHTML = "<span>▸</span> Start Analysis";
  }
});

function renderFindings(findings) {
  document.getElementById("finding-count").textContent = findings.length;
  const list = document.getElementById("finding-list");
  const grouped = findings.reduce((groups, finding) => {
    const category = finding.category || "Uncategorized";
    (groups[category] ||= []).push(finding);
    return groups;
  }, {});
  list.innerHTML = Object.entries(grouped).map(([category, categoryFindings]) => `
    <section class="finding-category">
      <h3>${escapeHtml(category)} <span>${categoryFindings.length}</span></h3>
      ${categoryFindings.map((finding) => `
    <article class="finding-item">
      <span class="severity-badge ${finding.severity.toLowerCase()}">${finding.severity}</span>
      <div class="finding-content">
        <strong>${escapeHtml(finding.title || finding.description)}</strong>
        <small>${escapeHtml(finding.category)} · ${escapeHtml(finding.affected_component || "Unspecified component")}</small>
        <p>${escapeHtml(finding.description)}</p>
        <small><b>CVSS:</b> ${escapeHtml(finding.cvss ?? "Not scored")} · <b>Vector:</b> ${escapeHtml(finding.cvss_vector || "Not specified")}</small>
        <small><b>Impact:</b> ${escapeHtml(finding.business_impact || "Not specified")}</small>
        <ol class="finding-steps">${(finding.steps_to_reproduce || []).map((step) => `<li>${escapeHtml(step)}</li>`).join("")}</ol>
        <small><b>PoC artifact:</b> ${escapeHtml((finding.poc_evidence || {}).artifact_ref || "Not available")}</small>
        <small><b>Remediation:</b> ${escapeHtml(finding.remediation)}</small>
      </div>
    </article>
      `).join("")}
    </section>
  `).join("");
  resultsCard.hidden = false;
  selectView("findings");
  resultsCard.scrollIntoView({ behavior: "smooth", block: "start" });
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
  }[character]));
}

document.getElementById("refresh-history").addEventListener("click", () => {
  loadHistory().catch((error) => showToast(error.message));
});

document.getElementById("settings-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const target = document.getElementById("settings-target-url").value.trim();
  document.getElementById("target-url").value = target;
  if (document.getElementById("settings-remember-target").checked) {
    window.localStorage.setItem("vigil.targetUrl", target);
  } else {
    window.localStorage.removeItem("vigil.targetUrl");
  }
  showToast("Settings saved.");
});

document.getElementById("reset-settings").addEventListener("click", () => {
  window.localStorage.removeItem("vigil.targetUrl");
  applyStoredSettings();
  showToast("Settings reset.");
});

applyStoredSettings();
if (window.location.hash) selectView(window.location.hash.slice(1));

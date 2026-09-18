const toast = document.getElementById("toast");
const scanForm = document.getElementById("scan-form");
const scanButton = document.getElementById("scan-button");
const resultsCard = document.getElementById("findings");

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
  resultsCard.scrollIntoView({ behavior: "smooth", block: "start" });
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
  }[character]));
}

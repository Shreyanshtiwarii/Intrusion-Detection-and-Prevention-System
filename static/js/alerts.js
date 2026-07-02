/* CyberShield -- Threat alerts page logic */

let currentPage = 1;
let allAlerts = {};

document.addEventListener("DOMContentLoaded", () => {
  loadAlerts(1);

  document.getElementById("applyFiltersBtn").addEventListener("click", () => loadAlerts(1));

  CyberShield.socket.on("new_alert", () => {
    if (currentPage === 1) loadAlerts(1);
  });
});

async function loadAlerts(page) {
  currentPage = page;
  const severity = document.getElementById("severityFilter").value;
  const attackType = document.getElementById("attackTypeFilter").value;
  const sourceIp = document.getElementById("sourceIpFilter").value.trim();

  const params = new URLSearchParams({ page, per_page: 20 });
  if (severity) params.set("severity", severity);
  if (attackType) params.set("attack_type", attackType);
  if (sourceIp) params.set("source_ip", sourceIp);

  const res = await apiGet(`/api/alerts?${params.toString()}`);
  if (!res.success) return;

  renderAlerts(res.data.items);
  buildPagination(document.getElementById("alertsPagination"), res.data.page, res.data.total_pages, loadAlerts);
}

function renderAlerts(items) {
  const tbody = document.getElementById("alertsTableBody");
  tbody.innerHTML = "";

  if (items.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8"><div class="empty-state"><i class="fa-solid fa-check-circle"></i>No alerts match these filters</div></td></tr>`;
    return;
  }

  items.forEach((alert) => {
    allAlerts[alert.id] = alert;
    const row = document.createElement("tr");
    row.innerHTML = `
      <td class="mono">${formatTime(alert.timestamp)}</td>
      <td>${escapeHtml(alert.attack_type)}</td>
      <td class="mono">${escapeHtml(alert.source_ip)}</td>
      <td>${severityBadge(alert.severity)}</td>
      <td class="mono">${alert.threat_score}</td>
      <td class="mono">${alert.confidence}%</td>
      <td><span class="badge badge-neutral">${escapeHtml(alert.action_taken)}</span></td>
      <td>
        <button class="btn btn-sm" onclick="viewAlert(${alert.id})"><i class="fa-solid fa-eye"></i></button>
        ${alert.resolved ? "" : `<button class="btn btn-sm" onclick="resolveAlert(${alert.id})"><i class="fa-solid fa-check"></i></button>`}
        <button class="btn btn-sm btn-danger" onclick="deleteAlert(${alert.id})"><i class="fa-solid fa-trash"></i></button>
      </td>
    `;
    tbody.appendChild(row);
  });
}

function viewAlert(id) {
  const alert = allAlerts[id];
  if (!alert) return;
  document.getElementById("alertModalBody").innerHTML = `
    <p><strong>Attack Type:</strong> ${escapeHtml(alert.attack_type)}</p>
    <p><strong>Severity:</strong> ${severityBadge(alert.severity)}</p>
    <p><strong>Threat Score:</strong> ${alert.threat_score} / 100</p>
    <p><strong>Confidence:</strong> ${alert.confidence}%</p>
    <p><strong>Source:</strong> <span class="mono">${escapeHtml(alert.source_ip)}${alert.source_port ? ":" + alert.source_port : ""}</span></p>
    <p><strong>Destination:</strong> <span class="mono">${escapeHtml(alert.destination_ip || "--")}${alert.destination_port ? ":" + alert.destination_port : ""}</span></p>
    <p><strong>Protocol:</strong> ${escapeHtml(alert.protocol || "--")}</p>
    <p><strong>Description:</strong> ${escapeHtml(alert.description)}</p>
    <p><strong>Suggested Mitigation:</strong> ${escapeHtml(alert.mitigation)}</p>
    <p><strong>Action Taken:</strong> ${escapeHtml(alert.action_taken)}</p>
    ${alert.raw_payload_snippet ? `<p><strong>Payload Snippet:</strong><br><span class="mono">${escapeHtml(alert.raw_payload_snippet)}</span></p>` : ""}
  `;
  document.getElementById("alertModal").style.display = "flex";
}

function closeAlertModal() {
  document.getElementById("alertModal").style.display = "none";
}

async function resolveAlert(id) {
  const res = await apiPost(`/api/alerts/${id}/resolve`);
  showToast(res.message || res.error, res.success ? "success" : "critical");
  loadAlerts(currentPage);
}

async function deleteAlert(id) {
  if (!confirm("Delete this alert permanently?")) return;
  const res = await apiDelete(`/api/alerts/${id}`);
  showToast(res.message || res.error, res.success ? "success" : "critical");
  loadAlerts(currentPage);
}

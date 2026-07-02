/* CyberShield -- Reports page logic */

document.addEventListener("DOMContentLoaded", () => {
  loadReports();

  document.querySelectorAll("[data-report-type]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const reportType = btn.getAttribute("data-report-type");
      btn.disabled = true;
      btn.innerHTML = '<span class="loader"></span> Generating...';

      const res = await apiPost("/api/reports/generate", { report_type: reportType });
      showToast(res.message || res.error, res.success ? "success" : "critical");

      btn.disabled = false;
      btn.textContent = "Generate";
      if (res.success) loadReports();
    });
  });
});

async function loadReports() {
  const res = await apiGet("/api/reports");
  const tbody = document.getElementById("reportsTableBody");
  if (!res.success || res.data.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7"><div class="empty-state"><i class="fa-solid fa-file-pdf"></i>No reports generated yet</div></td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  res.data.forEach((r) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td><span class="badge badge-accent">${escapeHtml(r.report_type)}</span></td>
      <td class="mono">${formatTime(r.period_start)} &rarr; ${formatTime(r.period_end)}</td>
      <td class="mono">${r.total_alerts}</td>
      <td class="mono">${r.total_blocked}</td>
      <td class="mono">${r.total_packets}</td>
      <td class="mono">${formatTime(r.generated_at)}</td>
      <td><a class="btn btn-sm" href="/api/reports/${r.id}/download"><i class="fa-solid fa-download"></i></a></td>
    `;
    tbody.appendChild(row);
  });
}

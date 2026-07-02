/* CyberShield -- Unified logs page logic */

let logsCurrentPage = 1;

const LOG_COLUMNS = {
  system: ["id", "timestamp", "level", "source", "message"],
  alerts: ["id", "timestamp", "attack_type", "source_ip", "severity", "threat_score", "action_taken"],
  packets: ["id", "timestamp", "source_ip", "destination_ip", "protocol", "source_port", "destination_port", "packet_size"],
  blocked_ips: ["id", "ip_address", "reason", "block_type", "blocked_at", "is_active"],
};

document.addEventListener("DOMContentLoaded", () => {
  renderTableHead();
  loadLogs(1);

  document.getElementById("logSourceSelect").addEventListener("change", () => {
    renderTableHead();
    loadLogs(1);
  });
  document.getElementById("logSearchBtn").addEventListener("click", () => loadLogs(1));
  document.getElementById("logSearchInput").addEventListener("keypress", (e) => {
    if (e.key === "Enter") loadLogs(1);
  });

  document.getElementById("exportCsvBtn").addEventListener("click", () => {
    const source = document.getElementById("logSourceSelect").value;
    window.location.href = `/api/logs/${source}/export/csv`;
  });
  document.getElementById("exportPdfBtn").addEventListener("click", () => {
    const source = document.getElementById("logSourceSelect").value;
    window.location.href = `/api/logs/${source}/export/pdf`;
  });
});

function renderTableHead() {
  const source = document.getElementById("logSourceSelect").value;
  const cols = LOG_COLUMNS[source];
  const head = document.getElementById("logsTableHead");
  head.innerHTML = cols.map((c) => `<th>${c.replace(/_/g, " ")}</th>`).join("");
}

async function loadLogs(page) {
  logsCurrentPage = page;
  const source = document.getElementById("logSourceSelect").value;
  const search = document.getElementById("logSearchInput").value.trim();
  const cols = LOG_COLUMNS[source];

  const params = new URLSearchParams({ page, per_page: 25 });
  if (search) params.set("search", search);

  const res = await apiGet(`/api/logs/${source}?${params.toString()}`);
  const tbody = document.getElementById("logsTableBody");

  if (!res.success) {
    tbody.innerHTML = `<tr><td><div class="empty-state"><i class="fa-solid fa-triangle-exclamation"></i>${escapeHtml(res.error)}</div></td></tr>`;
    return;
  }

  if (res.data.items.length === 0) {
    tbody.innerHTML = `<tr><td colspan="${cols.length}"><div class="empty-state"><i class="fa-solid fa-inbox"></i>No log entries found</div></td></tr>`;
    document.getElementById("logsPagination").innerHTML = "";
    return;
  }

  tbody.innerHTML = "";
  res.data.items.forEach((item) => {
    const row = document.createElement("tr");
    row.innerHTML = cols.map((c) => `<td class="mono">${escapeHtml(formatCell(c, item[c]))}</td>`).join("");
    tbody.appendChild(row);
  });

  buildPagination(document.getElementById("logsPagination"), res.data.page, res.data.total_pages, loadLogs);
}

function formatCell(col, value) {
  if (col === "timestamp" || col === "blocked_at") return formatTime(value);
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return value ?? "--";
}

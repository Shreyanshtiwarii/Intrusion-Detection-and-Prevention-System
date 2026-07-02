/* CyberShield -- IP blocklist page logic */

let ipsCurrentPage = 1;

document.addEventListener("DOMContentLoaded", () => {
  loadBlockedIps(1);

  document.getElementById("openBlockModalBtn").addEventListener("click", () => {
    document.getElementById("blockModal").style.display = "flex";
  });

  document.getElementById("activeOnlyCheck").addEventListener("change", () => loadBlockedIps(1));

  document.getElementById("blockTypeInput").addEventListener("change", (e) => {
    document.getElementById("durationGroup").style.display = e.target.value === "Permanent" ? "none" : "block";
  });

  document.getElementById("blockForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const payload = {
      ip_address: document.getElementById("blockIpInput").value.trim(),
      reason: document.getElementById("blockReasonInput").value.trim() || "Manual block by admin",
      block_type: document.getElementById("blockTypeInput").value,
      duration_minutes: parseInt(document.getElementById("blockDurationInput").value || "60", 10),
    };
    const res = await apiPost("/api/ips/block", payload);
    showToast(res.message || res.error, res.success ? "success" : "critical");
    if (res.success) {
      closeBlockModal();
      document.getElementById("blockForm").reset();
      loadBlockedIps(1);
    }
  });

  CyberShield.socket.on("ip_blocked", () => loadBlockedIps(ipsCurrentPage));
  CyberShield.socket.on("ip_unblocked", () => loadBlockedIps(ipsCurrentPage));
});

function closeBlockModal() {
  document.getElementById("blockModal").style.display = "none";
}

async function loadBlockedIps(page) {
  ipsCurrentPage = page;
  const activeOnly = document.getElementById("activeOnlyCheck").checked;
  const params = new URLSearchParams({ page, per_page: 20, active_only: activeOnly });

  const res = await apiGet(`/api/ips?${params.toString()}`);
  if (!res.success) return;

  renderIps(res.data.items);
  buildPagination(document.getElementById("ipsPagination"), res.data.page, res.data.total_pages, loadBlockedIps);
}

function renderIps(items) {
  const tbody = document.getElementById("ipsTableBody");
  tbody.innerHTML = "";

  if (items.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7"><div class="empty-state"><i class="fa-solid fa-ban"></i>No blocked IPs found</div></td></tr>`;
    return;
  }

  items.forEach((ip) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td class="mono">${escapeHtml(ip.ip_address)}</td>
      <td>${escapeHtml(ip.reason || "--")}</td>
      <td><span class="badge badge-neutral">${escapeHtml(ip.block_type)}</span></td>
      <td class="mono">${formatTime(ip.blocked_at)}</td>
      <td class="mono">${ip.expires_at ? formatTime(ip.expires_at) : "Never"}</td>
      <td>${ip.is_active ? '<span class="badge badge-critical">Active</span>' : '<span class="badge badge-low">Lifted</span>'}</td>
      <td>${ip.is_active ? `<button class="btn btn-sm" onclick="unblockIp('${ip.ip_address}')"><i class="fa-solid fa-unlock"></i> Unblock</button>` : "--"}</td>
    `;
    tbody.appendChild(row);
  });
}

async function unblockIp(ipAddress) {
  if (!confirm(`Unblock ${ipAddress}?`)) return;
  const res = await apiPost("/api/ips/unblock", { ip_address: ipAddress });
  showToast(res.message || res.error, res.success ? "success" : "critical");
  loadBlockedIps(ipsCurrentPage);
}

/* CyberShield -- File integrity monitoring page logic */

document.addEventListener("DOMContentLoaded", () => {
  loadFimFiles();

  document.getElementById("scanNowBtn").addEventListener("click", async (e) => {
    e.currentTarget.disabled = true;
    const res = await apiPost("/api/fim/scan-now");
    showToast(res.message || res.error, res.success ? "success" : "critical");
    e.currentTarget.disabled = false;
    loadFimFiles();
  });

  document.getElementById("addFileBtn").addEventListener("click", () => {
    document.getElementById("addFileModal").style.display = "flex";
  });

  document.getElementById("addFileForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const path = document.getElementById("fimPathInput").value.trim();
    const res = await apiPost("/api/fim/add", { file_path: path });
    showToast(res.message || res.error, res.success ? "success" : "critical");
    if (res.success) {
      closeAddFileModal();
      document.getElementById("addFileForm").reset();
      loadFimFiles();
    }
  });

  CyberShield.socket.on("fim_event", () => loadFimFiles());
});

function closeAddFileModal() {
  document.getElementById("addFileModal").style.display = "none";
}

async function loadFimFiles() {
  const res = await apiGet("/api/fim/files");
  const tbody = document.getElementById("fimTableBody");
  if (!res.success || res.data.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5"><div class="empty-state"><i class="fa-solid fa-file-shield"></i>No files monitored yet</div></td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  res.data.forEach((f) => {
    const statusBadge = {
      OK: '<span class="badge badge-low">OK</span>',
      MODIFIED: '<span class="badge badge-critical">Modified</span>',
      MISSING: '<span class="badge badge-high">Missing</span>',
    }[f.status] || '<span class="badge badge-neutral">Unknown</span>';

    const row = document.createElement("tr");
    row.innerHTML = `
      <td class="mono">${escapeHtml(f.file_path)}</td>
      <td class="mono" style="max-width:220px; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(f.sha256_hash)}</td>
      <td>${statusBadge}</td>
      <td class="mono">${formatTime(f.last_checked)}</td>
      <td><button class="btn btn-sm btn-danger" onclick="removeFimFile('${escapeHtml(f.file_path).replace(/'/g, "\\'")}')"><i class="fa-solid fa-trash"></i></button></td>
    `;
    tbody.appendChild(row);
  });
}

async function removeFimFile(path) {
  if (!confirm(`Stop monitoring ${path}?`)) return;
  const res = await apiPost("/api/fim/remove", { file_path: path });
  showToast(res.message || res.error, res.success ? "success" : "critical");
  loadFimFiles();
}

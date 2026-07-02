/* CyberShield -- Shared application shell logic */

const CyberShield = {
  socket: null,
  soundEnabled: true,
};

document.addEventListener("DOMContentLoaded", () => {
  initSidebarToggle();
  initSocket();
  initSoundToggle();
  loadMonitoringStatus();
});

function initSidebarToggle() {
  const toggle = document.getElementById("sidebarToggle");
  const sidebar = document.getElementById("sidebar");
  if (toggle && sidebar) {
    toggle.addEventListener("click", () => sidebar.classList.toggle("open"));
  }
}

function initSocket() {
  CyberShield.socket = io({ transports: ["websocket", "polling"] });

  CyberShield.socket.on("connect", () => {
    console.log("[CyberShield] Connected to live feed");
  });

  CyberShield.socket.on("new_alert", (alert) => {
    handleNewAlert(alert);
  });

  CyberShield.socket.on("ip_blocked", (info) => {
    showToast(`IP blocked: ${info.ip_address}`, "critical");
  });

  CyberShield.socket.on("system_log", (log) => {
    if (log.level === "CRITICAL") {
      showToast(log.message, "critical");
    }
  });
}

function handleNewAlert(alert) {
  const type = alert.severity === "Critical" || alert.severity === "High" ? "critical" : "default";
  showToast(`${alert.attack_type} detected from ${alert.source_ip} (${alert.severity})`, type);
  if (CyberShield.soundEnabled && (alert.severity === "Critical" || alert.severity === "High")) {
    playAlertSound();
  }
  // Let individual pages hook into new alerts
  if (typeof window.onCyberShieldAlert === "function") {
    window.onCyberShieldAlert(alert);
  }
}

function playAlertSound() {
  const audio = document.getElementById("alertSound");
  if (audio) {
    audio.currentTime = 0;
    audio.play().catch(() => {});
  }
}

function initSoundToggle() {
  const btn = document.getElementById("soundToggleBtn");
  const icon = document.getElementById("soundIcon");
  if (!btn) return;

  const stored = localStorage.getItem("cs_sound_enabled");
  CyberShield.soundEnabled = stored === null ? true : stored === "true";
  updateSoundIcon(icon);

  btn.addEventListener("click", () => {
    CyberShield.soundEnabled = !CyberShield.soundEnabled;
    localStorage.setItem("cs_sound_enabled", CyberShield.soundEnabled);
    updateSoundIcon(icon);
  });
}

function updateSoundIcon(icon) {
  if (!icon) return;
  icon.className = CyberShield.soundEnabled ? "fa-solid fa-volume-high" : "fa-solid fa-volume-xmark";
}

async function loadMonitoringStatus() {
  try {
    const res = await apiGet("/api/settings");
    if (res.success) {
      const dot = document.getElementById("monitorStatusDot");
      const text = document.getElementById("monitorStatusText");
      const enabled = res.data.monitoring_enabled === "true";
      if (dot && text) {
        dot.classList.toggle("off", !enabled);
        dot.classList.toggle("blink", enabled);
        text.textContent = enabled ? "Monitoring Active" : "Monitoring Paused";
      }
    }
  } catch (e) { /* silent */ }
}

/* ------------------------------------------------------------------
   Toasts
   ------------------------------------------------------------------ */
function showToast(message, type = "default") {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.innerHTML = `<i class="fa-solid ${type === "critical" ? "fa-triangle-exclamation" : "fa-circle-info"}"></i> ${escapeHtml(message)}`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transition = "opacity 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  }, 4500);
}

/* ------------------------------------------------------------------
   Fetch helpers
   ------------------------------------------------------------------ */
async function apiGet(url) {
  const res = await fetch(url, { headers: { "Accept": "application/json" } });
  return res.json();
}

async function apiPost(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  return res.json();
}

async function apiDelete(url) {
  const res = await fetch(url, { method: "DELETE" });
  return res.json();
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatTime(isoString) {
  if (!isoString) return "--";
  const d = new Date(isoString);
  return d.toLocaleString();
}

function severityBadge(severity) {
  const cls = {
    Critical: "badge-critical",
    High: "badge-high",
    Medium: "badge-medium",
    Low: "badge-low",
  }[severity] || "badge-neutral";
  return `<span class="badge ${cls}">${escapeHtml(severity || "Unknown")}</span>`;
}

function buildPagination(container, page, totalPages, onChange) {
  if (!container) return;
  container.innerHTML = "";
  const info = document.createElement("span");
  info.className = "page-info";
  info.textContent = `Page ${page} of ${totalPages}`;

  const prevBtn = document.createElement("button");
  prevBtn.innerHTML = '<i class="fa-solid fa-chevron-left"></i>';
  prevBtn.disabled = page <= 1;
  prevBtn.onclick = () => onChange(page - 1);

  const nextBtn = document.createElement("button");
  nextBtn.innerHTML = '<i class="fa-solid fa-chevron-right"></i>';
  nextBtn.disabled = page >= totalPages;
  nextBtn.onclick = () => onChange(page + 1);

  container.appendChild(prevBtn);
  container.appendChild(info);
  container.appendChild(nextBtn);
}

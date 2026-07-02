/* CyberShield -- Dashboard page logic */

let protocolChart, severityChart;
let threatFeedItems = [];

document.addEventListener("DOMContentLoaded", () => {
  initCharts();
  loadDashboardSummary();
  setInterval(loadDashboardSummary, 8000);

  CyberShield.socket.on("packet_counter", (data) => {
    document.getElementById("statPackets").textContent = data.total_packets.toLocaleString();
    document.getElementById("protocolTotal").textContent = `${data.total_packets.toLocaleString()} pkts`;
    updateProtocolChart(data.protocol_counts);
  });

  CyberShield.socket.on("threat_counter", (data) => {
    document.getElementById("statThreats").textContent = data.total_threats.toLocaleString();
  });

  CyberShield.socket.on("system_stats", (data) => {
    updateSystemGauges(data);
  });

  CyberShield.socket.on("ip_blocked", () => {
    const el = document.getElementById("statBlocked");
    el.textContent = (parseInt(el.textContent || "0") + 1).toString();
  });
});

window.onCyberShieldAlert = function (alert) {
  prependThreatFeed(alert);
  bumpSeverityChart(alert.severity);
};

function initCharts() {
  const protoCtx = document.getElementById("protocolChart");
  protocolChart = createDoughnutChart(protoCtx, ["TCP", "UDP", "ICMP", "ARP", "DNS"], [0, 0, 0, 0, 0],
    [PROTOCOL_COLORS.TCP, PROTOCOL_COLORS.UDP, PROTOCOL_COLORS.ICMP, PROTOCOL_COLORS.ARP, PROTOCOL_COLORS.DNS]);

  const sevCtx = document.getElementById("severityChart");
  severityChart = createBarChart(sevCtx, ["Low", "Medium", "High", "Critical"], [0, 0, 0, 0],
    [SEVERITY_COLORS.Low, SEVERITY_COLORS.Medium, SEVERITY_COLORS.High, SEVERITY_COLORS.Critical]);
}

function updateProtocolChart(counts) {
  if (!protocolChart) return;
  protocolChart.data.datasets[0].data = [
    counts.TCP || 0, counts.UDP || 0, counts.ICMP || 0, counts.ARP || 0, counts.DNS || 0,
  ];
  protocolChart.update("none");
}

function bumpSeverityChart(severity) {
  if (!severityChart) return;
  const idx = ["Low", "Medium", "High", "Critical"].indexOf(severity);
  if (idx === -1) return;
  severityChart.data.datasets[0].data[idx] += 1;
  severityChart.update();
}

function updateSystemGauges(data) {
  document.getElementById("statCpu").textContent = `${Math.round(data.cpu_percent)}%`;

  setGauge("cpu", data.cpu_percent);
  setGauge("mem", data.memory_percent);
  setGauge("disk", data.disk_percent);
}

function setGauge(prefix, value) {
  const pctEl = document.getElementById(`${prefix}Pct`);
  const fillEl = document.getElementById(`${prefix}Fill`);
  if (!pctEl || !fillEl) return;
  const rounded = Math.round(value);
  pctEl.textContent = `${rounded}%`;
  fillEl.style.width = `${rounded}%`;
  fillEl.classList.remove("warn", "danger");
  if (rounded >= 85) fillEl.classList.add("danger");
  else if (rounded >= 65) fillEl.classList.add("warn");
}

async function loadDashboardSummary() {
  try {
    const res = await apiGet("/api/dashboard/summary");
    if (!res.success) return;
    const d = res.data;

    document.getElementById("statPackets").textContent = d.sniffer.total_packets.toLocaleString();
    document.getElementById("statThreats").textContent = d.ids.total_threats.toLocaleString();
    document.getElementById("statBlocked").textContent = d.totals.total_blocked_active.toLocaleString();
    document.getElementById("statCpu").textContent = `${Math.round(d.system.cpu_percent || 0)}%`;
    document.getElementById("protocolTotal").textContent = `${d.sniffer.total_packets.toLocaleString()} pkts`;

    updateProtocolChart(d.sniffer.protocol_counts);
    updateSystemGauges(d.system);

    severityChart.data.datasets[0].data = [
      d.severity_breakdown.Low || 0,
      d.severity_breakdown.Medium || 0,
      d.severity_breakdown.High || 0,
      d.severity_breakdown.Critical || 0,
    ];
    severityChart.update();

    if (threatFeedItems.length === 0) {
      d.recent_alerts.forEach((a) => prependThreatFeed(a, true));
    }
  } catch (e) {
    console.error("Failed to load dashboard summary", e);
  }
}

function prependThreatFeed(alert, append = false) {
  const container = document.getElementById("liveThreatFeed");
  if (!container) return;

  const empty = container.querySelector(".empty-state");
  if (empty) empty.remove();

  const row = document.createElement("div");
  row.className = "threat-row";
  row.innerHTML = `
    <span class="sev-dot ${escapeHtml(alert.severity)}"></span>
    <div class="threat-main">
      <div class="threat-type">${escapeHtml(alert.attack_type)}</div>
      <div class="threat-meta">${escapeHtml(alert.source_ip)} &middot; ${formatTime(alert.timestamp)}</div>
    </div>
    <div class="threat-score">${alert.threat_score}</div>
  `;

  if (append) {
    container.appendChild(row);
  } else {
    container.prepend(row);
  }

  threatFeedItems.push(alert.id);
  while (container.children.length > 25) {
    container.removeChild(container.lastChild);
  }
}

/* CyberShield -- Packet capture page logic */

let feedPaused = false;
const MAX_ROWS = 200;

document.addEventListener("DOMContentLoaded", () => {
  loadSnifferStatus();
  setInterval(loadSnifferStatus, 5000);

  document.getElementById("startSnifferBtn").addEventListener("click", async () => {
    const res = await apiPost("/api/packets/sniffer/start");
    showToast(res.message || res.error, res.success ? "success" : "critical");
    loadSnifferStatus();
  });

  document.getElementById("stopSnifferBtn").addEventListener("click", async () => {
    const res = await apiPost("/api/packets/sniffer/stop");
    showToast(res.message || res.error, res.success ? "success" : "critical");
    loadSnifferStatus();
  });

  document.getElementById("pauseFeedBtn").addEventListener("click", (e) => {
    feedPaused = !feedPaused;
    e.currentTarget.innerHTML = feedPaused
      ? '<i class="fa-solid fa-play"></i> Resume Live Feed'
      : '<i class="fa-solid fa-pause"></i> Pause Live Feed';
  });

  document.getElementById("protocolFilter").addEventListener("change", () => { /* client-side filter applied live */ });

  CyberShield.socket.on("new_packet", (pkt) => {
    if (feedPaused) return;
    const protoFilter = document.getElementById("protocolFilter").value;
    const ipFilter = document.getElementById("ipFilter").value.trim();

    if (protoFilter && pkt.protocol !== protoFilter) return;
    if (ipFilter && !(pkt.source_ip || "").includes(ipFilter)) return;

    prependPacketRow(pkt);
  });
});

async function loadSnifferStatus() {
  try {
    const res = await apiGet("/api/packets/sniffer/status");
    if (!res.success) return;
    const d = res.data;
    document.getElementById("pcStatus").textContent = d.running ? "RUNNING" : "STOPPED";
    document.getElementById("pcStatus").style.color = d.running ? "var(--low)" : "var(--critical)";
    document.getElementById("pcInterface").textContent = d.interface || "default";
    document.getElementById("pcTotal").textContent = d.total_packets.toLocaleString();
    const protos = Object.entries(d.protocol_counts).filter(([, v]) => v > 0).map(([k]) => k);
    document.getElementById("pcProtocols").textContent = protos.length ? protos.join(", ") : "--";
  } catch (e) {
    console.error(e);
  }
}

function prependPacketRow(pkt) {
  const tbody = document.getElementById("packetsTableBody");
  const empty = tbody.querySelector(".empty-state");
  if (empty) empty.closest("tr").remove();

  const row = document.createElement("tr");
  row.innerHTML = `
    <td class="mono">${formatTime(pkt.timestamp)}</td>
    <td class="mono">${escapeHtml(pkt.source_ip || "--")}</td>
    <td class="mono">${escapeHtml(pkt.destination_ip || "--")}</td>
    <td><span class="badge badge-accent">${escapeHtml(pkt.protocol || "--")}</span></td>
    <td class="mono">${pkt.source_port ?? "--"}</td>
    <td class="mono">${pkt.destination_port ?? "--"}</td>
    <td class="mono">${pkt.packet_size ?? 0} B</td>
  `;
  tbody.prepend(row);

  while (tbody.children.length > MAX_ROWS) {
    tbody.removeChild(tbody.lastChild);
  }
}

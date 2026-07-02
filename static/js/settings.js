/* CyberShield -- Settings page logic */

document.addEventListener("DOMContentLoaded", () => {
  loadSettings();
  document.getElementById("saveSettingsBtn").addEventListener("click", saveSettings);
});

async function loadSettings() {
  const res = await apiGet("/api/settings");
  if (!res.success) return;
  const s = res.data;

  document.getElementById("monitoringEnabled").checked = s.monitoring_enabled === "true";
  document.getElementById("autoBlockEnabled").checked = s.auto_block_enabled === "true";
  document.getElementById("notificationSoundEnabled").checked = s.notification_sound_enabled === "true";
  document.getElementById("loggingLevel").value = s.logging_level || "INFO";
  document.getElementById("blockDurationMinutes").value = s.block_duration_minutes || 60;

  document.getElementById("synFloodThreshold").value = s.syn_flood_threshold || 100;
  document.getElementById("udpFloodThreshold").value = s.udp_flood_threshold || 150;
  document.getElementById("icmpFloodThreshold").value = s.icmp_flood_threshold || 100;
  document.getElementById("portScanThreshold").value = s.port_scan_threshold || 15;
  document.getElementById("bruteForceThreshold").value = s.brute_force_threshold || 5;
  document.getElementById("excessiveRequestThreshold").value = s.excessive_request_threshold || 200;
}

async function saveSettings() {
  const btn = document.getElementById("saveSettingsBtn");
  btn.disabled = true;
  btn.innerHTML = '<span class="loader"></span> Saving...';

  const payload = {
    monitoring_enabled: document.getElementById("monitoringEnabled").checked,
    auto_block_enabled: document.getElementById("autoBlockEnabled").checked,
    notification_sound_enabled: document.getElementById("notificationSoundEnabled").checked,
    logging_level: document.getElementById("loggingLevel").value,
    block_duration_minutes: document.getElementById("blockDurationMinutes").value,
    syn_flood_threshold: document.getElementById("synFloodThreshold").value,
    udp_flood_threshold: document.getElementById("udpFloodThreshold").value,
    icmp_flood_threshold: document.getElementById("icmpFloodThreshold").value,
    port_scan_threshold: document.getElementById("portScanThreshold").value,
    brute_force_threshold: document.getElementById("bruteForceThreshold").value,
    excessive_request_threshold: document.getElementById("excessiveRequestThreshold").value,
  };

  const res = await apiPost("/api/settings", payload);
  showToast(res.message || res.error, res.success ? "success" : "critical");

  btn.disabled = false;
  btn.innerHTML = '<i class="fa-solid fa-floppy-disk"></i> Save Changes';
}

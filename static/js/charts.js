/* CyberShield -- Chart.js theme helpers */

Chart.defaults.color = "#8592ab";
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.borderColor = "#1c2940";

function createDoughnutChart(ctx, labels, data, colors) {
  return new Chart(ctx, {
    type: "doughnut",
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: colors,
        borderColor: "#0b1220",
        borderWidth: 2,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      cutout: "68%",
      plugins: {
        legend: {
          position: "bottom",
          labels: { boxWidth: 10, padding: 14, font: { size: 11 } },
        },
      },
    },
  });
}

function createBarChart(ctx, labels, data, colors) {
  return new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: colors || "#00d4ff",
        borderRadius: 6,
        maxBarThickness: 34,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false } },
        y: { beginAtZero: true, grid: { color: "#16233a" } },
      },
    },
  });
}

function createLineChart(ctx, labels, data, label) {
  return new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [{
        label,
        data,
        borderColor: "#00d4ff",
        backgroundColor: "rgba(0,212,255,0.1)",
        tension: 0.35,
        fill: true,
        pointRadius: 0,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false } },
        y: { beginAtZero: true, grid: { color: "#16233a" } },
      },
    },
  });
}

const SEVERITY_COLORS = {
  Critical: "#ff3b5c",
  High: "#ff8a3d",
  Medium: "#ffc94d",
  Low: "#22c55e",
};

const PROTOCOL_COLORS = {
  TCP: "#00d4ff",
  UDP: "#3b82f6",
  ICMP: "#ffc94d",
  ARP: "#a855f7",
  DNS: "#22c55e",
  OTHER: "#56637d",
};

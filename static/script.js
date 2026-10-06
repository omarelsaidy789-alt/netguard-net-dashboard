
const $ = (id) => document.getElementById(id);


function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}


function formatRate(bytes) {
  const units = ["B/s", "KB/s", "MB/s", "GB/s"];
  let i = 0;
  while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
  return bytes.toFixed(i === 0 ? 0 : 1) + " " + units[i];
}

const commonOptions = {
  responsive: true,
  maintainAspectRatio: false,
  animation: false,
  interaction: { intersect: false, mode: "index" },
  plugins: { legend: { labels: { color: "#9ca3af" } } },
  scales: {
    x: { ticks: { color: "#6b7280", maxTicksLimit: 8 }, grid: { color: "#1f2937" } },
    y: { beginAtZero: true, ticks: { color: "#6b7280" }, grid: { color: "#1f2937" } },
  },
};

const bandwidthChart = new Chart($("bandwidthChart"), {
  type: "line",
  data: {
    labels: [],
    datasets: [
      { label: "Download (KB/s)", data: [], borderColor: "#22d3ee",
        backgroundColor: "rgba(34,211,238,.15)", fill: true, tension: .3, pointRadius: 0 },
      { label: "Upload (KB/s)", data: [], borderColor: "#f59e0b",
        backgroundColor: "rgba(245,158,11,.12)", fill: true, tension: .3, pointRadius: 0 },
    ],
  },
  options: commonOptions,
});

const packetsChart = new Chart($("packetsChart"), {
  type: "bar",
  data: {
    labels: [],
    datasets: [{ label: "Packets/s", data: [], backgroundColor: "#22c55e" }],
  },
  options: commonOptions,
});

async function api(url, options) {
  const res = await fetch(url, options);
  return res.json();
}

async function updateTraffic() {
  try {
    const data = await api("/api/traffic");
    if (!data.length) return;

    const labels = data.map((p) => p.time);
    bandwidthChart.data.labels = labels;
    bandwidthChart.data.datasets[0].data = data.map((p) => p.down_bps / 1024);
    bandwidthChart.data.datasets[1].data = data.map((p) => p.up_bps / 1024);
    bandwidthChart.update("none");

    packetsChart.data.labels = labels;
    packetsChart.data.datasets[0].data = data.map((p) => Math.round(p.pps));
    packetsChart.update("none");

    const last = data[data.length - 1];
    $("stat-down").textContent = formatRate(last.down_bps);
    $("stat-up").textContent = formatRate(last.up_bps);
    $("stat-pps").textContent = Math.round(last.pps);
  } catch (e) { console.error("traffic:", e); }
}

async function updateDevices() {
  try {
    const data = await api("/api/devices");
    const body = $("devices-body");

    if (!data.length) {
      body.innerHTML =
        '<tr><td colspan="5" class="text-secondary text-center py-3">No devices yet...</td></tr>';
      return;
    }

    body.innerHTML = data.map((d) => {
      const statusBadge = d.status === "online"
        ? '<span class="badge text-bg-success">Online</span>'
        : '<span class="badge text-bg-secondary">Offline</span>';

      let action = "";
      if (d.is_self) {
        action = '<span class="badge text-bg-info">This PC</span>';
      } else if (d.trusted) {
        action = '<span class="badge text-bg-dark border">Trusted</span>';
      } else {
        action = `<button class="btn btn-sm btn-outline-warning btn-trust"
                    data-mac="${escapeHtml(d.mac)}">Trust</button>`;
      }

      return `<tr>
        <td class="mono">${escapeHtml(d.ip)}</td>
        <td class="mono">${escapeHtml(d.mac)}</td>
        <td>${escapeHtml(d.hostname)}</td>
        <td>${statusBadge}</td>
        <td>${action}</td>
      </tr>`;
    }).join("");
  } catch (e) { console.error("devices:", e); }
}

async function updateAlerts() {
  try {
    const data = await api("/api/alerts");
    const list = $("alerts-list");

    if (!data.length) {
      list.innerHTML = '<li class="list-group-item text-secondary text-center">No alerts</li>';
      return;
    }

    const badge = { high: "danger", medium: "warning", low: "info" };
    list.innerHTML = data.map((a) => `
      <li class="list-group-item alert-${escapeHtml(a.severity)}">
        <div class="d-flex justify-content-between">
          <span class="badge text-bg-${badge[a.severity] || "secondary"}">${escapeHtml(a.type)}</span>
          <small class="text-secondary">${escapeHtml(a.time)}</small>
        </div>
        <div class="mt-1 small">${escapeHtml(a.message)}</div>
      </li>`).join("");
  } catch (e) { console.error("alerts:", e); }
}

async function updateStatus() {
  try {
    const s = await api("/api/status");
    $("stat-devices").textContent = s.online_count + "/" + s.device_count;
    $("stat-alerts").textContent = s.alert_count;
    $("scan-info").textContent = s.scanning
      ? "Scanning..."
      : (s.last_scan ? "Last scan: " + s.last_scan : "");
    $("btn-scan").disabled = s.scanning;
  } catch (e) { console.error("status:", e); }
}


$("btn-scan").addEventListener("click", async () => {
  $("btn-scan").disabled = true;
  await api("/api/scan", { method: "POST" });
});

$("btn-sim-scan").addEventListener("click", async () => {
  await api("/api/simulate/portscan", { method: "POST" });
  updateAlerts(); updateStatus();
});

$("btn-sim-rogue").addEventListener("click", async () => {
  await api("/api/simulate/rogue", { method: "POST" });
  updateAlerts(); updateDevices(); updateStatus();
});


$("devices-body").addEventListener("click", async (e) => {
  const btn = e.target.closest(".btn-trust");
  if (!btn) return;
  await api("/api/trust", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mac: btn.dataset.mac }),
  });
  updateDevices();
});


function refreshSlow() { updateStatus(); updateDevices(); updateAlerts(); }

updateTraffic();
refreshSlow();
setInterval(updateTraffic, 1000);   
setInterval(refreshSlow, 3000);    
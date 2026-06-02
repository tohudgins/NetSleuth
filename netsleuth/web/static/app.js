"use strict";

// --- tabs ---
document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("tab-" + btn.dataset.tab).classList.add("active");
  });
});

// --- helpers ---
const esc = (s) =>
  String(s ?? "").replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const stateClass = (s) => "state-" + String(s).replace("|", "-");

function bytesHuman(n) {
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  return (n / 1048576).toFixed(1) + " MB";
}

function protoChart(byProto) {
  const entries = Object.entries(byProto || {}).sort((a, b) => b[1] - a[1]);
  if (!entries.length) return "";
  const max = Math.max(...entries.map((e) => e[1]));
  const rows = entries.map(([proto, n]) => {
    const w = Math.max(2, Math.round((n / max) * 100));
    return `<div class="bar-row"><span>${esc(proto)}</span>
      <span class="bar ${proto.toLowerCase()}" style="width:${w}%"></span>
      <span class="num">${n}</span></div>`;
  }).join("");
  return `<div class="card"><h3>Protocols</h3><div class="bars">${rows}</div></div>`;
}

function talkers(byIp) {
  if (!byIp || !byIp.length) return "";
  const rows = byIp.map((r) =>
    `<tr><td class="mono">${esc(r.ip)}</td><td class="num">${r.packets}</td>
     <td class="num">${bytesHuman(r.bytes)}</td></tr>`).join("");
  return `<div class="card"><h3>Top talkers</h3><table>
    <tr><th>Source IP</th><th class="num">Pkts</th><th class="num">Bytes</th></tr>
    ${rows}</table></div>`;
}

function anomaliesCard(anoms) {
  if (anoms === undefined) return "";
  if (!anoms.length)
    return `<div class="card"><h3>Anomalies</h3><span class="badge ok">none flagged</span></div>`;
  const items = anoms.map((a) =>
    `<div class="anom"><span class="kind">[${esc(a.kind)}]</span> ${esc(a.detail)}</div>`).join("");
  return `<div class="card full"><h3>Anomaly flags (heuristic)</h3>${items}</div>`;
}

function scanCard(scan) {
  if (!scan) return "";
  const open = scan.ports.filter((p) => p.state === "open" || p.state === "open|filtered");
  const hidden = scan.ports.length - open.length;
  let rows = open.map((p) => {
    const cves = (p.cves || []).map((c) =>
      `<div class="small"><span class="badge warn">${esc(c.id)}</span> ${esc(c.summary)}</div>`).join("");
    return `<tr><td class="num">${p.port}</td><td>${esc(p.proto)}</td>
      <td class="${stateClass(p.state)}">${esc(p.state)}</td>
      <td>${esc(p.service_hint || "")}</td>
      <td><span class="banner">${esc(p.banner || "")}</span>${cves}</td></tr>`;
  }).join("");
  if (!open.length) rows = `<tr><td colspan="5" class="muted">no open ports</td></tr>`;
  const os = scan.os_family_guess
    ? `<p class="small muted">OS family (heuristic): ${esc(scan.os_family_guess)}</p>` : "";
  const note = hidden ? `<p class="small muted">${hidden} closed/filtered not shown</p>` : "";
  return `<div class="card full"><h3>${esc(scan.scan_type)} scan of ${esc(scan.target)}</h3>${os}
    <table><tr><th class="num">Port</th><th>Proto</th><th>State</th><th>Service</th><th>Banner / CVEs</th></tr>
    ${rows}</table>${note}</div>`;
}

function trafficCard(traffic) {
  if (!traffic) return "";
  return `<div class="card"><h3>Traffic</h3>
    <p class="small">${traffic.packets} packets · ${bytesHuman(traffic.bytes)}</p></div>`
    + protoChart(traffic.by_proto) + talkers(traffic.by_ip);
}

function renderReport(container, report) {
  if (report.error) { container.innerHTML = `<div class="card error">${esc(report.error)}</div>`; return; }
  container.innerHTML =
    scanCard(report.scan) + trafficCard(report.traffic) + anomaliesCard(report.anomalies);
}

async function postJSON(url, body) {
  const r = await fetch(url, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { ok: r.ok, data: await r.json() };
}

// --- scan ---
document.getElementById("scan-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target, spin = document.getElementById("scan-spin");
  const out = document.getElementById("scan-results");
  spin.hidden = false; out.innerHTML = "";
  try {
    const { data } = await postJSON("/api/scan", {
      target: f.target.value, ports: f.ports.value,
      udp: f.udp.checked, connect: f.connect.checked, cve: f.cve.checked,
    });
    renderReport(out, data);
  } catch (err) {
    out.innerHTML = `<div class="card error">${esc(err)}</div>`;
  } finally { spin.hidden = true; }
});

// --- pcap ---
document.getElementById("pcap-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const spin = document.getElementById("pcap-spin");
  const out = document.getElementById("pcap-results");
  const fd = new FormData(e.target);
  if (!fd.get("file") || !fd.get("file").name) {
    out.innerHTML = `<div class="card error">choose a capture file first</div>`; return;
  }
  spin.hidden = false; out.innerHTML = "";
  try {
    const r = await fetch("/api/pcap", { method: "POST", body: fd });
    renderReport(out, await r.json());
  } catch (err) {
    out.innerHTML = `<div class="card error">${esc(err)}</div>`;
  } finally { spin.hidden = true; }
});

// --- live capture ---
let evtSource = null;
const liveStart = document.getElementById("live-start");
const liveStop = document.getElementById("live-stop");
const liveStatus = document.getElementById("live-status");

document.getElementById("live-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  const out = document.getElementById("live-results");
  const log = document.getElementById("live-packets");
  out.innerHTML = ""; log.innerHTML = "";
  liveStatus.textContent = "starting…";
  const { ok, data } = await postJSON("/api/capture/start", {
    iface: f.iface.value, filter: f.filter.value,
  });
  if (!ok) { liveStatus.textContent = ""; out.innerHTML = `<div class="card error">${esc(data.error)}</div>`; return; }

  liveStart.disabled = true; liveStop.disabled = false; liveStatus.textContent = "● capturing";
  evtSource = new EventSource("/api/capture/events");
  evtSource.onmessage = (msg) => {
    const p = JSON.parse(msg.data);
    out.innerHTML = trafficCard(p.stats) + anomaliesCard(p.anomalies);
    for (const pkt of p.packets) {
      const div = document.createElement("div");
      div.className = "ln p-" + String(pkt.proto).toLowerCase();
      div.textContent = `${String(pkt.proto).padEnd(6)} ${String(pkt.length).padStart(5)}B  ${pkt.info}`;
      log.appendChild(div);
    }
    log.scrollTop = log.scrollHeight;
    if (p.error) { out.innerHTML = `<div class="card error">Capture failed: ${esc(p.error)}</div>` + out.innerHTML; }
    if (!p.running) endLive();
  };
  evtSource.onerror = () => endLive();
});

function endLive() {
  if (evtSource) { evtSource.close(); evtSource = null; }
  liveStart.disabled = false; liveStop.disabled = true; liveStatus.textContent = "";
}

liveStop.addEventListener("click", async () => {
  liveStatus.textContent = "stopping…";
  await fetch("/api/capture/stop", { method: "POST" });
  endLive();
});

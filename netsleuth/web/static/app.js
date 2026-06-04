"use strict";

// ---------------------------------------------------------------------------
// NetSleuth dashboard front-end. Vanilla JS, no build step / no CDN deps — the
// charts are hand-drawn SVG so the tool stays self-contained and offline.
// ---------------------------------------------------------------------------

// Protocol palette — kept in sync with the CSS custom properties so the donut,
// the traffic chart and the packet log all colour a protocol the same way.
const PROTO_COLORS = {
  TCP: "#4f8cff", UDP: "#22d3ee", DNS: "#34d399", ARP: "#fbbf24",
  ICMP: "#c084fc", ICMPv6: "#c084fc", IP: "#64748b", IPv6: "#64748b", OTHER: "#64748b",
};
const protoColor = (p) => PROTO_COLORS[p] || "#64748b";

// --- helpers ---------------------------------------------------------------
const esc = (s) =>
  String(s ?? "").replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const stateClass = (s) => "state-" + String(s).replace("|", "-");

function bytesHuman(n) {
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  return (n / 1048576).toFixed(1) + " MB";
}

async function postJSON(url, body) {
  const r = await fetch(url, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { ok: r.ok, data: await r.json() };
}

// --- generic sortable tables ----------------------------------------------
// Click a header cell with class "sortable" to sort the tbody. data-type="num"
// sorts numerically (reading data-sort if present, else the cell text).
function makeSortable(table) {
  const heads = table.querySelectorAll("th.sortable");
  heads.forEach((th) => {
    th.addEventListener("click", () => {
      const numeric = th.dataset.type === "num";
      const asc = !(th.classList.contains("sort-asc"));
      heads.forEach((h) => h.classList.remove("sort-asc", "sort-desc"));
      th.classList.add(asc ? "sort-asc" : "sort-desc");
      const tbody = table.tBodies[0];
      const rows = [...tbody.rows].filter((r) => !r.dataset.noSort);
      const key = (row) => {
        const cell = row.cells[colIndex(th)];
        if (!cell) return numeric ? 0 : "";
        const raw = cell.dataset.sort ?? cell.textContent.trim();
        return numeric ? parseFloat(raw) || 0 : raw.toLowerCase();
      };
      rows.sort((a, b) => {
        const x = key(a), y = key(b);
        return (x < y ? -1 : x > y ? 1 : 0) * (asc ? 1 : -1);
      });
      rows.forEach((r) => tbody.appendChild(r));
    });
  });
  // index of a header among its row (handles any leading non-sortable cells)
  function colIndex(th) { return [...th.parentNode.children].indexOf(th); }
}

function activateTables(container) {
  container.querySelectorAll("table[data-sortable]").forEach(makeSortable);
}

// --- charts (hand-drawn SVG) ----------------------------------------------
function donutChart(byProto) {
  const entries = Object.entries(byProto || {}).sort((a, b) => b[1] - a[1]);
  const total = entries.reduce((s, e) => s + e[1], 0);
  if (!total) return "";
  const R = 52, C = 2 * Math.PI * R;
  let offset = 0;
  const segs = entries.map(([proto, n]) => {
    const frac = n / total;
    const dash = `${(frac * C).toFixed(2)} ${(C - frac * C).toFixed(2)}`;
    const circle = `<circle r="${R}" cx="70" cy="70" fill="none"
      stroke="${protoColor(proto)}" stroke-width="16"
      stroke-dasharray="${dash}" stroke-dashoffset="${(-offset * C).toFixed(2)}"
      transform="rotate(-90 70 70)"></circle>`;
    offset += frac;
    return circle;
  }).join("");
  const legend = entries.map(([proto, n]) =>
    `<div class="row"><span class="dot" style="background:${protoColor(proto)}"></span>
      <span>${esc(proto)}</span>
      <span class="num">${n} · ${((n / total) * 100).toFixed(0)}%</span></div>`).join("");
  return `<div class="card"><h3>Protocols</h3><div class="donut-wrap">
    <svg class="donut" width="140" height="140" viewBox="0 0 140 140">${segs}
      <text x="70" y="66" text-anchor="middle" fill="#e2e8f0" font-size="20" font-weight="700">${total}</text>
      <text x="70" y="84" text-anchor="middle" fill="#8094b3" font-size="9">packets</text>
    </svg><div class="legend">${legend}</div></div></div>`;
}

// Build an SVG area+line chart from a numeric series (packets per tick).
function sparkline(series) {
  const W = 600, H = 90, pad = 4;
  if (series.length < 2) return `<div class="card full"><h3>Traffic over time</h3>
    <p class="muted small">collecting…</p></div>`;
  const max = Math.max(...series, 1);
  const dx = (W - pad * 2) / (series.length - 1);
  const pts = series.map((v, i) =>
    [pad + i * dx, H - pad - (v / max) * (H - pad * 2)]);
  const line = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
  const area = `M${pad} ${H - pad} ` + pts.map((p) => "L" + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ") + ` L${(W - pad).toFixed(1)} ${H - pad} Z`;
  return `<div class="card full"><h3>Traffic over time · peak ${max} pkt/tick</h3>
    <svg class="chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
      <path class="area" d="${area}"></path><path class="line" d="${line}"></path>
    </svg></div>`;
}

// --- cards -----------------------------------------------------------------
function statRow(items) {
  const cells = items.filter(Boolean).map(([n, l]) =>
    `<div class="stat"><div class="n">${n}</div><div class="l">${esc(l)}</div></div>`).join("");
  return cells ? `<div class="card full"><div class="statrow">${cells}</div></div>` : "";
}

function alertsCard(title, items, emptyMsg) {
  if (items === undefined) return "";
  if (!items.length)
    return `<div class="card full"><h3>${esc(title)}</h3><span class="badge ok">${esc(emptyMsg)}</span></div>`;
  const rows = items.map((a) =>
    `<div class="alert ${esc(a.severity)}"><span class="kind">[${esc(a.kind)}]</span> ${esc(a.detail)}</div>`).join("");
  return `<div class="card full"><h3>${esc(title)}</h3>${rows}</div>`;
}

function talkersCard(byIp) {
  if (!byIp || !byIp.length) return "";
  const hasGeo = byIp.some((r) => r.country || r.asn);
  const rows = byIp.map((r) => {
    const geo = hasGeo
      ? `<td>${esc(r.country || "—")}</td><td class="small">${esc([r.asn, r.org].filter(Boolean).join(" ") || "—")}</td>`
      : "";
    return `<tr><td class="mono">${esc(r.ip)}</td>
      <td class="num" data-sort="${r.packets}">${r.packets}</td>
      <td class="num" data-sort="${r.bytes}">${bytesHuman(r.bytes)}</td>${geo}</tr>`;
  }).join("");
  const geoHead = hasGeo
    ? `<th class="sortable">Country</th><th class="sortable">ASN / Org</th>` : "";
  return `<div class="card"><h3>Top talkers</h3>
    <table data-sortable><thead><tr>
      <th class="sortable">Source IP</th>
      <th class="sortable num" data-type="num">Pkts</th>
      <th class="sortable num" data-type="num">Bytes</th>${geoHead}
    </tr></thead><tbody>${rows}</tbody></table></div>`;
}

function scanCard(scan) {
  if (!scan) return "";
  const open = scan.ports.filter((p) => p.state === "open" || p.state === "open|filtered");
  const hidden = scan.ports.length - open.length;
  let rows = open.map((p) => {
    const cves = (p.cves || []).map((c) =>
      `<div class="small"><span class="badge warn">${esc(c.id)}</span>
        <span class="muted">${esc(c.match || "keyword")}</span> ${esc(c.summary)}</div>`).join("");
    return `<tr><td class="num" data-sort="${p.port}">${p.port}</td><td>${esc(p.proto)}</td>
      <td class="${stateClass(p.state)}">${esc(p.state)}</td>
      <td>${esc(p.service_hint || "")}</td>
      <td><span class="banner">${esc(p.banner || "")}</span>${cves}</td></tr>`;
  }).join("");
  if (!open.length) rows = `<tr data-no-sort="1"><td colspan="5" class="muted">no open ports</td></tr>`;
  const os = scan.os_family_guess
    ? `<p class="small muted">OS family (heuristic): ${esc(scan.os_family_guess)}</p>` : "";
  const note = hidden ? `<p class="small muted">${hidden} closed/filtered not shown</p>` : "";
  return `<div class="card full"><h3>${esc(scan.scan_type)} scan of ${esc(scan.target)}</h3>${os}
    <table data-sortable><thead><tr>
      <th class="sortable num" data-type="num">Port</th><th class="sortable">Proto</th>
      <th class="sortable">State</th><th class="sortable">Service</th><th>Banner / CVEs</th>
    </tr></thead><tbody>${rows}</tbody></table>${note}</div>`;
}

function discoveryCard(d) {
  if (!d) return "";
  const rows = d.hosts.map((h) =>
    `<tr><td class="mono" data-sort="${ipSort(h.ip)}">${esc(h.ip)}</td>
      <td class="mono">${esc(h.mac || "—")}</td>
      <td>${h.vendor ? `<span class="badge vendor">${esc(h.vendor)}</span>` : "—"}</td>
      <td>${esc(h.method)}</td>
      <td class="mono">${h.open_ports && h.open_ports.length ? esc(h.open_ports.join(", ")) : "—"}</td></tr>`).join("");
  const body = d.hosts.length ? rows
    : `<tr data-no-sort="1"><td colspan="5" class="muted">no hosts responded</td></tr>`;
  return statRow([[d.count, "hosts up"], [esc(d.method), "method"]]) +
    `<div class="card full"><h3>Hosts on ${esc(d.network)}</h3>
    <table data-sortable><thead><tr>
      <th class="sortable">IP</th><th class="sortable">MAC</th>
      <th class="sortable">Vendor (best guess)</th><th class="sortable">Via</th>
      <th>Open ports</th>
    </tr></thead><tbody>${body}</tbody></table>
    <p class="small muted">Vendor is a best-guess from a partial built-in OUI table.</p></div>`;
}
// numeric sort key for an IPv4 string (falls back to 0 for IPv6/odd input)
function ipSort(ip) {
  const parts = String(ip).split(".");
  if (parts.length !== 4) return 0;
  return parts.reduce((acc, p) => acc * 256 + (parseInt(p, 10) || 0), 0);
}

function trafficCards(traffic) {
  if (!traffic) return "";
  return statRow([[traffic.packets, "packets"], [bytesHuman(traffic.bytes), "volume"]]) +
    donutChart(traffic.by_proto) + talkersCard(traffic.by_ip);
}

// "What changed since last run" card, for scan + discovery diffs.
function diffCard(diff) {
  if (!diff) return "";
  if (diff.empty)
    return `<div class="card full"><h3>Changes since last run</h3><span class="badge ok">no changes</span></div>`;
  const d = (cls, label, rest) => `<div class="delta"><span class="${cls}">${label}</span> ${rest}</div>`;
  let rows = "";
  if (diff.kind === "scan") {
    rows += diff.ports_opened.map((p) => d("add", "+ opened", `port ${p}`)).join("");
    rows += diff.ports_closed.map((p) => d("del", "− closed", `port ${p}`)).join("");
    rows += diff.service_changed.map((c) =>
      d("chg", "~ service", `port ${c.port}: ${esc(c.from || "—")} → ${esc(c.to || "—")}`)).join("");
    rows += diff.banner_changed.map((p) => d("chg", "~ banner", `port ${p} changed`)).join("");
    if (diff.os_changed)
      rows += d("chg", "~ OS guess", `${esc(diff.os_changed.from || "—")} → ${esc(diff.os_changed.to || "—")}`);
  } else {
    rows += diff.hosts_added.map((h) =>
      d("add", "+ host", esc(h.ip) + (h.mac ? ` (${esc(h.mac)})` : ""))).join("");
    rows += diff.hosts_removed.map((h) => d("del", "− host", esc(h.ip))).join("");
    rows += diff.mac_changed.map((c) =>
      d("crit", "! MAC changed", `${esc(c.ip)}: ${esc(c.from)} → ${esc(c.to)} (possible spoofing)`)).join("");
    rows += diff.vendor_changed.map((c) =>
      d("chg", "~ vendor", `${esc(c.ip)}: ${esc(c.from || "—")} → ${esc(c.to || "—")}`)).join("");
    rows += diff.ports_changed.map((c) =>
      d("chg", "~ ports", `${esc(c.ip)}: ${esc((c.from || []).join(", ") || "—")} → ${esc((c.to || []).join(", ") || "—")}`)).join("");
  }
  return `<div class="card full"><h3>Changes since last run</h3>${rows}</div>`;
}

// Render a full /report-shaped object into a container (scan/pcap tabs).
function renderReport(container, report) {
  if (report.error) { container.innerHTML = `<div class="card error">${esc(report.error)}</div>`; return; }
  container.innerHTML =
    diffCard(report.diff) +
    scanCard(report.scan) +
    discoveryCard(report.discovery) +
    trafficCards(report.traffic) +
    alertsCard("ARP-spoofing / MITM alerts (heuristic)", report.defense, "no spoofing signs detected") +
    alertsCard("Anomaly flags (heuristic)", report.anomalies, "none flagged");
  activateTables(container);
}

// --- scan ------------------------------------------------------------------
document.getElementById("scan-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target, spin = document.getElementById("scan-spin");
  const out = document.getElementById("scan-results");
  spin.hidden = false; out.innerHTML = "";
  try {
    const { data } = await postJSON("/api/scan", {
      target: f.target.value, ports: f.ports.value, timing: f.timing.value,
      udp: f.udp.checked, connect: f.connect.checked, cve: f.cve.checked,
      save: f.save.checked, diff: f.save.checked,
    });
    renderReport(out, data);
  } catch (err) {
    out.innerHTML = `<div class="card error">${esc(err)}</div>`;
  } finally { spin.hidden = true; }
});

// --- discover --------------------------------------------------------------
document.getElementById("discover-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target, spin = document.getElementById("discover-spin");
  const out = document.getElementById("discover-results");
  spin.hidden = false; out.innerHTML = "";
  try {
    const { data } = await postJSON("/api/discover", {
      network: f.network.value, iface: f.iface.value,
      save: f.save.checked, diff: f.save.checked,
    });
    renderReport(out, data);
  } catch (err) {
    out.innerHTML = `<div class="card error">${esc(err)}</div>`;
  } finally { spin.hidden = true; }
});

// --- pcap ------------------------------------------------------------------
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

// --- live capture ----------------------------------------------------------
let evtSource = null;
let trafficSeries = [];      // packets-per-tick for the sparkline
let lastTotal = 0;
const liveStart = document.getElementById("live-start");
const liveStop = document.getElementById("live-stop");
const liveStatus = document.getElementById("live-status");
const liveGrid = document.querySelector(".live-grid");

document.getElementById("live-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  const out = document.getElementById("live-results");
  const log = document.getElementById("live-packets");
  out.innerHTML = ""; log.innerHTML = "";
  trafficSeries = []; lastTotal = 0;
  closeDetail();
  liveStatus.textContent = "starting…";
  const { ok, data } = await postJSON("/api/capture/start", {
    iface: f.iface.value, filter: f.filter.value,
  });
  if (!ok) { liveStatus.textContent = ""; out.innerHTML = `<div class="card error">${esc(data.error)}</div>`; return; }

  liveStart.disabled = true; liveStop.disabled = false; liveStatus.textContent = "● capturing";
  evtSource = new EventSource("/api/capture/events");
  evtSource.onmessage = (msg) => {
    const p = JSON.parse(msg.data);
    // update the traffic series from the cumulative packet count
    const total = p.stats ? p.stats.packets : 0;
    trafficSeries.push(Math.max(0, total - lastTotal)); lastTotal = total;
    if (trafficSeries.length > 80) trafficSeries.shift();

    out.innerHTML =
      sparkline(trafficSeries) +
      trafficCards(p.stats) +
      alertsCard("ARP-spoofing / MITM alerts (heuristic)", p.defense, "no spoofing signs detected") +
      alertsCard("Anomaly flags (heuristic)", p.anomalies, "none flagged");
    activateTables(out);

    for (const pkt of p.packets) {
      const div = document.createElement("div");
      div.className = "ln p-" + String(pkt.proto).toLowerCase();
      div.dataset.i = pkt.i;
      div.textContent = `${String(pkt.proto).padEnd(6)} ${String(pkt.length).padStart(5)}B  ${pkt.info}`;
      div.addEventListener("click", () => showDetail(div));
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

// --- packet drill-down (hexdump) ------------------------------------------
const detailPanel = document.getElementById("packet-detail");
const detailHex = document.getElementById("detail-hex");
document.getElementById("detail-close").addEventListener("click", closeDetail);

async function showDetail(lineEl) {
  document.querySelectorAll(".packets .ln.sel").forEach((el) => el.classList.remove("sel"));
  lineEl.classList.add("sel");
  detailPanel.hidden = false; liveGrid.classList.add("with-detail");
  detailHex.textContent = "loading…";
  try {
    const r = await fetch("/api/capture/frame/" + lineEl.dataset.i);
    const d = await r.json();
    detailHex.textContent = r.ok
      ? `#${d.index} · ${d.length} bytes\n\n${d.hex}`
      : (d.error || "frame unavailable");
  } catch (err) {
    detailHex.textContent = String(err);
  }
}

function closeDetail() {
  detailPanel.hidden = true; liveGrid.classList.remove("with-detail");
  document.querySelectorAll(".packets .ln.sel").forEach((el) => el.classList.remove("sel"));
}

// --- history ---------------------------------------------------------------
const historyList = document.getElementById("history-list");
const historyDetail = document.getElementById("history-detail");

async function loadHistory() {
  historyDetail.innerHTML = "";
  let runs;
  try {
    runs = (await (await fetch("/api/history")).json()).runs;
  } catch (err) {
    historyList.innerHTML = `<div class="card error">${esc(err)}</div>`; return;
  }
  if (!runs.length) {
    historyList.innerHTML = `<div class="card full"><span class="muted">no saved runs yet — tick “Save to history” on a scan or discovery.</span></div>`;
    return;
  }
  const rows = runs.map((r) =>
    `<tr class="hist-row" data-id="${r.id}">
      <td class="num">${r.id}</td><td class="mono">${esc(r.created_at)}</td>
      <td>${esc(r.kind)}</td><td class="mono">${esc(r.target)}</td></tr>`).join("");
  historyList.innerHTML = `<div class="card full"><h3>Saved runs</h3>
    <table data-sortable><thead><tr>
      <th class="sortable num" data-type="num">ID</th><th class="sortable">When (UTC)</th>
      <th class="sortable">Kind</th><th class="sortable">Target</th>
    </tr></thead><tbody>${rows}</tbody></table></div>`;
  activateTables(historyList);
  historyList.querySelectorAll(".hist-row").forEach((tr) =>
    tr.addEventListener("click", () => showRun(tr.dataset.id)));
}

async function showRun(id) {
  historyDetail.innerHTML = `<div class="card full muted">loading…</div>`;
  try {
    const report = await (await fetch("/api/history/" + id)).json();
    const { diff } = await (await fetch("/api/history/" + id + "/diff")).json();
    report.diff = diff;  // renderReport shows the diff card first
    renderReport(historyDetail, report);
  } catch (err) {
    historyDetail.innerHTML = `<div class="card error">${esc(err)}</div>`;
  }
}

document.getElementById("history-refresh").addEventListener("click", loadHistory);

// --- tabs (wired last so the handlers above already exist) ----------------
document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("tab-" + btn.dataset.tab).classList.add("active");
    if (btn.dataset.tab === "history") loadHistory();
  });
});

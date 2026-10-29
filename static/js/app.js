/* thscan frontend — vanilla JS, wired to the REST API. */
(() => {
"use strict";
const $ = s => document.querySelector(s), $$ = s => Array.from(document.querySelectorAll(s));
const api = (p, opt) => fetch(p, opt).then(async r => { const d = await r.json().catch(() => ({})); if (!r.ok) throw new Error(d.detail || ("HTTP " + r.status)); return d; });
const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = n => Number(n).toLocaleString("en-US");
const tip = t => `<span class="tip" data-tip="${esc(t)}" tabindex="0" role="img" aria-label="ข้อมูลเพิ่มเติม">ⓘ</span>`;

// ── tooltip engine (hover + tap + keyboard) ──
(() => {
  const box = $("#ttBox"); let pinned = false;
  const place = (x, y) => { let l = x - box.offsetWidth / 2, t = y - box.offsetHeight - 12; l = Math.max(6, Math.min(l, innerWidth - box.offsetWidth - 6)); if (t < 6) t = y + 18; box.style.left = l + "px"; box.style.top = t + "px"; };
  const show = (el, x, y) => { box.textContent = el.dataset.tip; box.classList.add("show"); place(x, y); };
  const hide = () => box.classList.remove("show");
  document.addEventListener("mouseover", e => { if (pinned) return; const t = e.target.closest("[data-tip]"); if (t) show(t, e.clientX, e.clientY); });
  document.addEventListener("mouseout", e => { if (pinned) return; if (e.target.closest("[data-tip]")) hide(); });
  document.addEventListener("mousemove", e => { if (pinned || !box.classList.contains("show")) return; place(e.clientX, e.clientY); });
  document.addEventListener("click", e => { const t = e.target.closest("[data-tip]"); if (t) { const r = t.getBoundingClientRect(); show(t, r.left + r.width / 2, r.top); pinned = true; e.stopPropagation(); } else if (pinned) { pinned = false; hide(); } });
  document.addEventListener("focusin", e => { const t = e.target.closest("[data-tip]"); if (t) { const r = t.getBoundingClientRect(); show(t, r.left + r.width / 2, r.top); } });
  document.addEventListener("focusout", e => { if (!pinned && e.target.closest("[data-tip]")) hide(); });
})();

// ── routing ──
const VIEWS = ["scan", "scanning", "results", "profile"];
function go(v) {
  if (!VIEWS.includes(v)) v = "scan";
  VIEWS.forEach(x => $("#view-" + x).classList.toggle("hidden", x !== v));
  $$("#appnav .navlink").forEach(a => a.classList.toggle("active", a.dataset.view === v));
  scrollTo(0, 0);
}
$$("#appnav .navlink").forEach(a => a.addEventListener("click", () => go(a.dataset.view)));

const state = { config: null, job: null, poll: null };

// ── SCAN (target picker) ──
let mode = "auto";
const octEl = (g, i) => document.querySelector(`.o[data-g="${g}"][data-i="${i}"]`);
const oct = (g, i) => { const el = octEl(g, i); let n = parseInt(el && el.value, 10); return isNaN(n) ? 0 : Math.min(255, Math.max(0, n)); };
$$(".o").forEach(inp => {
  inp.addEventListener("input", () => { let v = inp.value.replace(/[^0-9]/g, "").slice(0, 3); if (v !== "" && +v > 255) v = "255"; inp.value = v; if (v.length === 3) { const nx = octEl(inp.dataset.g, +inp.dataset.i + 1); if (nx) nx.focus(); } renderSummary(); });
  inp.addEventListener("blur", () => { if (inp.value === "") { inp.value = "0"; renderSummary(); } });
});
$$("#modes .mode").forEach(b => b.addEventListener("click", () => { $$("#modes .mode").forEach(x => x.setAttribute("aria-pressed", "false")); b.setAttribute("aria-pressed", "true"); mode = b.dataset.mode; ["auto", "cidr", "range", "single"].forEach(m => $("#pane-" + m).classList.toggle("hide", m !== mode)); renderSummary(); }));
$("#cidr-prefix").addEventListener("change", renderSummary);
$$("#cidr-presets .preset").forEach(p => p.addEventListener("click", () => { const [net, pre] = p.dataset.fill.split("/"); const o = net.split("."); [0, 1, 2, 3].forEach(i => octEl("cidr", i).value = o[i]); $("#cidr-prefix").value = pre; renderSummary(); }));

const toInt = (a, b, c, d) => ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;
const toIp = n => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
const isPriv = n => { const a = (n >>> 24) & 255, b = (n >>> 16) & 255; return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a === 127; };
const estTime = c => { const s = Math.max(1, Math.round(c / 600)); return s < 60 ? s + " วินาที" : Math.round(s / 60) + " นาที"; };
function cidr(a, b, c, d, p) { const base = toInt(a, b, c, d), mask = p === 0 ? 0 : (0xFFFFFFFF << (32 - p)) >>> 0, net = (base & mask) >>> 0, bc = (net | (~mask >>> 0)) >>> 0, total = Math.pow(2, 32 - p), count = p <= 30 ? total - 2 : total; return { ok: true, start: p <= 30 ? (net + 1) >>> 0 : net, end: p <= 30 ? (bc - 1) >>> 0 : bc, count, label: "ซับเน็ต /" + p, spec: toIp(net) + "/" + p }; }
function compute() {
  if (mode === "auto") { const sel = document.querySelector('#nicList .nic[aria-pressed="true"]'); if (!sel) return { ok: false, err: "ยังไม่พบเครือข่าย — เลือกโหมดอื่น", count: 0, start: 0, end: 0, label: "วง LAN" }; const [net, pre] = sel.dataset.cidr.split("/"); const o = net.split(".").map(Number); return cidr(o[0], o[1], o[2], o[3], +pre); }
  if (mode === "cidr") return cidr(oct("cidr", 0), oct("cidr", 1), oct("cidr", 2), oct("cidr", 3), +$("#cidr-prefix").value);
  if (mode === "single") { const n = toInt(oct("single", 0), oct("single", 1), oct("single", 2), oct("single", 3)); return { ok: true, start: n, end: n, count: 1, label: "IP เดียว", spec: toIp(n) }; }
  const base = [oct("range", 0), oct("range", 1), oct("range", 2)], s = oct("range", 3), e = oct("range", 4);
  const start = toInt(base[0], base[1], base[2], s), end = toInt(base[0], base[1], base[2], e);
  if (e < s) return { ok: false, err: "เลข 'สิ้นสุด' ต้องไม่น้อยกว่า 'เริ่ม'", count: 0, start, end, label: "ช่วง IP" };
  return { ok: true, start, end, count: e - s + 1, label: "ช่วง IP", spec: toIp(start) + "-" + toIp(end) };
}
function renderSummary() {
  const r = compute(), sum = $("#summary"), MAX = (state.config && state.config.max_targets) || 65536;
  $("#sumRange").textContent = r.count <= 1 ? toIp(r.start) : (toIp(r.start) + "  –  " + toIp(r.end));
  $("#sumCount").textContent = r.ok ? fmt(r.count) + " IP" : "—"; $("#sumScope").textContent = r.label || "—"; $("#sumTime").textContent = r.ok ? "~" + estTime(r.count) : "—";
  let level = "ok", badge = "✓ พร้อมสแกน", msg = "", enable = true;
  if (!r.ok) { level = "err"; badge = "✕ กรอกไม่ถูกต้อง"; msg = r.err; enable = false; }
  else if (r.count > MAX) { level = "err"; badge = "✕ ช่วงใหญ่เกินไป"; enable = false; msg = "เกินขีดจำกัด " + fmt(MAX) + " IP ต่อการสแกน"; }
  else if (!isPriv(r.start) || !isPriv(r.end)) { level = "warn"; badge = "⚠ IP สาธารณะ"; msg = "ช่วงนี้เป็น IP สาธารณะ — จะสแกนได้ก็ต่อเมื่ออยู่ใน scope ที่ผู้ดูแลตั้งไว้"; }
  else msg = "เป้าหมายอยู่ในวงเครือข่ายส่วนตัว (private)";
  sum.className = "summary " + level; $("#sumBadge").textContent = badge; $("#sumMsg").textContent = msg;
  $("#startBtn").disabled = !enable; $("#footCnt").textContent = enable ? ("จะสแกน " + fmt(r.count) + " เป้าหมาย") : "";
}
$("#startBtn").addEventListener("click", startScan);

async function startScan() {
  const r = compute(); if (!r.ok) return;
  $("#scanErr").textContent = ""; $("#startBtn").disabled = true;
  try {
    const job = await api("/api/scans", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ targets: [r.spec] }) });
    state.job = job.id; $("#scanScope").textContent = r.spec; $("#totalN").textContent = fmt(job.total_ips || r.count);
    resetRing(); go("scanning"); startPoll(job.id);
  } catch (e) { $("#scanErr").textContent = e.message; } finally { $("#startBtn").disabled = false; }
}

// ── SCANNING (progress) ──
const RC = 2 * Math.PI * 104; const STEPS = ["ค้นหาอุปกรณ์ออนไลน์…", "ตรวจพอร์ตและบริการที่เปิด…", "ตรวจเวอร์ชัน PHP…", "ประเมินตามเกณฑ์ ThaiCERT…"];
function resetRing() { const arc = $("#arc"); arc.style.strokeDasharray = RC; arc.style.strokeDashoffset = RC; $("#pct").textContent = "0%"; $("#orb").classList.remove("done"); $("#line").style.width = "0"; }
function updateScanning(job) {
  const p = job.progress, total = p.total_ips || 1;
  const pct = Math.min(100, Math.round((p.probed / total) * 100));
  $("#arc").style.strokeDashoffset = RC * (1 - pct / 100); $("#pct").textContent = pct + "%"; $("#line").style.width = pct + "%";
  $("#probed").textContent = fmt(p.probed); $("#totalN").textContent = fmt(total);
  $("#onlineN").textContent = fmt(p.online); $("#riskN").textContent = fmt(p.risks);
  $("#stepTxt").textContent = STEPS[Math.min(STEPS.length - 1, Math.floor(pct / 25))];
}
$("#cancelBtn").addEventListener("click", async () => { if (state.job) { await api("/api/scans/" + state.job + "/cancel", { method: "POST" }).catch(() => {}); } });

function startPoll(id) {
  if (state.poll) clearInterval(state.poll);
  const tick = async () => {
    try {
      const job = await api("/api/scans/" + id);
      updateScanning(job);
      if (["completed", "cancelled", "failed"].includes(job.state)) {
        clearInterval(state.poll); state.poll = null;
        if (job.state === "failed") { $("#scanErr").textContent = job.error || "สแกนล้มเหลว"; go("scan"); return; }
        $("#pct").textContent = "✓"; $("#orb").classList.add("done");
        Results.load(job); go("results");
      }
    } catch (e) { /* transient */ }
  };
  tick(); state.poll = setInterval(tick, 1200);
}

// ── RESULTS ──
const Results = (() => {
  let devices = [], meta = {}, st = { cat: "all", q: "", adv: { sev: "all", svc: "all", port: "all", lat: null }, sel: null };
  const sevLabel = s => ({ critical: "ร้ายแรงมาก", high: "สูง", low: "เสี่ยงต่ำ", safe: "ปลอดภัย" }[s] || s);
  const hasWeb = d => (d.open_ports && d.open_ports.length) || d.php_version;
  const phpClass = d => !hasWeb(d) ? "none" : (d.findings || []).some(f => f.rule_id === "php2shell") ? "vuln" : "ok";
  const counts = () => ({ all: devices.length, risk: devices.filter(d => d.severity !== "safe").length, php: devices.filter(hasWeb).length, client: devices.filter(d => !hasWeb(d)).length });
  function matches(d) {
    const a = st.adv;
    if (st.cat === "risk" && d.severity === "safe") return false;
    if (st.cat === "php" && !hasWeb(d)) return false;
    if (st.cat === "client" && hasWeb(d)) return false;
    if (st.q) { const h = (d.ip + " " + d.device_type + " " + d.service + " " + (d.mac || "") + " " + (d.php_version || "")).toLowerCase(); if (!h.includes(st.q)) return false; }
    if (a.sev !== "all" && d.severity !== a.sev) return false;
    if (a.svc === "web" && !hasWeb(d)) return false;
    if (a.svc === "none" && hasWeb(d)) return false;
    if (a.port === "open" && (!d.open_ports || !d.open_ports.length)) return false;
    if (a.port === "closed" && d.open_ports && d.open_ports.length) return false;
    if (a.lat != null && d.latency_ms != null && d.latency_ms > a.lat) return false;
    return true;
  }
  function triage() {
    const c = counts(), hero = c.risk > 0;
    $("#triage").innerHTML =
      `<div class="tri hero ${hero ? "risk" : "safe"}"><div class="cap">${hero ? "⚠ ต้องดำเนินการ" : "✓ สถานะเครือข่าย"}${tip("จำนวนอุปกรณ์ที่พบความเสี่ยงและควรแก้ไขก่อน")}</div><div class="big">${hero ? c.risk : "ปลอดภัย"}</div><div class="sub">${hero ? "อุปกรณ์ที่พบความเสี่ยง" : "ไม่พบบริการ PHP ที่มีช่องโหว่"}</div></div>` +
      `<div class="tri"><div class="cap">เซิร์ฟเวอร์ PHP${tip("อุปกรณ์ที่เปิดบริการเว็บ/PHP — กลุ่มที่อาจเสี่ยงต่อ php2shell")}</div><div class="big">${c.php}</div><div class="sub">มีบริการเว็บ/PHP</div></div>` +
      `<div class="tri"><div class="cap"><span class="dotg"></span> ออนไลน์${tip("จำนวนอุปกรณ์ที่กำลังเปิดใช้งานในเครือข่าย")}</div><div class="big">${c.all}</div><div class="sub">อุปกรณ์ในเครือข่าย</div></div>` +
      `<div class="tri"><div class="cap">เวลาสแกน${tip("เวลาที่ใช้สแกน · Workers คือจำนวนงานที่ตรวจพร้อมกัน")}</div><div class="big">${meta.duration != null ? meta.duration : "—"}<span style="font-size:14px;color:var(--g400)"> วิ</span></div><div class="sub">${meta.workers || 0} workers</div></div>`;
  }
  function render() {
    const c = counts();
    $("#c-all").textContent = c.all; $("#c-risk").textContent = c.risk; $("#c-php").textContent = c.php; $("#c-client").textContent = c.client;
    triage();
    const rows = devices.filter(matches);
    if (!st.sel || !rows.includes(st.sel)) st.sel = rows[0] || null;
    const list = $("#list"); list.innerHTML = "";
    rows.forEach(d => {
      const el = document.createElement("div");
      el.className = "host sev-" + d.severity + (d === st.sel ? " sel" : "");
      el.innerHTML = `<span class="hdot"></span><span class="main"><div class="ip">${esc(d.ip)}</div><div class="meta">${esc(d.device_type)}${d.latency_ms != null ? " · " + d.latency_ms + " ms" : ""}</div></span><span class="right"><span class="sev ${d.severity}">${sevLabel(d.severity)}</span><span class="php-tag ${phpClass(d)}">${esc(d.php_version || (hasWeb(d) ? "เว็บ" : "ไม่มีเว็บ"))}</span></span>`;
      el.addEventListener("click", () => { st.sel = d; render(); if (matchMedia("(max-width:800px)").matches) $("#detail").scrollIntoView({ behavior: "smooth", block: "start" }); });
      list.appendChild(el);
    });
    $("#emptyRow").hidden = rows.length > 0;
    $("#emptyRow").textContent = devices.length ? "ไม่พบอุปกรณ์ที่ตรงกับตัวกรอง" : "ไม่พบอุปกรณ์ออนไลน์ในช่วงที่สแกน";
    $("#showing").textContent = "แสดง " + rows.length + " / " + c.all + " อุปกรณ์";
    detail();
  }
  function detail() {
    const d = st.sel, box = $("#detail");
    if (!d) { box.innerHTML = '<div class="empty">เลือกอุปกรณ์ทางซ้ายเพื่อดูรายละเอียด</div>'; return; }
    const bk = d.severity, bT = { critical: "พบช่องโหว่ร้ายแรง", high: "พบความเสี่ยงสูง", low: "พบความเสี่ยงระดับต่ำ", safe: "ปลอดภัย — ไม่พบช่องโหว่" }[d.severity] || "ผลการตรวจ";
    const bS = { critical: "ควรรีบแก้ไขโดยด่วน", high: "ควรแก้ไข", low: "ควรปรับปรุงเมื่อสะดวก", safe: "ผ่านเกณฑ์ ThaiCERT" }[d.severity] || "";
    let assess;
    if (!hasWeb(d)) assess = `<div class="f-field"><span class="f-k">ผลการประเมิน</span><div class="f-v">${esc(d.assessment)}</div></div>`;
    else {
      const fs = (d.findings || []).filter(f => f.rule_id !== "version-disclosure" || d.findings.length === 1);
      const main = (d.findings || [])[0];
      const cves = [...new Set((d.findings || []).flatMap(f => f.cve || []))];
      assess = `<div class="f-field"><span class="f-k">คืออะไร (อธิบายง่าย ๆ)</span><div class="f-v">${esc(main ? main.description : d.assessment)}</div></div>` +
        (cves.length ? `<div class="f-field"><span class="f-k">รหัสอ้างอิงสากล${tip("รหัสอ้างอิงช่องโหว่ระดับสากล (CVE) ใช้ค้นหาข้อมูลและแนวทางแก้เพิ่มเติมได้")}</span><div><span class="cve">${esc(cves.join(", "))}</span></div></div>` : "") +
        (main && main.evidence ? `<div class="f-field"><span class="f-k">หลักฐานที่ตรวจพบ</span><div class="f-v"><code>${esc(main.evidence)}</code></div></div>` : "") +
        (main && main.recommendation ? `<div class="f-field fix"><span class="f-k">✓ สิ่งที่ควรทำ</span><div class="f-v">${esc(main.recommendation)}</div></div>` : "");
    }
    box.innerHTML =
      `<div class="d-ip"><span style="width:10px;height:10px;border-radius:50%;background:var(--safe);display:inline-block"></span>${esc(d.ip)}</div><div class="d-type">${esc(d.device_type)}</div>` +
      `<div class="banner ${bk}"><span class="bi">${bk === "safe" ? "✓" : "!"}</span><div><b>${bT}</b><small>${bS}</small></div></div>` +
      `<div class="ilabel">ข้อมูลระบบที่ตรวจพบ${tip("ข้อมูลพื้นฐานของอุปกรณ์ที่ระบบตรวจพบระหว่างสแกน")}</div><div class="kvbox">` +
        `<div class="kv"><span class="k">ประเภทอุปกรณ์${tip("ชนิดของอุปกรณ์ เช่น เราเตอร์ เครื่องเซิร์ฟเวอร์ หรือเครื่องลูกข่าย")}</span><span class="v">${esc(d.device_type)}</span></div>` +
        `<div class="kv"><span class="k">MAC Address${tip("หมายเลขประจำการ์ดเครือข่ายของอุปกรณ์ ใช้ระบุตัวเครื่องแบบเจาะจง (เห็นเฉพาะเครื่องในวงเดียวกัน)")}</span><span class="v m">${esc(d.mac || "—")}</span></div>` +
        `<div class="kv"><span class="k">บริการที่พบ${tip("บริการที่อุปกรณ์เปิด เช่น เว็บ (HTTP/HTTPS) ถ้าไม่มีบริการเว็บจะปลอดภัยจาก php2shell")}</span><span class="v">${esc(d.service)}</span></div>` +
        `<div class="kv"><span class="k">เวอร์ชันภาษา PHP${tip("รุ่นของ PHP ที่เว็บใช้ — รุ่นเก่าที่ยังไม่แพตช์อาจมีช่องโหว่ php2shell")}</span><span class="v m">${esc(d.php_version || "ไม่มี")}</span></div>` +
        `<div class="kv"><span class="k">พอร์ตที่เปิด${tip("ช่องทางที่อุปกรณ์เปิดรับการเชื่อมต่อ เช่น 80 = เว็บ, 443 = เว็บแบบเข้ารหัส")}</span><span class="v m">${d.open_ports && d.open_ports.length ? esc(d.open_ports.join(", ")) : "—"}</span></div>` +
        `<div class="kv"><span class="k">Latency${tip("เวลาตอบสนองของอุปกรณ์ (ms) ยิ่งน้อยยิ่งเร็ว")}</span><span class="v m">${d.latency_ms != null ? d.latency_ms + " ms" : "—"}</span></div>` +
      `</div><div class="ilabel">การประเมินความปลอดภัย (ThaiCERT)${tip("ผลประเมินตามเกณฑ์ของ ThaiCERT — ศูนย์ประสานการรักษาความมั่นคงปลอดภัยระบบคอมพิวเตอร์ประเทศไทย")}</div>${assess}`;
  }
  function wire() {
    $$("#cats button").forEach(b => b.addEventListener("click", () => { $$("#cats button").forEach(x => x.setAttribute("aria-pressed", "false")); b.setAttribute("aria-pressed", "true"); st.cat = b.dataset.cat; st.sel = null; render(); }));
    $("#search").addEventListener("input", e => { st.q = e.target.value.trim().toLowerCase(); st.sel = null; render(); });
    $("#advToggle").addEventListener("click", () => { const o = $("#advPanel").classList.toggle("open"); $("#advToggle").setAttribute("aria-expanded", o ? "true" : "false"); });
    $("#advApply").addEventListener("click", () => { st.adv = { sev: $("#f-sev").value, svc: $("#f-svc").value, port: $("#f-port").value, lat: $("#f-lat").value ? Number($("#f-lat").value) : null }; st.sel = null; render(); });
    $("#advReset").addEventListener("click", () => { ["f-sev", "f-svc", "f-port"].forEach(id => $("#" + id).value = "all"); $("#f-lat").value = ""; st.adv = { sev: "all", svc: "all", port: "all", lat: null }; st.sel = null; render(); });
    $("#exportBtn").addEventListener("click", () => { if (meta.id) location.href = "/api/scans/" + meta.id + "/export.csv"; });
    $("#rescan").addEventListener("click", () => go("scan"));
  }
  return {
    wire,
    load(job) {
      devices = job.devices || [];
      meta = { id: job.id, duration: job.duration_s, workers: job.workers };
      st.sel = null; st.cat = "all"; st.q = ""; $("#search").value = "";
      $("#resTarget").textContent = job.target_label || "—";
      $("#resDur").textContent = job.duration_s != null ? job.duration_s : "—";
      $("#resWorkers").textContent = job.workers || "—";
      $("#resBar").style.width = "100%";
      const ip = job.intercepted_ports || [], note = $("#interceptNote");
      note.hidden = !ip.length;
      if (ip.length) note.innerHTML = "ⓘ ตรวจพบอุปกรณ์กลาง (proxy/firewall) ที่ตอบแทนทุก IP บนพอร์ต <b>" + esc(ip.join(", ")) + "</b> — ระบบกรองผลปลอมจากอุปกรณ์นี้ออกแล้ว แสดงเฉพาะเครื่องที่ตอบจริง";
      render();
    }
  };
})();
Results.wire();

// ── boot ──
(async () => {
  try {
    state.config = await api("/api/config");
    $("#profScope").textContent = (state.config.allowed_cidrs || []).join(", ") || "—";
    $("#profMax").textContent = fmt(state.config.max_targets);
    $("#profWorkers").textContent = state.config.max_concurrency;
    $("#profPorts").textContent = (state.config.web_ports || []).join(", ");
  } catch (e) {}
  try {
    const d = await api("/api/autodetect");
    const nics = d.subnets || [];
    const wrap = $("#nicList");
    if (!nics.length) { wrap.innerHTML = '<div class="hint">ตรวจเครือข่ายอัตโนมัติไม่ได้ — เลือกโหมด “ซับเน็ต” แล้วกรอกเอง</div>'; }
    else {
      wrap.innerHTML = nics.map((n, i) => `<div class="nic" data-cidr="${esc(n.cidr)}" aria-pressed="${i === 0 ? "true" : "false"}"><span class="ni"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="7" width="20" height="10" rx="2"/><path d="M6 11h.01M10 11h4"/></svg></span><div class="nt"><b>${esc(n.name)}</b><div class="sub">${esc(n.cidr)}</div></div><span class="pick"></span></div>`).join("");
      $$("#nicList .nic").forEach(nic => nic.addEventListener("click", () => { $$("#nicList .nic").forEach(x => x.setAttribute("aria-pressed", "false")); nic.setAttribute("aria-pressed", "true"); renderSummary(); }));
    }
  } catch (e) { $("#nicList").innerHTML = '<div class="hint">ตรวจเครือข่ายอัตโนมัติไม่ได้ — เลือกโหมดอื่น</div>'; }
  renderSummary();
})();
})();

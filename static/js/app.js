/* thscan UI — every screen renders data from the REST API; nothing is invented
   client-side. Demo results come from the server and are always labelled. */
"use strict";

/* ── helpers ─────────────────────────────────────────────────────────── */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const icon = (id) => `<svg aria-hidden="true"><use href="#i-${id}"/></svg>`;
const tip = (text) => `<button type="button" class="tip" data-tip="${esc(text)}" aria-label="คำอธิบาย: ${esc(text)}">${icon("info")}</button>`;
const nf = new Intl.NumberFormat("th-TH");
const num = (n) => nf.format(n || 0);
const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } },
};

function fmtDate(iso, withTime = true) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d)) return "—";
  const opts = withTime ? { dateStyle: "medium", timeStyle: "short" } : { dateStyle: "medium" };
  try { return d.toLocaleString("th-TH", { ...opts, timeZone: (cfg && cfg.timezone) || undefined }); }
  catch { return d.toLocaleString("th-TH", opts); }
}
function fmtDuration(s) {
  if (s == null) return "—";
  if (s < 60) return `${Math.max(1, Math.round(s))} วินาที`;
  const m = Math.floor(s / 60), r = Math.round(s % 60);
  return r ? `${m} นาที ${r} วินาที` : `${m} นาที`;
}

async function api(path, opts = {}) {
  const init = { ...opts, headers: { Accept: "application/json", ...(opts.body ? { "Content-Type": "application/json" } : {}) } };
  let res;
  try { res = await fetch(path, init); } catch { throw new Error("เชื่อมต่อเซิร์ฟเวอร์ thscan ไม่ได้ — ตรวจว่าโปรแกรมยังทำงานอยู่"); }
  let data = null;
  try { data = await res.json(); } catch { /* empty body */ }
  if (!res.ok) {
    const d = data && data.detail;
    const msg = typeof d === "string" ? d : Array.isArray(d) ? d.map((x) => x.msg).join(", ") : `เซิร์ฟเวอร์ตอบกลับ ${res.status}`;
    const err = new Error(msg); err.status = res.status; throw err;
  }
  return data;
}

/* ── labels ──────────────────────────────────────────────────────────── */
const SEV = {
  critical: { cls: "crit", label: "ต้องแก้ด่วน", verdict: "crit", title: "ต้องแก้ไขโดยด่วน", rank: 0 },
  high: { cls: "warn", label: "เสี่ยงสูง", verdict: "warn", title: "มีความเสี่ยงสูง ควรแก้ไขเร็วที่สุด", rank: 1 },
  low: { cls: "plain", label: "ควรปรับปรุง", verdict: "warn", title: "ความเสี่ยงต่ำ ควรปรับปรุงเมื่อสะดวก", rank: 2 },
  safe: { cls: "ok", label: "ผ่าน", verdict: "ok", title: "ไม่พบช่องโหว่ PHP2Shell", rank: 3 },
};
const sevBadge = (s) => `<span class="badge ${SEV[s].cls}">${SEV[s].label}</span>`;
const CONF = { confirmed: "ยืนยันแล้ว", high: "มั่นใจสูง", medium: "มั่นใจปานกลาง", low: "มั่นใจต่ำ" };
const DEVTYPE = {
  "Gateway Router": "เราเตอร์ / เกตเวย์",
  "Web Server (HTTPS)": "เว็บเซิร์ฟเวอร์ (HTTPS)",
  "Web Server (HTTP)": "เว็บเซิร์ฟเวอร์ (HTTP)",
  "LAN Device": "อุปกรณ์ในเครือข่าย",
};
const devType = (t) => DEVTYPE[t] || t || "—";
const STATE = { queued: "รอคิว", running: "กำลังสแกน", completed: "เสร็จแล้ว", cancelled: "ยกเลิกแล้ว", failed: "ผิดพลาด" };
const DOW = ["อาทิตย์", "จันทร์", "อังคาร", "พุธ", "พฤหัสบดี", "ศุกร์", "เสาร์"];
const TIPS = {
  scope: "ช่วง IP ที่ผู้ติดตั้ง thscan อนุญาตให้สแกน (ตั้งใน THSCAN_ALLOWED_CIDRS ตอนติดตั้ง) เป้าหมายนอกช่วงนี้ระบบจะปฏิเสธเสมอ",
  score: "คำนวณโดย thscan จากจำนวนเครื่องที่เสี่ยง (เริ่ม 100 · ด่วน −22 · สูง −14 · ต่ำ −4) ใช้ติดตามความคืบหน้าภายในหน่วยงาน ไม่ใช่คะแนนรับรองจาก ThaiCERT หรือหน่วยงานใด",
  online: "เครื่องที่ตอบสนองการเชื่อมต่อ และยืนยันได้ว่ามีอยู่จริง",
  mac: "หมายเลขประจำการ์ดเครือข่าย อ่านได้เฉพาะเครื่องที่อยู่ในวง LAN เดียวกับเครื่องที่รัน thscan ถ้าอยู่คนละวง (ข้ามเราเตอร์) จะว่าง",
  latency: "เวลาที่เครื่องใช้ตอบกลับ หน่วยมิลลิวินาที ยิ่งน้อยยิ่งเร็ว",
  host: "ชื่อที่ได้จากการค้นหา DNS ย้อนกลับ (reverse DNS) ถ้าไม่มีการตั้งชื่อไว้จะว่าง",
  type: "คาดเดาจากบริการที่เปิดอยู่ อาจไม่ถูกต้อง 100%",
  ports: "ช่องทาง (พอร์ต) ของบริการเว็บที่เปิดรับการเชื่อมต่อ",
  php: "อ่านจาก header ที่เว็บตอบกลับ (เช่น X-Powered-By) ถ้าเว็บซ่อนเวอร์ชันไว้จะแสดงว่าไม่พบ",
  confidence: "ความมั่นใจของผลตรวจ: ยืนยันแล้ว = เห็นเวอร์ชันที่มีช่องโหว่ชัดเจน · ต่ำ = เป็นการคาดการณ์จากข้อมูลบางส่วน",
  portsPick: "thscan เชื่อมต่อแบบปกติ (TCP connect) ไปยังพอร์ตเหล่านี้บนเครื่องที่ออนไลน์ เพื่อดูว่าเปิดบริการอะไรไว้ ไม่ส่งข้อมูลโจมตี และตรวจพอร์ตเว็บเสมอ",
  services: "พอร์ตที่เครื่องนี้เปิดรับการเชื่อมต่อ และบริการที่มักใช้พอร์ตนั้น หมายเหตุสีส้มคือข้อควรระวัง ไม่ได้แปลว่ามีช่องโหว่",
  sites: "ใส่ลิงก์หรือชื่อโดเมน เช่น https://www.agency.go.th ระบบจะค้นหา IP จาก DNS ครั้งเดียว ตรวจว่าเป็นโดเมนหน่วยงานและอยู่ในขอบเขต แล้วสแกน IP นั้นโดยระบุชื่อเว็บไปด้วย",
  intercept: "อุปกรณ์อย่าง proxy หรือ firewall บางตัวตอบรับแทนทุกที่อยู่ ทำให้ดูเหมือนมีเครื่องออนไลน์ทุก IP thscan ทดสอบกับที่อยู่ที่ไม่มีจริงก่อนสแกน แล้วตัดผลปลอมเหล่านี้ออก",
};

/* ── tooltip (hover, focus, or tap) ─────────────────────────────────── */
const tt = $("#tt");
let ttFor = null;
function showTip(el) {
  ttFor = el; tt.textContent = el.dataset.tip; tt.classList.add("show");
  const r = el.getBoundingClientRect(), w = tt.offsetWidth, h = tt.offsetHeight;
  const x = Math.max(8, Math.min(r.left + r.width / 2 - w / 2, innerWidth - w - 8));
  let y = r.top - h - 8; if (y < 8) y = r.bottom + 8;
  tt.style.left = `${x}px`; tt.style.top = `${y}px`;
}
function hideTip() { ttFor = null; tt.classList.remove("show"); }
document.addEventListener("mouseover", (e) => { const t = e.target.closest("[data-tip]"); if (t) showTip(t); });
document.addEventListener("mouseout", (e) => { if (e.target.closest("[data-tip]")) hideTip(); });
document.addEventListener("focusin", (e) => { const t = e.target.closest("[data-tip]"); t ? showTip(t) : hideTip(); });
document.addEventListener("click", (e) => {
  const t = e.target.closest(".tip");
  if (t) { e.preventDefault(); ttFor === t ? hideTip() : showTip(t); } else if (ttFor) hideTip();
});
addEventListener("scroll", hideTip, { passive: true });

/* ── toast + modal ──────────────────────────────────────────────────── */
let toastTimer;
function toast(msg) {
  let el = $(".toast");
  if (!el) { el = document.createElement("div"); el.className = "toast"; el.setAttribute("role", "status"); document.body.append(el); }
  el.textContent = msg; el.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { el.hidden = true; }, 4200);
}

function openModal(html, { label } = {}) {
  const back = document.createElement("div");
  back.className = "modal-back";
  back.innerHTML = `<div class="modal" role="dialog" aria-modal="true" aria-label="${esc(label || "")}">${html}</div>`;
  const prev = document.activeElement;
  const close = () => { back.remove(); document.removeEventListener("keydown", onKey); prev && prev.focus && prev.focus(); };
  const onKey = (e) => {
    if (e.key === "Escape") close();
    if (e.key === "Tab") { // keep focus inside the dialog
      const f = $$("button, a[href], input, select, textarea", back).filter((x) => !x.disabled && x.offsetParent);
      if (!f.length) return;
      if (e.shiftKey && document.activeElement === f[0]) { e.preventDefault(); f[f.length - 1].focus(); }
      else if (!e.shiftKey && document.activeElement === f[f.length - 1]) { e.preventDefault(); f[0].focus(); }
    }
  };
  back.addEventListener("click", (e) => { if (e.target === back || e.target.closest("[data-close]")) close(); });
  document.addEventListener("keydown", onKey);
  document.body.append(back);
  const first = $("[autofocus], button.btn-primary, button, input", back); first && first.focus();
  return { el: back, close };
}

function confirmModal({ title, text, ok, danger }) {
  return new Promise((resolve) => {
    const m = openModal(`<h2>${esc(title)}</h2><p>${esc(text)}</p>
      <div class="modal-foot"><button class="btn btn-secondary" data-close>ยกเลิก</button>
      <button class="btn ${danger ? "btn-danger" : "btn-primary"}" data-ok>${esc(ok)}</button></div>`, { label: title });
    let done = false;
    $("[data-ok]", m.el).addEventListener("click", () => { done = true; m.close(); resolve(true); });
    const obs = new MutationObserver(() => { if (!m.el.isConnected) { obs.disconnect(); if (!done) resolve(false); } });
    obs.observe(document.body, { childList: true });
    $("[data-ok]", m.el).focus();
  });
}

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch {
    const ta = document.createElement("textarea"); ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.append(ta); ta.select();
    let ok = false; try { ok = document.execCommand("copy"); } catch { /* unsupported */ }
    ta.remove(); return ok;
  }
}

/* ── IPv4 math (mirrors app/scanner/ip_utils.py) ────────────────────── */
function ipToInt(s) {
  const p = String(s).trim().split(".");
  if (p.length !== 4) return null;
  let n = 0;
  for (const x of p) { if (!/^\d{1,3}$/.test(x) || +x > 255) return null; n = n * 256 + +x; }
  return n;
}
const intToIp = (n) => [16777216, 65536, 256, 1].map((d) => Math.floor(n / d) % 256).join(".");
function cidrBounds(spec) {
  const [ip, p] = spec.split("/");
  const base = ipToInt(ip), prefix = /^\d{1,2}$/.test(p) ? +p : NaN;
  if (base == null || !(prefix >= 0 && prefix <= 32)) return null;
  const size = 2 ** (32 - prefix), net = Math.floor(base / size) * size;
  return { net, bcast: net + size - 1, prefix };
}
function specBounds(spec) {
  spec = spec.trim();
  if (spec.includes("/")) {
    const b = cidrBounds(spec);
    if (!b) throw new Error(`“${spec}” ไม่ใช่ซับเน็ตที่ถูกต้อง (ตัวอย่าง 192.168.1.0/24)`);
    return b.prefix <= 30 ? [b.net + 1, b.bcast - 1] : [b.net, b.bcast];
  }
  if (spec.includes("-")) {
    let [l, r] = spec.split("-", 2).map((x) => x.trim());
    const a = ipToInt(l);
    if (a == null) throw new Error(`จุดเริ่ม “${l}” ไม่ใช่ IP ที่ถูกต้อง`);
    if (/^\d{1,3}$/.test(r)) r = l.split(".").slice(0, 3).concat(r).join(".");
    const b = ipToInt(r);
    if (b == null) throw new Error(`จุดสิ้นสุด “${r}” ไม่ใช่ IP ที่ถูกต้อง`);
    if (b < a) throw new Error("ช่วง IP กลับด้าน — จุดสิ้นสุดต้องมากกว่าจุดเริ่ม");
    return [a, b];
  }
  const n = ipToInt(spec);
  if (n == null) throw new Error(`“${spec}” ไม่ใช่ IP ที่ถูกต้อง`);
  return [n, n];
}
let allowedNets = [];
function inScope(a, b) { return allowedNets.some((n) => n.net <= a && b <= n.bcast); }
function checkTargets(specs) {
  const out = { count: 0, first: null, last: null, error: null, outside: [] };
  if (!specs.length) { out.error = "ยังไม่ได้ระบุเป้าหมาย"; return out; }
  for (const s of specs) {
    let a, b;
    try { [a, b] = specBounds(s); } catch (e) { out.error = e.message; return out; }
    out.count += b - a + 1;
    out.first = out.first == null ? a : Math.min(out.first, a);
    out.last = out.last == null ? b : Math.max(out.last, b);
    if (!inScope(a, b)) out.outside.push(s);
  }
  return out;
}
function estimate(count, nports = 4) {
  const conc = (cfg && cfg.max_concurrency) || 50, sockets = (cfg && cfg.max_sockets) || 256;
  // liveness for every address, then a port check on the ~quarter that are online
  const secs = Math.ceil(count / conc) * 1.5 + Math.ceil((count * 0.25 * nports) / sockets) * 1.5 + 8;
  if (secs < 60) return "ไม่ถึง 1 นาที";
  if (secs < 3600) return `ประมาณ ${Math.ceil(secs / 60)} นาที`;
  return `ประมาณ ${(secs / 3600).toFixed(1)} ชั่วโมง`;
}

/* ── app state + router ─────────────────────────────────────────────── */
let cfg = null;
let routeToken = 0;
let cleanup = null;
const app = $("#app");

async function loadConfig() {
  if (cfg) return cfg;
  cfg = await api("/api/config");
  allowedNets = (cfg.allowed_cidrs || []).map(cidrBounds).filter(Boolean);
  $("#ver").textContent = `v${cfg.version}`;
  return cfg;
}

const routes = [
  [/^#?\/?$/, viewHome, ""],
  [/^#\/scan\/([\w-]+)$/, viewScanning, ""],
  [/^#\/results\/([\w-]+)$/, viewResults, "results"],
  [/^#\/report\/([\w-]+)$/, viewReport, "results"],
  [/^#\/latest$/, viewLatest, "results"],
  [/^#\/history$/, viewHistory, "history"],
  [/^#\/settings$/, viewSettings, "settings"],
];

async function route() {
  if (cleanup) { cleanup(); cleanup = null; }
  hideTip();
  const token = ++routeToken;
  const alive = () => token === routeToken;
  const hash = location.hash || "#/";
  const hit = routes.find(([re]) => re.test(hash)) || routes[0];
  const params = hash.match(hit[0]) || [];
  $$("[data-nav]").forEach((a) => (a.dataset.nav === hit[2] ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current")));
  $("#nav").classList.remove("open");
  $(".nav-toggle").setAttribute("aria-expanded", "false");
  try {
    await loadConfig();
    await hit[1](params.slice(1), alive);
  } catch (e) {
    if (!alive()) return;
    app.innerHTML = `<section class="page"><div class="wrap"><div class="empty">
      <h3>${e.status === 404 ? "ไม่พบข้อมูลนี้" : "โหลดข้อมูลไม่สำเร็จ"}</h3><p>${esc(e.message)}</p>
      <p style="margin-top:24px"><a class="btn btn-secondary" href="#/">กลับหน้าแรก</a></p></div></div></section>`;
  }
}
function render(html) { app.innerHTML = html; scrollTo(0, 0); }

$(".nav-toggle").addEventListener("click", (e) => {
  const open = $("#nav").classList.toggle("open");
  e.currentTarget.setAttribute("aria-expanded", String(open));
});
$("[data-start]").addEventListener("click", (e) => {
  if ((location.hash || "#/") === "#/" || location.hash === "") {
    e.preventDefault();
    const card = $("#scan-card"); card && card.scrollIntoView({ behavior: "smooth", block: "center" });
  }
});
addEventListener("hashchange", route);

async function startScan(body) {
  const job = await api("/api/scans", { method: "POST", body: JSON.stringify(body) });
  location.hash = `#/scan/${job.id}`;
}

function openDemoPicker() {
  const demos = cfg.demos || [];
  let pick = demos[0] && demos[0].id;
  const m = openModal(`<h2>ดูตัวอย่างผลการสแกน</h2>
    <p>เลือกสถานการณ์ตัวอย่าง ระบบจะแสดงผลจาก<strong>ข้อมูลจำลอง</strong> (ไม่ได้สแกนเครือข่ายจริง) เพื่อให้เห็นว่าหน้าผลลัพธ์อ่านอย่างไร</p>
    <div class="choice-list" role="radiogroup" aria-label="สถานการณ์ตัวอย่าง">
      ${demos.map((d, i) => `<button type="button" class="choice" role="radio" aria-checked="${i === 0}" data-demo="${esc(d.id)}">
        <span class="radio"></span><span class="choice-main"><span class="choice-title">${esc(d.name)}</span>
        <span class="choice-sub">${esc(d.description)}</span></span></button>`).join("")}
    </div>
    <div class="modal-foot"><button class="btn btn-secondary" data-close>ยกเลิก</button>
    <button class="btn btn-primary" data-go>เปิดตัวอย่าง</button></div>`, { label: "ดูตัวอย่างผลการสแกน" });
  m.el.addEventListener("click", (e) => {
    const c = e.target.closest("[data-demo]");
    if (c) { pick = c.dataset.demo; $$("[data-demo]", m.el).forEach((x) => x.setAttribute("aria-checked", String(x === c))); }
  });
  $("[data-go]", m.el).addEventListener("click", async (e) => {
    e.currentTarget.disabled = true;
    try { await startScan({ demo_scenario: pick }); m.close(); } catch (err) { toast(err.message); e.currentTarget.disabled = false; }
  });
}

/* ── view: home ─────────────────────────────────────────────────────── */
const pick = {
  target: "net", // net = IP / network · site = website by link
  mode: "auto", auto: null, kind: "subnet",
  oct: { subnet: ["", "", "", ""], range: ["", "", "", ""], single: ["", "", "", ""] },
  prefix: 24, rangeEnd: "", text: "",
  sitesText: "", siteReport: null, siteFor: "",
  profile: "common", customPorts: "",
};
const PREFIXES = [30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 16];
const hostsFor = (p) => (p >= 31 ? 2 ** (32 - p) : 2 ** (32 - p) - 2);

function pickTargets() {
  if (pick.mode === "auto") return pick.auto ? [pick.auto] : [];
  const ip = (k) => (pick.oct[k].every((o) => o !== "") ? pick.oct[k].join(".") : null);
  if (pick.kind === "subnet") { const a = ip("subnet"); return a ? [`${a}/${pick.prefix}`] : []; }
  if (pick.kind === "range") { const a = ip("range"); return a && pick.rangeEnd !== "" ? [`${a}-${pick.rangeEnd}`] : []; }
  if (pick.kind === "single") { const a = ip("single"); return a ? [a] : []; }
  return pick.text.split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean).slice(0, 64);
}

const siteList = () => pick.sitesText.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean).slice(0, (cfg && cfg.max_sites) || 20);

/* mirrors app/scanner/ports.py parse_ports: returns { n } or { error } */
function countPorts(spec) {
  const set = new Set(), max = (cfg && cfg.max_custom_ports) || 1024;
  for (const raw of spec.split(/[\s,;]+/)) {
    if (!raw) continue;
    const m = raw.match(/^(\d{1,5})(?:-(\d{1,5}))?$/);
    if (!m) return { error: `พอร์ตไม่ถูกต้อง: ${raw}` };
    const a = +m[1], b = m[2] ? +m[2] : a;
    if (a < 1 || b > 65535) return { error: `พอร์ตต้องอยู่ระหว่าง 1–65535: ${raw}` };
    if (b < a) return { error: `ช่วงพอร์ตกลับด้าน: ${raw}` };
    if (b - a + 1 > max) return { error: `ระบุพอร์ตได้ไม่เกิน ${num(max)} พอร์ต` };
    for (let p = a; p <= b; p++) set.add(p);
    if (set.size > max) return { error: `ระบุพอร์ตได้ไม่เกิน ${num(max)} พอร์ต` };
  }
  if (!set.size) return { error: "ยังไม่ได้ระบุพอร์ต" };
  (cfg.web_ports || []).forEach((p) => set.add(p));
  return { n: set.size };
}
function portCount(profile = pick.profile, custom = pick.customPorts) {
  if (profile === "custom") return countPorts(custom);
  const p = (cfg.port_profiles || []).find((x) => x.id === profile);
  return { n: p && p.ports ? p.ports.length : 0 };
}
function portPicker(id = "pp", profile = pick.profile, custom = pick.customPorts) {
  return `<div class="port-pick">
    <div><label class="field-label" for="${id}">พอร์ตที่ตรวจในแต่ละเครื่อง ${tip(TIPS.portsPick)}</label>
    <select class="select" id="${id}" name="port_profile">${(cfg.port_profiles || []).map((p) => `<option value="${p.id}" ${p.id === profile ? "selected" : ""}>
      ${esc(p.label)}${p.ports ? ` · ${num(p.ports.length)} พอร์ต` : ""}</option>`).join("")}</select></div>
    <div class="grow" data-custom-ports ${profile === "custom" ? "" : "hidden"}><label class="field-label" for="${id}-custom">พอร์ตที่ต้องการ</label>
    <input class="input mono" id="${id}-custom" name="custom_ports" value="${esc(custom)}" autocomplete="off" spellcheck="false" placeholder="เช่น 22, 80, 8000-8100" style="width:100%"></div>
  </div>`;
}
function portLine(count) {
  const pc = portCount();
  if (pc.error) return { ok: false, html: `<div class="plan-line bad">${icon("x")}<span>${esc(pc.error)}</span></div>` };
  if (count * pc.n > cfg.max_port_probes) return { ok: false, html: `<div class="plan-line bad">${icon("x")}<span>งานใหญ่เกินไป (${num(count)} ที่อยู่ × ${num(pc.n)} พอร์ต) — ลดขนาดวงหรือจำนวนพอร์ตลง</span></div>` };
  return { ok: true, n: pc.n, html: `<div class="plan-line ok">${icon("list")}<span>ตรวจ <strong>${num(pc.n)}</strong> พอร์ตในแต่ละเครื่องที่ออนไลน์</span></div>` };
}

function octets(name, label) {
  return `<div><span class="field-label" id="lbl-${name}">${label}</span>
    <div class="ip-field" role="group" aria-labelledby="lbl-${name}">
    ${pick.oct[name].map((v, i) => `${i ? '<span class="dot">.</span>' : ""}<input inputmode="numeric" autocomplete="off" maxlength="3"
      data-oct="${name}" data-i="${i}" value="${esc(v)}" aria-label="${label} ส่วนที่ ${i + 1}" placeholder="0">`).join("")}
    </div></div>`;
}

function customPanel() {
  const k = pick.kind;
  const seg = [["subnet", "ทั้งวง (ซับเน็ต)"], ["range", "ช่วง IP"], ["single", "เครื่องเดียว"], ["text", "พิมพ์เอง"]]
    .map(([id, t]) => `<button type="button" data-kind="${id}" aria-pressed="${k === id}">${t}</button>`).join("");
  let row = "";
  if (k === "subnet") {
    row = `${octets("subnet", "ที่อยู่เครือข่าย")}
      <div><label class="field-label" for="prefix">ขนาดวง ${tip("/24 คือวงขนาดปกติของสำนักงาน (254 เครื่อง) ยิ่งเลขน้อย วงยิ่งใหญ่")}</label>
      <select class="select" id="prefix">${PREFIXES.map((p) => `<option value="${p}" ${p === pick.prefix ? "selected" : ""}>/${p} · ${num(hostsFor(p))} เครื่อง</option>`).join("")}</select></div>`;
  } else if (k === "range") {
    const o = pick.oct.range;
    row = `${octets("range", "จาก")}
      <div><label class="field-label" for="range-end">ถึง</label>
      <div class="ip-field"><span class="mono muted" id="range-prefix">${esc(o.slice(0, 3).map((x) => x || "_").join("."))}.</span>
      <input id="range-end" inputmode="numeric" autocomplete="off" maxlength="3" value="${esc(pick.rangeEnd)}" placeholder="254" aria-label="ส่วนสุดท้ายของ IP ปลายทาง"></div></div>`;
  } else if (k === "single") {
    row = octets("single", "IP ของเครื่อง");
  } else {
    row = `<div style="flex:1 1 100%"><label class="field-label" for="free">เป้าหมาย (คั่นหลายรายการด้วยจุลภาค)</label>
      <input class="input" id="free" style="width:100%" autocomplete="off" spellcheck="false" value="${esc(pick.text)}"
        placeholder="เช่น 10.0.5.0/24, 10.0.6.10-50, 10.0.7.3"></div>`;
  }
  const chips = (cfg.allowed_cidrs || []).map((c) => `<button type="button" class="chip" data-fill="${esc(c)}">${esc(c)}</button>`).join("");
  return `<div class="seg" role="group" aria-label="รูปแบบเป้าหมาย">${seg}</div>
    <div class="ip-row">${row}</div>
    ${chips ? `<div class="chips"><span class="field-label" style="margin:6px 4px 0 0">ช่วงที่อนุญาต ${tip(TIPS.scope)}</span>${chips}</div>` : ""}`;
}

function planHTML() {
  const wrap = (lines) => `<div class="plan" aria-live="polite">${lines.join("")}</div>`;
  const info = (t) => wrap([`<div class="plan-line">${icon("info")}<span>${t}</span></div>`]);
  if (pick.target === "site") {
    const list = siteList();
    if (!list.length) return info("วางลิงก์เว็บไซต์ของหน่วยงาน ระบบจะตรวจ DNS และขอบเขตให้ทันที");
    if (pick.siteFor !== list.join("\n") || !pick.siteReport) return info("กำลังตรวจสอบลิงก์…");
    const lines = pick.siteReport.map((r) => r.problems.length
      ? `<div class="plan-line bad">${icon("x")}<span>${esc(r.problems.join(" · "))}</span></div>`
      : `<div class="plan-line ok">${icon("check")}<span><strong>${esc(r.host)}</strong> → <span class="mono">${esc(r.ips.join(", "))}</span></span></div>`);
    const ips = new Set(pick.siteReport.flatMap((r) => r.ips)).size;
    const pl = portLine(ips); lines.push(pl.html);
    if (pl.ok && pick.siteReport.every((r) => !r.problems.length)) lines.push(`<div class="plan-line ok">${icon("clock")}<span>ใช้เวลา${estimate(ips, pl.n)}</span></div>`);
    return wrap(lines);
  }
  const specs = pickTargets();
  if (!specs.length) return info(pick.mode === "custom" ? "กรอกเป้าหมายให้ครบเพื่อดูสรุปก่อนสแกน" : "เลือกเครือข่ายที่ต้องการตรวจ");
  const c = checkTargets(specs);
  if (c.error) return wrap([`<div class="plan-line bad">${icon("x")}<span>${esc(c.error)}</span></div>`]);
  const lines = [`<div class="plan-line ok">${icon("server")}<span>จะตรวจ <strong>${num(c.count)}</strong> ที่อยู่ · <span class="mono">${intToIp(c.first)}${c.last !== c.first ? ` – ${intToIp(c.last)}` : ""}</span></span></div>`];
  if (c.outside.length) lines.push(`<div class="plan-line bad">${icon("x")}<span>อยู่นอกขอบเขตที่อนุญาต ${tip(TIPS.scope)} — ระบบนี้สแกนได้เฉพาะ ${esc((cfg.allowed_cidrs || []).join(", ") || "(ยังไม่ได้ตั้ง)")}</span></div>`);
  else lines.push(`<div class="plan-line ok">${icon("lock")}<span>อยู่ในขอบเขตที่ผู้ดูแลระบบอนุญาต ${tip(TIPS.scope)}</span></div>`);
  const pl = portLine(c.count); lines.push(pl.html);
  if (c.count > cfg.max_targets) lines.push(`<div class="plan-line bad">${icon("x")}<span>เกินจำนวนสูงสุด ${num(cfg.max_targets)} ที่อยู่ต่อครั้ง — ลดขนาดวงลง</span></div>`);
  else if (!c.outside.length && pl.ok) lines.push(`<div class="plan-line ok">${icon("clock")}<span>ใช้เวลา${estimate(c.count, pl.n)} ${tip("ขึ้นกับจำนวนเครื่องที่ออนไลน์และความเร็วเครือข่าย")}</span></div>`);
  return wrap(lines);
}
function planOk() {
  if (pick.target === "site") {
    const list = siteList();
    if (!list.length || pick.siteFor !== list.join("\n") || !pick.siteReport) return false;
    if (pick.siteReport.some((r) => r.problems.length)) return false;
    return portLine(new Set(pick.siteReport.flatMap((r) => r.ips)).size).ok;
  }
  const specs = pickTargets();
  if (!specs.length) return false;
  const c = checkTargets(specs);
  return !c.error && !c.outside.length && c.count <= cfg.max_targets && portLine(c.count).ok;
}
let resolveTimer;
function scheduleResolve(after) {
  clearTimeout(resolveTimer);
  const list = siteList(), key = list.join("\n");
  if (!list.length) { pick.siteReport = null; pick.siteFor = ""; after(); return; }
  if (key === pick.siteFor) { after(); return; }
  resolveTimer = setTimeout(async () => {
    let report;
    try { report = (await api(`/api/resolve?q=${encodeURIComponent(key)}`)).sites; }
    catch (e) { report = [{ input: key, host: null, ips: [], problems: [e.message] }]; }
    if (siteList().join("\n") !== key) return; // the text changed meanwhile
    pick.siteReport = report; pick.siteFor = key;
    after();
  }, 450);
  after();
}

async function viewHome(_, alive) {
  const [auto, jobs] = await Promise.all([
    api("/api/autodetect").catch(() => ({ subnets: [] })),
    api("/api/scans").catch(() => []),
  ]);
  if (!alive()) return;
  const subnets = (auto.subnets || []).map((s) => {
    const b = cidrBounds(s.cidr);
    return { ...s, ok: !!b && inScope(b.net, b.bcast), hosts: b ? hostsFor(b.prefix) : 0 };
  });
  if (pick.auto == null) {
    const first = subnets.find((s) => s.ok);
    if (first) pick.auto = first.cidr;
    else {
      pick.mode = "custom";
      const a = allowedNets[0];
      if (a) { pick.oct.subnet = intToIp(a.net).split("."); pick.prefix = Math.max(a.prefix, 24); }
    }
  }

  render(`
  <section class="hero"><div class="wrap hero-grid">
    <div>
      <p class="eyebrow">ใช้ฟรี · ติดตั้งในหน่วยงานของคุณเอง</p>
      <h1><span class="nw">ตรวจเว็บใน</span><span class="nw">เครือข่ายของคุณ</span> <span class="nw">ว่าเสี่ยง PHP2Shell</span> <span class="nw">หรือไม่</span></h1>
      <p class="lede">สแกนทั้งวงเครือข่ายหรือวางลิงก์เว็บไซต์ของหน่วยงาน thscan จะดูว่าแต่ละเครื่องเปิดพอร์ตอะไรไว้ อ่านเวอร์ชัน PHP แล้วบอกเป็นภาษาไทยว่าเครื่องไหนต้องแก้ก่อน และแก้อย่างไร</p>
      <ul class="checks">
        <li>${icon("check")}<span><b>ไม่ทำลายระบบ</b> — อ่านเฉพาะข้อมูลที่เว็บตอบกลับตามปกติ ไม่ส่งโค้ดโจมตี</span></li>
        <li>${icon("check")}<span><b>สแกนได้เฉพาะขอบเขตที่กำหนด</b> — ผู้ติดตั้งกำหนดช่วง IP ไว้ ผู้ใช้ขยายเองไม่ได้</span></li>
        <li>${icon("check")}<span><b>ผลบวกลวงต่ำ</b> — ตัดเครื่องที่ไม่มีอยู่จริงออก เช่น ผลที่ proxy ตอบแทน</span></li>
      </ul>
    </div>
    <div class="scan-card" id="scan-card">
      <h2>จะตรวจอะไร?</h2>
      <div class="seg seg-full" role="group" aria-label="ประเภทเป้าหมาย">
        <button type="button" data-target="net" aria-pressed="${pick.target === "net"}">${icon("server")}เครือข่าย (IP)</button>
        <button type="button" data-target="site" aria-pressed="${pick.target === "site"}">${icon("search")}เว็บไซต์ (ลิงก์)</button>
      </div>
      <div id="t-site" ${pick.target === "site" ? "" : "hidden"}>
        <label class="field-label" for="sites" style="margin-top:20px">ลิงก์หรือโดเมนเว็บไซต์ (บรรทัดละ 1 เว็บ) ${tip(TIPS.sites)}</label>
        <textarea class="input textarea" id="sites" rows="3" spellcheck="false" autocomplete="off"
          placeholder="https://www.agency.go.th&#10;eservice.agency.go.th">${esc(pick.sitesText)}</textarea>
        <p class="hint">ตรวจได้เฉพาะโดเมนหน่วยงาน (${esc((cfg.gov_suffixes || []).join(", "))}) ที่ชี้มายัง IP ในขอบเขตที่อนุญาต</p>
      </div>
      <div id="t-net" ${pick.target === "net" ? "" : "hidden"}>
      <p class="hint" style="margin-top:16px">ระบบหาวงเครือข่ายของเครื่องนี้ให้แล้ว เลือกได้เลยโดยไม่ต้องพิมพ์</p>
      <div class="choice-list" role="radiogroup" aria-label="เครือข่ายที่จะสแกน">
        ${subnets.map((s) => `<button type="button" class="choice" role="radio" data-auto="${esc(s.cidr)}" ${s.ok ? "" : "disabled"}
            aria-checked="${pick.mode === "auto" && pick.auto === s.cidr}">
          <span class="radio"></span><span class="choice-main"><span class="choice-title">${esc(s.name)}</span>
          <span class="choice-sub mono">${esc(s.cidr)}</span></span>
          <span class="choice-meta">${s.ok ? `${num(s.hosts)} เครื่อง` : "นอกขอบเขต"}</span></button>`).join("")}
        <button type="button" class="choice" role="radio" data-custom aria-checked="${pick.mode === "custom"}">
          <span class="radio"></span><span class="choice-main"><span class="choice-title">ระบุเป้าหมายเอง</span>
          <span class="choice-sub">ซับเน็ต ช่วง IP หรือเครื่องเดียว</span></span></button>
      </div>
      <div class="custom" id="custom" ${pick.mode === "custom" ? "" : "hidden"}>${customPanel()}</div>
      </div>
      <div class="ports-sec" id="ports-sec">${portPicker()}</div>
      <div id="plan">${planHTML()}</div>
      <div class="card-actions">
        <button class="btn btn-primary btn-lg btn-block" id="go" ${planOk() ? "" : "disabled"}>เริ่มสแกน ${icon("arrow")}</button>
        <p class="form-error" id="go-err" role="alert" hidden></p>
        <button type="button" class="link" id="demo-link">ยังไม่พร้อม? ดูตัวอย่างผลการสแกนก่อน</button>
      </div>
    </div>
  </div></section>

  <section class="section band"><div class="wrap">
    <div class="section-head"><p class="eyebrow">วิธีใช้งาน</p><h2>เสร็จใน 3 ขั้นตอน ไม่ต้องมีความรู้ด้านเครือข่าย</h2></div>
    <ol class="steps">
      <li class="step"><h3>เลือกเป้าหมาย</h3><p>เลือกวงเครือข่ายที่ระบบหาให้ หรือวางลิงก์เว็บไซต์ของหน่วยงาน แล้วเลือกชุดพอร์ตที่จะตรวจ</p></li>
      <li class="step"><h3>รอผลสักครู่</h3><p>ตรวจเฉพาะเครื่องที่ออนไลน์ วงขนาด 254 เครื่องมักใช้เวลาไม่กี่นาที</p></li>
      <li class="step"><h3>แก้ตามลำดับ</h3><p>เครื่องที่ต้องแก้ด่วนขึ้นก่อน พร้อมขั้นตอนแก้ไข แล้วกดตรวจซ้ำเพื่อยืนยัน</p></li>
    </ol>
  </div></section>

  <section class="section"><div class="wrap">
    <div class="section-head"><p class="eyebrow">ความปลอดภัย</p><h2>ออกแบบให้ปลอดภัยต่อเครือข่ายของคุณ</h2>
      <p>thscan เป็นเครื่องมือคัดกรอง ไม่ใช่เครื่องมือโจมตี ทุกการตรวจใช้การเชื่อมต่อปกติแบบเดียวกับที่เบราว์เซอร์ทำ</p></div>
    <div class="features">
      <div class="feature"><span class="ico">${icon("eye")}</span><h3>อ่านอย่างเดียว</h3><p>ขอหน้าเว็บตามปกติแล้วอ่าน header ไม่ส่งข้อมูลอันตราย ไม่เปลี่ยนแปลงอะไรบนเครื่องปลายทาง</p></div>
      <div class="feature"><span class="ico">${icon("lock")}</span><h3>ขอบเขตกำหนดตอนติดตั้ง</h3><p>ช่วง IP ที่สแกนได้ถูกล็อกไว้ที่ฝั่งเซิร์ฟเวอร์ เป้าหมายนอกช่วงจะถูกปฏิเสธเสมอ</p></div>
      <div class="feature"><span class="ico">${icon("check")}</span><h3>กรองผลปลอม</h3><p>ทดสอบกับที่อยู่ที่ไม่มีจริงก่อนสแกน ถ้า proxy หรือ firewall ตอบแทน ระบบจะตัดผลเหล่านั้นออก</p></div>
      <div class="feature"><span class="ico">${icon("server")}</span><h3>ทำงานได้แม้ไม่มีอินเทอร์เน็ต</h3><p>ทุกไฟล์อยู่ในเครื่องที่ติดตั้ง ไม่โหลดสคริปต์หรือฟอนต์จากภายนอก ข้อมูลไม่ออกนอกหน่วยงาน</p></div>
      <div class="feature"><span class="ico">${icon("clock")}</span><h3>ตั้งเวลาตรวจอัตโนมัติ</h3><p>ตั้งให้สแกนทุกคืนหรือทุกสัปดาห์ แล้วเปิดดูผลได้จากประวัติ</p></div>
      <div class="feature"><span class="ico">${icon("list")}</span><h3>ตรวจพอร์ตและบริการ</h3><p>ดูว่าแต่ละเครื่องเปิดพอร์ตอะไร เช่น RDP หรือฐานข้อมูล พร้อมคำแนะนำภาษาไทย แล้วส่งออกเป็น CSV หรือรายงานได้</p></div>
    </div>
  </div></section>

  ${jobs.length ? `<section class="section band"><div class="wrap">
    <div class="page-head" style="margin-bottom:24px"><div><p class="eyebrow">งานล่าสุด</p><h2 style="font-size:var(--fs-h2);margin-top:8px">ผลการสแกนก่อนหน้า</h2></div>
    <a class="link" href="#/history">ดูประวัติทั้งหมด ${icon("arrow")}</a></div>
    <div class="hist">${jobs.slice(0, 3).map(histRow).join("")}</div>
  </div></section>` : ""}

  <section class="section"><div class="wrap">
    <div class="section-head center"><p class="eyebrow">คำถามที่พบบ่อย</p><h2>มีข้อสงสัย?</h2></div>
    <div class="faq">
      <details><summary>PHP2Shell คืออะไร</summary><p>ช่องโหว่ร้ายแรงใน PHP (CVE-2026-109618 และ CVE-2026-109619 ระดับ CVSS 9.2) ที่อาจทำให้ผู้ไม่หวังดีสั่งงานเครื่องเซิร์ฟเวอร์ได้ แก้ได้ด้วยการอัปเดต PHP เป็น 8.5.12, 8.4.27, 8.3.36 หรือ 8.2.35 ขึ้นไปตามสาขาที่ใช้</p></details>
      <details><summary>การสแกนจะทำให้เว็บหรือเครือข่ายล่มไหม</summary><p>ไม่ thscan เปิดการเชื่อมต่อสั้น ๆ และขอหน้าเว็บตามปกติเหมือนผู้ใช้ทั่วไปเปิดเว็บ มีการจำกัดจำนวนการเชื่อมต่อพร้อมกัน และไม่ส่งโค้ดโจมตีใด ๆ</p></details>
      <details><summary>ทำไมบางเป้าหมายสแกนไม่ได้</summary><p>ผู้ติดตั้ง thscan กำหนดช่วง IP ที่อนุญาตไว้ (THSCAN_ALLOWED_CIDRS) เพื่อให้ใช้ตรวจได้เฉพาะเครือข่ายของหน่วยงานเอง ถ้าต้องการเพิ่มช่วง ให้ผู้ดูแลระบบแก้ค่านี้แล้วเริ่มโปรแกรมใหม่</p></details>
      <details><summary>ตรวจเว็บไซต์จากลิงก์ได้อย่างไร</summary><p>เลือก “เว็บไซต์ (ลิงก์)” แล้ววางลิงก์ เช่น https://www.agency.go.th ระบบจะค้นหา IP จาก DNS ครั้งเดียว ตรวจว่าเป็นโดเมนหน่วยงานและ IP อยู่ในขอบเขตที่อนุญาต จากนั้นสแกน IP นั้นโดยส่งชื่อเว็บไปด้วย เพื่อให้ได้ผลของเว็บนั้นจริง ๆ แม้เซิร์ฟเวอร์เดียวจะมีหลายเว็บ</p></details>
      <details><summary>การตรวจพอร์ตบอกอะไร และอันตรายไหม</summary><p>เป็นการลองเชื่อมต่อแบบปกติว่าพอร์ตไหนเปิดรับอยู่ (เหมือนการกดโทรแล้ววางสาย) ไม่ส่งข้อมูลโจมตี ผลที่ได้ช่วยให้เห็นบริการที่ไม่ควรเปิด เช่น Telnet หรือฐานข้อมูลที่เครื่องทั่วไปเข้าถึงได้ พอร์ตที่เปิดอยู่ไม่ได้แปลว่ามีช่องโหว่ จึงไม่นำไปลดคะแนน</p></details>
      <details><summary>ทำไมบางเครื่องไม่มี MAC address</summary><p>MAC อ่านได้เฉพาะเครื่องที่อยู่ในวง LAN เดียวกับเครื่องที่รัน thscan ถ้าเครื่องอยู่คนละวง (ผ่านเราเตอร์) ข้อมูลนี้จะว่าง ซึ่งเป็นเรื่องปกติ</p></details>
      <details><summary>“ตัวอย่างผลการสแกน” ต่างจากการสแกนจริงอย่างไร</summary><p>ตัวอย่างใช้ข้อมูลจำลองที่เตรียมไว้ ไม่ได้ส่งสัญญาณไปที่เครือข่ายใด ทุกหน้าที่มาจากตัวอย่างจะมีป้าย “ตัวอย่าง · ข้อมูลจำลอง” กำกับไว้เสมอ</p></details>
      <details><summary>คะแนนความปลอดภัยเป็นคะแนนทางการหรือไม่</summary><p>ไม่ใช่ คะแนนคำนวณโดย thscan จากจำนวนเครื่องที่มีความเสี่ยง ใช้ติดตามความคืบหน้าภายในหน่วยงาน ไม่ใช่การรับรองจาก ThaiCERT หรือหน่วยงานใด</p></details>
    </div>
  </div></section>

  <section class="section" style="padding-top:0"><div class="wrap">
    <div class="cta-band"><div><h2>พร้อมตรวจเครือข่ายของคุณแล้ว?</h2><p>ใช้เวลาไม่กี่นาที และไม่กระทบการทำงานของระบบ</p></div>
    <button class="btn btn-lg" id="cta-go">เริ่มสแกน</button></div>
  </div></section>`);

  const card = $("#scan-card");
  const refresh = (rebuildCustom) => {
    if (!$("#plan")) return;
    if (rebuildCustom) $("#custom").innerHTML = customPanel();
    $("#plan").innerHTML = planHTML();
    $("#go").disabled = !planOk();
    $("#go-err").hidden = true;
  };
  card.addEventListener("click", (e) => {
    const tg = e.target.closest("[data-target]");
    if (tg) {
      pick.target = tg.dataset.target;
      $$("[data-target]", card).forEach((x) => x.setAttribute("aria-pressed", String(x === tg)));
      $("#t-net").hidden = pick.target !== "net"; $("#t-site").hidden = pick.target !== "site";
      if (pick.target === "site") { $("#sites").focus(); scheduleResolve(() => refresh(false)); } else refresh(false);
      return;
    }
    const a = e.target.closest("[data-auto]"), c = e.target.closest("[data-custom]");
    const k = e.target.closest("[data-kind]"), f = e.target.closest("[data-fill]");
    if (a || c) {
      pick.mode = a ? "auto" : "custom"; if (a) pick.auto = a.dataset.auto;
      $$("[role=radio]", card).forEach((x) => x.setAttribute("aria-checked", String(x === (a || c))));
      $("#custom").hidden = pick.mode !== "custom";
      refresh(false);
      if (c) { const first = $("#custom input, #custom select", card); first && first.focus(); }
    } else if (k) {
      pick.kind = k.dataset.kind; refresh(true);
      const first = $("#custom input", card); first && first.focus();
    } else if (f) {
      const b = cidrBounds(f.dataset.fill);
      if (b) { pick.kind = "subnet"; pick.oct.subnet = intToIp(b.net).split("."); pick.prefix = Math.max(b.prefix, 24); refresh(true); }
    }
  });
  card.addEventListener("input", (e) => {
    const t = e.target;
    if (t.dataset.oct) {
      const v = t.value.replace(/\D/g, "").slice(0, 3);
      t.value = v; pick.oct[t.dataset.oct][+t.dataset.i] = v;
      t.setAttribute("aria-invalid", String(v !== "" && +v > 255));
      if (v.length === 3 && t.dataset.i < 3) focusOct(t, 1);
      if (t.dataset.oct === "range") { const p = $("#range-prefix"); if (p) p.textContent = pick.oct.range.slice(0, 3).map((x) => x || "_").join(".") + "."; }
    } else if (t.id === "range-end") { t.value = t.value.replace(/\D/g, "").slice(0, 3); pick.rangeEnd = t.value; }
    else if (t.id === "free") pick.text = t.value;
    else if (t.id === "prefix") pick.prefix = +t.value;
    else if (t.id === "pp-custom") pick.customPorts = t.value;
    else if (t.id === "sites") { pick.sitesText = t.value; scheduleResolve(() => refresh(false)); return; }
    else return;
    refresh(false);
  });
  card.addEventListener("change", (e) => {
    if (e.target.id === "prefix") { pick.prefix = +e.target.value; refresh(false); }
    if (e.target.id === "pp") {
      pick.profile = e.target.value;
      $("[data-custom-ports]", card).hidden = pick.profile !== "custom";
      if (pick.profile === "custom") $("#pp-custom").focus();
      refresh(false);
    }
  });
  card.addEventListener("keydown", (e) => {
    const t = e.target;
    if (!t.dataset.oct) { if (e.key === "Enter" && t.tagName === "INPUT" && !$("#go").disabled) $("#go").click(); return; }
    if ((e.key === "." || e.key === " ") && t.value) { e.preventDefault(); focusOct(t, 1); }
    else if (e.key === "Backspace" && !t.value) { e.preventDefault(); focusOct(t, -1); }
    else if (e.key === "ArrowLeft" && t.selectionStart === 0) focusOct(t, -1);
    else if (e.key === "ArrowRight" && t.selectionStart === t.value.length) focusOct(t, 1);
    else if (e.key === "Enter" && !$("#go").disabled) $("#go").click();
  });
  card.addEventListener("paste", (e) => {
    const t = e.target;
    if (!t.dataset.oct) return;
    const text = (e.clipboardData.getData("text") || "").trim();
    const m = text.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2})|-(\d{1,3}(?:\.\d{1,3}){3}|\d{1,3}))?$/);
    if (!m) return;
    e.preventDefault();
    const parts = m[1].split(".");
    if (m[2]) { pick.kind = "subnet"; pick.oct.subnet = parts; pick.prefix = Math.min(30, Math.max(16, +m[2])); }
    else if (m[3]) { pick.kind = "range"; pick.oct.range = parts; pick.rangeEnd = m[3].split(".").pop(); }
    else pick.oct[t.dataset.oct] = parts;
    refresh(true);
  });
  $("#go").addEventListener("click", async (e) => {
    const btn = e.currentTarget; btn.disabled = true;
    const ports = { port_profile: pick.profile, custom_ports: pick.profile === "custom" ? pick.customPorts : "" };
    try { await startScan(pick.target === "site" ? { sites: siteList(), ...ports } : { targets: pickTargets(), ...ports }); }
    catch (err) { const el = $("#go-err"); el.textContent = err.message; el.hidden = false; btn.disabled = false; }
  });
  $("#demo-link").addEventListener("click", openDemoPicker);
  $("#cta-go").addEventListener("click", () => card.scrollIntoView({ behavior: "smooth", block: "center" }));
}
function focusOct(input, dir) {
  const all = $$(`[data-oct="${input.dataset.oct}"]`);
  const next = all[+input.dataset.i + dir] || (dir > 0 && input.dataset.oct === "range" ? $("#range-end") : null);
  if (next) { next.focus(); next.select(); }
}

/* ── view: scanning ─────────────────────────────────────────────────── */
async function viewScanning([id], alive) {
  let s = await api(`/api/scans/${id}/summary`);
  if (!alive()) return;
  if (!["queued", "running"].includes(s.state)) { location.replace(`#/results/${id}`); return; }
  render(`<section class="scanning"><div class="scanning-box">
    ${s.demo_scenario ? '<span class="badge demo">ตัวอย่าง · ข้อมูลจำลอง</span>' : ""}
    <h1 class="eyebrow" style="font-size:var(--fs-body);margin-top:16px">กำลังสแกน <span class="mono">${esc(s.target_label)}</span></h1>
    <div class="big" id="pct" aria-hidden="true">0%</div>
    <div class="bar" role="progressbar" aria-label="ความคืบหน้า" aria-valuemin="0" aria-valuemax="100" id="bar-wrap"><i id="bar"></i></div>
    <p class="phase" id="phase" aria-live="polite">กำลังเตรียมการ…</p>
    <div class="counters">
      <div class="counter"><b id="c-probed">0</b><span>ตรวจแล้ว</span></div>
      <div class="counter"><b id="c-online">0</b><span>ออนไลน์</span></div>
      <div class="counter"><b id="c-risks">0</b><span>ควรแก้ไข</span></div>
    </div>
    <p style="margin-top:48px"><button class="btn btn-secondary" id="cancel">ยกเลิกการสแกน</button></p>
  </div></section>`);
  let stop = false;
  cleanup = () => { stop = true; };
  $("#cancel").addEventListener("click", async (e) => {
    e.currentTarget.disabled = true;
    try { await api(`/api/scans/${id}/cancel`, { method: "POST" }); $("#phase").textContent = "กำลังหยุด…"; }
    catch (err) { toast(err.message); e.currentTarget.disabled = false; }
  });
  const paint = (s) => {
    const p = s.progress, total = p.total_ips || 1;
    const phase1 = p.phase !== "inspect";
    const pct = phase1 ? Math.floor((p.probed / total) * 50)
      : 50 + Math.floor(((p.inspected || 0) / Math.max(1, p.to_inspect || 1)) * 48);
    $("#pct").textContent = `${pct}%`; $("#bar").style.width = `${pct}%`; $("#bar-wrap").setAttribute("aria-valuenow", pct);
    $("#c-probed").textContent = `${num(p.probed)}/${num(p.total_ips)}`;
    $("#c-online").textContent = num(p.online); $("#c-risks").textContent = num(p.risks);
    $("#phase").textContent = phase1 ? "ขั้นที่ 1 จาก 2 · ตรวจว่าเครื่องไหนออนไลน์"
      : `ขั้นที่ 2 จาก 2 · ตรวจพอร์ต เว็บ และเวอร์ชัน PHP (${num(p.inspected || 0)}/${num(p.to_inspect || 0)} เครื่อง)`;
  };
  paint(s);
  while (!stop) {
    await new Promise((r) => setTimeout(r, 700));
    if (stop || !alive()) return;
    try { s = await api(`/api/scans/${id}/summary`); } catch { continue; }
    if (stop || !alive()) return;
    if (!["queued", "running"].includes(s.state)) {
      $("#pct").textContent = "100%"; $("#bar").style.width = "100%";
      setTimeout(() => { if (alive()) location.replace(`#/results/${id}`); }, 350);
      return;
    }
    paint(s);
  }
}

/* ── view: results ──────────────────────────────────────────────────── */
const ADV0 = () => ({ type: "", php: "", port: "", gov: false, caution: false });
const R = { job: null, tab: "all", q: "", adv: ADV0(), showAdv: false, sel: null };
const svcPorts = (d) => (d.services && d.services.length ? d.services.map((x) => x.port) : d.open_ports);
const cautions = (d) => (d.services || []).filter((x) => x.note);

function phpBranch(v) { const m = /^(\d+\.\d+)/.exec(v || ""); return m ? m[1] : ""; }
function filtered() {
  const q = R.q.trim().toLowerCase();
  return R.job.devices.filter((d) => {
    if (R.tab === "urgent" && d.severity !== "critical") return false;
    if (R.tab === "fix" && !["high", "low"].includes(d.severity)) return false;
    if (R.tab === "ok" && d.severity !== "safe") return false;
    if (R.adv.type && d.device_type !== R.adv.type) return false;
    if (R.adv.php === "none" && d.php_version) return false;
    if (R.adv.php && R.adv.php !== "none" && phpBranch(d.php_version) !== R.adv.php) return false;
    if (R.adv.port && !svcPorts(d).includes(+R.adv.port)) return false;
    if (R.adv.caution && !cautions(d).length) return false;
    if (R.adv.gov && !d.matched_suffix) return false;
    if (!q) return true;
    const hay = [d.ip, d.hostname, d.mac, d.php_version, d.server, d.cms, devType(d.device_type), d.device_type, d.assessment,
      ...d.findings.flatMap((f) => [f.title, ...f.cve]),
      ...(d.services || []).flatMap((x) => [String(x.port), x.name])].join(" ").toLowerCase();
    return hay.includes(q);
  });
}
const advCount = () => ["type", "php", "port", "gov", "caution"].filter((k) => R.adv[k]).length;

async function viewResults([id], alive) {
  const job = await api(`/api/scans/${id}`);
  if (!alive()) return;
  if (["queued", "running"].includes(job.state)) { location.replace(`#/scan/${id}`); return; }
  if (!R.job || R.job.id !== job.id) Object.assign(R, { tab: "all", q: "", adv: ADV0(), showAdv: false, sel: null });
  R.job = job;
  renderResults();
}

function renderResults() {
  const j = R.job, c = { critical: 0, high: 0, low: 0, safe: 0 };
  j.devices.forEach((d) => c[d.severity]++);
  const risks = c.critical + c.high + c.low, demo = !!j.demo_scenario;
  const headline = !j.devices.length ? "ไม่พบเครื่องที่ออนไลน์ในช่วงนี้"
    : risks ? `พบ <span class="headline-num crit">${num(risks)}</span> เครื่องที่ควรแก้ไข`
      : `<span class="headline-num ok">ไม่พบ</span>เครื่องที่เสี่ยง PHP2Shell`;
  const types = [...new Set(j.devices.map((d) => d.device_type))].sort();
  const branches = [...new Set(j.devices.map((d) => phpBranch(d.php_version)).filter(Boolean))].sort();
  const ports = [...new Set(j.devices.flatMap(svcPorts))].sort((a, b) => a - b);
  const anyCaution = j.devices.some((d) => cautions(d).length);
  const portName = (p) => { for (const d of j.devices) { const x = (d.services || []).find((y) => y.port === p); if (x) return x.name; } return ""; };
  const anyGov = j.devices.some((d) => d.matched_suffix);
  const sel = (v, cur) => (String(v) === String(cur) ? "selected" : "");

  render(`<section class="page"><div class="wrap">
    <div class="page-head">
      <div>
        <div class="meta-line">${demo ? '<span class="badge demo">ตัวอย่าง · ข้อมูลจำลอง</span>' : ""}
          <span class="mono">${esc(j.target_label)}</span><span>·</span><span>${fmtDate(j.created_at)}</span>
          ${(j.scanned_ports || []).length ? `<span>·</span><span>ตรวจ ${num(j.scanned_ports.length)} พอร์ต</span>` : ""}
          ${j.duration_s != null ? `<span>·</span><span>ใช้เวลา ${fmtDuration(j.duration_s)}</span>` : ""}
          ${j.request && j.request.note ? `<span>·</span><span>${esc(j.request.note)}</span>` : ""}</div>
        <h1>${headline}</h1>
      </div>
      <div class="page-actions">
        ${demo ? `<a class="btn btn-secondary" href="#/">สแกนเครือข่ายจริง</a>`
          : `<button class="btn btn-secondary" id="rescan">${icon("refresh")}สแกนช่วงนี้อีกครั้ง</button>`}
        <div class="menu-wrap"><button class="btn btn-primary" id="export-btn" aria-haspopup="menu" aria-expanded="false">${icon("download")}ส่งออก</button>
          <div class="menu" id="export-menu" role="menu" hidden>
            <button role="menuitem" data-exp="csv">${icon("table")}<span><b>CSV ทั้งชุด</b><small>เปิดใน Excel ได้ · ทุกเครื่อง ทุกคอลัมน์</small></span></button>
            <button role="menuitem" data-exp="csv-view">${icon("list")}<span><b>CSV เฉพาะที่กรองอยู่</b><small id="exp-n">ตามตัวกรองและคำค้นปัจจุบัน</small></span></button>
            <button role="menuitem" data-exp="report">${icon("file")}<span><b>รายงานสรุปสำหรับผู้บริหาร</b><small>พิมพ์หรือบันทึกเป็น PDF</small></span></button>
            <button role="menuitem" data-exp="json">${icon("code")}<span><b>JSON</b><small>ข้อมูลดิบสำหรับเชื่อมกับระบบอื่น</small></span></button>
          </div></div>
      </div>
    </div>

    ${demo ? `<div class="notice info">${icon("info")}<span>นี่คือตัวอย่างจาก<strong>ข้อมูลจำลอง</strong> ไม่ใช่เครือข่ายของคุณ ไม่มีการส่งสัญญาณไปยังเครื่องใด · <a href="#/">เริ่มสแกนจริง</a></span></div>` : ""}
    ${j.state === "cancelled" ? `<div class="notice warn">${icon("alert")}<span>การสแกนนี้ถูกหยุดก่อนเสร็จ ผลด้านล่างอาจไม่ครบทุกเครื่อง</span></div>` : ""}
    ${j.state === "failed" ? `<div class="notice warn">${icon("alert")}<span>การสแกนผิดพลาด: ${esc(j.error || "ไม่ทราบสาเหตุ")}</span></div>` : ""}
    ${(j.intercepted_ports || []).length ? `<div class="notice info">${icon("shield")}<span>พบอุปกรณ์กลางทาง (เช่น proxy หรือ firewall) ตอบรับแทนทุกที่อยู่บนพอร์ต <span class="mono">${esc(j.intercepted_ports.join(", "))}</span> — thscan ตัดเครื่องที่ไม่มีอยู่จริงออกให้แล้ว ${tip(TIPS.intercept)}</span></div>` : ""}

    <div class="stats">
      <div class="stat"><span class="label">ออนไลน์ ${tip(TIPS.online)}</span><div class="value">${num(j.devices.length)}<small> / ${num(j.progress.total_ips)}</small></div></div>
      <div class="stat crit"><span class="label">ต้องแก้ด่วน</span><div class="value">${num(c.critical)}</div></div>
      <div class="stat warn"><span class="label">ควรแก้ไข</span><div class="value">${num(c.high + c.low)}</div></div>
      <div class="stat ${j.security_score >= 80 ? "ok" : j.security_score >= 65 ? "warn" : "crit"}"><span class="label">คะแนนความปลอดภัย ${tip(TIPS.score)}</span>
        <div class="value">${num(j.security_score)}<small> / 100 · ${esc(j.security_grade)}</small></div></div>
    </div>

    ${j.devices.length ? `
    <div class="toolbar">
      <div class="seg" role="tablist" aria-label="กรองตามผล">
        ${[["all", "ทั้งหมด", j.devices.length], ["urgent", "ต้องแก้ด่วน", c.critical], ["fix", "ควรแก้ไข", c.high + c.low], ["ok", "ผ่าน", c.safe]]
          .map(([k, t, n]) => `<button type="button" role="tab" data-tab="${k}" aria-pressed="${R.tab === k}" aria-selected="${R.tab === k}">${t}<span class="count">${num(n)}</span></button>`).join("")}
      </div>
      <span class="grow"></span>
      <label class="search"><span class="sr-only">ค้นหา</span>${icon("search")}<input type="search" id="q" value="${esc(R.q)}" placeholder="ค้นหา IP ชื่อเครื่อง PHP CVE…" autocomplete="off"></label>
      <button class="btn btn-secondary" id="adv-btn" aria-expanded="${R.showAdv}" aria-controls="filters">${icon("sliders")}ตัวกรองเพิ่มเติม${advCount() ? ` (${advCount()})` : ""}</button>
    </div>
    <div class="filters" id="filters" ${R.showAdv ? "" : "hidden"}>
      <label>ประเภทอุปกรณ์<select class="select" data-adv="type"><option value="">ทั้งหมด</option>
        ${types.map((t) => `<option value="${esc(t)}" ${sel(t, R.adv.type)}>${esc(devType(t))}</option>`).join("")}</select></label>
      <label>เวอร์ชัน PHP<select class="select" data-adv="php"><option value="">ทั้งหมด</option><option value="none" ${sel("none", R.adv.php)}>ไม่พบ PHP</option>
        ${branches.map((b) => `<option value="${esc(b)}" ${sel(b, R.adv.php)}>PHP ${esc(b)}.x</option>`).join("")}</select></label>
      <label>พอร์ตที่เปิด<select class="select" data-adv="port"><option value="">ทั้งหมด</option>
        ${ports.map((p) => `<option value="${p}" ${sel(p, R.adv.port)}>${p}${portName(p) && portName(p) !== "ไม่ทราบ" ? ` · ${esc(portName(p))}` : ""}</option>`).join("")}</select></label>
      ${anyCaution ? `<label style="display:flex;align-items:center;gap:8px;height:40px;font-size:var(--fs-sm);color:var(--ink)">
        <input type="checkbox" data-adv="caution" ${R.adv.caution ? "checked" : ""}> เฉพาะเครื่องที่มีพอร์ตควรระวัง</label>` : ""}
      ${anyGov ? `<label style="display:flex;align-items:center;gap:8px;height:40px;font-size:var(--fs-sm);color:var(--ink)">
        <input type="checkbox" data-adv="gov" ${R.adv.gov ? "checked" : ""}> เฉพาะชื่อโดเมนหน่วยงาน (.go.th ฯลฯ)</label>` : ""}
      <button class="btn btn-quiet" id="adv-clear">ล้างตัวกรอง</button>
    </div>
    <div class="split" id="split">
      <div class="list" id="list" role="listbox" aria-label="รายการเครื่อง"></div>
      <div class="detail" id="detail" aria-live="polite"></div>
    </div>` : `<div class="empty" style="border:1px solid var(--line);border-radius:var(--r-lg)">
      <h3>ไม่มีเครื่องที่ตอบสนองในช่วงนี้</h3>
      <p>อาจเป็นเพราะเครื่องปิดอยู่ ไฟร์วอลล์บล็อกการเชื่อมต่อ หรือช่วง IP ไม่ตรงกับเครือข่ายจริง ลองตรวจช่วงอีกครั้ง หรือเลือกวงอื่น</p>
      <p style="margin-top:24px"><a class="btn btn-secondary" href="#/">เลือกเป้าหมายใหม่</a></p></div>`}
  </div></section>`);

  wireResults();
  if (j.devices.length) { paintList(); paintDetail(); }
}

function wireResults() {
  const j = R.job;
  const btn = $("#export-btn"), menu = $("#export-menu");
  const closeMenu = () => { menu.hidden = true; btn.setAttribute("aria-expanded", "false"); };
  btn.addEventListener("click", (e) => {
    e.stopPropagation(); menu.hidden = !menu.hidden; btn.setAttribute("aria-expanded", String(!menu.hidden));
    if (!menu.hidden) { $("#exp-n").textContent = `${num(j.devices.length ? filtered().length : 0)} เครื่อง ตามตัวกรองปัจจุบัน`; menu.querySelector("button").focus(); }
  });
  const offMenu = (e) => { if (!e.target.closest(".menu-wrap")) closeMenu(); };
  document.addEventListener("click", offMenu);
  menu.addEventListener("keydown", (e) => { if (e.key === "Escape") { closeMenu(); btn.focus(); } });
  cleanup = () => document.removeEventListener("click", offMenu);
  menu.addEventListener("click", (e) => {
    const b = e.target.closest("[data-exp]"); if (!b) return;
    closeMenu();
    const k = b.dataset.exp;
    if (k === "csv") location.href = `/api/scans/${j.id}/export.csv`;
    else if (k === "json") location.href = `/api/scans/${j.id}/export.json`;
    else if (k === "report") location.hash = `#/report/${j.id}`;
    else downloadCsv(filtered(), `thscan-${j.id}-filtered.csv`);
  });
  const rescan = $("#rescan");
  rescan && rescan.addEventListener("click", async () => {
    rescan.disabled = true;
    try { await startScan({ targets: j.request.targets }); } catch (err) { toast(err.message); rescan.disabled = false; }
  });
  if (!j.devices.length) return;

  $$("[data-tab]").forEach((b) => b.addEventListener("click", () => {
    R.tab = b.dataset.tab;
    $$("[data-tab]").forEach((x) => { x.setAttribute("aria-pressed", String(x === b)); x.setAttribute("aria-selected", String(x === b)); });
    paintList(true);
  }));
  $("#q").addEventListener("input", (e) => { R.q = e.target.value; paintList(true); });
  $("#adv-btn").addEventListener("click", (e) => {
    R.showAdv = !R.showAdv; $("#filters").hidden = !R.showAdv; e.currentTarget.setAttribute("aria-expanded", String(R.showAdv));
  });
  const advLabel = () => { $("#adv-btn").lastChild.textContent = `ตัวกรองเพิ่มเติม${advCount() ? ` (${advCount()})` : ""}`; };
  $("#filters").addEventListener("change", (e) => {
    const k = e.target.dataset.adv; if (!k) return;
    R.adv[k] = e.target.type === "checkbox" ? e.target.checked : e.target.value;
    advLabel(); paintList(true);
  });
  $("#adv-clear").addEventListener("click", () => {
    R.adv = ADV0();
    $$("[data-adv]").forEach((x) => { if (x.type === "checkbox") x.checked = false; else x.value = ""; });
    advLabel(); paintList(true);
  });
  $("#list").addEventListener("click", (e) => { const r = e.target.closest("[data-ip]"); if (r) selectDevice(r.dataset.ip, true); });
  $("#list").addEventListener("keydown", (e) => {
    if (!["ArrowDown", "ArrowUp"].includes(e.key)) return;
    e.preventDefault();
    const rows = $$("[data-ip]", $("#list")), i = rows.findIndex((r) => r.dataset.ip === R.sel);
    const n = rows[Math.max(0, Math.min(rows.length - 1, i + (e.key === "ArrowDown" ? 1 : -1)))];
    if (n) { selectDevice(n.dataset.ip, false); n.focus(); }
  });
}

function paintList(fromFilter) {
  const list = filtered(), el = $("#list");
  if (fromFilter && !list.some((d) => d.ip === R.sel)) R.sel = null;
  if (!R.sel && list.length && matchMedia("(min-width: 961px)").matches) R.sel = list[0].ip;
  el.innerHTML = list.length ? list.map((d) => `<button type="button" class="row" role="option" data-ip="${esc(d.ip)}" aria-selected="${d.ip === R.sel}">
      <span class="ip">${esc(d.ip)}</span>${sevBadge(d.severity)}
      <span class="host">${esc(d.hostname || devType(d.device_type))}${d.php_version ? ` · PHP ${esc(d.php_version)}` : ""}</span></button>`).join("")
    : `<div class="empty"><h3>ไม่มีเครื่องที่ตรงกับเงื่อนไข</h3><p>ลองล้างคำค้นหรือตัวกรอง</p>
       <p style="margin-top:16px"><button class="btn btn-secondary" id="reset-filters">ล้างทั้งหมด</button></p></div>`;
  const reset = $("#reset-filters");
  reset && reset.addEventListener("click", () => {
    R.tab = "all"; R.q = ""; R.adv = ADV0(); renderResults();
  });
  if (fromFilter) paintDetail();
}

function selectDevice(ip, scroll) {
  R.sel = ip;
  $$("[data-ip]", $("#list")).forEach((r) => r.setAttribute("aria-selected", String(r.dataset.ip === ip)));
  paintDetail();
  if (scroll && !matchMedia("(min-width: 961px)").matches) $("#split").scrollIntoView({ behavior: "smooth", block: "start" });
}

function todoFor(d) {
  const recs = [...d.findings].sort((a, b) => SEV[a.severity].rank - SEV[b.severity].rank).map((f) => f.recommendation).filter(Boolean);
  const out = [...new Set(recs)];
  if (!out.length) out.push(d.php_version || d.open_ports.length ? "ไม่ต้องดำเนินการเพิ่ม — ตั้งเวลาสแกนซ้ำเป็นระยะเพื่อเฝ้าระวัง" : "เครื่องนี้ไม่มีบริการเว็บ จึงไม่ได้รับผลกระทบจาก PHP2Shell");
  else out.push("เมื่อแก้ไขแล้ว กด “ตรวจซ้ำเครื่องนี้” ด้านล่างเพื่อยืนยันผล");
  return out;
}

function paintDetail() {
  const el = $("#detail"), split = $("#split");
  const d = R.job.devices.find((x) => x.ip === R.sel);
  split.classList.toggle("show-detail", !!d);
  if (!d) { el.innerHTML = `<div class="empty"><h3>เลือกเครื่องจากรายการ</h3><p>รายละเอียด สิ่งที่พบ และวิธีแก้จะแสดงที่นี่</p></div>`; return; }
  const demo = !!R.job.demo_scenario, s = SEV[d.severity];
  const kv = [
    ["IP", `<span class="mono">${esc(d.ip)}</span>`],
    ["ชื่อโฮสต์", d.hostname ? `${esc(d.hostname)}${d.matched_suffix ? ` <span class="badge plain">${esc(d.matched_suffix)}</span>` : ""}` : "—", TIPS.host],
    ["MAC", d.mac ? `<span class="mono">${esc(d.mac)}</span>` : "—", TIPS.mac],
    ["ประเภทอุปกรณ์", esc(devType(d.device_type)), TIPS.type],
    ["บริการ", esc(d.service)],
    ["เวอร์ชัน PHP", d.php_version ? `<span class="mono">${esc(d.php_version)}</span>` : "ไม่พบ", TIPS.php],
    ["เว็บเซิร์ฟเวอร์", d.server ? esc(d.server) : "—"],
    ["CMS", d.cms ? esc(d.cms) : "—"],
    ["พอร์ตเว็บที่เปิด", d.open_ports.length ? `<span class="mono">${esc(d.open_ports.join(", "))}</span>` : "—", TIPS.ports],
    ["เวลาตอบสนอง", d.latency_ms != null ? `${num(d.latency_ms)} ms` : "—", TIPS.latency],
  ];
  const headers = Object.entries(d.headers || {});
  el.innerHTML = `
    <button class="btn btn-quiet detail-back" id="back">${icon("back")}กลับไปที่รายการ</button>
    <h2>${esc(d.ip)}</h2>
    <p class="sub">${esc(d.hostname || "ไม่มีชื่อโฮสต์")} · ${esc(devType(d.device_type))}</p>
    <div class="verdict ${s.verdict}"><b>${s.title}</b><span>${esc(d.assessment)}</span></div>

    <div class="block"><h3>สิ่งที่ควรทำ</h3><ol class="todo">${todoFor(d).map((t) => `<li><span>${esc(t)}</span></li>`).join("")}</ol></div>

    ${d.findings.length ? `<div class="block"><h3>สิ่งที่ตรวจพบ (${d.findings.length}) ${tip(TIPS.confidence)}</h3>
      ${d.findings.map((f) => `<div class="finding"><div class="finding-top"><h4>${esc(f.title)}</h4>${sevBadge(f.severity)}</div>
        <p>${esc(f.description)}</p>
        ${f.evidence ? `<div class="evidence">${esc(f.evidence)}</div>` : ""}
        <div class="cves"><span class="badge plain">ความมั่นใจ: ${CONF[f.confidence] || esc(f.confidence)}</span>
          ${f.cve.map((c) => `<span class="badge plain mono">${esc(c)}</span>`).join("")}
          ${f.cvss != null ? `<span class="badge plain">CVSS ${esc(f.cvss)}</span>` : ""}</div></div>`).join("")}</div>` : ""}

    ${d.services && d.services.length ? `<div class="block"><h3>พอร์ตและบริการที่เปิด (${d.services.length}) ${tip(TIPS.services)}</h3>
      <ul class="svc">${d.services.map((x) => `<li><span class="svc-port mono">${x.port}</span>
        <span><b>${esc(x.name)}</b> <span class="muted">· ${esc(x.description)}</span>
        ${x.note ? `<span class="svc-note">${icon("alert")}${esc(x.note)}</span>` : ""}</span></li>`).join("")}</ul></div>`
      : (R.job.scanned_ports || []).length ? `<div class="block"><h3>พอร์ตและบริการที่เปิด</h3><p class="muted" style="font-size:var(--fs-sm)">ไม่พบพอร์ตที่เปิดจาก ${num(R.job.scanned_ports.length)} พอร์ตที่ตรวจ (เครื่องตอบกลับแต่ปฏิเสธการเชื่อมต่อทุกพอร์ต)</p></div>` : ""}

    <div class="block"><h3>ข้อมูลเครื่อง</h3>
      <dl class="kv">${kv.map(([k, v, t]) => `<dt>${k}${t ? ` ${tip(t)}` : ""}</dt><dd>${v}</dd>`).join("")}</dl>
      ${headers.length ? `<details class="raw"><summary>ดู header ที่เว็บตอบกลับ (สำหรับเจ้าหน้าที่เทคนิค)</summary>
        <div class="evidence">${headers.map(([k, v]) => `${esc(k)}: ${esc(v)}`).join("\n")}</div></details>` : ""}
    </div>

    <div class="detail-actions">
      <button class="btn ${d.severity === "safe" ? "btn-secondary" : "btn-primary"}" id="recheck">${icon("refresh")}${demo ? "จำลองการแก้ไข (ตัวอย่าง)" : "ตรวจซ้ำเครื่องนี้"}</button>
      <button class="btn btn-secondary" id="copy">${icon("copy")}คัดลอกสรุป</button>
    </div>
    ${d.checked_at ? `<p class="stamp">ตรวจซ้ำล่าสุด ${fmtDate(d.checked_at)}</p>` : ""}
    ${d.patched_at ? `<p class="stamp">จำลองการแก้ไขเมื่อ ${fmtDate(d.patched_at)} (ข้อมูลตัวอย่าง)</p>` : ""}
    ${demo ? "" : `<p class="stamp">“ตรวจซ้ำ” จะสแกนเครื่องนี้ใหม่จริงอีกครั้ง แล้วแทนที่ผลเดิมด้วยผลล่าสุด</p>`}`;

  const back = $("#back");
  back.addEventListener("click", () => {
    R.sel = null; split.classList.remove("show-detail");
    $$("[data-ip]", $("#list")).forEach((r) => r.setAttribute("aria-selected", "false"));
    $("#split").scrollIntoView({ block: "start" });
  });
  $("#copy").addEventListener("click", async () => {
    const lines = [`${d.ip}${d.hostname ? ` (${d.hostname})` : ""}`, `ผล: ${s.label} — ${d.assessment}`,
      `PHP: ${d.php_version || "ไม่พบ"} · พอร์ตที่เปิด: ${(d.services || []).map((x) => `${x.port}/${x.name}`).join(", ") || d.open_ports.join(", ") || "—"}`,
      ...d.findings.map((f) => `- ${f.title}${f.cve.length ? ` [${f.cve.join(", ")}]` : ""}`),
      "สิ่งที่ควรทำ:", ...todoFor(d).map((t, i) => `${i + 1}. ${t}`)];
    if (demo) lines.unshift("[ตัวอย่าง · ข้อมูลจำลอง]");
    toast((await copyText(lines.join("\n"))) ? "คัดลอกสรุปแล้ว" : "คัดลอกไม่สำเร็จ");
  });
  $("#recheck").addEventListener("click", async (e) => {
    const b = e.currentTarget; b.disabled = true; b.lastChild.textContent = demo ? "กำลังจำลอง…" : "กำลังตรวจซ้ำ…";
    try {
      const res = await api(`/api/scans/${R.job.id}/devices/${encodeURIComponent(d.ip)}/recheck`, { method: "POST" });
      R.job = res.job;
      const after = res.device.severity;
      if (res.simulated) toast("จำลองการแก้ไขแล้ว — นี่คือข้อมูลตัวอย่าง ไม่ใช่ผลจริง");
      else if (!res.online) toast("เครื่องนี้ไม่ตอบสนองในตอนนี้ — ยังคงแสดงผลเดิมไว้");
      else toast(after === res.severity_before ? `ตรวจซ้ำแล้ว: ผลยังเป็น “${SEV[after].label}”` : `ตรวจซ้ำแล้ว: ${SEV[res.severity_before].label} → ${SEV[after].label}`);
      R.sel = d.ip; renderResults();
    } catch (err) { toast(err.message); b.disabled = false; b.lastChild.textContent = demo ? "จำลองการแก้ไข (ตัวอย่าง)" : "ตรวจซ้ำเครื่องนี้"; }
  });
}

function downloadCsv(devices, name) {
  const cell = (v) => { let s = String(v ?? ""); if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`; return `"${s.replace(/"/g, '""')}"`; };
  const head = ["ip", "hostname", "mac", "device_type", "service", "php_version", "cms", "open_ports", "open_services", "latency_ms", "severity", "assessment", "cve"];
  const rows = devices.map((d) => [d.ip, d.hostname, d.mac, d.device_type, d.service, d.php_version, d.cms, d.open_ports.join(" "),
    (d.services || []).map((x) => `${x.port}/${x.name}`).join(" "),
    d.latency_ms, d.severity, d.assessment, [...new Set(d.findings.flatMap((f) => f.cve))].sort().join(" ")]);
  const csv = "﻿" + [head, ...rows].map((r) => r.map(cell).join(",")).join("\r\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  a.download = name; document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  toast(`ดาวน์โหลด ${num(devices.length)} เครื่องแล้ว`);
}

/* ── view: report (print) ───────────────────────────────────────────── */
async function viewReport([id], alive) {
  const j = await api(`/api/scans/${id}`);
  if (!alive()) return;
  const c = { critical: 0, high: 0, low: 0, safe: 0 };
  j.devices.forEach((d) => c[d.severity]++);
  const act = j.devices.filter((d) => d.severity !== "safe");
  const demo = !!j.demo_scenario;
  const summary = !j.devices.length ? "ไม่พบเครื่องที่ออนไลน์ในช่วงที่ตรวจ"
    : act.length ? `จากการตรวจ ${num(j.progress.total_ips)} ที่อยู่ พบเครื่องออนไลน์ ${num(j.devices.length)} เครื่อง ในจำนวนนี้ ${num(c.critical)} เครื่องมีช่องโหว่ PHP2Shell ที่ต้องแก้ไขโดยด่วน และอีก ${num(c.high + c.low)} เครื่องมีความเสี่ยงที่ควรแก้ไข แนะนำให้อัปเดต PHP ของเครื่องกลุ่มแรกก่อน แล้วสั่งตรวจซ้ำเพื่อยืนยัน`
      : `จากการตรวจ ${num(j.progress.total_ips)} ที่อยู่ พบเครื่องออนไลน์ ${num(j.devices.length)} เครื่อง ไม่พบเครื่องที่มีความเสี่ยง PHP2Shell ณ เวลาที่ตรวจ`;
  render(`<section class="page"><div class="wrap"><div class="report">
    <div class="page-actions no-print" style="margin-bottom:32px">
      <a class="btn btn-quiet" href="#/results/${esc(j.id)}">${icon("back")}กลับไปที่ผลการสแกน</a>
      <button class="btn btn-primary" id="print">${icon("print")}พิมพ์ / บันทึก PDF</button>
    </div>
    ${demo ? '<p><span class="badge demo">ตัวอย่าง · ข้อมูลจำลอง — ไม่ใช่ผลการตรวจเครือข่ายจริง</span></p>' : ""}
    <h1 style="margin-top:12px">รายงานผลการตรวจช่องโหว่ PHP2Shell</h1>
    <p class="meta">ช่วงที่ตรวจ <span class="mono">${esc(j.target_label)}</span> · ${fmtDate(j.created_at)} · ใช้เวลา ${fmtDuration(j.duration_s)} · สถานะ ${STATE[j.state] || esc(j.state)}</p>
    <div class="sum">
      <div><span class="muted">ออนไลน์</span><b>${num(j.devices.length)}</b></div>
      <div><span class="muted">ต้องแก้ด่วน</span><b style="color:var(--crit)">${num(c.critical)}</b></div>
      <div><span class="muted">ควรแก้ไข</span><b style="color:var(--warn)">${num(c.high + c.low)}</b></div>
      <div><span class="muted">คะแนน (คำนวณโดย thscan)</span><b>${num(j.security_score)} · ${esc(j.security_grade)}</b></div>
    </div>
    <h2>สรุป</h2><p>${summary}</p>
    ${act.length ? `<h2>เครื่องที่ต้องดำเนินการ (เรียงตามความเร่งด่วน)</h2>
      <table><thead><tr><th>เครื่อง</th><th>ระดับ</th><th>PHP</th><th>สิ่งที่ควรทำ</th></tr></thead><tbody>
      ${act.map((d) => `<tr><td><span class="mono">${esc(d.ip)}</span><br><span class="muted">${esc(d.hostname || "")}</span></td>
        <td>${sevBadge(d.severity)}</td><td class="mono">${esc(d.php_version || "—")}</td>
        <td>${esc(todoFor(d)[0])}</td></tr>`).join("")}</tbody></table>` : ""}
    ${j.devices.length ? `<h2>เครื่องทั้งหมดที่ตรวจพบ</h2>
      <table><thead><tr><th>IP</th><th>ชื่อโฮสต์</th><th>ประเภท</th><th>PHP</th><th>พอร์ตที่เปิด</th><th>ผล</th></tr></thead><tbody>
      ${j.devices.map((d) => `<tr><td class="mono">${esc(d.ip)}</td><td>${esc(d.hostname || "—")}</td><td>${esc(devType(d.device_type))}</td>
        <td class="mono">${esc(d.php_version || "—")}</td>
        <td class="mono">${esc(svcPorts(d).join(", ") || "—")}</td><td>${SEV[d.severity].label}</td></tr>`).join("")}</tbody></table>` : ""}
    ${j.devices.some((d) => cautions(d).length) ? `<h2>พอร์ตที่ควรตรวจสอบ</h2>
      <table><thead><tr><th>เครื่อง</th><th>พอร์ต</th><th>ข้อควรระวัง</th></tr></thead><tbody>
      ${j.devices.flatMap((d) => cautions(d).map((x) => `<tr><td class="mono">${esc(d.ip)}</td><td>${x.port} · ${esc(x.name)}</td><td>${esc(x.note)}</td></tr>`)).join("")}</tbody></table>` : ""}
    <h2>หมายเหตุ</h2>
    <p class="muted">PHP รุ่นที่แก้ไขช่องโหว่แล้ว: 8.5.12, 8.4.27, 8.3.36, 8.2.35 ขึ้นไป · สาขาที่หมดอายุ (ต่ำกว่า 8.2) ควรย้ายไปรุ่นที่ยังได้รับการสนับสนุน ·
      ผลนี้มาจากการตรวจแบบไม่ทำลายระบบ ณ เวลาที่ระบุ · คะแนนคำนวณโดย thscan ไม่ใช่การรับรองจาก ThaiCERT หรือหน่วยงานใด</p>
  </div></div></section>`);
  $("#print").addEventListener("click", () => print());
}

/* ── view: latest ───────────────────────────────────────────────────── */
async function viewLatest(_, alive) {
  const jobs = await api("/api/scans");
  if (!alive()) return;
  if (jobs.length) { location.replace(`#/${["queued", "running"].includes(jobs[0].state) ? "scan" : "results"}/${jobs[0].id}`); return; }
  render(`<section class="page"><div class="wrap"><div class="empty">
    <h3>ยังไม่มีผลการสแกน</h3><p>เริ่มสแกนเครือข่ายครั้งแรก หรือเปิดตัวอย่างเพื่อดูว่าหน้าผลลัพธ์เป็นอย่างไร</p>
    <p style="margin-top:24px;display:flex;gap:12px;justify-content:center;flex-wrap:wrap"><a class="btn btn-primary" href="#/">เริ่มสแกน</a>
    <button class="btn btn-secondary" id="demo2">ดูตัวอย่าง</button></p></div></div></section>`);
  $("#demo2").addEventListener("click", openDemoPicker);
}

/* ── view: history ──────────────────────────────────────────────────── */
function histRow(s) {
  const live = ["queued", "running"].includes(s.state);
  return `<a class="hist-row" href="#/${live ? "scan" : "results"}/${esc(s.id)}">
    <span><span class="target">${esc(s.target_label || "—")}</span>
      ${s.demo_scenario ? ' <span class="badge demo">ตัวอย่าง</span>' : ""}
      ${s.state !== "completed" ? ` <span class="badge ${s.state === "failed" ? "crit" : "plain"}">${STATE[s.state] || esc(s.state)}</span>` : ""}
      <br><span class="when">${fmtDate(s.created_at)}${s.note ? ` · ${esc(s.note)}` : ""}</span></span>
    <span class="muted" style="font-size:var(--fs-sm)">ออนไลน์ ${num(s.online)} · <span style="color:${s.risks ? "var(--crit)" : "var(--ok)"}">ควรแก้ ${num(s.risks)}</span></span>
    <span class="grade g-${esc(s.security_grade)}" title="คะแนน ${num(s.security_score)}/100">${esc(s.security_grade)}</span>
    <span class="muted">${icon("arrow").replace("<svg", '<svg width="20" height="20"')}</span></a>`;
}

async function viewHistory(_, alive) {
  const jobs = await api("/api/scans");
  if (!alive()) return;
  render(`<section class="page"><div class="wrap">
    <div class="page-head"><div><p class="eyebrow">ประวัติ</p><h1>ผลการสแกนทั้งหมด</h1>
      <p>เก็บไว้ในเครื่องที่ติดตั้ง thscan (โฟลเดอร์ data/) ยังอยู่แม้รีสตาร์ทโปรแกรม</p></div>
      ${jobs.length ? `<div class="page-actions"><button class="btn btn-danger" id="clear">${icon("trash")}ล้างประวัติ</button></div>` : ""}</div>
    ${jobs.length ? `<div class="hist">${jobs.map(histRow).join("")}</div>`
      : `<div class="empty" style="border:1px solid var(--line);border-radius:var(--r-lg)"><h3>ยังไม่มีประวัติการสแกน</h3>
        <p>ผลการสแกนทุกครั้ง (รวมถึงที่ตั้งเวลาไว้) จะแสดงที่นี่</p><p style="margin-top:24px"><a class="btn btn-primary" href="#/">เริ่มสแกน</a></p></div>`}
  </div></section>`);
  const clear = $("#clear");
  clear && clear.addEventListener("click", async () => {
    const ok = await confirmModal({ title: "ล้างประวัติทั้งหมด?", text: `ผลการสแกน ${num(jobs.length)} รายการจะถูกลบถาวร รวมถึงไฟล์ผลลัพธ์ใน data/results (บันทึกการใช้งานยังคงอยู่)`, ok: "ลบทั้งหมด", danger: true });
    if (!ok) return;
    try { const r = await api("/api/scans", { method: "DELETE" }); toast(`ลบแล้ว ${num(r.removed)} รายการ`); route(); } catch (err) { toast(err.message); }
  });
}

/* ── view: settings ─────────────────────────────────────────────────── */
const AUDIT = {
  scan_started: "เริ่มสแกน", scan_finished: "สแกนเสร็จ", scan_cancelled: "ยกเลิกการสแกน", history_cleared: "ล้างประวัติ",
  device_rechecked: "ตรวจซ้ำเครื่อง", device_patch_simulated: "จำลองการแก้ไข (ตัวอย่าง)", schedule_created: "สร้างตารางเวลา",
  schedule_deleted: "ลบตารางเวลา", schedule_fired: "ตารางเวลาเริ่มสแกน", export_csv: "ส่งออก CSV", export_json: "ส่งออก JSON",
};
function auditDetail(e) {
  const p = [];
  if (e.targets && e.targets.length) p.push(`<span class="mono">${esc(e.targets.join(", "))}</span>`);
  if (e.demo_scenario) p.push(`ตัวอย่าง: ${esc(e.demo_scenario)}`);
  if (e.name) p.push(esc(e.name));
  if (e.cron) p.push(`<span class="mono">${esc(e.cron)}</span>`);
  if (e.ip) p.push(`<span class="mono">${esc(e.ip)}</span>`);
  if (e.severity_before && e.severity_after) p.push(`${SEV[e.severity_before] ? SEV[e.severity_before].label : esc(e.severity_before)} → ${SEV[e.severity_after] ? SEV[e.severity_after].label : esc(e.severity_after)}`);
  if (e.event === "scan_finished") p.push(`${STATE[e.state] || esc(e.state)} · ออนไลน์ ${num(e.online)} · ควรแก้ ${num(e.risks)}`);
  if (e.removed_jobs != null) p.push(`${num(e.removed_jobs)} รายการ`);
  if (e.job_id) p.push(`<a href="#/results/${esc(e.job_id)}" class="mono">${esc(e.job_id)}</a>`);
  return p.join(" · ") || "—";
}
function describeCron(cron) {
  const f = cron.trim().split(/\s+/);
  if (f.length !== 5) return cron;
  const [m, h, dom, mon, dow] = f, at = () => `${h.padStart(2, "0")}:${m.padStart(2, "0")} น.`;
  const num1 = (x) => /^\d+$/.test(x);
  if (num1(m) && h === "*" && dom === "*" && mon === "*" && dow === "*") return `ทุกชั่วโมง นาทีที่ ${m}`;
  if (!num1(m) || !num1(h) || mon !== "*") return "ตามรูปแบบที่กำหนดเอง";
  if (dom === "*" && dow === "*") return `ทุกวัน เวลา ${at()}`;
  if (dom === "*" && dow === "1-5") return `ทุกวันจันทร์–ศุกร์ เวลา ${at()}`;
  if (dom === "*" && num1(dow) && +dow <= 6) return `ทุกวัน${DOW[+dow]} เวลา ${at()}`;
  if (num1(dom) && dow === "*") return `ทุกวันที่ ${dom} ของเดือน เวลา ${at()}`;
  return "ตามรูปแบบที่กำหนดเอง";
}
const S = { freq: "daily", time: "02:00", dow: "1", dom: "1", cron: "0 2 * * *" };
function formCron() {
  const [h, m] = (S.time || "02:00").split(":").map((x) => String(+x));
  return { daily: `${m} ${h} * * *`, weekdays: `${m} ${h} * * 1-5`, weekly: `${m} ${h} * * ${S.dow}`,
    monthly: `${m} ${h} ${S.dom} * *`, hourly: `${m} * * * *`, custom: S.cron.trim() }[S.freq];
}

async function viewSettings(_, alive) {
  const [scheds, audit, auto] = await Promise.all([api("/api/schedules"), api("/api/audit"), api("/api/autodetect").catch(() => ({ subnets: [] }))]);
  if (!alive()) return;
  const suggest = (auto.subnets || []).map((s) => s.cidr).find((c) => { const b = cidrBounds(c); return b && inScope(b.net, b.bcast); }) || "";
  const box = (rows) => `<div class="box">${rows.map(([t, d, side]) => `<div class="box-row"><div><div class="t">${t}</div>${d ? `<div class="d">${d}</div>` : ""}</div>${side || ""}</div>`).join("")}</div>`;
  render(`<section class="page"><div class="wrap">
    <div class="page-head"><div><p class="eyebrow">ตั้งค่าและเครื่องมือ</p><h1>ตั้งเวลา ขอบเขต และบันทึกการใช้งาน</h1></div></div>
    <div class="settings">
      <nav class="subnav" aria-label="หัวข้อในหน้านี้">
        <a href="#/settings" data-jump="set-sched">ตั้งเวลาสแกนอัตโนมัติ</a>
        <a href="#/settings" data-jump="set-scope">ขอบเขตการสแกน</a>
        <a href="#/settings" data-jump="set-audit">บันทึกการใช้งาน</a>
        <a href="#/settings" data-jump="set-about">เกี่ยวกับ thscan</a>
      </nav>
      <div>
        <section class="set-section" id="set-sched">
          <h2>ตั้งเวลาสแกนอัตโนมัติ</h2>
          <p>ให้ thscan สแกนเองตามเวลาที่กำหนด (เวลาประเทศไทย) ผลจะไปอยู่ในหน้าประวัติ โปรแกรมต้องเปิดทำงานอยู่ ณ เวลานั้น</p>
          <div id="sched-list">${schedList(scheds)}</div>
          <form class="box" id="sched-form" novalidate>
            <div class="form-grid">
              <label>ชื่อ<input class="input" name="name" required maxlength="80" placeholder="เช่น สแกนวงสำนักงานทุกคืน"></label>
              <label><span>เป้าหมาย ${tip("ซับเน็ต ช่วง หรือ IP เดียว คั่นหลายรายการด้วยจุลภาค ต้องอยู่ในขอบเขตที่อนุญาต")}</span>
                <input class="input mono" name="targets" required spellcheck="false" autocomplete="off" value="${esc(suggest)}" placeholder="เช่น 192.168.1.0/24"></label>
              <label>ความถี่<select class="select" name="freq">
                <option value="daily">ทุกวัน</option><option value="weekdays">ทุกวันทำการ (จ.–ศ.)</option><option value="weekly">ทุกสัปดาห์</option>
                <option value="monthly">ทุกเดือน</option><option value="hourly">ทุกชั่วโมง</option><option value="custom">กำหนดเอง (cron)</option></select></label>
              <label data-f="time">เวลา<input class="input" type="time" name="time" value="02:00" required></label>
              <label data-f="dow" hidden>วัน<select class="select" name="dow">${DOW.map((d, i) => `<option value="${i}" ${i === 1 ? "selected" : ""}>วัน${d}</option>`).join("")}</select></label>
              <label data-f="dom" hidden>วันที่<select class="select" name="dom">${Array.from({ length: 28 }, (_, i) => `<option>${i + 1}</option>`).join("")}</select></label>
              <label data-f="cron" hidden><span>รูปแบบ cron ${tip("5 ช่อง: นาที ชั่วโมง วันที่ เดือน วันในสัปดาห์ (0 = อาทิตย์) เช่น 30 1 * * 1-5 = 01:30 น. วันจันทร์–ศุกร์")}</span>
                <input class="input mono" name="cron" value="0 2 * * *" spellcheck="false" autocomplete="off"></label>
              <div class="full">${portPicker("spp", "common", "")}</div>
              <p class="full muted" id="sched-preview" style="font-size:var(--fs-sm)"></p>
              <p class="full form-error" id="sched-err" role="alert" style="text-align:left" hidden></p>
              <div class="full"><button class="btn btn-primary" type="submit">บันทึกตารางเวลา</button></div>
            </div>
          </form>
        </section>

        <section class="set-section" id="set-scope">
          <h2>ขอบเขตการสแกน</h2>
          <p>กำหนดโดยผู้ติดตั้งในไฟล์ <span class="mono">docker-compose.yml</span> (<span class="mono">THSCAN_ALLOWED_CIDRS</span>) แล้วเริ่มโปรแกรมใหม่ — ตั้งใจให้แก้จากหน้านี้ไม่ได้ เพื่อไม่ให้ผู้ใช้ขยายขอบเขตเอง</p>
          ${box([
            ...(cfg.allowed_cidrs || []).map((c) => { const b = cidrBounds(c); return [`<span class="mono">${esc(c)}</span>`, b ? `${intToIp(b.net)} – ${intToIp(b.bcast)} · ${num(b.bcast - b.net + 1)} ที่อยู่` : ""]; }),
            ["จำนวนที่อยู่สูงสุดต่อการสแกน", `${num(cfg.max_targets)} ที่อยู่ (THSCAN_MAX_TARGETS)`],
            ["งานพร้อมกันสูงสุด", `${num(cfg.max_concurrency)} การเชื่อมต่อ (THSCAN_MAX_CONCURRENCY)`],
            ["พอร์ตเว็บที่ตรวจ PHP", `<span class="mono">${esc((cfg.web_ports || []).join(", "))}</span>`],
            ["พอร์ตที่ใช้ตรวจว่าเครื่องออนไลน์", `<span class="mono">${esc((cfg.liveness_ports || []).join(", "))}</span>`],
          ])}
        </section>

        <section class="set-section" id="set-audit">
          <div class="page-head" style="margin-bottom:0"><div><h2>บันทึกการใช้งาน</h2>
            <p style="color:var(--ink-2);margin-top:8px">ทุกการสแกน การตรวจซ้ำ การส่งออก และการตั้งเวลา ถูกบันทึกไว้ที่ <span class="mono">data/audit.log</span></p></div>
            <button class="btn btn-secondary" id="audit-refresh">${icon("refresh")}รีเฟรช</button></div>
          <div class="box scroll-x" id="audit-box">${auditTable(audit.entries)}</div>
        </section>

        <section class="set-section" id="set-about">
          <h2>เกี่ยวกับ thscan</h2>
          ${box([
            ["เวอร์ชัน", `v${esc(cfg.version)}`],
            ["สัญญาอนุญาต", "โอเพนซอร์ส ใช้ฟรี ไม่มีรุ่นเสียเงิน"],
            ["ข้อมูลอยู่ที่ไหน", "ทุกอย่างเก็บในเครื่องที่ติดตั้ง (โฟลเดอร์ data/) ไม่ส่งออกนอกหน่วยงาน"],
            ["ตรวจอะไร", "PHP2Shell (CVE-2026-109618, CVE-2026-109619), PHP สาขาที่หมดอายุ, การเปิดเผยเวอร์ชัน และ HSTS"],
          ])}
        </section>
      </div>
    </div>
  </div></section>`);

  $$("[data-jump]").forEach((a) => a.addEventListener("click", (e) => { e.preventDefault(); $(`#${a.dataset.jump}`).scrollIntoView({ behavior: "smooth" }); }));
  $("#audit-refresh").addEventListener("click", async () => {
    try { $("#audit-box").innerHTML = auditTable((await api("/api/audit")).entries); toast("อัปเดตแล้ว"); } catch (err) { toast(err.message); }
  });
  wireSchedules();
}

function profileLabel(id, custom) {
  if (id === "custom") return `พอร์ต ${custom}`;
  const p = (cfg.port_profiles || []).find((x) => x.id === (id || "common"));
  return p ? `${p.label} (${num(p.ports.length)} พอร์ต)` : "";
}
function schedList(items) {
  if (!items.length) return `<div class="box"><div class="box-row"><div><div class="t">ยังไม่มีตารางเวลา</div><div class="d">สร้างได้จากแบบฟอร์มด้านล่าง</div></div></div></div>`;
  return `<div class="box">${items.map((s) => `<div class="box-row">
    <div><div class="t">${esc(s.name)}</div>
      <div class="d"><span class="mono">${esc(s.targets.join(", "))}</span> · ${esc(describeCron(s.cron))} · ${esc(profileLabel(s.port_profile, s.custom_ports))}</div>
      <div class="d">ครั้งถัดไป ${fmtDate(s.next_run)}${s.last_run ? ` · ครั้งล่าสุด ${fmtDate(s.last_run)}` : " · ยังไม่เคยทำงาน"}
        ${s.last_job_id ? ` · <a href="#/results/${esc(s.last_job_id)}">ดูผลล่าสุด</a>` : ""}</div></div>
    <button class="btn btn-quiet" data-del="${esc(s.id)}" data-name="${esc(s.name)}" aria-label="ลบ ${esc(s.name)}">${icon("trash")}ลบ</button></div>`).join("")}</div>`;
}
function auditTable(entries) {
  if (!entries || !entries.length) return `<div class="box-row"><div class="d">ยังไม่มีบันทึก</div></div>`;
  return `<table class="audit"><thead><tr><th>เวลา</th><th>เหตุการณ์</th><th>รายละเอียด</th></tr></thead><tbody>
    ${entries.map((e) => `<tr><td>${fmtDate(e.ts)}</td><td>${esc(AUDIT[e.event] || e.event)}</td><td>${auditDetail(e)}</td></tr>`).join("")}</tbody></table>`;
}

function wireSchedules() {
  const form = $("#sched-form");
  const show = () => {
    S.freq = form.freq.value; S.time = form.time.value; S.dow = form.dow.value; S.dom = form.dom.value; S.cron = form.cron.value;
    $("[data-f=time]", form).hidden = S.freq === "custom";
    $("[data-custom-ports]", form).hidden = form.port_profile.value !== "custom";
    $("[data-f=dow]", form).hidden = S.freq !== "weekly";
    $("[data-f=dom]", form).hidden = S.freq !== "monthly";
    $("[data-f=cron]", form).hidden = S.freq !== "custom";
    const c = formCron();
    $("#sched-preview").innerHTML = S.freq === "hourly" ? `จะสแกนทุกชั่วโมง นาทีที่ ${esc(c.split(" ")[0])} · <span class="mono">${esc(c)}</span>`
      : `จะสแกน${esc(describeCron(c).replace(/^ทุก/, "ทุก"))} (เวลาประเทศไทย) · <span class="mono">${esc(c)}</span>`;
  };
  form.addEventListener("input", show); form.addEventListener("change", show); show();
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const err = $("#sched-err"); err.hidden = true;
    const targets = form.targets.value.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean);
    const name = form.name.value.trim();
    const c = checkTargets(targets);
    const fail = (m) => { err.textContent = m; err.hidden = false; };
    if (!name) return fail("กรุณาตั้งชื่อตารางเวลา");
    if (c.error) return fail(c.error);
    if (c.outside.length) return fail(`อยู่นอกขอบเขตที่อนุญาต: ${c.outside.join(", ")}`);
    if (c.count > cfg.max_targets) return fail(`เกินจำนวนสูงสุด ${num(cfg.max_targets)} ที่อยู่`);
    const pc = portCount(form.port_profile.value, form.custom_ports.value);
    if (pc.error) return fail(pc.error);
    if (c.count * pc.n > cfg.max_port_probes) return fail(`งานใหญ่เกินไป (${num(c.count)} ที่อยู่ × ${num(pc.n)} พอร์ต) — ลดขนาดวงหรือจำนวนพอร์ตลง`);
    const btn = $("button[type=submit]", form); btn.disabled = true;
    try {
      const port_profile = form.port_profile.value, custom_ports = port_profile === "custom" ? form.custom_ports.value : "";
      await api("/api/schedules", { method: "POST", body: JSON.stringify({ name, targets, cron: formCron(), enabled: true, port_profile, custom_ports }) });
      $("#sched-list").innerHTML = schedList(await api("/api/schedules"));
      form.name.value = ""; toast("บันทึกตารางเวลาแล้ว");
    } catch (ex) { fail(ex.message); } finally { btn.disabled = false; }
  });
  $("#sched-list").addEventListener("click", async (e) => {
    const b = e.target.closest("[data-del]"); if (!b) return;
    const ok = await confirmModal({ title: "ลบตารางเวลานี้?", text: `“${b.dataset.name}” จะไม่ทำงานอีก ผลการสแกนที่ผ่านมายังอยู่ในประวัติ`, ok: "ลบ", danger: true });
    if (!ok) return;
    try { await api(`/api/schedules/${encodeURIComponent(b.dataset.del)}`, { method: "DELETE" }); $("#sched-list").innerHTML = schedList(await api("/api/schedules")); toast("ลบแล้ว"); }
    catch (err) { toast(err.message); }
  });
}

route();

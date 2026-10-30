/* thscan UI — every screen renders data from the REST API; nothing is invented
   client-side. Demo results come from the server and are always labelled.
   Tools stay folded into one-line "docks" and open on hover, tap or focus. */
"use strict";

/* ── helpers ─────────────────────────────────────────────────────────── */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const nf = new Intl.NumberFormat("th-TH");
const num = (n) => nf.format(n || 0);
const reduceMotion = () => window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;

function fmtDate(iso, opts = { dateStyle: "medium", timeStyle: "short" }) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d)) return "—";
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

/* ── icons (24px stroke) ────────────────────────────────────────────── */
const P = {
  chev: "m6 9 6 6 6-6", arrow: "M5 12h14M13 6l6 6-6 6", back: "M19 12H5M11 6l-6 6 6 6",
  check: "m5 12.5 4.5 4.5L19 7.5", x: "M7 7l10 10M17 7 7 17", alert: "M12 4 21 20H3Z M12 10v4 M12 17h.01",
  warn: "M12 3.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 0 0 0-17Z M12 8v5 M12 16h.01",
  plate: "M3 12 12 7.5 21 12 12 16.5Z M3 15.5 12 20 21 15.5", range: "M4 12h16M4 8v8M20 8v8",
  cube: "M12 3 20 7.5v9L12 21 4 16.5v-9Z M4 7.5 12 12l8-4.5M12 12v9", globe: "M12 3.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 0 0 0-17Z M3.5 12h17 M12 3.5c2.4 2.5 3.5 5.3 3.5 8.5s-1.1 6-3.5 8.5c-2.4-2.5-3.5-5.3-3.5-8.5s1.1-6 3.5-8.5Z",
  lines: "M5 7h14M5 12h10M5 17h6", sliders: "M4 7h10M18 7h2M4 17h4M12 17h8 M16 5v4 M10 15v4",
  refresh: "M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7", copy: "M9 9h11v11H9Z M5 15V6a2 2 0 0 1 2-2h8", download: "M12 4v11M7.5 10.5 12 15l4.5-4.5M5 19h14",
  search: "M11 4.5a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13Z M16 16l4 4", print: "M7 9V4h10v5 M4 9h16v8H4Z M7 14h10v6H7Z",
  trash: "M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3", clock: "M12 3.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 0 0 0-17Z M12 7.5V12l3 2",
  shield: "M12 3 20 6v6c0 4.6-3.3 8.3-8 9.5C7.3 20.3 4 16.6 4 12V6Z",
};
const ic = (name, size = 18, sw = 2) => `<svg viewBox="0 0 24 24" width="${size}" height="${size}" fill="none" stroke="currentColor" stroke-width="${sw}" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${P[name]}"/></svg>`;
const chev = `<svg class="chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="${P.chev}"/></svg>`;

/* ── labels ──────────────────────────────────────────────────────────── */
const SEV = {
  critical: { word: "ต้องแก้ด่วน", cls: "b-bad", icon: "alert", title: "ต้องแก้ไขโดยด่วน", bg: "var(--crit-bg)", fg: "#8E1B22", dot: "var(--crit-dot)", rank: 0 },
  high: { word: "เสี่ยงสูง", cls: "b-warn", icon: "warn", title: "มีความเสี่ยงสูง ควรแก้เร็วที่สุด", bg: "var(--warn-bg)", fg: "#6E3F00", dot: "var(--warn-dot)", rank: 1 },
  low: { word: "ควรปรับปรุง", cls: "b-warn", icon: "warn", title: "ควรปรับปรุงเมื่อสะดวก", bg: "var(--warn-bg)", fg: "#6E3F00", dot: "var(--warn-dot)", rank: 2 },
  safe: { word: "ผ่าน", cls: "b-ok", icon: "check", title: "ไม่พบช่องโหว่ PHP2Shell", bg: "var(--ok-bg)", fg: "#0A5C39", dot: "var(--ok-dot)", rank: 3 },
};
const sevBadge = (s) => `<span class="badge ${SEV[s].cls}">${ic(SEV[s].icon, 13, 2.6)}${SEV[s].word}</span>`;
const CONF = { confirmed: "ยืนยันแล้ว", high: "สูง", medium: "ปานกลาง", low: "ต่ำ" };
const DEVTYPE = { "Gateway Router": "เราเตอร์ / เกตเวย์", "Web Server (HTTPS)": "เว็บเซิร์ฟเวอร์ (HTTPS)", "Web Server (HTTP)": "เว็บเซิร์ฟเวอร์ (HTTP)", "LAN Device": "อุปกรณ์ในเครือข่าย" };
const devType = (t) => DEVTYPE[t] || t || "—";
const STATE = { queued: "รอคิว", running: "กำลังสแกน", completed: "เสร็จแล้ว", cancelled: "ยกเลิกแล้ว", failed: "ผิดพลาด" };
const DOW = ["อาทิตย์", "จันทร์", "อังคาร", "พุธ", "พฤหัสบดี", "ศุกร์", "เสาร์"];
const DS = ["อา", "จ", "อ", "พ", "พฤ", "ศ", "ส"];
const gradeCls = (g) => (g === "A" || g === "B" ? "b-ok" : g === "C" ? "b-warn" : "b-bad");

/* ── tooltip shared by every ⓘ (fixed position, never clipped) ──────── */
const tt = $("#tt");
let ttFor = null;
const tip = (text) => `<button type="button" class="tip" data-tip="${esc(text)}" aria-label="คำอธิบาย: ${esc(text)}">i</button>`;
function showTip(el) {
  ttFor = el; tt.textContent = el.dataset.tip; tt.classList.add("show");
  const r = el.getBoundingClientRect(), w = tt.offsetWidth, h = tt.offsetHeight;
  const x = Math.max(8, Math.min(r.left + r.width / 2 - w / 2, innerWidth - w - 8));
  let y = r.top - h - 10; if (y < 8) y = r.bottom + 10;
  tt.style.left = `${x}px`; tt.style.top = `${y}px`;
}
function hideTip() { ttFor = null; tt.classList.remove("show"); }

/* ── docks: hover opens via CSS; tap/click toggles .open for touch.
   Only one dock is ever unfolded: hovering one folds any other. ────── */
function closeDocks(except) {
  $$(".dock.open").forEach((d) => {
    if (d === except) return;
    d.classList.remove("open");
    const b = $(":scope > [aria-expanded]", d); b && b.setAttribute("aria-expanded", "false");
  });
}
/* keep an unfolding panel inside the viewport (docks near an edge on small screens) */
function fitFly(d) {
  const fly = d && $(":scope > .fly", d);
  if (!fly) return;
  fly.style.marginLeft = "0px";
  const r = fly.getBoundingClientRect(), vw = document.documentElement.clientWidth;
  let dx = 0;
  if (r.right > vw - 8) dx = vw - 8 - r.right;
  if (r.left + dx < 8) dx = 8 - r.left;
  fly.style.marginLeft = `${Math.round(dx)}px`;
}
function shut(d) {
  if (!d) return;
  closeDocks(); d.classList.add("shut");
  const peek = $(":scope > [data-dock]", d); peek && peek.focus({ preventScroll: true });
}
document.addEventListener("mouseover", (e) => {
  const t = e.target.closest("[data-tip]"); if (t) showTip(t);
  const d = e.target.closest(".dock");
  if (d) { closeDocks(d); if (!d.contains(e.relatedTarget)) fitFly(d); }
});
document.addEventListener("mouseout", (e) => {
  if (e.target.closest("[data-tip]")) hideTip();
  const d = e.target.closest(".dock.shut");
  if (d && !d.contains(e.relatedTarget)) d.classList.remove("shut");
});
document.addEventListener("focusin", (e) => {
  const t = e.target.closest("[data-tip]"); t ? showTip(t) : hideTip();
  const d = e.target.closest(".dock"); if (d && !d.contains(e.relatedTarget)) fitFly(d);
});
document.addEventListener("focusout", (e) => { const d = e.target.closest(".dock.shut"); if (d && !d.contains(e.relatedTarget) && !d.matches(":hover")) d.classList.remove("shut"); });
addEventListener("scroll", hideTip, { passive: true });
document.addEventListener("click", (e) => {
  const t = e.target.closest(".tip");
  if (t) { e.preventDefault(); ttFor === t ? hideTip() : showTip(t); return; }
  if (ttFor) hideTip();
  const tog = e.target.closest("[data-dock]");
  if (tog) {
    const d = tog.closest(".dock"), open = !d.classList.contains("open");
    closeDocks(d); d.classList.remove("shut"); if (open) fitFly(d); d.classList.toggle("open", open); tog.setAttribute("aria-expanded", String(open));
    return;
  }
  if (!e.target.closest(".dock")) closeDocks();
});
document.addEventListener("keydown", (e) => { if (e.key === "Escape") { const d = document.activeElement && document.activeElement.closest(".dock"); closeDocks(); hideTip(); if (d) shut(d); } });
const dock = (id, peek, body, { w = 340, align = "", cls = "" } = {}) => `
  <div class="dock ${cls}" id="${id}" style="--w:${w}px">
    ${peek.replace("<button", `<button data-dock aria-expanded="false" aria-controls="${id}-fly"`)}
    <div class="fly ${align}" id="${id}-fly"><div class="panel">${body}</div></div>
  </div>`;

/* ── toast, modal, clipboard, count-up ─────────────────────────────── */
let toastTimer, toastAt = 0;
function toast(msg) {
  const old = $(".toast"); if (old) old.remove();
  toastAt = Date.now();
  const el = document.createElement("div"); el.className = "toast"; el.setAttribute("role", "status"); el.textContent = msg;
  document.body.append(el);
  clearTimeout(toastTimer); toastTimer = setTimeout(() => el.remove(), 4200);
}
function openModal(html, label) {
  closeDocks(); hideTip();
  const back = document.createElement("div");
  back.className = "modal-back";
  back.innerHTML = `<div class="modal" role="dialog" aria-modal="true" aria-label="${esc(label)}">${html}</div>`;
  const prev = document.activeElement;
  const close = () => { back.remove(); document.removeEventListener("keydown", onKey); prev && prev.focus && prev.focus(); };
  const onKey = (e) => {
    if (e.key === "Escape") close();
    if (e.key === "Tab") {
      const f = $$("button, a[href], input", back).filter((x) => !x.disabled);
      if (!f.length) return;
      if (e.shiftKey && document.activeElement === f[0]) { e.preventDefault(); f[f.length - 1].focus(); }
      else if (!e.shiftKey && document.activeElement === f[f.length - 1]) { e.preventDefault(); f[0].focus(); }
    }
  };
  back.addEventListener("click", (e) => { if (e.target === back || e.target.closest("[data-close]")) close(); });
  document.addEventListener("keydown", onKey);
  document.body.append(back);
  const first = $("[aria-checked='true'], .btn-g", back); first && first.focus();
  return { el: back, close };
}
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch {
    const ta = document.createElement("textarea"); ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.append(ta); ta.select();
    let ok = false; try { ok = document.execCommand("copy"); } catch { /* unsupported */ }
    ta.remove(); return ok;
  }
}
function tween(el, to, ms = 900, fmt = num) {
  if (!el) return;
  if (reduceMotion()) { el.textContent = fmt(to); el.dataset.v = to; return; }
  const from = Number(el.dataset.v || 0), t0 = performance.now();
  el.dataset.v = to;
  const step = (t) => { const k = Math.min(1, (t - t0) / ms), e = 1 - Math.pow(1 - k, 3); el.textContent = fmt(Math.round(from + (to - from) * e)); if (k < 1) requestAnimationFrame(step); };
  requestAnimationFrame(step);
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
  const [ip, p] = String(spec).split("/");
  const base = ipToInt(ip), prefix = /^\d{1,2}$/.test(p) ? +p : NaN;
  if (base == null || !(prefix >= 0 && prefix <= 32)) return null;
  const size = 2 ** (32 - prefix), net = Math.floor(base / size) * size;
  return { net, bcast: net + size - 1, prefix };
}
function specBounds(spec) {
  spec = spec.trim();
  if (spec.includes("/")) {
    const b = cidrBounds(spec);
    if (!b) throw new Error(`“${spec}” ไม่ใช่ซับเน็ตที่ถูกต้อง`);
    return b.prefix <= 30 ? [b.net + 1, b.bcast - 1] : [b.net, b.bcast];
  }
  if (spec.includes("-")) {
    let [l, r] = spec.split("-", 2).map((x) => x.trim());
    const a = ipToInt(l);
    if (a == null) throw new Error(`จุดเริ่ม “${l}” ไม่ใช่ IP ที่ถูกต้อง`);
    if (/^\d{1,3}$/.test(r)) r = l.split(".").slice(0, 3).concat(r).join(".");
    const b = ipToInt(r);
    if (b == null) throw new Error(`จุดสิ้นสุด “${r}” ไม่ใช่ IP ที่ถูกต้อง`);
    if (b < a) throw new Error("จุดสิ้นสุดต้องไม่น้อยกว่าจุดเริ่ม");
    return [a, b];
  }
  const n = ipToInt(spec);
  if (n == null) throw new Error(`“${spec}” ไม่ใช่ IP ที่ถูกต้อง`);
  return [n, n];
}
let allowedNets = [];
const inScope = (a, b) => !(cfg && cfg.enforce_scope) || allowedNets.some((n) => n.net <= a && b <= n.bcast);
function checkTargets(specs) {
  const out = { count: 0, error: null, outside: [] };
  if (!specs.length) { out.error = "ยังไม่ได้ระบุเป้าหมาย"; return out; }
  for (const s of specs) {
    let a, b;
    try { [a, b] = specBounds(s); } catch (e) { out.error = e.message; return out; }
    out.count += b - a + 1;
    if (!inScope(a, b)) out.outside.push(s);
  }
  return out;
}
/* mirrors app/scanner/ports.py parse_ports → { n } or { error } */
function countPorts(spec) {
  const set = new Set(cfg.web_ports || []), max = cfg.max_custom_ports || 1024;
  let any = false;
  for (const raw of String(spec).split(/[\s,;]+/)) {
    if (!raw) continue;
    const m = raw.match(/^(\d{1,5})(?:-(\d{1,5}))?$/);
    if (!m) return { error: `พอร์ตไม่ถูกต้อง: ${raw}` };
    const a = +m[1], b = m[2] ? +m[2] : a;
    if (a < 1 || b > 65535) return { error: `พอร์ตต้องอยู่ระหว่าง 1–65535: ${raw}` };
    if (b < a) return { error: `ช่วงพอร์ตกลับด้าน: ${raw}` };
    if (b - a + 1 > max) return { error: `ระบุพอร์ตได้ไม่เกิน ${num(max)} พอร์ต` };
    for (let p = a; p <= b; p++) set.add(p);
    any = true;
    if (set.size > max + 8) return { error: `ระบุพอร์ตได้ไม่เกิน ${num(max)} พอร์ต` };
  }
  return any ? { n: set.size } : { error: "ยังไม่ได้ระบุพอร์ต" };
}
function portCount(profile, custom) {
  if (profile === "custom") return countPorts(custom);
  const p = (cfg.port_profiles || []).find((x) => x.id === profile);
  return { n: p && p.ports ? p.ports.length : 0 };
}
const PROFILE_TEXT = {
  web: ["เฉพาะเว็บ", "พอร์ตเว็บอย่างเดียว · เร็วที่สุด"],
  common: ["ใช้บ่อย", "ครอบคลุมบริการหลัก เช่น SSH, RDP, ฐานข้อมูล"],
  top100: ["ยอดนิยม", "100 พอร์ตที่พบบ่อยที่สุด · ละเอียดขึ้น"],
  custom: ["กำหนดเอง", "ระบุพอร์ตเอง เช่น 22, 80, 8000-8100"],
};
const profileOpts = (attr, cur) => (cfg.port_profiles || []).map((p) => `<button type="button" class="opt" ${attr}="${p.id}" aria-pressed="${cur === p.id}" style="margin-top:8px">
  <span style="flex:1;min-width:0"><span class="ot">${esc((PROFILE_TEXT[p.id] || [p.label])[0])}${p.ports ? ` · ${num(p.ports.length)} พอร์ต` : ""}</span><span class="od">${esc((PROFILE_TEXT[p.id] || ["", ""])[1])}</span></span>
  ${p.id === "common" ? '<span class="badge b-blue">แนะนำ</span>' : ""}</button>`).join("");

/* ── app state + router ─────────────────────────────────────────────── */
let cfg = null;
let routeToken = 0;
let cleanups = [];
const app = $("#app");
const onCleanup = (fn) => cleanups.push(fn);

async function loadConfig() {
  if (cfg) return cfg;
  cfg = await api("/api/config");
  allowedNets = (cfg.allowed_cidrs || []).map(cidrBounds).filter(Boolean);
  return cfg;
}

const routes = [
  [/^#?\/?$/, viewScan, "scan"],
  [/^#\/scan\/([\w-]+)$/, viewScanning, "scan"],
  [/^#\/results\/([\w-]+)$/, viewResults, "results"],
  [/^#\/latest$/, viewLatest, "results"],
  [/^#\/report\/latest$/, viewReportLatest, "report"],
  [/^#\/report\/([\w-]+)$/, viewReport, "report"],
  [/^#\/history$/, viewHistory, "history"],
  [/^#\/settings$/, viewSettings, "settings"],
];

async function route() {
  cleanups.forEach((f) => { try { f(); } catch { /* ignore */ } }); cleanups = [];
  hideTip(); closeDocks();
  // a toast from the page being left would cover the next one; keep only a fresh one
  if (Date.now() - toastAt > 1000) { const t = $(".toast"); if (t) t.remove(); }
  const token = ++routeToken, alive = () => token === routeToken;
  const hash = location.hash || "#/";
  const hit = routes.find(([re]) => re.test(hash)) || routes[0];
  const params = hash.match(hit[0]) || [];
  $$("[data-nav]").forEach((a) => (a.dataset.nav === hit[2] ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current")));
  setTopSide("");
  try {
    await loadConfig();
    await hit[1](params.slice(1), alive);
  } catch (e) {
    if (!alive()) return;
    render(`<div class="app thin"><div class="card in1" style="padding:32px;text-align:center">
      <h1 class="h1" style="font-size:24px">${e.status === 404 ? "ไม่พบข้อมูลนี้" : "โหลดข้อมูลไม่สำเร็จ"}</h1>
      <p class="lead">${esc(e.message)}</p><p style="margin-top:18px"><a class="btn" href="#/">กลับหน้าสแกน</a></p></div></div>`);
  }
}
function render(html) { app.innerHTML = html; scrollTo(0, 0); fitAll(); }
// folded panels still take up layout space, so place them inside the viewport up front
const fitAll = () => [...$$(".dock"), $("#top-side")].forEach((d) => d && d.classList.contains("dock") && fitFly(d));
let fitTimer;
addEventListener("resize", () => { clearTimeout(fitTimer); fitTimer = setTimeout(fitAll, 150); });
function setTopSide(html) { $("#top-side").innerHTML = html; }
addEventListener("hashchange", route);

async function startScan(body) {
  const job = await api("/api/scans", { method: "POST", body: JSON.stringify(body) });
  location.hash = `#/scan/${job.id}`;
}
function openDemoPicker() {
  const demos = cfg.demos || [];
  let pick = demos[0] && demos[0].id;
  const m = openModal(`<h2>ดูตัวอย่างผลการสแกน</h2>
    <p class="lead">เลือกสถานการณ์ ระบบจะแสดงผลจาก<b>ข้อมูลจำลอง</b> (ไม่ได้สแกนเครือข่ายจริง) เพื่อให้เห็นว่าหน้าผลลัพธ์อ่านอย่างไร</p>
    <div role="radiogroup" aria-label="สถานการณ์ตัวอย่าง" style="display:flex;flex-direction:column;gap:8px;margin-top:14px">
      ${demos.map((d, i) => `<button type="button" class="opt" role="radio" aria-pressed="${i === 0}" aria-checked="${i === 0}" data-demo="${esc(d.id)}">
        <span class="oi">${ic("plate")}</span><span style="min-width:0"><span class="ot">${esc(d.name)}</span><span class="od">${esc(d.description)}</span></span></button>`).join("")}
    </div>
    <div class="modal-foot"><button type="button" class="btn" data-close>ยกเลิก</button><button type="button" class="btn btn-g" data-go>เปิดตัวอย่าง ${ic("arrow", 17)}</button></div>`, "ดูตัวอย่างผลการสแกน");
  m.el.addEventListener("click", (e) => {
    const c = e.target.closest("[data-demo]");
    if (c) { pick = c.dataset.demo; $$("[data-demo]", m.el).forEach((x) => { x.setAttribute("aria-pressed", String(x === c)); x.setAttribute("aria-checked", String(x === c)); }); }
  });
  $("[data-go]", m.el).addEventListener("click", async (e) => {
    const b = e.currentTarget; b.disabled = true;
    try { await startScan({ demo_scenario: pick }); m.close(); } catch (err) { toast(err.message); b.disabled = false; }
  });
}

/* ═══ view: scan ═══════════════════════════════════════════════════════ */
const S = { init: false, mode: "subnet", oct: ["192", "168", "1", "0"], prefix: 24, single: ["192", "168", "1", "1"], rs: "1", re: "254",
  site: "", text: "", profile: "common", custom: "22, 80, 8000-8100", speed: 0, delay: 0, swap: 0, report: null, reportFor: "", detected: [] };
const MODES = [
  ["subnet", "ทั้งวง", "ทุกเครื่องในวงเดียวกัน", "plate"], ["range", "ช่วง IP", "เช่น เครื่องที่ 10 ถึง 50", "range"],
  ["single", "เครื่องเดียว", "ตรวจซ้ำหลังแก้ไข", "cube"], ["site", "เว็บไซต์", "วางลิงก์ของหน่วยงาน", "globe"],
  ["text", "พิมพ์เอง", "หลายรายการคั่นด้วยจุลภาค", "lines"],
];
const siteList = () => S.site.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean).slice(0, cfg.max_sites || 20);
const hostsFor = (p) => (p >= 31 ? 2 ** (32 - p) : 2 ** (32 - p) - 2);
const detect = (subnets) => (subnets || []).map((s) => { const b = cidrBounds(s.cidr); return { ...s, ok: !!b && inScope(b.net, b.bcast), hosts: b ? hostsFor(b.prefix) : 0 }; });

function scanPlan() {
  const okOct = (o) => o.every((x) => x !== "" && +x <= 255);
  const ip = (o) => o.map((x) => String(+x)).join(".");  // "01" → "1": the server rejects leading zeros
  const plan = { valid: true, scoped: true, pending: false, count: 0, label: "", big: "", sub: "", summary: "", body: null, reason: "" };
  if (S.mode === "site") {
    const list = siteList();
    const fresh = S.reportFor === list.join("\n") && S.report;
    plan.valid = list.length > 0;
    plan.label = "เว็บไซต์"; plan.big = list.length > 1 ? `${list.length} เว็บไซต์` : (list[0] || "—").replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    plan.summary = `เว็บไซต์ · ${plan.big}`;
    const asIp = list.length === 1 && parseIpTarget(list[0]);
    if (!plan.valid) plan.reason = "วางลิงก์เว็บไซต์ก่อน";
    else if (asIp) { plan.valid = false; plan.scoped = false; plan.reason = `นี่คือเลข IP — กดปุ่มด้านล่างเพื่อตรวจ ${asIp.ip} ในโหมดเครื่องเดียว`; plan.sub = "ไม่ใช่โดเมนหน่วยงาน"; }
    else if (!fresh) { plan.pending = true; plan.reason = "กำลังตรวจสอบลิงก์…"; plan.sub = "กำลังค้นหา IP จาก DNS…"; }
    else {
      const bad = S.report.filter((r) => r.problems.length);
      plan.count = new Set(S.report.flatMap((r) => r.ips)).size;
      plan.scoped = !bad.length;
      plan.sub = plan.scoped ? S.report.map((r) => `${r.host} → ${r.ips.join(", ")}`).join(" · ") : bad[0].problems[0];
      if (!plan.scoped) plan.reason = bad[0].refused ? "ตรวจได้เฉพาะโดเมนหน่วยงาน" : bad[0].problems[0];
    }
    plan.body = { sites: list };
    return plan;
  }
  let specs = [];
  if (S.mode === "subnet") {
    plan.valid = okOct(S.oct);
    if (plan.valid) { const b = cidrBounds(`${ip(S.oct)}/${S.prefix}`); specs = [`${intToIp(b.net)}/${S.prefix}`]; plan.sub = `${intToIp(b.net + 1)} ถึง ${intToIp(b.bcast - 1)}`; }
    plan.label = "ขนาดวง"; plan.big = `/${S.prefix}`; plan.summary = `ทั้งวง · ${specs[0] || "กรอกให้ครบ"}`;
  } else if (S.mode === "range") {
    const base = ip(S.oct.slice(0, 3));
    plan.valid = okOct(S.oct) && S.rs !== "" && S.re !== "" && +S.rs <= +S.re && +S.re <= 255;
    specs = plan.valid ? [`${base}.${+S.rs}-${+S.re}`] : [];
    plan.label = "ช่วงที่ตรวจ"; plan.big = `${S.rs || "?"} – ${S.re || "?"}`; plan.sub = `${base}.${S.rs} ถึง ${base}.${S.re}`; plan.summary = `ช่วง · ${base}.${S.rs}–${S.re}`;
  } else if (S.mode === "single") {
    plan.valid = okOct(S.single); specs = plan.valid ? [ip(S.single)] : [];
    plan.label = "เครื่องเดียว"; plan.big = S.single.join("."); plan.sub = "ตรวจละเอียดเฉพาะเครื่องนี้"; plan.summary = `เครื่องเดียว · ${S.single.join(".")}`;
  } else {
    specs = S.text.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean).slice(0, 64);
    plan.label = "พิมพ์เอง"; plan.big = `${specs.length} รายการ`; plan.summary = `พิมพ์เอง · ${specs.length} รายการ`;
  }
  const c = checkTargets(specs);
  if (c.error) { plan.valid = false; plan.reason = c.error; if (S.mode === "text") plan.sub = c.error; }
  else {
    plan.count = c.count; plan.scoped = !c.outside.length;
    if (!plan.scoped) plan.reason = `อยู่นอกขอบเขตที่อนุญาต (${(cfg.allowed_cidrs || []).join(", ")})`;
    if (S.mode === "text") plan.sub = specs.join(", ");
  }
  if (!plan.valid && !plan.reason) plan.reason = "กรอกเป้าหมายให้ครบ (0–255)";
  if (plan.valid && plan.count > cfg.max_targets) { plan.scoped = false; plan.reason = `เกินจำนวนสูงสุด ${num(cfg.max_targets)} ที่อยู่ต่อครั้ง`; }
  plan.body = { targets: specs };
  return plan;
}

async function viewScan(_, alive) {
  const auto = await api("/api/autodetect").catch(() => ({ subnets: [] }));
  if (!alive()) return;
  S.detected = detect(auto.subnets);
  if (!S.init) {
    S.init = true; S.speed = cfg.max_concurrency;
    const first = S.detected.find((s) => s.ok);
    const b = first ? cidrBounds(first.cidr) : allowedNets[0];
    if (b) { S.oct = intToIp(b.net).split("."); S.prefix = Math.min(30, Math.max(first ? b.prefix : 24, 16)); S.single = intToIp(b.net + 1).split("."); }
  }
  setTopSide(`<button type="button" class="ghost" id="demo-btn">ดูตัวอย่างผล ↗</button>`);
  $("#demo-btn").addEventListener("click", openDemoPicker);

  render(`<div class="app narrow">
  <div class="in1" style="text-align:center">
    <h1 class="h1">ตรวจเครือข่ายของคุณ <span class="gtext">ได้ในคลิกเดียว</span></h1>
    <p class="lead">ระบบเลือกค่าที่เหมาะให้แล้ว · ชี้ที่แถบด้านล่างเมื่อต้องการปรับ · อ่านอย่างเดียว ไม่ทำลายระบบ</p>
  </div>
  <div class="tools in2" style="margin-top:22px">
    ${dock("d-target", `<button type="button" class="peek"><span class="ic">1</span><span style="min-width:0"><span class="k">เป้าหมาย</span><span class="v" id="sum-target"></span></span>${chev}</button>`, `<div id="p-target"></div>`, { w: 520 })}
    ${dock("d-ports", `<button type="button" class="peek"><span class="ic">2</span><span style="min-width:0"><span class="k">พอร์ตที่ตรวจ</span><span class="v" id="sum-ports"></span></span>${chev}</button>`, `<div id="p-ports"></div>`, { w: 380, align: "mid" })}
    ${dock("d-adv", `<button type="button" class="peek"><span class="ic grey">${ic("sliders", 19)}</span><span style="min-width:0"><span class="k">ขั้นสูง</span><span class="v" id="sum-adv"></span></span>${chev}</button>`, `<div id="p-adv"></div>`, { w: 340, align: "end" })}
  </div>
  <section class="card stage in3" aria-label="ตัวอย่างเป้าหมาย" style="margin-top:16px;padding:16px 24px 26px;text-align:center">
    <div id="stage-wrap" class="swap${S.swap}" style="position:relative;max-width:420px;margin:0 auto">${stageSvg()}
      <input class="ringin" id="ringin" type="range" min="16" max="30" step="1" aria-label="ขนาดวงเครือข่าย ลากเพื่อเปลี่ยน">
    </div>
    <div class="dial-ctl">
      <button type="button" class="round hov" id="bigger" aria-label="ขยายวงให้ใหญ่ขึ้น">−</button>
      <div style="min-width:0"><div class="k" id="v-label"></div><div class="big" id="v-big"></div></div>
      <button type="button" class="round hov" id="smaller" aria-label="ย่อวงให้เล็กลง">+</button>
    </div>
    <p style="margin-top:2px;font-size:14px;color:var(--muted);overflow-wrap:anywhere"><b class="num" id="v-count" style="color:var(--ink)">0</b> <span id="v-sub"></span></p>
    <p class="hov" id="v-hint" style="margin-top:4px;font-size:12.5px;color:var(--muted)">ลากวงแหวน หรือกด − / + เพื่อปรับขนาดวง</p>
    <div style="display:flex;flex-wrap:wrap;justify-content:center;align-items:center;gap:12px;margin-top:20px">
      ${dock("d-ready", `<button type="button" class="peek" style="width:auto;min-width:240px;max-width:min(420px,100%);padding-right:14px"><span class="ic" id="ready-ic" style="width:34px;height:34px;border-radius:50%"></span><span style="min-width:0;text-align:left"><span class="k" id="ready-k"></span><span class="v" id="ready-v"></span></span></button>`, `<div id="p-ready" style="text-align:left"></div>`, { w: 340, align: "mid" })}
      <button type="button" class="go" id="go">เริ่มสแกน${ic("arrow", 20, 2.2)}</button>
    </div>
  </section></div>`);

  renderTargetPanel(); renderPortsPanel(); renderAdvPanel(); updateScan(true);

  $("#ringin").addEventListener("input", (e) => { S.prefix = +e.target.value; updateScan(); });
  $("#bigger").addEventListener("click", () => { S.prefix = Math.max(16, S.prefix - 1); updateScan(); });
  $("#smaller").addEventListener("click", () => { S.prefix = Math.min(30, S.prefix + 1); updateScan(); });
  $("#go").addEventListener("click", async (e) => {
    const plan = scanPlan(), btn = e.currentTarget;
    btn.disabled = true;
    try { await startScan({ ...plan.body, port_profile: S.profile, custom_ports: S.profile === "custom" ? S.custom : "", concurrency: S.speed, polite_delay_ms: S.delay }); }
    catch (err) { toast(err.message); btn.disabled = false; }
  });

  // panels are re-rendered on change, so their events are delegated here once
  const pt = $("#p-target");
  pt.addEventListener("click", (e) => {
    const m = e.target.closest("[data-mode]"), d = e.target.closest("[data-detected]");
    if (m && m.dataset.mode !== S.mode) {
      S.mode = m.dataset.mode; S.swap = 1 - S.swap; renderTargetPanel(); updateScan(true);
      if (S.mode === "site") resolveSites();
      const first = $("input", pt); first && first.focus({ preventScroll: true });
    }
    if (d) { const b = cidrBounds(d.dataset.detected); if (b) { S.mode = "subnet"; S.oct = intToIp(b.net).split("."); S.prefix = Math.min(30, Math.max(16, b.prefix)); S.swap = 1 - S.swap; renderTargetPanel(); updateScan(true); shut($("#d-target")); } }
    const u = e.target.closest("[data-use-ip]");
    if (u) useIpTarget(u.dataset.ip, u.dataset.port ? +u.dataset.port : null);
  });
  pt.addEventListener("input", (e) => {
    const t = e.target, key = t.dataset.oct;
    if (key) {
      const v = t.value.replace(/\D/g, "").slice(0, 3);
      t.value = v; S[key][+t.dataset.i] = v; t.setAttribute("aria-invalid", String(v !== "" && +v > 255));
      if (v.length === 3 && +t.dataset.i < 3) focusOct(t, 1);
    } else if (t.id === "rs" || t.id === "re") { t.value = t.value.replace(/\D/g, "").slice(0, 3); S[t.id] = t.value; t.setAttribute("aria-invalid", String(t.value !== "" && +t.value > 255)); }
    else if (t.id === "site-in") { S.site = t.value; resolveSites(); }
    else if (t.id === "text-in") S.text = t.value;
    else return;
    updateScan();
  });
  pt.addEventListener("keydown", (e) => {
    const t = e.target;
    if (!t.dataset.oct) return;
    if (e.key === "." || e.key === " ") {
      // a field reached by auto-advance is fully selected: the typed dot just confirms it
      e.preventDefault();
      if (t.value && !(t.selectionStart === 0 && t.selectionEnd === t.value.length)) focusOct(t, 1);
    }
    else if (e.key === "Backspace" && !t.value) { e.preventDefault(); focusOct(t, -1); }
  });
  pt.addEventListener("paste", (e) => {
    const t = e.target;
    if (!t.dataset.oct) return;
    const text = (e.clipboardData.getData("text") || "").trim();
    const m = text.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2})|-(\d{1,3}(?:\.\d{1,3}){3}|\d{1,3}))?$/);
    if (!m) return;
    e.preventDefault();
    const parts = m[1].split(".");
    if (m[2]) { S.mode = "subnet"; S.oct = parts; S.prefix = Math.min(30, Math.max(16, +m[2])); }
    else if (m[3]) { S.mode = "range"; S.oct = parts; S.rs = parts[3]; S.re = m[3].split(".").pop(); }
    else S[t.dataset.oct] = parts;
    renderTargetPanel(); updateScan(true);
  });
  $("#p-ports").addEventListener("click", (e) => {
    const p = e.target.closest("[data-profile]");
    if (!p || p.dataset.profile === S.profile) return;
    S.profile = p.dataset.profile; renderPortsPanel(); updateScan();
    if (S.profile === "custom") $("#custom-in").focus(); else shut($("#d-ports"));
  });
  $("#p-ports").addEventListener("input", (e) => { if (e.target.id === "custom-in") { S.custom = e.target.value; updateScan(); } });
  $("#p-adv").addEventListener("input", (e) => {
    if (e.target.id === "speed") S.speed = +e.target.value;
    if (e.target.id === "delay") S.delay = +e.target.value;
    renderAdvValues(); updateScan();
  });
}
// A website-mode entry that is really an IP (optionally with a port), e.g.
// "http://10.255.254.68:18080" → {ip, port}. Lets us offer a one-click switch
// to single-machine mode instead of a dead-end "that's an IP" error.
function parseIpTarget(text) {
  const t = String(text).trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
  const m = t.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?$/);
  if (!m || ipToInt(m[1]) == null) return null;
  const port = m[2] ? +m[2] : null;
  if (port != null && (port < 1 || port > 65535)) return null;
  return { ip: m[1], port };
}
// Switch the scan form to "single machine" for this IP, and if a non-standard
// port was given, add it to a custom port set so the host is actually probed.
function useIpTarget(ip, port) {
  S.mode = "single"; S.single = ip.split(".");
  const web = cfg.web_ports || [];
  if (port && !web.includes(port)) { S.profile = "custom"; S.custom = [...web, port].join(", "); }
  S.swap = 1 - S.swap;
  renderTargetPanel(); renderPortsPanel(); updateScan(true);
  shut($("#d-target"));
}
function focusOct(input, dir) {
  const all = $$(`[data-oct="${input.dataset.oct}"]`);
  const next = all[+input.dataset.i + dir];
  if (next) { next.focus(); next.select(); }
}

function stageSvg() {
  return `<svg class="vis" viewBox="0 0 400 440" role="img" id="vis" aria-label="แผนภาพเป้าหมาย">
    <defs>
      <radialGradient id="mglow"><stop offset="0%" stop-color="#8B7CFF" stop-opacity=".35"/><stop offset="55%" stop-color="#4F7BFF" stop-opacity=".12"/><stop offset="100%" stop-color="#4F7BFF" stop-opacity="0"/></radialGradient>
      <linearGradient id="mgrad" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#2F5BEA"/><stop offset="1" stop-color="#6D4AFF"/></linearGradient>
    </defs>
    <ellipse class="halo" cx="200" cy="168" rx="160" ry="128" fill="url(#mglow)"/>
    <ellipse cx="200" cy="292" rx="122" ry="15" fill="#2F3B8C" opacity=".1" style="filter:blur(6px)"/>
    <g id="g-plate" style="transition:opacity .45s ease">
      <path id="p-lower" fill="none" stroke="#8A93D9" stroke-width="1.2"/>
      <path id="p-top" fill="rgba(243,245,255,.92)" stroke="url(#mgrad)" stroke-width="2" stroke-linejoin="round"/>
      <path id="p-light" fill="#C5CFEE"/><path id="p-dark" fill="url(#mgrad)"/>
    </g>
    <g id="g-globe" fill="none" style="transition:opacity .45s ease;opacity:0">
      <circle cx="200" cy="172" r="92" fill="rgba(243,245,255,.92)" stroke="url(#mgrad)" stroke-width="2.6"/>
      <ellipse cx="200" cy="172" rx="40" ry="92" stroke="#6D7BEA" stroke-width="1.4"/>
      <ellipse cx="200" cy="172" rx="92" ry="34" stroke="#6D7BEA" stroke-width="1.4"/>
      <ellipse cx="200" cy="172" rx="66" ry="92" stroke="#B4BDF2" stroke-width="1"/>
    </g>
    <path d="M39 300 C42 372 111 407 200 407 C289 407 358 372 361 300" fill="none" stroke="#E1E6F5" stroke-width="6" stroke-linecap="round"/>
    <path id="p-ring" d="M39 300 C42 372 111 407 200 407 C289 407 358 372 361 300" pathLength="100" fill="none" stroke="url(#mgrad)" stroke-width="6" stroke-linecap="round" style="transition:stroke-dasharray .65s cubic-bezier(.34,1.3,.64,1),opacity .4s"/>
    <g id="g-mark" class="mark"><circle r="13" fill="#fff" stroke="url(#mgrad)" stroke-width="3"/><circle r="4" fill="#4A4FF0"/></g>
  </svg>`;
}

const SEP = '<span aria-hidden="true" style="font-weight:700;color:#8A93B3">.</span>';
function renderTargetPanel() {
  const octInputs = (key, label) => `<div><span class="lbl" id="lbl-${key}">${label}</span>
    <div role="group" aria-labelledby="lbl-${key}" style="display:flex;align-items:center;gap:5px">
    ${S[key].map((v, i) => `${i ? SEP : ""}<input class="inp oct" inputmode="numeric" autocomplete="off" data-oct="${key}" data-i="${i}" value="${esc(v)}" aria-label="${label} ส่วนที่ ${i + 1}">`).join("")}
    </div></div>`;
  let input;
  if (S.mode === "subnet") input = octInputs("oct", "ที่อยู่เครือข่าย");
  else if (S.mode === "single") input = octInputs("single", "IP ของเครื่อง");
  else if (S.mode === "range") input = `<div><span class="lbl">ช่วง IP (ในวงเดียวกัน)</span><div style="display:flex;align-items:center;gap:5px;flex-wrap:wrap">
    ${S.oct.slice(0, 3).map((v, i) => `<input class="inp oct" inputmode="numeric" autocomplete="off" data-oct="oct" data-i="${i}" value="${esc(v)}" aria-label="ส่วนที่ ${i + 1}">`).join(SEP)}
    ${SEP}<input class="inp oct" id="rs" inputmode="numeric" autocomplete="off" value="${esc(S.rs)}" aria-label="เริ่มที่"><span style="font-size:13px;color:var(--muted)">ถึง</span><input class="inp oct" id="re" inputmode="numeric" autocomplete="off" value="${esc(S.re)}" aria-label="ถึง"></div></div>`;
  else if (S.mode === "site") input = `<label style="display:block"><span class="lbl">ลิงก์หรือโดเมนของหน่วยงาน ${tip("วางลิงก์ เช่น https://www.agency.go.th ระบบค้นหา IP จาก DNS ให้ และส่งชื่อเว็บไปด้วยเพื่อให้ได้ผลของเว็บนั้นจริง · ใส่ได้หลายเว็บคั่นด้วยเว้นวรรค")}</span>
    <input class="inp" id="site-in" value="${esc(S.site)}" placeholder="https://www.agency.go.th" autocomplete="off" spellcheck="false"></label><div id="site-preview" aria-live="polite" style="margin-top:8px"></div>`;
  else input = `<label style="display:block"><span class="lbl">ซับเน็ต ช่วง หรือ IP คั่นด้วยจุลภาค</span><input class="inp" id="text-in" value="${esc(S.text)}" placeholder="10.0.5.0/24, 10.0.6.10-50, 10.0.7.3" autocomplete="off" spellcheck="false"></label>`;
  const det = S.detected.length && S.mode !== "site" ? `<div style="margin-top:12px"><span class="lbl">ระบบหาให้แล้ว ${tip("วงเครือข่ายที่เครื่องนี้เชื่อมต่ออยู่ กดเพื่อใช้ได้ทันที")}</span>
    <div style="display:flex;flex-direction:column;gap:6px">${S.detected.map((d) => `<button type="button" class="opt" data-detected="${esc(d.cidr)}" ${d.ok ? "" : "disabled"} style="min-height:46px"><span style="flex:1;min-width:0"><span class="ot">${esc(d.cidr)}</span><span class="od">${esc(d.name)}</span></span><span class="badge ${d.ok ? "b-blue" : "b-grey"}">${d.ok ? `ใช้วงนี้ · ${num(d.hosts)}` : "นอกขอบเขต"}</span></button>`).join("")}</div></div>` : "";
  $("#p-target").innerHTML = `<div class="stag">
    <div class="ptitle">จะตรวจอะไร ${tip("เลือกว่าจะตรวจทั้งวง บางช่วง เครื่องเดียว หรือเว็บไซต์จากลิงก์ — ไม่แน่ใจ เลือก “ทั้งวง”")}</div>
    <div role="group" aria-label="ประเภทเป้าหมาย" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px">
      ${MODES.map(([k, t, d, i]) => `<button type="button" class="opt" data-mode="${k}" aria-pressed="${S.mode === k}"><span class="oi">${ic(i)}</span><span style="min-width:0"><span class="ot">${t}</span><span class="od">${d}</span></span></button>`).join("")}
    </div>
    <div style="margin-top:14px;padding-top:14px;border-top:1px solid #EDF0F8">${input}</div>
    ${det}</div>`;
  renderSitePreview();
}
function renderPortsPanel() {
  $("#p-ports").innerHTML = `<div class="stag">
    <div class="ptitle">ชุดพอร์ต ${tip("พอร์ตคือ “ช่องทาง” ที่บริการเปิดรับ ระบบลองเชื่อมต่อแบบปกติ (เหมือนโทรแล้ววาง) เพื่อดูว่าเปิดอะไรไว้ พอร์ตเว็บถูกตรวจเสมอ")}</div>
    ${profileOpts("data-profile", S.profile)}
    ${S.profile === "custom" ? `<label style="display:block;margin-top:10px"><span class="lbl">พอร์ตที่ต้องการ</span><input class="inp" id="custom-in" value="${esc(S.custom)}" autocomplete="off" spellcheck="false"></label>` : ""}
  </div>`;
}
function renderAdvPanel() {
  $("#p-adv").innerHTML = `<div class="stag">
    <label style="display:block"><span class="lbl" style="justify-content:space-between"><span style="display:flex;align-items:center;gap:6px">ความเร็ว ${tip("จำนวนการเชื่อมต่อพร้อมกัน ลดลงได้ถ้าเครือข่ายช้า หรือไม่อยากกระทบการใช้งาน")}</span><b style="color:var(--ink)" id="speed-v"></b></span>
      <input class="rng" id="speed" type="range" min="5" max="${cfg.max_concurrency}" step="5" value="${S.speed}" aria-label="ความเร็ว"></label>
    <label style="display:block;margin-top:10px"><span class="lbl" style="justify-content:space-between"><span style="display:flex;align-items:center;gap:6px">พักระหว่างเครื่อง ${tip("เว้นช่วงหลังตรวจแต่ละเครื่อง นุ่มนวลต่อเครือข่าย แต่ใช้เวลานานขึ้น")}</span><b style="color:var(--ink)" id="delay-v"></b></span>
      <input class="rng" id="delay" type="range" min="0" max="500" step="50" value="${S.delay}" aria-label="พักระหว่างเครื่อง"></label>
  </div>`;
  renderAdvValues();
}
function renderAdvValues() {
  $("#speed-v").textContent = `${S.speed} งาน`; $("#delay-v").textContent = `${S.delay} ms`;
  $("#speed").style.setProperty("--p", `${((S.speed - 5) / Math.max(1, cfg.max_concurrency - 5)) * 100}%`);
  $("#delay").style.setProperty("--p", `${(S.delay / 500) * 100}%`);
}
let resolveTimer;
function resolveSites() {
  clearTimeout(resolveTimer);
  const list = siteList(), key = list.join("\n");
  if (!key) { S.report = null; S.reportFor = ""; renderSitePreview(); return; }
  // a bare IP isn't a website — don't call /api/resolve, just show the switch
  if (list.length === 1 && parseIpTarget(list[0])) { S.report = null; S.reportFor = ""; renderSitePreview(); return; }
  if (key === S.reportFor) return;
  renderSitePreview();
  resolveTimer = setTimeout(async () => {
    let report;
    try { report = (await api(`/api/resolve?q=${encodeURIComponent(key)}`)).sites; }
    catch (e) { report = [{ input: key, host: key, ips: [], problems: [e.message], refused: false }]; }
    if (siteList().join("\n") !== key) return;
    S.report = report; S.reportFor = key;
    if ($("#vis")) { renderSitePreview(); updateScan(); }
  }, 450);
}
function renderSitePreview() {
  const box = $("#site-preview");
  if (!box) return;
  const list = siteList(), key = list.join("\n");
  if (!key) { box.innerHTML = `<p class="od">ตรวจได้เฉพาะโดเมนหน่วยงาน (${esc((cfg.gov_suffixes || []).join(", "))})</p>`; return; }
  // typed an IP (maybe with a port) into website mode? offer a one-click switch
  if (list.length === 1) {
    const t = parseIpTarget(list[0]);
    if (t) {
      box.innerHTML = `<div style="padding:10px 12px;border-radius:12px;background:var(--warn-bg)">
        <div style="font-size:13px;color:var(--warn);font-weight:600">นี่คือเลข IP ไม่ใช่โดเมนหน่วยงาน — โหมดเว็บไซต์ใช้กับลิงก์ .go.th ฯลฯ</div>
        <button type="button" class="btn btn-g" data-use-ip="${esc(t.ip)}" ${t.port ? `data-port="${t.port}"` : ""} style="margin-top:8px">
          ${ic("cube", 16)} ตรวจ ${esc(t.ip)} ในโหมดเครื่องเดียว${t.port ? ` · พอร์ต ${t.port}` : ""}</button></div>`;
      return;
    }
  }
  if (S.reportFor !== key || !S.report) { box.innerHTML = `<p class="od">กำลังค้นหา IP จาก DNS…</p>`; return; }
  box.innerHTML = S.report.map((r) => `<div style="display:flex;gap:8px;align-items:flex-start;padding:6px 0;font-size:13px">
    <span class="badge ${r.problems.length ? "b-bad" : "b-ok"}" style="padding:4px 7px">${ic(r.problems.length ? "x" : "check", 13, 3)}</span>
    <span style="min-width:0;overflow-wrap:anywhere">${r.problems.length ? esc(r.problems.join(" · ")) : `<b>${esc(r.host)}</b> → <span class="mono">${esc(r.ips.join(", "))}</span>`}</span></div>`).join("");
}

function updateScan(modeChanged) {
  if (!$("#vis")) return;
  const plan = scanPlan();
  // the 16×16 plate stands for one /24: highlighted dots are the addresses in scope
  const Pt = (i, j, lift) => [200 + (i - j) * 8.2, 104 + (i + j) * 4.1 + lift];
  const plate = (lift) => "M" + [Pt(-0.9, -0.9, lift), Pt(15.9, -0.9, lift), Pt(15.9, 15.9, lift), Pt(-0.9, 15.9, lift)].map((p) => p[0].toFixed(1) + " " + p[1].toFixed(1)).join("L") + "Z";
  const dot = (x, y, r) => `M${(x - r).toFixed(1)} ${y.toFixed(1)}a${r} ${r} 0 1 0 ${2 * r} 0a${r} ${r} 0 1 0 ${-2 * r} 0`;
  const p = S.prefix, size = 2 ** (32 - p);
  let hl;
  if (S.mode === "subnet") { const d = +S.oct[3] || 0, base = p >= 24 ? d - (d % size) : 0; hl = (n) => p < 24 || (n >= base && n < base + size); }
  else if (S.mode === "range") { const a = Math.min(255, +S.rs || 0), b = Math.min(255, +S.re || 0); hl = (n) => n >= a && n <= b; }
  else if (S.mode === "single") hl = (n) => n === +S.single[3];
  else { const k = Math.max(1, Math.round(Math.min(1, plan.count / 256) * 256)); hl = (n) => n < k; }
  let dark = "", light = "";
  for (let n = 0; n < 256; n += 1) { const [x, y] = Pt(Math.floor(n / 16), n % 16, 0); if (hl(n)) dark += dot(x, y, S.mode === "single" ? 3.4 : 1.8); else light += dot(x, y, 1.1); }
  let lower = "";
  if (S.mode === "subnet" && p < 24) for (let k = 1; k < Math.min(4, 2 ** (24 - p)); k += 1) lower += plate(k * 13);
  $("#p-top").setAttribute("d", plate(0)); $("#p-lower").setAttribute("d", lower || "M0 0");
  $("#p-dark").setAttribute("d", dark || "M0 0"); $("#p-light").setAttribute("d", light || "M0 0");
  const site = S.mode === "site", subnet = S.mode === "subnet";
  $("#g-plate").style.opacity = site ? 0 : 1; $("#g-globe").style.opacity = site ? 1 : 0;
  const th = Math.PI * (1 - (p - 16) / 14), mx = 200 + 160 * Math.cos(th), my = 362 + 45 * Math.sin(th);
  $("#g-mark").style.transform = `translate(${mx.toFixed(1)}px,${my.toFixed(1)}px)`; $("#g-mark").style.opacity = subnet ? 1 : 0;
  const ring = $("#p-ring"); ring.style.strokeDasharray = `${subnet ? Math.round(((p - 16) / 14) * 100) : 100} 100`; ring.style.opacity = subnet ? 1 : 0.25;
  $("#vis").setAttribute("aria-label", `${plan.label} ${plan.big} ${num(plan.count)} ที่อยู่`);
  const ri = $("#ringin"); ri.hidden = !subnet; ri.value = p;
  $("#bigger").hidden = !subnet; $("#smaller").hidden = !subnet; $("#v-hint").hidden = !subnet;
  $("#bigger").disabled = p <= 16; $("#smaller").disabled = p >= 30;
  if (modeChanged) $("#stage-wrap").className = `swap${S.swap}`;
  $("#v-label").textContent = plan.label; $("#v-big").textContent = plan.big;
  $("#v-sub").textContent = plan.sub ? (site ? plan.sub : `ที่อยู่ · ${plan.sub}`) : "ที่อยู่";
  tween($("#v-count"), plan.count, 600);
  // dock summaries
  const pc = portCount(S.profile, S.custom);
  $("#sum-target").textContent = plan.summary;
  $("#sum-ports").textContent = pc.error ? "รูปแบบพอร์ตไม่ถูกต้อง" : `${(PROFILE_TEXT[S.profile] || [S.profile])[0]} · ${num(pc.n)} พอร์ต`;
  $("#sum-adv").textContent = `${S.speed >= cfg.max_concurrency ? "เร็วสุด" : `${S.speed} งาน`} · ${S.delay ? `พัก ${S.delay} ms` : "ไม่พัก"}`;
  // readiness: the button is enabled only when the server would accept the request
  const budgetOk = !pc.error && plan.count * pc.n <= cfg.max_port_probes;
  const ok = plan.valid && plan.scoped && !plan.pending && !pc.error && budgetOk;
  const secs = Math.ceil(plan.count / Math.max(1, S.speed)) * 1.5 + Math.ceil((plan.count * 0.25 * Math.max(pc.n || 4, 4)) / (cfg.max_sockets || 256)) * 1.5 + 8 + (S.delay * plan.count) / 1000 / Math.max(1, S.speed);
  const time = secs < 60 ? "ไม่ถึง 1 นาที" : `ประมาณ ${num(Math.ceil(secs / 60))} นาที`;
  const reason = plan.reason || (pc.error ? pc.error : !budgetOk ? `งานใหญ่เกินไป (${num(plan.count)} ที่อยู่ × ${num(pc.n)} พอร์ต) — ลดขนาดวงหรือจำนวนพอร์ต` : "");
  $("#ready-ic").innerHTML = ic(ok ? "check" : plan.pending ? "clock" : "x", 17, 3);
  $("#ready-ic").style.background = ok ? "linear-gradient(135deg,#12A46B,#0B7045)" : plan.pending ? "var(--grad)" : "linear-gradient(135deg,#D9363E,#B4232B)";
  $("#ready-k").textContent = ok ? "พร้อมสแกน" : plan.pending ? "รอสักครู่" : "ยังเริ่มไม่ได้";
  $("#ready-v").textContent = ok ? `${num(plan.count)} ที่อยู่ · ${time}` : reason;
  const line = (good, text) => `<div style="display:flex;align-items:flex-start;gap:8px;padding:6px 0;font-size:13.5px"><span class="badge ${good ? "b-ok" : "b-bad"}" style="padding:4px 7px">${ic(good ? "check" : "x", 13, 3)}</span><span style="min-width:0;overflow-wrap:anywhere">${esc(text)}</span></div>`;
  $("#p-ready").innerHTML = `<div class="stag">
    ${line(plan.valid && !plan.pending, plan.valid ? (plan.pending ? "กำลังตรวจลิงก์…" : `เป้าหมาย: ${plan.summary}`) : plan.reason)}
    ${line(plan.scoped && !plan.pending, site ? (plan.scoped ? (cfg.enforce_scope ? "เป็นโดเมนหน่วยงาน" : "โหมดเปิด · สแกนได้ทุกเว็บไซต์") : plan.reason || "ไม่ใช่โดเมนหน่วยงาน") : (plan.scoped ? (cfg.enforce_scope ? "อยู่ในขอบเขตที่ผู้ดูแลอนุญาต" : "โหมดเปิด · สแกนได้ทุกเป้าหมาย") : plan.reason || "อยู่นอกขอบเขต"))}
    ${line(!pc.error && budgetOk, pc.error ? pc.error : budgetOk ? `ตรวจ ${num(pc.n)} พอร์ตต่อเครื่อง` : reason)}
    <div style="display:flex;align-items:center;gap:8px;padding:6px 0;font-size:13.5px"><span class="badge b-blue" style="padding:4px 7px">${ic("clock", 13, 2.6)}</span>ใช้เวลา${ok ? time : "—"} · อ่านอย่างเดียว ไม่ทำลายระบบ</div></div>`;
  $("#go").disabled = !ok;
}

/* ═══ view: scanning ═══════════════════════════════════════════════════ */
async function viewScanning([id], alive) {
  let s = await api(`/api/scans/${id}/summary`);
  if (!alive()) return;
  if (!["queued", "running"].includes(s.state)) { location.replace(`#/results/${id}`); return; }
  setTopSide(`<a class="ghost" href="#/history" title="สแกนต่อในเบื้องหลัง">ย่อไว้เบื้องหลัง</a><button type="button" class="ghost stop" id="cancel">หยุดสแกน</button>`);
  const STEPS = [
    ["ตรวจกลางทาง", "ทดสอบกับที่อยู่ที่ไม่มีจริงก่อน ถ้ามี proxy หรือ firewall ตอบแทนทุกที่อยู่ ระบบจะตัดผลปลอมเหล่านั้นออก"],
    ["หาเครื่องออนไลน์", "ลองเชื่อมต่อทุกที่อยู่ ตามชุดพอร์ตที่เลือก เพื่อดูว่าเครื่องไหนเปิดอยู่"],
    ["ตรวจพอร์ต เว็บ และ PHP", "ดูว่าเครื่องที่ออนไลน์เปิดบริการอะไร แล้วอ่านเวอร์ชัน PHP จากเว็บเพื่อเทียบกับรุ่นที่แพตช์"],
  ];
  render(`<div class="app thin" style="text-align:center">
    <div class="in1">
      <span class="badge b-blue" style="font-size:13px;padding:6px 12px"><span class="live"></span>${s.demo_scenario ? "ตัวอย่าง · ข้อมูลจำลอง" : "กำลังทำงาน"}</span>
      <h1 class="h1" style="margin-top:10px;font-size:clamp(24px,3vw,34px);overflow-wrap:anywhere">กำลังสแกน <span class="num">${esc(s.target_label || "")}</span></h1>
    </div>
    <section class="card in2" aria-label="ความคืบหน้า" style="margin-top:18px;padding:16px 24px 24px">
      <svg viewBox="0 0 400 440" role="img" aria-label="ความคืบหน้าการสแกน" style="display:block;width:100%;max-width:400px;height:auto;margin:0 auto;overflow:visible">
        <defs><radialGradient id="sglow"><stop offset="0%" stop-color="#8B7CFF" stop-opacity=".35"/><stop offset="55%" stop-color="#4F7BFF" stop-opacity=".12"/><stop offset="100%" stop-color="#4F7BFF" stop-opacity="0"/></radialGradient>
        <linearGradient id="sgrad" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#2F5BEA"/><stop offset="1" stop-color="#6D4AFF"/></linearGradient></defs>
        <ellipse class="halo" cx="200" cy="168" rx="160" ry="128" fill="url(#sglow)"/>
        <path id="sc-plate" fill="rgba(243,245,255,.92)" stroke="url(#sgrad)" stroke-width="2" stroke-linejoin="round"/>
        <path id="sc-todo" fill="#D5DDF3"/><path id="sc-done" fill="url(#sgrad)"/>
        <circle id="sc-head" r="7" fill="none" stroke="#6D4AFF" stroke-width="1.6"/>
        <path d="M39 300 C42 372 111 407 200 407 C289 407 358 372 361 300" fill="none" stroke="#E1E6F5" stroke-width="8" stroke-linecap="round"/>
        <path id="sc-ring" d="M39 300 C42 372 111 407 200 407 C289 407 358 372 361 300" pathLength="100" fill="none" stroke="url(#sgrad)" stroke-width="8" stroke-linecap="round" style="stroke-dasharray:0 100;transition:stroke-dasharray .5s ease"/>
      </svg>
      <div class="gtext num" id="sc-pct" style="margin-top:-20px;font-size:46px;font-weight:700;line-height:1.1">0%</div>
      <div class="sec" style="margin-top:6px">
      <div id="sc-phase" aria-live="polite" style="font-size:15px;font-weight:600;display:flex;align-items:center;justify-content:center;gap:8px"></div>
      ${dock("d-steps", `<button type="button" class="seg" aria-label="ดูขั้นตอนการสแกน">${STEPS.map((_, i) => `<i><b id="seg${i}"></b></i>`).join("")}</button>`, `<ol class="stag" id="steps-list" style="list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:6px;text-align:left"></ol>`, { w: 460, align: "mid" })}</div>
      <div style="display:flex;flex-wrap:wrap;justify-content:center;gap:8px;margin-top:14px">
        <span class="chip">ตรวจแล้ว <b id="c-probed">0</b>/<span id="c-total">0</span></span>
        <span class="chip">ออนไลน์ <b id="c-online" style="color:var(--blue-ink)">0</b></span>
        <span class="chip">ควรแก้ไข <b id="c-risks" style="color:var(--crit)">0</b></span>
      </div>
      <div id="sc-note"></div>
    </section>
    <p class="in3 muted" style="margin-top:14px;font-size:13px">ปิดหน้านี้ได้ ระบบสแกนต่อเบื้องหลังและเก็บผลไว้ที่หน้าประวัติ</p>
  </div>`);
  const Pt = (i, j) => [200 + (i - j) * 8.2, 104 + (i + j) * 4.1];
  $("#sc-plate").setAttribute("d", "M" + [Pt(-0.9, -0.9), Pt(15.9, -0.9), Pt(15.9, 15.9), Pt(-0.9, 15.9)].map((q) => q[0].toFixed(1) + " " + q[1].toFixed(1)).join("L") + "Z");
  const dot = (x, y, r) => `M${(x - r).toFixed(1)} ${y.toFixed(1)}a${r} ${r} 0 1 0 ${2 * r} 0a${r} ${r} 0 1 0 ${-2 * r} 0`;
  $("#cancel").addEventListener("click", async (e) => {
    const b = e.currentTarget; b.disabled = true;
    try { await api(`/api/scans/${id}/cancel`, { method: "POST" }); stopping = true; $("#sc-phase").textContent = "กำลังหยุด…"; lastPhase = "กำลังหยุด…"; }
    catch (err) { toast(err.message); b.disabled = false; }
  });
  // the plate shows the probed fraction only; mid-scan the API does not say which addresses answered
  let lastSteps = "", lastPhase = "", stopping = false;
  const paint = (s) => {
    const p = s.progress, total = Math.max(1, p.total_ips), inspect = p.phase === "inspect";
    const frac1 = Math.min(1, p.probed / total), frac2 = inspect ? (p.to_inspect ? p.inspected / p.to_inspect : 1) : 0;
    const pct = inspect ? 55 + Math.round(frac2 * 43) : Math.round(frac1 * 55);
    const stage = !p.phase ? 0 : inspect ? 2 : 1;
    const fills = [p.phase ? 1 : 0.5, inspect ? 1 : frac1, frac2];
    $$("[id^=seg]").forEach((b, i) => b.style.setProperty("--f", `${Math.round(fills[i] * 100)}%`));
    const steps = STEPS.map(([t, h], i) => {
      const st = i < stage ? "done" : i === stage ? "on" : "wait";
      return `<li style="display:grid;grid-template-columns:30px 1fr auto;gap:10px;align-items:center;padding:8px 10px;border-radius:12px;background:${st === "on" ? "var(--soft)" : "transparent"}">
        <span style="width:28px;height:28px;border-radius:50%;display:grid;place-items:center;font-size:13px;font-weight:700;color:${st === "wait" ? "var(--muted)" : "#fff"};background:${st === "wait" ? "#F0F2F8" : "var(--grad)"}">${st === "done" ? "✓" : i + 1}</span>
        <span style="min-width:0"><span class="ot">${t}</span><span class="od">${h}</span></span><span class="badge ${st === "done" ? "b-ok" : st === "on" ? "b-blue" : "b-grey"}">${st === "done" ? "เสร็จ" : st === "on" ? "กำลังทำ" : "รอคิว"}</span></li>`;
    }).join("");
    // rewrite only on change, or the open panel would replay its entrance every poll
    if (steps !== lastSteps) { $("#steps-list").innerHTML = steps; lastSteps = steps; }
    const shown = Math.round(frac1 * 256);
    let todo = "", done = "";
    for (let n = 0; n < 256; n += 1) { const [x, y] = Pt(Math.floor(n / 16), n % 16); if (n < shown) done += dot(x, y, 1.7); else todo += dot(x, y, 1.1); }
    $("#sc-todo").setAttribute("d", todo || "M0 0"); $("#sc-done").setAttribute("d", done || "M0 0");
    const h = Math.min(255, shown), [hx, hy] = Pt(Math.floor(h / 16), h % 16);
    $("#sc-head").setAttribute("cx", hx.toFixed(1)); $("#sc-head").setAttribute("cy", hy.toFixed(1));
    $("#sc-head").style.opacity = frac1 >= 1 ? 0 : 1;
    $("#sc-ring").style.strokeDasharray = `${pct} 100`;
    $("#sc-pct").textContent = `${pct}%`;
    const phase = stopping ? "กำลังหยุด…" : `${inspect ? `ขั้นที่ 3 จาก 3 · ${STEPS[2][0]} (${num(p.inspected)}/${num(p.to_inspect)} เครื่อง)` : `ขั้นที่ ${stage + 1} จาก 3 · ${STEPS[stage][0]}`} ${tip("ชี้ที่แถบความคืบหน้าเพื่อดูว่าแต่ละขั้นทำอะไร")}`;
    if (phase !== lastPhase) { $("#sc-phase").innerHTML = phase; lastPhase = phase; }
    $("#c-probed").textContent = num(p.probed); $("#c-total").textContent = num(p.total_ips);
    $("#c-online").textContent = num(p.online); $("#c-risks").textContent = num(p.risks);
    if ((s.intercepted_ports || []).length && !$("#sc-note").innerHTML) $("#sc-note").innerHTML = `<p class="notice b-blue" style="margin-top:14px;text-align:left">${ic("shield", 20)}<span>พบอุปกรณ์กลางทางตอบแทนทุกที่อยู่บนพอร์ต <span class="mono">${esc(s.intercepted_ports.join(", "))}</span> — ระบบจะตัดเครื่องที่ไม่มีอยู่จริงออกให้</span></p>`;
  };
  paint(s);
  let stop = false;
  onCleanup(() => { stop = true; });
  while (!stop) {
    await new Promise((r) => setTimeout(r, 700));
    if (stop || !alive()) return;
    try { s = await api(`/api/scans/${id}/summary`); } catch { continue; }
    if (stop || !alive()) return;
    if (!["queued", "running"].includes(s.state)) {
      $("#sc-pct").textContent = "100%"; $("#sc-ring").style.strokeDasharray = "100 100";
      setTimeout(() => { if (alive()) location.replace(`#/results/${id}`); }, 650);
      return;
    }
    paint(s);
  }
}

/* ═══ view: results ════════════════════════════════════════════════════ */
const R = { job: null, f: "all", q: "", sel: null, tab: "todo", swap: 0, tswap: 0 };
const FILTERS = [["all", "ทุกเครื่อง", "#8A93C2"], ["urgent", "ต้องแก้ด่วน", "var(--crit-dot)"], ["fix", "ควรแก้ไข", "var(--warn-dot)"], ["ok", "ผ่าน", "var(--ok-dot)"], ["php", "เว็บ PHP", "#6D4AFF"], ["node", "เว็บ Node.js", "#0B7045"], ["caution", "มีพอร์ตที่ควรระวัง", "#F2C063"]];
const services = (d) => (d.services && d.services.length ? d.services : d.open_ports.map((p) => ({ port: p, name: "HTTP", description: "เว็บ", note: null })));
const runtimeOf = (d) => d.runtime || (d.php_version ? `PHP ${d.php_version}` : (d.server || null));
const isNode = (d) => /node/i.test(d.runtime || "");
const isPHP = (d) => !!d.php_version || /php/i.test(d.runtime || "");
const hasFilter = (d, k) => k === "all" || (k === "urgent" && d.severity === "critical") || (k === "fix" && (d.severity === "high" || d.severity === "low")) || (k === "ok" && d.severity === "safe") || (k === "php" && isPHP(d)) || (k === "node" && isNode(d)) || (k === "caution" && services(d).some((x) => x.note));
function filteredDevices() {
  const q = R.q.trim().toLowerCase();
  return R.job.devices.filter((d) => hasFilter(d, R.f) && (!q || [d.ip, d.hostname, d.mac, d.php_version, d.runtime, d.server, d.cms, d.device_type, devType(d.device_type),
    ...services(d).flatMap((x) => [String(x.port), x.name]), ...d.findings.flatMap((f) => [f.title, ...f.cve])].join(" ").toLowerCase().includes(q)));
}
function todoFor(d) {
  const recs = [...new Set([...d.findings].sort((a, b) => SEV[a.severity].rank - SEV[b.severity].rank).map((f) => f.recommendation).filter(Boolean))];
  services(d).filter((x) => x.note).forEach((x) => recs.push(`พอร์ต ${x.port} (${x.name}): ${x.note}`));
  if (recs.length) recs.push(R.job && R.job.demo_scenario ? "แก้เสร็จแล้ว สั่งสแกนซ้ำเพื่อยืนยันผล" : "แก้เสร็จแล้ว กด “ตรวจซ้ำเครื่องนี้” เพื่อยืนยันผล");
  else recs.push(d.php_version || d.open_ports.length ? "ไม่ต้องทำอะไรเพิ่ม — ตั้งเวลาให้สแกนซ้ำเป็นระยะ" : "เครื่องนี้ไม่มีบริการเว็บ จึงไม่ได้รับผลกระทบจาก PHP2Shell");
  return recs;
}

async function viewResults([id], alive) {
  const job = await api(`/api/scans/${id}`);
  if (!alive()) return;
  if (["queued", "running"].includes(job.state)) { location.replace(`#/scan/${id}`); return; }
  if (!R.job || R.job.id !== job.id) Object.assign(R, { f: "all", q: "", sel: null, tab: "todo" });
  R.job = job;
  renderResults();
}
const portsChecked = (j) => ((j.scanned_ports || []).length ? `ตรวจ ${num(j.scanned_ports.length)} พอร์ต · ` : "");
function counts(j) { const c = { critical: 0, high: 0, low: 0, safe: 0 }; j.devices.forEach((d) => c[d.severity]++); return c; }
function renderResults() {
  const j = R.job, c = counts(j), risks = c.critical + c.high + c.low, demo = !!j.demo_scenario;
  const scoreColor = j.security_score >= 80 ? "var(--ok-dot)" : j.security_score >= 65 ? "var(--warn-dot)" : "var(--crit-dot)";
  const headline = !j.devices.length ? "ไม่พบเครื่องที่ออนไลน์ในช่วงนี้" : risks ? `พบ <span style="color:var(--crit)">${num(risks)} เครื่อง</span>ที่ควรแก้ไข` : `<span style="color:var(--ok)">ไม่พบ</span>เครื่องที่เสี่ยง PHP2Shell`;
  render(`<div class="app">
  <div class="page-head in1">
    <div class="sec" style="min-width:0">
      <p style="display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px;font-size:13px;color:var(--muted)">
        ${demo ? '<span class="badge b-blue">ตัวอย่าง · ข้อมูลจำลอง</span>' : ""}<span class="num" style="overflow-wrap:anywhere">${esc(j.target_label)}</span><span>· ${esc(fmtDate(j.created_at))}</span>
        ${tip(`${demo ? "ผลจากข้อมูลจำลอง ไม่ได้ส่งสัญญาณไปที่เครือข่ายใด · " : ""}${portsChecked(j)}ใช้เวลา ${fmtDuration(j.duration_s)}`)}</p>
      <h1 class="h1" style="margin-top:8px">${headline}</h1>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      ${demo ? `<a class="btn" href="#/">สแกนเครือข่ายจริง</a>` : `<button type="button" class="btn" id="rescan">${ic("refresh", 17)}สแกนอีกครั้ง</button>`}
      ${dock("d-export", `<button type="button" class="btn btn-g">${ic("download", 17)}ส่งออก${chev.replace('class="chev"', 'class="chev" style="color:#fff;margin-left:0"')}</button>`, `<div class="stag" role="menu">
        <a class="mi" role="menuitem" href="/api/scans/${esc(j.id)}/export.csv"><span><span style="display:block">CSV ทั้งชุด</span><span class="od">เปิดใน Excel ได้ · ทุกเครื่อง ทุกคอลัมน์</span></span></a>
        ${j.devices.length ? `<button type="button" class="mi" role="menuitem" id="csv-view"><span><span style="display:block">CSV เฉพาะที่แสดงอยู่</span><span class="od" id="csv-n"></span></span></button>` : ""}
        <a class="mi" role="menuitem" href="#/report/${esc(j.id)}"><span><span style="display:block">รายงานผู้บริหาร</span><span class="od">พิมพ์หรือบันทึก PDF</span></span></a>
        <a class="mi" role="menuitem" href="/api/scans/${esc(j.id)}/export.json"><span><span style="display:block">JSON</span><span class="od">เชื่อมกับระบบอื่น</span></span></a></div>`, { w: 280, align: "end" })}
    </div>
  </div>
  ${j.state === "cancelled" ? `<p class="notice b-warn in1" style="margin-top:14px">${ic("warn", 20)}<span>การสแกนนี้ถูกหยุดก่อนเสร็จ ผลอาจไม่ครบทุกเครื่อง</span></p>` : ""}
  ${j.state === "failed" ? `<p class="notice b-bad in1" style="margin-top:14px">${ic("alert", 20)}<span>การสแกนผิดพลาด: ${esc(j.error || "ไม่ทราบสาเหตุ")}</span></p>` : ""}
  ${(j.intercepted_ports || []).length ? `<p class="notice b-blue in1" style="margin-top:14px">${ic("shield", 20)}<span>พบอุปกรณ์กลางทาง (เช่น proxy หรือ firewall) ตอบแทนทุกที่อยู่บนพอร์ต <span class="mono">${esc(j.intercepted_ports.join(", "))}</span> — ระบบตัดเครื่องที่ไม่มีอยู่จริงออกให้แล้ว</span></p>` : ""}
  <dl class="card stats in2" style="margin-top:16px;margin-bottom:0">
    <div class="stat sec"><dt class="muted">ออนไลน์ ${tip("เครื่องที่ตอบรับการเชื่อมต่อ และยืนยันได้ว่ามีอยู่จริง")}</dt><dd style="color:var(--blue-ink)"><span class="cnt" data-to="${j.devices.length}">0</span><small> / ${num(j.progress.total_ips)}</small></dd></div>
    <div class="stat sec"><dt style="color:var(--crit)">ต้องแก้ด่วน ${tip("ใช้ PHP รุ่นที่มีช่องโหว่ PHP2Shell ผู้ไม่หวังดีอาจสั่งงานเครื่องได้ ควรอัปเดตก่อน")}</dt><dd style="color:var(--crit)"><span class="cnt" data-to="${c.critical}">0</span></dd></div>
    <div class="stat sec"><dt style="color:var(--warn)">ควรแก้ไข ${tip("ความเสี่ยงรองลงมา เช่น PHP สาขาหมดอายุ ซ่อนเวอร์ชัน หรือยังไม่เปิด HSTS")}</dt><dd style="color:var(--warn)"><span class="cnt" data-to="${c.high + c.low}">0</span></dd></div>
    <div class="stat sec" style="display:flex;align-items:center;justify-content:space-between;gap:8px"><div><dt class="muted">คะแนน ${tip("คำนวณโดย thscan: เริ่ม 100 หักเครื่องละ ด่วน 22 · สูง 14 · ต่ำ 4 ใช้ติดตามความคืบหน้า ไม่ใช่คะแนนรับรองจาก ThaiCERT")}</dt><dd><span class="cnt" data-to="${j.security_score}">0</span><small> · เกรด ${esc(j.security_grade)}</small></dd></div>
      <svg viewBox="0 0 56 56" width="48" height="48" aria-hidden="true" style="flex:none;transform:rotate(-90deg)"><circle cx="28" cy="28" r="22" fill="none" stroke="#E1E6F5" stroke-width="7"/><circle id="gauge" cx="28" cy="28" r="22" pathLength="100" fill="none" stroke="${scoreColor}" stroke-width="7" stroke-linecap="round" style="stroke-dasharray:0 100;transition:stroke-dasharray 1.1s cubic-bezier(.2,.8,.2,1)"/></svg></div>
  </dl>
  ${j.devices.length ? `<div class="split" style="margin-top:16px">
    <section class="card listcard in3" aria-label="รายการเครื่อง">
      <div style="display:flex;gap:8px">
        <div style="flex:1;min-width:0">${dock("d-filter", `<button type="button" class="peek flat" id="filter-peek"></button>`, `<div class="stag" role="group" aria-label="ตัวกรอง" id="filter-list"></div>`, { w: 290 })}</div>
        <label class="search" id="search">${ic("search", 19, 2.2)}<span class="sr">ค้นหา IP ชื่อเครื่อง PHP หรือพอร์ต</span><input type="search" id="q" placeholder="ค้นหา…" value="${esc(R.q)}"></label>
      </div>
      <div class="rows" role="listbox" aria-label="เครื่องที่พบ" id="rows"></div>
    </section>
    <section class="card hostcard in4" aria-label="เครื่องที่เลือก" id="host"></section>
  </div>` : `<div class="card in3" style="margin-top:16px;padding:32px;text-align:center"><h2 style="font-size:20px">ไม่มีเครื่องที่ตอบสนองในช่วงนี้</h2>
    <p class="lead">เครื่องอาจปิดอยู่ ไฟร์วอลล์บล็อกการเชื่อมต่อ หรือช่วง IP ไม่ตรงกับเครือข่ายจริง ลองเลือกชุดพอร์ตที่กว้างขึ้น หรือเลือกวงอื่น</p>
    <p style="margin-top:16px"><a class="btn" href="#/">เลือกเป้าหมายใหม่</a></p></div>`}
  </div>`);
  $$(".cnt").forEach((el) => tween(el, +el.dataset.to, 1100));
  requestAnimationFrame(() => requestAnimationFrame(() => { const g = $("#gauge"); if (g) g.style.strokeDasharray = `${j.security_score} 100`; }));
  const rescan = $("#rescan");
  rescan && rescan.addEventListener("click", async () => {
    rescan.disabled = true;
    const r = j.request || {};
    const base = { port_profile: r.port_profile, custom_ports: r.custom_ports };
    try { await startScan(r.sites && r.sites.length ? { ...base, sites: r.sites } : { ...base, targets: r.targets }); }
    catch (err) { toast(err.message); rescan.disabled = false; }
  });
  if (!j.devices.length) return;
  $("#csv-view").addEventListener("click", () => { shut($("#d-export")); downloadCsv(filteredDevices(), `thscan-${j.id}-filtered.csv`); });
  $("#filter-list").addEventListener("click", (e) => { const b = e.target.closest("[data-f]"); if (b) { R.f = b.dataset.f; shut($("#d-filter")); paintList(true); } });
  $("#q").addEventListener("input", (e) => { R.q = e.target.value; paintList(true); });
  $("#rows").addEventListener("click", (e) => { const r = e.target.closest("[data-ip]"); if (r) selectHost(r.dataset.ip); });
  $("#rows").addEventListener("keydown", (e) => {
    if (!["ArrowDown", "ArrowUp"].includes(e.key)) return;
    e.preventDefault();
    const rows = $$("[data-ip]", $("#rows")), i = rows.findIndex((r) => r.dataset.ip === R.sel);
    const n = rows[Math.max(0, Math.min(rows.length - 1, i + (e.key === "ArrowDown" ? 1 : -1)))];
    if (n) { selectHost(n.dataset.ip); n.focus(); }
  });
  // tabs switch on hover as well as click/focus
  const pickTab = (e) => { const t = e.target.closest("[data-tab]"); if (t && t.dataset.tab !== R.tab) { R.tab = t.dataset.tab; R.tswap = 1 - R.tswap; paintTabs(); } };
  const hostEl = $("#host");
  hostEl.addEventListener("mouseover", pickTab); hostEl.addEventListener("click", pickTab); hostEl.addEventListener("focusin", pickTab);
  paintList(true);
}
function paintList(fromFilter) {
  const j = R.job, list = filteredDevices();
  const fc = FILTERS.find((f) => f[0] === R.f);
  $("#filter-peek").innerHTML = `<span class="dot" style="background:${fc[2]}"></span><span style="min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${fc[1]} (${num(list.length)})</span>${chev}`;
  $("#filter-list").innerHTML = FILTERS.map(([k, label, color]) => `<button type="button" class="mi" data-f="${k}" aria-pressed="${R.f === k}"><span class="dot" style="background:${color}"></span>${label}<span class="n">${num(j.devices.filter((d) => hasFilter(d, k)).length)}</span></button>`).join("");
  $("#search").classList.toggle("filled", !!R.q);
  const n = $("#csv-n"); if (n) n.textContent = `${num(list.length)} เครื่อง ตามตัวกรองตอนนี้`;
  if (fromFilter && !list.some((d) => d.ip === R.sel)) R.sel = list[0] ? list[0].ip : null;
  if (!R.sel && list[0]) R.sel = list[0].ip;
  $("#rows").innerHTML = list.length ? list.map((d) => `<button type="button" class="row" role="option" data-ip="${esc(d.ip)}" aria-selected="${d.ip === R.sel}">
      <span style="min-width:0;flex:1"><span class="ip">${esc(d.ip)}</span><span class="sub">${esc(d.hostname || devType(d.device_type))}</span></span>
      <span class="more">${esc(runtimeOf(d) || devType(d.device_type))}</span>${sevBadge(d.severity)}</button>`).join("")
    : `<p style="margin:12px 6px;font-size:14px;color:var(--muted)">ไม่มีเครื่องที่ตรงกับเงื่อนไข · <button type="button" class="ghost" id="reset" style="min-height:44px;padding:0 4px">ล้างตัวกรอง</button></p>`;
  const reset = $("#reset");
  reset && reset.addEventListener("click", () => { R.f = "all"; R.q = ""; $("#q").value = ""; paintList(true); });
  paintHost();
}
function selectHost(ip) {
  if (ip === R.sel) return;
  R.sel = ip; R.swap = 1 - R.swap;
  $$("[data-ip]", $("#rows")).forEach((r) => r.setAttribute("aria-selected", String(r.dataset.ip === ip)));
  paintHost();
  if (innerWidth < 900) $("#host").scrollIntoView({ behavior: reduceMotion() ? "auto" : "smooth", block: "start" });
}
function cubeSvg(d) {
  const pitch = 35 * Math.PI / 180, yaw = 35 * Math.PI / 180, c = [];
  for (let i = 0; i < 8; i += 1) {
    const x = (i & 1) ? 1 : -1, y = (i & 2) ? 1 : -1, z = (i & 4) ? 1 : -1;
    const rx = x * Math.cos(yaw) - z * Math.sin(yaw), rz = x * Math.sin(yaw) + z * Math.cos(yaw);
    const ry = y * Math.cos(pitch) - rz * Math.sin(pitch), depth = y * Math.sin(pitch) + rz * Math.cos(pitch);
    c.push({ x: 200 + rx * 82, y: 170 - ry * 82, depth });
  }
  let vis = "", hid = "";
  for (let a = 0; a < 8; a += 1) for (let b = a + 1; b < 8; b += 1) {
    const k = a ^ b;
    if (k === 1 || k === 2 || k === 4) {
      const seg = `M${c[a].x.toFixed(1)} ${c[a].y.toFixed(1)}L${c[b].x.toFixed(1)} ${c[b].y.toFixed(1)}`;
      if ((c[a].depth + c[b].depth) / 2 < -0.1) hid += seg; else vis += seg;
    }
  }
  const n = Math.min(6, services(d).length);
  let slots = "";
  for (let k = 0; k < n; k += 1) {
    const t = (k + 1) / (n + 1);
    const ax = c[0].x + (c[2].x - c[0].x) * t, ay = c[0].y + (c[2].y - c[0].y) * t, bx = c[1].x + (c[3].x - c[1].x) * t, by = c[1].y + (c[3].y - c[1].y) * t;
    slots += `M${(ax + (bx - ax) * 0.18).toFixed(1)} ${(ay + (by - ay) * 0.18).toFixed(1)}L${(ax + (bx - ax) * 0.55).toFixed(1)} ${(ay + (by - ay) * 0.55).toFixed(1)}`;
  }
  return `<svg viewBox="76 46 248 256" role="img" aria-label="เครื่อง ${esc(d.ip)} เปิด ${services(d).length} พอร์ต" style="flex:none;width:104px;height:auto">
    <defs><linearGradient id="hgrad" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#2F5BEA"/><stop offset="1" stop-color="#6D4AFF"/></linearGradient></defs>
    <ellipse cx="200" cy="268" rx="90" ry="12" fill="#2F3B8C" opacity=".12" style="filter:blur(5px)"/>
    <path d="${hid || "M0 0"}" fill="none" stroke="#B4BDF2" stroke-width="1.5"/>
    <path d="${vis}" fill="none" stroke="url(#hgrad)" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
    <path d="${slots || "M0 0"}" fill="none" stroke="${SEV[d.severity].dot}" stroke-width="3" stroke-linecap="round"/></svg>`;
}
function paintHost() {
  const host = $("#host"), d = R.job.devices.find((x) => x.ip === R.sel);
  if (!d) { host.innerHTML = `<div style="padding:40px 10px;text-align:center"><h2 style="font-size:18px">เลือกเครื่องจากรายการ</h2><p class="lead">รายละเอียด สิ่งที่ควรทำ และพอร์ตที่เปิดจะแสดงที่นี่</p></div>`; return; }
  const s = SEV[d.severity], demo = !!R.job.demo_scenario, todo = todoFor(d), svc = services(d);
  const TABS = [["todo", "สิ่งที่ควรทำ", todo.length], ["find", "ที่ตรวจพบ", d.findings.length], ["ports", "พอร์ต", svc.length], ["info", "ข้อมูลเครื่อง", "·"]];
  host.innerHTML = `<div class="swap${R.swap}">
    <div style="display:flex;flex-wrap:wrap;gap:16px;align-items:center">${cubeSvg(d)}
      <div style="flex:1;min-width:200px">${sevBadge(d.severity)}
        <div class="big" style="margin-top:6px">${esc(d.ip)}</div>
        <div class="muted" style="font-size:14px;overflow-wrap:anywhere">${esc(d.hostname || "ไม่มีชื่อโฮสต์")} · ${esc(runtimeOf(d) || devType(d.device_type))}</div></div></div>
    <div style="display:flex;gap:12px;align-items:flex-start;margin-top:14px;padding:12px 14px;border-radius:16px;background:${s.bg};color:${s.fg}">
      <span style="flex:none;width:26px;height:26px;border-radius:50%;display:grid;place-items:center;font-size:12px;font-weight:700;color:#fff;background:var(--grad)">1</span>
      <div style="min-width:0"><div style="font-size:12px;font-weight:700">${esc(s.title)} · ขั้นต่อไป</div><div style="font-size:14.5px;font-weight:600;line-height:1.55">${esc(todo[0])}</div></div></div>
  </div>
  <div class="tabs" role="tablist" aria-label="รายละเอียดเครื่อง" style="--n:4;margin-top:16px">
    ${TABS.map(([id, label, n]) => `<button type="button" class="tab" role="tab" data-tab="${id}" aria-selected="${R.tab === id}">${label}<span class="c">${n}</span></button>`).join("")}
    <span class="tabbar" aria-hidden="true" id="tabbar"></span></div>
  <div class="tabpanel" role="tabpanel" id="tabpanel"></div>
  <div style="display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-top:14px;padding-top:14px;border-top:1px solid #EDF0F8">
    <button type="button" class="btn" id="recheck">${ic("refresh", 17)}<span>${demo ? "จำลองการแก้ไข (ตัวอย่าง)" : "ตรวจซ้ำเครื่องนี้"}</span></button>
    <button type="button" class="btn" id="copy">${ic("copy", 17)}<span>คัดลอกสรุป</span></button>
    <span class="muted" style="font-size:12.5px">${d.checked_at ? `ตรวจซ้ำล่าสุด ${esc(fmtDate(d.checked_at))}` : d.patched_at ? `จำลองการแก้ไขเมื่อ ${esc(fmtDate(d.patched_at))} (ตัวอย่าง)` : demo ? "" : "“ตรวจซ้ำ” จะสแกนเครื่องนี้ใหม่จริงอีกครั้ง"}</span>
  </div>`;
  paintTabs();
  $("#copy").addEventListener("click", async () => {
    const lines = [`${d.ip}${d.hostname ? ` (${d.hostname})` : ""}`, `ผล: ${s.word} — ${d.assessment}`,
      `PHP: ${d.php_version || "ไม่พบ"} · พอร์ตที่เปิด: ${svc.map((x) => `${x.port}/${x.name}`).join(", ") || "—"}`,
      ...d.findings.map((f) => `- ${f.title}${f.cve.length ? ` [${f.cve.join(", ")}]` : ""}`), "สิ่งที่ควรทำ:", ...todo.map((t, i) => `${i + 1}. ${t}`)];
    if (demo) lines.unshift("[ตัวอย่าง · ข้อมูลจำลอง]");
    toast((await copyText(lines.join("\n"))) ? "คัดลอกสรุปแล้ว" : "คัดลอกไม่สำเร็จ");
  });
  $("#recheck").addEventListener("click", async (e) => {
    const b = e.currentTarget, label = $("span", b), was = label.textContent;
    b.disabled = true; label.textContent = demo ? "กำลังจำลอง…" : "กำลังตรวจซ้ำ…";
    try {
      const res = await api(`/api/scans/${R.job.id}/devices/${encodeURIComponent(d.ip)}/recheck`, { method: "POST" });
      R.job = res.job;
      const after = res.device.severity;
      if (res.simulated) toast("จำลองการแก้ไขแล้ว — นี่คือข้อมูลตัวอย่าง ไม่ใช่ผลจริง");
      else if (!res.online) toast("เครื่องนี้ไม่ตอบสนองในตอนนี้ — ยังคงแสดงผลเดิมไว้");
      else toast(after === res.severity_before ? `ตรวจซ้ำแล้ว: ผลยังเป็น “${SEV[after].word}”` : `ตรวจซ้ำแล้ว: ${SEV[res.severity_before].word} → ${SEV[after].word}`);
      R.sel = d.ip; renderResults();
    } catch (err) { toast(err.message); b.disabled = false; label.textContent = was; }
  });
}
function paintTabs() {
  const d = R.job.devices.find((x) => x.ip === R.sel);
  if (!d) return;
  const ids = ["todo", "find", "ports", "info"];
  $$("[data-tab]").forEach((t) => t.setAttribute("aria-selected", String(t.dataset.tab === R.tab)));
  $("#tabbar").style.transform = `translateX(${ids.indexOf(R.tab) * 100}%)`;
  let html = "";
  if (R.tab === "todo") html = `<ol class="todo">${todoFor(d).map((t, i) => `<li><span>${i + 1}</span><span>${esc(t)}</span></li>`).join("")}</ol>`;
  else if (R.tab === "find") html = d.findings.length ? d.findings.map((f) => `<article class="finding">
      <div style="display:flex;justify-content:space-between;gap:10px;align-items:flex-start"><h3 style="font-size:14px;line-height:1.5">${esc(f.title)}</h3>${sevBadge(f.severity)}</div>
      <p style="margin-top:4px;font-size:13px;color:var(--muted)">${esc(f.description)}</p>
      <p style="margin-top:6px;font-size:12.5px;color:var(--muted)">ความมั่นใจ ${esc(CONF[f.confidence] || f.confidence)}${f.cve.length ? ` · ${esc(f.cve.join(", "))}` : ""}${f.cvss != null ? ` · CVSS ${esc(f.cvss)}` : ""}</p>
      ${f.evidence ? `<div class="evidence">${esc(f.evidence)}</div>` : ""}</article>`).join("") : `<p style="font-size:14px;font-weight:600;color:var(--ok)">✓ ไม่พบปัญหาบนเครื่องนี้</p>`;
  else if (R.tab === "ports") {
    const svc = services(d);
    html = svc.length ? `<ul class="ports">${svc.map((x) => `<li class="port ${x.note ? "warn" : ""}"><span class="pnum">${x.port}</span><span style="min-width:0"><span class="ot">${esc(x.name)}</span><span class="od">${esc(x.description || "")}</span>${x.note ? `<span class="od" style="margin-top:3px;font-weight:600;color:var(--warn)">ควรระวัง: ${esc(x.note)}</span>` : ""}</span></li>`).join("")}</ul>
      <p class="sec" style="margin-top:10px;font-size:12.5px;color:var(--muted);display:flex;align-items:center;gap:6px">พอร์ตที่ควรระวังไม่ใช่ช่องโหว่ และไม่ลดคะแนน ${tip("พอร์ตที่เปิดอยู่อาจจำเป็นต่อการใช้งาน ระบบแค่เตือนให้ตรวจดูว่าควรจำกัดผู้เข้าถึงหรือไม่")}</p>`
      : `<p class="muted" style="font-size:14px">ไม่พบพอร์ตที่เปิด${(R.job.scanned_ports || []).length ? ` จาก ${num(R.job.scanned_ports.length)} พอร์ตที่ตรวจ` : ""}</p>`;
  } else {
    const kv = [["IP", d.ip, ""], ["ชื่อโฮสต์", d.hostname || "—", "ชื่อจากการค้นหา DNS ย้อนกลับ ถ้าไม่ได้ตั้งไว้จะว่าง"],
      ["MAC", d.mac || "—", "หมายเลขการ์ดเครือข่าย เห็นเฉพาะเครื่องในวง LAN เดียวกับเครื่องที่รัน thscan"], ["ประเภท", devType(d.device_type), "คาดเดาจากบริการที่เปิดอยู่ อาจไม่แม่นยำ 100%"],
      ["Runtime", runtimeOf(d) || "—", "ซอฟต์แวร์ที่ให้บริการเว็บ เช่น PHP, Node.js/Express หรือเว็บเซิร์ฟเวอร์ (nginx/Apache)"], ["เวอร์ชัน PHP", d.php_version || "ไม่พบ", "อ่านจาก header ที่เว็บตอบกลับ ถ้าเว็บซ่อนไว้จะไม่เห็น"], ["เว็บเซิร์ฟเวอร์", d.server || "—", ""],
      ["CMS", d.cms || "—", ""], ["พอร์ตเว็บ", d.open_ports.join(", ") || "—", "พอร์ตที่ตอบกลับเป็นเว็บจริงระหว่างการสแกน"],
      ["เวลาตอบสนอง", d.latency_ms != null ? `${num(d.latency_ms)} ms` : "—", "เวลาที่เครื่องใช้ตอบกลับ ยิ่งน้อยยิ่งเร็ว"]];
    const headers = Object.entries(d.headers || {});
    html = `<dl class="kv">${kv.map(([k, v, h]) => `<div class="sec"><dt>${k}${h ? ` ${tip(h)}` : ""}</dt><dd>${esc(v)}</dd></div>`).join("")}</dl>
      ${headers.length ? `<details class="raw"><summary>ดู header ที่เว็บตอบกลับ (สำหรับเจ้าหน้าที่เทคนิค)</summary><div class="evidence">${esc(headers.map(([k, v]) => `${k}: ${v}`).join("\n"))}</div></details>` : ""}`;
  }
  const panel = $("#tabpanel");
  panel.className = `tabpanel swap${R.tswap}`;
  panel.innerHTML = html;
}
function downloadCsv(devices, name) {
  const cell = (v) => { let s = String(v ?? ""); if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`; return `"${s.replace(/"/g, '""')}"`; };
  const head = ["ip", "hostname", "mac", "device_type", "service", "php_version", "cms", "open_ports", "open_services", "latency_ms", "severity", "assessment", "cve"];
  const rows = devices.map((d) => [d.ip, d.hostname, d.mac, d.device_type, d.service, d.php_version, d.cms, d.open_ports.join(" "),
    services(d).map((x) => `${x.port}/${x.name}`).join(" "), d.latency_ms, d.severity, d.assessment, [...new Set(d.findings.flatMap((f) => f.cve))].sort().join(" ")]);
  const csv = "﻿" + [head, ...rows].map((r) => r.map(cell).join(",")).join("\r\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  a.download = name; document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  toast(`ดาวน์โหลด ${num(devices.length)} เครื่องแล้ว`);
}

async function viewLatest(_, alive) {
  const jobs = await api("/api/scans");
  if (!alive()) return;
  if (jobs.length) { location.replace(`#/${["queued", "running"].includes(jobs[0].state) ? "scan" : "results"}/${jobs[0].id}`); return; }
  emptyPage("ยังไม่มีผลการสแกน", "เริ่มสแกนเครือข่ายครั้งแรก หรือเปิดตัวอย่างเพื่อดูว่าหน้าผลลัพธ์เป็นอย่างไร");
}
function emptyPage(title, text) {
  render(`<div class="app thin"><div class="card in1" style="padding:36px;text-align:center"><h1 class="h1" style="font-size:24px">${title}</h1><p class="lead">${text}</p>
    <p style="margin-top:18px;display:flex;gap:8px;justify-content:center;flex-wrap:wrap"><a class="btn btn-g" href="#/">เริ่มสแกน</a><button type="button" class="btn" id="demo2">ดูตัวอย่าง</button></p></div></div>`);
  $("#demo2").addEventListener("click", openDemoPicker);
}

/* ═══ view: report (print) ═════════════════════════════════════════════ */
async function viewReportLatest(_, alive) {
  const jobs = (await api("/api/scans")).filter((j) => !["queued", "running"].includes(j.state));
  if (!alive()) return;
  if (jobs.length) { location.replace(`#/report/${jobs[0].id}`); return; }
  emptyPage("ยังไม่มีรายงาน", "รายงานจะสร้างจากผลการสแกนครั้งล่าสุด เริ่มสแกนก่อน หรือเปิดตัวอย่าง");
}
async function viewReport([id], alive) {
  const j = await api(`/api/scans/${id}`);
  if (!alive()) return;
  const c = counts(j), act = j.devices.filter((d) => d.severity !== "safe").sort((a, b) => SEV[a.severity].rank - SEV[b.severity].rank), demo = !!j.demo_scenario;
  const watch = j.devices.flatMap((d) => services(d).filter((x) => x.note).map((x) => ({ d, x })));
  const pill = (sev) => `<span class="badge ${SEV[sev].cls}">${SEV[sev].word}</span>`;
  const summary = !j.devices.length ? "ไม่พบเครื่องที่ออนไลน์ในช่วงที่ตรวจ"
    : act.length ? `จากการตรวจ ${num(j.progress.total_ips)} ที่อยู่ พบเครื่องออนไลน์ ${num(j.devices.length)} เครื่อง ${c.critical ? `<b style="color:var(--crit)">${num(c.critical)} เครื่องมีช่องโหว่ PHP2Shell ที่ต้องแก้ไขโดยด่วน</b> ` : ""}${c.high + c.low ? `และอีก ${num(c.high + c.low)} เครื่องควรปรับปรุง ` : ""}แนะนำให้แก้เครื่องที่ต้องแก้ด่วนก่อน แล้วสั่งตรวจซ้ำเพื่อยืนยัน`
      : `จากการตรวจ ${num(j.progress.total_ips)} ที่อยู่ พบเครื่องออนไลน์ ${num(j.devices.length)} เครื่อง ไม่พบเครื่องที่มีความเสี่ยง PHP2Shell ณ เวลาที่ตรวจ`;
  render(`<div class="app" style="padding-top:0">
    <div class="noprint in1" style="width:min(860px,100%);margin:8px auto 0;display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:10px">
      <a class="btn" href="#/results/${esc(j.id)}">${ic("back", 17)}กลับไปที่ผลการสแกน</a>
      <button type="button" class="btn btn-g" id="print">${ic("print", 17)}พิมพ์ / บันทึก PDF</button></div>
    <article class="sheet in2"><div class="sheet-strip" aria-hidden="true"></div><div class="sheet-body">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:20px">
        <div style="min-width:0">${demo ? '<span class="badge b-blue" style="white-space:normal">ตัวอย่าง · ข้อมูลจำลอง — ไม่ใช่ผลการตรวจเครือข่ายจริง</span>' : ""}
          <h1 style="margin-top:12px;font-size:28px;line-height:1.3">รายงานผลการตรวจช่องโหว่ PHP2Shell</h1>
          <p class="muted" style="margin-top:6px;font-size:13.5px">ช่วงที่ตรวจ <span class="num">${esc(j.target_label)}</span> · ${esc(fmtDate(j.created_at))} · ${portsChecked(j)}ใช้เวลา ${fmtDuration(j.duration_s)} · ${STATE[j.state] || esc(j.state)}</p></div>
        <div style="display:flex;align-items:center;gap:8px;flex:none"><span class="logo" style="width:34px;height:34px;border-radius:10px"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true" style="width:18px;height:18px"><path d="${P.shield}"/></svg></span><b>thscan</b></div></div>
      <dl class="sum4">
        <div style="background:var(--tint)"><dt style="color:var(--blue-ink)">เครื่องที่ออนไลน์</dt><dd style="color:var(--blue-ink)">${num(j.devices.length)}<span style="font-size:12.5px;font-weight:500"> / ${num(j.progress.total_ips)}</span></dd></div>
        <div style="background:var(--crit-bg)"><dt style="color:var(--crit)">ต้องแก้ด่วน</dt><dd style="color:var(--crit)">${num(c.critical)}</dd></div>
        <div style="background:var(--warn-bg)"><dt style="color:var(--warn)">ควรแก้ไข</dt><dd style="color:var(--warn)">${num(c.high + c.low)}</dd></div>
        <div style="background:var(--bg)"><dt class="muted">คะแนน (คำนวณโดย thscan)</dt><dd>${num(j.security_score)}<span style="font-size:12.5px;font-weight:500" class="muted"> · เกรด ${esc(j.security_grade)}</span></dd></div></dl>
      <h2>สรุปสำหรับผู้บริหาร</h2><p style="font-size:14.5px;line-height:1.8">${summary}</p>
      ${act.length ? `<h2>เครื่องที่ต้องดำเนินการ (เรียงตามความเร่งด่วน)</h2><div class="scroll"><table class="tbl"><thead><tr><th>เครื่อง</th><th>ระดับ</th><th>PHP</th><th>สิ่งที่ควรทำ</th></tr></thead><tbody>
        ${act.map((d) => `<tr><td><b class="num">${esc(d.ip)}</b><br><span class="muted">${esc(d.hostname || "")}</span></td><td>${pill(d.severity)}</td><td class="num">${esc(d.php_version || "—")}</td><td>${esc(todoFor(d)[0])}</td></tr>`).join("")}</tbody></table></div>` : ""}
      ${watch.length ? `<h2>พอร์ตที่ควรตรวจสอบ</h2><div class="scroll"><table class="tbl"><thead><tr><th>เครื่อง</th><th>พอร์ต</th><th>ข้อแนะนำ</th></tr></thead><tbody>
        ${watch.map(({ d, x }) => `<tr><td class="num">${esc(d.ip)}</td><td><span class="badge b-warn">${x.port} · ${esc(x.name)}</span></td><td>${esc(x.note)}</td></tr>`).join("")}</tbody></table></div>` : ""}
      ${j.devices.length ? `<h2>เครื่องทั้งหมดที่ตรวจพบ</h2><div class="scroll"><table class="tbl"><thead><tr><th>IP</th><th>ชื่อโฮสต์</th><th>Runtime</th><th>พอร์ตที่เปิด</th><th>ผล</th></tr></thead><tbody>
        ${j.devices.map((d) => `<tr><td class="num">${esc(d.ip)}</td><td>${esc(d.hostname || "—")}</td><td>${esc(devType(d.device_type))}</td><td>${esc(runtimeOf(d) || devType(d.device_type))}</td><td class="num">${esc(services(d).map((x) => x.port).join(", ") || "—")}</td><td>${pill(d.severity)}</td></tr>`).join("")}</tbody></table></div>` : ""}
      <h2>อ่านรายงานนี้อย่างไร</h2>
      <dl style="margin:0;display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;font-size:13px;line-height:1.6">
        <div style="padding:12px 14px;border-radius:14px;border:1px solid var(--crit-line)"><dt>${pill("critical")}</dt><dd style="margin:6px 0 0">ใช้ PHP รุ่นที่มีช่องโหว่ PHP2Shell ผู้ไม่หวังดีอาจสั่งงานเครื่องได้</dd></div>
        <div style="padding:12px 14px;border-radius:14px;border:1px solid var(--warn-line)"><dt>${pill("low")}</dt><dd style="margin:6px 0 0">ความเสี่ยงรองลงมา หรือพอร์ตที่ควรจำกัดผู้เข้าถึง</dd></div>
        <div style="padding:12px 14px;border-radius:14px;border:1px solid var(--ok-line)"><dt>${pill("safe")}</dt><dd style="margin:6px 0 0">ไม่พบช่องโหว่ PHP2Shell ณ เวลาที่ตรวจ</dd></div></dl>
      <p class="muted" style="margin-top:18px;font-size:12.5px;line-height:1.75">PHP รุ่นที่แก้ไขแล้ว: 8.5.12, 8.4.27, 8.3.36, 8.2.35 ขึ้นไป · ผลมาจากการตรวจแบบไม่ทำลายระบบ ณ เวลาที่ระบุ · พอร์ตที่เปิดไม่ถือเป็นช่องโหว่ · คะแนนคำนวณโดย thscan ไม่ใช่การรับรองจาก ThaiCERT หรือหน่วยงานใด</p>
      <div class="muted" style="display:flex;flex-wrap:wrap;gap:8px;justify-content:space-between;margin-top:28px;padding-top:12px;border-top:1px solid var(--line);font-size:12px"><span>thscan v${esc(cfg.version)} · ติดตั้งและดูแลโดยหน่วยงาน</span><span>พิมพ์เมื่อ ${esc(fmtDate(new Date().toISOString(), { dateStyle: "medium" }))}</span></div>
    </div></article></div>`);
  $("#print").addEventListener("click", () => print());
}

/* ═══ view: history ════════════════════════════════════════════════════ */
const H = { sel: null, flip: 0 };
async function viewHistory(_, alive) {
  const jobs = await api("/api/scans");
  if (!alive()) return;
  if (!jobs.length) { emptyPage("ยังไม่มีประวัติการสแกน", "ผลการสแกนทุกครั้ง (รวมที่ตั้งเวลาไว้) จะแสดงที่นี่ และยังอยู่แม้รีสตาร์ทโปรแกรม"); return; }
  const targets = [...new Set(jobs.map((j) => j.target_label))];
  if (!targets.includes(H.sel)) H.sel = targets[0];
  render(`<div class="app slim">
    <div class="page-head in1">
      <div><h1 class="h1">ประวัติการสแกน</h1><p class="lead">เก็บในเครื่องที่ติดตั้ง (โฟลเดอร์ data/) ยังอยู่แม้รีสตาร์ทโปรแกรม</p></div>
      ${dock("d-htarget", `<button type="button" class="peek flat" style="width:auto;min-width:240px;max-width:min(360px,100%)"><span class="muted" style="font-size:12.5px">เป้าหมาย</span><span id="h-sel" class="num" style="min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis"></span>${chev}</button>`, `<div class="stag" id="h-targets"></div>`, { w: 340, align: "end" })}
    </div>
    <section class="card sec in2" aria-labelledby="h-trend" style="margin-top:18px;padding:20px 22px" id="h-chart"></section>
    <section class="card in3" aria-labelledby="h-all" style="margin-top:16px;padding:14px 10px">
      <div style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:10px;padding:0 8px">
        <h2 id="h-all" style="font-size:15px">ทุกครั้ง (${num(jobs.length)}) <span class="muted" style="font-size:12.5px;font-weight:500">· ชี้ที่แถวเพื่อดูรายละเอียด</span></h2>
        <span id="h-clear"></span></div>
      <div style="margin-top:6px;display:flex;flex-direction:column">${jobs.map((s) => {
        const fix = s.risks, live = ["queued", "running"].includes(s.state);
        return `<a class="hrow" href="#/${live ? "scan" : "results"}/${esc(s.id)}">
          <span class="badge ${live ? "b-blue" : gradeCls(s.security_grade)}" style="min-width:76px;justify-content:center;font-size:13px;padding:8px 10px">${live ? "กำลังสแกน" : `เกรด ${esc(s.security_grade)}`}</span>
          <span style="flex:1;min-width:0"><span style="display:flex;flex-wrap:wrap;align-items:center;gap:8px;font-size:15px;font-weight:700;overflow-wrap:anywhere" class="num">${esc(s.target_label || "—")}${s.demo_scenario ? '<span class="badge b-blue">ตัวอย่าง</span>' : ""}${s.state === "cancelled" || s.state === "failed" ? `<span class="badge b-warn">${STATE[s.state]}</span>` : ""}</span>
            <span class="muted" style="display:block;font-size:12.5px">${esc(fmtDate(s.created_at))}${s.note ? ` · ${esc(s.note)}` : ""}</span></span>
          <span class="more"><span class="badge b-blue">ออนไลน์ ${num(s.online)}</span><span class="badge ${s.severity_counts.critical ? "b-bad" : fix ? "b-warn" : "b-ok"}">${fix ? `ควรแก้ ${num(fix)}` : "ไม่มีที่ต้องแก้"}</span><span class="badge b-grey">${num(s.security_score)}/100</span></span>
          <span class="arrow" aria-hidden="true">→</span></a>`;
      }).join("")}</div>
    </section></div>`);
  const paint = () => {
    const mine = jobs.filter((j) => j.target_label === H.sel && !["queued", "running"].includes(j.state)).reverse();
    $("#h-sel").textContent = H.sel;
    $("#h-targets").innerHTML = targets.map((t) => { const rs = jobs.filter((j) => j.target_label === t); return `<button type="button" class="mi" data-t="${esc(t)}" aria-pressed="${t === H.sel}"><span style="flex:1;min-width:0"><span class="ot num" style="overflow-wrap:anywhere">${esc(t)}</span><span class="od">${rs[0].demo_scenario ? "ตัวอย่าง · " : "ล่าสุด "}${esc(fmtDate(rs[0].created_at))}</span></span><span class="n">${rs.length}</span></button>`; }).join("");
    const X = (i) => (mine.length === 1 ? 420 : 40 + (760 * i) / (mine.length - 1)), Y = (v) => 200 - (170 * v) / 100;
    let line = "", pts = "";
    mine.forEach((r, i) => { line += `${i ? "L" : "M"}${X(i).toFixed(1)} ${Y(r.security_score).toFixed(1)}`; pts += `M${(X(i) - 6).toFixed(1)} ${Y(r.security_score).toFixed(1)}a6 6 0 1 0 12 0a6 6 0 1 0 -12 0`; });
    const area = mine.length > 1 ? `${line}L${X(mine.length - 1).toFixed(1)} 200L${X(0).toFixed(1)} 200Z` : "M0 0";
    const last = mine[mine.length - 1], prev = mine[mine.length - 2], d = last && prev ? last.security_score - prev.security_score : null;
    $("#h-chart").innerHTML = last ? `<div style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:flex-end;gap:12px">
        <div style="min-width:0"><h2 id="h-trend" style="display:flex;flex-wrap:wrap;align-items:center;gap:8px;font-size:14px;font-weight:600;color:var(--muted)">คะแนนล่าสุด · <span class="num" style="overflow-wrap:anywhere">${esc(H.sel)}</span> ${tip("คำนวณโดย thscan: 100 หักเครื่องละ ด่วน 22 · สูง 14 · ต่ำ 4 · เส้นที่ไต่ขึ้นแปลว่าปลอดภัยขึ้น")}</h2>
          <div class="gtext num" style="font-size:44px;font-weight:700;line-height:1.1"><span id="h-score">0</span><span style="font-size:16px">/100</span></div></div>
        <div style="display:flex;flex-wrap:wrap;gap:6px;justify-content:flex-end">
          <span class="badge ${d === null ? "b-grey" : d >= 0 ? "b-ok" : "b-bad"}" style="font-size:13px;padding:6px 12px">${d === null ? "สแกนครั้งเดียว ยังไม่มีแนวโน้ม" : d > 0 ? `▲ ดีขึ้น +${d}` : d < 0 ? `▼ แย่ลง ${d}` : "เท่าเดิม"}</span>
          <span class="badge ${gradeCls(last.security_grade)}" style="font-size:13px;padding:6px 12px">เกรด ${esc(last.security_grade)}</span>
          <span class="badge b-bad" style="font-size:13px;padding:6px 12px">ด่วน ${num(last.severity_counts.critical)}</span>
          <span class="badge b-warn" style="font-size:13px;padding:6px 12px">ควรแก้ ${num(last.severity_counts.high + last.severity_counts.low)}</span></div></div>
      <svg viewBox="0 0 840 220" role="img" aria-label="คะแนนของ ${esc(H.sel)}: ${mine.map((r) => r.security_score).join(" → ")}" style="display:block;width:100%;height:auto;margin-top:14px;overflow:visible">
        <defs><linearGradient id="hl" gradientUnits="userSpaceOnUse" x1="40" y1="0" x2="800" y2="0"><stop offset="0" stop-color="#2F5BEA"/><stop offset="1" stop-color="#6D4AFF"/></linearGradient>
        <linearGradient id="ha" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#6D4AFF" stop-opacity=".2"/><stop offset="1" stop-color="#2F5BEA" stop-opacity="0"/></linearGradient></defs>
        <path d="M20 30H820M20 87H820M20 143H820" stroke="#EDF0F8"/><path d="M20 200H820" stroke="#D5DDF3" stroke-width="1.2"/>
        <path d="${area}" fill="url(#ha)" class="swap${H.flip}"/><path class="draw${H.flip}" d="${line}" pathLength="100" fill="none" stroke="url(#hl)" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"/>
        <path d="${pts}" fill="#fff" stroke="#4A4FF0" stroke-width="2.5" class="swap${H.flip}"/></svg>
      <div class="muted" style="display:flex;justify-content:space-between;padding:0 4px;font-size:12px"><span>${esc(fmtDate(mine[0].created_at, { dateStyle: "medium" }))}</span><span>${mine.length > 1 ? esc(fmtDate(last.created_at, { dateStyle: "medium" })) : ""}</span></div>`
      : `<p class="muted">เป้าหมายนี้ยังไม่มีผลที่สแกนเสร็จ</p>`;
    tween($("#h-score"), last ? last.security_score : 0, 900);
  };
  const clearUi = (confirming) => {
    $("#h-clear").innerHTML = confirming
      ? `<span style="display:flex;flex-wrap:wrap;align-items:center;gap:6px;animation:rise .35s var(--ease) backwards"><span style="font-size:13px;font-weight:600;color:var(--crit)">ลบ ${num(jobs.length)} รายการถาวร?</span><button type="button" class="btn" id="c-no">ยกเลิก</button><button type="button" class="btn btn-danger" id="c-yes">ลบทั้งหมด</button></span>`
      : `<button type="button" class="ghost stop" id="c-ask">${ic("trash", 16)}ล้างประวัติ</button>`;
    const f = $(confirming ? "#c-no" : "#c-ask"); if (confirming && f) f.focus();
  };
  $("#h-targets").addEventListener("click", (e) => { const b = e.target.closest("[data-t]"); if (b && b.dataset.t !== H.sel) { H.sel = b.dataset.t; H.flip = 1 - H.flip; shut($("#d-htarget")); paint(); } });
  $("#h-clear").addEventListener("click", async (e) => {
    if (e.target.closest("#c-ask")) clearUi(true);
    else if (e.target.closest("#c-no")) clearUi(false);
    else if (e.target.closest("#c-yes")) {
      try { const r = await api("/api/scans", { method: "DELETE" }); toast(`ลบแล้ว ${num(r.removed)} รายการ`); route(); } catch (err) { toast(err.message); }
    }
  });
  clearUi(false); paint();
}

/* ═══ view: settings (schedules, scope, audit, about) ═════════════════ */
const AUDIT = {
  scan_started: ["เริ่มสแกน", "b-blue"], scan_finished: ["สแกนเสร็จ", "b-ok"], scan_cancelled: ["ยกเลิกการสแกน", "b-warn"], history_cleared: ["ล้างประวัติ", "b-warn"],
  device_rechecked: ["ตรวจซ้ำเครื่อง", "b-ok"], device_patch_simulated: ["จำลองการแก้ไข", "b-grey"], schedule_created: ["สร้างตารางเวลา", "b-blue"],
  schedule_updated: ["แก้ไขตารางเวลา", "b-blue"], schedule_deleted: ["ลบตารางเวลา", "b-warn"], schedule_fired: ["ตารางเวลาทำงาน", "b-blue"],
  export_csv: ["ส่งออก CSV", "b-grey"], export_json: ["ส่งออก JSON", "b-grey"],
};
function auditDetail(e) {
  const p = [];
  if (e.targets && e.targets.length) p.push(e.targets.join(", "));
  if (e.sites && e.sites.length) p.push(e.sites.join(", "));
  if (e.demo_scenario) p.push(`ตัวอย่าง: ${e.demo_scenario}`);
  if (e.name) p.push(e.name);
  if (e.ip) p.push(e.ip);
  if (e.severity_before && e.severity_after && SEV[e.severity_before] && SEV[e.severity_after]) p.push(`${SEV[e.severity_before].word} → ${SEV[e.severity_after].word}`);
  if (e.event === "scan_finished") p.push(`ออนไลน์ ${num(e.online)} · ควรแก้ ${num(e.risks)}`);
  if (e.removed_jobs != null) p.push(`${num(e.removed_jobs)} รายการ`);
  return esc(p.join(" · ") || "—");
}
/* "now" as wall-clock parts in the server's time zone, held in a UTC Date */
function tzNow() {
  const parts = {};
  try { new Intl.DateTimeFormat("en-GB", { timeZone: cfg.timezone, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }).formatToParts(new Date()).forEach((p) => { parts[p.type] = p.value; }); }
  catch { const d = new Date(); return new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate(), d.getHours(), d.getMinutes())); }
  return new Date(Date.UTC(+parts.year, +parts.month - 1, +parts.day, +parts.hour % 24, +parts.minute));
}
function parseCron(c) {
  const f = String(c).trim().split(/\s+/), base = { freq: "custom", slot: 4, dow: 1, dom: "1", cron: c };
  if (f.length !== 5) return base;
  const [m, h, dom, mon, dow] = f;
  if (!/^(0|30)$/.test(m) || !/^\d{1,2}$/.test(h) || +h > 23 || mon !== "*") return base;
  const slot = +h * 2 + (m === "30" ? 1 : 0);
  if (dom === "*" && dow === "*") return { ...base, freq: "daily", slot };
  if (dom === "*" && dow === "1-5") return { ...base, freq: "weekdays", slot };
  if (dom === "*" && /^[0-6]$/.test(dow)) return { ...base, freq: "weekly", slot, dow: +dow };
  if (/^\d{1,2}$/.test(dom) && +dom >= 1 && +dom <= 28 && dow === "*") return { ...base, freq: "monthly", slot, dom };
  return base;
}
const Z = { items: [], cur: "new", form: null, tab: "scope", tswap: 0, audit: [] };
function blankForm() { return { name: "", targets: (S.detected.find((d) => d.ok) || {}).cidr || (cfg.allowed_cidrs || [""])[0], freq: "daily", slot: 4, dow: 1, dom: "1", cron: "0 2 * * *", profile: "common", custom: "" }; }
function formCron(f) {
  const h = Math.floor(f.slot / 2), m = f.slot % 2 ? 30 : 0;
  return { daily: `${m} ${h} * * *`, weekdays: `${m} ${h} * * 1-5`, weekly: `${m} ${h} * * ${f.dow}`, monthly: `${m} ${h} ${f.dom || 1} * *`, custom: f.cron.trim() }[f.freq];
}
const freqWord = (f) => ({ daily: "ทุกวัน", weekdays: "จันทร์–ศุกร์", weekly: `ทุกวัน${DOW[f.dow]}`, monthly: `ทุกวันที่ ${f.dom || 1} ของเดือน`, custom: "ตามรูปแบบ cron" })[f.freq];
const slotTime = (slot) => `${String(Math.floor(slot / 2)).padStart(2, "0")}:${slot % 2 ? "30" : "00"}`;
function nextRunText(f) {
  if (f.freq === "custom") return "ระบบคำนวณให้หลังบันทึก";
  const now = tzNow(), hh = Math.floor(f.slot / 2), mm = f.slot % 2 ? 30 : 0;
  for (let k = 1; k < 48 * 40; k += 1) {
    const d = new Date(now.getTime() - (now.getUTCMinutes() % 30) * 60000 + k * 30 * 60000);
    if (d.getUTCHours() !== hh || d.getUTCMinutes() !== mm) continue;
    const wd = d.getUTCDay();
    if (f.freq === "daily" || (f.freq === "weekdays" && wd >= 1 && wd <= 5) || (f.freq === "weekly" && wd === +f.dow) || (f.freq === "monthly" && d.getUTCDate() === +(f.dom || 1)))
      return `${DS[wd]}. ${d.toLocaleDateString("th-TH", { timeZone: "UTC", day: "numeric", month: "short", year: "numeric" })} ${slotTime(f.slot)} น.`;
  }
  return "—";
}

async function viewSettings(_, alive) {
  const [items, audit, auto] = await Promise.all([api("/api/schedules"), api("/api/audit"), api("/api/autodetect").catch(() => ({ subnets: [] }))]);
  if (!alive()) return;
  if (!S.detected.length) S.detected = detect(auto.subnets);
  Z.items = items; Z.audit = audit.entries || [];
  if (Z.cur !== "new" && !Z.items.some((x) => x.id === Z.cur)) Z.cur = "new";
  if (Z.cur === "new" && Z.items[0] && !Z.form) Z.cur = Z.items[0].id;
  loadForm();
  render(`<div class="app narrow">
    <div class="page-head in1">
      <div><h1 class="h1">ตั้งเวลาสแกนอัตโนมัติ</h1><p class="lead">เวลาตาม ${esc(cfg.timezone || "Asia/Bangkok")} · โปรแกรมต้องเปิดอยู่ ณ เวลานั้น · ผลไปอยู่ที่หน้าประวัติ</p></div>
      ${dock("d-list", `<button type="button" class="peek" style="width:auto;min-width:260px;max-width:min(360px,100%);min-height:50px"><span style="min-width:0"><span class="k" id="l-k"></span><span class="v" id="l-v"></span></span>${chev}</button>`, `<div class="stag" id="l-list"></div>`, { w: 360, align: "end" })}
    </div>
    <div class="tools in2" style="margin-top:20px">
      ${dock("d-who", `<button type="button" class="peek"><span class="ic">1</span><span style="min-width:0"><span class="k">ชื่อและเป้าหมาย</span><span class="v" id="sum-who"></span></span>${chev}</button>`, `<div class="stag">
        <label style="display:block"><span class="lbl">ชื่อตารางเวลา</span><input class="inp" id="f-name" placeholder="เช่น สแกนวงสำนักงานทุกคืน" autocomplete="off" maxlength="80"></label>
        <label style="display:block;margin-top:10px"><span class="lbl">เป้าหมาย ${tip("ซับเน็ต ช่วง หรือ IP เดียว คั่นหลายรายการด้วยจุลภาค ต้องอยู่ในขอบเขตที่ผู้ติดตั้งอนุญาต")}</span><input class="inp num" id="f-targets" autocomplete="off" spellcheck="false"></label></div>`, { w: 420 })}
      ${dock("d-freq", `<button type="button" class="peek"><span class="ic">2</span><span style="min-width:0"><span class="k">ความถี่</span><span class="v" id="sum-freq"></span></span>${chev}</button>`, `<div id="p-freq"></div>`, { w: 360, align: "mid" })}
      ${dock("d-sports", `<button type="button" class="peek"><span class="ic">3</span><span style="min-width:0"><span class="k">พอร์ตที่ตรวจ</span><span class="v" id="sum-sports"></span></span>${chev}</button>`, `<div id="p-sports"></div>`, { w: 360, align: "end" })}
    </div>
    <section class="card stage in3" aria-label="เวลา" style="margin-top:16px;padding:16px 24px 24px;text-align:center">
      <div id="dial-wrap" style="position:relative;max-width:380px;margin:0 auto;transition:opacity .4s">
        <svg class="vis" viewBox="0 0 400 440" role="img" id="dial" aria-label="นาฬิกา 24 ชั่วโมง">
          <defs><linearGradient id="cg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#2F5BEA"/><stop offset="1" stop-color="#6D4AFF"/></linearGradient>
          <radialGradient id="cglow"><stop offset="0%" stop-color="#8B7CFF" stop-opacity=".3"/><stop offset="100%" stop-color="#4F7BFF" stop-opacity="0"/></radialGradient></defs>
          <circle class="halo" cx="200" cy="168" r="150" fill="url(#cglow)"/><circle cx="200" cy="168" r="112" fill="#fff" stroke="url(#cg)" stroke-width="3"/>
          <path id="night" fill="none" stroke="#C5CFEE" stroke-width="10" stroke-linecap="round" opacity=".7"/>
          <path id="ticks" fill="none" stroke="#8A93C2" stroke-width="1.4" stroke-linecap="round"/><path id="majors" fill="none" stroke="#2F5BEA" stroke-width="2.6" stroke-linecap="round"/>
          <g fill="#4B5575" font-size="13" font-weight="600" text-anchor="middle" font-family="Inter, sans-serif"><text x="200" y="64">0</text><text x="322" y="173">6</text><text x="200" y="283">12</text><text x="78" y="173">18</text></g>
          <g class="hand" id="hand"><path d="M200 168V92" stroke="#4A4FF0" stroke-width="5" stroke-linecap="round"/><circle cx="200" cy="88" r="7" fill="#6D4AFF"/></g>
          <circle cx="200" cy="168" r="8" fill="#fff" stroke="#4A4FF0" stroke-width="3"/>
          <path d="M39 300 C42 372 111 407 200 407 C289 407 358 372 361 300" fill="none" stroke="#E1E6F5" stroke-width="6" stroke-linecap="round"/>
          <path id="dial-ring" d="M39 300 C42 372 111 407 200 407 C289 407 358 372 361 300" pathLength="100" fill="none" stroke="url(#cg)" stroke-width="6" stroke-linecap="round" style="transition:stroke-dasharray .6s cubic-bezier(.34,1.3,.64,1)"/>
          <g class="mark" id="dial-mark"><circle r="13" fill="#fff" stroke="url(#cg)" stroke-width="3"/><circle r="4" fill="#4A4FF0"/></g>
        </svg>
        <input class="ringin" id="slot" type="range" min="0" max="47" step="1" aria-label="เวลา ลากเพื่อเปลี่ยนทีละ 30 นาที">
      </div>
      <div class="dial-ctl">
        <button type="button" class="round hov" id="earlier" aria-label="เร็วขึ้น 30 นาที">−</button>
        <div><div class="k" id="when"></div><div class="gtext num" id="time" style="font-size:40px;font-weight:700;line-height:1.1"></div></div>
        <button type="button" class="round hov" id="later" aria-label="ช้าลง 30 นาที">+</button></div>
      <p class="hov muted" style="margin-top:4px;font-size:12.5px">ลากวงแหวน หรือกด − / + เลื่อนทีละ 30 นาที · แถบจางบนหน้าปัดคือช่วงกลางคืน 22:00–06:00</p>
      <p class="summary" id="summary" aria-live="polite"></p>
      <div style="display:flex;flex-wrap:wrap;justify-content:center;align-items:center;gap:8px;margin-top:14px">
        <button type="button" class="go" id="save" style="min-height:54px;font-size:16px"></button>
        <button type="button" class="ghost stop" id="del" hidden>${ic("trash", 16)}ลบตารางเวลานี้</button></div>
    </section>
    <section class="card in4" aria-label="ข้อมูลระบบ" style="margin-top:16px;padding:6px 20px 20px">
      <div class="tabs" role="tablist" style="--n:3" id="z-tabs">
        ${[["scope", "ขอบเขตการสแกน"], ["audit", "บันทึกการใช้งาน"], ["about", "เกี่ยวกับ thscan"]].map(([id, l]) => `<button type="button" class="tab" role="tab" data-ztab="${id}">${l}</button>`).join("")}
        <span class="tabbar" id="z-bar" aria-hidden="true"></span></div>
      <div class="tabpanel" role="tabpanel" id="z-panel" style="min-height:190px"></div>
    </section></div>`);
  // static dial: hour ticks and the night arc
  const C = (h, r) => { const a = (h / 24) * 2 * Math.PI - Math.PI / 2; return [200 + r * Math.cos(a), 168 + r * Math.sin(a)]; };
  let minor = "", major = "";
  for (let h = 0; h < 24; h += 1) { const [x1, y1] = C(h, h % 6 === 0 ? 90 : 98), [x2, y2] = C(h, 104); const seg = `M${x1.toFixed(1)} ${y1.toFixed(1)}L${x2.toFixed(1)} ${y2.toFixed(1)}`; if (h % 6 === 0) major += seg; else minor += seg; }
  $("#ticks").setAttribute("d", minor); $("#majors").setAttribute("d", major);
  const [nx1, ny1] = C(22, 82), [nx2, ny2] = C(30, 82);
  $("#night").setAttribute("d", `M${nx1.toFixed(1)} ${ny1.toFixed(1)}A82 82 0 0 1 ${nx2.toFixed(1)} ${ny2.toFixed(1)}`);

  fillForm(); paintSchedule(); paintZTab();
  $("#l-list").addEventListener("click", (e) => {
    const b = e.target.closest("[data-sid]");
    if (!b) return;
    Z.cur = b.dataset.sid; loadForm(); shut($("#d-list")); fillForm(); paintSchedule();
    if (Z.cur === "new") $("#f-name").focus();
  });
  $("#f-name").addEventListener("input", (e) => { Z.form.name = e.target.value; paintSchedule(); });
  $("#f-targets").addEventListener("input", (e) => { Z.form.targets = e.target.value; paintSchedule(); });
  $("#p-freq").addEventListener("click", (e) => {
    const f = e.target.closest("[data-freq]"), d = e.target.closest("[data-dow]");
    if (f && f.dataset.freq !== Z.form.freq) {
      Z.form.freq = f.dataset.freq; paintFreq(); paintSchedule();
      const next = $("#f-dom, #f-cron, [data-dow]", $("#p-freq")); next ? next.focus() : shut($("#d-freq"));
    }
    if (d) { Z.form.dow = +d.dataset.dow; paintFreq(); paintSchedule(); shut($("#d-freq")); }
  });
  $("#p-freq").addEventListener("input", (e) => {
    if (e.target.id === "f-dom") { const n = e.target.value.replace(/\D/g, "").slice(0, 2); Z.form.dom = n && +n > 28 ? "28" : n === "0" ? "1" : n; e.target.value = Z.form.dom; }
    if (e.target.id === "f-cron") Z.form.cron = e.target.value;
    paintSchedule();
  });
  $("#p-sports").addEventListener("click", (e) => {
    const p = e.target.closest("[data-sprofile]");
    if (!p || p.dataset.sprofile === Z.form.profile) return;
    Z.form.profile = p.dataset.sprofile; paintSPorts(); paintSchedule();
    if (Z.form.profile === "custom") $("#f-custom").focus(); else shut($("#d-sports"));
  });
  $("#p-sports").addEventListener("input", (e) => { if (e.target.id === "f-custom") { Z.form.custom = e.target.value; paintSchedule(); } });
  $("#slot").addEventListener("input", (e) => { Z.form.slot = +e.target.value; paintSchedule(); });
  $("#earlier").addEventListener("click", () => { Z.form.slot = (Z.form.slot + 47) % 48; paintSchedule(); });
  $("#later").addEventListener("click", () => { Z.form.slot = (Z.form.slot + 1) % 48; paintSchedule(); });
  $("#save").addEventListener("click", saveSchedule);
  $("#del").addEventListener("click", deleteSchedule);
  const pick = (e) => { const t = e.target.closest("[data-ztab]"); if (t && t.dataset.ztab !== Z.tab) { Z.tab = t.dataset.ztab; Z.tswap = 1 - Z.tswap; paintZTab(); } };
  const zt = $("#z-tabs");
  zt.addEventListener("mouseover", pick); zt.addEventListener("click", pick); zt.addEventListener("focusin", pick);
}
function loadForm() {
  const it = Z.items.find((x) => x.id === Z.cur);
  if (!it) { Z.form = blankForm(); return; }
  const c = parseCron(it.cron);
  Z.form = { name: it.name, targets: it.targets.join(", "), freq: c.freq, slot: c.slot, dow: c.dow, dom: c.dom, cron: it.cron, profile: it.port_profile || "common", custom: it.custom_ports || "" };
}
function fillForm() {
  $("#f-name").value = Z.form.name; $("#f-targets").value = Z.form.targets;
  $("#l-k").textContent = `ตารางเวลาที่มี (${num(Z.items.length)})`;
  $("#l-list").innerHTML = Z.items.map((it) => { const c = parseCron(it.cron); return `<button type="button" class="mi" data-sid="${esc(it.id)}" aria-pressed="${it.id === Z.cur}"><span style="min-width:0;flex:1"><span class="ot">${esc(it.name)}</span><span class="od">${esc(it.targets.join(", "))} · ${esc(freqWord(c))}${c.freq !== "custom" ? ` ${slotTime(c.slot)}` : ""} · ครั้งถัดไป ${esc(fmtDate(it.next_run))}</span></span></button>`; }).join("")
    + `<button type="button" class="mi new" data-sid="new" aria-pressed="${Z.cur === "new"}" style="margin-top:6px">+ สร้างตารางเวลาใหม่</button>`;
  $("#del").hidden = Z.cur === "new";
  paintFreq(); paintSPorts();
}
function paintFreq() {
  const f = Z.form;
  const FREQ = [["daily", "ทุกวัน", "วันละครั้ง"], ["weekdays", "วันทำการ", "จันทร์–ศุกร์"], ["weekly", "ทุกสัปดาห์", "เลือกวัน"], ["monthly", "ทุกเดือน", "เลือกวันที่"], ["custom", "กำหนดเอง", "รูปแบบ cron"]];
  $("#p-freq").innerHTML = `<div class="stag"><div style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px">
    ${FREQ.map(([k, t, d]) => `<button type="button" class="opt" data-freq="${k}" aria-pressed="${f.freq === k}"><span style="min-width:0"><span class="ot">${t}</span><span class="od">${d}</span></span></button>`).join("")}</div>
    ${f.freq === "weekly" ? `<div role="group" aria-label="วันในสัปดาห์" style="display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:4px;margin-top:10px">${[1, 2, 3, 4, 5, 6, 0].map((d) => `<button type="button" class="day" data-dow="${d}" aria-pressed="${+f.dow === d}" aria-label="วัน${DOW[d]}">${DS[d]}</button>`).join("")}</div>` : ""}
    ${f.freq === "monthly" ? `<label style="display:block;margin-top:10px"><span class="lbl">วันที่ของเดือน (1–28)</span><input class="inp" id="f-dom" value="${esc(f.dom)}" inputmode="numeric" style="width:96px;text-align:center"></label>` : ""}
    ${f.freq === "custom" ? `<label style="display:block;margin-top:10px"><span class="lbl">รูปแบบ cron ${tip("5 ช่อง: นาที ชั่วโมง วันที่ เดือน วันในสัปดาห์ (0 = อาทิตย์) เช่น 30 1 * * 1-5 = 01:30 น. วันจันทร์–ศุกร์")}</span><input class="inp mono" id="f-cron" value="${esc(f.cron)}" spellcheck="false" autocomplete="off"></label>` : ""}</div>`;
}
function paintSPorts() {
  const f = Z.form;
  $("#p-sports").innerHTML = `<div class="stag"><div class="ptitle">ชุดพอร์ต ${tip("ชุดพอร์ตแบบเดียวกับหน้าสแกน · “ใช้บ่อย” คือค่าแนะนำ")}</div>
    ${profileOpts("data-sprofile", f.profile)}
    ${f.profile === "custom" ? `<label style="display:block;margin-top:10px"><span class="lbl">พอร์ตที่ต้องการ</span><input class="inp" id="f-custom" value="${esc(f.custom)}" autocomplete="off" spellcheck="false"></label>` : ""}</div>`;
}
const formTargets = (f) => f.targets.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean);
function scheduleProblem() {
  const f = Z.form;
  if (!f.name.trim()) return "ตั้งชื่อตารางเวลาก่อน (ชี้ที่แถบ 1)";
  const c = checkTargets(formTargets(f));
  if (c.error) return c.error;
  if (c.outside.length) return `อยู่นอกขอบเขตที่อนุญาต: ${c.outside.join(", ")}`;
  if (c.count > cfg.max_targets) return `เกินจำนวนสูงสุด ${num(cfg.max_targets)} ที่อยู่ต่อครั้ง`;
  const pc = portCount(f.profile, f.custom);
  if (pc.error) return pc.error;
  if (c.count * pc.n > cfg.max_port_probes) return `งานใหญ่เกินไป (${num(c.count)} ที่อยู่ × ${num(pc.n)} พอร์ต)`;
  if (f.freq === "custom" && f.cron.trim().split(/\s+/).length !== 5) return "รูปแบบ cron ต้องมี 5 ช่อง";
  return "";
}
function paintSchedule() {
  const f = Z.form, isNew = Z.cur === "new", custom = f.freq === "custom";
  const hh = Math.floor(f.slot / 2), mm = f.slot % 2 ? 30 : 0;
  $("#l-v").textContent = isNew ? "+ ตารางเวลาใหม่" : f.name || "—";
  $("#sum-who").textContent = `${f.name || "ยังไม่ได้ตั้งชื่อ"} · ${f.targets || "—"}`;
  $("#sum-freq").textContent = custom ? "กำหนดเอง (cron)" : `${freqWord(f)} · ${slotTime(f.slot)}`;
  const pc = portCount(f.profile, f.custom);
  $("#sum-sports").textContent = pc.error ? "รูปแบบพอร์ตไม่ถูกต้อง" : `${(PROFILE_TEXT[f.profile] || [f.profile])[0]} · ${num(pc.n)} พอร์ต`;
  $("#hand").style.transform = `rotate(${((hh + mm / 60) / 24) * 360}deg)`;
  const th = Math.PI * (1 - f.slot / 47), mx = 200 + 160 * Math.cos(th), my = 362 + 45 * Math.sin(th);
  $("#dial-mark").style.transform = `translate(${mx.toFixed(1)}px,${my.toFixed(1)}px)`;
  $("#dial-ring").style.strokeDasharray = `${Math.round((f.slot / 47) * 100)} 100`;
  $("#slot").value = f.slot;
  $("#dial-wrap").style.opacity = custom ? 0.35 : 1; $("#slot").disabled = custom; $("#earlier").disabled = custom; $("#later").disabled = custom;
  $("#when").textContent = custom ? "กำหนดเวลาด้วย cron" : `${freqWord(f)} เวลา`;
  $("#time").textContent = custom ? formCron(f) || "—" : `${slotTime(f.slot)} น.`;
  $("#dial").setAttribute("aria-label", custom ? "นาฬิกา (ไม่ใช้เมื่อกำหนดด้วย cron)" : `นาฬิกา 24 ชั่วโมง ตั้งไว้ที่ ${slotTime(f.slot)}`);
  const problem = scheduleProblem();
  $("#summary").innerHTML = problem ? `<span style="color:var(--crit);font-weight:600">${esc(problem)}</span>`
    : `จะสแกน <b class="num">${esc(formTargets(f).join(", "))}</b> ${esc(freqWord(f))}${custom ? ` (<span class="mono">${esc(formCron(f))}</span>)` : ` เวลา ${slotTime(f.slot)} น.`} ด้วยชุดพอร์ต${esc((PROFILE_TEXT[f.profile] || [""])[0])} · ครั้งถัดไป ${esc(nextRunText(f))}`;
  $("#save").innerHTML = `${isNew ? "สร้างตารางเวลา" : "บันทึกการแก้ไข"}${ic("arrow", 20, 2.2)}`;
  $("#save").disabled = !!problem;
}
async function saveSchedule() {
  const f = Z.form, btn = $("#save");
  const body = { name: f.name.trim(), targets: formTargets(f), cron: formCron(f), enabled: true, port_profile: f.profile, custom_ports: f.profile === "custom" ? f.custom : "" };
  btn.disabled = true;
  try {
    const saved = Z.cur === "new" ? await api("/api/schedules", { method: "POST", body: JSON.stringify(body) }) : await api(`/api/schedules/${encodeURIComponent(Z.cur)}`, { method: "PUT", body: JSON.stringify(body) });
    Z.items = await api("/api/schedules"); Z.cur = saved.id; loadForm(); fillForm(); paintSchedule();
    const it = Z.items.find((x) => x.id === saved.id);
    toast(`บันทึกแล้ว · ครั้งถัดไป ${fmtDate(it && it.next_run)}`);
    Z.audit = (await api("/api/audit")).entries || []; if (Z.tab === "audit") paintZTab();
  } catch (err) { toast(err.message); btn.disabled = false; }
}
function deleteSchedule() {
  const it = Z.items.find((x) => x.id === Z.cur);
  if (!it) return;
  const m = openModal(`<h2>ลบตารางเวลานี้?</h2><p class="lead">“${esc(it.name)}” จะไม่ทำงานอีก ผลการสแกนที่ผ่านมายังอยู่ในประวัติ</p>
    <div class="modal-foot"><button type="button" class="btn" data-close>ยกเลิก</button><button type="button" class="btn btn-danger" data-ok>${ic("trash", 17)}ลบ</button></div>`, "ลบตารางเวลา");
  $("[data-ok]", m.el).addEventListener("click", async () => {
    m.close();
    try {
      await api(`/api/schedules/${encodeURIComponent(it.id)}`, { method: "DELETE" });
      Z.items = await api("/api/schedules"); Z.cur = Z.items[0] ? Z.items[0].id : "new"; loadForm(); fillForm(); paintSchedule(); toast("ลบแล้ว");
      Z.audit = (await api("/api/audit")).entries || []; if (Z.tab === "audit") paintZTab();
    } catch (err) { toast(err.message); }
  });
}
function paintZTab() {
  const ids = ["scope", "audit", "about"];
  $$("[data-ztab]").forEach((t) => t.setAttribute("aria-selected", String(t.dataset.ztab === Z.tab)));
  $("#z-bar").style.transform = `translateX(${ids.indexOf(Z.tab) * 100}%)`;
  let html;
  if (Z.tab === "scope") {
    html = `<p class="notice ${cfg.enforce_scope ? "b-warn" : "b-ok"}" style="font-size:13px;margin-bottom:10px">${ic(cfg.enforce_scope ? "shield" : "check", 18)}<span>${cfg.enforce_scope ? "โหมดจำกัดขอบเขต: สแกนได้เฉพาะช่วง IP ด้านล่าง และเว็บไซต์โดเมนหน่วยงานเท่านั้น" : "โหมดเปิด: สแกนเป้าหมายใดก็ได้ที่กรอก (IP, ช่วง, หรือเว็บไซต์) ผู้ดูแลรับผิดชอบให้สแกนเฉพาะเครือข่ายที่ได้รับอนุญาต · ตั้ง THSCAN_ENFORCE_SCOPE=1 เพื่อบังคับขอบเขตตามรายการด้านล่าง"}</span></p>
      <p class="muted" style="font-size:13.5px;line-height:1.6">ช่วง IP ตั้งค่าใน <span class="mono">docker-compose.yml</span> (THSCAN_ALLOWED_CIDRS)${cfg.enforce_scope ? " — จะถูกบังคับใช้" : " — ใช้เป็นค่าตั้งต้น/คำแนะนำเมื่ออยู่โหมดเปิด"}</p>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px;margin-top:10px;font-size:13.5px">
      ${(cfg.allowed_cidrs || []).map((c) => { const b = cidrBounds(c); return `<div style="padding:10px 12px;border-radius:12px;background:var(--bg)"><b class="num">${esc(c)}</b><br><span class="muted">${b ? `${num(b.bcast - b.net + 1)} ที่อยู่` : ""}</span></div>`; }).join("")}
      <div style="padding:10px 12px;border-radius:12px;background:var(--soft)"><b>โดเมนหน่วยงาน</b><br><span class="muted">${esc((cfg.gov_suffixes || []).join(" · "))}</span></div>
      <div style="padding:10px 12px;border-radius:12px;background:var(--bg)"><b>สูงสุดต่อครั้ง</b><br><span class="muted">${num(cfg.max_targets)} ที่อยู่ · ${num(cfg.max_port_probes)} ครั้งตรวจพอร์ต</span></div>
      <div style="padding:10px 12px;border-radius:12px;background:var(--bg)"><b>พอร์ตเว็บที่ตรวจ PHP</b><br><span class="muted num">${esc((cfg.web_ports || []).join(", "))}</span></div></div>`;
  } else if (Z.tab === "audit") {
    html = Z.audit.length ? `<ol class="audit">${Z.audit.slice(0, 40).map((e) => { const a = AUDIT[e.event] || [e.event, "b-grey"]; return `<li><span class="muted num">${esc(fmtDate(e.ts))}</span><span style="min-width:0;overflow-wrap:anywhere"><span class="badge ${a[1]}" style="margin-right:6px">${esc(a[0])}</span>${auditDetail(e)}</span></li>`; }).join("")}</ol>
      <p class="muted" style="margin-top:8px;font-size:12.5px">เก็บที่ data/audit.log เพื่อตรวจสอบย้อนหลัง</p>` : `<p class="muted">ยังไม่มีบันทึก</p>`;
  } else {
    html = `<dl class="kv">
      <div><dt>เวอร์ชัน</dt><dd>v${esc(cfg.version)}</dd></div><div><dt>สัญญาอนุญาต</dt><dd>โอเพนซอร์ส ใช้ฟรี</dd></div>
      <div><dt>ข้อมูลอยู่ที่ไหน</dt><dd>ในเครื่องที่ติดตั้งเท่านั้น (data/)</dd></div><div><dt>ตรวจอะไร</dt><dd>PHP2Shell · PHP หมดอายุ · พอร์ต · header</dd></div>
      <div><dt>เขตเวลา</dt><dd>${esc(cfg.timezone || "Asia/Bangkok")}</dd></div><div><dt>ฟอนต์</dt><dd>Inter · Anuphan (SIL OFL)</dd></div></dl>`;
  }
  const p = $("#z-panel"); p.className = `tabpanel swap${Z.tswap}`; p.innerHTML = html;
}

route();

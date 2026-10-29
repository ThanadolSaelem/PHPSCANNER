/* thscan frontend — vanilla JS, no build step. */
(() => {
  "use strict";

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));
  const api = (p, opts) => fetch(p, opts).then(async (r) => {
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
    return data;
  });

  const state = {
    config: null,
    suffixes: new Set(),
    currentJob: null,
    poll: null,
    sevFilter: "all",
    search: "",
  };

  // --- Navigation --------------------------------------------------------
  function showView(name) {
    $$(".view").forEach((v) => v.classList.add("hidden"));
    $(`#view-${name}`).classList.remove("hidden");
    $$(".nav-item").forEach((n) => n.classList.toggle("active", n.dataset.view === name));
    if (name === "history") loadHistory();
  }
  $$(".nav-item").forEach((n) => n.addEventListener("click", () => showView(n.dataset.view)));

  // --- Config / suffix chips --------------------------------------------
  function renderSuffixChips() {
    const base = state.config.default_allowed_suffixes.slice();
    const extra = ["ac.th", "in.th", "net.th", "co.th"];
    const all = [...new Set([...base, ...Array.from(state.suffixes), ...extra])];
    const wrap = $("#suffixChips");
    wrap.innerHTML = "";
    all.forEach((suf) => {
      const el = document.createElement("span");
      el.className = "chip" + (state.suffixes.has(suf) ? " on" : "");
      el.textContent = "." + suf;
      el.addEventListener("click", () => {
        if (state.suffixes.has(suf)) state.suffixes.delete(suf);
        else state.suffixes.add(suf);
        renderSuffixChips();
      });
      wrap.appendChild(el);
    });
  }

  $("#customSuffix").addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      const val = e.target.value.trim().replace(/^\./, "").toLowerCase();
      if (val) { state.suffixes.add(val); e.target.value = ""; renderSuffixChips(); }
      e.preventDefault();
    }
  });

  // --- Estimate ----------------------------------------------------------
  function parseTargets() {
    return $("#targets").value.split("\n").map((s) => s.trim()).filter(Boolean);
  }
  $("#targets").addEventListener("input", updateEstimate);
  function updateEstimate() {
    const n = parseTargets().length;
    $("#estimate").textContent = n ? `${n} รายการเป้าหมาย` : "";
  }

  const exampleBtn = $("#exampleBtn");
  if (exampleBtn) exampleBtn.addEventListener("click", () => {
    $("#targets").value = "203.0.113.0/24\n198.51.100.10-198.51.100.60";
    updateEstimate();
    $("#targets").focus();
  });

  // --- Start scan --------------------------------------------------------
  $("#startBtn").addEventListener("click", startScan);
  async function startScan() {
    const err = $("#scanErr");
    err.textContent = "";
    const targets = parseTargets();
    if (!targets.length) { err.textContent = "กรุณาระบุอย่างน้อยหนึ่งช่วงเป้าหมาย"; return; }

    const ports = $("#ports").value.split(",").map((s) => parseInt(s.trim(), 10)).filter((n) => n > 0);
    const payload = {
      targets,
      allowed_suffixes: Array.from(state.suffixes),
      ports,
      concurrency: parseInt($("#concurrency").value, 10) || null,
      polite_delay_ms: parseInt($("#delay").value, 10) || 0,
      authorized: $("#authorized").checked,
      note: $("#note").value.trim(),
    };
    if (state.config.require_authorization && !payload.authorized) {
      err.textContent = "ต้องยืนยันการได้รับอนุญาตก่อนเริ่มสแกน";
      return;
    }

    $("#startBtn").disabled = true;
    try {
      const job = await api("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      state.currentJob = job.id;
      showView("results");
      startPolling(job.id);
    } catch (e) {
      err.textContent = e.message;
    } finally {
      $("#startBtn").disabled = false;
    }
  }

  // --- Polling -----------------------------------------------------------
  function startPolling(jobId) {
    if (state.poll) clearInterval(state.poll);
    const tick = async () => {
      try {
        const job = await api(`/api/scans/${jobId}`);
        renderJob(job);
        if (["completed", "failed", "cancelled"].includes(job.state)) {
          clearInterval(state.poll);
          state.poll = null;
        }
      } catch (e) { /* transient */ }
    };
    tick();
    state.poll = setInterval(tick, 1500);
  }

  // --- Render job --------------------------------------------------------
  const SEV = ["critical", "high", "medium", "low", "info"];
  function renderJob(job) {
    const p = job.progress;
    const denom = p.total_ips || 1;
    const pct = Math.min(100, Math.round((p.resolved / denom) * 100));
    const probePct = p.in_scope ? Math.round((p.probed / p.in_scope) * 100) : 0;
    $("#progressFill").style.width = (job.state === "running" ? Math.max(pct, probePct) : 100) + "%";
    $("#progressText").textContent =
      `สถานะ: ${stateLabel(job.state)} · resolve ${p.resolved}/${p.total_ips} · ` +
      `ใน scope ${p.in_scope} · probe แล้ว ${p.probed}/${p.in_scope}`;
    $("#resultMeta").textContent =
      `Job ${job.id}${job.request.note ? " · " + job.request.note : ""} · ` +
      `เริ่ม ${fmt(job.started_at)}${job.error ? " · ⚠ " + job.error : ""}`;
    $("#cancelBtn").disabled = job.state !== "running";

    renderStats(job);
    renderHosts(job);
  }

  function renderStats(job) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    let hosts = 0;
    job.hosts.forEach((h) => {
      if (h.in_scope) hosts++;
      h.services.forEach((s) => s.findings.forEach((f) => counts[f.severity]++));
    });
    const row = $("#statRow");
    row.innerHTML = "";
    const tiles = [
      ["hosts", hosts, "Hosts in scope"],
      ["critical", counts.critical, "Critical"],
      ["high", counts.high, "High"],
      ["medium", counts.medium, "Medium"],
      ["low", counts.low, "Low"],
      ["info", counts.info, "Info"],
    ];
    tiles.forEach(([cls, num, cap]) => {
      const el = document.createElement("div");
      el.className = "stat " + cls;
      el.innerHTML = `<div class="num">${num}</div><div class="cap">${cap}</div>`;
      row.appendChild(el);
    });
  }

  function hostMatchesFilter(host) {
    if (state.search) {
      const hay = [host.ip, host.hostname, ...host.services.map((s) => s.server || "")]
        .join(" ").toLowerCase();
      if (!hay.includes(state.search)) return false;
    }
    if (state.sevFilter === "all") return true;
    return host.services.some((s) => s.findings.some((f) => f.severity === state.sevFilter));
  }

  function renderHosts(job) {
    const wrap = $("#results");
    wrap.innerHTML = "";
    const hosts = job.hosts.filter(hostMatchesFilter);
    $("#emptyResults").classList.toggle("hidden",
      !(job.state !== "running" && hosts.length === 0));
    hosts.forEach((host) => wrap.appendChild(renderHost(host)));
  }

  function renderHost(host) {
    const sev = host.max_severity || "info";
    const el = document.createElement("div");
    el.className = "host " + sev;
    const tags = [];
    const svcSev = {};
    host.services.forEach((s) => s.findings.forEach((f) => { svcSev[f.severity] = (svcSev[f.severity] || 0) + 1; }));
    SEV.forEach((s) => { if (svcSev[s]) tags.push(`<span class="badge ${s}">${s} ${svcSev[s]}</span>`); });
    const php = host.services.map((s) => s.php_version).filter(Boolean)[0];
    const cms = host.services.map((s) => s.cms).filter(Boolean)[0];
    if (php) tags.push(`<span class="badge tech">PHP ${php}</span>`);
    if (cms) tags.push(`<span class="badge tech">${cms}</span>`);

    const head = document.createElement("div");
    head.className = "host-head";
    head.innerHTML =
      `<div><div class="host-title">${esc(host.hostname || "(no PTR)")}</div>` +
      `<div class="host-ip">${host.ip} · .${esc(host.matched_suffix || "")}</div></div>` +
      `<div class="host-spacer"></div><div class="host-tags">${tags.join("")}</div>`;
    head.addEventListener("click", () => el.classList.toggle("open"));
    el.appendChild(head);

    const body = document.createElement("div");
    body.className = "host-body";
    if (!host.services.length) {
      body.innerHTML = `<div class="svc muted small">ไม่พบบริการเว็บที่ตอบสนองบนพอร์ตที่ตรวจ</div>`;
    } else {
      host.services.forEach((svc) => body.appendChild(renderService(svc)));
    }
    el.appendChild(body);
    if (sev === "critical" || sev === "high") el.classList.add("open");
    return el;
  }

  function renderService(svc) {
    const el = document.createElement("div");
    el.className = "svc";
    const meta = [
      `HTTP ${svc.status_code ?? "—"}`,
      svc.server ? `Server: ${esc(svc.server)}` : "",
      svc.powered_by ? `X-Powered-By: ${esc(svc.powered_by)}` : "",
      svc.title ? `“${esc(svc.title)}”` : "",
    ].filter(Boolean);
    el.innerHTML =
      `<div class="svc-url">${esc(svc.url)}</div>` +
      `<div class="svc-meta">${meta.map((m) => `<span>${m}</span>`).join("")}</div>`;
    svc.findings.forEach((f) => el.appendChild(renderFinding(f)));
    return el;
  }

  function renderFinding(f) {
    const el = document.createElement("div");
    el.className = "finding";
    el.innerHTML =
      `<div class="finding-head">` +
      `<span class="badge ${f.severity}">${f.severity}</span>` +
      `<span class="finding-title">${esc(f.title)}</span>` +
      `<span class="badge tech">confidence: ${f.confidence}</span>` +
      (f.cve.length ? `<span class="cve">${f.cve.join(", ")}</span>` : "") +
      `</div>` +
      `<div class="finding-desc">${esc(f.description)}</div>` +
      `<div class="finding-meta">` +
      (f.evidence ? `<div><span class="kv">หลักฐาน:</span> <code>${esc(f.evidence)}</code></div>` : "") +
      (f.recommendation ? `<div><span class="kv">แนวทางแก้:</span> ${esc(f.recommendation)}</div>` : "") +
      `</div>`;
    return el;
  }

  // --- Filters -----------------------------------------------------------
  $("#searchBox").addEventListener("input", (e) => {
    state.search = e.target.value.trim().toLowerCase();
    refresh();
  });
  $$("#sevFilter button").forEach((b) => b.addEventListener("click", () => {
    $$("#sevFilter button").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    state.sevFilter = b.dataset.sev;
    refresh();
  }));
  async function refresh() {
    if (!state.currentJob) return;
    try { renderJob(await api(`/api/scans/${state.currentJob}`)); } catch (e) {}
  }

  // --- Cancel / export ---------------------------------------------------
  $("#cancelBtn").addEventListener("click", async () => {
    if (state.currentJob) await api(`/api/scans/${state.currentJob}/cancel`, { method: "POST" }).catch(() => {});
  });
  $("#exportCsv").addEventListener("click", () => {
    if (state.currentJob) window.location = `/api/scans/${state.currentJob}/export.csv`;
  });
  $("#exportJson").addEventListener("click", () => {
    if (state.currentJob) window.location = `/api/scans/${state.currentJob}/export.json`;
  });

  // --- History -----------------------------------------------------------
  async function loadHistory() {
    const list = $("#historyList");
    list.innerHTML = `<div class="muted small">กำลังโหลด…</div>`;
    try {
      const jobs = await api("/api/scans");
      if (!jobs.length) { list.innerHTML = `<div class="empty">ยังไม่มีประวัติการสแกน</div>`; return; }
      list.innerHTML = "";
      jobs.forEach((j) => {
        const sc = j.severity_counts || {};
        const el = document.createElement("div");
        el.className = "hist-item";
        el.innerHTML =
          `<span class="hist-state state-${j.state}">${stateLabel(j.state)}</span>` +
          `<div><div><strong>Job ${j.id}</strong> ${j.note ? "· " + esc(j.note) : ""}</div>` +
          `<div class="muted small">${fmt(j.created_at)} · in scope ${j.hosts_in_scope}</div></div>` +
          `<div class="host-spacer"></div>` +
          `<div class="host-tags">` +
          SEV.filter((s) => sc[s]).map((s) => `<span class="badge ${s}">${s} ${sc[s]}</span>`).join("") +
          `</div>`;
        el.addEventListener("click", () => { state.currentJob = j.id; showView("results"); startPolling(j.id); });
        list.appendChild(el);
      });
    } catch (e) { list.innerHTML = `<div class="err">${e.message}</div>`; }
  }

  // --- Helpers -----------------------------------------------------------
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  function fmt(iso) {
    if (!iso) return "—";
    const d = new Date(iso);
    return d.toLocaleString("th-TH", { dateStyle: "medium", timeStyle: "short" });
  }
  function stateLabel(s) {
    return { queued: "รอคิว", running: "กำลังสแกน", completed: "เสร็จสิ้น",
             failed: "ผิดพลาด", cancelled: "ยกเลิก" }[s] || s;
  }

  // --- Boot --------------------------------------------------------------
  (async () => {
    try {
      state.config = await api("/api/config");
      state.config.default_allowed_suffixes.forEach((s) => state.suffixes.add(s));
      $("#concurrency").value = Math.min(25, state.config.max_concurrency);
      $("#concurrency").max = state.config.max_concurrency;
      $("#versionTag").textContent = "thscan v" + state.config.version;
      if (!state.config.require_authorization) $("#authWrap").classList.add("hidden");
      renderSuffixChips();
    } catch (e) {
      $("#scanErr").textContent = "โหลดค่าตั้งต้นไม่สำเร็จ: " + e.message;
    }
  })();
})();

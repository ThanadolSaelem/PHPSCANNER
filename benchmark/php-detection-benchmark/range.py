"""PHP2Shell Detection Range — a self-contained training/benchmark range in the
spirit of OWASP Juice Shop, but for *detection* (no exploitation).

One command starts everything:
  * the target fixtures on 127.0.0.1:9001-9023 (canned HTTP responses — no PHP
    is run, no payload is sent anywhere), and
  * a live Scoreboard web UI + grading API on 127.0.0.1:9000.

You "solve" a challenge by scanning the target and submitting the php2shell
status your tool concluded; the range grades it against ground truth and the
scoreboard updates. The one failure that matters is FALSE-SAFE: calling a host
that is at-risk / needs-verification "safe".

Run:  python3 range.py     (stdlib only)   then open http://127.0.0.1:9000/
"""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cases import CASES
from fixtures import make_handler

HOST = os.environ.get("RANGE_BIND", "127.0.0.1")
BOARD_PORT = int(os.environ.get("RANGE_BOARD_PORT", "9000"))

RISK = {
    "confirmed_affected": "at_risk", "possibly_affected": "at_risk",
    "evidence_of_patch": "not_at_risk", "none": "not_at_risk",
    "undetermined": "needs_verification",
}
THSCAN_TO_DOC = {
    "affected": "confirmed_affected", "likely": "possibly_affected",
    "fixed": "evidence_of_patch", "unverified": "undetermined", "none": "none",
}

CATEGORY = {
    frozenset({"82-vuln", "82-fixed", "83-vuln", "83-fixed", "84-vuln", "84-fixed",
               "85-vuln", "85-fixed"}): ("Version boundary", "easy"),
    frozenset({"74-eol", "56-eol"}): ("EOL branch", "easy"),
    frozenset({"hidden-link", "hidden-cookie", "hidden-error", "hidden-patched"}): ("Hidden version", "medium"),
    frozenset({"nginx-fpm", "litespeed", "frankenphp"}): ("Runtime fingerprint", "medium"),
    frozenset({"wordpress-hidden", "laravel-hidden"}): ("Framework (hidden)", "medium"),
    frozenset({"cdn-stripped", "node-decoy", "static-nginx"}): ("Obstacle / decoy", "hard"),
    frozenset({"backport"}): ("Distro backport (false-positive trap)", "hard"),
}


def meta(cid):
    for ids, (cat, diff) in CATEGORY.items():
        if cid in ids:
            return cat, diff
    return "Other", "medium"


# in-memory board state: cid -> {"status": submitted_doc_status, "solved", "exact", "false_safe"}
STATE = {}
LOCK = threading.Lock()


def grade(submission):
    """submission: {port_or_id: status}. status may be the document taxonomy or
    thscan's native labels. Returns the fresh board + totals."""
    by_port = {str(c["port"]): c for c in CASES}
    by_id = {c["id"]: c for c in CASES}
    with LOCK:
        for key, raw in submission.items():
            c = by_port.get(str(key)) or by_id.get(str(key))
            if not c:
                continue
            doc = THSCAN_TO_DOC.get(raw, raw)
            exp = c["label"]
            got_risk, exp_risk = RISK.get(doc, "not_at_risk"), exp["risk"]
            fs = exp_risk in ("at_risk", "needs_verification") and got_risk == "not_at_risk"
            STATE[c["id"]] = {
                "status": doc, "exact": doc == exp["status"],
                "solved": (got_risk == exp_risk) and not fs, "false_safe": fs,
            }
    return board()


def board():
    chals = []
    for c in CASES:
        cat, diff = meta(c["id"])
        st = STATE.get(c["id"])
        chals.append({
            "id": c["id"], "title": c["title"], "port": c["port"],
            "category": cat, "difficulty": diff,
            "expected": c["label"]["status"], "risk": c["label"]["risk"],
            "note": c["label"].get("note", ""),
            "submitted": st["status"] if st else None,
            "solved": bool(st and st["solved"]),
            "exact": bool(st and st["exact"]),
            "false_safe": bool(st and st["false_safe"]),
        })
    solved = sum(x["solved"] for x in chals)
    exact = sum(x["exact"] for x in chals)
    fs = sum(x["false_safe"] for x in chals)
    attempted = sum(1 for x in chals if x["submitted"] is not None)
    return {"challenges": chals, "total": len(chals), "solved": solved,
            "exact": exact, "false_safe": fs, "attempted": attempted}


class Board(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, html):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._html(PAGE)
        elif self.path == "/api/state":
            self._json(board())
        elif self.path == "/api/reset":
            with LOCK:
                STATE.clear()
            self._json(board())
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path != "/api/grade":
            self.send_error(404)
            return
        n = int(self.headers.get("Content-Length", 0))
        try:
            sub = json.loads(self.rfile.read(n) or b"{}")
            assert isinstance(sub, dict)
        except Exception:  # noqa: BLE001
            self._json({"error": "body must be JSON {port: status}"}, 400)
            return
        self._json(grade(sub))

    def log_message(self, *a):
        pass


PAGE = r"""<!doctype html><html lang="th"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PHP2Shell Detection Range · Scoreboard</title>
<style>
:root{--bg:#0f1221;--card:#191d33;--ink:#e8ecff;--mut:#9aa3c7;--line:#2a3050;
--ok:#3ad29f;--bad:#ff6b6b;--warn:#ffcc66;--accent:#7c6cff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 system-ui,"Segoe UI",sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:24px 18px 70px}
h1{font-size:24px;margin:0 0 4px}.sub{color:var(--mut);font-size:13.5px;margin-bottom:18px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:18px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px}
.stat b{display:block;font-size:26px}.stat span{color:var(--mut);font-size:12.5px}
.fs0{color:var(--ok)}.fsbad{color:var(--bad)}
.bar{height:10px;border-radius:99px;background:#141830;overflow:hidden;margin:4px 0 0}
.bar i{display:block;height:100%;background:linear-gradient(90deg,#7c6cff,#3ad29f)}
.cat{margin:18px 0 8px;color:var(--mut);font-size:12.5px;text-transform:uppercase;letter-spacing:.06em}
.ch{display:grid;grid-template-columns:28px 1fr auto;gap:10px;align-items:center;
background:var(--card);border:1px solid var(--line);border-radius:12px;padding:10px 14px;margin-bottom:6px}
.ch.solved{border-color:#2d6b57}.ch.fs{border-color:#6b2d2d}
.dot{width:20px;height:20px;border-radius:50%;display:grid;place-items:center;font-size:12px;
background:#222846;color:var(--mut)}.dot.ok{background:#17402f;color:var(--ok)}
.dot.bad{background:#401717;color:var(--bad)}
.ti{font-weight:600}.mt{color:var(--mut);font-size:12px}
.pill{font-size:11px;padding:2px 8px;border-radius:99px;border:1px solid var(--line);color:var(--mut)}
.pill.easy{color:#9fe}.pill.medium{color:var(--warn)}.pill.hard{color:#ff9}
.right{text-align:right;font-size:12px;color:var(--mut)}
.sub-box{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px;margin:18px 0}
textarea{width:100%;height:92px;background:#0c0f1c;color:var(--ink);border:1px solid var(--line);
border-radius:10px;padding:10px;font:12.5px/1.5 ui-monospace,monospace}
button{background:var(--accent);color:#fff;border:0;border-radius:10px;padding:9px 16px;
font-weight:600;cursor:pointer;margin-top:8px}button.ghost{background:#222846;color:var(--ink)}
code{background:#0c0f1c;padding:1px 6px;border-radius:6px}
</style></head><body><div class="wrap">
<h1>🧪 PHP2Shell Detection Range</h1>
<div class="sub">สนามเป้าหมายแบบ Juice Shop สำหรับวัด <b>การตรวจจับ</b> php2shell (ไม่ยิง exploit) ·
เป้าหมายอยู่ที่ <code>127.0.0.1:9001-9023</code> · สแกนแล้วส่งผลเข้ามาเพื่อ "solve"</div>
<div class="stats">
  <div class="stat"><b id="s-solved">0</b><span>แก้แล้ว (solved)</span><div class="bar"><i id="s-pbar" style="width:0"></i></div></div>
  <div class="stat"><b id="s-exact">0</b><span>ตรงสถานะเป๊ะ (exact)</span></div>
  <div class="stat"><b id="s-fs" class="fs0">0</b><span>FALSE-SAFE (ต้องเป็น 0)</span></div>
  <div class="stat"><b id="s-att">0</b><span>ส่งผลแล้ว / ทั้งหมด</span></div>
</div>
<div class="sub-box">
  <b>วิธีเล่น</b> — 1) สแกน <code>127.0.0.1</code> พอร์ต <code>9001-9023</code> ด้วยเครื่องมือของคุณ ·
  2) วางผลเป็น JSON <code>{"9001":"affected", ...}</code> (รับสถานะ thscan หรือ taxonomy เอกสาร) · 3) กด Submit
  <textarea id="inp" placeholder='{"9001":"affected","9002":"fixed","9011":"unverified"}'></textarea>
  <button onclick="submitResults()">Submit results</button>
  <button class="ghost" onclick="reset()">Reset</button>
  <span class="mt" id="msg"></span>
</div>
<div id="list"></div>
</div>
<script>
async function load(){const r=await fetch('/api/state');render(await r.json())}
async function submitResults(){let t=document.getElementById('inp').value.trim();let o;
 try{o=JSON.parse(t)}catch(e){document.getElementById('msg').textContent='JSON ไม่ถูกต้อง';return}
 const r=await fetch('/api/grade',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(o)});
 render(await r.json());document.getElementById('msg').textContent='อัปเดตแล้ว'}
async function reset(){render(await (await fetch('/api/reset')).json());document.getElementById('msg').textContent='รีเซ็ตแล้ว'}
function esc(s){return (s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
function render(d){
 document.getElementById('s-solved').textContent=d.solved+'/'+d.total;
 document.getElementById('s-pbar').style.width=(100*d.solved/d.total)+'%';
 document.getElementById('s-exact').textContent=d.exact+'/'+d.total;
 const fs=document.getElementById('s-fs');fs.textContent=d.false_safe;fs.className=d.false_safe?'fsbad':'fs0';
 document.getElementById('s-att').textContent=d.attempted+' / '+d.total;
 const cats={};d.challenges.forEach(c=>{(cats[c.category]=cats[c.category]||[]).push(c)});
 let h='';for(const cat in cats){h+='<div class="cat">'+esc(cat)+'</div>';
  cats[cat].forEach(c=>{const cls=c.false_safe?'fs':(c.solved?'solved':'');
   const dot=c.submitted==null?'<div class="dot">·</div>':(c.false_safe?'<div class="dot bad">!</div>':(c.solved?'<div class="dot ok">✓</div>':'<div class="dot bad">✗</div>'));
   const got=c.submitted==null?'<span class="mt">ยังไม่ส่ง</span>':(c.false_safe?'<span style="color:var(--bad)">FALSE-SAFE: บอก "'+esc(c.submitted)+'"</span>':'<span class="mt">ส่ง: '+esc(c.submitted)+(c.exact?' ·เป๊ะ':'')+'</span>');
   h+='<div class="ch '+cls+'">'+dot+
      '<div><div class="ti">'+esc(c.title)+' <span class="pill '+c.difficulty+'">'+c.difficulty+'</span></div>'+
      '<div class="mt">:'+c.port+' · เป้าหมาย ground-truth = <b>'+esc(c.expected)+'</b>'+(c.note?' · '+esc(c.note):'')+'</div></div>'+
      '<div class="right">'+got+'</div></div>'})}
 document.getElementById('list').innerHTML=h}
load();
</script></body></html>"""


def main():
    servers = []
    for c in CASES:
        s = ThreadingHTTPServer((HOST, c["port"]), make_handler(c["response"], c["port"]))
        threading.Thread(target=s.serve_forever, daemon=True).start()
        servers.append(s)
    board_srv = ThreadingHTTPServer((HOST, BOARD_PORT), Board)
    print(f"targets  : http://{HOST}:{CASES[0]['port']}-{CASES[-1]['port']}", flush=True)
    print(f"scoreboard: http://{HOST}:{BOARD_PORT}/   (open in a browser)", flush=True)
    try:
        board_srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

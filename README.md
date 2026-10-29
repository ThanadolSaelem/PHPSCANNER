# thscan — Thai Government Web Vulnerability Scanner (PHP2Shell aware)

เครื่องมือสแกนหาช่องโหว่แบบ **ไม่ทำลายระบบ (non-destructive)** สำหรับทีม CERT/CSIRT
และหน่วยงานรัฐไทย ออกแบบมาเพื่อค้นหาและประเมินความเสี่ยงต่อช่องโหว่
**PHP2Shell** (`CVE-2026-109618`, `CVE-2026-109619` · CVSS 9.2) ในเว็บและบริการ
ของหน่วยงานไทย โดยเน้น **false positive ต่ำ**

> ⚠️ **ใช้เฉพาะระบบที่คุณได้รับอนุญาตให้ทดสอบเท่านั้น** การสแกนระบบของผู้อื่นโดยไม่ได้รับ
> อนุญาตอาจผิดกฎหมาย เครื่องมือนี้มีไว้ให้หน่วยงานเจ้าของระบบ และทีมที่ได้รับมอบหมาย
> (เช่น สกมช./NCSA) ใช้ตรวจทรัพย์สินของตนเอง

---

## มันทำอะไร

```
ช่วง IP ที่ได้รับอนุญาต
        │
        ▼
  reverse DNS (PTR)          ←  เทียบเท่า `nslookup -x <ip>`
        │
        ▼
  กรองเฉพาะโดเมนหน่วยงานไทย   ←  .go.th / .or.th / .mi.th (ปรับได้)
        │
        ▼
  ตรวจพอร์ตเว็บ (TCP connect) ←  80 / 443 / 8080 / 8443
        │
        ▼
  อ่าน HTTP header + หน้าเพจ  ←  ตรวจเวอร์ชัน PHP, CMS (WordPress/Drupal/Joomla)
        │
        ▼
  ประเมินช่องโหว่ด้วยการเทียบเวอร์ชัน
        │
        ▼
  รายงาน + export (CSV / JSON) + audit log
```

### ทำไม false positive ต่ำ
- **เทียบเวอร์ชันเป็นหลัก** ไม่เดาจากพฤติกรรม — เทียบ PHP ที่ตรวจพบกับรุ่นที่แพตช์แล้ว
  (`8.5.12` / `8.4.27` / `8.3.36` / `8.2.35`) ตามสาขา (branch)
- ทุก finding มี **ระดับความเชื่อมั่น (confidence)** — `confirmed` / `high` / `medium` / `low`
  ให้กรองได้
- ระบุ **หลักฐาน (evidence)** ที่ตรวจพบจริงทุกครั้ง
- ถ้าตรวจพบ PHP แต่ซ่อนเวอร์ชัน จะรายงานเป็น `info` (ต้องตรวจเพิ่มเอง) ไม่เหมาเป็นช่องโหว่

### สิ่งที่เครื่องมือนี้ **ไม่ทำ** (โดยตั้งใจ)
ไม่ส่ง exploit · ไม่ drop shell · ไม่ brute-force path/login · ไม่ส่ง payload ทำลายระบบ
— เป็นการตรวจจับเชิงป้องกันล้วน ๆ ปลอดภัยที่จะรันกับ production

---

## การติดตั้งและใช้งาน (Docker)

```bash
# build + run
docker compose up --build -d

# เปิดใช้งานที่
open http://localhost:8000
```

หรือรันด้วย Docker โดยตรง:

```bash
docker build -t thscan:1.0.0 .
docker run -d -p 8000:8000 -v thscan-data:/data thscan:1.0.0
```

### รันแบบ local (dev)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn app.main:app --reload
pytest        # รันชุดทดสอบ
```

---

## การตั้งค่า (environment variables)

| ตัวแปร | ค่าเริ่มต้น | ความหมาย |
|---|---|---|
| `THSCAN_ALLOWED_SUFFIXES` | `go.th,or.th,mi.th` | โดเมน suffix ที่จะเก็บไว้ใน scope |
| `THSCAN_MAX_TARGETS` | `65536` | จำนวน IP สูงสุดต่อการสแกน (กัน scope ใหญ่เกิน) |
| `THSCAN_MAX_CONCURRENCY` | `50` | จำนวน host ที่ probe พร้อมกันสูงสุด |
| `THSCAN_CONNECT_TIMEOUT` | `4` | timeout การเชื่อมต่อ (วินาที) |
| `THSCAN_HTTP_TIMEOUT` | `8` | timeout HTTP (วินาที) |
| `THSCAN_DNS_TIMEOUT` | `4` | timeout reverse DNS (วินาที) |
| `THSCAN_POLITE_DELAY_MS` | `0` | หน่วงเวลาต่อ host (ms) เพื่อสุภาพต่อเป้าหมาย |
| `THSCAN_WEB_PORTS` | `80,443,8080,8443` | พอร์ตเว็บที่ตรวจ |
| `THSCAN_REQUIRE_AUTH` | `true` | บังคับยืนยันการได้รับอนุญาตก่อนสแกน |
| `THSCAN_DNS_SERVERS` | *(ระบบ)* | resolver สำหรับ reverse DNS เช่น `1.1.1.1,8.8.8.8` |
| `THSCAN_DATA_DIR` | `/data` | ที่เก็บผลสแกน + audit log |

> **หมายเหตุเรื่อง DNS:** การทำ reverse DNS ต้องการ egress UDP/53 ไปยัง resolver
> ถ้าเครือข่ายปิด DNS ขาออก (เช่น sandbox บางแบบ) host จะ resolve ไม่ได้และไม่เข้า scope
> ให้ตั้ง `THSCAN_DNS_SERVERS` หรือรันในเครือข่ายที่เข้าถึง DNS ของหน่วยงานได้

---

## รูปแบบเป้าหมายที่รองรับ

| รูปแบบ | ตัวอย่าง |
|---|---|
| CIDR | `203.0.113.0/24` |
| ช่วงแบบขีด | `198.51.100.10-198.51.100.60` |
| ช่วงย่อ (octet สุดท้าย) | `198.51.100.10-60` |
| IP เดี่ยว | `203.0.113.7` |

หนึ่งรายการต่อบรรทัด บรรทัดที่ขึ้นต้นด้วย `#` จะถูกข้าม

---

## REST API

| Method | Path | ใช้ทำอะไร |
|---|---|---|
| `GET` | `/api/config` | ค่าตั้งต้น (suffix, limit, พอร์ต) |
| `POST` | `/api/scans` | เริ่มสแกน (ต้องมี `authorized: true`) |
| `GET` | `/api/scans` | รายการงานทั้งหมด |
| `GET` | `/api/scans/{id}` | ผลเต็มของงาน |
| `GET` | `/api/scans/{id}/summary` | สรุป (ใช้ poll) |
| `POST` | `/api/scans/{id}/cancel` | ยกเลิกงาน |
| `GET` | `/api/scans/{id}/export.csv` | ดาวน์โหลด CSV |
| `GET` | `/api/scans/{id}/export.json` | ดาวน์โหลด JSON |
| `GET` | `/healthz` | health check |

ตัวอย่างเริ่มสแกนผ่าน API:

```bash
curl -X POST http://localhost:8000/api/scans \
  -H 'Content-Type: application/json' \
  -d '{
        "targets": ["203.0.113.0/24"],
        "allowed_suffixes": ["go.th", "or.th"],
        "authorized": true,
        "note": "NCSA-OPS-2026-014"
      }'
```

---

## โครงสร้างโปรเจกต์

```
app/
  main.py              FastAPI app + REST API + เสิร์ฟ UI
  config.py            ค่าตั้งค่า + safety rails
  models.py            โมเดลข้อมูล (Pydantic)
  store.py             คิวงาน + รันเบื้องหลัง + export
  audit.py             audit log (append-only)
  scanner/
    ip_utils.py        แตกช่วง IP (sizing แบบ arithmetic, fail fast)
    dns_resolver.py    reverse DNS + กรอง scope (ตรวจขอบเขต label)
    port_scanner.py    TCP connect scan
    http_probe.py      probe HTTP(S) แบบไม่ทำลาย (ต่อผ่าน IP + Host header)
    vuln_rules.py      กฎช่องโหว่ (PHP2Shell + hygiene) — เทียบเวอร์ชัน
    engine.py          orchestration ของงานสแกน
static/                UI (HTML/CSS/JS, ไม่พึ่ง CDN — ใช้ใน air-gap ได้)
tests/                 unit tests (ip, version logic, scope filter)
```

## การแก้ไข (remediation)

พบ PHP2Shell → อัปเดต PHP เป็นรุ่นที่แพตช์: **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**
หรือใหม่กว่าในสาขาเดียวกัน · สาขา EOL (< 8.2) ต้องย้ายไปรุ่นที่ยังรองรับ ·
ระหว่างรอแพตช์ ใช้มาตรการ WAF/mitigation ของผู้ให้บริการ

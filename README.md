# thscan — เครื่องสแกนช่องโหว่เครือข่าย (PHP2Shell / ThaiCERT)

เครื่องมือ **self-host ใช้งานฟรี** สำหรับหน่วยงาน/ทีม CERT–CSIRT ไทย ใช้ค้นหาอุปกรณ์ใน
เครือข่ายของตน แล้วคัดกรองความปลอดภัยของบริการเว็บ/PHP โดยเน้นช่องโหว่
**PHP2Shell** (`CVE-2026-109618`, `CVE-2026-109619` · CVSS 9.2) พร้อมการประเมินตามเกณฑ์
**ThaiCERT** การตรวจเป็นแบบ **ไม่ทำลายระบบ** และ **false positive ต่ำ**

UI โทน Gov-AI (AiPASS-inspired) ออกแบบให้ผู้ใช้ทุกระดับใช้ได้ — มีไอคอน ⓘ อธิบายศัพท์
ทุกจุด, ช่องกรอกเป้าหมายแบบลดการพิมพ์ (auto-detect วง LAN / preset), และหน้าแสดงผล
แบบ triage + master-detail

> ⚠️ **ใช้เฉพาะเครือข่ายที่คุณมีสิทธิ์ดูแลเท่านั้น** การสแกนระบบที่ไม่ได้รับอนุญาตอาจผิดกฎหมาย

---

## การควบคุมการเข้าถึง (สำคัญ)

เครื่องมือนี้ **ไม่มี** ปุ่มติ๊ก "ยืนยันว่าได้รับอนุญาต" แบบเดิม เพราะบังคับใช้จริงไม่ได้
การควบคุมที่มีความหมายคือ:

- **ขอบเขต (scope) ที่กำหนดตอน deploy** — `THSCAN_ALLOWED_CIDRS` ระบุว่าinstanceนี้สแกน
  ช่วงไหนได้บ้าง ช่วงที่อยู่นอกขอบเขตจะถูก API ปฏิเสธ (403) ค่าเริ่มต้นคือช่วง private เท่านั้น
- **ตรวจอินพุตฝั่งเซิร์ฟเวอร์** — ตรวจ IPv4/0–255, จำกัดจำนวนเป้าหมาย, ค่าไม่ถูกส่งเข้า shell
- **การยิงสัญญาณเป็น TCP connect แบบไม่ทำลาย** + timeout + จำกัด concurrency
- **audit log** บันทึกทุกการสแกน

---

## การทำงาน

```
ช่วงเป้าหมาย (ภายใน scope)
  → liveness + latency (TCP connect — connection refused ก็ถือว่าออนไลน์)
  → MAC จาก ARP table (เฉพาะเครื่องในวง L2 เดียวกัน)
  → สแกนพอร์ตเว็บ → probe HTTP(S) อ่าน header (PHP/Server/CMS)
  → เทียบเวอร์ชัน PHP กับรุ่นที่แพตช์ (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35)
  → สรุปเป็นอุปกรณ์ + ระดับความรุนแรง + ประโยคประเมินตามเกณฑ์ ThaiCERT
```

ข้อมูลต่ออุปกรณ์: IP, MAC, ประเภทอุปกรณ์, บริการ, เวอร์ชัน PHP, พอร์ตที่เปิด, latency,
ระดับความรุนแรง, การประเมิน ThaiCERT และ finding (พร้อม CVE/หลักฐาน/แนวทางแก้)

> **หมายเหตุเรื่อง MAC/สิทธิ์:** MAC อ่านจาก ARP table ของเคอร์เนล จึงเห็นเฉพาะอุปกรณ์ที่อยู่
> ในวงบรอดแคสต์เดียวกับเครื่องที่รัน thscan ข้ามเราเตอร์จะว่าง เทคนิคทั้งหมดไม่ต้องใช้ raw
> socket/สิทธิ์พิเศษ

---

## รันด้วย Docker

```bash
docker compose up --build -d      # → http://localhost:8000
```

ตั้งขอบเขตให้ตรงกับเครือข่ายที่คุณดูแลใน `docker-compose.yml`:

```yaml
environment:
  THSCAN_ALLOWED_CIDRS: "192.168.10.0/24,10.20.0.0/16"   # <- แก้เป็นของคุณ
```

### รันแบบ local (dev)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn app.main:app --reload
pytest
```

---

## การตั้งค่า (environment variables)

| ตัวแปร | ค่าเริ่มต้น | ความหมาย |
|---|---|---|
| `THSCAN_ALLOWED_CIDRS` | `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16` | **ขอบเขตที่สแกนได้** (เฉพาะช่วงเหล่านี้) |
| `THSCAN_MAX_TARGETS` | `65536` | จำนวน IP สูงสุดต่อการสแกน |
| `THSCAN_MAX_CONCURRENCY` | `50` | จำนวนงานที่ตรวจพร้อมกันสูงสุด |
| `THSCAN_CONNECT_TIMEOUT` | `1.5` | timeout การเชื่อมต่อ (วินาที) |
| `THSCAN_HTTP_TIMEOUT` | `6` | timeout HTTP (วินาที) |
| `THSCAN_WEB_PORTS` | `80,443,8080,8443` | พอร์ตเว็บที่ตรวจ PHP |
| `THSCAN_LIVENESS_PORTS` | `22,445,3389,53` | พอร์ตเสริมที่ใช้ตรวจว่าเครื่องออนไลน์ |
| `THSCAN_POLITE_DELAY_MS` | `0` | หน่วงต่อ host (ms) |
| `THSCAN_DEFAULT_SUBNET` | *(ไม่มี)* | ซับเน็ตสำรองสำหรับ auto-detect เมื่อหาเองไม่ได้ |
| `THSCAN_DATA_DIR` | `/data` | ที่เก็บผลสแกน + audit log |

---

## รูปแบบเป้าหมาย

| รูปแบบ | ตัวอย่าง |
|---|---|
| CIDR | `10.255.252.0/22` |
| ช่วงแบบขีด | `192.168.1.10-192.168.1.50` (หรือ `192.168.1.10-50`) |
| IP เดียว | `192.168.1.20` |

## REST API

| Method | Path | ใช้ทำอะไร |
|---|---|---|
| `GET` | `/api/config` | ค่าตั้งต้น (web_ports, limit, scope) |
| `GET` | `/api/autodetect` | ซับเน็ตของเครื่องนี้ (สำหรับโหมด auto) |
| `POST` | `/api/scans` | เริ่มสแกน `{ "targets": ["10.0.0.0/24"] }` (ตรวจ scope) |
| `GET` | `/api/scans/{id}` | ผลเต็ม (รายการอุปกรณ์) |
| `GET` | `/api/scans/{id}/summary` | สรุป (ใช้ poll ระหว่างสแกน) |
| `POST` | `/api/scans/{id}/cancel` | ยกเลิก |
| `GET` | `/api/scans/{id}/export.csv` | ดาวน์โหลด CSV ทั้งชุด |
| `GET` | `/healthz` | health check |

---

## หน้าจอแอป

1. **สแกน** — เลือกเป้าหมายแบบลดการพิมพ์ (วง LAN อัตโนมัติ / ซับเน็ต / ช่วง / IP เดียว) พร้อมสรุปสด + ตรวจ scope
2. **กำลังสแกน** — วงแหวน progress เคลื่อนไหว, จำนวนที่ตรวจแล้ว/ออนไลน์/เสี่ยง
3. **ผลการสแกน** — triage (เครื่องเสี่ยงเด่นก่อน) + รายการซ้าย/รายละเอียดขวา, ค้นหา, ตัวกรอง + ตัวกรองขั้นสูง, Export CSV
4. **โปรไฟล์** — ขอบเขต scope, ลิมิต, ตั้งค่า

ทุกหัวข้อเทคนิคมีไอคอน **ⓘ** ชี้/แตะดูคำอธิบายภาษาคนทั่วไป

## โครงสร้างโปรเจกต์

```
app/
  main.py              FastAPI + REST API + เสิร์ฟ UI
  config.py            scope allowlist + safety rails
  models.py            Device / ScanJob (Pydantic)
  store.py             คิวงาน + รันเบื้องหลัง + export + audit
  scanner/
    ip_utils.py        แตกช่วง IP + ตรวจ scope (sizing แบบ arithmetic)
    discovery.py       liveness/latency, MAC (ARP), device-type, autodetect
    port_scanner.py    TCP connect scan
    http_probe.py      probe HTTP(S) แบบไม่ทำลาย
    vuln_rules.py      PHP2Shell + การประเมิน ThaiCERT
    engine.py          orchestration
static/                UI (Gov-AI, ไม่พึ่ง CDN — ใช้ใน air-gap ได้)
tests/                 unit tests
```

## การแก้ไข (remediation)

พบ PHP2Shell → อัปเดต PHP เป็น **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35** หรือใหม่กว่าในสาขาเดียวกัน ·
สาขา EOL (< 8.2) ย้ายไปรุ่นที่รองรับ · ระหว่างรอแพตช์ใช้มาตรการ WAF/mitigation

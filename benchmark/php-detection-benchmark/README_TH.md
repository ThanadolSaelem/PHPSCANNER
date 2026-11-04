# PHP2Shell Detection Benchmark (ชุดวัดความแม่นยำการตรวจ)

ชุดวัดผล **การตรวจจับ** ช่องโหว่ PHP2Shell (CVE-2026-109618 / CVE-2026-109619) สำหรับ
เครื่องมือสแกน — ใช้ตรวจว่าเครื่องมือจัดสถานะเครื่องได้ถูกต้องตาม **แนวทางเอกสาร
cloud-provider audit** หรือไม่ (เน้นหลักฐานเวอร์ชัน/แพตช์ ไม่ทดสอบ exploit)

> ⚠️ **นี่ไม่ใช่ exploit และไม่ใช่หลักฐาน code execution** — fixtures เป็นแค่ HTTP response
> ที่กำหนดไว้ล่วงหน้า เสิร์ฟบน `127.0.0.1` เท่านั้น ไม่รัน PHP จริงและไม่ส่ง payload ไปที่ใด
> "ยืนยันได้รับผลกระทบ (confirmed)" **ไม่ใช่** สถานะที่สรุปได้จาก banner ภายนอกเพียงอย่างเดียว

## วัดอะไร (metrics)

| ตัวชี้วัด | ความหมาย |
|---|---|
| **FALSE-SAFE** | จำนวนเครื่องที่ควร "เสี่ยง/ต้องตรวจต่อ" แต่เครื่องมือบอก "ปลอดภัย" — **ต้องเป็น 0** (หัวใจเอกสาร) |
| risk-class accuracy | จัดกลุ่มหยาบถูกไหม: at_risk / not_at_risk / needs_verification |
| exact-status accuracy | ตรงสถานะละเอียดตามเอกสารไหม (เข้มกว่า) |
| precision / recall | ของคลาส "at_risk" |
| runtime / CMS accuracy | อ่าน runtime (PHP/Node) และ CMS ถูกไหม |

## สถานะ 4 แบบ (taxonomy ตามเอกสาร)

- `possibly_affected` — banner เผยเวอร์ชันต่ำกว่าจุดแพตช์ของสาขา (เป็น candidate)
- `evidence_of_patch` — banner เผยเวอร์ชันที่อยู่ที่/สูงกว่าจุดแพตช์
- `undetermined` — พบ PHP แต่ซ่อนเวอร์ชัน หรือหลักฐานไม่น่าเชื่อถือ → **ห้ามสรุปว่าปลอดภัย**
- `none` — ไม่มีหลักฐาน PHP ที่เชื่อถือได้
- `confirmed_affected` — ได้เฉพาะเมื่อมี **หลักฐานภายในที่ได้รับอนุญาต** (ยืนยันว่าไม่มี backport) — ไม่ใช่จาก banner

## ครอบคลุม 23 เคส

- **ทุกสาขาที่รองรับ** 8.2 / 8.3 / 8.4 / 8.5 — คู่ "ต่ำกว่า 1 ขั้น vs รุ่นแพตช์"
- **สาขา EOL**: 7.4, 5.6
- **ซ่อนเวอร์ชัน** หลายสัญญาณ: ลิงก์ `.php`, คุกกี้ PHPSESSID, error page ของ PHP, patched-แต่-ซ่อน
- **runtime หลากหลาย**: Apache mod_php, nginx+PHP-FPM, LiteSpeed, FrankenPHP (Caddy)
- **framework ซ่อนเวอร์ชัน**: WordPress, Laravel (ต้องไม่ถูกมองว่าปลอดภัย)
- **อุปสรรคจริง / decoy**: หลัง CDN ตัด header, Node.js/Express, static site
- **❗distro backport**: เลขเวอร์ชันเก่าแต่แพตช์แล้ว — ภายนอกต้องขึ้น "possibly" ไม่ใช่ "confirmed"

ความจริง (ground truth) ของแต่ละเคสอยู่ใน [`cases.py`](cases.py) (ไฟล์เดียว ใช้ทั้งเสิร์ฟและให้คะแนน)

## วิธีรัน

**รันได้ด้วยตัวเอง — ใช้แค่ `python3` ไม่ต้องมี thscan หรือ dependency ใด** (คัดลอกเฉพาะโฟลเดอร์นี้ไปก็พอ)

```sh
python3 fixtures.py &      # เสิร์ฟ 23 เป้าหมายบน 127.0.0.1:9001-9023
python3 evaluate.py        # ให้คะแนน "reference detector" ในตัว (เกณฑ์ตามเอกสาร)
```

หรือคำสั่งเดียว:

```sh
PYTHON=python3 ./run.sh
```

### วัดเครื่องมืออื่น (เช่น thscan) ด้วย `--results`

ให้เครื่องมือสแกน `127.0.0.1:9001-9023` แล้วสร้างไฟล์ผลลัพธ์ `{พอร์ต: สถานะ}` แล้วป้อนเข้ามา:

```sh
python3 evaluate.py --results tool.json
```

`tool.json` รับได้ทั้ง taxonomy ของเอกสาร (`possibly_affected` ฯลฯ) หรือสถานะของ thscan
(`affected / likely / fixed / unverified / none`) — ระบบ map ให้เอง · พอร์ตที่เครื่องมือไม่รายงาน
ถือเป็น `none` และจะถูกจับ FALSE-SAFE ถ้าควรเสี่ยง
ตัวอย่างสร้างจาก thscan: ดึง `GET /api/scans/<id>` แล้วแมป `ip:port → php_status` ของแต่ละ device

**แบบ Docker (เผยแพร่ ให้ reproducible)**:

```sh
./pin-digests.sh && docker compose up -d && python3 evaluate.py && docker compose down
```

ทุกพอร์ต bind ที่ `127.0.0.1` เท่านั้น — ไม่เปิดสู่ LAN หรืออินเทอร์เน็ต

### ดู "ตรวจถึงไหนแล้ว" แบบเรียลไทม์

ปกติ fixtures เงียบ (เพื่อให้ผลของ harness สะอาด) ถ้าอยากเห็น log ไหลตามจริงว่า scanner
แตะเป้าหมายไหนแล้วบ้าง ให้เปิด `FIXTURE_LOG=1`:

```sh
FIXTURE_LOG=1 python3 fixtures.py        # แยกหน้าต่าง แล้วค่อยสแกน
# หรือใน docker: ตั้ง FIXTURE_LOG=1 ใน docker-compose.yml แล้ว `docker compose logs -f`
```

แต่ละบรรทัดจะบอก พอร์ต · path · ผู้ยิง · และ ground-truth ของเป้านั้น เช่น
`:9001 GET / <- 127.0.0.1 [82-vuln: PHP 8.2.34 · ground-truth=possibly_affected]`
— ใช้ยืนยันว่า scanner เข้าถึงครบทุกเป้าหมาย (ไม่ได้พลาดพอร์ตไหน)

> หมายเหตุ: log ของ container บอกแค่ "มีการยิงมา" ไม่ได้บอก "เครื่องมือสรุปสถานะอะไร" —
> ผลการตัดสิน (ตรวจได้สถานะไหน ผ่าน/ไม่ผ่าน) ดูที่ output ของ `evaluate.py` เท่านั้น

## ชั้นเสริม "ของจริง" (authenticity) — ไม่บังคับ

`fixtures.py` เสิร์ฟ response ที่กำหนดไว้ (ควบคุมได้ครบ แต่ไม่ได้รัน PHP จริง) ถ้าต้องการ
banner จาก PHP จริง ใช้ overlay ใน [`real-php/`](real-php/) ซึ่งรัน official `php:*` image หลาย
เวอร์ชัน (pin digest ก่อนใช้) และมี [`real-php/ubuntu-backport/`](real-php/ubuntu-backport/)
สำหรับจำลองเคส distro backport (official php image ทำไม่ได้) — ยืนยันเวอร์ชันหลัง build ด้วย
`php -r 'echo PHP_VERSION;'` และ `dpkg -l | grep php`

## การตีความผล (สำคัญ)

- **FALSE-SAFE = 0 คือเกณฑ์ผ่านด้านความปลอดภัย** ที่ขาดไม่ได้ (เอกสารห้ามสรุปว่าปลอดภัยเมื่อยังยืนยันไม่ได้)
- `status-dev` = เครื่องมืออ่าน banner เวอร์ชันต่ำแล้วขึ้น "confirmed" ทันที ขณะที่เอกสารสงวน
  "confirmed" ไว้ให้หลักฐานภายใน — **กลุ่มความเสี่ยงเดียวกัน ต่างแค่ถ้อยคำ** ไม่ใช่บั๊กความปลอดภัย
- เคส `backport` และ `cdn-stripped` เตือนขีดจำกัดของการสแกนภายนอก: เลขเวอร์ชันเชื่อ 100% ไม่ได้
  และหลัง CDN อาจมี PHP ที่มองไม่เห็น — ต้องยืนยันภายในเสมอก่อนสรุป

## ข้อจำกัด / สิ่งที่ยังไม่ครอบคลุม

- liveness/middlebox ที่ตอบแทนทุกที่อยู่ (เป็นเรื่องการค้นหาโฮสต์ ไม่ใช่การตรวจรายเครื่อง)
- การยืนยันภายในจริง (agent/snapshot) — benchmark นี้วัด **การตรวจจากภายนอก** เท่านั้น
- ตัวเลขเวอร์ชันอ้างอิงประกาศ PHP upstream สำหรับ CVE ชุดนี้ (ดู [SOURCES.md](SOURCES.md)) —
  งานจริงต้องตรวจ advisory ของ distro/vendor ประกอบเสมอ

benchmark นี้ช่วย **วัดและเทียบเครื่องมือ** ไม่ได้แทนการประเมินระบบจริงหรือการตรวจเงื่อนไข
เวอร์ชันจากเอกสาร audit ของผู้ให้บริการคลาวด์

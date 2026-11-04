# ห้องทดลองตรวจคัดกรอง PHP Version สำหรับ thscan

ห้องทดลองนี้มีเว็บทดสอบ 3 เป้าหมาย ใช้ตรวจสอบการค้นหา PHP และอ่านเวอร์ชันผ่าน HTTP แบบไม่ส่ง payload สำหรับ exploit:

| Service | URL บนเครื่อง | Runtime / การตั้งค่า | สัญญาณที่คาดหวัง |
|---|---|---|---|
| `php-affected-visible` | `http://127.0.0.1:8080/` | PHP 8.2.34, `expose_php=On` | เห็น PHP version ใน `X-Powered-By` |
| `php-patched-visible` | `http://127.0.0.1:8081/` | PHP 8.2.35, `expose_php=On` | เห็นเวอร์ชันที่แก้ไขแล้ว |
| `php-affected-hidden` | `http://127.0.0.1:8082/` | PHP 8.2.34, `expose_php=Off` | พบสัญญาณ PHP จากลิงก์ `.php` แต่ไม่เปิดเผยเวอร์ชัน |

ใช้อิมเมจ official Docker Library และ pin ด้วย manifest digest แล้ว เกณฑ์เวอร์ชันอ้างอิง PHP upstream security release สำหรับ CVE-2026-109618 และ CVE-2026-109619 รายละเอียดแหล่งข้อมูลและ digest อยู่ใน [SOURCES.md](SOURCES.md) ห้องทดลองนี้ไม่ส่ง exploit payload และไม่ใช่หลักฐานยืนยัน code execution หรือผลประเมินระบบจริง

## เริ่มและตรวจสอบห้องทดลอง

รันจากไดเรกทอรีนี้:

```sh
docker compose up -d
docker compose ps
curl -sSI http://127.0.0.1:8080/ | grep -i '^X-Powered-By:'
curl -sSI http://127.0.0.1:8081/ | grep -i '^X-Powered-By:'
curl -sSI http://127.0.0.1:8082/ | grep -i '^X-Powered-By:' || true
```

สองเป้าหมายแรกควรแสดง PHP 8.2.34 และ 8.2.35 ตามลำดับ เป้าหมายที่สามไม่ควรส่ง header `X-Powered-By`; แต่หน้าเว็บมีลิงก์ `/health.php` เพื่อให้ scanner เห็นสัญญาณว่าใช้ PHP โดยยังระบุเวอร์ชันไม่ได้

ตรวจเวอร์ชัน runtime ภายใน container ได้ด้วย:

```sh
docker compose exec php-affected-visible php -r 'echo PHP_VERSION, "\\n";'
docker compose exec php-patched-visible php -r 'echo PHP_VERSION, "\\n";'
docker compose exec php-affected-hidden php -r 'echo PHP_VERSION, "\\n";'
```

## สแกนด้วย thscan

เปิด thscan บนเครื่องเดียวกับ Docker แล้วเลือก **Fast scan**, กำหนดเป้าหมาย `127.0.0.1` และ custom ports `8080,8081,8082` ปิด RCE Verify และ LAN fingerprinting สำหรับการทดสอบคัดกรองเวอร์ชันนี้ หากเปิดการบังคับ scope ให้ใช้ค่าทดสอบชั่วคราวที่อนุญาตเฉพาะ `127.0.0.1/32` เท่านั้น ห้ามขยาย scope ของการสแกนระบบจริงหรือ cloud provider เพื่อทดสอบนี้

หาก thscan ทำงานใน container แยกต่างหาก `127.0.0.1` จะหมายถึงตัว container เอง ไม่ใช่ host ที่รัน Docker; ให้รัน thscan บน host หรือกำหนดเส้นทางใน lab ที่แยกและจำกัดชัดเจน อย่าแก้โดยเปิดพอร์ตไปยัง `0.0.0.0`

## การแมปผลลัพธ์ตาม 4 สถานะในเอกสารตรวจประเมิน

| สถานะ | กรณีในห้องทดลอง / หลักฐาน | การแปลผลอย่างระมัดระวัง |
|---|---|---|
| **Confirmed Affected** | ต้องมีหลักฐาน runtime/package inventory ที่ได้รับอนุญาต ยืนยันว่า workload ใช้ PHP build ที่ได้รับผลกระทบจริง และไม่มี vendor backport ที่ใช้ได้ | HTTP banner เพียงอย่างเดียวไม่เพียงพอให้สรุปสถานะนี้ ห้องทดลองนี้ไม่ได้สร้างหลักฐาน guest inventory, provider evidence หรือ exploit proof |
| **Possibly Affected** | `php-affected-visible` เปิดเผย PHP 8.2.34 | เวอร์ชันต่ำกว่า upstream fixed release จึงเป็น candidate ที่ควรตรวจต่อ แต่ยังต้องยืนยัน package provenance/backport และ runtime ที่ให้บริการ cloud endpoint |
| **Evidence of Patch** | `php-patched-visible` เปิดเผย PHP 8.2.35 | เป็นหลักฐานว่า PHP upstream branch ที่สังเกตได้อยู่ที่ fixed release; สำหรับแพ็กเกจจาก distro ให้ตรวจ advisory/revision ของ vendor เพิ่ม เพราะอาจมี backport |
| **Undetermined** | `php-affected-hidden` ส่งสัญญาณว่าเป็น PHP ผ่านลิงก์ `.php` แต่ปิดบังเวอร์ชัน หรือไม่มีหลักฐาน PHP/version ที่เชื่อถือได้ | ห้ามสรุปว่าปลอดภัยหรือได้รับผลกระทบ ให้เก็บหลักฐาน runtime/package จากช่องทางที่ได้รับอนุญาต |

ต้องตรวจ cutoff ที่ถูกต้องตาม PHP branch และ vendor advisory ที่เกี่ยวข้องในงานจริง ตัวเลขในห้องทดลองนี้ใช้สาธิตการจัดกลุ่มผล ไม่ใช่การแทนที่การตรวจเงื่อนไขเวอร์ชันจากเอกสาร cloud-provider audit โดยเฉพาะสถานะ **Confirmed Affected** ต้องอาศัยหลักฐานที่ยืนยัน runtime จริง ไม่ใช่การอนุมานจาก banner

## ปิดห้องทดลอง

```sh
docker compose down
```

ทุกพอร์ต bind อยู่ที่ `127.0.0.1` อย่าแก้เป็น `0.0.0.0` หรือเปิด runtime ที่ตั้งใจให้เป็นเวอร์ชันเก่าออกสู่ LAN, cloud VPC หรืออินเทอร์เน็ตสาธารณะ

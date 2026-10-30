"""Port profiles, custom port lists and plain-language service descriptions.

The port scan is a TCP connect check only. Open ports are reported as
information with a short note; they never raise a device's severity, so a
normal file server with SMB open is not flagged as "vulnerable".
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

MAX_CUSTOM_PORTS = 1024

# Ports that speak a known non-HTTP protocol. An open port NOT in this set is
# worth an HTTP probe (so PHP on a non-standard port like 18080 is read), while
# sending an HTTP GET to SSH / a database here would be pointless noise.
NON_WEB_PORTS = frozenset({
    22, 23, 25, 53, 110, 111, 135, 137, 138, 139, 143, 161, 389, 445,
    465, 514, 587, 636, 993, 995, 1433, 1521, 1723, 2049,
    3306, 3389, 5432, 5900, 5901, 6379, 11211, 27017,
})

COMMON = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 993, 995,
          1433, 1521, 2049, 2375, 3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443,
          9200, 11211, 27017]

TOP100 = [7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
          119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
          515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
          1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
          2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
          5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
          8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152,
          49153, 49154, 49155, 49156, 49157]

PROFILES = {
    "web": "เฉพาะพอร์ตเว็บ",
    "common": "พอร์ตที่ใช้บ่อย",
    "top100": "100 พอร์ตยอดนิยม",
    "custom": "กำหนดเอง",
}

_DB = "ฐานข้อมูลไม่ควรเปิดให้เครื่องทั่วไปในเครือข่ายเข้าถึง ควรจำกัดเฉพาะเครื่องแอปที่ใช้งาน"
# port -> (service, what it is, caution note or None)
SERVICES: Dict[int, Tuple[str, str, Optional[str]]] = {
    21: ("FTP", "รับส่งไฟล์", "ส่งรหัสผ่านแบบไม่เข้ารหัส ควรเปลี่ยนไปใช้ SFTP หรือ FTPS"),
    22: ("SSH", "เข้าควบคุมเครื่องจากระยะไกล (เข้ารหัส)", None),
    23: ("Telnet", "เข้าควบคุมเครื่องจากระยะไกล (ไม่เข้ารหัส)", "ข้อมูลและรหัสผ่านไม่เข้ารหัส ควรปิดและใช้ SSH แทน"),
    25: ("SMTP", "ส่งอีเมล", None),
    53: ("DNS", "บริการชื่อโดเมน", None),
    80: ("HTTP", "เว็บ (ไม่เข้ารหัส)", None),
    81: ("HTTP", "เว็บ (พอร์ตสำรอง)", None),
    88: ("Kerberos", "ยืนยันตัวตนของโดเมน Windows", None),
    110: ("POP3", "รับอีเมล (ไม่เข้ารหัส)", None),
    111: ("RPCbind", "บริการ RPC ของ Unix/NFS", "ควรเปิดเฉพาะเครื่องที่ให้บริการ NFS"),
    135: ("MS-RPC", "บริการ RPC ของ Windows", None),
    139: ("NetBIOS", "แชร์ไฟล์ Windows (รุ่นเก่า)", None),
    143: ("IMAP", "รับอีเมล", None),
    389: ("LDAP", "บริการรายชื่อผู้ใช้ (Active Directory)", None),
    443: ("HTTPS", "เว็บ (เข้ารหัส)", None),
    445: ("SMB", "แชร์ไฟล์และเครื่องพิมพ์ Windows", "ควรเปิดเฉพาะเครื่องที่ต้องแชร์ไฟล์ และอัปเดตแพตช์ให้ครบ"),
    465: ("SMTPS", "ส่งอีเมล (เข้ารหัส)", None),
    587: ("SMTP", "ส่งอีเมลจากโปรแกรมอีเมล", None),
    631: ("IPP", "เครื่องพิมพ์", None),
    873: ("rsync", "สำรอง/ซิงก์ไฟล์", "ตรวจว่าต้องใช้รหัสผ่านก่อนเข้าถึงข้อมูล"),
    993: ("IMAPS", "รับอีเมล (เข้ารหัส)", None),
    995: ("POP3S", "รับอีเมล (เข้ารหัส)", None),
    1433: ("MS SQL", "ฐานข้อมูล Microsoft SQL Server", _DB),
    1521: ("Oracle", "ฐานข้อมูล Oracle", _DB),
    1723: ("PPTP", "VPN รุ่นเก่า", "PPTP ถือว่าไม่ปลอดภัยแล้ว ควรเปลี่ยนเป็น VPN แบบอื่น"),
    2049: ("NFS", "แชร์ไฟล์ Unix", "ควรจำกัดเครื่องที่เข้าถึงได้"),
    2375: ("Docker API", "ควบคุม Docker แบบไม่เข้ารหัส", "อันตรายมาก ผู้ที่เข้าถึงพอร์ตนี้ควบคุมเครื่องได้ทั้งเครื่อง ควรปิดหรือใช้ TLS (2376)"),
    3000: ("HTTP", "เว็บแอป/ระบบพัฒนา", None),
    3128: ("Proxy", "พร็อกซีเว็บ (Squid)", None),
    3306: ("MySQL", "ฐานข้อมูล MySQL / MariaDB", _DB),
    3389: ("RDP", "เดสก์ท็อประยะไกลของ Windows", "ควรเข้าถึงผ่าน VPN เท่านั้น เปิด NLA และอัปเดตแพตช์"),
    5000: ("HTTP", "เว็บแอป/ระบบพัฒนา", None),
    5060: ("SIP", "โทรศัพท์ VoIP", None),
    5432: ("PostgreSQL", "ฐานข้อมูล PostgreSQL", _DB),
    5800: ("VNC (เว็บ)", "เดสก์ท็อประยะไกล VNC ผ่านเว็บ", "ควรมีรหัสผ่านที่แข็งแรงและเข้าถึงผ่าน VPN"),
    5900: ("VNC", "เดสก์ท็อประยะไกล VNC", "ควรมีรหัสผ่านที่แข็งแรงและเข้าถึงผ่าน VPN"),
    5985: ("WinRM", "ควบคุม Windows จากระยะไกล", "ควรเปิดเฉพาะเครื่องผู้ดูแลระบบ"),
    6379: ("Redis", "ฐานข้อมูลในหน่วยความจำ", "Redis หลายระบบไม่มีรหัสผ่าน ควรจำกัดการเข้าถึงและตั้งรหัสผ่าน"),
    8000: ("HTTP", "เว็บ (พอร์ตสำรอง)", None),
    8008: ("HTTP", "เว็บ (พอร์ตสำรอง)", None),
    8080: ("HTTP", "เว็บ (พอร์ตสำรอง/พร็อกซี)", None),
    8081: ("HTTP", "เว็บ (พอร์ตสำรอง)", None),
    8443: ("HTTPS", "เว็บ (พอร์ตสำรอง เข้ารหัส)", None),
    8888: ("HTTP", "เว็บ (พอร์ตสำรอง)", None),
    9100: ("JetDirect", "พิมพ์งานผ่านเครือข่าย", None),
    9200: ("Elasticsearch", "ฐานข้อมูลค้นหา", "รุ่นที่ไม่ได้ตั้งค่าความปลอดภัยเปิดให้อ่านข้อมูลได้ ควรเปิดการยืนยันตัวตน"),
    10000: ("Webmin", "หน้าจัดการเซิร์ฟเวอร์ผ่านเว็บ", "ควรเปิดเฉพาะเครื่องผู้ดูแลระบบ"),
    11211: ("Memcached", "แคชข้อมูล", "ไม่มีการยืนยันตัวตน ควรจำกัดการเข้าถึง"),
    27017: ("MongoDB", "ฐานข้อมูล MongoDB", _DB),
}


class PortSpecError(ValueError):
    pass


def parse_ports(spec: str, limit: int = MAX_CUSTOM_PORTS) -> List[int]:
    """Parse ``"22, 80, 8000-8010"`` into a sorted list of unique ports."""
    out: set[int] = set()
    for part in spec.replace(";", ",").replace(" ", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            if not (a.strip().isdigit() and b.strip().isdigit()):
                raise PortSpecError(f"ช่วงพอร์ตไม่ถูกต้อง: {part}")
            lo, hi = int(a), int(b)
            if hi < lo:
                raise PortSpecError(f"ช่วงพอร์ตกลับด้าน: {part}")
        elif part.isdigit():
            lo = hi = int(part)
        else:
            raise PortSpecError(f"พอร์ตไม่ถูกต้อง: {part}")
        if lo < 1 or hi > 65535:
            raise PortSpecError(f"พอร์ตต้องอยู่ระหว่าง 1–65535: {part}")
        if len(out) + (hi - lo + 1) > limit * 4:
            raise PortSpecError(f"ระบุพอร์ตได้ไม่เกิน {limit} พอร์ต")
        out.update(range(lo, hi + 1))
        if len(out) > limit:
            raise PortSpecError(f"ระบุพอร์ตได้ไม่เกิน {limit} พอร์ต")
    if not out:
        raise PortSpecError("ยังไม่ได้ระบุพอร์ต")
    return sorted(out)


def profile_ports(profile: str, custom: str, web_ports: List[int]) -> List[int]:
    """The ports a scan checks for the given profile.

    When ``profile == "custom"``, scan ONLY the ports explicitly requested by the
    operator (instead of silently adding all default web ports), so targeted
    scans like ``21, 22`` do not trigger firewall rate limits with unrequested probes.
    """
    if profile == "web":
        return sorted(set(web_ports))
    if profile == "custom":
        return parse_ports(custom)
    if profile == "top100":
        extra = TOP100
    elif profile == "common":
        extra = COMMON
    else:
        raise PortSpecError(f"ไม่รู้จักชุดพอร์ต: {profile}")
    return sorted(set(extra) | set(web_ports))


def describe(port: int, web: bool = False) -> Dict[str, Optional[str]]:
    """*web*: the port answered HTTP(S) during this scan, whatever its number."""
    if port not in SERVICES and web:
        return {"name": "HTTP", "description": "เว็บ (ตอบกลับจริงระหว่างการสแกน)", "note": None}
    name, desc, note = SERVICES.get(port, ("ไม่ทราบ", "บริการที่ไม่อยู่ในรายการ", None))
    return {"name": name, "description": desc, "note": note}

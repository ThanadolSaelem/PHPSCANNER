"""Built-in presentation and simulation scenarios for live stage demonstrations."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from ..models import Device, Severity
from . import dns_resolver, vuln_rules

DEMO_SCENARIOS: List[Dict[str, Any]] = [
    {
        "id": "gov-cert",
        "name": "เครือข่ายหน่วยงานรัฐ",
        "name_en": "Thai Government Agency Network (Gov-CERT Demo)",
        "cidr": "10.255.252.0/24",
        "total_ips": 254,
        "description": "จำลองการตรวจเครือข่ายระดับกระทรวง พบทั้งระบบ Portal ที่ติดช่องโหว่ PHP2Shell (CVE-2026-109618), ระบบสารบรรณอิเล็กทรอนิกส์บน PHP 7.4 EOL และเครื่องที่แพตช์แล้ว",
    },
    {
        "id": "enterprise",
        "name": "ดาต้าเซ็นเตอร์องค์กร",
        "name_en": "Enterprise Hybrid Data Center Cluster",
        "cidr": "172.16.40.0/24",
        "total_ips": 254,
        "description": "จำลองคลัสเตอร์ Production/Staging ขององค์กรขนาดใหญ่ ตรวจพบ Staging API ที่ลืมอัปเดต PHP 8.4.11 และการตั้งค่า HSTS/Header ที่ยังไม่รัดกุม",
    },
    {
        "id": "zero-trust",
        "name": "เครือข่ายที่แพตช์ครบแล้ว",
        "name_en": "100% Patched Zero-Trust Baseline",
        "cidr": "192.168.100.0/24",
        "total_ips": 254,
        "description": "จำลองสถานะเครือข่ายหลังดำเนินการแพตช์ PHP 8.4.27 / 8.3.36 และตั้งค่า Hardening ครบถ้วนทุกเซิร์ฟเวอร์",
    },
]

_RAW_HOSTS: Dict[str, List[Dict[str, Any]]] = {
    "gov-cert": [
        {
            "ip": "10.255.252.10",
            "hostname": "portal.demo-agency.go.th",
            "mac": "00:1b:63:84:45:e6",
            "device_type": "Web Server (HTTPS)",
            "open_ports": [80, 443],
            "latency_ms": 3,
            "scheme": "https",
            "headers": {
                "server": "Apache/2.4.58 (Ubuntu)",
                "x-powered-by": "PHP/8.3.10",
                "content-type": "text/html; charset=UTF-8",
            },
            "body": '<meta name="generator" content="WordPress 6.5"><link rel="stylesheet" href="/wp-content/themes/gov/style.css">',
        },
        {
            "ip": "10.255.252.15",
            "hostname": "edoc.agency-demo.go.th",
            "mac": "00:1b:63:84:45:f1",
            "device_type": "Web Server (HTTP)",
            "open_ports": [80, 8080],
            "latency_ms": 5,
            "scheme": "http",
            "headers": {
                "server": "Apache/2.4.41 (Ubuntu)",
                "x-powered-by": "PHP/7.4.33",
                "set-cookie": "laravel_session=eyJpdiI6ImRlbW8ifQ==; Path=/; HttpOnly",
            },
            "body": "<html><title>ระบบสารบรรณอิเล็กทรอนิกส์ (e-Document)</title></html>",
        },
        {
            "ip": "10.255.252.22",
            "hostname": "cms.public-service.or.th",
            "mac": "00:1b:63:84:46:12",
            "device_type": "Web Server (HTTPS)",
            "open_ports": [80, 443],
            "latency_ms": 4,
            "scheme": "https",
            "headers": {
                "server": "nginx/1.24.0",
                "x-powered-by": "PHP/8.2.18",
                "x-generator": "Drupal 10 (https://www.drupal.org)",
                "strict-transport-security": "max-age=31536000; includeSubDomains",
            },
            "body": "<html><head><title>ระบบบริการประชาชนออนไลน์</title></head></html>",
        },
        {
            "ip": "10.255.252.30",
            "hostname": "intranet.agency-demo.go.th",
            "mac": "00:1b:63:84:46:40",
            "device_type": "Web Server (HTTPS)",
            "open_ports": [443, 8443],
            "latency_ms": 2,
            "scheme": "https",
            "headers": {
                "server": "nginx/1.26.1",
                "x-powered-by": "PHP",
            },
            "body": '<meta name="generator" content="Joomla! - Open Source Content Management">',
        },
        {
            "ip": "10.255.252.40",
            "hostname": "hr-portal.demo-agency.go.th",
            "mac": "00:1b:63:84:46:55",
            "device_type": "Web Server (HTTPS)",
            "open_ports": [80, 443],
            "latency_ms": 3,
            "scheme": "https",
            "headers": {
                "server": "nginx",
                "x-powered-by": "PHP/8.4.27",
                "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
            },
            "body": "<html><title>HR Self-Service Portal</title></html>",
        },
        {
            "ip": "10.255.252.45",
            "hostname": "procurement.agency-demo.go.th",
            "mac": "00:1b:63:84:46:89",
            "device_type": "Web Server (HTTPS)",
            "open_ports": [443],
            "latency_ms": 4,
            "scheme": "https",
            "headers": {
                "server": "cloudflare",
                "x-powered-by": "PHP/8.3.36",
                "strict-transport-security": "max-age=31536000",
            },
            "body": "<html><title>ระบบจัดซื้อจัดจ้างภาครัฐ</title></html>",
        },
        {
            "ip": "10.255.252.1",
            "hostname": "core-gw01.agency-demo.go.th",
            "mac": "f0:9f:c2:11:22:01",
            "device_type": "Gateway Router",
            "open_ports": [],
            "latency_ms": 1,
            "scheme": "http",
            "headers": {},
            "body": "",
        },
        {
            "ip": "10.255.252.101",
            "hostname": "sec-soc-workstation.local",
            "mac": "a4:83:e7:29:10:b2",
            "device_type": "LAN Device",
            "open_ports": [],
            "latency_ms": 6,
            "scheme": "http",
            "headers": {},
            "body": "",
        },
        {
            "ip": "10.255.252.254",
            "hostname": "fw-edge02.agency-demo.go.th",
            "mac": "f0:9f:c2:11:22:fe",
            "device_type": "Gateway Router",
            "open_ports": [],
            "latency_ms": 1,
            "scheme": "http",
            "headers": {},
            "body": "",
        },
    ],
    "enterprise": [
        {
            "ip": "172.16.40.12",
            "hostname": "staging-api.corp.in.th",
            "mac": "02:42:ac:10:28:0c",
            "device_type": "Web Server (HTTPS)",
            "open_ports": [443, 8443],
            "latency_ms": 2,
            "scheme": "https",
            "headers": {
                "server": "nginx/1.25.3",
                "x-powered-by": "PHP/8.4.11",
                "set-cookie": "laravel_session=staging; Path=/",
            },
            "body": "<html><title>Staging API Gateway</title></html>",
        },
        {
            "ip": "172.16.40.20",
            "hostname": "prod-web01.corp.in.th",
            "mac": "02:42:ac:10:28:14",
            "device_type": "Web Server (HTTPS)",
            "open_ports": [80, 443],
            "latency_ms": 1,
            "scheme": "https",
            "headers": {
                "server": "nginx",
                "x-powered-by": "PHP/8.4.27",
                "strict-transport-security": "max-age=31536000; includeSubDomains",
            },
            "body": '<meta name="generator" content="WordPress 6.6">',
        },
        {
            "ip": "172.16.40.21",
            "hostname": "prod-web02.corp.in.th",
            "mac": "02:42:ac:10:28:15",
            "device_type": "Web Server (HTTPS)",
            "open_ports": [80, 443],
            "latency_ms": 2,
            "scheme": "https",
            "headers": {
                "server": "nginx",
                "x-powered-by": "PHP/8.3.36",
                "strict-transport-security": "max-age=31536000; includeSubDomains",
            },
            "body": "<html><title>Customer Portal Node 2</title></html>",
        },
        {
            "ip": "172.16.40.1",
            "hostname": "dc-router.corp.in.th",
            "mac": "02:42:ac:10:28:01",
            "device_type": "Gateway Router",
            "open_ports": [],
            "latency_ms": 1,
            "scheme": "http",
            "headers": {},
            "body": "",
        },
    ],
    "zero-trust": [
        {
            "ip": "192.168.100.10",
            "hostname": "secure-portal.demo-agency.go.th",
            "mac": "00:1b:63:99:00:0a",
            "device_type": "Web Server (HTTPS)",
            "open_ports": [443],
            "latency_ms": 2,
            "scheme": "https",
            "headers": {
                "server": "nginx",
                "x-powered-by": "PHP/8.4.27",
                "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
            },
            "body": '<meta name="generator" content="WordPress 6.6">',
        },
        {
            "ip": "192.168.100.15",
            "hostname": "edoc-v2.agency-demo.go.th",
            "mac": "00:1b:63:99:00:0f",
            "device_type": "Web Server (HTTPS)",
            "open_ports": [443],
            "latency_ms": 3,
            "scheme": "https",
            "headers": {
                "server": "nginx",
                "x-powered-by": "PHP/8.3.36",
                "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
                "set-cookie": "laravel_session=secure; Path=/; Secure; HttpOnly",
            },
            "body": "<html><title>e-Document v2 (Patched)</title></html>",
        },
        {
            "ip": "192.168.100.1",
            "hostname": "zt-gateway.agency-demo.go.th",
            "mac": "00:1b:63:99:00:01",
            "device_type": "Gateway Router",
            "open_ports": [],
            "latency_ms": 1,
            "scheme": "http",
            "headers": {},
            "body": "",
        },
    ],
}


def build_demo_devices(scenario_id: str, suffixes: List[str]) -> List[Device]:
    raw_list = _RAW_HOSTS.get(scenario_id, _RAW_HOSTS["gov-cert"])
    devices: List[Device] = []
    for item in raw_list:
        open_ports: List[int] = list(item.get("open_ports", []))
        has_web = bool(open_ports)
        has_tls = any(p in (443, 8443) for p in open_ports)
        headers: Dict[str, str] = {
            k.lower(): v for k, v in item.get("headers", {}).items()
        }
        body: str = item.get("body", "")
        scheme: str = item.get("scheme", "https" if has_tls else "http")

        if has_web:
            findings, php_ver, cms, server = vuln_rules.evaluate(
                scheme=scheme, headers=headers, body=body
            )
            severity = vuln_rules.device_severity(findings)
            service = "HTTPS" if has_tls else "HTTP"
        else:
            findings, php_ver, cms, server = [], None, None, None
            severity = Severity.safe
            service = "ไม่มีบริการเว็บ"

        hostname = item.get("hostname")
        matched = dns_resolver.match_suffix(hostname, suffixes)
        devices.append(
            Device(
                ip=item["ip"],
                hostname=hostname,
                matched_suffix=matched,
                up=True,
                mac=item.get("mac"),
                device_type=item.get("device_type", "LAN Device"),
                service=service,
                php_version=php_ver,
                server=server,
                cms=cms,
                open_ports=sorted(open_ports),
                latency_ms=item.get("latency_ms", 2),
                severity=severity,
                assessment=vuln_rules.thaicert_assessment(severity, has_web, findings),
                findings=findings,
                headers=headers,
            )
        )

    order = {
        Severity.critical: 0,
        Severity.high: 1,
        Severity.low: 2,
        Severity.safe: 3,
    }
    devices.sort(
        key=lambda d: (
            order[d.severity],
            0 if (d.php_version or d.open_ports) else 1,
            [int(o) for o in d.ip.split(".")],
        )
    )
    return devices


def apply_patch_to_device(device: Device) -> Device:
    if not device.open_ports and not device.php_version:
        return device

    target_php = "8.4.27"
    if device.php_version:
        parts = device.php_version.split(".")
        if len(parts) >= 2:
            br = (int(parts[0]), int(parts[1]))
            fixed = vuln_rules.PHP2SHELL_FIXED.get(br)
            if fixed:
                target_php = f"{fixed[0]}.{fixed[1]}.{fixed[2]}"
            elif br < (8, 2):
                target_php = "8.3.36"

    new_headers = dict(device.headers)
    new_headers["server"] = "nginx"
    new_headers["x-powered-by"] = f"PHP/{target_php}"
    new_headers["strict-transport-security"] = "max-age=63072000; includeSubDomains; preload"

    has_tls = any(p in (443, 8443) for p in device.open_ports) or device.service == "HTTPS"
    scheme = "https" if has_tls else "http"
    findings, php_ver, _, server = vuln_rules.evaluate(
        scheme=scheme, headers=new_headers, body=""
    )
    severity = vuln_rules.device_severity(findings)

    device.php_version = php_ver
    device.server = server
    device.headers = new_headers
    device.findings = findings
    device.severity = severity
    device.assessment = vuln_rules.thaicert_assessment(severity, True, findings)
    device.patched_at = datetime.now(timezone.utc).isoformat()
    return device

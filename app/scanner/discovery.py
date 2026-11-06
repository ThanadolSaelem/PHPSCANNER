"""Device discovery for a local/authorized network with Multi-Vector L3/L4 probing and MAC vendor resolution."""
from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import socket
import struct
import time
from typing import Dict, List, Optional, Tuple

import csv
from . import netlimit

_CLEAN_RE = re.compile(r"[^0-9a-fA-F]")

# Curated enterprise, cloud, LAN, NAS, router/firewall, IoT/CCTV & hypervisor OUIs
BUILTIN_OUI_VENDORS: Dict[str, str] = {
    # Virtualization / Containers / Cloud
    "000569": "VMware",
    "000C29": "VMware",
    "001C14": "VMware",
    "005056": "VMware",
    "00155D": "Microsoft Hyper-V",
    "0003FF": "Microsoft Hyper-V",
    "080027": "Oracle VirtualBox",
    "0A0027": "Oracle VirtualBox",
    "525400": "QEMU / KVM",
    "BC2411": "Proxmox VE",
    "0242AC": "Docker Container",
    "00163E": "Xen / AWS EC2",
    "060000": "AWS VPC Elastic NIC",
    "42010A": "Google Cloud VPC",
    "001DD8": "Microsoft Azure",
    "000D3A": "Microsoft Azure",
    # NAS / Storage Appliances
    "001132": "Synology Inc.",
    "9009D0": "Synology Inc.",
    "00089B": "QNAP Systems",
    "245EBE": "QNAP Systems",
    "D05099": "ASRock / TrueNAS",
    "002590": "Supermicro",
    "AC1F6B": "Supermicro",
    "3CECEF": "Supermicro",
    "00A098": "NetApp",
    # Firewalls / Routers / Switches / Enterprise Networking
    "00090F": "Fortinet (FortiGate)",
    "704CA5": "Fortinet (FortiGate)",
    "906CAC": "Fortinet (FortiGate)",
    "00000C": "Cisco Systems",
    "000142": "Cisco Systems",
    "001EBD": "Cisco Systems",
    "F872EA": "Cisco Systems",
    "B0AA77": "Cisco Systems",
    "001B17": "Palo Alto Networks",
    "D4F4BE": "Palo Alto Networks",
    "4C5E0C": "MikroTik (RouterBoard)",
    "D4CA6D": "MikroTik (RouterBoard)",
    "CC2DE0": "MikroTik (RouterBoard)",
    "E48D8C": "MikroTik (RouterBoard)",
    "64D154": "MikroTik (RouterBoard)",
    "B869F4": "MikroTik (RouterBoard)",
    "18FD74": "MikroTik (RouterBoard)",
    "24A43C": "Ubiquiti Inc.",
    "F09FC2": "Ubiquiti Inc.",
    "7483C2": "Ubiquiti Inc.",
    "802AA8": "Ubiquiti Inc.",
    "FC528D": "Ubiquiti Inc.",
    "000BDB": "Dell EMC Networking",
    "2C6BF5": "Juniper Networks",
    "000585": "Juniper Networks",
    "000B86": "Aruba Networks (HPE)",
    "24DE9A": "Aruba Networks (HPE)",
    # CCTV / IP Cameras / NVR
    "C056E3": "Hikvision Digital",
    "2857BE": "Hikvision Digital",
    "4419B6": "Hikvision Digital",
    "A41437": "Hikvision Digital",
    "BCAD28": "Hikvision Digital",
    "3CEF8C": "Dahua Technology",
    "E0508B": "Dahua Technology",
    "9002A9": "Dahua Technology",
    "00408C": "Axis Communications",
    "ACCC8E": "Axis Communications",
    "B8A44F": "Axis Communications",
    # Enterprise Servers (Dell, HPE, Lenovo, IBM)
    "1866DA": "Dell Inc.",
    "F875A4": "Dell Inc.",
    "001422": "Dell Inc.",
    "D4BE5B": "Dell Inc.",
    "B82A72": "Dell Inc.",
    "3CD92B": "Hewlett Packard Enterprise",
    "9457A5": "Hewlett Packard Enterprise",
    "0017A4": "Hewlett Packard Enterprise",
    "EC9A74": "Hewlett Packard Enterprise",
    "00215E": "IBM / Lenovo Server",
    "0894EF": "Lenovo Enterprise",
    # Single-Board Computers / IoT
    "B827EB": "Raspberry Pi Foundation",
    "DCA632": "Raspberry Pi Trading",
    "E45F01": "Raspberry Pi Trading",
    "D83ADD": "Raspberry Pi Trading",
    "2CF05D": "Espressif Inc. (ESP32)",
    "240AC4": "Espressif Inc. (ESP32)",
    # Consumer / SMB Routers & NICs
    "50C7BF": "TP-Link Systems",
    "B0BE76": "TP-Link Systems",
    "14CC20": "TP-Link Systems",
    "F81A67": "TP-Link Systems",
    "04D9F5": "ASUSTek Computer",
    "2CFDA1": "ASUSTek Computer",
    "001E58": "D-Link Corporation",
    "C8D3A3": "D-Link Corporation",
    "00E04C": "Realtek Semiconductor",
    "54E1AD": "LCFC / Realtek NIC",
    "001B21": "Intel Corporate",
    "A0369F": "Intel Corporate",
    "3CFDFE": "Intel Corporate",
    "6805CA": "Intel Corporate",
    "482AE3": "Huawei Technologies",
    "00E0FC": "Huawei Technologies",
    "8828B3": "Huawei Technologies",
    # Apple / Workstations / Printers
    "3C22FB": "Apple Inc.",
    "A483E7": "Apple Inc.",
    "F01898": "Apple Inc.",
    "BC52B7": "Apple Inc.",
    "ACDE48": "Apple Inc.",
    "008077": "Brother Industries",
    "30055C": "Brother Industries",
    "000048": "Seiko Epson",
    "001E8F": "Canon Inc.",
}

_EXTERNAL_LOADED = False


def _load_external_csv() -> None:
    global _EXTERNAL_LOADED
    if _EXTERNAL_LOADED:
        return
    _EXTERNAL_LOADED = True
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "mac_vendor_mapping.csv"),
        os.path.join(os.path.dirname(here), "mac_vendor_mapping.csv"),
        os.path.join(os.path.dirname(os.path.dirname(here)), "core", "mac_vendor_mapping.csv"),
    ]
    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                reader = csv.reader(fh)
                for row in reader:
                    if len(row) < 2:
                        continue
                    prefix = _CLEAN_RE.sub("", row[0]).upper()[:6]
                    vendor = row[1].strip()
                    if len(prefix) == 6 and vendor and prefix not in BUILTIN_OUI_VENDORS:
                        BUILTIN_OUI_VENDORS[prefix] = vendor
        except OSError:
            continue


def lookup_mac_vendor(mac: Optional[str]) -> Optional[str]:
    """Return the hardware/virtualisation vendor for a MAC address, or None."""
    if not mac:
        return None
    _load_external_csv()
    hex_only = _CLEAN_RE.sub("", mac).upper()
    if len(hex_only) < 6 or hex_only == "000000000000" or hex_only == "FFFFFFFFFFFF":
        return None
    oui = hex_only[:6]
    if oui in BUILTIN_OUI_VENDORS:
        return BUILTIN_OUI_VENDORS[oui]
    # Check locally administered bit (bit 1 of first octet) -> virtual/container/randomised MAC
    try:
        first_byte = int(hex_only[:2], 16)
        if first_byte & 0x02:
            return "Virtual / Locally Administered NIC"
    except ValueError:
        pass
    return None


def infer_category_from_vendor(vendor: Optional[str]) -> Optional[str]:
    """Map a known hardware vendor to a more specific device category when applicable."""
    if not vendor:
        return None
    v = vendor.lower()
    if any(k in v for k in ("synology", "qnap", "truenas", "netapp")):
        return "NAS Storage"
    if any(k in v for k in ("hikvision", "dahua", "axis")):
        return "IP Camera / NVR"
    if any(k in v for k in ("fortinet", "palo alto", "mikrotik", "ubiquiti", "cisco", "juniper", "aruba")):
        return "Gateway Router"
    if any(k in v for k in ("brother", "epson", "canon")):
        return "Network Printer"
    return None


_MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$", re.IGNORECASE)
_ZERO_MAC = "00:00:00:00:00:00"

# Standard non-destructive UDP discovery payloads (NetBIOS NBSTAT, mDNS DNS-SD, SSDP, DNS)
_NBNS_NBSTAT = (
    b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
    b"\x00\x21\x00\x01"
)
_MDNS_QUERY = (
    b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
    b"\x00\x0c\x00\x01"
)
_SSDP_MSEARCH = (
    b"M-SEARCH * HTTP/1.1\r\n"
    b"HOST: 239.255.255.250:1900\r\n"
    b'MAN: "ssdp:discover"\r\n'
    b"MX: 1\r\n"
    b"ST: ssdp:all\r\n\r\n"
)
_DNS_STATUS = b"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03"

_UDP_VECTORS: Tuple[Tuple[int, bytes, str], ...] = (
    (137, _NBNS_NBSTAT, "udp-netbios"),
    (5353, _MDNS_QUERY, "udp-mdns"),
    (1900, _SSDP_MSEARCH, "udp-ssdp"),
    (53, _DNS_STATUS, "udp-dns"),
)


def is_private_ipv4(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.version == 4 and addr.is_private and not addr.is_loopback
    except ValueError:
        return False


async def _probe_port(ip: str, port: int, timeout: float) -> Tuple[bool, Optional[float]]:
    async with netlimit.slot():
        return await _probe_port_unlimited(ip, port, timeout)


async def _probe_port_unlimited(ip: str, port: int, timeout: float) -> Tuple[bool, Optional[float]]:
    loop = asyncio.get_running_loop()
    start = loop.time()
    try:
        fut = asyncio.open_connection(ip, port)
        _, writer = await asyncio.wait_for(fut, timeout=timeout)
        rtt = (loop.time() - start) * 1000.0
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
        return True, rtt
    except ConnectionRefusedError:
        return True, (loop.time() - start) * 1000.0
    except (asyncio.TimeoutError, OSError):
        return False, None


def _sync_multi_vector_probe(ip: str, timeout: float = 0.65) -> Tuple[bool, Optional[float], Optional[str]]:
    """Non-privileged L3/L4 multi-vector probe (ICMP DGRAM + Connected UDP 137/5353/1900/53).

    A connected UDP socket receives ``ConnectionRefusedError`` when the remote
    host returns an ICMP Port Unreachable packet, proving host liveness even
    when all TCP ports are closed or filtered. Also triggers kernel ARP
    resolution for local-subnet targets.
    """
    # 1. Try unprivileged ICMP Echo (SOCK_DGRAM, IPPROTO_ICMP) where supported
    try:
        icmpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        try:
            icmpsock.settimeout(min(timeout, 0.35))
            t0 = time.monotonic()
            # ICMP Echo Request: type=8, code=0, checksum=0 (filled by kernel for DGRAM ICMP), id=0x5448, seq=1
            pkt = struct.pack("!BBHHH", 8, 0, 0, 0x5448, 1) + b"thscan"
            icmpsock.sendto(pkt, (ip, 0))
            data, _ = icmpsock.recvfrom(128)
            if data:
                return True, (time.monotonic() - t0) * 1000.0, "icmp-echo"
        finally:
            icmpsock.close()
    except OSError:
        pass

    # 2. Connected UDP vectors (NetBIOS 137, mDNS 5353, SSDP 1900, DNS 53)
    per_vec = max(0.12, min(timeout / len(_UDP_VECTORS), 0.25))
    for port, payload, label in _UDP_VECTORS:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.settimeout(per_vec)
            t0 = time.monotonic()
            s.connect((ip, port))
            s.send(payload)
            data = s.recv(512)
            if data:
                return True, (time.monotonic() - t0) * 1000.0, label
        except ConnectionRefusedError:
            # Target explicitly replied with ICMP Port Unreachable -> host is alive!
            return True, (time.monotonic() - t0) * 1000.0, f"{label}-icmp-unreach"
        except OSError:
            continue
        finally:
            try:
                s.close()
            except OSError:
                pass
    return False, None, None


async def multi_vector_probe(ip: str, timeout: float = 0.65) -> Tuple[bool, Optional[float], Optional[str]]:
    """Async wrapper for non-privileged UDP/ICMP multi-vector host discovery."""
    async with netlimit.slot():
        return await asyncio.to_thread(_sync_multi_vector_probe, ip, timeout)


# A documentation address (RFC 5737 TEST-NET-2) that can never be a real host.
# Anything that answers for it is a middlebox answering for every address.
async def _accepts_tcp(ip: str, port: int, timeout: float) -> bool:
    """Return True ONLY when a full TCP handshake succeeds (SYN-ACK)."""
    async with netlimit.slot():
        try:
            fut = asyncio.open_connection(ip, port)
            _, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False


CANARY_IP = "198.51.100.1"


async def intercepted_ports(ports: List[int], timeout: float,
                            canary: str = CANARY_IP) -> set:
    """Ports on which a middlebox accepts TCP for an address that cannot exist."""
    canary_timeout = min(timeout, 1.5)
    results = await asyncio.gather(*(_accepts_tcp(canary, p, canary_timeout) for p in ports))
    return {p for p, ok in zip(ports, results) if ok}


async def alive_latency(
    ip: str, ports: List[int], timeout: float, *, enable_multi_vector: bool = False
) -> Tuple[bool, Optional[int]]:
    if not ports and not enable_multi_vector:
        return False, None
    if ports:
        results = await asyncio.gather(*(_probe_port(ip, p, timeout) for p in ports))
        rtts = [rtt for ok, rtt in results if ok and rtt is not None]
        up = any(ok for ok, _ in results)
        if up:
            return True, (round(min(rtts)) if rtts else None)
    if enable_multi_vector and is_private_ipv4(ip):
        mv_ok, mv_rtt, _ = await multi_vector_probe(ip, min(timeout, 0.65))
        if mv_ok:
            return True, (round(mv_rtt) if mv_rtt is not None else None)
    return False, None


def read_arp_table() -> Dict[str, str]:
    table: Dict[str, str] = {}
    try:
        with open("/proc/net/arp", encoding="utf-8") as fh:
            next(fh, None)
            for line in fh:
                parts = line.split()
                if len(parts) >= 4:
                    ip, mac = parts[0], parts[3].lower()
                    if _MAC_RE.match(mac) and mac != _ZERO_MAC:
                        table[ip] = mac
    except (OSError, StopIteration):
        pass
    if not table:
        table = _arp_command_table()
    return table


_ARP_LINE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\D+?((?:[0-9a-f]{1,2}[:-]){5}[0-9a-f]{1,2})", re.IGNORECASE)


def _arp_command_table() -> Dict[str, str]:
    """Fallback for Windows/macOS: parse ``arp -a`` (fixed args, no user input)."""
    import subprocess
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                             timeout=5, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    table: Dict[str, str] = {}
    for ip, mac in _ARP_LINE.findall(out):
        norm = ":".join(p.zfill(2) for p in re.split(r"[:-]", mac.lower()))
        if norm not in (_ZERO_MAC, "ff:ff:ff:ff:ff:ff"):
            table[ip] = norm
    return table


def infer_device_type(
    ip: str,
    open_web_ports: List[int],
    has_tls: bool,
    has_other_open: bool,
    mac: Optional[str] = None,
    mac_vendor: Optional[str] = None,
) -> str:
    try:
        last = int(ip.rsplit(".", 1)[1])
    except (ValueError, IndexError):
        last = -1
    if last in (1, 254):
        return "Gateway Router"
    if open_web_ports:
        return "Web Server (HTTPS)" if has_tls else "Web Server (HTTP)"
    vendor = mac_vendor or lookup_mac_vendor(mac)
    cat = infer_category_from_vendor(vendor)
    if cat:
        return cat
    return "LAN Device"


def autodetect_subnets() -> List[Dict[str, str]]:
    subnets: List[Dict[str, str]] = []
    seen: set[str] = set()

    def add(name: str, ip: str, prefix: int = 24) -> None:
        try:
            net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        except ValueError:
            return
        key = str(net)
        if key not in seen and ip != "127.0.0.1" and not ip.startswith("127."):
            seen.add(key)
            subnets.append({"name": name, "cidr": key})

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            add("เครือข่ายหลัก (Primary LAN)", s.getsockname()[0])
        finally:
            s.close()
    except OSError:
        pass

    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            add("อินเทอร์เฟซภายใน (Local NIC)", info[4][0])
    except (OSError, socket.gaierror):
        pass

    default_sub = os.environ.get("THSCAN_DEFAULT_SUBNET", "").strip()
    if not subnets and default_sub:
        parts = default_sub.split("/")
        try:
            prefix = int(parts[1]) if len(parts) > 1 else 24
        except ValueError:
            prefix = 24
        add("ค่าตั้งต้น (Default Subnet)", parts[0], prefix)

    if not subnets:
        add("เครือข่ายจำลองมาตรฐาน (Fallback LAN)", "192.168.1.0", 24)
    return subnets

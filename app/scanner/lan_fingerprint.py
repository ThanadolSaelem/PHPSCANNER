"""Opt-in, bounded device hints from a directly attached private IPv4 LAN.

The default mode sends only one unicast NetBIOS node-status query to each
scan-confirmed target. Link multicast (mDNS/SSDP) is an additional opt-in because
those requests are visible to every listener on the selected LAN segment. No
Nmap raw-socket scan, arbitrary URL fetch, or remote SSDP LOCATION fetch occurs.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import secrets
import socket
import struct
import subprocess
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..models import Confidence, Device
from . import discovery

RFC1918 = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
MAX_TARGETS = 256
MAX_WORKERS = 4
MAX_TIMEOUT_S = 1.0
MAX_TOTAL_TIMEOUT_S = 90
MAX_MULTICAST_INTERFACES = 4
MAX_MULTICAST_RESPONSES = 32
MAX_EVIDENCE_ITEMS = 8
MAX_EVIDENCE_CHARS = 180

_MDNS_QUESTIONS = (
    "_services._dns-sd._udp.local",
    "_device-info._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_hap._tcp.local",
    "_companion-link._tcp.local",
    "_googlecast._tcp.local",
    "_workstation._tcp.local",
    "_smb._tcp.local",
    "_ipp._tcp.local",
    "_printer._tcp.local",
)


def _load_route_table() -> Optional[List[Tuple[ipaddress.IPv4Network, str, bool]]]:
    """Load kernel IPv4 routes as (network, egress-interface, directly-connected)."""
    routes: List[Tuple[ipaddress.IPv4Network, str, bool]] = []
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/net/route", encoding="ascii") as route_file:
                next(route_file, None)
                for line in route_file:
                    fields = line.split()
                    if len(fields) < 8:
                        continue
                    iface, destination, gateway, flags, _ref, _use, _metric, mask = fields[:8]
                    if not (int(flags, 16) & 0x1):  # RTF_UP
                        continue
                    dest_ip = socket.inet_ntoa(struct.pack("<I", int(destination, 16)))
                    mask_ip = socket.inet_ntoa(struct.pack("<I", int(mask, 16)))
                    network = ipaddress.IPv4Network((dest_ip, mask_ip), strict=False)
                    routes.append((network, iface, int(gateway, 16) == 0))
            return routes
        except (OSError, ValueError, struct.error):
            return None

    if sys.platform == "darwin" or "bsd" in sys.platform:
        try:
            result = subprocess.run(
                ["netstat", "-rn", "-f", "inet"], capture_output=True, text=True,
                timeout=3, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0:
            return None
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) < 4 or fields[0].lower() in {"destination", "default"}:
                continue
            destination, _gateway, flags, iface = fields[:4]
            try:
                if "/" in destination:
                    address_text, prefix_text = destination.split("/", 1)
                    if address_text.count(".") == 2:
                        address_text += ".0"
                    network = ipaddress.IPv4Network(f"{address_text}/{prefix_text}", strict=False)
                elif destination.count(".") == 3:
                    network = ipaddress.IPv4Network(f"{destination}/32")
                else:
                    continue
            except ValueError:
                continue
            normalized_flags = flags.upper()
            routes.append((network, iface, "U" in normalized_flags and "G" not in normalized_flags))
        return routes

    if sys.platform.startswith("win"):
        try:
            result = subprocess.run(
                ["route.exe", "print", "-4"], capture_output=True, text=True,
                timeout=3, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0:
            return None
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) != 5:
                continue
            destination, mask, gateway, iface, _metric = fields
            try:
                network = ipaddress.IPv4Network((destination, mask), strict=False)
            except ValueError:
                continue
            routes.append((network, iface, gateway.lower() in {"on-link", "0.0.0.0"}))
        return routes
    return None


def _selected_route_source(target: ipaddress.IPv4Address) -> Optional[str]:
    """Ask the kernel which IPv4 source it would use; UDP connect sends no datagram."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((str(target), 9))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def _has_direct_route(
    target: ipaddress.IPv4Address,
    interface: Dict[str, str],
    routes: List[Tuple[ipaddress.IPv4Network, str, bool]],
) -> bool:
    matches = [route for route in routes if target in route[0]]
    if not matches:
        return False
    longest_prefix = max(route[0].prefixlen for route in matches)
    best = [route for route in matches if route[0].prefixlen == longest_prefix]
    expected_iface = interface["address"] if sys.platform.startswith("win") else interface["name"]
    if not best or not all(direct and egress == expected_iface for _, egress, direct in best):
        return False
    selected_source = _selected_route_source(target)
    return selected_source == interface["address"]


def validate_targets(
    targets: Iterable[str], interfaces: Optional[List[Dict[str, str]]] = None,
    *, require_direct_route: bool = False,
) -> Tuple[Optional[str], Dict[str, Dict[str, str]]]:
    """Validate all requested addresses and map each to one real interface.

    This deliberately does not use allowed_cidrs or autodetect_subnets(), since
    neither proves that a destination is directly attached to this host.
    """
    if interfaces is None:
        interfaces = discovery.local_ipv4_interfaces()
    if not interfaces:
        return "ไม่พบ private IPv4 interface ที่ยืนยันได้ จึงไม่เริ่ม LAN fingerprint", {}

    parsed_interfaces: List[Tuple[Dict[str, str], ipaddress.IPv4Network]] = []
    for iface in interfaces:
        try:
            network = ipaddress.ip_network(iface["cidr"], strict=False)
            address = ipaddress.ip_address(iface["address"])
        except (KeyError, ValueError, TypeError):
            continue
        if (network.version != 4 or address.version != 4 or address.is_loopback
                or address.is_link_local or not any(address in net for net in RFC1918)):
            continue
        parsed_interfaces.append((iface, network))
    if not parsed_interfaces:
        return "ไม่พบ private IPv4 interface ที่ยืนยันได้ จึงไม่เริ่ม LAN fingerprint", {}

    routes: Optional[List[Tuple[ipaddress.IPv4Network, str, bool]]] = None
    if require_direct_route:
        routes = _load_route_table()
        if routes is None:
            return "ไม่สามารถตรวจตาราง route ของระบบปฏิบัติการได้ จึงปฏิเสธ LAN fingerprint แบบ fail-closed", {}

    mapping: Dict[str, Dict[str, str]] = {}
    used_interfaces: set[Tuple[str, str]] = set()
    unique_targets = list(dict.fromkeys(str(x) for x in targets))
    if len(unique_targets) > MAX_TARGETS:
        return f"LAN fingerprint จำกัดไม่เกิน {MAX_TARGETS} IPv4 targets ต่อครั้ง", {}
    for text in unique_targets:
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            return "LAN fingerprint รับเฉพาะ IPv4 address ที่ขยายจาก IP/CIDR โดยตรง", {}
        if address.version != 4 or address.is_loopback or address.is_link_local or not any(
            address in net for net in RFC1918
        ):
            return f"เป้าหมาย {text} ไม่ใช่ RFC1918 private IPv4 address", {}
        matches = [
            iface for iface, network in parsed_interfaces
            if address in network
        ]
        if len(matches) != 1:
            return f"เป้าหมาย {text} ไม่อยู่บน interface เดียวที่ยืนยันได้ หรือมี route/interface กำกวม", {}
        iface = matches[0]
        if require_direct_route and routes is not None and not _has_direct_route(address, iface, routes):
            return f"เป้าหมาย {text} ไม่ได้ใช้ direct on-link route ผ่าน interface ที่ยืนยัน จึงไม่ส่ง fingerprint probe", {}
        mapping[str(address)] = iface
        used_interfaces.add((iface.get("name", ""), iface.get("cidr", "")))
    if len(used_interfaces) > MAX_MULTICAST_INTERFACES:
        return f"เป้าหมายครอบคลุม interface มากกว่า {MAX_MULTICAST_INTERFACES} วง ซึ่งเกินเพดาน fingerprint", {}
    return None, mapping


def _clean(value: Any, limit: int = MAX_EVIDENCE_CHARS) -> str:
    text = str(value or "")
    text = "".join(ch if ch.isprintable() else " " for ch in text)
    return " ".join(text.split())[:limit]


def _encode_dns_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        if not raw or len(raw) > 63:
            raise ValueError("invalid DNS label")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def _mdns_query() -> bytes:
    questions = b"".join(
        _encode_dns_name(name) + struct.pack("!HH", 12, 0x8001)
        for name in _MDNS_QUESTIONS
    )
    # Multicast DNS query messages use transaction ID zero.
    return struct.pack("!HHHHHH", 0, 0, len(_MDNS_QUESTIONS), 0, 0, 0) + questions


def _parse_mdns(packet: bytes) -> List[str]:
    try:
        import dns.message
        import dns.rdatatype

        message = dns.message.from_wire(packet, ignore_trailing=True)
    except Exception:  # malformed or truncated network response
        return []
    evidence: List[str] = []
    for rrset in (*message.answer, *message.authority, *message.additional):
        rtype = rrset.rdtype
        if rtype == dns.rdatatype.PTR:
            for record in rrset:
                evidence.append(_clean(f"mDNS {rrset.name} -> {record.target}"))
        elif rtype == dns.rdatatype.TXT:
            for record in rrset:
                strings = getattr(record, "strings", ())
                for item in strings:
                    try:
                        text = item.decode("utf-8", "replace")
                    except AttributeError:
                        text = str(item)
                    # Keep identity-bearing model/manufacturer hints only.
                    if re.match(r"(?i)^(model|md|manufacturer|product|device|name)=", text):
                        evidence.append(_clean(f"mDNS TXT {text}"))
        if len(evidence) >= MAX_EVIDENCE_ITEMS:
            break
    return list(dict.fromkeys(evidence))[:MAX_EVIDENCE_ITEMS]


def _parse_ssdp(packet: bytes) -> List[str]:
    try:
        text = packet[:8192].decode("iso-8859-1", "replace")
    except Exception:
        return []
    headers: Dict[str, str] = {}
    for line in text.replace("\r", "").split("\n")[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        if key in {"st", "nt", "usn", "server"}:
            headers[key] = _clean(value)
    # LOCATION is intentionally neither retained nor fetched.
    return [f"SSDP {key.upper()}: {value}" for key, value in headers.items() if value][:4]


def _query_multicast(
    interface: Dict[str, str], timeout_s: float, cancel_event: Optional[asyncio.Event] = None
) -> Dict[str, List[str]]:
    """Send one mDNS query and one SSDP M-SEARCH on exactly one local NIC."""
    found: Dict[str, List[str]] = {}
    local_ip = interface["address"]
    overall_deadline = time.monotonic() + max(0.1, timeout_s)
    probes = (
        ("224.0.0.251", 5353, _mdns_query(), _parse_mdns),
        ("239.255.255.250", 1900,
         b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
         b'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n', _parse_ssdp),
    )
    for index, (group, port, payload, parser) in enumerate(probes):
        if cancel_event is not None and cancel_event.is_set():
            break
        remaining_total = overall_deadline - time.monotonic()
        if remaining_total <= 0:
            break
        probe_deadline = min(overall_deadline, time.monotonic() + remaining_total / (len(probes) - index))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            sock.bind((local_ip, 0))
            sock.settimeout(max(0.05, probe_deadline - time.monotonic()))
            sock.sendto(payload, (group, port))
            deadline = probe_deadline
            for _ in range(MAX_MULTICAST_RESPONSES):
                if cancel_event is not None and cancel_event.is_set():
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                sock.settimeout(remaining)
                try:
                    packet, peer = sock.recvfrom(8192)
                except socket.timeout:
                    break
                evidence = parser(packet)
                if evidence:
                    found.setdefault(peer[0], []).extend(evidence)
        except OSError:
            # Capability/interface-level failures are represented as no evidence;
            # the caller still records a completed, bounded fingerprint attempt.
            continue
        finally:
            sock.close()
    return {ip: list(dict.fromkeys(rows))[:MAX_EVIDENCE_ITEMS] for ip, rows in found.items()}


def _nbns_encoded_wildcard_name() -> bytes:
    # NetBIOS wildcard name (15 spaces + '*' + suffix 0x00), first-level encoded.
    raw_name = b"*" + (b" " * 14) + b"\x00"
    encoded = bytearray()
    for byte in raw_name:
        encoded.extend((ord("A") + (byte >> 4), ord("A") + (byte & 0x0F)))
    return bytes(encoded)


def _nbns_name_query(transaction_id: Optional[int] = None) -> bytes:
    name = b"\x20" + _nbns_encoded_wildcard_name() + b"\x00"
    txid = secrets.randbelow(65536) if transaction_id is None else transaction_id
    return struct.pack("!HHHHHH", txid, 0, 1, 0, 0, 0) + name + struct.pack("!HH", 0x0021, 0x0001)


def _read_dns_name(packet: bytes, offset: int) -> Tuple[str, int]:
    labels: List[str] = []
    cursor = offset
    end = None
    seen: set[int] = set()
    while cursor < len(packet):
        length = packet[cursor]
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(packet):
                raise ValueError("truncated DNS name pointer")
            pointer = ((length & 0x3F) << 8) | packet[cursor + 1]
            if pointer in seen:
                raise ValueError("DNS name pointer loop")
            seen.add(pointer)
            if end is None:
                end = cursor + 2
            cursor = pointer
            continue
        cursor += 1
        if length == 0:
            return ".".join(labels), end if end is not None else cursor
        if length > 63 or cursor + length > len(packet):
            raise ValueError("invalid DNS label")
        labels.append(packet[cursor:cursor + length].decode("ascii", "replace"))
        cursor += length
    raise ValueError("unterminated DNS name")


def _parse_nbns(packet: bytes, expected_transaction_id: Optional[int] = None) -> List[str]:
    if len(packet) < 12:
        return []
    try:
        transaction_id, flags, qdcount, ancount, _nscount, _arcount = struct.unpack_from("!HHHHHH", packet, 0)
        if (expected_transaction_id is not None and transaction_id != expected_transaction_id) or \
                not flags & 0x8000 or flags & (0x7800 | 0x0200 | 0x000F):
            return []
        if qdcount != 1:
            return []
        pos = 12
        question_name, pos = _read_dns_name(packet, pos)
        if question_name.upper() != _nbns_encoded_wildcard_name().decode("ascii") or pos + 4 > len(packet):
            return []
        question_type, question_class = struct.unpack_from("!HH", packet, pos)
        if question_type != 0x0021 or question_class != 0x0001:
            return []
        pos += 4
        evidence: List[str] = []
        for _ in range(min(ancount, 8)):
            _, pos = _read_dns_name(packet, pos)
            if pos + 10 > len(packet):
                break
            rtype, rr_class, _ttl, rdlength = struct.unpack_from("!HHIH", packet, pos)
            pos += 10
            end = pos + rdlength
            if end > len(packet):
                break
            if rtype == 0x0021 and rr_class == 0x0001 and rdlength >= 1:
                count = packet[pos]
                cursor = pos + 1
                for _ in range(min(count, 16)):
                    if cursor + 18 > end:
                        break
                    name = _clean(packet[cursor:cursor + 15].decode("ascii", "replace").strip(), 48)
                    suffix = packet[cursor + 15]
                    flags = struct.unpack_from("!H", packet, cursor + 16)[0]
                    if name and any(ch.isalnum() for ch in name):
                        kind = "group" if flags & 0x8000 else "unique"
                        evidence.append(f"NetBIOS {name} <0x{suffix:02x}> ({kind})")
                    cursor += 18
            pos = end
        return list(dict.fromkeys(evidence))[:MAX_EVIDENCE_ITEMS]
    except (ValueError, struct.error, IndexError):
        return []


def _query_nbns(local_ip: str, target_ip: str, timeout_s: float) -> List[str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    transaction_id = secrets.randbelow(65536)
    try:
        sock.bind((local_ip, 0))
        sock.settimeout(min(MAX_TIMEOUT_S, max(0.1, timeout_s)))
        sock.sendto(_nbns_name_query(transaction_id), (target_ip, 137))
        packet, peer = sock.recvfrom(4096)
        if peer[0] != target_ip or peer[1] != 137:
            return []
        return _parse_nbns(packet, expected_transaction_id=transaction_id)
    except OSError:
        return []
    finally:
        sock.close()


def _classify(evidence: List[str]) -> Tuple[Optional[str], Confidence, List[str]]:
    text = " ".join(evidence)
    lower = text.lower()
    model_match = re.search(r"(?i)model\s*=\s*([^\s;]+)", text)
    model = model_match.group(1) if model_match else ""
    if model:
        label_model = model.split(".", 1)[0]
        if re.search(r"(?i)iphone", model):
            return "Apple iPhone (model hint)", Confidence.medium, [f"mDNS model={label_model}"]
        if re.search(r"(?i)ipad", model):
            return "Apple iPad (model hint)", Confidence.medium, [f"mDNS model={label_model}"]
        if re.search(r"(?i)macbook", model):
            return "Apple MacBook (model hint)", Confidence.medium, [f"mDNS model={label_model}"]
        if re.search(r"(?i)imac|macmini|macpro", model):
            return "Apple Mac (model hint)", Confidence.medium, [f"mDNS model={label_model}"]
    if any(token in lower for token in ("internetgatewaydevice", "wanipconnection", "wanpppconnection")):
        return "Possible router / Internet gateway", Confidence.medium, [x for x in evidence if x.startswith("SSDP")][:4]
    if any(token in lower for token in ("_ipp._tcp", "_printer._tcp")):
        return "Network printer (probable)", Confidence.medium, [x for x in evidence if "ipp" in x.lower() or "printer" in x.lower()][:4]
    if "printer" in lower:
        return "Possible printer (name hint)", Confidence.low, evidence[:4]
    if any(token in lower for token in ("_airplay._tcp", "_raop._tcp", "_hap._tcp", "_companion-link._tcp")):
        return "Apple ecosystem service (device class unknown)", Confidence.low, [x for x in evidence if x.startswith("mDNS")][:4]
    if any(token in lower for token in ("_googlecast._tcp", "googlecast", "chromecast")):
        return "Google Cast / media device hint", Confidence.low, [x for x in evidence if x.startswith("mDNS")][:4]
    if any(token in lower for token in ("_workstation._tcp", "_smb._tcp", "netbios")):
        return "Workstation / SMB-compatible host (OS unconfirmed)", Confidence.low, evidence[:4]
    return None, Confidence.low, []


async def fingerprint_devices(
    devices: List[Device],
    settings: Any,
    cancel: asyncio.Event,
    progress: Any,
    *,
    multicast: bool = False,
) -> Dict[str, Any]:
    """Fingerprint only the scan-confirmed devices, with fixed bounded probes."""
    progress.lan_fingerprint_started = True
    progress.lan_fingerprint_total = len(devices)
    progress.lan_fingerprint_completed = 0
    progress.lan_fingerprint_active = 0
    for device in devices:
        device.lan_fingerprint_status = "pending"

    configured_cap = max(1, min(MAX_TARGETS, int(getattr(settings, "lan_fingerprint_max_targets", MAX_TARGETS))))
    configured_workers = max(1, min(MAX_WORKERS, int(getattr(settings, "lan_fingerprint_max_workers", 2))))
    probe_timeout = max(0.1, min(MAX_TIMEOUT_S, float(getattr(settings, "lan_fingerprint_probe_timeout_s", 0.8))))
    total_timeout = max(1, min(MAX_TOTAL_TIMEOUT_S, int(getattr(settings, "lan_fingerprint_total_timeout_s", 90))))
    if len(devices) > configured_cap:
        for device in devices:
            device.lan_fingerprint_status = "rejected_cap"
        progress.lan_fingerprint_completed = len(devices)
        progress.lan_fingerprint_done = True
        return {"status": "rejected_cap", "target_count": len(devices), "max_targets": configured_cap}
    if not devices:
        progress.lan_fingerprint_done = True
        return {"status": "completed", "target_count": 0, "matched": 0, "multicast_enabled": multicast}

    interfaces = discovery.local_ipv4_interfaces()
    error, mapping = validate_targets(
        (device.ip for device in devices), interfaces, require_direct_route=True
    )
    if error:
        for device in devices:
            device.lan_fingerprint_status = "unavailable_scope"
        progress.lan_fingerprint_completed = len(devices)
        progress.lan_fingerprint_done = True
        return {"status": "unavailable_scope", "error": error, "target_count": len(devices)}
    if cancel.is_set():
        for device in devices:
            device.lan_fingerprint_status = "cancelled"
        progress.lan_fingerprint_done = True
        return {"status": "cancelled", "target_count": len(devices)}

    loop = asyncio.get_running_loop()
    phase_deadline = loop.time() + total_timeout
    evidence_by_ip: Dict[str, List[str]] = {device.ip: [] for device in devices}
    iface_by_key: Dict[Tuple[str, str], Dict[str, str]] = {}
    for iface in mapping.values():
        iface_by_key[(iface.get("name", ""), iface.get("cidr", ""))] = iface
    if multicast:
        # Separate explicit consent is required because queries reach all listeners
        # on these segments. Responses are retained only for scan targets.
        for iface in iface_by_key.values():
            remaining = phase_deadline - loop.time()
            if cancel.is_set() or remaining <= 0:
                break
            iface_timeout = min(probe_timeout * 2, remaining)
            try:
                responses = await asyncio.wait_for(
                    asyncio.to_thread(_query_multicast, iface, iface_timeout, cancel),
                    timeout=min(iface_timeout + 0.2, remaining),
                )
            except (asyncio.TimeoutError, OSError):
                responses = {}
            for ip, rows in responses.items():
                if ip in evidence_by_ip:
                    evidence_by_ip[ip].extend(rows)

    semaphore = asyncio.Semaphore(configured_workers)

    async def inspect(device: Device) -> None:
        if cancel.is_set():
            device.lan_fingerprint_status = "cancelled"
            return
        if loop.time() >= phase_deadline:
            device.lan_fingerprint_status = "timeout"
            progress.lan_fingerprint_completed += 1
            return
        async with semaphore:
            progress.lan_fingerprint_active += 1
            try:
                iface = mapping[device.ip]
                try:
                    rows = await asyncio.wait_for(
                        asyncio.to_thread(_query_nbns, iface["address"], device.ip, probe_timeout),
                        timeout=probe_timeout + 0.4,
                    )
                except (asyncio.TimeoutError, OSError):
                    rows = []
                evidence_by_ip[device.ip].extend(rows)
                evidence = list(dict.fromkeys(evidence_by_ip[device.ip]))[:MAX_EVIDENCE_ITEMS]
                label, confidence, label_evidence = _classify(evidence)
                if label:
                    device.device_type = label
                    device.device_type_confidence = confidence
                    device.device_type_source = ", ".join(
                        dict.fromkeys("mDNS" if x.startswith("mDNS") else "SSDP" if x.startswith("SSDP") else "NetBIOS" for x in label_evidence)
                    )
                    device.device_type_evidence = label_evidence[:MAX_EVIDENCE_ITEMS]
                    device.lan_fingerprint_status = "matched"
                else:
                    device.lan_fingerprint_status = "completed_no_match"
                    device.device_type_source = "fast-scan service role; LAN fingerprint had no identifying response"
                    device.device_type_evidence = evidence
            except asyncio.CancelledError:
                device.lan_fingerprint_status = "cancelled" if cancel.is_set() else "timeout"
                raise
            except Exception:
                device.lan_fingerprint_status = "error"
            finally:
                progress.lan_fingerprint_active = max(0, progress.lan_fingerprint_active - 1)
                progress.lan_fingerprint_completed += 1

    workers = [asyncio.create_task(inspect(device)) for device in devices]
    all_done = asyncio.gather(*workers)
    cancel_wait = asyncio.create_task(cancel.wait())
    try:
        done, _ = await asyncio.wait(
            {all_done, cancel_wait}, timeout=max(0, phase_deadline - loop.time()), return_when=asyncio.FIRST_COMPLETED
        )
        if cancel_wait in done and cancel.is_set() and not all_done.done():
            for task in workers:
                task.cancel()
            all_done.cancel()
        elif all_done not in done:
            for task in workers:
                task.cancel()
            all_done.cancel()
    finally:
        if not cancel_wait.done():
            cancel_wait.cancel()
        await asyncio.gather(cancel_wait, return_exceptions=True)
        await asyncio.gather(all_done, return_exceptions=True)
    for device in devices:
        if device.lan_fingerprint_status == "pending":
            device.lan_fingerprint_status = "cancelled" if cancel.is_set() else "timeout"
            progress.lan_fingerprint_completed += 1
    progress.lan_fingerprint_active = 0
    progress.lan_fingerprint_done = True
    status = (
        "cancelled" if cancel.is_set()
        else "partial_error" if any(d.lan_fingerprint_status == "error" for d in devices)
        else "partial_timeout" if any(d.lan_fingerprint_status == "timeout" for d in devices)
        else "completed"
    )
    return {
        "status": status,
        "target_count": len(devices),
        "matched": sum(d.lan_fingerprint_status == "matched" for d in devices),
        "multicast_enabled": multicast,
        "multicast_interfaces": len(iface_by_key) if multicast else 0,
        "max_workers": configured_workers,
    }

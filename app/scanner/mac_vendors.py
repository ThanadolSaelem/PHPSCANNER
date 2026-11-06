"""IEEE OUI MAC address vendor lookup and device category inference.

Provides fast in-memory OUI prefix resolution for common enterprise, cloud,
virtualisation, NAS, firewall, router, camera/NVR, and workstation vendors,
plus optional loading of an external ``mac_vendor_mapping.csv`` if present.
"""
from __future__ import annotations

import csv
import os
import re
from typing import Dict, Optional

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

"""Lightweight async TCP connect scan for web ports.

A plain connect() check — no raw sockets, no SYN scanning, nothing that needs
elevated privileges or that fingerprints evasively. We only want to know which
web ports answer so we can probe them over HTTP(S).
"""
from __future__ import annotations

import asyncio
from typing import List


async def is_open(ip: str, port: int, timeout: float) -> bool:
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False


async def open_ports(ip: str, ports: List[int], timeout: float) -> List[int]:
    results = await asyncio.gather(
        *(is_open(ip, port, timeout) for port in ports)
    )
    return [port for port, ok in zip(ports, results) if ok]

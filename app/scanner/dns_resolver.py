"""Reverse DNS resolution and Thai-government scope filtering.

This is the equivalent of ``nslookup -x <ip>`` (a PTR lookup), done with
dnspython for reliability and async friendliness. A host is considered *in
scope* only when its PTR name ends in one of the operator-selected suffixes
(default: go.th / or.th / mi.th).
"""
from __future__ import annotations

import asyncio
from typing import List, Optional, Tuple

import dns.asyncresolver
import dns.resolver
import dns.reversename


def _normalise(hostname: str) -> str:
    return hostname.rstrip(".").lower()


def match_suffix(hostname: Optional[str], suffixes: List[str]) -> Optional[str]:
    """Return the matched suffix if *hostname* is in scope, else ``None``.

    Matching is done on dotted-label boundaries so ``evil-go.th.attacker.com``
    does not match ``go.th`` and ``notgo.th`` does not match ``go.th``.
    """
    if not hostname:
        return None
    host = _normalise(hostname)
    for suffix in suffixes:
        suf = _normalise(suffix).lstrip(".")
        if host == suf or host.endswith("." + suf):
            return suf
    return None


class ReverseResolver:
    def __init__(
        self,
        dns_servers: Optional[List[str]] = None,
        timeout: float = 4.0,
    ) -> None:
        self._resolver = dns.asyncresolver.Resolver(configure=not dns_servers)
        if dns_servers:
            self._resolver.nameservers = dns_servers
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout

    async def reverse(self, ip: str) -> Optional[str]:
        """Return the first PTR name for *ip*, or ``None`` if there is none."""
        try:
            rev_name = dns.reversename.from_address(ip)
            answer = await self._resolver.resolve(rev_name, "PTR")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout,
                dns.exception.DNSException):
            return None
        for rdata in answer:
            return _normalise(str(rdata.target))
        return None

    async def resolve_and_match(
        self, ip: str, suffixes: List[str]
    ) -> Tuple[str, Optional[str], Optional[str]]:
        """Return ``(ip, hostname, matched_suffix)`` for a single address."""
        hostname = await self.reverse(ip)
        matched = match_suffix(hostname, suffixes)
        return ip, hostname, matched


async def resolve_batch(
    ips: List[str],
    suffixes: List[str],
    resolver: ReverseResolver,
    concurrency: int,
) -> List[Tuple[str, Optional[str], Optional[str]]]:
    sem = asyncio.Semaphore(max(1, concurrency))

    async def _one(ip: str):
        async with sem:
            return await resolver.resolve_and_match(ip, suffixes)

    return await asyncio.gather(*(_one(ip) for ip in ips))

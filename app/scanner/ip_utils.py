"""Parsing and expansion of operator-supplied target specifications.

Accepts three forms, one per line/entry:
  * CIDR .............. 203.0.113.0/24
  * hyphen range ...... 203.0.113.10-203.0.113.50  (or ...-50 shorthand)
  * single address .... 203.0.113.7

Sizing is computed arithmetically (never by materialising addresses) so an
over-large scope such as a ``/8`` is rejected instantly instead of expanding
16 million objects into memory. Expansion is bounded by ``max_targets`` so the
tool cannot be turned into an indiscriminate internet sweeper.
"""
from __future__ import annotations

import ipaddress
from typing import Iterable, Iterator, List, Tuple


class TargetError(ValueError):
    """Raised when a target specification cannot be parsed."""


def _bounds(spec: str) -> tuple[int, int]:
    """Return the inclusive ``(start_int, end_int)`` an spec covers.

    Network/broadcast are trimmed for CIDR prefixes shorter than /31 to mirror
    :func:`ipaddress.IPv4Network.hosts`. Raises :class:`TargetError` on bad input.
    Does not materialise any address.
    """
    spec = spec.strip()

    # CIDR
    if "/" in spec:
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError as exc:
            raise TargetError(f"Invalid CIDR: {spec!r} ({exc})") from exc
        if net.version != 4:
            raise TargetError(f"Only IPv4 is supported: {spec!r}")
        first = int(net.network_address)
        last = int(net.broadcast_address)
        if net.prefixlen <= 30:
            first += 1
            last -= 1
        return first, last

    # Hyphen range
    if "-" in spec:
        left, right = (part.strip() for part in spec.split("-", 1))
        try:
            start = ipaddress.ip_address(left)
        except ValueError as exc:
            raise TargetError(f"Invalid range start: {left!r}") from exc
        if right.isdigit():  # shorthand "203.0.113.10-50"
            octets = left.split(".")
            octets[-1] = right
            right = ".".join(octets)
        try:
            end = ipaddress.ip_address(right)
        except ValueError as exc:
            raise TargetError(f"Invalid range end: {right!r}") from exc
        if start.version != 4 or end.version != 4:
            raise TargetError(f"Only IPv4 is supported: {spec!r}")
        if int(end) < int(start):
            raise TargetError(f"Range end before start: {spec!r}")
        return int(start), int(end)

    # Single address
    try:
        addr = ipaddress.ip_address(spec)
    except ValueError as exc:
        raise TargetError(f"Invalid IP address: {spec!r}") from exc
    if addr.version != 4:
        raise TargetError(f"Only IPv4 is supported: {spec!r}")
    return int(addr), int(addr)


def _spec_size(spec: str) -> int:
    first, last = _bounds(spec)
    return last - first + 1


def _active_specs(specs: Iterable[str]) -> Iterator[str]:
    for spec in specs:
        s = spec.strip()
        if s and not s.startswith("#"):
            yield s


def count_targets(specs: Iterable[str]) -> int:
    """How many addresses the specs expand to (arithmetic, no materialisation)."""
    return sum(_spec_size(spec) for spec in _active_specs(specs))


def expand_targets(specs: Iterable[str], max_targets: int) -> Tuple[List[str], int]:
    """Expand specs to a de-duplicated, ordered list of IP strings.

    Returns ``(ips, total)`` where ``total`` is the raw count before de-dup.
    Raises :class:`TargetError` if the total exceeds ``max_targets`` — and does
    so *before* building the list, so an oversized scope costs nothing.
    """
    active = list(_active_specs(specs))
    total = sum(_spec_size(spec) for spec in active)  # validates + sizes cheaply
    if total > max_targets:
        raise TargetError(
            f"Scan would cover {total} addresses, exceeding the limit of "
            f"{max_targets}. Narrow the range or raise THSCAN_MAX_TARGETS."
        )

    seen: set[int] = set()
    ordered: List[str] = []
    for spec in active:
        first, last = _bounds(spec)
        for value in range(first, last + 1):
            if value not in seen:
                seen.add(value)
                ordered.append(str(ipaddress.ip_address(value)))
    return ordered, total


def iter_targets(specs: Iterable[str]) -> Iterator[str]:
    for spec in _active_specs(specs):
        first, last = _bounds(spec)
        for value in range(first, last + 1):
            yield str(ipaddress.ip_address(value))


def out_of_scope(
    specs: Iterable[str], allowed: "list[ipaddress.IPv4Network]"
) -> List[str]:
    """Return the target specs whose range is not fully inside *allowed*.

    An empty ``allowed`` means "no scope configured" and everything is rejected.
    Checking is done on the spec's integer bounds, so it is cheap even for a
    large CIDR.
    """
    if not allowed:
        return [s for s in _active_specs(specs)]
    bad: List[str] = []
    for spec in _active_specs(specs):
        first, last = _bounds(spec)
        covered = any(
            int(net.network_address) <= first and last <= int(net.broadcast_address)
            for net in allowed
        )
        if not covered:
            bad.append(spec)
    return bad


def label_targets(specs: Iterable[str]) -> str:
    """A short human label for a target list, e.g. '10.0.0.0/22' or '3 ช่วง'."""
    active = list(_active_specs(specs))
    if not active:
        return ""
    if len(active) == 1:
        return active[0]
    return f"{len(active)} ช่วง"

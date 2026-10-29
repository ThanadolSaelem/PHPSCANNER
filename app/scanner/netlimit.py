"""One process-wide cap on simultaneous outbound connections.

Every probe (liveness, port check, HTTP) takes a slot, so a big port scan can
never exhaust file descriptors. Without this, macOS (default limit 256 open
files) would fail connects with EMFILE and hosts would silently look offline.
"""
from __future__ import annotations

import asyncio
import os
import weakref
from contextlib import asynccontextmanager
from typing import AsyncIterator

try:
    import resource
except ImportError:  # Windows
    resource = None  # type: ignore


def _compute_limit() -> int:
    env = os.environ.get("THSCAN_MAX_SOCKETS", "")
    if env.isdigit() and int(env) > 0:
        return int(env)
    if resource is None:
        return 256
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    want = 4096 if hard == resource.RLIM_INFINITY else min(hard, 4096)
    if soft < want:
        try:  # raising the soft limit up to the hard limit needs no privilege
            resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
            soft = want
        except (ValueError, OSError):
            pass
    # keep headroom for the web server, log files and DNS
    return max(16, min(512, soft // 2 - 32))


MAX_SOCKETS = _compute_limit()
_sems: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Semaphore]" = weakref.WeakKeyDictionary()


@asynccontextmanager
async def slot() -> AsyncIterator[None]:
    loop = asyncio.get_running_loop()
    sem = _sems.get(loop)
    if sem is None:
        sem = _sems[loop] = asyncio.Semaphore(MAX_SOCKETS)
    async with sem:
        yield

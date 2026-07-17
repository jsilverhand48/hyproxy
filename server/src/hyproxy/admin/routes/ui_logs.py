"""Ingest endpoint for browser-side SPA logs -> <log_dir>/ui.log.

Unauthenticated by design: the errors most worth capturing happen before or
during login, and the portal origin is internet-facing. Abuse is contained
by strict payload caps (batch and field lengths below) and an in-memory
token bucket per client IP plus a global cap. Deliberately NOT backed by
security/ratelimit.py: that throttle writes a DB row per hit, which would
turn log spam into a database DoS.
"""

import logging
import time
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from hyproxy.core.netutil import resolve_client_ip
from hyproxy.logs import file_logger

router = APIRouter(prefix="/api/v1", tags=["ui-logs"])

_MAX_ENTRIES = 20
_PER_IP_PER_MIN = 10
_GLOBAL_PER_MIN = 60


class UiLogEntry(BaseModel):
    level: Literal["info", "warn", "error"]
    msg: str = Field(max_length=2000)
    stack: str | None = Field(default=None, max_length=8000)
    url: str | None = Field(default=None, max_length=500)
    ts: str | None = Field(default=None, max_length=64)


class UiLogBatch(BaseModel):
    entries: Annotated[list[UiLogEntry], Field(min_length=1, max_length=_MAX_ENTRIES)]


class _Bucket:
    """Fixed-window counters; entries expire with the window, so the per-IP
    map cannot grow past one window of distinct senders."""

    def __init__(self) -> None:
        self.window_start = 0
        self.global_count = 0
        self.per_ip: dict[str, int] = {}

    def allow(self, ip: str, now: float) -> bool:
        window = int(now // 60)
        if window != self.window_start:
            self.window_start = window
            self.global_count = 0
            self.per_ip.clear()
        if self.global_count >= _GLOBAL_PER_MIN or self.per_ip.get(ip, 0) >= _PER_IP_PER_MIN:
            return False
        self.global_count += 1
        self.per_ip[ip] = self.per_ip.get(ip, 0) + 1
        return True


_bucket = _Bucket()

_LEVELS = {"info": logging.INFO, "warn": logging.WARNING, "error": logging.ERROR}


@router.post("/ui-logs", status_code=204)
async def ingest_ui_logs(batch: UiLogBatch, request: Request) -> None:
    client_ip = resolve_client_ip(request)
    if not _bucket.allow(client_ip, time.time()):
        raise HTTPException(status_code=429, detail="rate limited")
    logger = file_logger("hyproxy.ui", "ui.log", "ui")
    for entry in batch.entries:
        logger.log(
            _LEVELS[entry.level],
            entry.msg,
            extra={
                "src": client_ip,
                "stack": entry.stack,
                "url": entry.url,
                "client_ts": entry.ts,
            },
        )

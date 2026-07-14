"""Centralized logging for the Python control plane.

One scheme across the whole stack (Python apps, Go dataplane, Node tunnel,
UI ingest): JSON lines with keys ts (ISO-8601 UTC), level (lowercase),
service, logger, msg, plus record extras flattened at the top level.

Files live under settings.log_dir (HYPROXY_LOG_DIR), one file per service
(idp.log, admin.log, authz.log, cli.log, plus ui.log and audit.log via
file_logger). Rotation is size-based: when a file exceeds log_max_bytes the
chain shifts (x.log -> x.log.1 -> x.log.2) and anything older is deleted,
so at most log_backup_count (2) archives exist per file.

An empty log_dir disables file logging entirely (dev default); everything
still goes to stderr for journald / docker logs. Unhandled request errors
reach the files through uvicorn.error propagation, wired in setup_logging.
"""

import fcntl
import json
import logging
import os
import sys
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import override

# LogRecord attributes that are bookkeeping, not user extras
# (color_message is uvicorn's ANSI duplicate of msg).
_STANDARD_ATTRS = frozenset(
    {
        "args",
        "color_message",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "message",
        "module",
        "msecs",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)


class JsonLineFormatter(logging.Formatter):
    def __init__(self, service: str) -> None:
        super().__init__()
        self._service = service

    def format(self, record: logging.LogRecord) -> str:
        out: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname.lower(),
            "service": self._service,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _STANDARD_ATTRS and not key.startswith("_") and key not in out:
                out[key] = value
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        return json.dumps(out, separators=(",", ":"), default=str)


class SafeRotatingFileHandler(RotatingFileHandler):
    """RotatingFileHandler that tolerates multiple processes on one host
    (the authz app runs 2 uvicorn workers against one file).

    Two additions: reopen the stream when another process rotated the file
    out from under us (inode watch), and guard rollover with an exclusive
    flock on a sidecar so only one process rotates. Writes are O_APPEND
    single lines, so interleaving is not a practical concern.
    """

    def __init__(self, filename: str | os.PathLike[str], **kwargs: object) -> None:
        super().__init__(filename, delay=True, **kwargs)  # type: ignore[arg-type]
        self._dev_ino: tuple[int, int] | None = None

    def _remember(self) -> None:
        try:
            st = os.stat(self.baseFilename)
            self._dev_ino = (st.st_dev, st.st_ino)
        except OSError:
            self._dev_ino = None

    def emit(self, record: logging.LogRecord) -> None:
        try:
            st = os.stat(self.baseFilename)
            current = (st.st_dev, st.st_ino)
        except OSError:
            current = None
        if self.stream is not None and current != self._dev_ino:
            self.stream.close()
            self.stream = None  # next write reopens the live file
        super().emit(record)
        if current != self._dev_ino:
            self._remember()

    @override
    def shouldRollover(self, record: logging.LogRecord) -> bool:
        if self.maxBytes <= 0:
            return False
        try:
            return os.path.getsize(self.baseFilename) >= self.maxBytes
        except OSError:
            return False

    @override
    def doRollover(self) -> None:
        lock_path = self.baseFilename + ".lock"
        with open(lock_path, "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                # Another worker may have rotated while we waited on the lock.
                try:
                    if os.path.getsize(self.baseFilename) < self.maxBytes:
                        return
                except OSError:
                    return
                super().doRollover()
                self._remember()
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)


_configured: set[str] = set()


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def _make_file_handler(
    log_dir: str, filename: str, service: str
) -> SafeRotatingFileHandler | None:
    """Rotating handler on log_dir/filename, or None (with a stderr warning)
    when the directory is unusable. Logging must never take a service down."""
    from hyproxy.config import get_settings

    settings = get_settings()
    path = Path(log_dir) / filename
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        handler = SafeRotatingFileHandler(
            path,
            maxBytes=settings.log_max_bytes,
            backupCount=settings.log_backup_count,
        )
    except OSError as exc:
        print(f"hyproxy.logs: cannot open {path}: {exc}; stderr only", file=sys.stderr)
        return None
    handler.setFormatter(JsonLineFormatter(service))
    return handler


def setup_logging(service: str) -> None:
    """Configure the root logger for a service: JSON lines to stderr always,
    plus a rotating <service>.log under settings.log_dir when set. Idempotent
    per service (create_app may run more than once in-process)."""
    if service in _configured:
        return
    _configured.add(service)

    from hyproxy.config import get_settings

    settings = get_settings()
    root = logging.getLogger()
    root.setLevel(settings.log_level.upper())

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(JsonLineFormatter(service))
    root.handlers = [stderr_handler]

    if settings.log_dir:
        file_handler = _make_file_handler(settings.log_dir, f"{service}.log", service)
        if file_handler is not None:
            root.addHandler(file_handler)

    # Funnel uvicorn (error + access) through the root handlers so backend
    # request lines land in this service's file. The canonical HTTP access
    # log is the dataplane's (dataplane-access.log); these are for
    # correlating backend behavior. Runs after uvicorn's own dictConfig
    # (app import happens later), so this wins.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uv = logging.getLogger(name)
        uv.handlers.clear()
        uv.propagate = True


def file_logger(name: str, filename: str, service: str) -> logging.Logger:
    """Dedicated non-propagating logger with its own rotating file (used for
    ui.log and audit.log, which are separate streams from the service log).
    Falls back to stderr when log_dir is empty or unwritable."""
    from hyproxy.config import get_settings

    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    logger.propagate = False

    settings = get_settings()
    handler: logging.Handler | None = None
    if settings.log_dir:
        handler = _make_file_handler(settings.log_dir, filename, service)
    if handler is None:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(JsonLineFormatter(service))
    logger.addHandler(handler)
    return logger

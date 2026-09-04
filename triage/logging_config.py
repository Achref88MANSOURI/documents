"""Pipeline-wide logging — installs one console handler and one rotating
file handler, both tagging every log line with the alert it belongs to.

Not architecture v4 — a deployment addition, 2026-08-21. Before this, 12
modules already called `logging.getLogger(__name__)` but nothing anywhere
called `logging.basicConfig()` or configured a handler/formatter/level, so
Python's logging defaults applied: root at WARNING, a bare "lastResort"
handler with no timestamp and no way to tell which alert a line belonged to.
Almost every existing call was `.warning`/`.error` (failure paths) — there
was no visibility into the happy path at any level, because nothing was
configured to print INFO/DEBUG at all.

`configure_logging()` is called once, automatically, from `nodes/__init__.py`
and `tools/__init__.py` — every node/tool module lives under one of those two
packages, so importing any of them (a real run, an ad-hoc verification
script, or pytest) triggers setup with no `main.py` dependency.

Retroactive by design: `_AlertIdFilter` tags EVERY log record via the alert-
id `ContextVar`, including the ~30 `logger.warning`/`.debug` calls that
already existed in this codebase before this file did. None of those call
sites needed editing to pick up the alert-id tag.
"""

from __future__ import annotations

import contextlib
import logging
import logging.handlers
import sys
from contextvars import ContextVar
from pathlib import Path

import config

# ContextVar, not a thread-local — this is an asyncio codebase, and
# ContextVar is the one mechanism that propagates correctly through `await`
# boundaries and concurrent tasks. A thread-local would silently show "-" (or
# worse, a stale value from a different alert) for anything logged from
# inside an awaited coroutine.
alert_id_var: ContextVar[str] = ContextVar("alert_id", default="-")

FORMAT = "%(asctime)s %(levelname)-8s [%(alert_id)s] %(name)s: %(message)s"

_configured = False

# Third-party libraries whose own DEBUG output drowns out this pipeline's —
# confirmed live 2026-08-21: LOG_LEVEL=DEBUG produced pages of httpcore/httpx
# wire-level frames before this list existed, burying the actual per-tool
# lifecycle logs _guard.py adds. These stay at WARNING regardless of
# config.LOG_LEVEL; nothing in this pipeline has needed transport-level
# tracing yet, and anyone who does can still raise these two individually.
_NOISY_LOGGERS = ("httpcore", "httpx", "asyncio")


class _AlertIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.alert_id = alert_id_var.get()
        return True


def configure_logging() -> None:
    """Idempotent — a module-level flag, not a `root.handlers` empty-check.
    Pytest (or another framework) may already have attached its own handlers
    by the time this runs; this must add its own alongside them, not decide
    "someone else configured logging, skip" and leave the console/file
    handlers with alert-id tagging unset."""
    global _configured
    if _configured:
        return
    _configured = True

    root = logging.getLogger()
    root.setLevel(config.LOG_LEVEL)

    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)

    formatter = logging.Formatter(FORMAT)
    alert_filter = _AlertIdFilter()

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    console.addFilter(alert_filter)
    root.addHandler(console)

    if config.LOG_FILE:
        path = Path(config.LOG_FILE)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            path, maxBytes=10_000_000, backupCount=5
        )
        file_handler.setFormatter(formatter)
        file_handler.addFilter(alert_filter)
        root.addHandler(file_handler)


@contextlib.contextmanager
def alert_context(alert_id: str):
    """Tag every log line emitted inside this block — and everything it
    awaits, including tool calls several layers down — with `alert_id`.
    Resets via the token on exit so nested or concurrent alerts never leak
    into each other's log lines."""
    token = alert_id_var.set(alert_id or "-")
    try:
        yield
    finally:
        alert_id_var.reset(token)

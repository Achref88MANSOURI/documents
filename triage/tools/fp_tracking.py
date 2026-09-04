"""`get_fp_signal` and `record_triage_outcome` — architecture §6 tool 1, §18.

Local SQLite (`config.FP_TRACKING_DB_PATH`), created on first run. This is
the tightest-budget, highest-value Stage 1 tool: 100ms budget
(`STAGE_1_TOOL_TIMEOUT_FP`), and per architecture's own citation (AACT,
arXiv:2505.09843) the single strongest per-rule FP signal available — and
unlike `search_closed_cases_by_rule` (empty for ~3 months after deployment)
it's useful from the very first alert.

THREE DELIBERATE DESIGN DECISIONS, agreed with the maintainer, that diverge
from architecture §6 tool 1's illustrative example:

1. **SQLite, not MySQL.** Matches `config.FP_TRACKING_DB_PATH` (already
   defined) and architecture's own file-layout comment. No server, no
   credentials, no new dependency.

2. **Two INDEPENDENT signals, not one joint rate.** `FPSignal` (see
   `schemas/evidence.py`) reports the rule's FP history regardless of host,
   and the host's FP history regardless of rule — two separate counts, not
   one rate filtered `WHERE rule_uuid=? AND host=?`. `get_fp_signal` still
   takes both `rule_uuid` and `host` (it needs both to report both), it just
   never joins them together in a single query.

3. **Counts, not a rate.** `record_triage_outcome` is called ONLY when an
   alert closes as `false_positive` (never on a true-positive close) — same
   as architecture's own INSERT example, which never shows a TP write either.
   With only FP events ever logged, `fp_count / total_count` has no valid
   denominator, so this tool reports the raw count as the signal, not a
   0.0-1.0 fraction.

**Time-windowing is kept** (24h short-term, 30d long-term, per architecture)
by storing a timestamped event-log table (`fp_events`) rather than raw
mutable counters, and computing two independent `COUNT(*) ... WHERE
triage_timestamp >= ?` queries per window (one by `rule_uuid`, one by
`host`). From the caller's side this behaves exactly like "a rule counter"
and "a host counter" — internally it's an indexed COUNT over a small table,
which gets the windowing for free. Window cutoffs are computed in Python
(`datetime.now(timezone.utc) - timedelta(...)`), not SQLite's `datetime('now',
...)`, so they're deterministic and injectable in tests via the `now=`
keyword on both functions.

Both functions NEVER RAISE. `sqlite3` is synchronous, so the actual work runs
in `asyncio.to_thread(...)`, wrapped in `asyncio.wait_for(..., timeout)` —
same shape as every other Stage 1 tool's async wrapper, just around a thread
instead of an HTTP call. Zero history for a given rule/host is a real,
fully-successful result (`FPSignal()` all-zero, `gap=None`) — implementation
guide §2's own verification-input table says so explicitly. A `Gap` means an
actual backend problem: a corrupt/locked DB file, an unwritable storage
directory, or a timeout — architecture's stated failure mode ("SQLite file
corrupted -> returns zeros, not catastrophic") still holds; a Gap accompanies
those zeros so the caller can tell "no history" from "couldn't check."
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import config
from schemas import FPSignal, Gap

logger = logging.getLogger(__name__)

TOOL_NAME_GET = "get_fp_signal"
TOOL_NAME_RECORD = "record_triage_outcome"
SOURCE = "fp_tracking"

SHORT_TERM_WINDOW = timedelta(hours=24)
LONG_TERM_WINDOW = timedelta(days=30)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS fp_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_uuid TEXT NOT NULL,
    host TEXT NOT NULL,
    triage_timestamp TEXT NOT NULL,
    analyst_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_fp_events_rule ON fp_events(rule_uuid, triage_timestamp);
CREATE INDEX IF NOT EXISTS idx_fp_events_host ON fp_events(host, triage_timestamp);
"""


def _connect(db_path: str) -> sqlite3.Connection:
    """Open a connection, creating the parent directory, file, and schema on
    first run (architecture §18: "created on first run"). Idempotent — safe
    to call on every invocation, matches the no-persistent-connection pattern
    every other Stage 1 tool already uses (a fresh httpx client per call)."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")  # concurrent Stage-1 reads while Stage-6 writes
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


def _count_rule_since(conn: sqlite3.Connection, rule_uuid: str, cutoff_iso: str) -> int:
    row = conn.execute(
        "SELECT COUNT(*) FROM fp_events WHERE rule_uuid = ? AND triage_timestamp >= ?",
        (rule_uuid, cutoff_iso),
    ).fetchone()
    return row[0] if row else 0


def _count_host_since(conn: sqlite3.Connection, host: str, cutoff_iso: str) -> int:
    row = conn.execute(
        "SELECT COUNT(*) FROM fp_events WHERE host = ? AND triage_timestamp >= ?",
        (host, cutoff_iso),
    ).fetchone()
    return row[0] if row else 0


def _get_fp_signal_sync(
    db_path: str, rule_uuid: str | None, host: str | None, now: datetime
) -> FPSignal:
    conn = _connect(db_path)
    try:
        short_cutoff = (now - SHORT_TERM_WINDOW).isoformat()
        long_cutoff = (now - LONG_TERM_WINDOW).isoformat()
        signal = FPSignal()
        if rule_uuid:
            signal.rule_fp_count_24h = _count_rule_since(conn, rule_uuid, short_cutoff)
            signal.rule_fp_count_30d = _count_rule_since(conn, rule_uuid, long_cutoff)
        if host:
            signal.host_fp_count_24h = _count_host_since(conn, host, short_cutoff)
            signal.host_fp_count_30d = _count_host_since(conn, host, long_cutoff)
        return signal
    finally:
        conn.close()


def _record_sync(
    db_path: str, rule_uuid: str, host: str, analyst_reason: str | None, now: datetime
) -> None:
    conn = _connect(db_path)
    try:
        conn.execute(
            "INSERT INTO fp_events (rule_uuid, host, triage_timestamp, analyst_reason) "
            "VALUES (?, ?, ?, ?)",
            (rule_uuid, host, now.isoformat(), analyst_reason),
        )
        conn.commit()
    finally:
        conn.close()


async def get_fp_signal(
    rule_uuid: str | None,
    host: str | None,
    timeout: float | None = None,
    *,
    now: datetime | None = None,
) -> tuple[FPSignal, Gap | None]:
    """How often has this rule fired FP (any host), and this host had FP
    closures (any rule), in the last 24h / 30d?

    NEVER RAISES. Returns `(FPSignal, Gap | None)`:

    - history found or genuinely empty -> `(FPSignal(...), None)` — zero
      counts with no Gap is a real, fully successful "no history yet" result
      (implementation guide §2), not a failure.
    - nothing to look up               -> `(FPSignal(), Gap)`, DB never touched
    - backend problem                  -> `(FPSignal(), Gap)` with the reason;
                                           counts stay at zero either way, per
                                           architecture's stated failure mode

    `now` is keyword-only and exists for deterministic testing — real callers
    never pass it.
    """
    timeout = timeout if timeout is not None else config.STAGE_1_TOOL_TIMEOUT_FP
    started = time.monotonic()

    def elapsed_ms() -> int:
        return int((time.monotonic() - started) * 1000)

    if not rule_uuid and not host:
        return FPSignal(), Gap(
            source=SOURCE,
            tool=TOOL_NAME_GET,
            reason="No rule uuid or host on the alert — nothing to look up",
            duration_ms=elapsed_ms(),
        )

    resolved_now = now or datetime.now(timezone.utc)

    try:
        signal = await asyncio.wait_for(
            asyncio.to_thread(
                _get_fp_signal_sync, config.FP_TRACKING_DB_PATH, rule_uuid, host, resolved_now
            ),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        logger.warning("%s timed out after %.1fs", TOOL_NAME_GET, timeout)
        return FPSignal(), Gap(
            source=SOURCE,
            tool=TOOL_NAME_GET,
            reason=f"Timeout after {timeout}s querying the local FP tracker",
            duration_ms=elapsed_ms(),
        )
    except sqlite3.Error as exc:
        logger.warning("%s DB error: %s", TOOL_NAME_GET, exc)
        return FPSignal(), Gap(
            source=SOURCE,
            tool=TOOL_NAME_GET,
            reason=f"FP tracker DB error: {type(exc).__name__}: {exc}",
            duration_ms=elapsed_ms(),
        )
    except OSError as exc:
        logger.warning("%s storage error: %s", TOOL_NAME_GET, exc)
        return FPSignal(), Gap(
            source=SOURCE,
            tool=TOOL_NAME_GET,
            reason=f"FP tracker storage error: {exc}",
            duration_ms=elapsed_ms(),
        )
    except Exception as exc:  # noqa: BLE001 — a tool must never raise into gather
        logger.warning("%s failed: %s", TOOL_NAME_GET, exc)
        return FPSignal(), Gap(
            source=SOURCE,
            tool=TOOL_NAME_GET,
            reason=f"{type(exc).__name__}: {exc}",
            duration_ms=elapsed_ms(),
        )

    return signal, None


async def record_triage_outcome(
    rule_uuid: str,
    host: str,
    analyst_reason: str | None = None,
    timeout: float | None = None,
    *,
    now: datetime | None = None,
) -> tuple[bool, Gap | None]:
    """Record a false-positive triage closure.

    Call this ONLY when an alert closes as `false_positive` (architecture's
    "FP feedback loop", Stage 6 / `/feedback` endpoint — not wired yet, build
    order step 8). Never call it for a true-positive close — see module
    docstring, design decision 3. The caller decides the verdict; this
    function only writes.

    NEVER RAISES. Returns `(True, None)` on success, `(False, Gap)` on any
    failure (missing keys, backend problem, timeout).

    Reuses `STAGE_1_TOOL_TIMEOUT_FP` as the default budget — this write
    happens from Stage 6, not Stage 1, but no dedicated timeout constant
    exists yet and 100ms is still generous for a local insert; a Stage-6
    constant can be added in config.py when `nodes/audit.py` is built.
    """
    timeout = timeout if timeout is not None else config.STAGE_1_TOOL_TIMEOUT_FP
    started = time.monotonic()

    def elapsed_ms() -> int:
        return int((time.monotonic() - started) * 1000)

    if not rule_uuid or not host:
        return False, Gap(
            source=SOURCE,
            tool=TOOL_NAME_RECORD,
            reason="rule_uuid and host are both required to record a triage outcome",
            duration_ms=elapsed_ms(),
        )

    resolved_now = now or datetime.now(timezone.utc)

    try:
        await asyncio.wait_for(
            asyncio.to_thread(
                _record_sync,
                config.FP_TRACKING_DB_PATH,
                rule_uuid,
                host,
                analyst_reason,
                resolved_now,
            ),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        logger.warning("%s timed out after %.1fs", TOOL_NAME_RECORD, timeout)
        return False, Gap(
            source=SOURCE,
            tool=TOOL_NAME_RECORD,
            reason=f"Timeout after {timeout}s writing to the local FP tracker",
            duration_ms=elapsed_ms(),
        )
    except sqlite3.Error as exc:
        logger.warning("%s DB error: %s", TOOL_NAME_RECORD, exc)
        return False, Gap(
            source=SOURCE,
            tool=TOOL_NAME_RECORD,
            reason=f"FP tracker DB error: {type(exc).__name__}: {exc}",
            duration_ms=elapsed_ms(),
        )
    except OSError as exc:
        logger.warning("%s storage error: %s", TOOL_NAME_RECORD, exc)
        return False, Gap(
            source=SOURCE,
            tool=TOOL_NAME_RECORD,
            reason=f"FP tracker storage error: {exc}",
            duration_ms=elapsed_ms(),
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("%s failed: %s", TOOL_NAME_RECORD, exc)
        return False, Gap(
            source=SOURCE,
            tool=TOOL_NAME_RECORD,
            reason=f"{type(exc).__name__}: {exc}",
            duration_ms=elapsed_ms(),
        )

    return True, None

"""Shared node plumbing: bound a tool coroutine, skip one deliberately, and
defensively unpack `asyncio.gather(..., return_exceptions=True)` results.

Extracted from `nodes/gather.py` (pure move, no behavior change) so
`nodes/rag.py` doesn't duplicate it — `tools/es_client.py`'s own module
docstring makes the argument for extraction generally: duplicating shared
plumbing across modules "is how the two drift apart." Every node that wraps
several backend/tool calls in one `asyncio.gather` imports from here.

Also the single injection point for per-tool lifecycle logging (2026-08-21).
Every one of Stage 1's 8 tools and Stage 2's 3 Qdrant calls passes through
`_guarded`/`_skip` — adding entry/exit/duration DEBUG logs here covers all 11
tool calls with zero edits to any individual `tools/*.py` file. DEBUG, not
INFO: this is the "every tool call" firehose; INFO is reserved for the
per-stage narrative in each `nodes/*.py` file, so the default log level
(`config.LOG_LEVEL=INFO`) reads as a story, not a wall of noise.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, TypeVar

from schemas import Gap

logger = logging.getLogger(__name__)

T = TypeVar("T")


async def _guarded(
    coro, *, seconds: float, default: T, source: str, tool: str
) -> tuple[T, Gap | None]:
    """Bound a tool coroutine with an outer timeout and never let anything
    escape it — see module docstring."""
    started = time.monotonic()
    logger.debug("tool %s started (timeout=%.1fs)", tool, seconds)
    try:
        result, gap = await asyncio.wait_for(coro, timeout=seconds)
        elapsed_ms = int((time.monotonic() - started) * 1000)
        if gap is not None:
            logger.debug("tool %s completed in %dms with a Gap: %s", tool, elapsed_ms, gap.reason)
        else:
            logger.debug("tool %s completed in %dms", tool, elapsed_ms)
        return result, gap
    except asyncio.TimeoutError:
        logger.debug("tool %s hit the gather-level timeout after %.1fs", tool, seconds)
        return default, Gap(
            source=source,
            tool=tool,
            reason=f"gather-level timeout after {seconds}s",
            duration_ms=int(seconds * 1000),
        )
    except Exception as exc:  # noqa: BLE001 — belt-and-suspenders, see module docstring
        logger.warning("gather guard caught an unexpected error from %s: %s", tool, exc)
        return default, Gap(
            source=source,
            tool=tool,
            reason=f"Unexpected error: {type(exc).__name__}: {exc}",
            duration_ms=0,
        )


async def _skip(*, default: T, source: str, tool: str, reason: str) -> tuple[T, Gap | None]:
    """No coroutine to run at all — e.g. a dataset gate or a disabled feature
    flag."""
    logger.debug("tool %s skipped: %s", tool, reason)
    return default, Gap(source=source, tool=tool, reason=reason, duration_ms=0)


def _unpack(result: Any, default: T) -> tuple[T, Gap | None]:
    """`_guarded`/`_skip` always return a `(value, Gap | None)` tuple. This is
    purely defensive, for the case `asyncio.gather(..., return_exceptions=True)`
    catches something that escaped `_guarded` anyway (a bug in `_guarded`
    itself) — synthesize a final fallback Gap rather than raising a confusing
    unpacking error."""
    if isinstance(result, BaseException):
        return default, Gap(
            source="node",
            tool="unknown",
            reason=(
                "Unhandled exception escaped _guarded and reached the outer "
                f"asyncio.gather: {type(result).__name__}: {result}"
            ),
            duration_ms=0,
        )
    return result

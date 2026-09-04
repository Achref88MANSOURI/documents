"""`retrieve_mitre` / `retrieve_playbooks` / `retrieve_cve` / `retrieve_incidents`
— Stage 2 RAG retrieval, architecture §7 (plus a deployment-added 4th
collection).

Deterministic Python, NOT an LLM-callable tool — no tool schema is exposed
anywhere in this module. `nodes/rag.py` (build-order step 4, not yet built)
calls these functions BEFORE either LLM stage runs and assembles the results
into `EnrichedEvidence`; Stage 3's single-shot call then reads that as plain
data. This matches every other `tools/*.py` in this repo and CLAUDE.md's hard
constraint that neither LLM call has tool access.

VERIFIED AGAINST THE LIVE BACKEND 2026-08-16. Qdrant at `config.QDRANT_URL`,
embedding microservice at `config.EMBEDDING_API_URL`
(`POST {"text": ...} -> {"embedding": [float x 1024]}`, BAAI/bge-m3, 1024-dim
Cosine on every collection). Four real collections, point counts confirmed
live:

    mitre_techniques   697 points
    soc_playbooks       48 points  (8 runbooks x ~6 sections)
    cve_context       6358 points
    incident_history     2 points  (grows as TheHive cases close)

`triage_kb` (2412 points) also exists and is a known test artifact — never
queried by this module.

THREE THINGS THE REAL BACKEND DOES THAT AN ILLUSTRATIVE SPEC DID NOT SAY:

1. Real point payloads for mitre_techniques/soc_playbooks/cve_context do NOT
   match architecture §7's illustrative example fields — see the corrected
   `MitreCandidate` / `PlaybookMatch` / `CveMatch` docstrings in
   `schemas/evidence.py`. This module maps the REAL payload keys.
2. Qdrant's payload filter on a keyword field is EXACT match only, confirmed
   live against `cve_context.affected_products`:
   `match: {value: "openssl:openssl"}` -> 1 hit,
   `match: {value: "openssl"}` -> 0 hits. A bare product name from evidence
   can never be used as a server-side filter, so `retrieve_cve`'s product
   narrowing is a CLIENT-SIDE substring filter over a wider semantic
   candidate set, not a Qdrant `filter`.
3. The embedding model is not loaded in-process (architecture §7's "loaded
   ONCE at service startup as a module-level singleton" assumes an in-process
   model) — it's its own already-running HTTP microservice, colocated on the
   same host as Qdrant. There is nothing to initialize once on this side;
   every call below is a fresh, cheap HTTP round trip, matching every other
   `tools/*.py`'s own fresh-client-per-call convention (see
   `tools/opencti.py`).

`incident_history` is a deployment-added 4th collection, not in architecture
v4 §7's three — see CLAUDE.md "Deployment-specific decisions" and
`IncidentMatch`'s docstring in `schemas/evidence.py`. It is a semantic-search
COMPLEMENT to `tools.thehive.search_closed_cases_by_rule`'s exact rule_uuid
match, not a replacement for it — that tool keeps running in Stage 1
unchanged.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, TypeVar

import httpx

import config
from schemas import CveMatch, Gap, IncidentMatch, MitreCandidate, PlaybookMatch

logger = logging.getLogger(__name__)

SOURCE = "qdrant"
TOOL_NAME_MITRE = "retrieve_mitre"
TOOL_NAME_PLAYBOOKS = "retrieve_playbooks"
TOOL_NAME_CVE = "retrieve_cve"
TOOL_NAME_INCIDENTS = "retrieve_incidents"

MITRE_COLLECTION = "mitre_techniques"
PLAYBOOK_COLLECTION = "soc_playbooks"
CVE_COLLECTION = "cve_context"
INCIDENT_COLLECTION = "incident_history"

# architecture §7: broader recall for MITRE, tighter for the other three.
MITRE_MIN_SIMILARITY = 0.5
PLAYBOOK_MIN_SIMILARITY = 0.55
CVE_MIN_SIMILARITY = 0.55
INCIDENT_MIN_SIMILARITY = 0.55

# retrieve_cve's candidate pool when a product filter is requested (see module
# docstring point 2). MUST be wide, not a small multiple of top_k: verified
# live 2026-08-16 that a real matching CVE (CVE-2026-31789, openssl:openssl)
# ranked 48th by semantic score among 50 candidates for an on-topic OpenSSL
# query — cve_context mixes thousands of CRITICAL-severity CVEs across
# unrelated products at similar score bands (~0.6-0.66), so a shallow
# candidate window (e.g. top_k*4 = 12) would almost always miss the actual
# product match and silently fall back to unfiltered results, defeating the
# filter's purpose. 50 candidates cost ~0.4s live-measured, well inside
# STAGE_1_TOOL_TIMEOUT_QDRANT's 3s budget alongside the embed call.
_CVE_PRODUCT_FILTER_CANDIDATE_POOL = 50

T = TypeVar("T")


def _describe_error(exc: Exception, url: str) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        body = (exc.response.text or "")[:200].replace("\n", " ")
        return f"HTTP {exc.response.status_code} from {url}: {body}"
    if isinstance(exc, httpx.ConnectError):
        return f"Cannot connect to {url}: {exc}"
    if isinstance(exc, httpx.ReadTimeout):
        return f"Read timeout from {url}: {exc}"
    return f"{type(exc).__name__}: {exc}"


async def _embed(text: str, client: httpx.AsyncClient) -> list[float]:
    """POST config.EMBEDDING_API_URL/embed. Raises on transport/HTTP error or
    an unusable response — the caller converts that into a Gap."""
    response = await client.post(f"{config.EMBEDDING_API_URL}/embed", json={"text": text})
    response.raise_for_status()
    data = response.json()
    embedding = data.get("embedding")
    if not isinstance(embedding, list) or not embedding:
        raise ValueError(f"Embedding API returned no usable 'embedding' field: {str(data)[:200]}")
    return embedding


async def _search(
    collection: str,
    vector: list[float],
    *,
    top_k: int,
    score_threshold: float,
    client: httpx.AsyncClient,
) -> list[dict[str, Any]]:
    """POST config.QDRANT_URL/collections/{collection}/points/search. Raises
    on transport/HTTP error — the caller converts that into a Gap.
    `score_threshold` excludes low-similarity hits entirely (verified live —
    they are not returned with a low score, they are absent)."""
    body = {
        "vector": vector,
        "limit": top_k,
        "with_payload": True,
        "score_threshold": score_threshold,
    }
    response = await client.post(
        f"{config.QDRANT_URL}/collections/{collection}/points/search", json=body
    )
    response.raise_for_status()
    data = response.json()
    return data.get("result") or []


async def _fetch_hits(
    collection: str, query_text: str, top_k: int, score_threshold: float, timeout: float
) -> list[dict[str, Any]]:
    async with httpx.AsyncClient(timeout=timeout) as client:
        vector = await _embed(query_text, client)
        return await _search(
            collection, vector, top_k=top_k, score_threshold=score_threshold, client=client
        )


def _mitre_from_hit(hit: dict[str, Any]) -> MitreCandidate:
    payload = hit.get("payload") or {}
    return MitreCandidate(
        technique_id=payload.get("technique_id", ""),
        technique_name=payload.get("name", ""),
        tactic=payload.get("tactic") or [],
        platforms=payload.get("platforms") or [],
        is_sub_technique=bool(payload.get("is_sub_technique", False)),
        parent_technique_id=payload.get("parent_technique_id"),
        x_mitre_version=payload.get("x_mitre_version"),
        detection_strategy_id=payload.get("detection_strategy_id"),
        analytic_ids=payload.get("analytic_ids") or [],
        log_sources=payload.get("log_sources") or [],
        score=float(hit.get("score", 0.0)),
    )


def _playbook_from_hit(hit: dict[str, Any]) -> PlaybookMatch:
    payload = hit.get("payload") or {}
    return PlaybookMatch(
        playbook_id=payload.get("runbook_id", ""),
        title=payload.get("title", ""),
        category=payload.get("category", ""),
        section=payload.get("section", ""),
        runbook_section_id=payload.get("runbook_section_id", ""),
        document_text=payload.get("document_text", ""),
        score=float(hit.get("score", 0.0)),
    )


def _cve_from_hit(hit: dict[str, Any]) -> CveMatch:
    payload = hit.get("payload") or {}
    return CveMatch(
        cve_id=payload.get("cve_id", ""),
        cvss_score=payload.get("cvss_score"),
        severity=payload.get("severity"),
        published_date=payload.get("published_date"),
        affected_products=payload.get("affected_products") or [],
        score=float(hit.get("score", 0.0)),
    )


def _incident_from_hit(hit: dict[str, Any]) -> IncidentMatch:
    payload = hit.get("payload") or {}
    return IncidentMatch(
        incident_id=payload.get("incident_id", ""),
        case_number=payload.get("case_number"),
        title=payload.get("title", ""),
        severity=payload.get("severity"),
        status=payload.get("status"),
        stage=payload.get("stage"),
        attack_type=payload.get("attack_type", ""),
        tags=payload.get("tags") or [],
        summary=payload.get("summary", ""),
        end_date=payload.get("end_date"),
        engine=payload.get("engine"),
        score=float(hit.get("score", 0.0)),
    )


async def _retrieve(
    *,
    collection: str,
    query_text: str,
    top_k: int,
    score_threshold: float,
    map_hit: Callable[[dict[str, Any]], T],
    tool: str,
    timeout: float | None,
) -> tuple[list[T], Gap | None]:
    """Shared NEVER-RAISES body for all four retrieve_* functions. Returns
    `(hits, Gap | None)`:

    - hits found or genuinely none clear score_threshold -> `(list, None)` —
      an empty list with no Gap is a real, fully successful result, same
      convention as every other Stage 1/2 tool in this repo.
    - nothing to embed        -> `([], Gap)`, network never touched
    - embed/search/timeout failure -> `([], Gap)` with the transport reason
    """
    timeout = timeout if timeout is not None else config.STAGE_1_TOOL_TIMEOUT_QDRANT
    started = time.monotonic()

    def elapsed_ms() -> int:
        return int((time.monotonic() - started) * 1000)

    if not query_text or not query_text.strip():
        return [], Gap(
            source=SOURCE,
            tool=tool,
            reason="Empty query_text — nothing to embed or search",
            duration_ms=elapsed_ms(),
        )

    try:
        hits = await asyncio.wait_for(
            _fetch_hits(collection, query_text, top_k, score_threshold, timeout),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        logger.warning("%s timed out after %.1fs", tool, timeout)
        return [], Gap(
            source=SOURCE,
            tool=tool,
            reason=f"Timeout after {timeout}s embedding/searching {collection}",
            duration_ms=elapsed_ms(),
        )
    except Exception as exc:  # noqa: BLE001 — a tool must never raise into gather
        logger.warning("%s failed for %s: %s", tool, collection, exc)
        return [], Gap(
            source=SOURCE,
            tool=tool,
            reason=_describe_error(exc, config.QDRANT_URL),
            duration_ms=elapsed_ms(),
        )

    try:
        return [map_hit(h) for h in hits], None
    except Exception as exc:  # noqa: BLE001
        logger.warning("%s could not map hits for %s: %s", tool, collection, exc)
        return [], Gap(
            source=SOURCE,
            tool=tool,
            reason=f"Hit mapping failed: {type(exc).__name__}: {exc}",
            duration_ms=elapsed_ms(),
        )


async def retrieve_mitre(
    query_text: str, top_k: int = 5, timeout: float | None = None
) -> tuple[list[MitreCandidate], Gap | None]:
    """Always called (architecture §7): grounds the LLM's MITRE technique
    output against the real corpus instead of letting it invent IDs cold.
    `query_text` should be the single most behaviorally specific observation
    from the evidence, NOT the full evidence package concatenated — a
    multi-behavior blob collapses recall on the technique that actually
    matters (see nodes/rag.py, not yet built, for query construction).

    NEVER RAISES. See `_retrieve` for the `(result, Gap | None)` contract.
    """
    return await _retrieve(
        collection=MITRE_COLLECTION,
        query_text=query_text,
        top_k=top_k,
        score_threshold=MITRE_MIN_SIMILARITY,
        map_hit=_mitre_from_hit,
        tool=TOOL_NAME_MITRE,
        timeout=timeout,
    )


async def retrieve_playbooks(
    query_text: str, top_k: int = 3, timeout: float | None = None
) -> tuple[list[PlaybookMatch], Gap | None]:
    """Conditional (architecture §7) — the caller (`nodes/rag.py`) decides
    whether the alert matches a known playbook trigger pattern before calling
    this; this function always performs the query it's asked for. Multiple
    sections (Detection, Investigation Steps, Containment, ...) sharing one
    `playbook_id` in a single result set is expected, not a duplicate.

    NEVER RAISES. See `_retrieve` for the `(result, Gap | None)` contract.
    """
    return await _retrieve(
        collection=PLAYBOOK_COLLECTION,
        query_text=query_text,
        top_k=top_k,
        score_threshold=PLAYBOOK_MIN_SIMILARITY,
        map_hit=_playbook_from_hit,
        tool=TOOL_NAME_PLAYBOOKS,
        timeout=timeout,
    )


async def retrieve_cve(
    query_text: str,
    product: str | None = None,
    top_k: int = 3,
    timeout: float | None = None,
) -> tuple[list[CveMatch], Gap | None]:
    """Conditional (architecture §7) — caller decides whether evidence has
    product/version/exploit indicators before calling this.

    `product`, if given, narrows results to CVEs whose `affected_products`
    contains it as a case-insensitive substring — CLIENT-SIDE, not a Qdrant
    filter. `affected_products` is a `vendor:product` CPE-style keyword field
    and Qdrant's payload filter on it is EXACT match only (verified live —
    see module docstring). A bare product name from evidence would never
    exact-match a CPE string, so this fetches a wider semantic candidate set
    first, then substring-filters client-side, then truncates to `top_k`.
    Falls back to the unfiltered semantic results if no product is given, or
    if the substring filter would leave nothing.

    NEVER RAISES. See `_retrieve` for the `(result, Gap | None)` contract.
    """
    fetch_k = _CVE_PRODUCT_FILTER_CANDIDATE_POOL if product else top_k
    candidates, gap = await _retrieve(
        collection=CVE_COLLECTION,
        query_text=query_text,
        top_k=fetch_k,
        score_threshold=CVE_MIN_SIMILARITY,
        map_hit=_cve_from_hit,
        tool=TOOL_NAME_CVE,
        timeout=timeout,
    )
    if gap is not None or not product:
        return candidates[:top_k], gap

    needle = product.strip().lower()
    filtered = [c for c in candidates if any(needle in p.lower() for p in c.affected_products)]
    return (filtered or candidates)[:top_k], gap


async def retrieve_incidents(
    query_text: str, top_k: int = 3, timeout: float | None = None
) -> tuple[list[IncidentMatch], Gap | None]:
    """Always called — a deployment-added complement to
    `tools.thehive.search_closed_cases_by_rule`'s exact rule_uuid match, see
    `IncidentMatch`'s docstring. Returns `[]` gracefully while the collection
    is still near-empty (2 points today, 2026-08-16) — a real, checked result,
    not a failure.

    NEVER RAISES. See `_retrieve` for the `(result, Gap | None)` contract.
    """
    return await _retrieve(
        collection=INCIDENT_COLLECTION,
        query_text=query_text,
        top_k=top_k,
        score_threshold=INCIDENT_MIN_SIMILARITY,
        map_hit=_incident_from_hit,
        tool=TOOL_NAME_INCIDENTS,
        timeout=timeout,
    )

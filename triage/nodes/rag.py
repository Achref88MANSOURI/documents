"""`rag_enrichment` — Stage 2, architecture §7 (trimmed to this deployment's
scope — see module docstring notes below).

Runs three Qdrant retrievals in parallel: `retrieve_mitre` (always),
`retrieve_incidents` (always, deployment-added 4th collection — see
`tools/qdrant.py`), and `retrieve_cve` (gated on `_has_cve_indicators`, which
reuses the already-tested `_extract_product_hint` heuristic — re-enabled
2026-08-19, gap #3; previously hardcoded off, see git history / CLAUDE.md).
Turns Stage 1's `RawEvidence` into Stage 3's input, `EnrichedEvidence`.

**`retrieve_playbooks` is deliberately NOT called here.** Playbook/runbook
retrieval's natural query input is Stage 3's confirmed MITRE mapping
(`ContextualAssessment.refined_mitre_mapping`, which is populated for every
alert regardless of source engine — Sigma, Suricata, or YARA), not anything
Stage 1/2 has. `rule_context.mitre_tactics` — the only MITRE-tactic field
Stage 2 has access to — is Sigma-`attack.*`-tag-only: Suricata and YARA
alerts never populate it, and plenty of Sigma rules don't either. Querying
playbooks from it here would silently zero out playbook retrieval for a
large share of alerts, forever. Playbook lookup is out of scope for this
node; it is not designed or implemented anywhere in this repo yet.

Same two-layer never-raises pattern as `nodes/gather.py`: each
`tools.qdrant.retrieve_*` call is already internally `NEVER RAISES`
(`tools/qdrant.py`'s own contract), `_guarded` (now shared, see
`nodes/_guard.py`) adds an outer `asyncio.wait_for` as the last line of
defense, and one `asyncio.gather(..., return_exceptions=True)` sits on top
per CLAUDE.md's hard constraint.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import config
from logging_config import alert_context
from nodes._guard import _guarded, _skip, _unpack
from schemas import CanonicalAlert, EnrichedEvidence, RawEvidence
from tools import qdrant

logger = logging.getLogger(__name__)

MAX_MITRE_QUERY_CHARS = 500
MAX_DESCRIPTION_CHARS = 200
MAX_COMMAND_LINE_CHARS = 300

# Signer names observed on the one real fixture — the OS vendor's own
# certificate, never a third-party product. See _extract_product_hint.
_GENERIC_SIGNERS = {"microsoft windows", "microsoft corporation"}


def _truncate(text: str, max_len: int) -> str:
    text = text.strip()
    return text if len(text) <= max_len else text[:max_len].rstrip()


def _most_specific_behavior_keyword(alert: CanonicalAlert) -> str | None:
    """Exactly one priority-selected behavioral phrase — never a
    concatenation of everything available. See module docstring / the
    approved plan for why a multi-behavior blob collapses MITRE recall."""
    if alert.process and alert.process.api and alert.process.api.name:
        api = alert.process.api
        target_name = (alert.target_process.name if alert.target_process else None) or (
            "target process"
        )
        return f"{api.name} call against {target_name} with {api.desired_access}"

    if alert.process and alert.process.command_line:
        collapsed = " ".join(alert.process.command_line.split())
        return _truncate(collapsed, MAX_COMMAND_LINE_CHARS)

    if alert.network and (alert.network.dst_ip or alert.network.dst_ipv6):
        dst = alert.network.dst_ip or alert.network.dst_ipv6
        protocol = alert.network.protocol or "unknown protocol"
        if alert.network.dst_port:
            return f"network connection to {dst}:{alert.network.dst_port} over {protocol}"
        return f"network connection to {dst} over {protocol}"

    if alert.file:
        if alert.file.malware and alert.file.malware.signature_name:
            return alert.file.malware.signature_name
        if alert.file.name:
            return f"file {alert.file.name}"

    if alert.library and alert.library.name:
        return f"module load {alert.library.name}"

    return None


def _build_mitre_query(evidence: RawEvidence) -> str:
    alert = evidence.canonical_alert
    rule_ctx = evidence.rule_context

    title = (rule_ctx.title if rule_ctx and rule_ctx.title else None) or alert.rule.name
    parts = [title] if title else []

    if rule_ctx and rule_ctx.description:
        parts.append(_truncate(rule_ctx.description, MAX_DESCRIPTION_CHARS))

    keyword = _most_specific_behavior_keyword(alert)
    if keyword:
        parts.append(keyword)

    return " — ".join(p.strip() for p in parts if p and p.strip())[:MAX_MITRE_QUERY_CHARS]


def _build_incident_query(evidence: RawEvidence) -> str:
    """Reuses the MITRE query verbatim — the same "what actually happened"
    content is what should match a similar past incident. Kept as its own
    named function so a future divergence in requirements doesn't force
    touching the MITRE call site."""
    return _build_mitre_query(evidence)


def _extract_product_hint(evidence: RawEvidence) -> str | None:
    alert = evidence.canonical_alert
    for sig in (
        alert.file.code_signature if alert.file else None,
        alert.process.code_signature if alert.process else None,
    ):
        if sig and sig.subject_name and sig.subject_name.strip().lower() not in _GENERIC_SIGNERS:
            return sig.subject_name.strip()
    if alert.file and alert.file.name:
        return alert.file.name  # weakest signal, last resort
    return None


def _build_cve_query(evidence: RawEvidence, product_hint: str | None) -> str:
    alert = evidence.canonical_alert
    rule_ctx = evidence.rule_context
    title = (rule_ctx.title if rule_ctx and rule_ctx.title else None) or alert.rule.name
    technique = rule_ctx.mitre_attack[0] if rule_ctx and rule_ctx.mitre_attack else ""
    return " ".join(p for p in (product_hint, title, technique) if p).strip()


def _has_cve_indicators(evidence: RawEvidence) -> bool:
    # Gate re-enabled 2026-08-19 (gap #3). Previously hardcoded False because
    # the one real fixture available at the time (sigma-alert-real.json) has
    # process.code_signature.subject_name = "Microsoft Windows" throughout —
    # the OS vendor's own cert, not a third-party product — so there was no
    # real example to validate a product-detection heuristic against.
    # _extract_product_hint already implements that heuristic correctly (excludes
    # generic OS signers, falls back to filename) and was fully tested — it was
    # just never wired to anything. Reusing it here rather than duplicating its
    # logic: CVE retrieval fires whenever it finds a signal, on the same terms
    # already proven correct against the real fixture (still resolves to no
    # signal there — Microsoft-signed is still excluded).
    return _extract_product_hint(evidence) is not None


async def rag_enrichment(evidence: RawEvidence) -> EnrichedEvidence:
    with alert_context(evidence.canonical_alert.alert_id):
        return await _rag_enrichment(evidence)


async def _rag_enrichment(evidence: RawEvidence) -> EnrichedEvidence:
    started = time.monotonic()
    logger.info("Stage 2 started")

    if _has_cve_indicators(evidence):
        product_hint = _extract_product_hint(evidence)
        cve_call = _guarded(
            qdrant.retrieve_cve(_build_cve_query(evidence, product_hint), product=product_hint),
            seconds=config.STAGE_1_TOOL_TIMEOUT_QDRANT,
            default=[],
            source=qdrant.SOURCE,
            tool=qdrant.TOOL_NAME_CVE,
        )
    else:
        cve_call = _skip(
            default=[],
            source=qdrant.SOURCE,
            tool=qdrant.TOOL_NAME_CVE,
            reason=(
                "CVE gate disabled — no product-identifying field verified "
                "against real data yet; see nodes/rag.py::_has_cve_indicators"
            ),
        )

    calls = [
        _guarded(
            qdrant.retrieve_mitre(_build_mitre_query(evidence)),
            seconds=config.STAGE_1_TOOL_TIMEOUT_QDRANT,
            default=[],
            source=qdrant.SOURCE,
            tool=qdrant.TOOL_NAME_MITRE,
        ),
        cve_call,
        _guarded(
            qdrant.retrieve_incidents(_build_incident_query(evidence)),
            seconds=config.STAGE_1_TOOL_TIMEOUT_QDRANT,
            default=[],
            source=qdrant.SOURCE,
            tool=qdrant.TOOL_NAME_INCIDENTS,
        ),
    ]

    results = await asyncio.gather(*calls, return_exceptions=True)
    enriched = _build_enriched_evidence(evidence, results, started)
    logger.info(
        "Stage 2 completed in %dms: %d mitre, %d incident, %d cve matches",
        enriched.stage_2_duration_ms,
        len(enriched.mitre_candidates),
        len(enriched.incident_matches),
        len(enriched.cve_matches),
    )
    return enriched


def _build_enriched_evidence(
    evidence: RawEvidence, results: list[Any], started: float
) -> EnrichedEvidence:
    mitre_candidates, gap_mitre = _unpack(results[0], [])
    cve_matches, gap_cve = _unpack(results[1], [])
    incident_matches, gap_incident = _unpack(results[2], [])

    new_gaps = [g for g in (gap_mitre, gap_cve, gap_incident) if g is not None]

    return EnrichedEvidence(
        **evidence.model_dump(exclude={"investigation_gaps"}),
        investigation_gaps=list(evidence.investigation_gaps) + new_gaps,
        mitre_candidates=mitre_candidates,
        cve_matches=cve_matches,
        incident_matches=incident_matches,
        stage_2_duration_ms=int((time.monotonic() - started) * 1000),
    )

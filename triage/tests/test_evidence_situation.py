"""`EvidenceSituation`/`EvidenceSource` — v5 redesign (`newdesign.md` §3).

Replaces `confidence`/`contextual_modifiers`/`llm_criticality_score` on
`ContextualAssessment`. Two things are covered here: the models themselves
(construction, literal enums), and `nodes/context.py::_stage_3_fallback`'s
deterministic build of `evidence_situation` from `evidence.investigation_gaps`
when the Stage 3 LLM call itself fails — the one place in this codebase that
constructs an `EvidenceSituation` without an LLM in the loop.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx
import pytest

from nodes import context as context_mod
from schemas import (
    CanonicalAlert,
    EnrichedEvidence,
    EvidenceSituation,
    EvidenceSource,
    Gap,
    RawEvidence,
    Rule,
)


def run(coro):
    return asyncio.run(coro)


def make_alert(**overrides) -> CanonicalAlert:
    defaults = dict(
        alert_id="~1",
        timestamp=datetime.now(timezone.utc),
        rule=Rule(name="Test Rule", uuid="test-uuid"),
    )
    defaults.update(overrides)
    return CanonicalAlert(**defaults)


def make_evidence(*, investigation_gaps=None) -> EnrichedEvidence:
    raw = RawEvidence(canonical_alert=make_alert(), investigation_gaps=investigation_gaps or [])
    return EnrichedEvidence(**raw.model_dump())


class TestEvidenceSourceConstruction:
    def test_valid_statuses(self):
        for status in ("present", "empty", "missing"):
            source = EvidenceSource(source_name="rule_context", status=status, impact_on_triage="x")
            assert source.status == status

    def test_invalid_status_is_rejected(self):
        with pytest.raises(Exception):
            EvidenceSource(source_name="rule_context", status="unknown", impact_on_triage="x")


class TestEvidenceSituationConstruction:
    def test_valid_reliability_levels(self):
        for level in ("high", "medium", "low"):
            situation = EvidenceSituation(
                sources=[], overall_evidence_reliability=level, analyst_must_verify=[]
            )
            assert situation.overall_evidence_reliability == level

    def test_invalid_reliability_is_rejected(self):
        with pytest.raises(Exception):
            EvidenceSituation(sources=[], overall_evidence_reliability="critical", analyst_must_verify=[])

    def test_evidence_situation_is_required_on_contextual_assessment(self):
        """No default — a ContextualAssessment missing evidence_situation
        entirely must fail validation, the same way correlation_decision
        (the only other required field) already does."""
        from schemas import ContextualAssessment, CorrelationDecision

        with pytest.raises(Exception):
            ContextualAssessment(
                correlation_decision=CorrelationDecision(action="new"),
            )


class TestStage3FallbackBuildsEvidenceSituation:
    """nodes/context.py::_stage_3_fallback — the deterministic,
    LLM-independent construction of evidence_situation when Stage 3 itself
    fails. Mirrors TASK 5's missing-vs-present distinction, but built purely
    from evidence.investigation_gaps (Gap.tool), since there is no LLM
    output to draw a status judgment from at all on this path."""

    def test_reliability_is_always_low(self, monkeypatch):
        async def raising_call_llm(evidence):
            raise httpx.ConnectError("simulated")

        monkeypatch.setattr(context_mod, "_call_llm", raising_call_llm)
        assessment = run(context_mod.context_analysis(make_evidence()))

        assert assessment.evidence_situation.overall_evidence_reliability == "low"

    def test_analyst_must_verify_is_non_empty(self, monkeypatch):
        async def raising_call_llm(evidence):
            raise httpx.ConnectError("simulated")

        monkeypatch.setattr(context_mod, "_call_llm", raising_call_llm)
        assessment = run(context_mod.context_analysis(make_evidence()))

        assert len(assessment.evidence_situation.analyst_must_verify) >= 1
        assert "Stage 3 LLM call failed" in assessment.evidence_situation.analyst_must_verify[0]

    def test_all_eight_sources_are_covered(self, monkeypatch):
        async def raising_call_llm(evidence):
            raise httpx.ConnectError("simulated")

        monkeypatch.setattr(context_mod, "_call_llm", raising_call_llm)
        assessment = run(context_mod.context_analysis(make_evidence()))

        names = {s.source_name for s in assessment.evidence_situation.sources}
        assert names == {
            "fp_signal",
            "rule_context",
            "open_cases",
            "closed_cases_summary",
            "asset_context",
            "related_alerts_24h",
            "process_history_24h",
            "opencti_enrichment",
        }

    def test_source_named_in_a_real_gap_is_missing(self, monkeypatch):
        async def raising_call_llm(evidence):
            raise httpx.ConnectError("simulated")

        monkeypatch.setattr(context_mod, "_call_llm", raising_call_llm)
        gap = Gap(source="elasticsearch", reason="timeout after 5s", tool="process_history_24h")
        assessment = run(context_mod.context_analysis(make_evidence(investigation_gaps=[gap])))

        by_name = {s.source_name: s for s in assessment.evidence_situation.sources}
        assert by_name["process_history_24h"].status == "missing"

    def test_source_not_named_in_any_gap_is_present(self, monkeypatch):
        async def raising_call_llm(evidence):
            raise httpx.ConnectError("simulated")

        monkeypatch.setattr(context_mod, "_call_llm", raising_call_llm)
        gap = Gap(source="elasticsearch", reason="timeout after 5s", tool="process_history_24h")
        assessment = run(context_mod.context_analysis(make_evidence(investigation_gaps=[gap])))

        by_name = {s.source_name: s for s in assessment.evidence_situation.sources}
        assert by_name["rule_context"].status == "present"

    def test_mutation_guard_gap_source_detection_actually_matters(self, monkeypatch):
        """Confirms the missing/present split is driven by real Gap data, not
        a hardcoded constant — two different gap sets must produce two
        different missing sets."""

        async def raising_call_llm(evidence):
            raise httpx.ConnectError("simulated")

        monkeypatch.setattr(context_mod, "_call_llm", raising_call_llm)

        no_gaps = run(context_mod.context_analysis(make_evidence(investigation_gaps=[])))
        with_gap = run(
            context_mod.context_analysis(
                make_evidence(
                    investigation_gaps=[
                        Gap(source="thehive", reason="500 error", tool="open_cases")
                    ]
                )
            )
        )

        no_gaps_missing = {
            s.source_name for s in no_gaps.evidence_situation.sources if s.status == "missing"
        }
        with_gap_missing = {
            s.source_name for s in with_gap.evidence_situation.sources if s.status == "missing"
        }
        assert no_gaps_missing == set()
        assert with_gap_missing == {"open_cases"}

"""`TriageResult` — v5 redesign (`newdesign.md` §6). No more `PriorityScore`;
priority fields now come straight from `TriageVerdict`/`ContextualAssessment`
via `main.py::_build_triage_result`, a thin, math-free assembly function
that replaces the deleted `nodes/score.py::priority_scoring` Stage 5 node.
"""

from __future__ import annotations

from datetime import datetime, timezone

from schemas import (
    CanonicalAlert,
    ContextualAssessment,
    CorrelationDecision,
    EnrichedEvidence,
    EvidenceSituation,
    EvidenceSource,
    Host,
    RawEvidence,
    Rule,
    TriageResult,
    TriageVerdict,
    User,
)

import main


def make_alert() -> CanonicalAlert:
    return CanonicalAlert(
        alert_id="~1",
        timestamp=datetime.now(timezone.utc),
        rule=Rule(name="Test Rule", uuid="x"),
        host=Host(hostname="win-test"),
        user=User(name="tester"),
    )


def make_evidence() -> EnrichedEvidence:
    raw = RawEvidence(canonical_alert=make_alert())
    return EnrichedEvidence(**raw.model_dump())


def make_context(**overrides) -> ContextualAssessment:
    defaults = dict(
        correlation_decision=CorrelationDecision(action="new", reasoning="correlation reasoning"),
        evidence_situation=EvidenceSituation(
            sources=[
                EvidenceSource(
                    source_name="rule_context", status="present", impact_on_triage="fine"
                )
            ],
            overall_evidence_reliability="medium",
            analyst_must_verify=["Verify asset criticality manually"],
        ),
    )
    defaults.update(overrides)
    return ContextualAssessment(**defaults)


def make_verdict(**overrides) -> TriageVerdict:
    defaults = dict(
        likelihood="likely",
        impact_if_true="significant",
        verdict="true_positive",
        reasoning="verdict reasoning",
        summary="verdict summary",
        recommended_action="create_case",
        priority_band="P2",
        priority_reasoning="P2 because confirmed malicious, no active spread",
        investigation_gaps=["Verify asset criticality manually"],
        safety_gate_applied=False,
    )
    defaults.update(overrides)
    return TriageVerdict(**defaults)


class TestTriageResultHasNoPriorityScore:
    def test_priority_field_does_not_exist(self):
        assert "priority" not in TriageResult.model_fields

    def test_priority_score_class_is_gone(self):
        import schemas

        assert not hasattr(schemas, "PriorityScore")


class TestTriageResultPriorityFieldsComeFromVerdict:
    def test_priority_band_and_reasoning(self):
        result = main._build_triage_result(make_verdict(), make_context(), make_evidence())
        assert result.priority_band == "P2"
        assert result.priority_reasoning == "P2 because confirmed malicious, no active spread"

    def test_investigation_gaps_comes_from_verdict_not_context(self):
        """v5 (newdesign.md §9): investigation_gaps now sources from
        TriageVerdict.investigation_gaps (Stage 4's consolidated task list),
        not the removed ContextualAssessment.additional_investigation_gaps."""
        context = make_context()
        context.additional_investigation_gaps = ["a stage-3-only gap that must NOT appear"]
        verdict = make_verdict(investigation_gaps=["the real Stage 4 consolidated gap"])

        result = main._build_triage_result(verdict, context, make_evidence())

        assert result.investigation_gaps == ["the real Stage 4 consolidated gap"]
        assert "a stage-3-only gap that must NOT appear" not in result.investigation_gaps

    def test_safety_gate_applied_is_copied_through(self):
        result = main._build_triage_result(
            make_verdict(safety_gate_applied=True), make_context(), make_evidence()
        )
        assert result.safety_gate_applied is True

    def test_evidence_situation_comes_from_context(self):
        result = main._build_triage_result(make_verdict(), make_context(), make_evidence())
        assert result.evidence_situation.overall_evidence_reliability == "medium"
        assert result.evidence_situation.analyst_must_verify == ["Verify asset criticality manually"]


class TestTriageResultBuilderIsPureNoMath:
    """The whole point of the v5 redesign — no scoring formula anywhere.
    Mutation guard: if a future change reintroduces a numeric priority
    field, this test's field-set assertion should be revisited deliberately,
    not silently pass."""

    def test_result_fields_are_all_traceable_to_verdict_or_context(self):
        verdict = make_verdict()
        context = make_context()
        result = main._build_triage_result(verdict, context, make_evidence())

        assert result.verdict == verdict.verdict
        assert result.recommended_action == verdict.recommended_action
        assert result.summary == verdict.summary
        assert result.reasoning == verdict.reasoning
        assert result.likelihood == verdict.likelihood
        assert result.impact_if_true == verdict.impact_if_true
        assert result.stage_3_reasoning == context.correlation_decision.reasoning
        assert result.refined_mitre_mapping == context.refined_mitre_mapping

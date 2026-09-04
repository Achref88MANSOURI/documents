"""`nodes/analyze.py::_apply_safety_backstop` — v5 redesign (`newdesign.md`
§4). Deterministic safety gate applied after Stage 4's LLM output is parsed:
if evidence reliability is "low" and the LLM assigned P4/P5 anyway, escalate
one band. Belt-and-suspenders behind the identical prompt instruction in
`prompts/analyst_agent.py`'s `== EVIDENCE SITUATION ==` section — this test
file exercises the deterministic code path directly, bypassing the LLM
entirely, the same way `tests/test_context.py::TestMergeTargetValidation`
proves `_validate_merge_target` holds independently of schema enforcement.
"""

from __future__ import annotations

from nodes import analyze as analyze_mod
from schemas import ContextualAssessment, CorrelationDecision, EvidenceSituation, TriageVerdict


def make_context(reliability: str) -> ContextualAssessment:
    return ContextualAssessment(
        correlation_decision=CorrelationDecision(action="new", reasoning="test"),
        evidence_situation=EvidenceSituation(
            sources=[], overall_evidence_reliability=reliability, analyst_must_verify=[]
        ),
    )


def make_verdict(priority_band: str) -> TriageVerdict:
    return TriageVerdict(
        likelihood="possible",
        impact_if_true="moderate",
        verdict="needs_review",
        reasoning="x",
        summary="x",
        recommended_action="needs_review",
        priority_band=priority_band,
        priority_reasoning="original reasoning",
    )


class TestFiresOnLowReliabilityAndLowBand:
    def test_p5_escalates_to_p4(self):
        verdict, fired = analyze_mod._apply_safety_backstop(
            make_verdict("P5"), make_context("low")
        )
        assert fired is True
        assert verdict.priority_band == "P4"

    def test_p4_escalates_to_p3(self):
        verdict, fired = analyze_mod._apply_safety_backstop(
            make_verdict("P4"), make_context("low")
        )
        assert fired is True
        assert verdict.priority_band == "P3"

    def test_reasoning_states_the_escalation_and_why(self):
        verdict, fired = analyze_mod._apply_safety_backstop(
            make_verdict("P5"), make_context("low")
        )
        assert "SAFETY GATE APPLIED" in verdict.priority_reasoning
        assert "P5" in verdict.priority_reasoning
        assert "P4" in verdict.priority_reasoning
        # original LLM reasoning is preserved, not replaced
        assert "original reasoning" in verdict.priority_reasoning


class TestDoesNotFireOnHigherBands:
    def test_p3_does_not_escalate(self):
        verdict, fired = analyze_mod._apply_safety_backstop(
            make_verdict("P3"), make_context("low")
        )
        assert fired is False
        assert verdict.priority_band == "P3"
        assert verdict.priority_reasoning == "original reasoning"

    def test_p2_does_not_escalate(self):
        verdict, fired = analyze_mod._apply_safety_backstop(
            make_verdict("P2"), make_context("low")
        )
        assert fired is False
        assert verdict.priority_band == "P2"

    def test_p1_does_not_escalate(self):
        verdict, fired = analyze_mod._apply_safety_backstop(
            make_verdict("P1"), make_context("low")
        )
        assert fired is False
        assert verdict.priority_band == "P1"


class TestDoesNotFireOnAdequateReliability:
    def test_medium_reliability_p5_is_untouched(self):
        verdict, fired = analyze_mod._apply_safety_backstop(
            make_verdict("P5"), make_context("medium")
        )
        assert fired is False
        assert verdict.priority_band == "P5"

    def test_high_reliability_p5_is_untouched(self):
        verdict, fired = analyze_mod._apply_safety_backstop(
            make_verdict("P5"), make_context("high")
        )
        assert fired is False
        assert verdict.priority_band == "P5"


class TestReturnsANewObjectNotAMutation:
    def test_original_verdict_object_is_unmodified(self):
        original = make_verdict("P5")
        updated, fired = analyze_mod._apply_safety_backstop(original, make_context("low"))
        assert fired is True
        assert original.priority_band == "P5"
        assert updated.priority_band == "P4"
        assert updated is not original

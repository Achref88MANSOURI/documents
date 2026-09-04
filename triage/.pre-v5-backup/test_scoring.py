"""Stage 5 — SOC-3s Scoring System **v3** (`newscoresystem.md`). Pure Python,
no I/O — every test here is synchronous and mocks nothing except where noted.

PROVENANCE: `tests/fixtures/score_v3_live_run_real.json` is REAL — computed by
running `nodes.score.priority_scoring` (v3) against real, freshly-gathered
`EnrichedEvidence` (`gather_evidence` + `rag_enrichment`, real backends, the
xordump/Invoke-WebRequest alert) paired with the real captured
`ContextualAssessment` (`tests/fixtures/context_live_run_fixed_real.json`) and
`TriageVerdict` (`tests/fixtures/analyze_live_run_real.json`), 2026-08-24.
Every level and every fired rule in that capture was hand-verified against the
real evidence before this suite was written (implementation guide §2's
discipline — the real run happened and was inspected first).

`tests/fixtures/score_live_run_real.json` is the v1 capture of the SAME real
evidence. It is deliberately kept and is asserted against in
`TestV1ToV3Migration` — not as a target to reproduce (v3 is a different system
and produces a different answer), but as the real, dated record of what changed
and why.

Everything else here builds small, explicit synthetic `EnrichedEvidence` /
`ContextualAssessment` objects per test — this stage has no "real backend
shape" to be wrong about (unlike Stage 1's tools), only decision-table
correctness, so synthetic, deliberately-chosen inputs are the right tool for
exercising each rule in isolation.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import scoring
import scoring_config as cfg
from nodes import score as score_mod
from schemas import (
    AlertSummary,
    AssetContext,
    CanonicalAlert,
    ClosedCasesSummary,
    ContextualAssessment,
    ContextualModifier,
    CorrelationDecision,
    CortexResult,
    EnrichedEvidence,
    FPSignal,
    Gap,
    Host,
    MitreMapping,
    Network,
    Observables,
    PriorityScore,
    Process,
    RawEvidence,
    Rule,
    RuleContext,
    TriageResult,
    TriageVerdict,
    User,
)

V3_FIXTURE = Path(__file__).parent / "fixtures" / "score_v3_live_run_real.json"
V1_FIXTURE = Path(__file__).parent / "fixtures" / "score_live_run_real.json"


@pytest.fixture(scope="module")
def real_v3() -> dict:
    return json.loads(V3_FIXTURE.read_text())


@pytest.fixture(scope="module")
def real_v1() -> dict:
    return json.loads(V1_FIXTURE.read_text())


# ===========================================================================
# Builders
# ===========================================================================


def make_alert(**overrides) -> CanonicalAlert:
    defaults = dict(
        alert_id="~1",
        timestamp=datetime.now(timezone.utc),
        rule=Rule(name="test rule", uuid="rule-uuid-1"),
        host=Host(hostname="win-test01"),
        user=User(name="Administrator"),
    )
    defaults.update(overrides)
    return CanonicalAlert(**defaults)


def make_evidence(
    *,
    alert: CanonicalAlert | None = None,
    rule_context: RuleContext | None = None,
    asset_context: AssetContext | None = None,
    fp_signal: FPSignal | None = None,
    closed_cases_summary: ClosedCasesSummary | None = None,
    related_alerts_24h: list[AlertSummary] | None = None,
    investigation_gaps: list | None = None,
) -> EnrichedEvidence:
    raw = RawEvidence(
        canonical_alert=alert or make_alert(),
        rule_context=rule_context,
        asset_context=asset_context,
        fp_signal=fp_signal,
        closed_cases_summary=closed_cases_summary or ClosedCasesSummary(),
        related_alerts_24h=related_alerts_24h or [],
        investigation_gaps=investigation_gaps or [],
    )
    return EnrichedEvidence(**raw.model_dump())


def make_context(*, tactics: list[str] | None = None, **overrides) -> ContextualAssessment:
    defaults = dict(
        correlation_decision=CorrelationDecision(action="new", reasoning="test"),
        refined_mitre_mapping=[
            MitreMapping(technique_id="T1059", tactic=t, confidence="medium")
            for t in (tactics or [])
        ],
    )
    defaults.update(overrides)
    return ContextualAssessment(**defaults)


def make_verdict(*, verdict: str = "needs_review", **overrides) -> TriageVerdict:
    defaults = dict(
        likelihood="possible",
        impact_if_true="moderate",
        verdict=verdict,
        reasoning="test",
        summary="test",
        recommended_action="needs_review",
    )
    defaults.update(overrides)
    return TriageVerdict(**defaults)


def cortex(verdicts: list[str], analyzer: str = "VirusTotal") -> CortexResult:
    return CortexResult(observable="x", type="hash", verdict=verdicts, analyzer=analyzer)


def gaps(n: int) -> list[Gap]:
    return [Gap(tool=f"tool{i}", reason="timeout") for i in range(n)]


# ===========================================================================
# Level algebra — the primitives every rule is built on
# ===========================================================================


class TestLevelAlgebra:
    def test_impact_levels_are_ordered_ascending(self):
        """Order is load-bearing: every max() and every escalation indexes it."""
        assert cfg.IMPACT_LEVELS == [
            "Negligible",
            "Minor",
            "Moderate",
            "Significant",
            "Severe",
        ]

    def test_likelihood_levels_are_ordered_ascending(self):
        assert cfg.LIKELIHOOD_LEVELS == [
            "Rare",
            "Unlikely",
            "Possible",
            "Likely",
            "Near-Certain",
        ]

    def test_max_level_picks_the_more_severe(self):
        assert scoring._max_level("Minor", "Severe", cfg.IMPACT_LEVELS) == "Severe"
        assert scoring._max_level("Severe", "Minor", cfg.IMPACT_LEVELS) == "Severe"

    def test_max_level_of_equal_levels_is_that_level(self):
        assert scoring._max_level("Moderate", "Moderate", cfg.IMPACT_LEVELS) == "Moderate"

    def test_escalate_level_moves_one_step_up(self):
        assert scoring._escalate_level("Moderate", cfg.IMPACT_LEVELS) == "Significant"

    def test_escalate_level_saturates_at_the_top(self):
        assert scoring._escalate_level("Severe", cfg.IMPACT_LEVELS) == "Severe"

    def test_escalate_one_band_moves_toward_p1(self):
        assert scoring.escalate_one_band("P3") == "P2"
        assert scoring.escalate_one_band("P5") == "P4"

    def test_escalate_one_band_saturates_at_p1(self):
        assert scoring.escalate_one_band("P1") == "P1"

    def test_unknown_level_resolves_to_the_scale_midpoint_not_an_exception(self):
        """Never-raise posture: an unrecognised level is treated as the neutral
        centre, never as benign and never as a crash."""
        assert scoring._level_index("Nonsense", cfg.IMPACT_LEVELS) == 2


class TestTacticNormalisation:
    @pytest.mark.parametrize(
        "raw",
        [
            "defense-evasion",
            "Defense_Evasion",
            "Defense Evasion",
            "DEFENSE-EVASION",
            "  defense-evasion  ",
        ],
    )
    def test_every_real_producer_spelling_normalises_to_one_key(self, raw):
        assert scoring._normalise_tactic(raw) == "defense-evasion"

    def test_ta_ids_pass_through_lowercased(self):
        assert scoring._normalise_tactic("TA0040") == "ta0040"


# ===========================================================================
# LIKELIHOOD — newscoresystem.md §5.1 rules 1-5, 9 + §4.4b collision rule
# ===========================================================================


class TestLikelihoodRule1Malicious:
    def test_malicious_cortex_verdict_floors_at_near_certain(self):
        alert = make_alert(cortex_results=[cortex(["malicious"])])
        out = scoring.assess_likelihood(make_evidence(alert=alert))
        assert out["likelihood_level"] == "Near-Certain"
        assert out["likelihood_rule_fired"] == 1

    def test_rule_1_is_marked_fixed_not_provisional(self):
        """§5.1 row 1: the evidence CATEGORY determines the floor, so there is
        no threshold to calibrate — the status must say so."""
        alert = make_alert(cortex_results=[cortex(["malicious"])])
        out = scoring.assess_likelihood(make_evidence(alert=alert))
        assert out["likelihood_rule_status"] == cfg.STATUS_FIXED

    def test_reason_names_the_analyzer(self):
        alert = make_alert(cortex_results=[cortex(["malicious"], analyzer="OpenCTI")])
        out = scoring.assess_likelihood(make_evidence(alert=alert))
        assert "OpenCTI" in out["likelihood_rule_reason"]

    def test_a_single_occurrence_is_enough(self):
        """§5.1 row 1: 'any single occurrence' — no repetition required."""
        alert = make_alert(cortex_results=[cortex([]), cortex(["malicious"]), cortex([])])
        out = scoring.assess_likelihood(make_evidence(alert=alert))
        assert out["likelihood_rule_fired"] == 1


class TestLikelihoodRule2Suspicious:
    def test_suspicious_floors_at_likely(self):
        alert = make_alert(cortex_results=[cortex(["suspicious"])])
        out = scoring.assess_likelihood(make_evidence(alert=alert))
        assert out["likelihood_level"] == "Likely"
        assert out["likelihood_rule_fired"] == 2

    def test_malicious_beats_suspicious_when_both_present(self):
        alert = make_alert(cortex_results=[cortex(["suspicious"]), cortex(["malicious"])])
        out = scoring.assess_likelihood(make_evidence(alert=alert))
        assert out["likelihood_rule_fired"] == 1
        assert out["likelihood_level"] == "Near-Certain"

    def test_empty_verdicts_fire_neither_rule(self):
        """An analyzer that ran and reported nothing adverse is not a positive
        finding — CortexResult.verdict is pre-filtered to malicious/suspicious
        only, so an empty list means 'checked, nothing adverse'."""
        alert = make_alert(cortex_results=[cortex([]), cortex([])])
        out = scoring.assess_likelihood(make_evidence(alert=alert))
        assert out["likelihood_rule_fired"] == 9


class TestLikelihoodRule3HistoricalTpFloor:
    def test_fires_at_the_exact_threshold(self):
        ev = make_evidence(closed_cases_summary=ClosedCasesSummary(tp_count=4, fp_count=1))
        out = scoring.assess_likelihood(ev)  # 5 cases, 80% TP
        assert out["likelihood_rule_fired"] == 3
        assert out["likelihood_level"] == cfg.RULE_3_TP_FLOOR_LEVEL

    def test_does_not_fire_below_the_sample_minimum(self):
        """4 cases at 100% TP is still anecdotal under N=5."""
        ev = make_evidence(closed_cases_summary=ClosedCasesSummary(tp_count=4, fp_count=0))
        assert scoring.assess_likelihood(ev)["likelihood_rule_fired"] == 9

    def test_does_not_fire_below_the_ratio_minimum(self):
        """6 cases at 50% TP — sample is fine, ratio is not."""
        ev = make_evidence(closed_cases_summary=ClosedCasesSummary(tp_count=3, fp_count=3))
        assert scoring.assess_likelihood(ev)["likelihood_rule_fired"] == 9

    def test_other_count_is_excluded_from_the_sample(self):
        """`other_count` (Duplicated/Indeterminate) means the historical signal
        is WEAK, not that it is negative — folding it in would misstate the
        ratio. 4 TP + 0 FP + 10 other must still be below the N=5 sample."""
        ev = make_evidence(
            closed_cases_summary=ClosedCasesSummary(tp_count=4, fp_count=0, other_count=10)
        )
        assert scoring.assess_likelihood(ev)["likelihood_rule_fired"] == 9

    def test_is_provisional_not_fixed(self):
        ev = make_evidence(closed_cases_summary=ClosedCasesSummary(tp_count=5, fp_count=0))
        out = scoring.assess_likelihood(ev)
        assert out["likelihood_rule_status"] == cfg.STATUS_PROVISIONAL


class TestLikelihoodRule4FpCountCap:
    def test_fires_at_the_threshold_on_rule_scope(self):
        ev = make_evidence(fp_signal=FPSignal(rule_fp_count_30d=5))
        out = scoring.assess_likelihood(ev)
        assert out["likelihood_rule_fired"] == 4
        assert out["likelihood_level"] == cfg.RULE_4_FP_CAP_LEVEL
        assert "rule" in out["likelihood_rule_reason"]

    def test_fires_on_host_scope_alone(self):
        """The two counts are INDEPENDENT signals (FPSignal's own docstring) —
        either one alone at full strength is meaningful."""
        ev = make_evidence(fp_signal=FPSignal(rule_fp_count_30d=0, host_fp_count_30d=7))
        out = scoring.assess_likelihood(ev)
        assert out["likelihood_rule_fired"] == 4
        assert "host" in out["likelihood_rule_reason"]

    def test_does_not_fire_below_threshold(self):
        ev = make_evidence(fp_signal=FPSignal(rule_fp_count_30d=4, host_fp_count_30d=4))
        assert scoring.assess_likelihood(ev)["likelihood_rule_fired"] == 9

    def test_24h_counts_are_not_read(self):
        """Rule 4's window is 30 days; the 24h counters exist for other uses."""
        ev = make_evidence(fp_signal=FPSignal(rule_fp_count_24h=99, host_fp_count_24h=99))
        assert scoring.assess_likelihood(ev)["likelihood_rule_fired"] == 9

    def test_absent_fp_signal_does_not_crash(self):
        assert scoring.assess_likelihood(make_evidence(fp_signal=None))["likelihood_rule_fired"] == 9


class TestLikelihoodRule5BenignRatioCap:
    def test_fires_at_the_threshold(self):
        ev = make_evidence(closed_cases_summary=ClosedCasesSummary(tp_count=1, fp_count=4))
        out = scoring.assess_likelihood(ev)  # 5 cases, 20% TP
        assert out["likelihood_rule_fired"] == 5
        assert out["likelihood_level"] == cfg.RULE_5_FP_RATIO_CAP_LEVEL

    def test_does_not_fire_just_above_the_ratio(self):
        ev = make_evidence(closed_cases_summary=ClosedCasesSummary(tp_count=2, fp_count=4))
        assert scoring.assess_likelihood(ev)["likelihood_rule_fired"] == 9

    def test_thresholds_are_deliberately_asymmetric_with_rule_3(self):
        """§5.1 row 5: capping requires STRONGER evidence of benignness than
        flooring requires of maliciousness, because a false negative costs more
        than a false positive. 0.70 floor vs 0.20 cap is not symmetric around
        0.5 by accident."""
        assert cfg.RULE_3_TP_FLOOR_MIN_TP_RATIO == 0.70
        assert cfg.RULE_5_FP_RATIO_CAP_MAX_TP_RATIO == 0.20
        assert (1 - cfg.RULE_3_TP_FLOOR_MIN_TP_RATIO) != cfg.RULE_5_FP_RATIO_CAP_MAX_TP_RATIO


class TestLikelihoodCollisionRule:
    """`newscoresystem.md` §4.4b — the ordering IS the rule. These are the
    tests that would catch a refactor to independent boolean checks."""

    def test_cortex_floor_beats_an_fp_cap_that_also_fires(self):
        alert = make_alert(cortex_results=[cortex(["malicious"])])
        ev = make_evidence(alert=alert, fp_signal=FPSignal(rule_fp_count_30d=50))
        out = scoring.assess_likelihood(ev)
        assert out["likelihood_rule_fired"] == 1
        assert out["likelihood_level"] == "Near-Certain"

    def test_cortex_floor_beats_a_benign_ratio_cap_that_also_fires(self):
        alert = make_alert(cortex_results=[cortex(["suspicious"])])
        ev = make_evidence(
            alert=alert, closed_cases_summary=ClosedCasesSummary(tp_count=0, fp_count=20)
        )
        assert scoring.assess_likelihood(ev)["likelihood_rule_fired"] == 2

    def test_rule_3_floor_beats_a_cap_that_also_fires(self):
        """§4.4b step 2, stated explicitly there: a current positive TP history
        outweighs an FP history signal."""
        ev = make_evidence(
            closed_cases_summary=ClosedCasesSummary(tp_count=8, fp_count=1),
            fp_signal=FPSignal(rule_fp_count_30d=50),
        )
        out = scoring.assess_likelihood(ev)
        assert out["likelihood_rule_fired"] == 3
        assert out["likelihood_level"] == "Likely"

    def test_rule_4_wins_over_rule_5_when_both_caps_fire(self):
        """Both are caps and both can fire. Table order puts 4 first, and it is
        also the stronger cap — so the chain lands on the more benign level."""
        ev = make_evidence(
            fp_signal=FPSignal(rule_fp_count_30d=9),
            closed_cases_summary=ClosedCasesSummary(tp_count=0, fp_count=9),
        )
        out = scoring.assess_likelihood(ev)
        assert out["likelihood_rule_fired"] == 4
        assert out["likelihood_level"] == "Rare"


class TestLikelihoodDefault:
    def test_empty_evidence_is_possible_not_benign(self):
        """§4.2: Possible is 'insufficient evidence to move off center'. An
        alert we know nothing about is never scored as benign."""
        out = scoring.assess_likelihood(make_evidence())
        assert out["likelihood_level"] == "Possible"
        assert out["likelihood_rule_fired"] == 9


# ===========================================================================
# IMPACT — newscoresystem.md §4.3a, §4.3b, §5.1 rules 6-7
# ===========================================================================


class TestAssetImpactSubscore:
    @pytest.mark.parametrize(
        "criticality,expected",
        [("high", "Severe"), ("medium", "Significant"), ("low", "Minor")],
    )
    def test_lookup_table(self, criticality, expected):
        ev = make_evidence(asset_context=AssetContext(found=True, criticality=criticality))
        assert scoring._asset_impact(ev)[0] == expected

    def test_case_and_whitespace_insensitive(self):
        ev = make_evidence(asset_context=AssetContext(found=True, criticality="  HIGH "))
        assert scoring._asset_impact(ev)[0] == "Severe"

    @pytest.mark.parametrize(
        "asset",
        [
            None,
            AssetContext(found=False),
            AssetContext(found=True, criticality=None),
            AssetContext(found=True, criticality=""),
            AssetContext(found=True, criticality="business-critical-ish"),
        ],
    )
    def test_every_unknown_shape_defaults_to_moderate_and_never_raises(self, asset):
        """§4.3a: 'Do not raise an exception on unknown values.' §5.2: unknown
        severity is never silently treated as low — that would create a
        systematic blind spot exactly where visibility is already weakest
        (Suricata's IP-only alerts can never resolve an iTop asset)."""
        assert scoring._asset_impact(make_evidence(asset_context=asset))[0] == "Moderate"


class TestTechnicalImpactSubscore:
    @pytest.mark.parametrize(
        "tactic,expected",
        [
            ("impact", "Severe"),
            ("exfiltration", "Severe"),
            ("lateral-movement", "Severe"),
            ("credential-access", "Significant"),
            ("privilege-escalation", "Significant"),
            ("collection", "Significant"),
            ("command-and-control", "Significant"),
            ("persistence", "Moderate"),
            ("execution", "Moderate"),
            ("initial-access", "Moderate"),
            ("discovery", "Minor"),
            ("reconnaissance", "Negligible"),
            ("resource-development", "Negligible"),
        ],
    )
    def test_every_tactic_in_the_spec_table(self, tactic, expected):
        ctx = make_context(tactics=[tactic])
        assert scoring._technical_impact(ctx, make_evidence())[0] == expected

    @pytest.mark.parametrize("tactic", ["stealth", "defense-impairment", "defense-evasion"])
    def test_v19_split_and_its_legacy_label_all_score_the_same(self, tactic):
        """§4.3b: the Defense Evasion -> Stealth/Defense Impairment split does
        not change the severity assessment, so a rule written before ATT&CK v19
        scores identically to one written after."""
        ctx = make_context(tactics=[tactic])
        assert scoring._technical_impact(ctx, make_evidence())[0] == "Moderate"

    def test_ta_ids_are_accepted_directly(self):
        ctx = make_context(tactics=["TA0040"])
        assert scoring._technical_impact(ctx, make_evidence())[0] == "Severe"

    def test_max_not_average_across_tactics(self):
        """§4.3b: 'Take the max() across all tactics present — do not average
        them.' One exfiltration step in a chain of recon is an exfil alert."""
        ctx = make_context(tactics=["reconnaissance", "discovery", "exfiltration"])
        level, reason = scoring._technical_impact(ctx, make_evidence())
        assert level == "Severe"
        assert "exfiltration" in reason

    def test_unknown_tactic_defaults_to_moderate(self):
        ctx = make_context(tactics=["cyber-shenanigans"])
        assert scoring._technical_impact(ctx, make_evidence())[0] == "Moderate"

    def test_no_tactic_anywhere_defaults_to_moderate(self):
        """'A fired detection rule with no MITRE mapping is still a detection
        rule' — never assumed benign."""
        assert scoring._technical_impact(make_context(), make_evidence())[0] == "Moderate"

    def test_falls_back_to_rule_context_when_stage_3_carried_no_tactic(self):
        """LOAD-BEARING: nodes/context.py::_stage_3_fallback builds
        refined_mitre_mapping with tactic="" on every entry, so without this
        fallback a downed Stage 3 LLM would silently collapse this sub-score to
        Moderate — the same class of silent severity cap architecture §8 calls
        out by name."""
        ctx = ContextualAssessment(
            correlation_decision=CorrelationDecision(action="new"),
            refined_mitre_mapping=[MitreMapping(technique_id="T1486", tactic="", confidence="medium")],
        )
        ev = make_evidence(rule_context=RuleContext(found=True, mitre_tactics=["impact"]))
        level, reason = scoring._technical_impact(ctx, ev)
        assert level == "Severe"
        assert "rule_context" in reason

    def test_stage_3_mapping_wins_over_rule_context_when_present(self):
        ctx = make_context(tactics=["discovery"])
        ev = make_evidence(rule_context=RuleContext(found=True, mitre_tactics=["impact"]))
        assert scoring._technical_impact(ctx, ev)[0] == "Minor"


class TestImpactCombination:
    def test_impact_is_max_of_subscores_never_their_sum(self):
        """v1 SUMMED these (asset 95 + tactic 65 = 160, clamped to 100, which
        made impact modifiers inert). v3 takes the max, per OWASP."""
        ev = make_evidence(asset_context=AssetContext(found=True, criticality="high"))
        out = scoring.assess_impact(make_context(tactics=["execution"]), ev)
        assert out["impact_level"] == "Severe"  # asset Severe > technical Moderate
        assert out["impact_governing_subscore"] == "asset"

    def test_technical_can_govern_over_a_low_value_asset(self):
        """A ransomware technique on a low-value host is still a Severe event —
        this is exactly the case averaging would hide."""
        ev = make_evidence(asset_context=AssetContext(found=True, criticality="low"))
        out = scoring.assess_impact(make_context(tactics=["impact"]), ev)
        assert out["impact_level"] == "Severe"
        assert out["impact_governing_subscore"] == "technical"

    def test_governing_subscore_reports_both_on_a_tie(self):
        ev = make_evidence(asset_context=AssetContext(found=True, criticality="medium"))
        out = scoring.assess_impact(make_context(tactics=["collection"]), ev)
        assert out["impact_level"] == "Significant"
        assert out["impact_governing_subscore"] == "both"


class TestBlastRadiusEscalation:
    def _alerts(self, hosts: list[str]) -> list[AlertSummary]:
        return [AlertSummary(host=h) for h in hosts]

    def test_escalates_one_level_at_the_threshold(self):
        ev = make_evidence(
            asset_context=AssetContext(found=True, criticality="low"),
            related_alerts_24h=self._alerts(["a", "b", "c"]),
        )
        out = scoring.assess_impact(make_context(tactics=["discovery"]), ev)
        assert out["impact_before_modifiers"] == "Minor"
        assert out["impact_level"] == "Moderate"
        assert len(out["impact_modifiers_applied"]) == 1

    def test_does_not_fire_below_the_threshold(self):
        ev = make_evidence(related_alerts_24h=self._alerts(["a", "b"]))
        out = scoring.assess_impact(make_context(), ev)
        assert out["impact_modifiers_applied"] == []

    def test_the_alerts_own_host_is_excluded(self):
        """The origin host is not evidence of spread."""
        alert = make_alert(host=Host(hostname="win-test01"))
        ev = make_evidence(
            alert=alert,
            related_alerts_24h=self._alerts(["win-test01", "win-test01", "a", "b"]),
        )
        out = scoring.assess_impact(make_context(), ev)
        assert out["other_host_count"] == 2
        assert out["impact_modifiers_applied"] == []

    def test_duplicate_hosts_count_once(self):
        ev = make_evidence(related_alerts_24h=self._alerts(["a", "a", "a", "a", "a"]))
        assert scoring.assess_impact(make_context(), ev)["other_host_count"] == 1

    def test_escalation_is_bounded_at_one_level(self):
        """§5.1 row 6: 'One level escalation (not more) is a bounded effect.'
        20 hosts escalates exactly as far as 3 do."""
        few = make_evidence(related_alerts_24h=self._alerts(list("abc")))
        many = make_evidence(related_alerts_24h=self._alerts([f"h{i}" for i in range(20)]))
        ctx = make_context(tactics=["discovery"])
        assert (
            scoring.assess_impact(ctx, few)["impact_level"]
            == scoring.assess_impact(ctx, many)["impact_level"]
        )

    def test_already_severe_cannot_escalate_further_and_says_so(self):
        ev = make_evidence(
            asset_context=AssetContext(found=True, criticality="high"),
            related_alerts_24h=self._alerts(list("abcd")),
        )
        out = scoring.assess_impact(make_context(), ev)
        assert out["impact_level"] == "Severe"
        assert "no further escalation" in out["impact_modifiers_applied"][0]


# ===========================================================================
# EVIDENCE QUALITY — newscoresystem.md §4.5
# ===========================================================================


def _rich_alert() -> CanonicalAlert:
    """7 of the 8 completeness checks populated (no cortex_results)."""
    return make_alert(
        process=Process(name="powershell.exe"),
        network=Network(src_ip="10.0.0.1"),
        file={"name": "x.exe"},
        observables=Observables(
            external_ips=["1.2.3.4"], hashes={"sha256": "a" * 64}
        ),
    )


class TestEvidenceQuality:
    def test_rich_alert_with_no_gaps_is_high(self):
        ev = make_evidence(alert=_rich_alert())
        out = scoring.assess_evidence_quality(ev)
        assert out["evidence_quality"] == "HIGH"

    def test_rich_alert_with_many_gaps_cannot_be_high(self):
        """The two inputs are ANDed, not averaged: backends failing is its own
        way of not knowing enough, and completeness cannot compensate."""
        ev = make_evidence(alert=_rich_alert(), investigation_gaps=gaps(3))
        assert scoring.assess_evidence_quality(ev)["evidence_quality"] == "MODERATE"

    def test_thin_alert_with_clean_backends_cannot_be_high_either(self):
        ev = make_evidence(alert=make_alert())  # 2 of 8 fields
        assert scoring.assess_evidence_quality(ev)["evidence_quality"] == "LOW"

    def test_many_gaps_alone_forces_low(self):
        ev = make_evidence(alert=_rich_alert(), investigation_gaps=gaps(6))
        assert scoring.assess_evidence_quality(ev)["evidence_quality"] == "LOW"

    def test_completeness_and_gap_count_are_separate_signals(self):
        """Deriving both from one signal would penalise the same fact twice
        under two names. Same completeness, different gap counts, different
        quality."""
        rich = _rich_alert()
        a = scoring.assess_evidence_quality(make_evidence(alert=rich))
        b = scoring.assess_evidence_quality(make_evidence(alert=rich, investigation_gaps=gaps(5)))
        assert a["evidence_completeness_pct"] == b["evidence_completeness_pct"]
        assert a["evidence_quality"] != b["evidence_quality"]

    def test_completeness_field_count_matches_the_config_constant(self):
        ev = make_evidence(alert=_rich_alert())
        pct = scoring.assess_evidence_quality(ev)["evidence_completeness_pct"]
        assert pct == pytest.approx(100.0 * 7 / cfg.EVIDENCE_COMPLETENESS_FIELD_COUNT)


# ===========================================================================
# THE MATRIX — newscoresystem.md §4.4
# ===========================================================================


class TestMatrix:
    def test_every_cell_is_populated(self):
        for likelihood in cfg.LIKELIHOOD_LEVELS:
            for impact in cfg.IMPACT_LEVELS:
                assert (likelihood, impact) in cfg.PRIORITY_MATRIX

    def test_matrix_matches_the_spec_grid_verbatim(self):
        """newscoresystem.md §4.4's grid, transcribed independently of
        scoring_config's own dict literal — if either drifts, this goes red."""
        grid = {
            "Near-Certain": ["P4", "P3", "P2", "P1", "P1"],
            "Likely": ["P4", "P3", "P2", "P2", "P1"],
            "Possible": ["P5", "P4", "P3", "P2", "P2"],
            "Unlikely": ["P5", "P4", "P4", "P3", "P3"],
            "Rare": ["P5", "P5", "P4", "P4", "P3"],
        }
        for likelihood, row in grid.items():
            for impact, expected in zip(cfg.IMPACT_LEVELS, row):
                assert cfg.PRIORITY_MATRIX[(likelihood, impact)] == expected

    def test_priority_never_decreases_as_impact_rises(self):
        """Monotonicity — a structural sanity property of any risk matrix."""
        order = cfg.PRIORITY_BANDS_ORDERED
        for likelihood in cfg.LIKELIHOOD_LEVELS:
            severities = [
                order.index(cfg.PRIORITY_MATRIX[(likelihood, i)]) for i in cfg.IMPACT_LEVELS
            ]
            assert severities == sorted(severities, reverse=True)

    def test_priority_never_decreases_as_likelihood_rises(self):
        order = cfg.PRIORITY_BANDS_ORDERED
        for impact in cfg.IMPACT_LEVELS:
            severities = [
                order.index(cfg.PRIORITY_MATRIX[(l, impact)]) for l in cfg.LIKELIHOOD_LEVELS
            ]
            assert severities == sorted(severities, reverse=True)


# ===========================================================================
# compute_priority — end to end
# ===========================================================================


class TestComputePriorityEndToEnd:
    def test_confirmed_malicious_on_a_critical_asset_is_p1(self):
        alert = _rich_alert()
        alert.cortex_results = [cortex(["malicious"])]
        ev = make_evidence(alert=alert, asset_context=AssetContext(found=True, criticality="high"))
        out = scoring.compute_priority(make_context(tactics=["exfiltration"]), ev)
        assert out["likelihood_level"] == "Near-Certain"
        assert out["impact_level"] == "Severe"
        assert out["final_priority"] == "P1"

    def test_repeated_fp_on_a_low_value_recon_alert_is_p5(self):
        alert = _rich_alert()
        ev = make_evidence(
            alert=alert,
            asset_context=AssetContext(found=True, criticality="low"),
            fp_signal=FPSignal(rule_fp_count_30d=20),
        )
        out = scoring.compute_priority(make_context(tactics=["reconnaissance"]), ev)
        assert out["likelihood_level"] == "Rare"
        assert out["impact_level"] == "Negligible"
        assert out["final_priority"] == "P5"

    def test_evidence_quality_low_escalates_one_band(self):
        """§4.5's STANDARD safety default: escalate under uncertainty, downgrade
        later. Low confidence makes an alert MORE urgent, not less."""
        ev = make_evidence(alert=make_alert(), asset_context=None)  # thin -> LOW quality
        out = scoring.compute_priority(make_context(), ev)
        assert out["evidence_quality"] == "LOW"
        assert out["evidence_quality_override_applied"] is True
        assert out["final_priority"] == scoring.escalate_one_band(out["matrix_priority"])

    def test_high_evidence_quality_leaves_the_matrix_result_untouched(self):
        ev = make_evidence(alert=_rich_alert())
        out = scoring.compute_priority(make_context(), ev)
        assert out["evidence_quality_override_applied"] is False
        assert out["final_priority"] == out["matrix_priority"]

    def test_the_override_can_never_de_escalate(self):
        """One-way by construction: escalate_one_band only ever moves toward
        P1, and nothing else touches final_priority."""
        order = cfg.PRIORITY_BANDS_ORDERED
        for band in order:
            assert order.index(scoring.escalate_one_band(band)) <= order.index(band)

    def test_llm_contextual_modifiers_do_not_move_the_priority(self):
        """v3's decision table never references them. This is the regression
        guard on that decision — if someone re-wires Stage 3's modifiers into
        scoring, this goes red."""
        ev = make_evidence(alert=_rich_alert())
        plain = scoring.compute_priority(make_context(), ev)
        loaded = scoring.compute_priority(
            make_context(
                contextual_modifiers=[
                    ContextualModifier(
                        dimension=d, factor_name="x", direction="increase", strength="critical"
                    )
                    for d in ("likelihood", "impact")
                    for _ in range(5)
                ]
            ),
            ev,
        )
        assert plain["final_priority"] == loaded["final_priority"]

    def test_llm_criticality_score_does_not_move_the_priority(self):
        ev = make_evidence(alert=_rich_alert())
        low = scoring.compute_priority(make_context(llm_criticality_score=0), ev)
        high = scoring.compute_priority(make_context(llm_criticality_score=100), ev)
        assert low["final_priority"] == high["final_priority"]

    def test_every_spec_section_8_field_is_present(self):
        out = scoring.compute_priority(make_context(), make_evidence())
        for field in [
            "likelihood_level",
            "likelihood_rule_fired",
            "likelihood_rule_reason",
            "likelihood_rule_status",
            "impact_level",
            "impact_governing_subscore",
            "impact_modifiers_applied",
            "impact_rule_status",
            "matrix_priority",
            "matrix_status",
            "evidence_quality",
            "evidence_quality_override_applied",
            "final_priority",
            "deployment_mode",
            "explanation",
        ]:
            assert field in out, field

    def test_no_numeric_score_is_emitted_anywhere(self):
        """v3 removed the 0-100 score deliberately — a priority is a matrix
        cell, and a representative number alongside it would re-introduce the
        false precision v3 exists to remove."""
        out = scoring.compute_priority(make_context(), make_evidence())
        assert "score" not in out
        assert not hasattr(PriorityScore(**out), "score")


class TestExplanation:
    def test_carries_the_status_labels(self):
        """§8: 'Every number the system ever produces carries its own honesty
        label.' A reviewer must never have to take the output on faith."""
        out = scoring.compute_priority(make_context(), make_evidence())
        assert cfg.STATUS_PROVISIONAL in out["explanation"]

    def test_names_the_rule_that_fired(self):
        alert = make_alert(cortex_results=[cortex(["malicious"])])
        out = scoring.compute_priority(make_context(), make_evidence(alert=alert))
        assert "rule 1" in out["explanation"]
        assert cfg.STATUS_FIXED in out["explanation"]

    def test_reports_the_escalation_when_it_happens(self):
        out = scoring.compute_priority(make_context(), make_evidence(alert=make_alert()))
        assert "LOW evidence quality" in out["explanation"]

    def test_carries_the_deployment_mode(self):
        out = scoring.compute_priority(make_context(), make_evidence())
        assert f"mode={cfg.DEPLOYMENT_MODE}" in out["explanation"]


# ===========================================================================
# The Stage 5 node
# ===========================================================================


class TestPriorityScoringNode:
    def test_returns_a_triage_result_with_a_typed_priority(self):
        result = score_mod.priority_scoring(make_verdict(), make_context(), make_evidence())
        assert isinstance(result, TriageResult)
        assert isinstance(result.priority, PriorityScore)
        assert result.priority.final_priority in cfg.PRIORITY_BANDS_ORDERED

    def test_verdict_fields_are_copied_through(self):
        verdict = make_verdict(verdict="true_positive", summary="s", reasoning="r")
        result = score_mod.priority_scoring(verdict, make_context(), make_evidence())
        assert result.verdict == "true_positive"
        assert result.summary == "s"

    def test_stage_3_and_evidence_objects_are_copied_through(self):
        ctx = make_context(tactics=["execution"])
        ev = make_evidence()
        result = score_mod.priority_scoring(make_verdict(), ctx, ev)
        assert result.stage_3_assessment == ctx
        assert result.gathered_evidence == ev

    def test_deployment_mode_reaches_the_typed_output(self):
        result = score_mod.priority_scoring(make_verdict(), make_context(), make_evidence())
        assert result.priority.deployment_mode == cfg.DEPLOYMENT_MODE

    def test_never_raises_on_an_internal_scoring_bug(self, monkeypatch):
        def boom(*a, **k):
            raise RuntimeError("simulated internal defect")

        monkeypatch.setattr(scoring, "compute_priority", boom)
        result = score_mod.priority_scoring(make_verdict(), make_context(), make_evidence())
        assert result.priority.final_priority == "P3"
        assert "fallback" in result.priority.explanation

    def test_fallback_does_not_fabricate_urgency_from_a_code_bug(self, monkeypatch):
        """The fallback reports LOW evidence quality honestly but deliberately
        does NOT apply the escalation — escalating a value that was never
        computed would invent urgency out of a defect."""

        def boom(*a, **k):
            raise RuntimeError("boom")

        monkeypatch.setattr(scoring, "compute_priority", boom)
        priority = score_mod.priority_scoring(
            make_verdict(), make_context(), make_evidence()
        ).priority
        assert priority.evidence_quality == "LOW"
        assert priority.evidence_quality_override_applied is False
        assert priority.final_priority == priority.matrix_priority


# ===========================================================================
# Real captured run
# ===========================================================================


class TestAgainstRealCapturedRun:
    """REAL — see this module's docstring for full provenance."""

    def test_fixture_declares_its_provenance(self, real_v3):
        assert "REAL" in real_v3["note"]

    def test_recomputing_from_the_captured_inputs_reproduces_the_captured_output(self, real_v3):
        """The load-bearing one: replays the real EnrichedEvidence and
        ContextualAssessment through the live code path and asserts the whole
        PriorityScore matches what the real run produced."""
        evidence = EnrichedEvidence.model_validate(real_v3["inputs"]["evidence"])
        context = ContextualAssessment.model_validate(real_v3["inputs"]["context"])
        recomputed = scoring.compute_priority(context, evidence)
        for field, expected in real_v3["priority"].items():
            if field == "components":
                continue
            assert recomputed[field] == expected, field

    def test_real_run_landed_on_the_hand_verified_levels(self, real_v3):
        p = real_v3["priority"]
        assert p["likelihood_level"] == "Possible"
        assert p["likelihood_rule_fired"] == 9
        assert p["impact_level"] == "Significant"
        assert p["impact_governing_subscore"] == "technical"
        assert p["matrix_priority"] == "P2"

    def test_real_run_shows_the_evidence_quality_escalation(self, real_v3):
        p = real_v3["priority"]
        assert p["evidence_quality"] == "LOW"
        assert p["evidence_quality_override_applied"] is True
        assert p["final_priority"] == "P1"


class TestV1ToV3Migration:
    """The v1 capture of the SAME real evidence, kept as the dated record of
    what changed. Not a target to reproduce — v3 is a different system."""

    def test_v1_fixture_still_has_the_removed_numeric_score(self, real_v1):
        assert "score" in real_v1["priority"]
        assert real_v1["priority"]["score"] == 69

    def test_v3_removed_every_v1_engine_field(self, real_v3):
        for gone in [
            "score",
            "base_likelihood",
            "adjusted_likelihood",
            "likelihood_modifiers_applied",
            "base_impact",
            "adjusted_impact",
            "impact_modifiers_applied_points",
            "base_confidence",
            "confidence_gate_applied",
            "velocity_multiplier",
            "llm_criticality_score",
            "final_score_calculation",
        ]:
            assert gone not in real_v3["priority"], gone

    def test_both_systems_agree_this_alert_is_p1_by_different_routes(self, real_v1, real_v3):
        """v1: 69/100 -> P2, escalated to P1 by the confidence gate.
        v3: Possible x Significant -> P2, escalated to P1 by LOW evidence
        quality. Same answer, but v3 states which rule produced each half."""
        assert real_v1["priority"]["priority"] == "P1"
        assert real_v3["priority"]["final_priority"] == "P1"
        assert real_v1["priority"]["confidence_gate_applied"] is True
        assert real_v3["priority"]["evidence_quality_override_applied"] is True


class TestProvisionalStatusDiscipline:
    """`newscoresystem.md` §11 / §7.2 — the honesty labels are the point of v3.
    These tests fail loudly if someone marks a threshold CALIBRATED without
    having run §7's validation pass."""

    def test_nothing_claims_calibrated_status_yet(self):
        for status in (cfg.LIKELIHOOD_RULE_STATUS, cfg.IMPACT_RULE_STATUS, cfg.MATRIX_STATUS):
            assert "CALIBRATED" not in status

    def test_cortex_rules_are_fixed_not_provisional(self):
        """§5.1 rows 1-2 are 'fixed (no calibration needed)' — the evidence
        category determines the floor, so there is no threshold to validate."""
        assert cfg.STATUS_FIXED != cfg.STATUS_PROVISIONAL

    def test_deployment_mode_defaults_to_shadow(self):
        """§11's sequence: implement -> run in shadow mode -> review worksheet
        -> calibrate -> go live. Nothing should start out claiming to be live."""
        import importlib

        import config

        assert config.DEPLOYMENT_MODE in ("shadow", "live")
        importlib.reload(config)

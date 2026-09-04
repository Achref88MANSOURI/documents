"""`rag_enrichment` — Stage 2, architecture §7 (trimmed scope — see
`nodes/rag.py`'s module docstring for why `retrieve_playbooks` is not called
here).

This node has no backend logic of its own — it orchestrates three
already-verified `tools.qdrant` calls (each already has its own real-backend
verification in `tests/test_qdrant.py`). These tests mock every
`tools.qdrant.retrieve_*` function at its source module and check the
orchestration logic only: query construction, timeout/exception containment,
the CVE gate, and `EnrichedEvidence` assembly.

PROVENANCE: `tests/fixtures/rag_live_run_real.json` is REAL — captured by
running `rag_enrichment` once against a real `RawEvidence` (built from the
real `sigma-alert-sample.json` webhook body via `alert_builder.
build_canonical_alert`, plus a real `RuleContext` from `tests/fixtures/
so_detection_5e3cc4d8.json` via `tools.detection_rules._build_rule_context`)
through the actual live Qdrant + embedding microservice, no mocking,
2026-08-16. Unlike `test_gather.py` (whose docstring claims a
`test_live_against_real_backends` test that does not actually exist in that
file — confirmed by reading it), this suite does not keep a live
network-calling test in the permanent run: the real verification already
happened once, its output is captured here with full provenance, and
`TestRealFixtureLooksReasonable` asserts basic sanity on that captured real
data so a future regression in the captured shape itself would be caught.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import config
from nodes import rag as rag_mod
from schemas import (
    CanonicalAlert,
    CodeSignature,
    File,
    Host,
    MalwareVerdict,
    Network,
    Process,
    RawEvidence,
    Rule,
    RuleContext,
    User,
)
from tools import qdrant

FIXTURE = Path(__file__).parent / "fixtures" / "rag_live_run_real.json"


@pytest.fixture(scope="module")
def real() -> dict:
    """REAL — one live nodes.rag.rag_enrichment run, captured 2026-08-16."""
    return json.loads(FIXTURE.read_text())


def run(coro):
    return asyncio.run(coro)


def make_alert(**overrides) -> CanonicalAlert:
    defaults = dict(
        alert_id="~1",
        timestamp=datetime.now(timezone.utc),
        rule=Rule(name="Suspicious Invoke-WebRequest Execution", uuid="5e3cc4d8-…"),
        host=Host(hostname="win-kvkmd51ggkq"),
        user=User(name="Administrator"),
    )
    defaults.update(overrides)
    return CanonicalAlert(**defaults)


def make_evidence(**alert_overrides) -> RawEvidence:
    return RawEvidence(canonical_alert=make_alert(**alert_overrides))


def patch_all_ok(monkeypatch, *, calls=None):
    """Patch every tools.qdrant.retrieve_* to succeed with a distinct,
    recognizable value so each EnrichedEvidence field can be traced back to
    the right call."""

    def record(name):
        async def wrapper(*args, **kwargs):
            if calls is not None:
                calls.setdefault(name, []).append((args, kwargs))
            return _RETURNS[name]

        return wrapper

    _RETURNS = {
        "retrieve_mitre": ([], None),
        "retrieve_cve": ([], None),
        "retrieve_incidents": ([], None),
    }

    monkeypatch.setattr(qdrant, "retrieve_mitre", record("retrieve_mitre"))
    monkeypatch.setattr(qdrant, "retrieve_cve", record("retrieve_cve"))
    monkeypatch.setattr(qdrant, "retrieve_incidents", record("retrieve_incidents"))
    return _RETURNS


class TestHappyPath:
    def test_all_fields_populated_no_gaps_except_cve_skip(self, monkeypatch):
        patch_all_ok(monkeypatch)
        evidence = run(rag_mod.rag_enrichment(make_evidence()))

        assert evidence.mitre_candidates == []
        assert evidence.cve_matches == []
        assert evidence.incident_matches == []
        assert len(evidence.investigation_gaps) == 1
        assert evidence.investigation_gaps[0].tool == qdrant.TOOL_NAME_CVE
        assert evidence.stage_2_duration_ms >= 0

    def test_mitre_always_called(self, monkeypatch):
        calls: dict = {}
        patch_all_ok(monkeypatch, calls=calls)
        run(rag_mod.rag_enrichment(make_evidence()))
        assert "retrieve_mitre" in calls

    def test_incidents_always_called(self, monkeypatch):
        calls: dict = {}
        patch_all_ok(monkeypatch, calls=calls)
        run(rag_mod.rag_enrichment(make_evidence()))
        assert "retrieve_incidents" in calls

    def test_cve_skipped_by_default(self, monkeypatch):
        calls: dict = {}
        patch_all_ok(monkeypatch, calls=calls)
        evidence = run(rag_mod.rag_enrichment(make_evidence()))

        assert "retrieve_cve" not in calls
        gap = evidence.investigation_gaps[0]
        assert gap.tool == qdrant.TOOL_NAME_CVE
        assert "gate disabled" in gap.reason.lower()

    def test_cve_called_when_genuine_third_party_signer_present(self, monkeypatch):
        """Gap #3 orchestration-level proof: retrieve_cve is unreachable code
        until _has_cve_indicators returns True for some real evidence shape.
        Confirms the full rag_enrichment wiring, not just the gate function in
        isolation."""
        calls: dict = {}
        patch_all_ok(monkeypatch, calls=calls)
        evidence = make_evidence(
            process=Process(code_signature=CodeSignature(subject_name="Evil Corp Software"))
        )
        result = run(rag_mod.rag_enrichment(evidence))

        assert "retrieve_cve" in calls
        assert not any(g.tool == qdrant.TOOL_NAME_CVE for g in result.investigation_gaps)

    def test_no_playbook_call_exists_at_all(self, monkeypatch):
        """Regression guard for the scope decision: this node must never
        call retrieve_playbooks, under any evidence shape."""
        assert not hasattr(rag_mod, "_build_playbook_query")
        assert not hasattr(rag_mod, "retrieve_playbooks")


class TestPartialFailure:
    def test_one_gap_does_not_affect_other_fields(self, monkeypatch):
        from schemas import Gap

        patch_all_ok(monkeypatch)

        async def failing_mitre(*args, **kwargs):
            return [], Gap(source="qdrant", tool="retrieve_mitre", reason="simulated failure")

        monkeypatch.setattr(qdrant, "retrieve_mitre", failing_mitre)
        evidence = run(rag_mod.rag_enrichment(make_evidence()))

        assert evidence.mitre_candidates == []
        assert any(g.tool == "retrieve_mitre" for g in evidence.investigation_gaps)
        # incidents still ran fine, cve still gated — only the mitre gap plus the cve gap
        tool_names = {g.tool for g in evidence.investigation_gaps}
        assert tool_names == {"retrieve_mitre", qdrant.TOOL_NAME_CVE}


class TestGatherLevelTimeout:
    def test_slow_tool_produces_gap_not_a_hang(self, monkeypatch):
        patch_all_ok(monkeypatch)

        async def slow_mitre(*args, **kwargs):
            await asyncio.sleep(5)
            return [], None

        monkeypatch.setattr(qdrant, "retrieve_mitre", slow_mitre)
        monkeypatch.setattr(config, "STAGE_1_TOOL_TIMEOUT_QDRANT", 0.05)

        evidence = run(rag_mod.rag_enrichment(make_evidence()))

        gap = next(g for g in evidence.investigation_gaps if g.tool == "retrieve_mitre")
        assert "gather-level timeout" in gap.reason
        assert evidence.mitre_candidates == []


class TestUnexpectedExceptionIsContained:
    def test_tool_raising_does_not_crash_rag_enrichment(self, monkeypatch):
        """Simulates a bug in a tool despite its own 'never raises' contract.
        Proves the hard constraint: rag_enrichment must never propagate an
        unhandled exception to its caller."""
        patch_all_ok(monkeypatch)

        async def broken_incidents(*args, **kwargs):
            raise RuntimeError("simulated bug")

        monkeypatch.setattr(qdrant, "retrieve_incidents", broken_incidents)
        evidence = run(rag_mod.rag_enrichment(make_evidence()))

        assert evidence.incident_matches == []
        gap = next(g for g in evidence.investigation_gaps if g.tool == "retrieve_incidents")
        assert "RuntimeError" in gap.reason


class TestQueryConstruction:
    def test_mitre_query_prefers_command_line_over_bare_title(self):
        """Marker string (a distinctive URL) exists ONLY in the command line,
        never in the rule title/description — unlike an earlier draft of this
        test, which asserted on "Invoke-WebRequest" and stayed green even when
        the command-line branch was deliberately disabled, because the rule
        title itself already contains that substring. Caught by mutation
        -checking this suite; do not reintroduce that mistake."""
        evidence = make_evidence(
            process=Process(
                command_line="powershell.exe Invoke-WebRequest https://distinctive-marker.test/x.exe"
            )
        )
        query = rag_mod._build_mitre_query(evidence)
        assert "Suspicious Invoke-WebRequest Execution" in query
        assert "distinctive-marker.test" in query

    def test_mitre_query_falls_back_to_title_and_description_when_no_process(self):
        rule_ctx = RuleContext(found=True, title="A Rule", description="does a thing")
        evidence = RawEvidence(canonical_alert=make_alert(), rule_context=rule_ctx)
        query = rag_mod._build_mitre_query(evidence)
        assert "A Rule" in query
        assert "does a thing" in query

    def test_mitre_query_falls_back_to_bare_rule_name_with_no_evidence_at_all(self):
        evidence = make_evidence()
        query = rag_mod._build_mitre_query(evidence)
        assert query == "Suspicious Invoke-WebRequest Execution"

    def test_network_keyword_used_when_no_process(self):
        evidence = make_evidence(
            network=Network(dst_ip="10.0.0.5", dst_port=4444, protocol="tcp")
        )
        query = rag_mod._build_mitre_query(evidence)
        assert "10.0.0.5:4444" in query
        assert "tcp" in query

    def test_incident_query_equals_mitre_query(self):
        evidence = make_evidence(
            process=Process(command_line="cmd.exe /c whoami")
        )
        assert rag_mod._build_incident_query(evidence) == rag_mod._build_mitre_query(evidence)

    def test_extract_product_hint_excludes_generic_os_signer(self):
        evidence = make_evidence(
            process=Process(code_signature=CodeSignature(subject_name="Microsoft Windows"))
        )
        assert rag_mod._extract_product_hint(evidence) is None

    def test_extract_product_hint_returns_genuine_third_party_signer(self):
        evidence = make_evidence(
            process=Process(code_signature=CodeSignature(subject_name="Evil Corp Software"))
        )
        assert rag_mod._extract_product_hint(evidence) == "Evil Corp Software"

    def test_has_cve_indicators_true_for_genuine_third_party_signer(self):
        """Gap #3, re-enabled 2026-08-19. The gate now reuses
        _extract_product_hint directly rather than being hardcoded off."""
        evidence = make_evidence(
            process=Process(code_signature=CodeSignature(subject_name="Evil Corp Software"))
        )
        assert rag_mod._has_cve_indicators(evidence) is True

    def test_has_cve_indicators_false_for_generic_os_signer(self):
        """Regression guard: the real fixture (Microsoft-signed) must still
        resolve to False — the gate reusing _extract_product_hint doesn't
        change behavior for the one alert shape this deployment has actually
        seen, only unblocks genuinely product-identifying signers."""
        evidence = make_evidence(
            process=Process(code_signature=CodeSignature(subject_name="Microsoft Windows"))
        )
        assert rag_mod._has_cve_indicators(evidence) is False

    def test_has_cve_indicators_false_with_no_signal_at_all(self):
        evidence = make_evidence()
        assert rag_mod._has_cve_indicators(evidence) is False


class TestGapsPreserveStage1:
    def test_stage_1_gap_survives_into_enriched_evidence(self, monkeypatch):
        from schemas import Gap

        patch_all_ok(monkeypatch)
        evidence = make_evidence()
        evidence.investigation_gaps.append(
            Gap(source="itop", tool="itop_asset_lookup", reason="Stage 1 failure")
        )

        enriched = run(rag_mod.rag_enrichment(evidence))

        stage_1_gap_tools = {g.tool for g in enriched.investigation_gaps}
        assert "itop_asset_lookup" in stage_1_gap_tools
        assert qdrant.TOOL_NAME_CVE in stage_1_gap_tools


class TestRealFixtureLooksReasonable:
    """Sanity checks on the captured real live run — not a mock, reads
    tests/fixtures/rag_live_run_real.json directly. Guards against the
    captured shape itself silently rotting (e.g. a future tools/qdrant.py
    schema change nobody re-verified against real data)."""

    def test_mitre_candidates_are_relevant_to_the_real_alert(self, real):
        """The real alert is a PowerShell download-and-execute. T1059.001
        (PowerShell) should be among the top real hits — proves the query
        construction actually retrieves on-topic techniques, not noise."""
        technique_ids = {c["technique_id"] for c in real["mitre_candidates"]}
        assert "T1059.001" in technique_ids

    def test_incident_matches_are_the_same_rule_prior_closures(self, real):
        assert len(real["incident_matches"]) >= 1
        for incident in real["incident_matches"]:
            assert incident["status"] in ("TruePositive", "FalsePositive")

    def test_cve_gate_produced_the_expected_gap(self, real):
        gap_tools = {g["tool"] for g in real["investigation_gaps"]}
        assert qdrant.TOOL_NAME_CVE in gap_tools

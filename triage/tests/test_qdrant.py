"""`retrieve_mitre` / `retrieve_playbooks` / `retrieve_cve` / `retrieve_incidents`
— Stage 2 RAG retrieval tools. See `tools/qdrant.py`'s module docstring for
the full live-verification writeup (payload shape corrections vs. architecture
§7's illustrative example, the exact-match-only Qdrant filter finding, the
colocated embedding microservice).

PROVENANCE: `tests/fixtures/qdrant_real.json` is REAL, captured live from
Qdrant at `172.20.24.224:6333` (via `172.20.24.224:8001`'s embedding
microservice) on 2026-08-16 — one real `/points/search` response per
collection (`mitre_techniques`, `soc_playbooks`, `cve_context`,
`incident_history`), verbatim, `with_payload: true`. The tool itself was
called live against the real backend, and its output field-by-field inspected
against `MitreCandidate`/`PlaybookMatch`/`CveMatch`/`IncidentMatch`, before any
of these tests were written (implementation guide §2) — including the product
substring-filter fix (see `TestCveProductFilter`), which was live-verified to
actually catch the target CVE before the candidate-pool constant was set.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from tools import qdrant as qdrant_mod
from tools.qdrant import (
    retrieve_cve,
    retrieve_incidents,
    retrieve_mitre,
    retrieve_playbooks,
)

FIXTURE = Path(__file__).parent / "fixtures" / "qdrant_real.json"


@pytest.fixture(scope="module")
def real() -> dict:
    """REAL — captured live from Qdrant on 2026-08-16, one collection each."""
    return json.loads(FIXTURE.read_text())


def patch_fetch_hits(monkeypatch, hits=None, exc=None, capture=None):
    async def fake_fetch_hits(collection, query_text, top_k, score_threshold, timeout):
        if capture is not None:
            capture["collection"] = collection
            capture["query_text"] = query_text
            capture["top_k"] = top_k
            capture["score_threshold"] = score_threshold
        if exc is not None:
            raise exc
        return hits or []

    monkeypatch.setattr(qdrant_mod, "_fetch_hits", fake_fetch_hits)


def run(coro):
    return asyncio.run(coro)


class TestRealHits:
    """Each retrieve_* function correctly maps ITS collection's real payload
    shape — proving the corrected schemas in schemas/evidence.py, not the
    architecture §7 illustrative example."""

    def test_mitre_maps_real_payload(self, monkeypatch, real):
        patch_fetch_hits(monkeypatch, hits=real["mitre_techniques"])
        results, gap = run(retrieve_mitre("PowerShell download and execute"))
        assert gap is None
        assert len(results) == len(real["mitre_techniques"])
        top = results[0]
        assert top.technique_id == real["mitre_techniques"][0]["payload"]["technique_id"]
        assert top.technique_name == real["mitre_techniques"][0]["payload"]["name"]
        assert isinstance(top.tactic, list)
        assert top.score == real["mitre_techniques"][0]["score"]

    def test_playbooks_maps_real_payload_including_runbook_id_rename(self, monkeypatch, real):
        """The schema field is `playbook_id`; the real payload key is
        `runbook_id` — this is the rename the mapping function exists to do."""
        patch_fetch_hits(monkeypatch, hits=real["soc_playbooks"])
        results, gap = run(retrieve_playbooks("phishing attachment"))
        assert gap is None
        top = results[0]
        assert top.playbook_id == real["soc_playbooks"][0]["payload"]["runbook_id"]
        assert top.document_text == real["soc_playbooks"][0]["payload"]["document_text"]

    def test_multiple_sections_of_same_runbook_are_not_deduped(self, monkeypatch, real):
        """Architecture §7: multiple sections from one runbook co-occurring in
        a result set is expected behavior, not a bug to filter out."""
        hits = real["soc_playbooks"]
        patch_fetch_hits(monkeypatch, hits=hits)
        results, _ = run(retrieve_playbooks("phishing attachment", top_k=len(hits)))
        assert len(results) == len(hits)

    def test_cve_maps_real_payload_including_cvss_score_rename(self, monkeypatch, real):
        """The schema field is `cvss_score`, matching the real payload key —
        architecture §7's illustrative `cvss_v3_score` does not exist live."""
        patch_fetch_hits(monkeypatch, hits=real["cve_context"])
        results, gap = run(retrieve_cve("OpenSSL vulnerability"))
        assert gap is None
        top = results[0]
        assert top.cve_id == real["cve_context"][0]["payload"]["cve_id"]
        assert top.cvss_score == real["cve_context"][0]["payload"]["cvss_score"]
        assert top.severity == real["cve_context"][0]["payload"]["severity"]

    def test_incidents_maps_real_payload(self, monkeypatch, real):
        patch_fetch_hits(monkeypatch, hits=real["incident_history"])
        results, gap = run(retrieve_incidents("Suspicious Invoke-WebRequest execution"))
        assert gap is None
        top = results[0]
        assert top.incident_id == real["incident_history"][0]["payload"]["incident_id"]
        assert top.status == real["incident_history"][0]["payload"]["status"]
        assert top.tags == real["incident_history"][0]["payload"]["tags"]


class TestQueryConstruction:
    def test_empty_query_text_gaps_without_calling_out(self, monkeypatch):
        capture: dict = {}
        patch_fetch_hits(monkeypatch, hits=[], capture=capture)
        results, gap = run(retrieve_mitre(""))
        assert results == []
        assert "empty" in gap.reason.lower()
        assert capture == {}

    def test_whitespace_only_query_text_gaps(self, monkeypatch):
        capture: dict = {}
        patch_fetch_hits(monkeypatch, hits=[], capture=capture)
        results, gap = run(retrieve_playbooks("   "))
        assert results == []
        assert capture == {}

    def test_mitre_uses_its_own_lower_similarity_threshold(self, monkeypatch):
        capture: dict = {}
        patch_fetch_hits(monkeypatch, hits=[], capture=capture)
        run(retrieve_mitre("query"))
        assert capture["score_threshold"] == qdrant_mod.MITRE_MIN_SIMILARITY
        assert capture["score_threshold"] < qdrant_mod.CVE_MIN_SIMILARITY

    def test_no_results_above_threshold_is_not_a_gap(self, monkeypatch):
        """Architecture §7 semantics, matching every other Stage 1/2 tool:
        genuinely nothing cleared score_threshold is a real, successful
        empty result, not a failure."""
        patch_fetch_hits(monkeypatch, hits=[])
        results, gap = run(retrieve_mitre("query with no good matches"))
        assert results == []
        assert gap is None


class TestCveProductFilter:
    """The client-side substring filter this repo built to replace Qdrant's
    exact-match-only keyword filter — see tools/qdrant.py module docstring
    point 2, verified live against affected_products='openssl:openssl'."""

    _CANDIDATES = [
        {"score": 0.66, "payload": {"cve_id": "CVE-A", "affected_products": ["hpe:oneview"]}},
        {
            "score": 0.64,
            "payload": {"cve_id": "CVE-B", "affected_products": ["openssl:openssl"]},
        },
        {
            "score": 0.63,
            "payload": {
                "cve_id": "CVE-C",
                "affected_products": ["rust-openssl_project:rust-openssl"],
            },
        },
        {"score": 0.60, "payload": {"cve_id": "CVE-D", "affected_products": ["linux:linux_kernel"]}},
    ]

    def test_product_filter_selects_matching_substring_case_insensitively(self, monkeypatch):
        patch_fetch_hits(monkeypatch, hits=self._CANDIDATES)
        results, gap = run(retrieve_cve("query", product="OpenSSL", top_k=5))
        assert gap is None
        ids = {r.cve_id for r in results}
        assert ids == {"CVE-B", "CVE-C"}

    def test_product_filter_truncates_to_top_k_after_filtering(self, monkeypatch):
        patch_fetch_hits(monkeypatch, hits=self._CANDIDATES)
        results, _ = run(retrieve_cve("query", product="openssl", top_k=1))
        assert len(results) == 1
        assert results[0].cve_id == "CVE-B"

    def test_no_product_given_skips_filtering_entirely(self, monkeypatch):
        capture: dict = {}
        patch_fetch_hits(monkeypatch, hits=self._CANDIDATES, capture=capture)
        results, _ = run(retrieve_cve("query", product=None, top_k=2))
        assert capture["top_k"] == 2  # no widened candidate pool when unfiltered
        assert len(results) == 2

    def test_product_given_widens_the_candidate_pool(self, monkeypatch):
        """Regression guard for the exact bug found live: a small multiplier
        (top_k*4) let the real target CVE rank outside the fetched window and
        the filter silently no-op'd. The pool must be the fixed wide constant,
        not scaled off top_k."""
        capture: dict = {}
        patch_fetch_hits(monkeypatch, hits=self._CANDIDATES, capture=capture)
        run(retrieve_cve("query", product="openssl", top_k=1))
        assert capture["top_k"] == qdrant_mod._CVE_PRODUCT_FILTER_CANDIDATE_POOL

    def test_filter_matching_nothing_falls_back_to_unfiltered(self, monkeypatch):
        patch_fetch_hits(monkeypatch, hits=self._CANDIDATES)
        results, gap = run(retrieve_cve("query", product="totally-unrelated-vendor", top_k=2))
        assert gap is None
        assert len(results) == 2  # fell back to the unfiltered top_k, not []


class TestFailureModes:
    def test_timeout_is_a_gap(self, monkeypatch):
        async def slow_fetch(collection, query_text, top_k, score_threshold, timeout):
            await asyncio.sleep(10)

        monkeypatch.setattr(qdrant_mod, "_fetch_hits", slow_fetch)
        results, gap = run(retrieve_mitre("query", timeout=0.01))
        assert results == []
        assert "timeout" in gap.reason.lower()

    def test_qdrant_connection_error_is_a_gap(self, monkeypatch):
        patch_fetch_hits(monkeypatch, exc=httpx.ConnectError("refused"))
        results, gap = run(retrieve_mitre("query"))
        assert results == []
        assert "cannot connect" in gap.reason.lower()

    def test_embedding_api_bad_response_is_a_gap_not_a_crash(self, monkeypatch):
        """The real failure shape if the embedding microservice returns a
        malformed body — see tools/qdrant.py::_embed's explicit check, which
        raises exactly this ValueError."""
        patch_fetch_hits(
            monkeypatch,
            exc=ValueError("Embedding API returned no usable 'embedding' field: {}"),
        )
        results, gap = run(retrieve_playbooks("query"))
        assert results == []
        assert "embedding" in gap.reason.lower()

    def test_hit_mapping_failure_is_a_gap_not_a_crash(self, monkeypatch):
        """A structurally malformed hit (payload isn't even a dict) must not
        raise AttributeError up through gather — it becomes a Gap. A merely
        incomplete payload is NOT this case: every _*_from_hit getter has a
        safe default, so missing keys alone never raise (see TestHitMapping's
        `test_mitre_from_hit_defaults_missing_optional_fields`)."""
        patch_fetch_hits(monkeypatch, hits=[{"score": 0.9, "payload": "not-a-dict"}])
        results, gap = run(retrieve_mitre("query"))
        assert results == []
        assert "mapping failed" in gap.reason.lower()


class TestHitMapping:
    """Direct unit tests of the four _*_from_hit mapping functions — no
    network, no mocking."""

    def test_mitre_from_hit_defaults_missing_optional_fields(self):
        from tools.qdrant import _mitre_from_hit

        candidate = _mitre_from_hit({"score": 0.7, "payload": {"technique_id": "T9999"}})
        assert candidate.technique_id == "T9999"
        assert candidate.technique_name == ""
        assert candidate.tactic == []
        assert candidate.is_sub_technique is False
        assert candidate.score == 0.7

    def test_playbook_from_hit_maps_runbook_id_to_playbook_id(self):
        from tools.qdrant import _playbook_from_hit

        match = _playbook_from_hit(
            {"score": 0.6, "payload": {"runbook_id": "phishing-response", "section": "Detection"}}
        )
        assert match.playbook_id == "phishing-response"
        assert match.section == "Detection"

    def test_cve_from_hit_maps_cvss_score(self):
        from tools.qdrant import _cve_from_hit

        match = _cve_from_hit(
            {"score": 0.5, "payload": {"cve_id": "CVE-2026-1", "cvss_score": 9.8, "severity": "CRITICAL"}}
        )
        assert match.cve_id == "CVE-2026-1"
        assert match.cvss_score == 9.8
        assert match.severity == "CRITICAL"

    def test_incident_from_hit_maps_all_fields(self):
        from tools.qdrant import _incident_from_hit

        match = _incident_from_hit(
            {
                "score": 0.75,
                "payload": {
                    "incident_id": "~123",
                    "status": "FalsePositive",
                    "tags": ["engine:sigma"],
                },
            }
        )
        assert match.incident_id == "~123"
        assert match.status == "FalsePositive"
        assert match.tags == ["engine:sigma"]

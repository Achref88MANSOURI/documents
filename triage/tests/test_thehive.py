"""TheHive case correlation — architecture §6 tools 3 and 4.

PROVENANCE, two tiers:

- `tests/fixtures/thehive_real.json` is REAL, captured live from TheHive
  **5.7.5-1** at `172.20.24.228` on 2026-08-13: the `/api/v1/describe/*` enum
  vocabularies, genuine query results, case observables, and — replacing the
  retired custom Function's payload — the stock two-call `getAlert` +
  `getAlert -> observables` shape `get_full_alert_with_analysis` now calls.

  Supersedes the 2026-08-09 capture from 5.7.3 at `172.20.24.221` (that
  instance moved and was upgraded again; its alert/case ids no longer exist).

  Three real cases exist this time — `~8609848` New/New (a manually-created
  "test" case with **zero** observables of its own — real fixture data now
  proves an open-case entity match can legitimately come back empty without a
  broken query), `~4653208` Closed/FalsePositive, and `~8613944`
  Closed/TruePositive. This is an improvement on the 2026-08-09 capture, which
  only had a TruePositive closed case — FalsePositive summarisation is now
  also proven against real data, not just `SYNTHETIC_CLOSED_FP`.

- The remaining `SYNTHETIC_*` rows stay synthetic, covering resolution
  statuses the live instance still has no example of (Indeterminate,
  duplicate handling). Every enum value is drawn from the captured live
  vocabulary.

`test_real_schema_enums_are_what_the_code_assumes` is the guard that matters
most — it pins the synthetic rows to the captured vocabulary, so if TheHive's
model changes they cannot quietly keep passing against a model that no longer
exists.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from schemas import HashBundle, Observables
from tools import thehive as th
from tools.thehive import (
    _entity_values,
    _summarise_closed_cases,
    fetch_case_observables_with_type,
    search_closed_cases_by_rule,
    search_open_cases_by_entities,
)

FIXTURE = Path(__file__).parent / "fixtures" / "thehive_real.json"
SIMILAR_CASES_FIXTURE = Path(__file__).parent / "fixtures" / "thehive_similar_cases_real.json"
RULE_NAME = "Suspicious Invoke-WebRequest Execution"
RULE_UUID = "5e3cc4d8-3e68-43db-8656-eaaeefdec9cc"
SHA256 = "1c84c8632c5269f24876ed9f49fa810b49f77e1e92e8918fc164c34b020f9a94"


@pytest.fixture(scope="module")
def real() -> dict:
    """REAL — captured live from TheHive 5.7.3 on 2026-08-09."""
    return json.loads(FIXTURE.read_text())


@pytest.fixture(scope="module")
def real_similar_cases() -> list:
    """REAL — `getAlert(~4661456) -> similarCases`, captured live 2026-08-19
    (gap #12). Same alert TestGetFullAlertWithAnalysis already uses. Two
    real cases, both stage=="Closed" (~8613944 TruePositive, ~4653208
    FalsePositive) — proves the exclusion side of the open-case stage
    filter; SYNTHETIC_SIMILAR_OPEN_ROW below proves the inclusion side."""
    return json.loads(SIMILAR_CASES_FIXTURE.read_text())


def observables(**kw) -> Observables:
    return Observables(
        external_ips=kw.get("ips", []),
        domains=kw.get("domains", []),
        urls=kw.get("urls", []),
        hashes=HashBundle(sha256=kw.get("sha256", [])),
    )


def patch_query(monkeypatch, results=None, exc=None, capture=None):
    """Replace TheHive's query transport. `results` may be a list consumed in
    call order, or a single value reused."""
    state = {"i": 0}

    async def fake_query(body, timeout, name="soc3s"):
        if capture is not None:
            capture.setdefault("bodies", []).append(body)
            capture.setdefault("names", []).append(name)
        if exc is not None:
            raise exc
        if isinstance(results, list) and results and isinstance(results[0], (list, dict)):
            out = results[min(state["i"], len(results) - 1)]
            state["i"] += 1
            return out
        return results if results is not None else []

    monkeypatch.setattr(th, "_query", fake_query)


def patch_query_by_name(monkeypatch, by_name: dict, capture=None):
    """Like `patch_query`, but keyed by the `name=` query-tag rather than call
    order. `get_full_alert_with_analysis` fires its two queries concurrently
    via `asyncio.gather`, so pinning behaviour to argument order would be
    testing asyncio scheduling, not the tool."""

    async def fake_query(body, timeout, name="soc3s"):
        if capture is not None:
            capture.setdefault("bodies", []).append(body)
            capture.setdefault("names", []).append(name)
        result = by_name.get(name, [])
        if isinstance(result, BaseException):
            raise result
        return result

    monkeypatch.setattr(th, "_query", fake_query)


def run(coro):
    return asyncio.run(coro)


def _enum_values(describe_doc: dict, field: str) -> list:
    """`/api/v1/describe/<entity>`'s envelope changed shape between 5.7.3 and
    5.7.5-1: the old capture was a flat `{field: [values]}` dict, the new one
    is `{label, path, initialQuery, attributes: [{name, values, ...}, ...]}`.
    Dev-time-only endpoint (see tools/thehive.py's `_describe_error` docstring
    reference) — nothing at runtime reads this shape, only these tests."""
    for attr in describe_doc.get("attributes", []):
        if attr.get("name") == field:
            return attr.get("values", [])
    raise KeyError(field)


# SYNTHETIC case rows — every enum value drawn from the captured live schema.
SYNTHETIC_OPEN_CASE = {
    "_id": "~100",
    "number": 7,
    "title": "PowerShell download cradle on win-kvkmd51ggkq",
    "severity": 3,
    "stage": "InProgress",
    "status": "InProgress",
    "tags": [f"rule:{RULE_NAME}", "win-kvkmd51ggkq"],
    "_createdAt": 1785971216169,
}
SYNTHETIC_CLOSED_TP = {
    "_id": "~200", "number": 8, "title": "Confirmed credential theft",
    "severity": 4, "stage": "Closed", "status": "TruePositive", "tags": [], "_createdAt": 1785971216169,
}
SYNTHETIC_CLOSED_FP = {
    "_id": "~201", "number": 9, "title": "SCCM deployment",
    "severity": 2, "stage": "Closed", "status": "FalsePositive", "tags": [], "_createdAt": 1785971216169,
}
SYNTHETIC_CLOSED_OTHER = {
    "_id": "~202", "number": 10, "title": "Could not determine",
    "severity": 2, "stage": "Closed", "status": "Indeterminate", "tags": [], "_createdAt": 1785971216169,
}
# SYNTHETIC similarCases row — proves the OPEN/inclusion side of the stage
# filter (gap #12), since the one real fixture only has closed examples.
# Wraps the already-real-schema-vocabulary SYNTHETIC_OPEN_CASE.
SYNTHETIC_SIMILAR_OPEN_ROW = {
    "case": SYNTHETIC_OPEN_CASE,
    "similarObservableCount": 3,
    "observableCount": 3,
    "linkedWith": [{"dataType": "hash", "data": SHA256}, {"dataType": "domain", "data": "evil.test"}],
}


class TestAgainstRealCapturedCases:
    def test_real_schema_enums_are_what_the_code_assumes(self, real):
        """THE ANCHOR TEST. Every synthetic case row below uses these values.
        If TheHive's vocabulary changes, this fails first and the synthetic
        fixtures stop being trustworthy — rather than passing forever against a
        model that no longer exists."""
        case = real["describe_case_enums"]
        assert _enum_values(case, "stage") == ["New", "InProgress", "Closed"]
        assert set(_enum_values(case, "status")) == {
            "Duplicated", "FalsePositive", "InProgress",
            "Indeterminate", "New", "Other", "TruePositive",
        }
        assert _enum_values(case, "severity") == [1, 2, 3, 4]
        # "Closed" is a STAGE, never a STATUS. Filtering status for openness
        # would silently match everything.
        assert "Closed" not in _enum_values(case, "status")

    def test_stage_and_status_are_different_vocabularies(self, real):
        case = real["describe_case_enums"]
        assert set(_enum_values(case, "stage")) != set(_enum_values(case, "status"))
        assert "TruePositive" not in _enum_values(case, "stage")

    def test_real_open_query_returns_no_matches(self, real):
        """REAL RESULT, 2026-08-13. Three cases exist: `~8609848` New/New (a
        manually-created "test" case), `~4653208` Closed/FalsePositive,
        `~8613944` Closed/TruePositive. The entity query correctly returns
        EMPTY — not because it's broken, but because the only open case has
        zero observables of its own (confirmed via a direct getCase ->
        observables call), so it cannot share an entity with anything. No
        closed case leaks in either way, which the closed query below proves
        is a real, working match."""
        assert real["open_cases_by_entity"] == []
        open_ids = {c["_id"] for c in real["all_cases"] if c["stage"] != "Closed"}
        assert open_ids == {"~8609848"}

    def test_real_closed_query_returns_both_closed_cases(self, real):
        rows = real["closed_cases_by_tag"]
        assert {c["_id"] for c in rows} == {"~4653208", "~8613944"}
        by_id = {c["_id"]: c for c in rows}
        assert by_id["~4653208"]["status"] == "FalsePositive"
        assert by_id["~8613944"]["status"] == "TruePositive"
        assert all(c["stage"] == "Closed" for c in rows)

    def test_stage_filter_proven_on_real_data_not_just_syntax(self, real):
        """The stage-vs-status trap, settled empirically: the open ("test")
        case's id never appears in the closed-case result, and vice versa —
        even though the open query legitimately returns nothing to compare
        against this time (see test_real_open_query_returns_no_matches)."""
        closed_ids = {c["_id"] for c in real["closed_cases_by_tag"]}
        assert "~8609848" not in closed_ids

    def test_real_open_case_query_maps_empty_result_cleanly(self, monkeypatch, real):
        """Feeding the tool the exact real (empty) response must produce an
        empty case list with NO gap — empty-with-no-gap is the correct
        real answer here, not a failure to distinguish from a broken query."""
        patch_query(monkeypatch, results=[real["open_cases_by_entity"], []])
        cases, gap = run(search_open_cases_by_entities(observables(sha256=[SHA256])))
        assert gap is None
        assert cases == []

    def test_real_closed_case_summarises_tp_and_fp(self, monkeypatch, real):
        patch_query(monkeypatch, results=[real["closed_cases_by_tag"]])
        summary, gap = run(search_closed_cases_by_rule(RULE_UUID, RULE_NAME, None))
        assert gap is None
        assert (summary.tp_count, summary.fp_count) == (1, 1)
        assert summary.avg_severity == 3.0


class TestOpenCaseQueryConstruction:
    def test_filters_on_stage_not_status(self, monkeypatch):
        """The single most dangerous mistake available here."""
        capture: dict = {}
        patch_query(monkeypatch, results=[], capture=capture)
        run(search_open_cases_by_entities(observables(sha256=[SHA256])))
        steps = capture["bodies"][0]["query"]
        stage_filters = [
            s for s in steps if s.get("_name") == "filter" and "stage" in json.dumps(s)
        ]
        assert stage_filters, "no stage filter present"
        assert stage_filters[0]["_ne"] == {"_field": "stage", "_value": "Closed"}
        assert '"_field": "status"' not in json.dumps(steps)

    def test_traverses_observable_first_not_case_first(self, monkeypatch):
        """Observable-first keeps the entity match on an index. Case-first would
        walk every case and inspect its observables — fine at 0 cases, hopeless
        at 10,000."""
        capture: dict = {}
        patch_query(monkeypatch, results=[], capture=capture)
        run(search_open_cases_by_entities(observables(sha256=[SHA256])))
        names = [s.get("_name") for s in capture["bodies"][0]["query"]]
        assert names[0] == "listObservable"
        assert "case" in names
        assert "dedup" in names

    def test_all_entity_kinds_reach_the_query(self, monkeypatch):
        capture: dict = {}
        patch_query(monkeypatch, results=[], capture=capture)
        run(
            search_open_cases_by_entities(
                observables(ips=["10.0.0.1"], domains=["evil.test"], urls=["https://e/x"], sha256=[SHA256]),
                host="win-kvkmd51ggkq",
                user="Administrator",
            )
        )
        values = capture["bodies"][0]["query"][1]["_in"]["_values"]
        for expected in ("10.0.0.1", "evil.test", "https://e/x", SHA256, "win-kvkmd51ggkq", "Administrator"):
            assert expected in values

    def test_entity_values_deduplicated_and_capped(self):
        obs = observables(ips=["1.1.1.1"] * 5, domains=[f"d{i}.test" for i in range(80)])
        values = _entity_values(obs, "1.1.1.1", None)
        assert values.count("1.1.1.1") == 1
        assert len(values) <= th.MAX_ENTITY_VALUES

    def test_no_entities_gaps_rather_than_querying(self, monkeypatch):
        """"Nothing to correlate on" must not look like "correlated and found
        nothing"."""
        capture: dict = {}
        patch_query(monkeypatch, results=[], capture=capture)
        cases, gap = run(search_open_cases_by_entities(Observables(), None, None))
        assert cases == []
        assert "no observables, hostname or username" in gap.reason
        assert capture.get("bodies") is None


class TestOpenCaseMapping:
    def test_maps_a_case_row(self, monkeypatch):
        patch_query(monkeypatch, results=[[SYNTHETIC_OPEN_CASE], []])
        cases, gap = run(search_open_cases_by_entities(observables(sha256=[SHA256])))
        assert gap is None and len(cases) == 1
        case = cases[0]
        assert case.case_id == "~100"
        assert case.case_number == 7
        assert case.severity == 3
        assert case.stage == "InProgress"
        assert case.status == "InProgress"
        assert f"rule:{RULE_NAME}" in case.tags

    def test_epoch_millis_are_not_read_as_seconds(self, monkeypatch):
        """TheHive returns epoch MILLISECONDS. Pydantic parses a bare int as
        seconds, which would date every case to 1970 and silently break any
        recency reasoning in Stage 3."""
        patch_query(monkeypatch, results=[[SYNTHETIC_OPEN_CASE], []])
        cases, _ = run(search_open_cases_by_entities(observables(sha256=[SHA256])))
        assert cases[0].created_at.year == 2026

    def test_case_observables_are_enriched(self, monkeypatch):
        patch_query(
            monkeypatch,
            results=[[SYNTHETIC_OPEN_CASE], [{"data": SHA256}, {"data": "10.0.0.9"}]],
        )
        cases, _ = run(search_open_cases_by_entities(observables(sha256=[SHA256])))
        assert cases[0].observables == [SHA256, "10.0.0.9"]

    def test_enrichment_failure_still_returns_the_case(self, monkeypatch):
        calls = {"n": 0}

        async def flaky(body, timeout, name="soc3s"):
            calls["n"] += 1
            if calls["n"] == 1:
                return [SYNTHETIC_OPEN_CASE]
            raise httpx.ConnectError("enrichment died")

        monkeypatch.setattr(th, "_query", flaky)
        cases, gap = run(search_open_cases_by_entities(observables(sha256=[SHA256])))
        assert len(cases) == 1
        assert cases[0].observables == []
        assert gap is None


class TestClosedCaseSummary:
    def test_rule_uuid_alone_cannot_match_and_says_so(self, monkeypatch):
        """No rule-uuid attribute exists on Case or Alert in TheHive 5.6.1 and
        there are no customFields. Silently returning zeros would be
        indistinguishable from a real all-zero history."""
        capture: dict = {}
        patch_query(monkeypatch, results=[], capture=capture)
        summary, gap = run(search_closed_cases_by_rule(RULE_UUID, None, None))
        assert summary.tp_count == 0
        assert "rule uuid alone is not searchable" in gap.reason
        assert capture.get("bodies") is None

    def test_matches_by_rule_tag_and_records_it(self, monkeypatch):
        capture: dict = {}
        patch_query(monkeypatch, results=[], capture=capture)
        summary, _ = run(search_closed_cases_by_rule(RULE_UUID, RULE_NAME, None))
        assert summary.matched_by == ["rule_tag"]
        assert f"rule:{RULE_NAME}" in json.dumps(capture["bodies"][0])

    def test_matches_by_both_when_observables_present(self, monkeypatch):
        capture: dict = {}
        patch_query(monkeypatch, results=[], capture=capture)
        summary, _ = run(
            search_closed_cases_by_rule(RULE_UUID, RULE_NAME, observables(sha256=[SHA256]))
        )
        assert summary.matched_by == ["rule_tag", "observables"]
        assert len(capture["bodies"]) == 2

    def test_closed_filter_uses_stage(self, monkeypatch):
        capture: dict = {}
        patch_query(monkeypatch, results=[], capture=capture)
        run(search_closed_cases_by_rule(RULE_UUID, RULE_NAME, None))
        assert '"_field": "stage", "_value": "Closed"' in json.dumps(capture["bodies"][0])

    def test_counts_by_resolution_status(self):
        summary = _summarise_closed_cases(
            [SYNTHETIC_CLOSED_TP, SYNTHETIC_CLOSED_FP, SYNTHETIC_CLOSED_OTHER], ["rule_tag"]
        )
        assert (summary.tp_count, summary.fp_count, summary.other_count) == (1, 1, 1)
        assert summary.avg_severity == pytest.approx((4 + 2 + 2) / 3, abs=0.01)

    def test_indeterminate_is_other_not_folded_into_tp_or_fp(self):
        """A high "other" count means the historical signal is WEAK, which is
        different from it being negative. Folding it into fp would push
        likelihood down on no evidence."""
        summary = _summarise_closed_cases([SYNTHETIC_CLOSED_OTHER], [])
        assert summary.other_count == 1
        assert summary.tp_count == summary.fp_count == 0

    def test_same_case_from_both_queries_counted_once(self):
        """The rule-tag query and the observable query can return the same case.
        Double counting would inflate the historical prior and skew likelihood."""
        summary = _summarise_closed_cases(
            [SYNTHETIC_CLOSED_TP, SYNTHETIC_CLOSED_TP, SYNTHETIC_CLOSED_TP], []
        )
        assert summary.tp_count == 1

    def test_partial_failure_returns_data_plus_gap(self, monkeypatch):
        calls = {"n": 0}

        async def half_broken(body, timeout, name="soc3s"):
            calls["n"] += 1
            if calls["n"] == 1:
                return [SYNTHETIC_CLOSED_TP]
            raise httpx.ConnectError("second query died")

        monkeypatch.setattr(th, "_query", half_broken)
        summary, gap = run(
            search_closed_cases_by_rule(RULE_UUID, RULE_NAME, observables(sha256=[SHA256]))
        )
        assert summary.tp_count == 1
        assert "Partial result" in gap.reason


class TestFailuresProduceGapsNotExceptions:
    def test_connection_error(self, monkeypatch):
        patch_query(monkeypatch, exc=httpx.ConnectError("refused"))
        cases, gap = run(search_open_cases_by_entities(observables(sha256=[SHA256])))
        assert cases == []
        assert "Cannot connect to TheHive" in gap.reason

    def test_http_error_includes_status_and_body(self, monkeypatch):
        response = httpx.Response(
            401, text="unauthorized", request=httpx.Request("POST", "http://th/api/v1/query")
        )
        patch_query(
            monkeypatch,
            exc=httpx.HTTPStatusError("x", request=response.request, response=response),
        )
        _, gap = run(search_open_cases_by_entities(observables(sha256=[SHA256])))
        assert "HTTP 401 from TheHive" in gap.reason
        assert "unauthorized" in gap.reason

    def test_timeout(self, monkeypatch):
        async def slow(body, timeout, name="soc3s"):
            await asyncio.sleep(5)

        monkeypatch.setattr(th, "_query", slow)
        cases, gap = run(
            search_open_cases_by_entities(observables(sha256=[SHA256]), timeout=0.05)
        )
        assert cases == []
        assert "Timeout after 0.05s" in gap.reason

    def test_unexpected_shape(self, monkeypatch):
        patch_query(monkeypatch, results={"not": "a list"})
        cases, gap = run(search_open_cases_by_entities(observables(sha256=[SHA256])))
        assert cases == []
        assert "Unexpected response shape" in gap.reason

    def test_closed_cases_total_failure(self, monkeypatch):
        patch_query(monkeypatch, exc=httpx.ConnectError("refused"))
        summary, gap = run(search_closed_cases_by_rule(RULE_UUID, RULE_NAME, None))
        assert summary.tp_count == 0
        assert "Cannot connect to TheHive" in gap.reason


# ===========================================================================
# similarCases refactor — gap #12, added 2026-08-19
# ===========================================================================
class TestSimilarCasesOpenPath:
    """search_open_cases_by_entities's new primary path, tried first when
    thehive_alert_id is given."""

    def test_real_closed_rows_correctly_excluded(self, monkeypatch, real_similar_cases):
        """Both real similarCases rows for this alert are stage=='Closed' —
        the open-cases result must be empty, proving the exclusion side of
        the stage filter against real data."""
        patch_query_by_name(monkeypatch, {"similar-cases": real_similar_cases})
        cases, gap = run(
            search_open_cases_by_entities(
                observables(sha256=[SHA256]), thehive_alert_id="~4661456"
            )
        )
        assert gap is None
        assert cases == []

    def test_synthetic_open_row_included_with_similarity_signal(self, monkeypatch):
        """Inclusion side of the same filter, plus proves
        similar_observable_count and the linkedWith-derived observables list
        both map correctly — real fixture has no open example to test this
        against."""
        patch_query_by_name(
            monkeypatch, {"similar-cases": [SYNTHETIC_SIMILAR_OPEN_ROW]}
        )
        cases, gap = run(
            search_open_cases_by_entities(
                observables(sha256=[SHA256]), thehive_alert_id="~4661456"
            )
        )
        assert gap is None
        assert len(cases) == 1
        assert cases[0].case_id == "~100"
        assert cases[0].similar_observable_count == 3
        assert cases[0].observables == [SHA256, "evil.test"]

    def test_similar_cases_query_shape(self, monkeypatch):
        capture: dict = {}
        patch_query_by_name(monkeypatch, {"similar-cases": []}, capture=capture)
        run(
            search_open_cases_by_entities(
                observables(sha256=[SHA256]), thehive_alert_id="~4661456"
            )
        )
        body = capture["bodies"][capture["names"].index("similar-cases")]
        assert body == {
            "query": [
                {"_name": "getAlert", "idOrName": "~4661456"},
                {"_name": "similarCases"},
            ]
        }

    def test_missing_alert_id_never_calls_similar_cases(self, monkeypatch):
        capture: dict = {}
        patch_query(monkeypatch, results=[], capture=capture)
        run(search_open_cases_by_entities(observables(sha256=[SHA256])))
        assert "similar-cases" not in capture.get("names", [])

    def test_similar_cases_failure_falls_back_to_old_query(self, monkeypatch):
        """thehive_alert_id given, but the similarCases call itself fails —
        must fall through to the untouched old entity-value query rather
        than propagating the failure or returning an empty result."""

        async def fake_query(body, timeout, name="soc3s"):
            if name == "similar-cases":
                raise httpx.ConnectError("similarity engine down")
            return [SYNTHETIC_OPEN_CASE] if name == "open-cases-by-entity" else []

        monkeypatch.setattr(th, "_query", fake_query)
        cases, gap = run(
            search_open_cases_by_entities(
                observables(sha256=[SHA256]), thehive_alert_id="~4661456"
            )
        )
        assert gap is None
        assert len(cases) == 1
        assert cases[0].case_id == "~100"
        # Old path's case came back with no similarity signal — correctly None.
        assert cases[0].similar_observable_count is None


class TestSimilarCasesClosedPath:
    """search_closed_cases_by_rule's observable-matching half, replaced by
    similarCases when thehive_alert_id is given. The rule-tag half is
    unaffected."""

    def test_real_closed_rows_summarised_correctly(self, monkeypatch, real_similar_cases):
        patch_query_by_name(monkeypatch, {"similar-cases": real_similar_cases})
        summary, gap = run(
            search_closed_cases_by_rule(
                RULE_UUID, None, None, thehive_alert_id="~4661456"
            )
        )
        assert gap is None
        assert (summary.tp_count, summary.fp_count) == (1, 1)
        assert summary.matched_by == ["observables"]

    def test_matched_by_includes_both_when_rule_name_also_given(self, monkeypatch):
        patch_query_by_name(monkeypatch, {"similar-cases": [], "closed-cases": []})
        summary, _ = run(
            search_closed_cases_by_rule(
                RULE_UUID, RULE_NAME, None, thehive_alert_id="~4661456"
            )
        )
        assert summary.matched_by == ["rule_tag", "observables"]

    def test_similar_cases_failure_falls_back_to_old_closed_query(self, monkeypatch):
        async def fake_query(body, timeout, name="soc3s"):
            if name == "similar-cases":
                raise httpx.ConnectError("similarity engine down")
            return [SYNTHETIC_CLOSED_TP]

        monkeypatch.setattr(th, "_query", fake_query)
        summary, gap = run(
            search_closed_cases_by_rule(
                RULE_UUID, RULE_NAME, observables(sha256=[SHA256]), thehive_alert_id="~4661456"
            )
        )
        assert gap is None
        assert summary.tp_count == 1
        assert summary.matched_by == ["rule_tag", "observables"]

    def test_missing_alert_id_never_calls_similar_cases(self, monkeypatch):
        capture: dict = {}
        patch_query(monkeypatch, results=[], capture=capture)
        run(search_closed_cases_by_rule(RULE_UUID, RULE_NAME, observables(sha256=[SHA256])))
        assert "similar-cases" not in capture.get("names", [])


# ===========================================================================
# get_full_alert_with_analysis — the stock two-call path (2026-08-13)
# ===========================================================================
class TestGetFullAlertWithAnalysis:
    """REAL payloads from alert `~4661456`, captured 2026-08-13 from TheHive
    5.7.5-1 at 172.20.24.228 — richer than the alert used elsewhere in this
    fixture, since it carries genuine VirusTotal reports (not just OpenCTI
    "Not found") alongside OpenCTI's.

    This function used to call a custom `getAlertWithObservables` Function
    because TheHive 5.7.3's external API silently dropped
    `extraData:["reports"]`. Re-verified 2026-08-13: the Function is gone
    (404), but the stock `getAlert` -> `observables` -> `page` projection now
    returns `reports[analyzer].taxonomies` directly with no `extraData`
    needed, so the function was rewritten to two concurrent stock queries
    instead of re-registering the Function. See the function's own docstring
    in tools/thehive.py.
    """

    def test_real_payload_yields_alert_and_observables(self, monkeypatch, real):
        patch_query_by_name(
            monkeypatch,
            {"alert-detail": real["alert_detail"], "alert-observables": real["alert_observables"]},
        )
        hive_alert, gap = run(th.get_full_alert_with_analysis("~4661456"))
        assert gap is None
        assert hive_alert["title"].startswith("[HIGH]")
        assert len(hive_alert["observables"]) == 4

    def test_taxonomies_survive_into_the_hive_alert(self, monkeypatch, real):
        """The whole point of the rewrite: reports[analyzer].taxonomies must
        still reach alert_builder unchanged, now via the stock query."""
        patch_query_by_name(
            monkeypatch,
            {"alert-detail": real["alert_detail"], "alert-observables": real["alert_observables"]},
        )
        hive_alert, _ = run(th.get_full_alert_with_analysis("~4661456"))
        with_reports = [o for o in hive_alert["observables"] if o.get("reports")]
        assert len(with_reports) == 3
        vt = [o for o in with_reports if "VirusTotal_GetReport_3_1" in o["reports"]][0]
        taxonomies = vt["reports"]["VirusTotal_GetReport_3_1"]["taxonomies"]
        assert taxonomies and "value" in taxonomies[0]

    def test_calls_getalert_then_the_observables_projection(self, monkeypatch, real):
        capture: dict = {}
        patch_query_by_name(
            monkeypatch,
            {"alert-detail": real["alert_detail"], "alert-observables": real["alert_observables"]},
            capture=capture,
        )
        run(th.get_full_alert_with_analysis("~4661456"))
        assert set(capture["names"]) == {"alert-detail", "alert-observables"}
        step_names = {n: [s.get("_name") for s in b["query"]] for n, b in zip(capture["names"], capture["bodies"])}
        assert step_names["alert-detail"] == ["getAlert"]
        assert step_names["alert-observables"] == ["getAlert", "observables", "page"]

    def test_alert_not_found_is_a_gap(self, monkeypatch):
        patch_query_by_name(monkeypatch, {"alert-detail": [], "alert-observables": []})
        hive_alert, gap = run(th.get_full_alert_with_analysis("~doesnotexist"))
        assert hive_alert is None
        assert "no alert" in gap.reason.lower()

    def test_observables_fetch_failure_still_returns_the_alert(self, monkeypatch):
        """A partial failure — alert fetched fine, observables query broke —
        must not throw the alert away too."""
        patch_query_by_name(
            monkeypatch,
            {
                "alert-detail": [{"_id": "~1", "title": "t"}],
                "alert-observables": httpx.ReadTimeout("slow"),
            },
        )
        hive_alert, gap = run(th.get_full_alert_with_analysis("~1"))
        assert hive_alert["title"] == "t"
        assert hive_alert["observables"] == []
        assert "observables query failed" in gap.reason

    def test_alert_without_observables_gaps_but_still_returns_the_alert(self, monkeypatch):
        patch_query_by_name(
            monkeypatch, {"alert-detail": [{"_id": "~1", "title": "t"}], "alert-observables": []}
        )
        hive_alert, gap = run(th.get_full_alert_with_analysis("~1"))
        assert hive_alert["title"] == "t"
        assert "no observables" in gap.reason

    def test_no_alert_id(self, monkeypatch):
        capture: dict = {}
        patch_query_by_name(monkeypatch, {}, capture=capture)
        hive_alert, gap = run(th.get_full_alert_with_analysis(""))
        assert hive_alert is None
        assert "No thehive_alert_id" in gap.reason
        assert capture == {}

    def test_connection_error(self, monkeypatch):
        exc = httpx.ConnectError("refused")
        patch_query_by_name(monkeypatch, {"alert-detail": exc, "alert-observables": exc})
        hive_alert, gap = run(th.get_full_alert_with_analysis("~4661456"))
        assert hive_alert is None
        assert "Cannot connect to TheHive" in gap.reason


class TestFetchCaseObservablesWithType:
    """New in the 2026-08-23 Stage 4 build (CLAUDE.md) — Stage 4's read-side
    fetch of a merge target case's existing observables. Same
    getCase -> observables -> page query `_fetch_case_observables` already
    proves live, but keeps dataType/tags instead of collapsing to bare
    value strings, and follows the standard NEVER RAISES + Gap contract
    every other public function in this file uses."""

    def test_maps_datatype_value_and_tags(self, monkeypatch):
        patch_query(
            monkeypatch,
            results=[
                [
                    {"_id": "~111", "dataType": "ip", "data": "1.2.3.4", "tags": ["malicious"]},
                    {"_id": "~222", "dataType": "hash", "data": "deadbeef", "tags": []},
                ]
            ],
        )
        rows, gap = run(fetch_case_observables_with_type("~123"))
        assert gap is None
        assert rows == [
            {"observable_id": "~111", "data_type": "ip", "value": "1.2.3.4", "tags": ["malicious"]},
            {"observable_id": "~222", "data_type": "hash", "value": "deadbeef", "tags": []},
        ]

    def test_row_without_id_gets_empty_string_not_a_crash(self, monkeypatch):
        patch_query(
            monkeypatch, results=[[{"dataType": "ip", "data": "1.2.3.4", "tags": []}]]
        )
        rows, gap = run(fetch_case_observables_with_type("~123"))
        assert gap is None
        assert rows[0]["observable_id"] == ""

    def test_rows_without_data_are_skipped(self, monkeypatch):
        patch_query(
            monkeypatch, results=[[{"dataType": "ip", "data": ""}, "not-a-dict"]]
        )
        rows, gap = run(fetch_case_observables_with_type("~123"))
        assert gap is None
        assert rows == []

    def test_no_case_id(self, monkeypatch):
        capture: dict = {}
        patch_query(monkeypatch, results=[], capture=capture)
        rows, gap = run(fetch_case_observables_with_type(""))
        assert rows == []
        assert "No case_id" in gap.reason
        assert capture == {}

    def test_connection_error_never_raises(self, monkeypatch):
        patch_query(monkeypatch, exc=httpx.ConnectError("refused"))
        rows, gap = run(fetch_case_observables_with_type("~123"))
        assert rows == []
        assert "Cannot connect to TheHive" in gap.reason

    def test_timeout_never_raises(self, monkeypatch):
        async def hangs(body, timeout, name="soc3s"):
            await asyncio.sleep(10)

        monkeypatch.setattr(th, "_query", hangs)
        rows, gap = run(fetch_case_observables_with_type("~123", timeout=0.01))
        assert rows == []
        assert "Timed out" in gap.reason

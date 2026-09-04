"""`tools/thehive.py::create_case_observable` — the one primitive that
survives from the 2026-08-21 observable-write build.

`add_extracted_observables` (the old composed "write all 6 ExtractedObservables
buckets, blindly, no dedup" function this file used to test at length) was
retired 2026-08-23 — see `nodes/case_action.py`'s module docstring for why:
Stage 3's raw extraction was being written straight to TheHive without ever
consulting Stage 4's judgment. Its replacement, `nodes/case_action.py::
_write_actionable_observables`, is tested in `tests/test_case_action.py`
instead (that's where the logic actually lives now — dedup-against-existing,
confidence-based tags, ID capture).

PROVENANCE for what remains here: `tests/fixtures/thehive_create_observable_real.json`
is REAL — live-verified 2026-08-21 against `http://172.20.24.228:9000`
(TheHive 5.7.5-1), disposable test case `~8609848`. `response_example` is a
single real create-observable response (`POST /api/v1/case/{id}/observable`
→ 201, a LIST containing the created object) — the exact shape the
2026-08-23 fix (`create_case_observable` now returns the real assigned
`_id` instead of discarding the response) depends on being correct.
"""

import json
from pathlib import Path

import httpx
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from tools.thehive import create_case_observable

OBSERVABLE_FIXTURE = Path(__file__).parent / "fixtures" / "thehive_create_observable_real.json"


@pytest.fixture(scope="module")
def real() -> dict:
    return json.loads(OBSERVABLE_FIXTURE.read_text())


def run(coro):
    import asyncio

    return asyncio.run(coro)


class TestCreateCaseObservable:
    def test_happy_path_returns_the_real_id(self):
        with patch("tools.thehive._write", new_callable=AsyncMock) as mock_write:
            mock_resp = MagicMock()
            mock_resp.json.return_value = [{"_id": "~4632816", "dataType": "domain"}]
            mock_write.return_value = mock_resp

            observable_id, gap = run(
                create_case_observable(
                    "~case1",
                    data_type="domain",
                    data="evil.com",
                    tags=["malicious"],
                    message="Test observable",
                )
            )

            assert observable_id == "~4632816"
            assert gap is None
            mock_write.assert_called_once()

    def test_missing_case_id_short_circuits(self):
        with patch("tools.thehive._write", new_callable=AsyncMock) as mock_write:
            observable_id, gap = run(
                create_case_observable("", data_type="domain", data="evil.com")
            )

            assert observable_id is None
            assert gap is not None
            assert "Missing case_id" in gap.reason
            mock_write.assert_not_called()

    def test_missing_data_short_circuits(self):
        with patch("tools.thehive._write", new_callable=AsyncMock) as mock_write:
            observable_id, gap = run(
                create_case_observable("~case1", data_type="domain", data="")
            )

            assert observable_id is None
            assert gap is not None
            mock_write.assert_not_called()

    def test_http_error_produces_gap(self):
        with patch("tools.thehive._write", new_callable=AsyncMock) as mock_write:
            mock_write.side_effect = httpx.HTTPStatusError(
                "404 Not Found", request=MagicMock(), response=MagicMock(status_code=404, text="")
            )

            observable_id, gap = run(
                create_case_observable("~case1", data_type="domain", data="evil.com")
            )

            assert observable_id is None
            assert gap is not None
            assert "HTTP" in gap.reason

    def test_response_not_a_list_produces_gap(self):
        """Defensive: a malformed/unexpected response shape must not raise
        or silently return a fabricated id."""
        with patch("tools.thehive._write", new_callable=AsyncMock) as mock_write:
            mock_resp = MagicMock()
            mock_resp.json.return_value = {"unexpected": "shape"}
            mock_write.return_value = mock_resp

            observable_id, gap = run(
                create_case_observable("~case1", data_type="domain", data="evil.com")
            )

            assert observable_id is None
            assert gap is not None

    def test_response_missing_id_produces_gap(self):
        with patch("tools.thehive._write", new_callable=AsyncMock) as mock_write:
            mock_resp = MagicMock()
            mock_resp.json.return_value = [{"dataType": "domain"}]  # no _id
            mock_write.return_value = mock_resp

            observable_id, gap = run(
                create_case_observable("~case1", data_type="domain", data="evil.com")
            )

            assert observable_id is None
            assert gap is not None


class TestAgainstRealCapturedResponse:
    """Regression guard: if TheHive's real create-observable response shape
    ever drifts (e.g. stops being a list, renames `_id`), this goes red
    rather than the mocks above silently agreeing with themselves."""

    def test_real_response_is_a_list_containing_one_object_with_an_id(self, real):
        example = real["response_example"]
        assert isinstance(example, list)
        assert len(example) == 1
        assert "_id" in example[0]

    def test_id_extraction_matches_the_real_captured_response(self, real):
        with patch("tools.thehive._write", new_callable=AsyncMock) as mock_write:
            mock_resp = MagicMock()
            mock_resp.json.return_value = real["response_example"]
            mock_write.return_value = mock_resp

            observable_id, gap = run(
                create_case_observable("~case1", data_type="domain", data="soc3s-test-observable.fake")
            )

            assert observable_id == real["response_example"][0]["_id"]
            assert gap is None

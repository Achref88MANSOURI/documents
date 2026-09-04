"""`get_fp_signal` / `record_triage_outcome` — architecture §6 tool 1.

No external network backend here — "real" means the actual on-disk SQLite
file and actual blocking `sqlite3` calls (via a real temp file per test,
pytest's `tmp_path`), never a mocked `sqlite3.connect`. Implementation guide
§2's own verification-input table says "even one with zero history is a
valid real result to inspect" for this tool, and that loop was run for real
before these tests were written (a temp-DB script seeded rows spanning
inside-24h / inside-30d / outside-30d and confirmed the exact counts,
matching `tools/fp_tracking.py`'s module docstring).

Every test here points `config.FP_TRACKING_DB_PATH` at a fresh `tmp_path`
file, so tests never share state and never touch the real deployment DB.
"""

from __future__ import annotations

import asyncio
import os
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

import config
from tools import fp_tracking as fp_mod
from tools.fp_tracking import get_fp_signal, record_triage_outcome

RULE = "5e3cc4d8-3e68-43db-8656-eaaeefdec9cc"
HOST = "win-kvkmd51ggkq"
OTHER_RULE = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OTHER_HOST = "some-other-host"


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def fp_db(tmp_path, monkeypatch):
    """Point every test at its own fresh, real SQLite file."""
    db_path = str(tmp_path / "fp_events.db")
    monkeypatch.setattr(config, "FP_TRACKING_DB_PATH", db_path)
    return db_path


class TestGetFpSignalAgainstRealDb:
    def test_empty_db_returns_real_zero_result_no_gap(self):
        """Zero history is a real, fully successful result — not a Gap."""
        signal, gap = run(get_fp_signal(RULE, HOST))
        assert gap is None
        assert signal.rule_fp_count_24h == 0
        assert signal.rule_fp_count_30d == 0
        assert signal.host_fp_count_24h == 0
        assert signal.host_fp_count_30d == 0

    def test_seeded_events_produce_correct_windowed_counts(self):
        now = datetime.now(timezone.utc)
        run(record_triage_outcome(RULE, HOST, "recent", now=now - timedelta(hours=1)))
        run(record_triage_outcome(RULE, HOST, "mid", now=now - timedelta(days=5)))
        run(record_triage_outcome(RULE, HOST, "old", now=now - timedelta(days=40)))

        signal, gap = run(get_fp_signal(RULE, HOST, now=now))
        assert gap is None
        assert signal.rule_fp_count_24h == 1  # "recent" only
        assert signal.rule_fp_count_30d == 2  # "recent" + "mid", not "old"
        assert signal.host_fp_count_24h == 1
        assert signal.host_fp_count_30d == 2

    def test_events_outside_30d_window_are_excluded(self):
        now = datetime.now(timezone.utc)
        run(record_triage_outcome(RULE, HOST, "ancient", now=now - timedelta(days=31)))
        signal, gap = run(get_fp_signal(RULE, HOST, now=now))
        assert gap is None
        assert signal.rule_fp_count_30d == 0
        assert signal.host_fp_count_30d == 0

    def test_rule_and_host_signals_are_independent(self):
        """REGRESSION GUARD for design decision 2: a row must count toward the
        rule's signal even when queried with a different host, and toward the
        host's signal even when queried with a different rule — NOT a joint
        `WHERE rule_uuid=? AND host=?` match."""
        now = datetime.now(timezone.utc)
        run(record_triage_outcome(RULE, OTHER_HOST, "diff host", now=now))
        run(record_triage_outcome(OTHER_RULE, HOST, "diff rule", now=now))

        signal, gap = run(get_fp_signal(RULE, HOST, now=now))
        assert gap is None
        assert signal.rule_fp_count_30d == 1  # RULE fired on OTHER_HOST — still counts
        assert signal.host_fp_count_30d == 1  # OTHER_RULE fired on HOST — still counts

    def test_rule_only_lookup_leaves_host_counts_at_zero(self):
        now = datetime.now(timezone.utc)
        run(record_triage_outcome(RULE, HOST, now=now))
        signal, gap = run(get_fp_signal(RULE, None, now=now))
        assert gap is None
        assert signal.rule_fp_count_30d == 1
        assert signal.host_fp_count_30d == 0

    def test_host_only_lookup_leaves_rule_counts_at_zero(self):
        now = datetime.now(timezone.utc)
        run(record_triage_outcome(RULE, HOST, now=now))
        signal, gap = run(get_fp_signal(None, HOST, now=now))
        assert gap is None
        assert signal.host_fp_count_30d == 1
        assert signal.rule_fp_count_30d == 0


class TestRecordTriageOutcome:
    def test_insert_succeeds_and_is_queryable(self, fp_db):
        ok, gap = run(record_triage_outcome(RULE, HOST, "SCCM deployment"))
        assert ok is True
        assert gap is None

        conn = sqlite3.connect(fp_db)
        try:
            row = conn.execute(
                "SELECT rule_uuid, host, analyst_reason FROM fp_events"
            ).fetchone()
        finally:
            conn.close()
        assert row == (RULE, HOST, "SCCM deployment")

    def test_multiple_inserts_accumulate(self, fp_db):
        for _ in range(3):
            run(record_triage_outcome(RULE, HOST))
        conn = sqlite3.connect(fp_db)
        try:
            (count,) = conn.execute("SELECT COUNT(*) FROM fp_events").fetchone()
        finally:
            conn.close()
        assert count == 3

    def test_missing_rule_uuid_produces_gap_no_db_touch(self, fp_db):
        ok, gap = run(record_triage_outcome("", HOST))
        assert ok is False
        assert "required" in gap.reason
        assert not os.path.exists(fp_db)

    def test_missing_host_produces_gap_no_db_touch(self, fp_db):
        ok, gap = run(record_triage_outcome(RULE, ""))
        assert ok is False
        assert "required" in gap.reason
        assert not os.path.exists(fp_db)


class TestNoLookupKey:
    def test_no_rule_or_host_at_all(self, fp_db):
        signal, gap = run(get_fp_signal(None, None))
        assert gap is not None
        assert "nothing to look up" in gap.reason
        assert not os.path.exists(fp_db)


class TestFailuresProduceGapsNotExceptions:
    def test_corrupt_db_file_produces_gap(self, fp_db):
        with open(fp_db, "wb") as f:
            f.write(b"not a sqlite file, just garbage bytes")

        signal, gap = run(get_fp_signal(RULE, HOST))
        assert gap is not None
        assert "FP tracker DB error" in gap.reason
        assert signal.rule_fp_count_24h == 0

    def test_unwritable_parent_directory_produces_gap(self, tmp_path, monkeypatch):
        if os.geteuid() == 0:
            pytest.skip("permission checks don't apply as root")
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir(mode=0o444)
        monkeypatch.setattr(
            config, "FP_TRACKING_DB_PATH", str(readonly_dir / "nested" / "fp.db")
        )
        try:
            signal, gap = run(get_fp_signal(RULE, HOST))
            assert gap is not None
            assert "FP tracker storage error" in gap.reason
        finally:
            readonly_dir.chmod(0o755)  # let tmp_path cleanup succeed

    def test_timeout(self, monkeypatch):
        def slow_sync(db_path, rule_uuid, host, now):
            import time as _time

            _time.sleep(5)

        monkeypatch.setattr(fp_mod, "_get_fp_signal_sync", slow_sync)
        signal, gap = run(get_fp_signal(RULE, HOST, timeout=0.05))
        assert gap is not None
        assert "Timeout after 0.05s" in gap.reason

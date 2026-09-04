"""Shared fixtures.

The provenance distinction enforced here matters more than any assertion in the
suite: `real_sigma_process_alert` is a genuine captured Security Onion alert;
everything in `tests/fixtures/synthetic_alerts.py` is constructed from field
mappings. Tests must not blur the two.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture(scope="session")
def webhook_envelope() -> dict:
    """The raw n8n webhook envelope exactly as saved from Security Onion.

    Shape: `[{headers, params, query, body, webhookUrl, executionMode}]`. This
    is what n8n RECEIVES; it is not what n8n POSTs to /triage. Unwrapping it is
    n8n's job — see schemas.AlertWebhookPayload.
    """
    return json.loads((REPO_ROOT / "sigma-alert-sample.json").read_text())[0]


@pytest.fixture(scope="session")
def real_es_alert_hit() -> dict:
    """REAL, VERBATIM — a full Elasticsearch hit pulled unmodified from
    `.ds-logs-detections.alerts-so-2026.08.02-000147` on 2026-08-08.

    This is the highest-authority alert fixture in the repo: an untouched
    production document, not a webhook capture. Same rule as the webhook sample
    (5e3cc4d8-…), different alert instance.

    It DOES contain a top-level `ioc` block. That is not contamination — the
    `so-ioc-normalize` pipeline is live in this deployment and stamps
    `ioc.{schema_version, source_engine, rule, dataset}` onto 100% of alerts
    from 2026-07-16 onward (5571 of 7719 verified). `ioc.*` is still not a
    Security Onion field and must never be read; keeping it in the fixture is
    what lets `TestRealProductionEsDocument` prove the code ignores it on real
    data rather than only on a synthetic case.
    """
    return json.loads((REPO_ROOT / "tests" / "fixtures" / "sigma-alert-real.json").read_text())


@pytest.fixture(scope="session")
def real_es_alert_source(real_es_alert_hit: dict) -> dict:
    """The `_source` of the verbatim ES hit — the raw alert document itself.

    Differs from the webhook body by exactly six keys the alerter/n8n layer adds
    at webhook time and which are absent from the index: `_id`, `_index`,
    `num_hits`, `num_matches`, `severity_filter`, `source_system`. Every shared
    key is identical between the two.
    """
    return real_es_alert_hit["_source"]


@pytest.fixture(scope="session")
def real_suricata_alert_hit() -> dict:
    """REAL, VERBATIM (`_source` unmodified) — a Suricata alert pulled from
    another Security Onion instance, ES search-hit shape trimmed to
    `_id`/`_index`/`_score`/`_source` to match `real_es_alert_hit`'s
    convention. "GPL ATTACK_RESPONSE id check returned root", SID 2100498.

    Re-confirmed live 2026-08-18 against THIS deployment: `logs-suricata.
    alerts-so` now holds 39,949 real fired Suricata alerts, including one
    from that same day for this exact SID, field-for-field identical in shape
    (rule.uuid as a string, event.module="suricata", event.dataset=
    "suricata.alert", no host/user/process fields). This fixture is not a
    stale one-off from a different deployment's quirks — it's the live shape.

    Note this alert has NEVER reached `/triage`: `config.ES_ALERTS_INDEX`
    (`logs-detections.alerts-so*`, what this repo's alert-consumption chain
    reads from) is 100% `event.module=sigma` — confirmed live, 0 Suricata/YARA
    docs ever. `logs-suricata.alerts-so` is a separate index Security Onion's
    own Sigma-match alerter (`so-alert-reference/securityonion-es.py`) never
    writes to. Making `build_canonical_alert` handle this shape correctly is
    necessary but not sufficient for a real Suricata alert to ever arrive at
    `/triage` — an n8n/SO-side bridge is also needed. See CLAUDE.md.
    """
    return json.loads((REPO_ROOT / "tests" / "fixtures" / "suricata-alert-real.json").read_text())


@pytest.fixture(scope="session")
def real_suricata_alert_source(real_suricata_alert_hit: dict) -> dict:
    """The `_source` of the verbatim Suricata ES hit above — the raw_alert
    shape `/triage` would receive in its webhook body, per the same
    `_source` == `raw_alert` relationship `real_es_alert_source` documents
    for the Sigma fixture."""
    return real_suricata_alert_hit["_source"]


@pytest.fixture(scope="session")
def real_sysmon_registry_alert_hit() -> dict:
    """REAL, VERBATIM — a live Sysmon registry-set alert pulled directly
    from `config.ES_ALERTS_INDEX` on 2026-08-19 (gap #8a/#10/#11 live
    verification, `~/.claude/plans/is-there-an-sqlite-melodic-globe.md`
    Phase 3a). "Potential Persistence Via GlobalFlags" (rule uuid
    36803969-5421-41ec-b92f-8500f79c23b0), a real Atomic-Red-Team-style
    persistence technique fired by `nanodump.x64.exe` on win-kvkmd51ggkq.

    This is a genuinely different Sysmon event shape from the already-
    verified `endpoint.events.process` one (`real_sigma_process_alert`
    below) — `event_data.event.code == 13` (int, not string — confirmed on
    this raw document), `event_data.registry.{hive,key,path,value,
    data.{type,strings}}` populated, no `event_data.process.pe.*` (that's
    the separate code==1 ProcessCreate shape).

    Also the live citation for gap #11's collision: `event_data.rule` here
    is `{"name": "T1183,IFEO"}` — Sysmon's own internal RuleName config tag
    — while the REAL fired Sigma rule name is the TOP-LEVEL `rule.name`,
    "Potential Persistence Via GlobalFlags". Confirms the collision this
    repo's `_parse_rule` guards against is not hypothetical.
    """
    return json.loads(
        (REPO_ROOT / "tests" / "fixtures" / "sysmon-registry-alert-real.json").read_text()
    )


@pytest.fixture(scope="session")
def real_sysmon_registry_alert_source(real_sysmon_registry_alert_hit: dict) -> dict:
    """The `_source` of the verbatim Sysmon registry ES hit above — the
    raw_alert shape `/triage` would receive in its webhook body."""
    return real_sysmon_registry_alert_hit["_source"]


@pytest.fixture(scope="session")
def real_sysmon_pe_alert_hit() -> dict:
    """REAL, VERBATIM — a live Sysmon ProcessCreate alert pulled directly
    from `config.ES_ALERTS_INDEX` on 2026-08-19 (gap #5 live verification,
    same Phase 3a pass as `real_sysmon_registry_alert_hit`). "Potentially
    Suspicious Powershell Script Execution From Temp Folder" (rule uuid
    a6a39bdb-935c-4f0a-ab77-35f4bbf44d33, 88 total real matches in this
    deployment, this is the most recent) — a real xordump/lsass-dump
    PowerShell invocation on win-kvkmd51ggkq.

    Confirms `event_data.process.pe.{company,description,file_version,
    product,imphash,original_file_name}` are all populated on real data;
    `.architecture` is NOT present on this example (stays tier 3 only, per
    Process's docstring in schemas/alert.py)."""
    return json.loads(
        (REPO_ROOT / "tests" / "fixtures" / "sysmon-powershell-pe-alert-real.json").read_text()
    )


@pytest.fixture(scope="session")
def real_sysmon_pe_alert_source(real_sysmon_pe_alert_hit: dict) -> dict:
    """The `_source` of the verbatim Sysmon PE-metadata ES hit above."""
    return real_sysmon_pe_alert_hit["_source"]


@pytest.fixture(scope="session")
def real_sigma_process_alert(webhook_envelope: dict) -> dict:
    """REAL captured alert — Sigma, `endpoint.events.process` dataset.

    "Suspicious Invoke-WebRequest Execution" / xordump.exe download on
    win-kvkmd51ggkq, rule uuid 5e3cc4d8-3e68-43db-8656-eaaeefdec9cc.

    This is ONE example of ONE dataset shape. Assertions against it prove that
    shape works and nothing more.
    """
    return webhook_envelope["body"]

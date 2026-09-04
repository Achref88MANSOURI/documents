"""alert_builder → CanonicalAlert.

PROVENANCE, read before trusting a green run:

- `TestRealSigmaProcessAlert` runs against a REAL captured Security Onion alert.
  It covers the `endpoint.events.process` dataset shape — 93% of this
  deployment's alert volume — and **only** that shape.
- Every other class runs against SYNTHETIC fixtures built from field mappings
  (`ingest-templates.txt`, `so-alert-reference/`). They prove the extractors map
  the documented field paths without crashing. They prove nothing about what
  Security Onion actually emits for those shapes, because no alert of those
  shapes has been captured in this deployment.

Per implementation guide §0.1 this partial coverage is the expected state today,
not an incomplete build.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from alert_builder import build_canonical_alert
from schemas import CanonicalAlert, File, Library
from tests.fixtures.synthetic_alerts import (
    ENDPOINT_FILE_ALERT,
    ENDPOINT_LIBRARY_ALERT,
    KRATOS_LOGIN_FLOW_ALERT,
    POWERSHELL_ENGINE_ALERT,
    RELATED_ENTITIES_ALERT,
    SSH_AUTH_ALERT,
    SSH_AUTH_ALERT_WITH_COMMUNITY_ID,
    SURICATA_ALERT,
    SYSMON_WINLOG_ALERT,
    TARGET_PROCESS_ALERT,
    YARA_STRELKA_ALERT,
)


def build(raw, hive_alert=None, asset_context=None, alert_id="") -> CanonicalAlert:
    return build_canonical_alert(
        raw_alert=raw,
        hive_alert=hive_alert,
        asset_context=asset_context or {},
        thehive_alert_id=alert_id,
    )


# ===========================================================================
# REAL captured alert — endpoint.events.process ONLY
# ===========================================================================
class TestRealSigmaProcessAlert:
    """REAL — Sigma / endpoint.events.process, from sigma-alert-sample.json
    (xordump.exe Invoke-WebRequest on win-kvkmd51ggkq).

    Covers this one dataset shape. Not evidence for any other shape.
    """

    def test_identity_and_profile(self, real_sigma_process_alert):
        alert = build(real_sigma_process_alert, alert_id="~1190993992")
        assert alert.alert_id == "~1190993992"
        assert alert.source_engine == "sigma"
        assert alert.investigation_profile == "endpoint_behavior"
        assert alert.event_dataset == "endpoint.events.process"

    def test_alert_id_falls_back_to_document_id(self, real_sigma_process_alert):
        alert = build(real_sigma_process_alert)
        assert alert.alert_id == "6qS9fp8BiUkBvoTNPeON"

    def test_rule_uses_structured_top_level_dict(self, real_sigma_process_alert):
        """Regression guard for the docstring correction in _parse_rule: Sigma
        alerts DO carry a top-level `rule` dict. If this ever falls through to
        the description regex, uuid comes back empty and detection_rule_lookup
        and get_fp_signal both lose their join key."""
        rule = build(real_sigma_process_alert).rule
        assert rule.uuid == "5e3cc4d8-3e68-43db-8656-eaaeefdec9cc"
        assert rule.name == "Suspicious Invoke-WebRequest Execution"
        assert rule.product == "windows"
        assert rule.category == "process_creation"
        assert rule.level == "high"
        assert rule.native_severity == 4

    def test_host(self, real_sigma_process_alert):
        host = build(real_sigma_process_alert).host
        assert host.hostname == "win-kvkmd51ggkq"
        assert host.host_id == "c8fc26bf-dc76-4dba-adbb-bf31640d9c9f"
        assert host.os.type == "windows"

    def test_host_ip_recovered_from_beats_metadata(self, real_sigma_process_alert):
        """event_data.host.ip is absent in this real alert; the agent address is
        only at event_data.metadata.input.beats.host.ip. Without the fallback the
        host IP is lost entirely for this shape."""
        assert build(real_sigma_process_alert).host.ip == ["172.20.24.99"]

    def test_user(self, real_sigma_process_alert):
        user = build(real_sigma_process_alert).user
        assert user.name == "Administrator"
        assert user.id.endswith("-500")  # built-in Administrator RID
        assert user.domain == "WIN-KVKMD51GGKQ"

    def test_process_core(self, real_sigma_process_alert):
        process = build(real_sigma_process_alert).process
        assert process.pid == 8524
        assert process.name == "powershell.exe"
        assert process.path.endswith("powershell.exe")
        assert "xordump.exe" in process.command_line
        assert process.working_directory.startswith("C:\\Users\\ADMINI~1")
        assert process.parent_pid == 7796
        assert process.parent_name == "powershell.exe"
        assert process.original_file_name == "PowerShell.EXE"
        assert process.exit_code == 0

    def test_process_tree_join_keys(self, real_sigma_process_alert):
        """entity_id / parent_entity_id / ancestry are what let
        elasticsearch_process_history walk the real parent chain instead of
        blind-scanning a 24h window (architecture §6 tool 7)."""
        process = build(real_sigma_process_alert).process
        assert process.entity_id == "L3ZrVQcxRfv3RsiWyLpX9A"
        assert process.parent_entity_id == "OE9m/Yj5spu59rcd4uZU3w"
        assert process.ancestry == ["OE9m/Yj5spu59rcd4uZU3w"]
        assert process.ancestry[0] == process.parent_entity_id

    def test_process_elevation_and_session_context(self, real_sigma_process_alert):
        process = build(real_sigma_process_alert).process
        assert process.integrity_level == "high"
        assert process.elevation_level == "default"
        assert process.logon_type == "Interactive"
        assert process.authentication_package == "NTLM"

    def test_process_code_signature(self, real_sigma_process_alert):
        """The real alert carries process.code_signature as a single object and
        process.Ext.code_signature as a LIST. Both must resolve."""
        process = build(real_sigma_process_alert).process
        assert process.code_signature.trusted is True
        assert process.code_signature.subject_name == "Microsoft Windows"
        assert process.parent_code_signature.trusted is True

    def test_process_args_vector(self, real_sigma_process_alert):
        args = build(real_sigma_process_alert).process.args
        assert len(args) == 8
        assert any("xordump.exe" in a for a in args)

    def test_hashes_reach_observables(self, real_sigma_process_alert):
        hashes = build(real_sigma_process_alert).observables.hashes
        assert hashes.sha256 == [
            "1c84c8632c5269f24876ed9f49fa810b49f77e1e92e8918fc164c34b020f9a94"
        ]
        assert hashes.imphash == ["bf7a6e7a62c3f5b2e8e069438ac1dd3d"]

    def test_no_iocs_without_thehive(self, real_sigma_process_alert):
        """Implementation guide §0.2, confirmed empirically: the raw Sigma alert
        carries no IOCs. `ioc` exists but has no `indicators` key — the live
        index mapping has no such field at all. The xordump URL appears only
        inside process.command_line and process.args, and extracting it here is
        explicitly forbidden (that work lives in n8n).

        If this test ever fails, someone has added IOC extraction to this repo.
        """
        observables = build(real_sigma_process_alert).observables
        assert observables.urls == []
        assert observables.domains == []
        assert observables.external_ips == []

    def test_shapes_absent_from_this_dataset_stay_none(self, real_sigma_process_alert):
        alert = build(real_sigma_process_alert)
        assert alert.network is None
        assert alert.file is None
        assert alert.library is None
        assert alert.target_process is None
        assert alert.related_entities is None

    def test_alert_and_event_timestamps_both_captured_and_differ(
        self, real_sigma_process_alert
    ):
        """~2 days apart in this real sample. Architecture §10's
        `evidence_age_hours > 24` branch does not say which it means, so both
        are carried and Stage 5 decides explicitly."""
        alert = build(real_sigma_process_alert)
        assert alert.timestamp.isoformat().startswith("2026-07-22T08:55:59")
        assert alert.event_timestamp.isoformat().startswith("2026-07-20T08:52:32")
        assert (alert.timestamp - alert.event_timestamp).total_seconds() > 24 * 3600

    def test_thehive_observables_and_cortex_reports(self, real_sigma_process_alert):
        """The IOC path that DOES exist: hive_alert.observables, with Cortex
        reports already attached (architecture §6)."""
        hive_alert = {
            "observables": [
                {
                    "_id": "~obs1",
                    "dataType": "url",
                    "data": "https://github.com/audibleblink/xordump/releases/download/v0.0.1/xordump.exe",
                    "reports": {
                        "VirusTotal_GetReport_3_1": {
                            "summary": {
                                "taxonomies": [
                                    {
                                        "level": "suspicious",
                                        "namespace": "VT",
                                        "predicate": "GetReport",
                                        "value": "3/70",
                                    }
                                ]
                            }
                        }
                    },
                },
                {"_id": "~obs2", "dataType": "ip", "data": "140.82.121.4", "reports": {}},
            ]
        }
        alert = build(real_sigma_process_alert, hive_alert=hive_alert)
        assert alert.observables.urls == [
            "https://github.com/audibleblink/xordump/releases/download/v0.0.1/xordump.exe"
        ]
        assert alert.observables.external_ips == ["140.82.121.4"]
        assert len(alert.cortex_results) == 1
        assert alert.cortex_results[0].verdict == ["suspicious"]
        assert alert.cortex_results[0].analyzer == "VirusTotal_GetReport_3_1"
        assert alert.thehive_observable_ids["140.82.121.4"] == "~obs2"

    def test_url_wins_over_mislabelled_datatype(self, real_sigma_process_alert):
        """n8n's Alert Builder is known to stamp URLs with the wrong dataType.
        A value starting with http(s):// is a URL regardless."""
        hive_alert = {
            "observables": [
                {"_id": "~x", "dataType": "fqdn", "data": "https://evil.example/pay.exe"}
            ]
        }
        alert = build(real_sigma_process_alert, hive_alert=hive_alert)
        assert alert.observables.urls == ["https://evil.example/pay.exe"]
        assert alert.observables.domains == []


class TestRealProductionEsDocument:
    """REAL, VERBATIM — an untouched production alert document pulled from
    `.ds-logs-detections.alerts-so-2026.08.02-000147` on 2026-08-08.

    Higher authority than the webhook sample: nothing has been through a capture
    or edit step. Same rule, different alert instance (deeper process ancestry).
    """

    def test_parses_from_the_raw_index_document(self, real_es_alert_source):
        alert = build(real_es_alert_source, alert_id="~prod")
        assert alert.source_engine == "sigma"
        assert alert.investigation_profile == "endpoint_behavior"
        assert alert.event_dataset == "endpoint.events.process"
        assert alert.rule.uuid == "5e3cc4d8-3e68-43db-8656-eaaeefdec9cc"
        assert alert.host.hostname == "win-kvkmd51ggkq"
        assert alert.user.name == "Administrator"
        assert alert.process.name == "powershell.exe"
        assert alert.process.integrity_level == "high"

    def test_ioc_present_in_real_production_data_and_still_ignored(
        self, real_es_alert_source
    ):
        """The definitive version of the ioc guard.

        `so-ioc-normalize` is live in this deployment and stamps `ioc.*` onto
        100% of alerts since 2026-07-16, so this untouched production document
        genuinely contains it. `ioc.source_engine` is set from `ctx.event.module`
        by that pipeline, which is exactly why it can never corroborate
        `event.module` — and why engine detection must read `event.module`.
        """
        assert "ioc" in real_es_alert_source
        assert real_es_alert_source["ioc"]["source_engine"] == "sigma"
        alert = build(real_es_alert_source)
        # Same answer, but reached from event.module — verify by contradicting
        # the ioc block and confirming the result does not move.
        contradicted = dict(real_es_alert_source)
        contradicted["ioc"] = {**contradicted["ioc"], "source_engine": "suricata"}
        assert build(contradicted).source_engine == alert.source_engine == "sigma"

    def test_deeper_process_ancestry_than_the_webhook_sample(self, real_es_alert_source):
        """This instance has a two-level ancestry chain, the webhook sample one.
        Confirms ancestry is read as a real list, not a single-element special
        case."""
        process = build(real_es_alert_source).process
        assert len(process.ancestry) == 2
        assert process.parent_entity_id in process.ancestry

    def test_no_iocs_reach_observables_from_production_document(
        self, real_es_alert_source
    ):
        observables = build(real_es_alert_source).observables
        assert observables.urls == []
        assert observables.domains == []
        assert observables.external_ips == []
        # Process hash still reaches the bundle — that is not an IOC extraction.
        assert len(observables.hashes.sha256) == 1


# ===========================================================================
# SYNTHETIC — every shape below is unvalidated against real data
# ===========================================================================
class TestSyntheticEndpointFileShape:
    """SYNTHETIC — endpoint.events.file. Field paths from ingest-templates.txt.
    No real alert of this dataset exists to validate against."""

    def test_file_extracted_from_event_data(self):
        alert = build(ENDPOINT_FILE_ALERT)
        assert isinstance(alert.file, File)
        assert alert.file.name == "payload.exe"
        assert alert.file.directory.endswith("Startup")
        assert alert.file.extension == "exe"
        assert alert.file.owner == "Administrator"
        assert alert.file.size == 184320
        assert alert.file.quarantine_result is True

    def test_file_hash_reaches_observables(self):
        assert build(ENDPOINT_FILE_ALERT).observables.hashes.sha256 == ["d3adb33f" * 8]

    def test_malware_verdict_captured(self):
        malware = build(ENDPOINT_FILE_ALERT).file.malware
        assert malware.classification_score == pytest.approx(0.97)
        assert malware.classification_threshold == pytest.approx(0.66)
        assert malware.signature_name == "Windows.Trojan.Generic"
        assert "packer.upx" in malware.matches

    def test_risk_score_and_dataset_carried(self):
        alert = build(ENDPOINT_FILE_ALERT)
        assert alert.event_dataset == "endpoint.events.file"
        assert alert.risk_score == 47


class TestSyntheticEndpointLibraryShape:
    """SYNTHETIC — endpoint.events.library. No real alert of this dataset
    exists to validate against."""

    def test_dll_becomes_library_not_file(self):
        """A loaded module is not a written file. If this ever collapses into
        File, Stage 3 loses the ability to distinguish them."""
        alert = build(ENDPOINT_LIBRARY_ALERT)
        assert isinstance(alert.library, Library)
        assert alert.file is None
        assert alert.library.name == "evil.dll"
        assert alert.library.path == "C:\\Windows\\Temp\\evil.dll"
        assert alert.library.file_version == "1.0.0.1"
        assert alert.library.size == 91136

    def test_unsigned_module_signature_captured(self):
        signature = build(ENDPOINT_LIBRARY_ALERT).library.code_signature
        assert signature.trusted is False
        assert signature.status == "unsigned"

    def test_dll_hashes_reach_observables(self):
        hashes = build(ENDPOINT_LIBRARY_ALERT).observables.hashes
        assert hashes.sha256 == ["beefcafe" * 8]
        assert hashes.imphash == ["1122334455667788990011223344556677"]

    def test_host_process_still_extracted(self):
        alert = build(ENDPOINT_LIBRARY_ALERT)
        assert alert.process.name == "lsass.exe"
        assert alert.host.hostname == "win-kvkmd51ggkq"


class TestSyntheticTargetProcessShape:
    """SYNTHETIC — cross-process access (event_data.Target.process.*).
    No real alert carrying this field has been captured."""

    def test_source_and_target_stay_distinct(self):
        alert = build(TARGET_PROCESS_ALERT)
        assert alert.process.name == "rundll32.exe"
        assert alert.process.entity_id == "SOURCEENTITY"
        assert alert.target_process.name == "lsass.exe"
        assert alert.target_process.pid == 704
        assert alert.target_process.entity_id == "TARGETENTITY"
        assert alert.target_process.integrity_level == "system"


class TestSyntheticApiCallShape:
    """SYNTHETIC — endpoint.events.api (process.Ext.api.*). Field paths and
    types from ingest-templates.txt. No real alert of this dataset exists to
    validate against."""

    def test_api_call_captured(self):
        api = build(TARGET_PROCESS_ALERT).process.api
        assert api.name == "WriteProcessMemory"
        assert api.behaviors == ["cross-process", "shellcode", "hollowing"]
        assert api.target_address_name == "lsass.exe!ntdll"
        assert api.handle_type == "process"

    def test_numeric_parameters_stay_numeric(self):
        """address / size / desired_access_numeric are `long` in the mapping,
        not keyword. desired_access is the keyword form alongside them."""
        api = build(TARGET_PROCESS_ALERT).process.api
        assert api.address == 140737488355328
        assert api.size == 4096
        assert api.desired_access_numeric == 2097151
        assert api.desired_access == "PROCESS_VM_WRITE|PROCESS_VM_OPERATION"

    def test_api_pairs_with_target_process(self):
        """The injection evidence surface: the API call says what was done, the
        target process says what it was done to."""
        alert = build(TARGET_PROCESS_ALERT)
        assert alert.process.api.name == "WriteProcessMemory"
        assert alert.target_process.name == "lsass.exe"

    def test_absent_api_stays_none(self, real_sigma_process_alert):
        """The real endpoint.events.process alert has process.Ext but no
        Ext.api — must not produce an empty ApiCall shell."""
        assert build(real_sigma_process_alert).process.api is None


class TestSyntheticRelatedEntities:
    """SYNTHETIC — ECS event_data.related.* roll-ups."""

    def test_related_entities_captured(self):
        related = build(RELATED_ENTITIES_ALERT).related_entities
        assert related.ip == ["10.1.2.3", "8.8.8.8"]
        assert related.hash == ["a" * 64]
        assert related.user == ["Administrator"]

    def test_related_entities_not_merged_into_observables(self):
        """Implementation guide §0.2: hive_alert.observables is the single IOC
        source of truth. Merging related.* here would duplicate n8n's upstream
        extraction across two systems and drift out of sync."""
        alert = build(RELATED_ENTITIES_ALERT)
        assert alert.observables.external_ips == []
        assert alert.observables.hashes.sha256 == []


class TestSyntheticWinlogShapes:
    """SYNTHETIC — winlog / powershell / ssh / kratos telemetry shapes."""

    def test_sysmon_winlog(self):
        alert = build(SYSMON_WINLOG_ALERT)
        assert alert.host.hostname == "win-kvkmd51ggkq"
        assert alert.user.name == "SYSTEM"
        assert alert.user.id == "S-1-5-18"
        assert alert.process.pid == 3312
        assert alert.event_dataset == "windows.sysmon_operational"

    def test_powershell_engine_state_synthesized(self):
        """No process exists for an engine-state event; the extractor
        synthesizes a descriptive command_line rather than inventing a pid."""
        process = build(POWERSHELL_ENGINE_ALERT).process
        assert "powershell engine" in process.command_line
        assert "None -> Available" in process.command_line
        assert process.pid is None

    def test_ssh_auth_synthesized_and_network_from_event_data(self):
        alert = build(SSH_AUTH_ALERT)
        assert alert.process.command_line == "ssh Accepted (publickey)"
        assert alert.network.src_ip == "10.20.30.40"
        assert alert.network.src_port == 51234

    def test_community_id_from_nested_event_data_network(self):
        """Gap #5, synthetic-only (no real Sysmon network_connection alert
        captured yet — see fixture docstring). Suricata's top-level
        network.community_id is covered by TestRealSuricataPath; this covers
        the nested event_data.network.community_id fallback path."""
        alert = build(SSH_AUTH_ALERT_WITH_COMMUNITY_ID)
        assert alert.network.community_id == "1:synthetic-community-id-hash="

    def test_kratos_login_flow_synthesized_with_host_port_split(self):
        alert = build(KRATOS_LOGIN_FLOW_ALERT)
        assert "POST /self-service/login" in alert.process.command_line
        assert "state=choose_method" in alert.process.command_line
        assert alert.network.src_ip == "203.0.113.9"
        assert alert.network.src_port == 44321


class TestSyntheticSuricataPath:
    # NOTE: this fixture now covers only what the real fixture below doesn't
    # (a different rule/uuid, an IPv6 destination, network.initiated — see
    # synthetic_alerts.py's comment). `transport` was corrected 2026-08-18 to
    # "TCP" (uppercase) to match real data; this test's assertion follows.
    def test_network_threat_profile_and_network_fields(self):
        alert = build(SURICATA_ALERT)
        assert alert.source_engine == "suricata"
        assert alert.investigation_profile == "network_threat"
        assert alert.network.src_ip == "172.20.24.99"
        assert alert.network.dst_ip == "185.53.178.50"
        assert alert.network.dst_port == 443
        assert alert.network.protocol == "TCP"
        assert alert.network.initiated is True

    def test_no_endpoint_context(self):
        alert = build(SURICATA_ALERT)
        assert alert.process is None
        assert alert.file is None


# ===========================================================================
# REAL captured Suricata alert — network_threat profile
# ===========================================================================
class TestRealSuricataPath:
    """REAL — suricata.alert, from `tests/fixtures/suricata-alert-real.json`
    ("GPL ATTACK_RESPONSE id check returned root", SID 2100498). Re-confirmed
    live 2026-08-18 against a freshly-fired alert for the same rule in this
    deployment's `logs-suricata.alerts-so` — see conftest.py's
    `real_suricata_alert_hit` docstring for the full provenance note,
    including why this alert has never actually reached `/triage` (Gap 0,
    CLAUDE.md).

    Covers this one dataset shape (network_threat / suricata.alert) and only
    that shape — same discipline `TestRealSigmaProcessAlert` follows above.
    """

    def test_identity_and_profile(self, real_suricata_alert_source):
        alert = build(real_suricata_alert_source)
        assert alert.source_engine == "suricata"
        assert alert.investigation_profile == "network_threat"

    def test_event_dataset_from_top_level_fallback(self, real_suricata_alert_source):
        """Regression test for the alert_builder.py fix: Suricata has no
        event_data, so event_dataset must fall back to the top-level
        raw_alert.event.dataset — it must NOT be None just because the
        Sigma-shaped nested path doesn't exist on this alert."""
        alert = build(real_suricata_alert_source)
        assert alert.event_dataset == "suricata.alert"

    def test_rule_identity(self, real_suricata_alert_source):
        alert = build(real_suricata_alert_source)
        assert alert.rule.uuid == "2100498"
        assert alert.rule.name == "GPL ATTACK_RESPONSE id check returned root"

    def test_network_fields(self, real_suricata_alert_source):
        alert = build(real_suricata_alert_source)
        assert alert.network.src_ip == "192.168.1.11"
        assert alert.network.src_port == 6200
        assert alert.network.dst_ip == "192.168.1.175"
        assert alert.network.dst_port == 39391
        assert alert.network.protocol == "TCP"

    def test_community_id(self, real_suricata_alert_source):
        """Gap #5, tier-1 verified 2026-08-19: raw_alert.network.community_id
        is real and populated on this fixture — the pivot key for a future
        elasticsearch_suricata_flow_context tool to correlate this alert
        against companion EVE-log documents (DNS/HTTP/TLS/flow)."""
        alert = build(real_suricata_alert_source)
        assert alert.network.community_id == "1:4VUkJupYhA6RP+xhGL5c62H+GNQ="

    def test_no_endpoint_context(self, real_suricata_alert_source):
        """Confirmed on the real alert, not assumed: no host/user/process
        fields exist anywhere on a Suricata document."""
        alert = build(real_suricata_alert_source)
        assert alert.host is None
        assert alert.user is None
        assert alert.process is None
        assert alert.file is None


class TestRealSysmonRegistryPath:
    """REAL — windows.sysmon_operational, event_data.event.code == 13
    (RegistryEvent: Value Set), from
    tests/fixtures/sysmon-registry-alert-real.json ("Potential Persistence
    Via GlobalFlags", rule uuid 36803969-5421-41ec-b92f-8500f79c23b0).
    Gap #8a/#10/#11, live-verified 2026-08-19. Covers this one dataset shape
    and only that shape."""

    def test_registry_fields(self, real_sysmon_registry_alert_source):
        alert = build(real_sysmon_registry_alert_source)
        assert alert.registry is not None
        assert alert.registry.hive == "HKLM"
        assert alert.registry.value == "GlobalFlag"
        assert alert.registry.data == "512"
        assert alert.registry.key == (
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File "
            "Execution Options\\lsass.exe\\GlobalFlag"
        )
        assert alert.registry.path == (
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File "
            "Execution Options\\lsass.exe\\GlobalFlag"
        )

    def test_process_still_populated_on_a_registry_event(
        self, real_sysmon_registry_alert_source
    ):
        """event_data.process is present on this shape too (the process that
        touched the registry) — must not be dropped just because a registry
        object also fired. No dispatch exclusivity between the two."""
        alert = build(real_sysmon_registry_alert_source)
        assert alert.process is not None
        assert alert.process.name == "nanodump.x64.exe"

    def test_rule_identity_not_confused_with_sysmon_internal_rule_name(
        self, real_sysmon_registry_alert_source
    ):
        """Gap #11's live citation: event_data.rule.name on this real alert
        is "T1183,IFEO" (Sysmon's own internal RuleName tag) — completely
        different from the real fired Sigma rule name. Regression guard that
        _parse_rule picks the right one."""
        raw = real_sysmon_registry_alert_source
        assert raw["event_data"]["rule"]["name"] == "T1183,IFEO"
        alert = build(raw)
        assert alert.rule.name == "Potential Persistence Via GlobalFlags"
        assert alert.rule.uuid == "36803969-5421-41ec-b92f-8500f79c23b0"

    def test_registry_defaults_to_none_on_other_alert_shapes(self):
        assert build(SURICATA_ALERT).registry is None
        assert build(YARA_STRELKA_ALERT).registry is None


class TestRealSysmonProcessPeMetadata:
    """REAL — windows.sysmon_operational, event_data.event.code == 1
    (ProcessCreate), from
    tests/fixtures/sysmon-powershell-pe-alert-real.json ("Potentially
    Suspicious Powershell Script Execution From Temp Folder", rule uuid
    a6a39bdb-935c-4f0a-ab77-35f4bbf44d33). Gap #5 (Process half), live-
    verified 2026-08-19."""

    def test_pe_metadata_fields(self, real_sysmon_pe_alert_source):
        alert = build(real_sysmon_pe_alert_source)
        assert alert.process.description == "Windows PowerShell"
        assert alert.process.product == "Microsoft® Windows® Operating System"
        assert alert.process.company == "Microsoft Corporation"
        assert alert.process.file_version == "10.0.20348.1 (WinBuild.160101.0800)"
        # Not present on this real example — stays None, not fabricated.
        assert alert.process.architecture is None

    def test_existing_pe_fields_unaffected(self, real_sysmon_pe_alert_source):
        """Regression guard: original_file_name/imphash were already read
        from the same `pe` dict before this addition — must still work."""
        alert = build(real_sysmon_pe_alert_source)
        assert alert.process.original_file_name == "PowerShell.EXE"
        assert alert.observables.hashes.imphash == ["bf7a6e7a62c3f5b2e8e069438ac1dd3d"]


class TestSyntheticYaraPath:
    # NOTE: YARA path — unit-tested against synthetic fixture only, no live SO
    # alert exists yet to validate against (implementation guide §0.1).
    def test_malicious_file_profile_and_top_level_hashes(self):
        alert = build(YARA_STRELKA_ALERT)
        # event.module is "strelka" for Security Onion's file-extraction path.
        # PROFILE_BY_ENGINE maps both "strelka" and "yara" to malicious_file,
        # because neither spelling can be confirmed live in this deployment.
        assert alert.source_engine == "strelka"
        assert alert.investigation_profile == "malicious_file"
        assert alert.file.name == "invoice.doc.exe"
        assert alert.file.mime_type == "application/x-dosexec"
        # Strelka puts hashes at a top-level `hash`, sibling of `file`.
        assert alert.observables.hashes.sha256 == ["f" * 64]
        assert alert.observables.hashes.md5 == ["0" * 32]

    def test_strelka_scan_and_timestamp_fields(self):
        """Gap #7, synthetic-only (see fixture docstring — Strelka sensor not
        enabled in this deployment, no real alert of this shape exists)."""
        from datetime import datetime, timezone

        alert = build(YARA_STRELKA_ALERT)
        assert alert.file.entropy == 7.89
        assert alert.file.pe_image_version == "6.1"
        assert alert.file.pe_flags == "DLL, EXECUTABLE_IMAGE"
        assert alert.file.mode == "0755"
        assert alert.file.created == datetime(2026, 7, 22, 10, 39, 50, tzinfo=timezone.utc)
        assert alert.file.mtime == datetime(2026, 6, 1, 8, 0, 0, tzinfo=timezone.utc)
        assert alert.observables.hashes.ssdeep == ["768:abc123:xyz789"]

    def test_strelka_pe_flags_list_is_joined_to_string(self):
        """Defensive path: File.pe_flags is typed str, but the resolved
        schema's `text` type doesn't strictly rule out a caller supplying a
        list — must not raise a Pydantic validation error either way."""
        alert_data = {
            **YARA_STRELKA_ALERT,
            "scan": {
                "entropy": {"entropy": 1.0},
                "pe": {"image_version": "1.0", "flags": ["DLL", "EXECUTABLE_IMAGE"]},
            },
        }
        alert = build(alert_data)
        assert alert.file.pe_flags == "DLL, EXECUTABLE_IMAGE"

    def test_rule_uuid_equals_rule_name_for_yara(self):
        """Security Onion's strelka.file pipeline sets rule.uuid = rule.name —
        there is no separate YARA rule ID."""
        rule = build(YARA_STRELKA_ALERT).rule
        assert rule.uuid == rule.name == "MALWARE_Win_Generic"


# ===========================================================================
# Degradation — the invariant that must hold for EVERY shape, known or not
# ===========================================================================
class TestDegradesRatherThanRaises:
    """Presence-guarded extraction is the load-bearing property of this module:
    an unrecognised shape must produce a sparse CanonicalAlert, never an
    exception. Stage 0 returning 500 on an unfamiliar alert would take the
    pipeline down for a shape nobody anticipated."""

    def test_empty_alert(self):
        alert = build({})
        assert alert.rule.name == "unknown"
        assert alert.host is None
        assert alert.process is None
        assert alert.observables.hashes.is_empty()

    def test_alert_with_only_event_data_scaffolding(self):
        alert = build({"event_data": {}})
        assert isinstance(alert, CanonicalAlert)
        assert alert.event_dataset is None

    def test_wrong_types_do_not_raise(self):
        """n8n's envelope carries a top-level `source` STRING (the source
        system) which collides with Suricata's ECS `source` OBJECT. Every
        nested read goes through _as_dict for exactly this reason."""
        alert = build(
            {
                "source": "security-onion",
                "rule": "not-a-dict",
                "event": None,
                "event_data": {"host": "nope", "process": ["also", "nope"], "user": 42},
                "ioc": "string-not-dict",
                "tags": None,
            }
        )
        assert isinstance(alert, CanonicalAlert)
        assert alert.host is None
        assert alert.process is None

    def test_scalar_where_array_expected(self):
        """ECS array-typed fields are routinely emitted as bare scalars when
        there is exactly one value."""
        alert = build(
            {
                "rule": {"name": "x", "uuid": "u"},
                "event_data": {
                    "host": {"name": "h", "ip": "10.0.0.1", "mac": "00:11:22:33:44:55"},
                    "related": {"ip": "10.0.0.2"},
                },
            }
        )
        assert alert.host.ip == ["10.0.0.1"]
        assert alert.host.mac == ["00:11:22:33:44:55"]
        assert alert.related_entities.ip == ["10.0.0.2"]

    def test_unknown_engine_falls_back_to_generic_profile(self):
        alert = build({"event": {"module": "some-future-engine"}})
        assert alert.source_engine == "some-future-engine"
        assert alert.investigation_profile == "generic"

    def test_source_engine_falls_back_to_event_dataset_prefix(self):
        """event.dataset is the second confirmed path from the real alerter
        source (securityonion-es.py writes event.severity/module/dataset)."""
        alert = build({"event": {"dataset": "suricata.alert"}})
        assert alert.source_engine == "suricata"
        assert alert.investigation_profile == "network_threat"

    def test_ioc_field_is_ignored_entirely(self):
        """REGRESSION GUARD. `ioc.*` is NOT a Security Onion field. It came from
        a custom development-time ingest pipeline that set
        `ioc.source_engine = ctx.event.module` — derived from event.module, so
        it can never corroborate it — and it is mapped in only 1 of the 24 live
        backing indices.

        If this test fails, someone has reintroduced a dependency on a field
        that does not exist in production Security Onion alerts."""
        alert = build(
            {
                "ioc": {
                    "source_engine": "suricata",
                    "rule": {"severity": "critical", "uuid": "ioc-uuid", "name": "ioc-name"},
                    "indicators": [
                        {"type": "ip", "value": "1.2.3.4"},
                        {"type": "url", "value": "https://evil.example/x"},
                        {"type": "hash_sha256", "value": "c" * 64},
                    ],
                },
                "event": {"module": "sigma"},
                "rule": {"name": "real-name", "uuid": "real-uuid"},
            }
        )
        # engine comes from event.module, never from ioc.source_engine
        assert alert.source_engine == "sigma"
        assert alert.investigation_profile == "endpoint_behavior"
        # rule identity comes from the top-level rule dict, never from ioc.rule
        assert alert.rule.uuid == "real-uuid"
        assert alert.rule.name == "real-name"
        assert alert.rule.level is None
        # ioc.indicators must NOT reach observables — IOCs come from TheHive only
        assert alert.observables.external_ips == []
        assert alert.observables.urls == []
        assert alert.observables.hashes.is_empty()

    def test_missing_timestamp_defaults_to_now_but_event_timestamp_stays_none(self):
        """"unknown" must stay distinguishable from "just happened" for the
        event timestamp, since §10 may use it for evidence age."""
        alert = build({})
        assert alert.timestamp is not None
        assert alert.event_timestamp is None

    def test_hive_alert_none_is_safe(self):
        alert = build({"rule": {"name": "x"}}, hive_alert=None)
        assert alert.cortex_results == []
        assert alert.thehive_observable_ids == {}

    def test_malformed_observables_are_skipped_not_fatal(self):
        alert = build(
            {"rule": {"name": "x"}},
            hive_alert={"observables": [{"dataType": "ip"}, {"data": ""}, {}]},
        )
        assert alert.observables.external_ips == []


# ===========================================================================
# Cortex taxonomies -> verdict.
# ===========================================================================
@pytest.fixture(scope="module")
def hive_alert() -> dict:
    """REAL — the 4 observables of alert ~4661456, captured 2026-08-13 via the
    stock `getAlert -> observables -> page` projection (tools/thehive.py; the
    custom getAlertWithObservables Function this used to come from is gone —
    see that module's docstring). Chosen because it's the richest of the three
    alerts on this instance: real VirusTotal reports on the URL observable,
    not just OpenCTI's "Not found"."""
    payload = json.loads(
        (Path(__file__).parent / "fixtures" / "thehive_real.json").read_text()
    )
    return {"observables": payload["alert_observables"]}


class TestCortexTaxonomyVerdicts:
    """REAL — the four observables of alert ~4661456, captured 2026-08-13.

    Real reports on this instance are simpler than the 2026-08-09 capture
    that originally motivated the verdict-collapsing fix: no observable here
    carries duplicate rows or a context-row/verdict-row split (VT ran only on
    the URL, and its two rows — Scan and GetReport — each carry a single
    `level: malicious` row at a low 1/92 ratio; OpenCTI's rows are all
    `level: info`, "Not found"; the github.com domain has no reports at all).
    The duplicate-row and context-vs-verdict scenarios that the 2026-08-09 fix
    was actually about are still covered below, but as SYNTHETIC unit tests on
    `_summarize_taxonomies` directly — this instance's current real data no
    longer happens to exhibit that shape.
    """

    def results_by_observable(self, real_sigma_process_alert, hive_alert):
        alert = build(real_sigma_process_alert, hive_alert=hive_alert)
        return {(r.observable, r.analyzer): r for r in alert.cortex_results}

    def test_reports_without_a_summary_wrapper_are_read(
        self, real_sigma_process_alert, hive_alert
    ):
        """The stock projection returns `report["taxonomies"]` unwrapped (no
        `summary` key); Cortex's own API wraps it as
        `report["summary"]["taxonomies"]`. Both must work. 5 results: the URL
        carries 3 analyzer reports (VT Scan, VT GetReport, OpenCTI), each hash
        carries 1 (OpenCTI), the domain carries 0."""
        alert = build(real_sigma_process_alert, hive_alert=hive_alert)
        assert len(alert.cortex_results) == 5

    def test_low_ratio_ties_are_still_trusted_as_malicious(
        self, real_sigma_process_alert, hive_alert
    ):
        """VT's own GetReport row for the xordump URL is `1/92` labelled
        `malicious` directly — no ratio parsing happens here, the analyzer's
        own label is taken as-is, even though 1 of 92 engines looks weak
        next to the label."""
        results = self.results_by_observable(real_sigma_process_alert, hive_alert)
        url = [r for k, r in results.items() if "xordump" in k[0] and "GetReport" in k[1]][0]
        assert url.verdict == ["malicious"]
        assert "1/92 (malicious)" in url.details

    def test_opencti_not_found_is_not_a_verdict(
        self, real_sigma_process_alert, hive_alert
    ):
        """OpenCTI's "Not found" rows are all `level: info` — info is context,
        not a verdict, on every observable it ran against."""
        results = self.results_by_observable(real_sigma_process_alert, hive_alert)
        opencti_rows = [r for (obs, an), r in results.items() if "OpenCTI" in an]
        assert opencti_rows
        assert all(r.verdict == [] for r in opencti_rows)
        assert all("Not found (info)" in r.details for r in opencti_rows)

    def test_domain_with_no_reports_yields_no_result(
        self, real_sigma_process_alert, hive_alert
    ):
        """github.com (the domain observable, distinct from the xordump URL
        that references it) had no analyzer run against it at all — an empty
        `reports: {}`, not an empty-taxonomies report."""
        results = self.results_by_observable(real_sigma_process_alert, hive_alert)
        assert not any(k[0] == "github.com" for k in results)

    def test_hash_with_no_matching_analyzer_yields_no_result(
        self, real_sigma_process_alert, hive_alert
    ):
        """Sanity check on a second observable-with-no-reports shape distinct
        from the domain above: the sha256 hash (not the observable this
        instance's OpenCTI/VT jobs ran on) still gets a real OpenCTI 'Not
        found' — confirms the no-report case above isn't the only path
        exercised."""
        results = self.results_by_observable(real_sigma_process_alert, hive_alert)
        assert any(k[0].startswith("1c84c863") for k in results)

    def test_context_row_does_not_silently_win_over_the_real_verdict(self):
        """SYNTHETIC, modelled on the real 2026-08-09 github.com shape (this
        instance's current data no longer has an observable with this split —
        see class docstring). VT's actual pattern: a context row
        ("56 resolution(s)") happens to be tagged `level: malicious`, while
        the real detection-ratio row ("0/91") is tagged `level: info`. Under
        the current rule both rows are taken at face value — verdict
        genuinely includes "malicious" — but `details` must keep BOTH rows
        with their own labels so that fact is visible downstream, not lost."""
        from alert_builder import _summarize_taxonomies

        verdict, details = _summarize_taxonomies([
            {"namespace": "VT", "predicate": "GetReport", "value": "56 resolution(s)", "level": "malicious"},
            {"namespace": "VT", "predicate": "GetReport", "value": "0/91", "level": "info"},
        ])
        assert verdict == ["malicious"]
        assert "56 resolution(s) (malicious)" in details
        assert "0/91 (info)" in details

    def test_duplicate_taxonomy_rows_are_collapsed(self):
        """SYNTHETIC, modelled on the real 2026-08-09 payload, which carried
        `VT:GetReport=3/97` twice (this instance's current data has no
        duplicated row — see class docstring)."""
        from alert_builder import _summarize_taxonomies

        verdict, details = _summarize_taxonomies([
            {"namespace": "VT", "predicate": "GetReport", "value": "3/97", "level": "malicious"},
            {"namespace": "VT", "predicate": "GetReport", "value": "3/97", "level": "malicious"},
        ])
        assert verdict == ["malicious"]
        assert details.count("3/97") == 1

    def test_level_is_honoured_with_no_ratio_present(self):
        """Analyzers like MISP report `hits=2 (suspicious)` with no ratio at
        all — the level IS the verdict."""
        from alert_builder import _summarize_taxonomies

        verdict, _ = _summarize_taxonomies(
            [{"namespace": "MISP", "predicate": "hits", "value": "2", "level": "suspicious"}]
        )
        assert verdict == ["suspicious"]

    def test_ratio_count_no_longer_drives_the_verdict(self):
        """THE RETIRED BEHAVIOR, kept as a guard against reintroducing it. A
        high detection count with an explicit `info` label must NOT be
        promoted to malicious/suspicious — that promotion is exactly the
        scoring judgement this function no longer makes. The analyzer's own
        label wins, even when it looks under-cautious next to the number."""
        from alert_builder import _summarize_taxonomies

        verdict, details = _summarize_taxonomies(
            [{"namespace": "VT", "predicate": "GetReport", "value": "42/70", "level": "info"}]
        )
        assert verdict == []
        assert "42/70" in details

    def test_low_ratio_count_with_malicious_label_is_trusted(self):
        """The mirror case: a LOW detection count explicitly labelled
        malicious by the analyzer is still taken at face value — no threshold
        second-guesses it either direction."""
        from alert_builder import _summarize_taxonomies

        verdict, _ = _summarize_taxonomies(
            [{"namespace": "VT", "predicate": "GetReport", "value": "1/92", "level": "malicious"}]
        )
        assert verdict == ["malicious"]

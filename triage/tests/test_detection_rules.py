"""`detection_rule_lookup` — architecture §6 tool 2.

PROVENANCE: `tests/fixtures/so_detection_5e3cc4d8.json` is the ACTUAL captured
response from the live `so-detection` index on 2026-08-08 for rule
`5e3cc4d8-3e68-43db-8656-eaaeefdec9cc`, saved verbatim per implementation guide
§2 step 6 — not an imagined shape. The tool was called against the real backend
before any of these tests were written.

`_parse_suricata_content` (added 2026-08-18) IS verified against real rules —
`TestSuricataMetadataParsing` below reads `so_detection_2100498.json` and
`so_detection_suricata_mitre_real.json`, both real captures. YARA is still
synthetic-only: confirmed live 2026-08-18 that 0 of 4,321 real YARA rule
bodies in this deployment contain any MITRE reference, and no `strelka.*`
alert index exists, so there's neither data to extract nor an alert path to
verify a parser against (see `tools/detection_rules.py`'s module docstring).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from schemas import RuleContext
from tools import detection_rules
from tools.detection_rules import (
    _normalise_sigma_tags,
    _parse_sigma_content,
    _parse_suricata_content,
    detection_rule_lookup,
)

FIXTURE = Path(__file__).parent / "fixtures" / "so_detection_5e3cc4d8.json"
REAL_UUID = "5e3cc4d8-3e68-43db-8656-eaaeefdec9cc"

SURICATA_FIXTURE = Path(__file__).parent / "fixtures" / "so_detection_2100498.json"
SURICATA_MITRE_FIXTURE = (
    Path(__file__).parent / "fixtures" / "so_detection_suricata_mitre_real.json"
)


@pytest.fixture
def real_es_response() -> dict:
    """REAL — captured live from so-detection on 2026-08-08."""
    return json.loads(FIXTURE.read_text())


@pytest.fixture
def real_suricata_es_response() -> dict:
    """REAL — captured live from so-detection on 2026-08-18, SID 2100498 (the
    rule tied to `tests/fixtures/suricata-alert-real.json`). Has a `metadata:`
    clause but no MITRE keys — the common case: 34,976 of 67,434 real
    Suricata rules (52%) carry no ATT&CK mapping at all."""
    return json.loads(SURICATA_FIXTURE.read_text())


@pytest.fixture
def real_suricata_mitre_es_response() -> dict:
    """REAL — captured live from so-detection on 2026-08-18, SID 2001482, one
    of the 32,458 real Suricata rules (48%) that DO carry a parseable
    `mitre_tactic_id`/`mitre_technique_id` metadata clause."""
    return json.loads(SURICATA_MITRE_FIXTURE.read_text())


def patch_es(monkeypatch, result=None, exc=None, capture=None):
    """Replace the ES transport. The tool's own logic is what's under test."""

    async def fake_es_search(index, body, timeout):
        if capture is not None:
            capture.update({"index": index, "body": body, "timeout": timeout})
        if exc is not None:
            raise exc
        return result

    monkeypatch.setattr(detection_rules, "es_search", fake_es_search)


def run(coro):
    return asyncio.run(coro)


# ===========================================================================
# REAL captured response
# ===========================================================================
class TestAgainstRealCapturedResponse:
    def test_no_gap_and_found(self, monkeypatch, real_es_response):
        patch_es(monkeypatch, result=real_es_response)
        context, gap = run(detection_rule_lookup(REAL_UUID))
        assert gap is None
        assert context.found is True
        assert context.rule_uuid == REAL_UUID

    def test_source_engine_from_language_not_engine(self, monkeypatch, real_es_response):
        """The document carries language="sigma" AND engine="elastalert".
        Reading `engine` would send every rule down the wrong parse branch."""
        patch_es(monkeypatch, result=real_es_response)
        context, _ = run(detection_rule_lookup(REAL_UUID))
        assert context.source_engine == "sigma"
        assert context.execution_engine == "elastalert"

    def test_mitre_parsed_from_content_yaml_and_normalised(
        self, monkeypatch, real_es_response
    ):
        """Doc-level `tags` is null on this rule — MITRE exists only inside the
        `content` Sigma YAML as `attack.t1105` / `attack.command-and-control`.
        If this returns empty, the compiled-rule trap has been reintroduced."""
        assert real_es_response["hits"]["hits"][0]["_source"]["so_detection"]["tags"] is None
        patch_es(monkeypatch, result=real_es_response)
        context, _ = run(detection_rule_lookup(REAL_UUID))
        assert context.mitre_attack == ["T1105"]
        assert context.mitre_tactics == ["command-and-control"]

    def test_falsepositive_placeholder_yields_false_boolean(
        self, monkeypatch, real_es_response
    ):
        """Raw list is preserved for audit; the derived boolean is what Stage 3
        reads, so it never reasons about an FP condition named "Unknown"."""
        patch_es(monkeypatch, result=real_es_response)
        context, _ = run(detection_rule_lookup(REAL_UUID))
        assert context.falsepositives == ["Unknown"]
        assert context.has_known_falsepositives is False

    def test_severity_and_level_both_captured(self, monkeypatch, real_es_response):
        patch_es(monkeypatch, result=real_es_response)
        context, _ = run(detection_rule_lookup(REAL_UUID))
        assert context.severity == "high"  # so-detection doc field
        assert context.level == "high"  # Sigma YAML field

    def test_sigma_status_captured_with_derived_boolean(self, monkeypatch, real_es_response):
        """Rule maturity — a day-one FP signal, available on the very first
        alert, unlike get_fp_signal which starts empty. Raw string kept for
        audit, derived boolean is what downstream reads (same pattern as
        has_known_falsepositives)."""
        patch_es(monkeypatch, result=real_es_response)
        context, _ = run(detection_rule_lookup(REAL_UUID))
        assert context.status == "test"
        assert context.has_reliable_status is False

    def test_logsource_from_yaml(self, monkeypatch, real_es_response):
        patch_es(monkeypatch, result=real_es_response)
        context, _ = run(detection_rule_lookup(REAL_UUID))
        assert context.logsource.category == "process_creation"
        assert context.logsource.product == "windows"

    def test_operational_metadata(self, monkeypatch, real_es_response):
        patch_es(monkeypatch, result=real_es_response)
        context, _ = run(detection_rule_lookup(REAL_UUID))
        assert context.is_enabled is True
        assert context.is_reporting is False
        assert context.is_community is True
        assert context.ruleset == "all_rules"
        assert context.author.startswith("Nasreddine")
        assert len(context.references) == 1

    def test_no_content_parse_error(self, monkeypatch, real_es_response):
        patch_es(monkeypatch, result=real_es_response)
        context, _ = run(detection_rule_lookup(REAL_UUID))
        assert context.content_parse_error is None


# ===========================================================================
# The query itself
# ===========================================================================
class TestQueryConstruction:
    def test_index_is_pinned_not_wildcarded(self, monkeypatch, real_es_response):
        """`so-detection*` also matches so-detectionhistory (345,474 revision
        docs). A wildcard here can return a superseded rule version."""
        capture: dict = {}
        patch_es(monkeypatch, result=real_es_response, capture=capture)
        run(detection_rule_lookup(REAL_UUID))
        assert capture["index"] == "so-detection"
        assert "*" not in capture["index"]

    def test_exact_term_query_on_publicid(self, monkeypatch, real_es_response):
        capture: dict = {}
        patch_es(monkeypatch, result=real_es_response, capture=capture)
        run(detection_rule_lookup(REAL_UUID))
        assert capture["body"]["query"] == {"term": {"so_detection.publicId": REAL_UUID}}
        assert capture["body"]["size"] == 1

    def test_timeout_is_passed_through(self, monkeypatch, real_es_response):
        capture: dict = {}
        patch_es(monkeypatch, result=real_es_response, capture=capture)
        run(detection_rule_lookup(REAL_UUID, timeout=1.5))
        assert capture["timeout"] == 1.5


# ===========================================================================
# Failure paths — a tool must produce a Gap, never an exception
# ===========================================================================
class TestFailuresProduceGapsNotExceptions:
    def test_connection_error(self, monkeypatch):
        patch_es(monkeypatch, exc=httpx.ConnectError("connection refused"))
        context, gap = run(detection_rule_lookup(REAL_UUID))
        assert context.found is False
        assert gap is not None
        assert gap.tool == "detection_rule_lookup"
        assert "Cannot connect to Elasticsearch" in gap.reason
        assert gap.reason != "unknown"

    def test_http_error_includes_status_and_body(self, monkeypatch):
        response = httpx.Response(
            403, text="access denied", request=httpx.Request("POST", "https://es/_search")
        )
        patch_es(
            monkeypatch,
            exc=httpx.HTTPStatusError("boom", request=response.request, response=response),
        )
        _, gap = run(detection_rule_lookup(REAL_UUID))
        assert "HTTP 403" in gap.reason
        assert "access denied" in gap.reason

    def test_timeout_produces_gap(self, monkeypatch):
        async def slow(index, body, timeout):
            await asyncio.sleep(5)

        monkeypatch.setattr(detection_rules, "es_search", slow)
        context, gap = run(detection_rule_lookup(REAL_UUID, timeout=0.05))
        assert context.found is False
        assert "Timeout after 0.05s" in gap.reason
        assert gap.duration_ms is not None

    def test_rule_absent_is_a_valid_result_distinguishable_from_failure(self, monkeypatch):
        """A rule can legitimately not be in the index. The Gap reason must say
        so rather than implying the backend broke."""
        patch_es(monkeypatch, result={"hits": {"hits": []}})
        context, gap = run(detection_rule_lookup(REAL_UUID))
        assert context.found is False
        assert context.rule_uuid == REAL_UUID
        assert "No document in so-detection" in gap.reason
        assert "timeout" not in gap.reason.lower()

    def test_empty_uuid_short_circuits(self, monkeypatch):
        called = {"n": 0}

        async def should_not_run(index, body, timeout):
            called["n"] += 1
            return {}

        monkeypatch.setattr(detection_rules, "es_search", should_not_run)
        context, gap = run(detection_rule_lookup(""))
        assert context.found is False
        assert "No rule uuid" in gap.reason
        assert called["n"] == 0

    def test_unexpected_document_shape(self, monkeypatch):
        patch_es(monkeypatch, result={"hits": {"hits": [{"_source": {"wrong": 1}}]}})
        context, gap = run(detection_rule_lookup(REAL_UUID))
        assert context.found is False
        assert "unexpected document shape" in gap.reason

    def test_malformed_yaml_degrades_without_losing_doc_fields(self, monkeypatch):
        """A content parse failure must not lose title/severity — architecture
        §6 says MITRE falls back to Qdrant, the rule stays usable."""
        patch_es(
            monkeypatch,
            result={
                "hits": {
                    "hits": [
                        {
                            "_source": {
                                "so_detection": {
                                    "publicId": REAL_UUID,
                                    "title": "Broken Rule",
                                    "severity": "high",
                                    "language": "sigma",
                                    "content": "tags:\n  - [unclosed",
                                }
                            }
                        }
                    ]
                }
            },
        )
        context, gap = run(detection_rule_lookup(REAL_UUID))
        assert gap is None
        assert context.found is True
        assert context.title == "Broken Rule"
        assert context.severity == "high"
        assert context.mitre_attack == []
        assert "YAML parse failed" in context.content_parse_error

    def test_missing_content_is_recorded(self, monkeypatch):
        patch_es(
            monkeypatch,
            result={
                "hits": {
                    "hits": [
                        {"_source": {"so_detection": {"publicId": REAL_UUID, "title": "X"}}}
                    ]
                }
            },
        )
        context, _ = run(detection_rule_lookup(REAL_UUID))
        assert context.found is True
        assert context.content_parse_error == "so_detection.content was empty or absent"


# ===========================================================================
# Sigma tag normalisation
# ===========================================================================
class TestSigmaTagNormalisation:
    def test_techniques_and_subtechniques_upper_cased(self):
        buckets = _normalise_sigma_tags(["attack.t1105", "attack.t1059.001"])
        assert buckets["techniques"] == ["T1105", "T1059.001"]

    def test_tactics_keep_attack_shortname_form(self):
        buckets = _normalise_sigma_tags(["attack.command-and-control", "attack.execution"])
        assert buckets["tactics"] == ["command-and-control", "execution"]

    def test_groups_and_software_separated_from_tactics(self):
        """`attack.g0016` is a group and `attack.s0002` is software. Neither is
        a tactic, and lumping them in would pollute the tactic list."""
        buckets = _normalise_sigma_tags(["attack.g0016", "attack.s0002", "attack.execution"])
        assert buckets["groups"] == ["G0016"]
        assert buckets["software"] == ["S0002"]
        assert buckets["tactics"] == ["execution"]

    def test_non_attack_namespaces_land_in_other(self):
        buckets = _normalise_sigma_tags(["cve.2021-44228", "car.2013-05-002", "tlp.white"])
        assert buckets["other"] == ["cve.2021-44228", "car.2013-05-002", "tlp.white"]
        assert buckets["techniques"] == []

    def test_deduplicated_preserving_order(self):
        buckets = _normalise_sigma_tags(["attack.t1105", "attack.t1105", "attack.t1059"])
        assert buckets["techniques"] == ["T1105", "T1059"]

    def test_junk_does_not_raise(self):
        buckets = _normalise_sigma_tags([None, 42, "", "   ", "attack.", "attack"])
        assert buckets["techniques"] == []
        assert "attack" in buckets["other"]

    def test_scalar_falsepositives_string_accepted(self):
        """Sigma authors routinely write `falsepositives: Unknown` as a scalar
        rather than a list."""
        context = RuleContext()
        _parse_sigma_content("falsepositives: Unknown\nlevel: low\n", context)
        assert context.falsepositives == ["Unknown"]
        assert context.has_known_falsepositives is False

    def test_real_falsepositive_sets_boolean_true(self):
        context = RuleContext()
        _parse_sigma_content(
            "falsepositives:\n  - Software update scripts\n  - Unknown\n", context
        )
        assert context.has_known_falsepositives is True

    @pytest.mark.parametrize(
        "status,expected",
        [
            ("stable", True),
            ("Stable", True),  # Sigma authors are inconsistent about case
            ("test", False),
            ("experimental", False),
            ("deprecated", False),
            ("unsupported", False),
            (None, False),  # absence of a maturity claim is not a maturity claim
        ],
    )
    def test_has_reliable_status_only_true_for_stable(self, status, expected):
        context = RuleContext()
        content = f"status: {status}\n" if status else "level: high\n"
        _parse_sigma_content(content, context)
        assert context.has_reliable_status is expected

    def test_yaml_cannot_construct_python_objects(self):
        """safe_load only — rule content comes from a community ruleset."""
        context = RuleContext()
        _parse_sigma_content("!!python/object/apply:os.system ['echo pwned']", context)
        assert context.content_parse_error is not None
        assert context.mitre_attack == []


# ===========================================================================
# Non-Sigma languages — SYNTHETIC, no such rule exists in this deployment
# ===========================================================================
class TestSyntheticNonSigmaLanguages:
    # This one case remains synthetic on purpose: a Suricata rule with NO
    # `metadata:` clause at all (real coverage for the two shapes that DO
    # have one — with and without MITRE keys — lives in
    # TestSuricataMetadataParsing / TestAgainstRealSuricataResponse below).
    def test_suricata_rule_keeps_doc_fields_without_yaml_mitre(self, monkeypatch):
        patch_es(
            monkeypatch,
            result={
                "hits": {
                    "hits": [
                        {
                            "_source": {
                                "so_detection": {
                                    "publicId": "2027001",
                                    "title": "ET MALWARE Observed DNS Query",
                                    "severity": "high",
                                    "language": "suricata",
                                    "engine": "suricata",
                                    "content": 'alert dns any any -> any any (msg:"ET MALWARE"; sid:2027001;)',
                                }
                            }
                        }
                    ]
                }
            },
        )
        context, gap = run(detection_rule_lookup("2027001"))
        assert gap is None
        assert context.found is True
        assert context.source_engine == "suricata"
        assert context.title == "ET MALWARE Observed DNS Query"
        # A Suricata signature is not YAML; MITRE stays empty and Stage 2's
        # Qdrant retrieval is the fallback, per architecture §6.
        assert context.mitre_attack == []

    # NOTE: YARA path — unit-tested against a synthetic document only, same
    # reason as above (implementation guide §0.1).
    def test_yara_rule_keeps_doc_fields(self, monkeypatch):
        patch_es(
            monkeypatch,
            result={
                "hits": {
                    "hits": [
                        {
                            "_source": {
                                "so_detection": {
                                    "publicId": "MALWARE_Win_Generic",
                                    "title": "MALWARE_Win_Generic",
                                    "language": "yara",
                                    "content": "rule MALWARE_Win_Generic { condition: true }",
                                }
                            }
                        }
                    ]
                }
            },
        )
        context, gap = run(detection_rule_lookup("MALWARE_Win_Generic"))
        assert gap is None
        assert context.source_engine == "yara"
        assert context.mitre_attack == []


# ===========================================================================
# `_parse_suricata_content` — direct unit tests against REAL rule text
# ===========================================================================
class TestSuricataMetadataParsing:
    """Live-verified 2026-08-18 against 5 real Suricata rules (SIDs 2001482,
    2001485, 2001734, 2002016, 2016781) plus the rule tied to the real
    captured alert (SID 2100498). Content strings below are copied verbatim
    from those live `so-detection` responses, not reconstructed by hand."""

    REAL_2100498 = (
        'alert ip any any -> any any (msg:"GPL ATTACK_RESPONSE id check returned root"; '
        'content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:2100498; rev:7; '
        "metadata:created_at 2010_09_23, confidence Medium, "
        "signature_severity Informational, updated_at 2019_07_26;)"
    )
    REAL_2001482 = (
        'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ADWARE_PUP '
        'thebestsoft4u.com Spyware Install (1)"; flow:established,to_server; '
        'http.uri; content:"/pa/glx.exe"; nocase; classtype:pup-activity; '
        "sid:2001482; rev:10; metadata:attack_target Client_Endpoint, "
        "created_at 2010_07_30, deployment Perimeter, signature_severity Minor, "
        "updated_at 2024_03_15, mitre_tactic_id TA0009, mitre_tactic_name Collection, "
        "mitre_technique_id T1005, mitre_technique_name Data_from_local_system;)"
    )
    REAL_2016781 = (
        'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET EXPLOIT_KIT Sakura '
        'obfuscated javascript Apr 21 2013"; flow:established,to_client; '
        "flowbits:set,et.exploitkitlanding; file.data; "
        'content:"OD&|3a|x9T6"; classtype:exploit-kit; sid:2016781; rev:4; '
        "metadata:created_at 2013_04_23, signature_severity Major, "
        "updated_at 2024_03_14, mitre_tactic_id TA0005, "
        "mitre_tactic_name Defense_Evasion, mitre_technique_id T1027, "
        "mitre_technique_name Obfuscated_Files_or_Information;)"
    )

    def test_real_rule_with_no_mitre_keeps_metadata_it_does_have(self):
        """SID 2100498 — a metadata: clause exists but carries no MITRE keys,
        the common real case (52% of Suricata rules). Must not be confused
        with content_parse_error, which means the clause itself is missing."""
        context = RuleContext()
        _parse_suricata_content(self.REAL_2100498, context)
        assert context.content_parse_error is None
        assert context.mitre_attack == []
        assert context.mitre_tactics == []
        assert context.level == "informational"
        assert "created_at:2010_09_23" in context.other_tags
        assert "confidence:Medium" in context.other_tags

    def test_real_rule_with_mitre_extracts_technique_and_tactic(self):
        """SID 2001482 — mitre_technique_id feeds mitre_attack (same list
        Sigma populates); mitre_tactic_name normalises to ATT&CK's own
        hyphenated-lowercase shortname, matching Sigma's convention."""
        context = RuleContext()
        _parse_suricata_content(self.REAL_2001482, context)
        assert context.mitre_attack == ["T1005"]
        assert context.mitre_tactics == ["collection"]
        assert context.level == "low"  # signature_severity Minor -> low
        assert "mitre_tactic_id:TA0009" in context.other_tags
        assert "mitre_technique_name:Data_from_local_system" in context.other_tags
        assert "attack_target:Client_Endpoint" in context.other_tags

    def test_underscored_tactic_name_normalises_to_attack_shortname(self):
        """SID 2016781 — `Defense_Evasion` must become `defense-evasion`,
        ATT&CK's real shortname, matching what Sigma's own tactic tags use so
        Stage 2/3 never has to special-case which engine a tactic came from."""
        context = RuleContext()
        _parse_suricata_content(self.REAL_2016781, context)
        assert context.mitre_attack == ["T1027"]
        assert context.mitre_tactics == ["defense-evasion"]
        assert context.level == "high"  # signature_severity Major -> high

    def test_no_metadata_clause_sets_parse_error_not_exception(self):
        context = RuleContext()
        _parse_suricata_content('alert tcp any any -> any any (msg:"x"; sid:1; rev:1;)', context)
        assert context.content_parse_error == "No metadata: clause found in Suricata rule text"
        assert context.mitre_attack == []

    def test_level_not_overridden_if_already_set(self):
        """Mirrors `_parse_sigma_content`'s `parsed.get("level") or
        context.level` precedence — content-derived severity should not
        clobber a level a caller already set."""
        context = RuleContext(level="critical")
        _parse_suricata_content(self.REAL_2100498, context)
        assert context.level == "critical"

    @pytest.mark.parametrize(
        "suricata_value,expected_level",
        [
            ("Informational", "informational"),
            ("Minor", "low"),
            ("Major", "high"),
            ("Critical", "critical"),
        ],
    )
    def test_severity_map_covers_all_four_real_values(self, suricata_value, expected_level):
        """These 4 values cover 67,064 of 67,434 real Suricata rules with a
        signature_severity key — confirmed live 2026-08-18."""
        context = RuleContext()
        content = f'alert tcp any any -> any any (msg:"x"; sid:1; rev:1; metadata:signature_severity {suricata_value};)'
        _parse_suricata_content(content, context)
        assert context.level == expected_level


# ===========================================================================
# `detection_rule_lookup` end-to-end against REAL Suricata so-detection docs
# ===========================================================================
class TestAgainstRealSuricataResponse:
    def test_no_mitre_rule_end_to_end(self, monkeypatch, real_suricata_es_response):
        patch_es(monkeypatch, result=real_suricata_es_response)
        context, gap = run(detection_rule_lookup("2100498"))
        assert gap is None
        assert context.found is True
        assert context.source_engine == "suricata"
        assert context.execution_engine == "suricata"
        assert context.title == "GPL ATTACK_RESPONSE id check returned root"
        assert context.mitre_attack == []
        assert context.level == "informational"
        assert context.content_parse_error is None

    def test_mitre_rule_end_to_end(self, monkeypatch, real_suricata_mitre_es_response):
        patch_es(monkeypatch, result=real_suricata_mitre_es_response)
        context, gap = run(detection_rule_lookup("2001482"))
        assert gap is None
        assert context.found is True
        assert context.mitre_attack == ["T1005"]
        assert context.mitre_tactics == ["collection"]
        assert context.level == "low"

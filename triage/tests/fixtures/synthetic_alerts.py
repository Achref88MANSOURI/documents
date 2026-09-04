"""Synthetic raw-alert fixtures for dataset shapes with no captured live alert.

READ THIS BEFORE TRUSTING ANY TEST THAT USES THESE.

Every fixture in this module is SYNTHETIC. Field paths are transcribed from
`ingest-templates.txt` (the live `logs-detections.alerts-so/_mapping` dump) and
from `so-alert-reference/`'s ingest pipelines — sources that prove a field *can
exist*, never that a real alert of this shape *was observed*. No alert of any
shape below has been captured from this deployment.

A green test against these fixtures proves exactly one thing: the extractor does
not crash and maps the field paths as written. It does NOT prove the shape is
what Security Onion actually emits. Per implementation guide §0.1, that can only
be established once the relevant sensor or telemetry path is live.

The one REAL fixture lives in `sigma-alert-sample.json` at the repo root and
covers `endpoint.events.process` only. It is loaded by `conftest.py`, not here.

These are Python rather than JSON files on purpose: the provenance labelling
above and per-fixture below is the most important content in this file, and JSON
cannot carry it.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# SYNTHETIC — endpoint.events.file
# Field paths from ingest-templates.txt event_data.file.* (42 leaves).
# No real endpoint.events.file alert exists yet to validate against.
# ---------------------------------------------------------------------------
ENDPOINT_FILE_ALERT = {
    "@timestamp": "2026-07-22T09:10:00Z",
    "sigma_level": "medium",
    "rule": {
        "name": "Suspicious File Written To Startup Folder",
        "uuid": "aaaaaaaa-1111-2222-3333-444444444444",
        "product": "windows",
        "category": "file_event",
    },
    "event": {"severity": 3, "module": "sigma", "severity_label": "medium"},
    "event_data": {
        "@timestamp": "2026-07-22T09:09:12.100000Z",
        "event": {"dataset": "endpoint.events.file", "module": "endpoint", "risk_score": 47},
        "host": {"name": "win-kvkmd51ggkq", "id": "c8fc26bf", "os": {"type": "windows"}},
        "user": {"name": "Administrator", "id": "S-1-5-21-500"},
        "file": {
            "name": "payload.exe",
            "path": "C:\\Users\\Administrator\\Start Menu\\Programs\\Startup\\payload.exe",
            "directory": "C:\\Users\\Administrator\\Start Menu\\Programs\\Startup",
            "extension": "exe",
            "owner": "Administrator",
            "size": 184320,
            "hash": {"sha256": "d3adb33f" * 8},
            "code_signature": {"exists": False},
            "Ext": {
                "quarantine_result": True,
                "malware_classification": {
                    "identifier": "endpointpe",
                    "score": 0.97,
                    "threshold": 0.66,
                },
                "malware_signature": {
                    "identifier": "sig-12345",
                    "primary": {
                        "matches": ["packer.upx", "susp.startup_persist"],
                        "signature": {"id": "SIG-2024-0099", "name": "Windows.Trojan.Generic"},
                    },
                },
            },
        },
    },
}

# ---------------------------------------------------------------------------
# SYNTHETIC — endpoint.events.library (module load)
# Field paths from ingest-templates.txt event_data.dll.* (18 leaves).
# No real endpoint.events.library alert exists yet to validate against.
# ---------------------------------------------------------------------------
ENDPOINT_LIBRARY_ALERT = {
    "@timestamp": "2026-07-22T09:20:00Z",
    "sigma_level": "high",
    "rule": {
        "name": "Unsigned Module Loaded Into LSASS",
        "uuid": "bbbbbbbb-1111-2222-3333-444444444444",
        "product": "windows",
        "category": "image_load",
    },
    "event": {"severity": 4, "module": "sigma", "severity_label": "high"},
    "event_data": {
        "@timestamp": "2026-07-22T09:19:40.000000Z",
        "event": {"dataset": "endpoint.events.library", "module": "endpoint"},
        "host": {"name": "win-kvkmd51ggkq", "os": {"type": "windows"}},
        "process": {"name": "lsass.exe", "pid": 704, "executable": "C:\\Windows\\System32\\lsass.exe"},
        "dll": {
            "name": "evil.dll",
            "path": "C:\\Windows\\Temp\\evil.dll",
            "hash": {"sha256": "beefcafe" * 8},
            "pe": {
                "imphash": "1122334455667788990011223344556677",
                "file_version": "1.0.0.1",
                "original_file_name": "evil.dll",
            },
            "code_signature": {"trusted": False, "exists": False, "status": "unsigned"},
            "Ext": {"size": 91136, "load_index": 42},
        },
    },
}

# ---------------------------------------------------------------------------
# SYNTHETIC — cross-process access (Sysmon EID 10 and kin)
# Field paths from ingest-templates.txt event_data.Target.process.* (5 leaves).
# Note the capital T — that is Elastic's own field name.
# No real alert carrying event_data.Target.* has been captured yet.
# ---------------------------------------------------------------------------
TARGET_PROCESS_ALERT = {
    "@timestamp": "2026-07-22T09:30:00Z",
    "sigma_level": "critical",
    "rule": {
        "name": "LSASS Memory Access",
        "uuid": "cccccccc-1111-2222-3333-444444444444",
        "product": "windows",
        "category": "process_access",
    },
    "event": {"severity": 5, "module": "sigma", "severity_label": "critical"},
    "event_data": {
        "@timestamp": "2026-07-22T09:29:55.000000Z",
        "event": {"dataset": "endpoint.events.api", "module": "endpoint"},
        "host": {"name": "win-kvkmd51ggkq", "os": {"type": "windows"}},
        "process": {
            "name": "rundll32.exe",
            "pid": 4444,
            "executable": "C:\\Windows\\System32\\rundll32.exe",
            "entity_id": "SOURCEENTITY",
            # SYNTHETIC — process.Ext.api.* per ingest-templates.txt. Types are
            # as mapped: address/size/desired_access_numeric are longs.
            "Ext": {
                "api": {
                    "name": "WriteProcessMemory",
                    "behaviors": ["cross-process", "shellcode", "hollowing"],
                    "metadata": {"target_address_name": "lsass.exe!ntdll"},
                    "parameters": {
                        "address": 140737488355328,
                        "size": 4096,
                        "desired_access": "PROCESS_VM_WRITE|PROCESS_VM_OPERATION",
                        "desired_access_numeric": 2097151,
                        "handle_type": "process",
                    },
                }
            },
        },
        "Target": {
            "process": {
                "name": "lsass.exe",
                "pid": 704,
                "executable": "C:\\Windows\\System32\\lsass.exe",
                "entity_id": "TARGETENTITY",
                "Ext": {"token": {"integrity_level_name": "system"}},
            }
        },
    },
}

# ---------------------------------------------------------------------------
# SYNTHETIC — ECS related.* entity roll-ups
# Field paths from ingest-templates.txt event_data.related.{ip,hash,user,hosts}.
# ---------------------------------------------------------------------------
RELATED_ENTITIES_ALERT = {
    "@timestamp": "2026-07-22T09:40:00Z",
    "rule": {"name": "Related Rollup Probe", "uuid": "dddddddd-1111-2222-3333-444444444444"},
    "event": {"severity": 3, "module": "sigma"},
    "event_data": {
        "event": {"dataset": "endpoint.events.process"},
        "host": {"name": "win-kvkmd51ggkq"},
        "process": {"name": "cmd.exe", "pid": 1},
        "related": {
            "ip": ["10.1.2.3", "8.8.8.8"],
            "hash": ["a" * 64],
            "user": ["Administrator"],
            "hosts": ["win-kvkmd51ggkq"],
        },
    },
}

# ---------------------------------------------------------------------------
# SYNTHETIC — windows.sysmon_operational (native winlog channel)
# Field paths from ingest-templates.txt event_data.winlog.*.
# ---------------------------------------------------------------------------
SYSMON_WINLOG_ALERT = {
    "@timestamp": "2026-07-22T09:50:00Z",
    "sigma_level": "medium",
    "rule": {
        "name": "Sysmon Process Creation Anomaly",
        "uuid": "eeeeeeee-1111-2222-3333-444444444444",
        "product": "windows",
    },
    "event": {"severity": 3, "module": "sigma", "severity_label": "medium"},
    "event_data": {
        "@timestamp": "2026-07-22T09:49:30.000000Z",
        "event": {"dataset": "windows.sysmon_operational", "code": "1"},
        "winlog": {
            "computer_name": "win-kvkmd51ggkq",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_id": 1,
            "process": {"pid": 3312},
            "user": {"name": "SYSTEM", "identifier": "S-1-5-18", "domain": "NT AUTHORITY"},
        },
    },
}

# ---------------------------------------------------------------------------
# SYNTHETIC — PowerShell engine-lifecycle (winlog sub-shape)
# ---------------------------------------------------------------------------
POWERSHELL_ENGINE_ALERT = {
    "@timestamp": "2026-07-22T10:00:00Z",
    "rule": {"name": "PowerShell Engine Started", "uuid": "ffffffff-1111-2222-3333-444444444444"},
    "event": {"severity": 2, "module": "sigma"},
    "event_data": {
        "event": {"dataset": "windows.powershell_operational"},
        "winlog": {"computer_name": "win-kvkmd51ggkq"},
        "powershell": {
            "engine": {"new_state": "Available", "previous_state": "None", "version": "5.1.19041.1"},
            "process": {"executable_version": "5.1.19041.1"},
            "runspace_id": "11111111-2222-3333-4444-555555555555",
        },
    },
}

# ---------------------------------------------------------------------------
# SYNTHETIC — system.auth (Filebeat SSH auth log)
# ---------------------------------------------------------------------------
SSH_AUTH_ALERT = {
    "@timestamp": "2026-07-22T10:10:00Z",
    "rule": {"name": "SSH Login Accepted", "uuid": "00000000-1111-2222-3333-444444444444"},
    "event": {"severity": 2, "module": "sigma"},
    "event_data": {
        "event": {"dataset": "system.auth"},
        "system": {"auth": {"ssh": {"event": "Accepted", "method": "publickey"}}},
        "source": {"ip": "10.20.30.40", "port": 51234},
        "user": {"name": "root"},
    },
}

# ---------------------------------------------------------------------------
# SYNTHETIC — windows.sysmon_operational network_connection event (gap #5).
# No real Sysmon network_connection alert has been captured in this
# deployment yet — field path (event_data.network.community_id) taken from
# so-analysis/elasticsearch templates (tier 3), not a live document.
# ---------------------------------------------------------------------------
SSH_AUTH_ALERT_WITH_COMMUNITY_ID = {
    "@timestamp": "2026-07-22T10:10:00Z",
    "rule": {"name": "SSH Login Accepted", "uuid": "00000000-1111-2222-3333-444444444444"},
    "event": {"severity": 2, "module": "sigma"},
    "event_data": {
        "event": {"dataset": "system.auth"},
        "system": {"auth": {"ssh": {"event": "Accepted", "method": "publickey"}}},
        "source": {"ip": "10.20.30.40", "port": 51234},
        "user": {"name": "root"},
        "network": {"community_id": "1:synthetic-community-id-hash="},
    },
}

# ---------------------------------------------------------------------------
# SYNTHETIC — kratos.audit (HTTP identity-provider login flow)
# ---------------------------------------------------------------------------
KRATOS_LOGIN_FLOW_ALERT = {
    "@timestamp": "2026-07-22T10:20:00Z",
    "rule": {"name": "Repeated Failed Login Flow", "uuid": "99999999-1111-2222-3333-444444444444"},
    "event": {"severity": 3, "module": "sigma"},
    "event_data": {
        "event": {"dataset": "kratos.audit"},
        "http": {
            "method": "POST",
            "uri": "/self-service/login",
            "useragent": "Mozilla/5.0",
            "request": {"remote": "203.0.113.9:44321"},
        },
        "login_flow": {"type": "browser", "state": "choose_method", "active": "password"},
    },
}

# ---------------------------------------------------------------------------
# SYNTHETIC — Suricata network alert.
# A REAL Suricata alert fixture now exists (`tests/fixtures/
# suricata-alert-real.json`, `real_suricata_alert_source` in conftest.py) —
# see TestRealSuricataPath for the parts that fixture covers. This synthetic
# fixture remains for the parts it doesn't: a different rule/uuid (breadth
# across more than one Suricata rule), an IPv6 destination, and
# `network.initiated` — a field the live index mapping (ingest-templates.txt)
# confirms CAN appear on a Suricata alert, just not one the one real sample
# happens to have populated. `transport` was corrected 2026-08-18 to match
# real data: `"TCP"` (uppercase), not `"tcp"`.
# ---------------------------------------------------------------------------
SURICATA_ALERT = {
    "@timestamp": "2026-07-22T10:30:00Z",
    "rule": {"name": "ET MALWARE Observed DNS Query", "uuid": "2027001"},
    "event": {"severity": 4, "module": "suricata", "severity_label": "high"},
    "source": {"ip": "172.20.24.99", "port": 51515},
    "destination": {"ip": "185.53.178.50", "port": 443, "ipv6": None},
    "network": {"transport": "TCP", "initiated": True},
}

# ---------------------------------------------------------------------------
# SYNTHETIC — YARA/Strelka file alert.
# NOTE: YARA path — unit-tested against synthetic fixture only, no live SO alert
# exists yet to validate against (implementation guide §0.1). Hashes sit at a
# TOP-LEVEL `hash` sibling of `file`, not nested under it — per Security Onion's
# own strelka.file ingest pipeline in so-alert-reference/.
#
# entropy/pe_image_version/pe_flags/timestamps/mode/ssdeep (added 2026-08-19,
# gap #7) are ALSO synthetic — field paths from so-analysis/elasticsearch
# templates (TEMPLATE-SCHEMA-REFERENCE.md §5), not a live document. The
# Strelka sensor isn't enabled in this deployment (gap #13), so no real
# alert of this shape can exist yet to validate against.
# ---------------------------------------------------------------------------
YARA_STRELKA_ALERT = {
    "@timestamp": "2026-07-22T10:40:00Z",
    "rule": {"name": "MALWARE_Win_Generic", "uuid": "MALWARE_Win_Generic"},
    "event": {"severity": 4, "module": "strelka", "severity_label": "high"},
    "file": {
        "name": "invoice.doc.exe",
        "path": "/nsm/strelka/extracted/invoice.doc.exe",
        "size": 245760,
        "mime_type": "application/x-dosexec",
        "created": "2026-07-22T10:39:50Z",
        "accessed": "2026-07-22T10:39:55Z",
        "mtime": "2026-06-01T08:00:00Z",
        "ctime": "2026-06-01T08:00:00Z",
        "mode": "0755",
    },
    "hash": {"md5": "0" * 32, "sha256": "f" * 64, "ssdeep": "768:abc123:xyz789"},
    "scan": {
        "entropy": {"entropy": 7.89},
        "pe": {"image_version": "6.1", "flags": "DLL, EXECUTABLE_IMAGE"},
    },
}

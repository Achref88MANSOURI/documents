#!/usr/bin/env python3
"""
Ingests IR playbooks into the `triage_kb` Qdrant collection, under
collection="playbooks". This is what the agent's rag_tool queries to answer:
  - "Is there a runbook for this alert type?"
  - "What are the standard triage/containment steps for this category?"

Data source
-----------
Unlike MITRE ATT&CK (STIX feed) and CVE/KEV (CISA feed), there is no single
machine-readable public API for IR playbooks. This script instead ships a
curated seed set (PLAYBOOKS below) covering the alert categories a SOC
actually triages day to day, written in a consistent PICERL-derived shape:

    detection_and_scope  -> what confirms this is really happening
    immediate_triage     -> the analyst's first moves
    containment          -> how to limit blast radius
    eradication_recovery -> how to actually clean up / restore
    escalation_criteria  -> when this stops being an analyst-only call

Extending with your own org runbooks
-------------------------------------
Add entries to PLAYBOOKS in the same shape, or point --custom-dir at a
folder of markdown files structured like:

    # <title>
    category: <category_slug>
    mitre_techniques: T1078, T1110

    ## detection_and_scope
    ...
    ## immediate_triage
    ...
    ## containment
    ...
    ## eradication_recovery
    ...
    ## escalation_criteria
    ...

Logic recap (mirrors ingest_mitre_attack.py / ingest_cve_intel.py conventions):
  - One chunk per playbook PHASE (natural retrieval unit — an analyst asking
    "what's the containment step" shouldn't get the whole runbook back)
  - Point ID = UUID5 derived from "playbooks:<category>:<phase>" (deterministic,
    so re-running this script updates existing entries instead of duplicating them)
  - Same Qdrant collection (triage_kb) as the other sources, distinguished by
    payload["collection"] = "playbooks", per the rag_tool schema

Usage:
  python3 ingest_playbooks.py --dry-run                        # preview only
  python3 ingest_playbooks.py                                  # ingest the seed set
  python3 ingest_playbooks.py --custom-dir ./org_playbooks      # + your own markdown runbooks
"""

import argparse
import json
import re
import sys
import urllib.request
import uuid
from pathlib import Path

EMBED_URL = "http://localhost:8001/embed"
QDRANT_URL = "http://localhost:6333/collections/triage_kb/points"
BATCH_SIZE = 50

PHASE_ORDER = [
    "detection_and_scope",
    "immediate_triage",
    "containment",
    "eradication_recovery",
    "escalation_criteria",
]

# ---------------------------------------------------------------------------
# Seed playbooks. category slug should match / be mappable to the "category"
# field your policy_tool and detection rules already use.
# ---------------------------------------------------------------------------
PLAYBOOKS = [
    {
        "category": "valid_accounts_abuse",
        "title": "Valid Accounts / Credential Abuse",
        "mitre_techniques": ["T1078"],
        "phases": {
            "detection_and_scope": "Confirm the login or action used legitimate credentials rather than malware. Check source IP/geo/ASN against the account's normal baseline, time-of-day against normal working pattern, and whether MFA was satisfied, bypassed, or absent. Identify every session and resource touched under this identity since the anomaly began.",
            "immediate_triage": "Pull the account's recent auth history (successes and failures) across all systems, not just the alerting one. Check for concurrent impossible-travel sessions. Determine account privilege level and whether it is a service account, admin account, or standard user.",
            "containment": "If confidence is high, force logout of all active sessions and reset credentials. Disable the account only if abuse is confirmed, not on suspicion alone, since disabling a legitimate user's account is itself a business-impacting action. Revoke any OAuth tokens or API keys tied to the identity.",
            "eradication_recovery": "Rotate credentials and any secrets the account had access to. Re-enable with a fresh credential and mandatory MFA re-enrollment. Review and, if needed, tighten conditional access policies (geo-fencing, device compliance) that would have caught this earlier.",
            "escalation_criteria": "Escalate to human-required if the account is privileged (domain admin, cloud admin, service account with broad scope) or if lateral movement/data access is observed. Standard-user, single-session, low-privilege cases with clear benign explanation (VPN misconfig, travel) can stay analyst-level.",
        },
    },
    {
        "category": "phishing_initial_access",
        "title": "Phishing / Suspicious Email",
        "mitre_techniques": ["T1566", "T1204.002"],
        "phases": {
            "detection_and_scope": "Identify all recipients of the message via mail gateway logs, not just the reporting user. Determine if any recipient clicked the link, opened the attachment, or entered credentials on a landing page.",
            "immediate_triage": "Detonate the attachment/URL in a sandbox if not already scored by an analyzer. Check sender domain age, SPF/DKIM/DMARC results, and whether the domain or URL is newly registered.",
            "containment": "Purge the message from all mailboxes it reached (including unread copies). Block the sender domain and any URLs/hashes at the email gateway and proxy. If credentials were entered, treat as valid_accounts_abuse in parallel and force a reset.",
            "eradication_recovery": "Confirm no follow-on payload executed on any clicked endpoint (correlate with EDR). If a payload ran, escalate to malware_execution playbook for that host.",
            "escalation_criteria": "Escalate if any executive, finance, or IT-admin mailbox was targeted or if credential harvesting is confirmed for a privileged account. Single unclicked report with no engagement can be closed at analyst level.",
        },
    },
    {
        "category": "malware_execution",
        "title": "Malware / Suspicious Process Execution",
        "mitre_techniques": ["T1059", "T1204"],
        "phases": {
            "detection_and_scope": "Identify the parent process chain and how the binary/script arrived (download, email attachment, removable media, living-off-the-land binary). Check EDR/AV verdict and hash reputation.",
            "immediate_triage": "Determine what the process actually did: network connections made, files written, registry/persistence changes, child processes spawned. Check if it's a known commodity family or unclassified.",
            "containment": "Isolate the host from the network (EDR network containment) while preserving the process for forensic capture. Kill the process tree if isolation alone is insufficient to stop spread.",
            "eradication_recovery": "Remove persistence mechanisms, delete/quarantine the artifact, and re-image if rootkit-level or unclear scope. Restore from known-good backup if data was modified.",
            "escalation_criteria": "Escalate immediately if the host is a server, domain controller, or holds regulated data, or if the malware family is associated with ransomware precursors (loader/dropper for known ransomware). Isolated, low-privilege workstation with a known-benign or fully quarantined commodity sample can stay analyst-level.",
        },
    },
    {
        "category": "ransomware",
        "title": "Ransomware / Mass Encryption Activity",
        "mitre_techniques": ["T1486", "T1490"],
        "phases": {
            "detection_and_scope": "Identify the first host showing encryption behavior (mass file rename/modify events, shadow copy deletion) and every host/share reachable from it. Treat this as active until proven otherwise — do not wait for full confirmation before starting containment.",
            "immediate_triage": "Check for shadow copy / backup deletion commands (vssadmin, wbadmin) and for lateral movement in the hours prior. Identify the entry vector if visible (phishing, exposed RDP, exploited service).",
            "containment": "Network-isolate all affected and adjacent hosts immediately. Disable affected accounts. Pull the domain controller and backup infrastructure into a protected/segmented state if not already isolated from the affected segment.",
            "eradication_recovery": "Do not restore from backup until the entry vector and lateral movement path are understood, or the restored systems will be re-encrypted. Coordinate restoration with backup/DR team once scope is fully mapped.",
            "escalation_criteria": "Always human-required, regardless of confidence — this is a hard invariant, not a judgment call. Notify IR lead and, per org policy, legal/comms immediately.",
        },
    },
    {
        "category": "brute_force",
        "title": "Brute Force / Credential Stuffing",
        "mitre_techniques": ["T1110"],
        "phases": {
            "detection_and_scope": "Determine target scope: single account or spray across many accounts. Check source IP(s) for known malicious infrastructure and whether any attempt succeeded.",
            "immediate_triage": "If any attempt succeeded, immediately pivot to valid_accounts_abuse for that identity. Check whether the targeted service has account lockout / rate limiting enabled and whether it triggered.",
            "containment": "Block source IP(s) at the perimeter/WAF. If credential stuffing (many accounts, few attempts each), consider forcing a password reset for the targeted account population if a breach-list match is suspected.",
            "eradication_recovery": "Verify lockout/rate-limit policy is functioning as intended; if it isn't, that's a finding independent of this specific alert. No host-level eradication needed unless a login succeeded.",
            "escalation_criteria": "Escalate if any login succeeded on a privileged account, or if the source is part of a larger coordinated campaign (correlate via correlation_tool). Failed, low-volume, single-account attempts from non-malicious-flagged IPs can stay analyst-level.",
        },
    },
    {
        "category": "lateral_movement",
        "title": "Lateral Movement (RDP/SMB/WinRM/PsExec-style)",
        "mitre_techniques": ["T1021", "T1570"],
        "phases": {
            "detection_and_scope": "Map the full chain: source host, account used, destination host(s), protocol, and timestamp sequence. Check if the account and path are consistent with normal admin activity or IT tooling.",
            "immediate_triage": "Check destination host criticality and whether authentication succeeded. Look for accompanying tooling (PsExec, WMI, scheduled tasks) that indicates non-interactive/automated movement rather than a human admin session.",
            "containment": "Isolate the destination host if compromise indicators are present. Disable the account used for movement if it's clearly not the account owner's legitimate action.",
            "eradication_recovery": "Sweep for persistence on every hop in the chain, not just the final destination. Re-verify credentials used at each hop haven't been further reused elsewhere (use correlation_tool).",
            "escalation_criteria": "Escalate if the destination is a domain controller, backup server, or other critical asset, or if the chain spans three or more hosts. A single admin-to-server hop matching known IT change-management activity can stay analyst-level.",
        },
    },
    {
        "category": "c2_beaconing",
        "title": "Command-and-Control Beaconing",
        "mitre_techniques": ["T1071", "T1573"],
        "phases": {
            "detection_and_scope": "Confirm periodicity and destination reputation (known C2 infrastructure, newly registered domain, DGA-like pattern). Identify what process on the host is generating the traffic.",
            "immediate_triage": "Check the destination against threat intel (RAG cve_intel/mitre_attack lookups and cortex_tool reputation) and whether other internal hosts are beaconing to the same destination (correlation_tool).",
            "containment": "Block the destination IP/domain at the perimeter. Isolate the beaconing host from the network while preserving it for analysis.",
            "eradication_recovery": "Identify and remove the implant/process responsible. Treat as malware_execution for the host-level cleanup steps.",
            "escalation_criteria": "Escalate if multiple internal hosts beacon to the same C2, or if the host is a server/critical asset. A single low-privilege workstation with a promptly blocked, low-confidence beacon can stay analyst-level pending confirmation.",
        },
    },
    {
        "category": "data_exfiltration",
        "title": "Data Exfiltration",
        "mitre_techniques": ["T1041", "T1567"],
        "phases": {
            "detection_and_scope": "Identify volume, destination, and data classification of what left the environment (or was staged to leave). Determine if the transfer used an approved channel (sanctioned cloud storage) misused, or an unapproved channel entirely.",
            "immediate_triage": "Check the account/host's baseline transfer volume to that destination. Check data_classification via asset_context_tool for the source system to understand regulatory/contractual exposure.",
            "containment": "Block the destination if transfer is still in progress. Suspend the account or host involved. Preserve logs/network capture for scope determination before anything is auto-remediated.",
            "eradication_recovery": "Close the channel that allowed exfil (revoke sharing link, disable the export mechanism, patch the misconfiguration). Assess whether breach notification obligations apply given data classification.",
            "escalation_criteria": "Always human-required if data_classification is confidential or regulated, or if volume is inconsistent with any legitimate business process. Small transfers matching known sanctioned workflows can stay analyst-level.",
        },
    },
    {
        "category": "privilege_escalation",
        "title": "Privilege Escalation",
        "mitre_techniques": ["T1068", "T1548"],
        "phases": {
            "detection_and_scope": "Identify the mechanism (exploit, token manipulation, misconfigured permission, UAC bypass) and the account/process's privilege level before and after the event.",
            "immediate_triage": "Check known_vulnerabilities and patch_status for the host via asset_context_tool — is this a known CVE with a public exploit or KEV entry? Check what the elevated context was subsequently used for.",
            "containment": "Isolate the host if the escalation was exploit-based and the vulnerability remains unpatched. Revoke the elevated session/token where possible without a full host isolation if impact is contained.",
            "eradication_recovery": "Patch the underlying vulnerability or misconfiguration. Audit for persistence installed while elevated (new admin accounts, scheduled tasks, services).",
            "escalation_criteria": "Escalate if escalation reached SYSTEM/root or domain-admin-equivalent, or the host is internet-facing and unpatched for a KEV-listed CVE. Escalation to a non-privileged secondary account with no further activity can stay analyst-level.",
        },
    },
    {
        "category": "web_shell_defacement",
        "title": "Web Shell / Website Defacement",
        "mitre_techniques": ["T1505.003"],
        "phases": {
            "detection_and_scope": "Identify the vulnerable application/component that allowed upload or code execution, and confirm scope: single file dropped, or broader compromise with additional backdoors.",
            "immediate_triage": "Check internet_facing and data_classification for the asset via asset_context_tool. Determine if the web shell has been actively used (check web server access logs for POSTs to the shell path) or only dropped.",
            "containment": "Take the affected application offline or isolate it behind WAF rules blocking the shell path immediately. Remove the shell file and any other newly created files in the web root.",
            "eradication_recovery": "Patch the vulnerability that allowed upload (unrestricted file upload, RCE, deserialization, etc.). Rebuild the web root from known-good source rather than trusting selective file deletion.",
            "escalation_criteria": "Always human-required if the application is internet-facing and holds regulated data, or if the shell shows evidence of use (not just presence). Freshly dropped, unused shell on a low-sensitivity dev system can stay analyst-level with prompt remediation.",
        },
    },
    {
        "category": "insider_data_access",
        "title": "Insider / Anomalous Internal Data Access",
        "mitre_techniques": ["T1530"],
        "phases": {
            "detection_and_scope": "Confirm the access pattern is genuinely anomalous for this user (volume, resource sensitivity, time-of-day) rather than a role change or legitimate project the account context doesn't reflect.",
            "immediate_triage": "Check data_classification of what was accessed and whether it falls within the user's normal job function. This category has a higher false-positive rate than external-attacker categories — verify before acting.",
            "containment": "If access is confirmed unauthorized, restrict the account's access to the specific resource rather than a blanket suspension, unless further indicators (exfil, off-hours mass access) justify a full suspension.",
            "eradication_recovery": "Review and correct the permission grant that allowed the access if it was a misconfiguration rather than intentional misuse. Coordinate with HR/legal per org policy if intentional misuse is confirmed.",
            "escalation_criteria": "Always human-required — insider cases carry HR/legal/employment implications regardless of technical severity and should never be auto-resolved or auto-actioned.",
        },
    },
    {
        "category": "dos_ddos",
        "title": "Denial of Service / DDoS",
        "mitre_techniques": ["T1498"],
        "phases": {
            "detection_and_scope": "Confirm volumetric or application-layer pattern, identify targeted service, and check current availability impact.",
            "immediate_triage": "Check if existing DDoS mitigation (CDN/scrubbing) is engaged and effective. Identify source characteristics (botnet-distributed vs. small number of sources) to pick the right mitigation.",
            "containment": "Engage upstream scrubbing/rate-limiting or CDN-level mitigation. Block clearly identifiable malicious sources at the perimeter if the attack is not fully distributed.",
            "eradication_recovery": "No host-level eradication typically needed; focus is capacity/mitigation tuning. Review whether autoscaling or mitigation thresholds need adjustment post-incident.",
            "escalation_criteria": "Escalate if the targeted service is customer-facing/revenue-impacting and mitigation is not immediately effective. Brief, fully-mitigated events with no measurable impact can stay analyst-level.",
        },
    },
]


def load_custom_playbooks(custom_dir):
    """Parse org-specific markdown runbooks matching the format documented above."""
    playbooks = []
    header_re = re.compile(r"^#\s+(.+)$", re.MULTILINE)
    category_re = re.compile(r"^category:\s*(.+)$", re.MULTILINE)
    techniques_re = re.compile(r"^mitre_techniques:\s*(.+)$", re.MULTILINE)
    phase_re = re.compile(r"^##\s+(\w+)\s*$", re.MULTILINE)

    for path in sorted(Path(custom_dir).glob("*.md")):
        text = path.read_text()
        title_m = header_re.search(text)
        category_m = category_re.search(text)
        techniques_m = techniques_re.search(text)
        if not title_m or not category_m:
            print(f"SKIP {path}: missing title or category", file=sys.stderr)
            continue

        phase_matches = list(phase_re.finditer(text))
        phases = {}
        for i, m in enumerate(phase_matches):
            phase_name = m.group(1).strip()
            start = m.end()
            end = phase_matches[i + 1].start() if i + 1 < len(phase_matches) else len(text)
            phases[phase_name] = text[start:end].strip()

        playbooks.append({
            "category": category_m.group(1).strip(),
            "title": title_m.group(1).strip(),
            "mitre_techniques": [t.strip() for t in techniques_m.group(1).split(",")] if techniques_m else [],
            "phases": phases,
            "source": str(path),
        })
    return playbooks


def build_chunk_text(pb, phase_name, phase_text):
    techniques = ", ".join(pb["mitre_techniques"]) if pb["mitre_techniques"] else "none mapped"
    return (
        f"Playbook: {pb['title']} (category: {pb['category']}) — {phase_name.replace('_', ' ')} phase. "
        f"Related MITRE techniques: {techniques}. {phase_text}"
    )


def deterministic_id(category, phase_name):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"playbooks:{category}:{phase_name}"))


def embed(text):
    req = urllib.request.Request(
        EMBED_URL,
        data=json.dumps({"text": text}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())["embedding"]


def upsert_batch(points):
    req = urllib.request.Request(
        QDRANT_URL,
        data=json.dumps({"points": points}).encode(),
        headers={"Content-Type": "application/json"},
        method="PUT",
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def iter_chunks(playbooks):
    for pb in playbooks:
        phase_names = [p for p in PHASE_ORDER if p in pb["phases"]]
        # include any custom phase names not in the standard order, appended after
        phase_names += [p for p in pb["phases"] if p not in PHASE_ORDER]
        for phase_name in phase_names:
            phase_text = pb["phases"][phase_name]
            if not phase_text:
                continue
            yield pb, phase_name, phase_text


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--custom-dir", default=None,
                         help="directory of org-specific markdown playbooks to ingest alongside the seed set")
    parser.add_argument("--seed-only", action="store_true",
                         help="ignore --custom-dir even if provided, ingest only the built-in seed set")
    parser.add_argument("--dry-run", action="store_true",
                         help="parse and preview chunks only, no embedding/Qdrant calls")
    parser.add_argument("--limit", type=int, default=None,
                         help="only process the first N chunks (useful for a quick test batch)")
    args = parser.parse_args()

    playbooks = list(PLAYBOOKS)
    if args.custom_dir and not args.seed_only:
        custom = load_custom_playbooks(args.custom_dir)
        print(f"Loaded {len(custom)} custom playbook(s) from {args.custom_dir}", file=sys.stderr)
        playbooks += custom

    chunks = list(iter_chunks(playbooks))
    if args.limit:
        chunks = chunks[:args.limit]

    print(f"Found {len(playbooks)} playbooks, {len(chunks)} phase chunks.", file=sys.stderr)

    if args.dry_run:
        for pb, phase_name, phase_text in chunks[:5]:
            print("---")
            print(build_chunk_text(pb, phase_name, phase_text)[:300])
        print(f"\n(dry run - showed up to 5 of {len(chunks)}, no network calls made)")
        return

    batch = []
    done = 0
    for pb, phase_name, phase_text in chunks:
        text = build_chunk_text(pb, phase_name, phase_text)
        try:
            vector = embed(text)
        except Exception as e:
            print(f"SKIP {pb['category']}:{phase_name}: embed failed ({e})", file=sys.stderr)
            continue

        batch.append({
            "id": deterministic_id(pb["category"], phase_name),
            "vector": vector,
            "payload": {
                "text": text,
                "collection": "playbooks",
                "source": f"{pb['category']}:{phase_name}",
                "metadata": {
                    "category": pb["category"],
                    "title": pb["title"],
                    "phase": phase_name,
                    "mitre_techniques": pb["mitre_techniques"],
                },
            },
        })

        if len(batch) >= BATCH_SIZE:
            upsert_batch(batch)
            done += len(batch)
            print(f"upserted {done}/{len(chunks)}", file=sys.stderr)
            batch = []

    if batch:
        upsert_batch(batch)
        done += len(batch)
        print(f"upserted {done}/{len(chunks)}", file=sys.stderr)

    print(f"Done. {done} playbook phase-chunks ingested into triage_kb (collection=playbooks).")


if __name__ == "__main__":
    main()

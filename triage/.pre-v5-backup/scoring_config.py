"""Stage 5 scoring constants — SOC-3s Scoring System **v3** (`newscoresystem.md`).

Every value here carries an explicit epistemic status, per that document's core
honesty commitment (`newscoresystem.md` §Status):

- **STANDARD** — traceable to a cited external framework (NIST SP 800-30,
  OWASP Risk Rating Methodology, MITRE ATT&CK). Trust immediately.
- **PROVISIONAL** — set by this team's documented judgment on a recorded date,
  not yet validated against real closed-alert outcomes. Runnable, not trusted.
- **CALIBRATED** — validated against this SOC's own data (`newscoresystem.md`
  §7). **Nothing in this file has this status yet.**

`newscoresystem.md` §11 is explicit that every PROVISIONAL value must live here
as a named constant with its status and date, never inline in `scoring.py`, so
calibration can update them without touching logic code.

**What v3 replaced.** v1 blended four dimensions into one 0-100 number with
invented weights (0.40/0.35/0.25/0.15), averaged likelihood and impact instead
of multiplying them, and folded confidence into the risk magnitude itself.
v3 replaces all of that with a discrete 5x5 matrix lookup, `max()` over
independent impact sub-scores, and confidence kept fully separate as a
one-way escalation override. See `newscoresystem.md` §1 and §4.

**Deliberately not referenced anywhere in v3's scoring**: Stage 3's
`contextual_modifiers` and `llm_criticality_score`, and Stage 4's `likelihood`/
`impact_if_true` labels. v3's Likelihood and Impact rules are an exhaustive
decision table (§4.2-§4.3, §5.1) that names none of them. They remain in
`/triage`'s response and the TheHive case write-up as analyst-facing context;
they no longer move the priority. User-confirmed, 2026-08-24.
"""

from __future__ import annotations

import config

# ---------------------------------------------------------------------------
# Levels — ordered ASCENDING (index 0 = least severe). Order is load-bearing:
# `max()` over impact sub-scores and the one-level/one-band escalations all
# work on these indices, never on the strings themselves.
# STANDARD — 5-level qualitative scales, NIST SP 800-30 Appendix G/I.
# ---------------------------------------------------------------------------

LIKELIHOOD_LEVELS: list[str] = ["Rare", "Unlikely", "Possible", "Likely", "Near-Certain"]
IMPACT_LEVELS: list[str] = ["Negligible", "Minor", "Moderate", "Significant", "Severe"]

# newscoresystem.md §4.2 / §4.3 — level meanings, carried here so the audit
# trail can explain a level without the reader holding the spec open.
LIKELIHOOD_LEVEL_MEANING: dict[str, str] = {
    "Near-Certain": "Confirmed malicious signal exists",
    "Likely": "Strong corroborating evidence",
    "Possible": "Default — insufficient evidence to move off center",
    "Unlikely": "Evidence points toward benign",
    "Rare": "Strong, repeated evidence of benign pattern",
}
IMPACT_LEVEL_MEANING: dict[str, str] = {
    "Severe": "Critical asset or terminal-stage kill-chain tactic",
    "Significant": "High-value asset or late-stage tactic",
    "Moderate": "Default / unknown — never assumed benign",
    "Minor": "Low-value asset, early recon-stage tactic",
    "Negligible": "Reconnaissance/resource-development only, low-value target",
}

# ---------------------------------------------------------------------------
# The matrix — newscoresystem.md §4.4
#
# STANDARD structure (Risk = Likelihood x Impact as a discrete matrix, not a
# weighted average — NIST SP 800-30 Rev.1 / OWASP Risk Rating Methodology)
# applied to a PROVISIONAL cell arrangement. Unlike CVSS's own tier boundaries,
# this specific arrangement has NOT been through an expert-panel review. It is
# a reasonable starting point, flagged for §5 review, not a validated one.
#
#                 Negligible  Minor   Moderate  Significant  Severe
#   Near-Certain      P4        P3       P2          P1        P1
#   Likely            P4        P3       P2          P2        P1
#   Possible          P5        P4       P3          P2        P2
#   Unlikely          P5        P4       P4          P3        P3
#   Rare              P5        P5       P4          P4        P3
# ---------------------------------------------------------------------------

PRIORITY_MATRIX: dict[tuple[str, str], str] = {
    ("Near-Certain", "Negligible"): "P4",
    ("Near-Certain", "Minor"): "P3",
    ("Near-Certain", "Moderate"): "P2",
    ("Near-Certain", "Significant"): "P1",
    ("Near-Certain", "Severe"): "P1",
    ("Likely", "Negligible"): "P4",
    ("Likely", "Minor"): "P3",
    ("Likely", "Moderate"): "P2",
    ("Likely", "Significant"): "P2",
    ("Likely", "Severe"): "P1",
    ("Possible", "Negligible"): "P5",
    ("Possible", "Minor"): "P4",
    ("Possible", "Moderate"): "P3",
    ("Possible", "Significant"): "P2",
    ("Possible", "Severe"): "P2",
    ("Unlikely", "Negligible"): "P5",
    ("Unlikely", "Minor"): "P4",
    ("Unlikely", "Moderate"): "P4",
    ("Unlikely", "Significant"): "P3",
    ("Unlikely", "Severe"): "P3",
    ("Rare", "Negligible"): "P5",
    ("Rare", "Minor"): "P5",
    ("Rare", "Moderate"): "P4",
    ("Rare", "Significant"): "P4",
    ("Rare", "Severe"): "P3",
}

# P1 first — index 0 is the most severe, so escalate_one_band() moves toward 0.
PRIORITY_BANDS_ORDERED: list[str] = ["P1", "P2", "P3", "P4", "P5"]

# Unreachable via the matrix (every cell is populated); used only if a level
# string somehow arrives outside the two vocabularies above.
PRIORITY_FALLBACK = "P3"

# ---------------------------------------------------------------------------
# Impact sub-score 1: ASSET — newscoresystem.md §4.3a
# Source: evidence.asset_context.criticality (iTop CMDB, Stage 1 tool 5).
# Match on exact lowercase string; anything unrecognised falls to the default.
# Never raise on an unknown value (§4.3a implementation note).
# ---------------------------------------------------------------------------

ASSET_CRITICALITY_TO_IMPACT: dict[str, str] = {
    "high": "Severe",
    "medium": "Significant",
    "low": "Minor",
}

# PROVISIONAL — 2026-08-24, SOC-3s pre-fill (§5.1 row 7, recommended in §5.2).
# Reasoning: NIST SP 800-30's treatment of unassessed conditions — unknown
# severity is never silently treated as low. Suricata alerts are IP-only and
# structurally cannot resolve an iTop asset (see CLAUDE.md), and they are the
# highest-volume network-threat class; defaulting them to Minor would
# systematically underscore exactly the alert class most likely to represent a
# network-borne attack. Moderate is the neutral choice: neither penalising nor
# inflating. v1's implicit behaviour here was a 20/100 near-floor — the
# systematic blind spot this replaces.
ASSET_IMPACT_DEFAULT = "Moderate"

# ---------------------------------------------------------------------------
# Impact sub-score 2: TECHNICAL — newscoresystem.md §4.3b
#
# STANDARD — the tactic list is MITRE ATT&CK Enterprise v19.2 (per
# newscoresystem.md's live fetch, 2026-08-24, source 11). The LEVEL ASSIGNED to
# each tactic is kill-chain-position reasoning documented per-row in §4.3b.
#
# Keys are normalised by scoring._normalise_tactic (lowercase, `_`/space -> `-`)
# so every real producer in this repo matches: Sigma's hyphenated-lowercase
# `rule_context.mitre_tactics`, tools/detection_rules.py's Suricata
# normalisation (`Defense_Evasion` -> `defense-evasion`), and Stage 3's
# free-form LLM `refined_mitre_mapping[].tactic`. TA#### ids are accepted
# directly, per §4.3b's implementation note.
#
# v19 split the former Defense Evasion (TA0005) into Stealth (TA0005) and
# Defense Impairment (TA0112). Both successors AND the legacy label are mapped,
# all three to Moderate — §4.3b is explicit that the split does not change the
# severity assessment, so a rule written before v19 scores identically.
# ---------------------------------------------------------------------------

TACTIC_TO_IMPACT: dict[str, str] = {
    # --- Severe: terminal kill-chain stages ---
    "ta0040": "Severe",
    "impact": "Severe",
    "ta0010": "Severe",
    "exfiltration": "Severe",
    "ta0008": "Severe",
    "lateral-movement": "Severe",
    # --- Significant: high-enabler / objective-fulfilling stages ---
    "ta0006": "Significant",
    "credential-access": "Significant",
    "ta0004": "Significant",
    "privilege-escalation": "Significant",
    "ta0009": "Significant",
    "collection": "Significant",
    "ta0011": "Significant",
    "command-and-control": "Significant",
    # --- Moderate: mid-chain, support, and first-foothold stages ---
    "ta0003": "Moderate",
    "persistence": "Moderate",
    "ta0002": "Moderate",
    "execution": "Moderate",
    "ta0005": "Moderate",
    "stealth": "Moderate",
    "ta0112": "Moderate",
    "defense-impairment": "Moderate",
    "defense-evasion": "Moderate",  # legacy pre-v19 label, same level
    "ta0001": "Moderate",
    "initial-access": "Moderate",
    # --- Minor / Negligible: pre-exploitation ---
    "ta0007": "Minor",
    "discovery": "Minor",
    "ta0043": "Negligible",
    "reconnaissance": "Negligible",
    "ta0042": "Negligible",
    "resource-development": "Negligible",
}

# PROVISIONAL — §4.3b's final table row. A fired detection rule with no MITRE
# mapping is still a fired detection rule; never assumed benign.
TACTIC_IMPACT_DEFAULT = "Moderate"

# ---------------------------------------------------------------------------
# Likelihood decision table — newscoresystem.md §5.1
#
# Rules 1 and 2 need no calibration: the evidence CATEGORY determines the
# floor, not a statistical threshold (§5.1 rows 1-2, "fixed"). Rules 3-5 are
# the PROVISIONAL ones and the first targets for §7 calibration.
# ---------------------------------------------------------------------------

# Rule 1 — STANDARD/fixed. A single confirmed malicious verdict from a deployed
# threat-intel analyzer is direct positive evidence; no repetition required.
RULE_1_MALICIOUS_FLOOR = "Near-Certain"

# Rule 2 — STANDARD/fixed. "suspicious" is a weaker but still positive finding.
RULE_2_SUSPICIOUS_FLOOR = "Likely"

# Rule 3 — PROVISIONAL, 2026-08-24, SOC-3s pre-fill (§5.1 row 3).
# N=5 sits above the anecdotal floor (2-3 cases) and well below the statistical
# ideal (30+): a cold-start compromise — enough to have seen the pattern more
# than once, not enough to fully trust it. X=0.70 means the pattern resolves as
# real more often than not, a 2:1 TP:FP ratio.
RULE_3_TP_FLOOR_MIN_CLOSED_CASES = 5
RULE_3_TP_FLOOR_MIN_TP_RATIO = 0.70
RULE_3_TP_FLOOR_LEVEL = "Likely"

# Rule 4 — PROVISIONAL, 2026-08-24, SOC-3s pre-fill (§5.1 row 4).
# 5 FPs in 30 days means this rule/host has been repeatedly benign. 30 days is
# the standard operational window and, not coincidentally, exactly the window
# FPSignal already reports (`rule_fp_count_30d`/`host_fp_count_30d`) — so this
# constant documents the window rather than configuring it; changing it alone
# would NOT change what tools/fp_tracking.py counts.
RULE_4_FP_CAP_MIN_COUNT = 5
RULE_4_FP_CAP_WINDOW_DAYS = 30
RULE_4_FP_CAP_LEVEL = "Rare"

# Rule 5 — PROVISIONAL, 2026-08-24, SOC-3s pre-fill (§5.1 row 5).
# <=20% TP means the pattern has been benign 4 times out of 5 or more.
# Deliberately ASYMMETRIC with rule 3's 0.70: capping requires stronger
# evidence of benignness than flooring requires of maliciousness, because a
# false negative costs more than a false positive.
RULE_5_FP_RATIO_CAP_MIN_CLOSED_CASES = 5
RULE_5_FP_RATIO_CAP_MAX_TP_RATIO = 0.20
RULE_5_FP_RATIO_CAP_LEVEL = "Unlikely"

# Rule 9 — §4.4b step 4 / §4.2. The centre of the scale: insufficient evidence
# to move off it in either direction.
RULE_9_DEFAULT_LEVEL = "Possible"

# Rule 6 — PROVISIONAL, 2026-08-24, SOC-3s pre-fill (§5.1 row 6).
# One other affected host could be coincidence or a shared service; three
# distinct hosts suggests active lateral movement or a spreading condition.
# The escalation is bounded at exactly one level, never more.
RULE_6_BLAST_RADIUS_MIN_OTHER_HOSTS = 3

# ---------------------------------------------------------------------------
# Evidence Quality — newscoresystem.md §4.5
#
# §4.5 specifies the MECHANISM as STANDARD (escalate under uncertainty,
# downgrade later — arXiv:2601.04486's "Aligned Trust" pattern) and names the
# inputs ("evidence completeness % + Stage-1 tool gaps), but **gives no
# thresholds** — §5.1's worksheet has no row for them either. The values below
# are therefore a documented gap-fill, not a spec transcription, and are the
# one place in this file where the number's source is this repo rather than
# `newscoresystem.md`. Flagged for §5.1 review alongside rows 1-7.
#
# PROVISIONAL — 2026-08-24, SOC-3s pre-fill.
# Reasoning: the two inputs measure different failures and are ANDed, so a
# rich alert whose backends all failed cannot reach HIGH, and neither can a
# thin alert with clean backends. Boundaries are set at the natural fractions
# of the 8-field completeness check (6/8 and 4/8) rather than at round decimals
# that would fall between fields and be unreachable. The gap allowances are
# deliberately tight because Stage 1 runs only 8 tools: 2 gaps is a quarter of
# the evidence base missing.
EVIDENCE_QUALITY_HIGH_MIN_COMPLETENESS_PCT = 75.0  # >= 6 of 8 fields
EVIDENCE_QUALITY_HIGH_MAX_GAPS = 1
EVIDENCE_QUALITY_MODERATE_MIN_COMPLETENESS_PCT = 50.0  # >= 4 of 8 fields
EVIDENCE_QUALITY_MODERATE_MAX_GAPS = 3

EVIDENCE_QUALITY_LEVELS: list[str] = ["LOW", "MODERATE", "HIGH"]

# STANDARD (§4.5) — the ONE override rule. A safety default, not a precision
# instrument; errs deliberately in the safe direction and needs no calibration.
EVIDENCE_QUALITY_ESCALATION_TRIGGER = "LOW"

# The 8 CanonicalAlert-level presence checks behind evidence_completeness_pct.
# Carried over unchanged from v1 — it measures how much the ALERT itself
# yielded, which is a different question from how many TOOL calls failed
# (gap_count). Computing both from one signal would double-count it.
EVIDENCE_COMPLETENESS_FIELD_COUNT = 8

# ---------------------------------------------------------------------------
# Status labels — newscoresystem.md §8's three NEW audit-trail fields.
#
# These are the honesty labels the whole v3 document exists to carry: every
# number the system emits states whether it has been validated. §7.2 is what
# flips them to "CALIBRATED [date, n=...]" — do not edit them by hand without
# having actually run that validation pass.
# ---------------------------------------------------------------------------

STATUS_PROVISIONAL = "PROVISIONAL"

LIKELIHOOD_RULE_STATUS = STATUS_PROVISIONAL
IMPACT_RULE_STATUS = STATUS_PROVISIONAL
MATRIX_STATUS = STATUS_PROVISIONAL

# Rules 1 and 2 are the exception — §5.1 marks both "fixed (no calibration
# needed)", since the evidence category itself determines the floor.
STATUS_FIXED = "FIXED"

# ---------------------------------------------------------------------------
# Deployment mode — newscoresystem.md §6 / §8's `deployment_mode` field.
#
# DEVIATION FROM SPEC, user-directed 2026-08-24: §6 step 2 and §7.2 require
# that shadow-mode output must not drive TheHive case severity until §7
# calibration completes. **This deployment writes the computed severity in
# BOTH modes** — the user's explicit instruction ("yes it's shadow mode but
# for the cases created in this mode let them have the shadow severity").
# `deployment_mode` is therefore an honest LABEL on the audit trail and the
# case write-up, not a gate on the TheHive write. Do not "correct" this back
# toward the spec without asking — it is deliberate, like every other entry in
# CLAUDE.md's deployment-decisions section.
# ---------------------------------------------------------------------------

DEPLOYMENT_MODE = config.DEPLOYMENT_MODE

# TheHive's own 1-4 severity scale. Unchanged from v1/v2 (§7.2 says so
# explicitly) — the mapping is the same, only what feeds it changed.
PRIORITY_TO_HIVE_SEVERITY: dict[str, int] = {"P1": 4, "P2": 3, "P3": 2, "P4": 1, "P5": 1}

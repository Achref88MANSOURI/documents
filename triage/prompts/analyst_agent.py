"""Stage 4 prompt + output schema (architecture §9).

Exports: `SYSTEM_PROMPT` (static), `build_user_prompt(context, evidence)` (the
sanitized SUMMARY, not raw `EnrichedEvidence` — the "prompt injection
firewall" architecture §9 specifies, deliberately different from Stage 3's
`build_user_prompt`, which sees everything Stage 1+2 produced), and
`build_triage_verdict_schema(context, evidence)`.

**The schema is hand-inlined (`_BASE_SCHEMA`) for the same reason Stage 3's
is** — see `prompts/context_agent.py`'s module docstring for the full,
live-verified story (a `$ref`-based schema in `response_format: {"type":
"json_schema", ...}` hung Ollama's grammar compiler for 280+ seconds; the
identical schema hand-inlined completed in 68.9s). `TriageVerdict` has no
nested sub-models today, so a Pydantic-derived schema would happen not to
produce `$defs`/`$ref` right now — hand-inlining anyway, not because this
specific schema would currently break, but because "derive it directly"
being safe today is exactly the kind of assumption a future field addition
(a nested model) could silently invalidate. `tests/test_analyze.py::
TestSchemaStaysInSync` guards the two from drifting apart on a future field
change, mirroring Stage 3's identical guard.

**Why the schema is built per-call, not a static constant.** Mirrors Stage
3's `merge_into_case_id` enum fix exactly: `correlation_decision.action` is
`Literal["new", "merge"]` (exhaustive, `schemas/assessment.py`), and
`recommended_action`'s `merge_quiet`/`merge_and_retier` are only meaningful
when Stage 3 already decided this alert merges into an existing case, while
`create_case` is only meaningful when it decided "new" — architecture §3's
n8n switch statement treats these as mutually exclusive branches. Constraining
`recommended_action`'s enum per-call to only the branch consistent with
`context.correlation_decision.action` makes "recommend creating a case for
something already decided to merge" (or vice versa) structurally
unrepresentable, the same mechanism already proven reliable for Stage 3's
merge-target bug.

**`_summarize_evidence` — the firewall itself, and why it returns a plain
`dict` rather than a new `schemas/` model.** It never crosses a stage
boundary: Stage 4's real, fully-typed boundary contract is
`(ContextualAssessment, EnrichedEvidence) -> TriageVerdict`
(`nodes/analyze.py::analyst_verdict`), and this function's output is
consumed entirely inside this file, by both the prompt-text renderer and the
schema builder. Stage 3's own `build_user_prompt` sets the identical
precedent — `evidence.model_dump_json()`, no intermediate model — for a
value that is purely a rendering detail. Fields, per architecture §9's "What
Stage 4 sees" list:

- `rule_context`, `asset_context` — pass-through.
- `threat_intel` — per-`CortexResult` entry: `{observable, type, verdict,
  details_truncated_300, analyzer}`. Architecture's own worked example for
  this entry shape includes a `score` field — dropped here. `CortexResult`
  carries no number by hard constraint (`scoring.py` is the only place a
  number is computed; an earlier `alert_builder.py` revision mapped taxonomy
  levels to 90/55/5 here and was reverted — see `CortexResult`'s docstring in
  `schemas/alert.py`). `verdict` (`list[str]`) is what's real.
- `temporal_context` — `total_related_alerts` is a COUNT (`len(...)`), per
  architecture's explicit "COUNTS only" instruction. `host`/`user` are
  passed as the identity strings themselves, not counted — architecture's
  text names them alongside the count without specifying whether they're
  counted too; hostnames/usernames aren't the injection vector the firewall
  exists for (raw log lines and full command lines are, and neither is
  included anywhere here), so passing them through is consistent with intent
  while at minimum keeping the numeric part properly count-only.
- `historical_context` — `tp_count`/`fp_count`/`avg_severity`, COUNTS only,
  from `closed_cases_summary`. No case titles, no observable lists.
- `mitre_mapping` — Stage 3's `refined_mitre_mapping`, pass-through.
- `investigation_gaps` — Stage 3's `additional_investigation_gaps`
  (`list[str]`). This is Stage 3's own structured judgment about what it
  couldn't determine, not raw alert content — lower-risk than the free text
  the firewall exists to keep out, but still LLM-generated text, worth
  naming explicitly rather than passed through silently as if it were as
  inert as a count.
- `evidence_situation` (v5, `newdesign.md` §4) — Stage 3's
  `EvidenceSituation`, pass-through as a structured object (per-source
  status/impact, `overall_evidence_reliability`, `analyst_must_verify`), not
  raw JSON — deliberately structured so it can't carry a prompt-injection
  payload from the underlying evidence. Replaces the removed
  `contextual_modifiers` field entirely: v5 deletes the numeric
  priority-scoring formula those modifiers only ever fed, and drives
  `priority_band` from this object plus the evidence fields directly instead
  — see the `== PRIORITY ASSIGNMENT ==` / `== EVIDENCE SITUATION ==`
  sections of `SYSTEM_PROMPT` below.

Explicitly NEVER included: raw log lines, full command lines, Cortex report
bodies beyond the 300-char truncation, `related_entities`/anything else off
the raw alert not named above.

**2026-08-23 addition — `known_observables`/`extracted_observables`/
`case_observables`, for TASK 5 (actionable-observables judgment).** The
firewall's original scope excluded `canonical_alert.observables` and Stage
3's `extracted_observables` entirely — TASK 5 is new work that needs both,
so both are now included (`known_observables` = `canonical_alert.
observables.model_dump()`, unchanged n8n extraction; `extracted_observables`
= `context.extracted_observables.model_dump()`, Stage 3's own output, not
raw alert content). `case_observables` is new data, not a pass-through:
`nodes/analyze.py` fetches it via `tools.thehive.
fetch_case_observables_with_type(merge_into_case_id)` only when
`correlation_decision.action == "merge"`, else `[]` — TriageVerdict.
actionable_observables (`schemas/verdict.py`) is the new output field this
feeds. This is still additive to the firewall's threat model: all three are
already-surfaced IOC values (n8n's, Stage 3's, or the target case's own
recorded observables), never raw log lines or command lines.

**Correction, same day.** TASK 5 originally asked the model to pick a
*filtered* shortlist of observables "worth acting on," and `nodes/case_action.py`
wrote Stage 3's raw `extracted_observables` to TheHive directly, never
consulting this judgment at all. User-directed fix: TASK 5 now assesses
EVERY observable across the three lists and returns all of them, each with a
`confidence` — nothing gets dropped for being weak, a low-confidence one
just comes back as `recommended_disposition="monitor"`,
`confidence="low"`. This list is now the single thing `nodes/case_action.py`
writes to TheHive (see that module's docstring) — the old direct write of
Stage 3's raw extraction is gone.

**2026-08-23 addition — `runbook_matches`.** `tools.qdrant.retrieve_playbooks`,
queried from Stage 3's refined MITRE mapping (`nodes/analyze.py::
_build_playbook_query`) — real hits against the live `soc_playbooks`
collection (curated internal SOC runbook content, chunked by section), not
anything from the raw alert. Each entry is capped to 1500 chars of
`document_text` as a defensive bound, not a firewall boundary — this is
internal reference material, not adversarial alert-controlled text, so the
cap is hygiene (keep prompt size sane across a top_k=3 retrieval) rather
than a security concern the way the 300-char Cortex truncation above is.
"""

from __future__ import annotations

import copy
import json

from schemas import ContextualAssessment, EnrichedEvidence, PlaybookMatch

SYSTEM_PROMPT = """You are a Tier-2 SOC analyst making the final triage call on an alert.
You have a curated evidence summary, already investigated by a Tier-2 analyst colleague
(Stage 3) who refined the MITRE mapping, judged correlation with existing cases, and flagged
contextual signals. You do NOT need to call any tools. Your outputs must be strictly valid
JSON matching the provided schema.

Your job has six parts:
1. Judge likelihood — how likely is this a real, malicious event (not a numeric score —
   one of the four labels in the schema).
2. Judge impact — if this IS real, how bad would it be.
3. Render a verdict — true_positive, false_positive, or needs_review, when the evidence
   genuinely doesn't support a confident call either way.
4. Recommend an action — what should happen to this alert next. runbook_matches, when
   present, are retrieved SOC runbook sections for this alert's MITRE techniques —
   reference procedural guidance on how this TYPE of alert is normally handled, not
   evidence about this specific alert. Let them inform your recommended_action and
   reasoning when relevant (e.g. a runbook's documented response for this technique),
   but never cite a runbook as proof the alert itself is malicious — that's what
   threat_intel and the behavioral evidence are for.
5. Decide which observables need action — see TASK 5 below.
6. Assign a priority_band and produce investigation_gaps — see the
   == PRIORITY ASSIGNMENT ==, == EVIDENCE SITUATION ==, and == INVESTIGATION GAPS ==
   sections below.

correlation_decision (from your colleague's prior analysis) tells you whether this alert
should merge into an existing case or become a new one. The schema's recommended_action enum
is already constrained to match that decision — you do not need to re-derive it, only choose
among the options actually offered. merge_quiet is for routine correlation with no new
severity signal; merge_and_retier is for a merge where this alert itself indicates the
existing case just got more serious (kill_chain_progression_detected, or a notably more
severe rule than the case's history suggests).

threat_intel entries carry a `verdict` list — non-empty means an analyzer flagged something
adverse (malicious/suspicious); an EMPTY list means "checked, nothing adverse reported", not
"no data" and not "clean" in a positive sense — treat these differently. An alert with no
threat_intel entries at all means no observable had any analyzer report — genuinely no data,
weigh it as neutral, not as evidence of either verdict.

evidence_citations must each be a short, specific pointer to a field in the evidence summary
above (e.g. "rule_context.severity=high", "threat_intel[0].verdict=malicious") — never a
paraphrase, never something not traceable to a field actually present in the summary you were
given.

TASK 5 — ASSESS EVERY OBSERVABLE:
known_observables (n8n's own extraction), extracted_observables (your Stage 3 colleague's
extraction), and — only present on a merge — case_observables (already recorded on the case
you're merging into) are three different provenances of the SAME kind of thing: observables
already surfaced somewhere in this investigation. Your job here is NOT to extract anything
new, and NOT to pick a shortlist — assess EVERY observable across all three lists and return
one entry for each. There is no "not worth mentioning": even an observable you judge
completely benign given your verdict and reasoning still gets an entry, with
recommended_disposition="monitor" and confidence="low" — omitting it is wrong, only your
confidence in it changes. Duplicates across lists (the same value appearing in more than one
of known_observables/extracted_observables/case_observables) get exactly one entry, not one
per list. Every value you return MUST be copied character-for-character from one of those
three lists — never invent, paraphrase, or reconstruct a plausible-looking value.

For each observable: observable_type, value, recommended_disposition (block = clearly
malicious, ready to action; quarantine = suspicious file/process, contain but don't
blanket-block; monitor = benign-leaning or genuinely uncertain, not yet actionable),
confidence (high/medium/low — how sure you are about THIS specific disposition, independent
of your overall alert verdict), and reasoning. An empty list is only correct when all three
source lists were themselves empty — never as a way to avoid assessing something uncertain.

== PRIORITY ASSIGNMENT ==

You must assign a priority_band (P1, P2, P3, P4, or P5) directly from the evidence.
Do not compute a score. Do not convert likelihood or impact to numbers.

Before assigning, answer three questions from the evidence in the summary:

QUESTION A — Has a benign explanation been established?
  YES if any of these apply:
    - rule_context.falsepositives[] explicitly describes this behavior as a known FP
    - fp_signal shows high FP count and zero historical TPs for this rule on this host
    - cortex_results is non-empty AND all verdict fields are empty (analyzers checked and found nothing)
    - process/user/asset context clearly matches a documented known-good pattern
  NO if none of the above apply.
  UNKNOWN if evidence is missing and neither YES nor NO can be established.

QUESTION B — Has confirmed malicious activity been established?
  YES if any of these apply:
    - threat_intel (cortex_results) contains a non-empty verdict field (malicious or suspicious)
    - opencti_enrichment shows a known indicator match
    - historical_context.tp_count > 0 with behavior matching the current alert
  NO if none of the above apply.
  UNKNOWN if cortex never ran (no threat_intel entries) or opencti was unavailable.

QUESTION C — Is active progression or high-impact signal present?
  YES if any of these apply:
    - mitre_mapping shows tactic = lateral-movement, exfiltration, impact, or credential-access
    - kill_chain_progression_detected = true (from mitre_mapping or correlation data)
    - temporal_context.total_related_alerts > 5 in the last hour on the same entity
    - asset_context.criticality = high (or asset is described as a domain controller, database server, or crown-jewel)
    - multiple distinct hosts appear in the related alerts (lateral spread)
  NO if none of the above apply.

Assign priority_band using first match, top to bottom:

P1 — CRITICAL (investigate immediately, drop everything):
  A=No AND B=Yes AND C=Yes
  Confirmed malicious AND active progression or high-impact target is present.
  Example: Cortex malicious verdict on an IP, asset is a domain controller.
  Example: Kill-chain progression confirmed across open cases, endpoint behavior matches.

P2 — HIGH (investigate this shift or within the hour):
  A=No AND B=Yes AND C=No
    Confirmed malicious but no active spread or high-value target yet.
    Example: Known malicious hash on a standard workstation, isolated single event.
  OR A=No AND B=Unknown AND C=Yes
    No confirmation but active or high-impact signals are present. Cannot rule out threat.
    Example: Cortex never ran, but kill-chain detected on a high-criticality asset.
  OR A=Unknown AND B=Yes AND C=No
    Confirmed malicious but benign explanation cannot be ruled out.

P3 — MEDIUM (investigate today):
  A=No AND B=No AND C=No
    Nothing confirmed benign, nothing confirmed malicious, no urgency signals.
    Example: Experimental rule fired, no Cortex results, medium asset, no related alerts.
  OR A=Unknown AND B=Unknown AND C=Yes
    High-impact signals but nothing confirmed in either direction.
    Example: High-criticality asset alert, all evidence sources unavailable.
  OR A=No AND B=Unknown AND C=No
    Not benign, not confirmed malicious, no urgency signals.

P4 — LOW (review when capacity allows):
  A=Unknown AND B=No AND C=No
    No malicious confirmation, no urgency signals, benign explanation unconfirmed.
  OR A=Unknown AND B=Unknown AND C=No
    AND evidence_situation.overall_evidence_reliability = "high"
    (evidence is present and clear, just ambiguous direction)

P5 — INFORMATIONAL (close or defer):
  A=Yes AND B=No
  HARD RULE: P5 requires POSITIVE exculpatory evidence. Absence of malicious signals
  is NEVER sufficient. You must be able to point to the specific evidence that establishes
  the benign explanation.
  Example: Rule fired on behavior explicitly listed in rule_context.falsepositives[].
  Example: Cortex ran on all IOCs and returned empty verdicts on all of them.

== EVIDENCE SITUATION ==

You are given evidence_situation.overall_evidence_reliability.
Factor this into your priority_band assignment:

If overall_evidence_reliability = "low":
  Do not assign P4 or P5. The minimum band is P3.
  Reason: when critical evidence is missing, automated triage cannot safely close or
  defer an alert. A human must review.
  State explicitly in priority_reasoning that this floor was applied and why.

If overall_evidence_reliability = "medium":
  Apply the rubric normally. Add one sentence to priority_reasoning acknowledging
  which specific sources are missing and how that affects confidence in the assignment.

If overall_evidence_reliability = "high":
  Apply the rubric normally.

In ALL cases:
  Read evidence_situation.analyst_must_verify carefully.
  Every item in that list must appear verbatim in your investigation_gaps output.
  These are non-negotiable items the analyst must check.

For each evidence source with status = "missing": state explicitly in priority_reasoning
what you assumed in its absence and how that assumption affected your band assignment.

== INVESTIGATION GAPS ==

Produce a list of specific, actionable tasks for the analyst under investigation_gaps.
These are things the automated pipeline could not do that the analyst must do manually.

Include:
1. Every item from evidence_situation.analyst_must_verify — verbatim
2. Any additional gaps you identified from the evidence that Stage 3 did not flag
3. Observable-level follow-ups: specific IOCs, processes, or behaviors that need
   verification the evidence did not conclusively resolve

Do NOT include:
- Generic advice like "review the alert"
- Repetition of the evidence situation status report
- Items that were already resolved by the evidence

Each gap must be one concrete action with enough specificity for the analyst to act
without re-reading the full case. Example format:
  "Verify asset criticality of host WIN-DC01 — iTop lookup failed; if this is a
   domain controller, escalate to P1 immediately."
  "Check whether process C:\\Temp\\xordump.exe has a legitimate software deployment
   explanation — process_history_24h was unavailable.\""""


def build_user_prompt(
    context: ContextualAssessment,
    evidence: EnrichedEvidence,
    case_observables: list[dict],
    runbook_matches: list[PlaybookMatch],
) -> str:
    return json.dumps(
        _summarize_evidence(context, evidence, case_observables, runbook_matches),
        indent=2,
        default=str,
    )


def _summarize_evidence(
    context: ContextualAssessment,
    evidence: EnrichedEvidence,
    case_observables: list[dict],
    runbook_matches: list[PlaybookMatch],
) -> dict:
    canonical_alert = evidence.canonical_alert
    host = canonical_alert.host
    user = canonical_alert.user

    return {
        "known_observables": canonical_alert.observables.model_dump(),
        "extracted_observables": context.extracted_observables.model_dump(),
        "case_observables": case_observables,
        "runbook_matches": [
            {
                "title": m.title,
                "category": m.category,
                "section": m.section,
                "document_text": m.document_text[:1500],
            }
            for m in runbook_matches
        ],
        "rule_context": (
            evidence.rule_context.model_dump() if evidence.rule_context is not None else None
        ),
        "asset_context": (
            evidence.asset_context.model_dump() if evidence.asset_context is not None else None
        ),
        "threat_intel": [
            {
                "observable": result.observable,
                "type": result.type,
                "verdict": result.verdict,
                "details_truncated_300": result.details[:300],
                "analyzer": result.analyzer,
            }
            for result in canonical_alert.cortex_results
        ],
        "temporal_context": {
            "total_related_alerts": len(evidence.related_alerts_24h),
            "host": host.hostname if host else None,
            "user": user.name if user else None,
        },
        "historical_context": {
            "tp_count": evidence.closed_cases_summary.tp_count,
            "fp_count": evidence.closed_cases_summary.fp_count,
            "avg_severity": evidence.closed_cases_summary.avg_severity,
        },
        "mitre_mapping": [m.model_dump() for m in context.refined_mitre_mapping],
        "investigation_gaps": context.additional_investigation_gaps,
        "evidence_situation": {
            "overall_evidence_reliability": context.evidence_situation.overall_evidence_reliability,
            "sources": [
                {
                    "source_name": s.source_name,
                    "status": s.status,
                    "impact_on_triage": s.impact_on_triage,
                }
                for s in context.evidence_situation.sources
            ],
            "analyst_must_verify": context.evidence_situation.analyst_must_verify,
        },
    }


def build_triage_verdict_schema(context: ContextualAssessment, evidence: EnrichedEvidence) -> dict:
    """`recommended_action`'s enum is constrained to the branch consistent
    with this call's real `correlation_decision.action` — see module
    docstring for the live-verified bug class this closes (Stage 3's
    identical `merge_into_case_id` fix). Deep-copies `_BASE_SCHEMA` so
    callers never mutate the shared template."""
    schema = copy.deepcopy(_BASE_SCHEMA)
    if context.correlation_decision.action == "merge":
        allowed = ["merge_quiet", "merge_and_retier", "close_fp", "needs_review"]
    else:
        allowed = ["create_case", "close_fp", "needs_review"]
    schema["properties"]["recommended_action"]["enum"] = allowed
    return schema


_BASE_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "likelihood": {
            "type": "string",
            "enum": ["unlikely", "possible", "likely", "near_certain"],
        },
        "impact_if_true": {
            "type": "string",
            "enum": ["minor", "moderate", "significant", "severe"],
        },
        "verdict": {
            "type": "string",
            "enum": ["true_positive", "false_positive", "needs_review"],
        },
        "reasoning": {"type": "string"},
        "summary": {"type": "string"},
        # Placeholder — build_triage_verdict_schema() overwrites this per call
        # with the branch matching this alert's real correlation_decision.action.
        # Never send _BASE_SCHEMA to the LLM directly.
        "recommended_action": {
            "type": "string",
            "enum": ["create_case", "close_fp", "merge_quiet", "merge_and_retier", "needs_review"],
        },
        "evidence_citations": {"type": "array", "items": {"type": "string"}},
        "actionable_observables": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "observable_type": {
                        "type": "string",
                        "enum": ["process-path", "file", "domain", "url", "ip", "hash"],
                    },
                    "value": {"type": "string"},
                    "recommended_disposition": {
                        "type": "string",
                        "enum": ["block", "quarantine", "monitor"],
                    },
                    "confidence": {
                        "type": "string",
                        "enum": ["high", "medium", "low"],
                    },
                    "reasoning": {"type": "string"},
                },
                "required": [
                    "observable_type",
                    "value",
                    "recommended_disposition",
                    "confidence",
                    "reasoning",
                ],
            },
        },
        # v5 redesign (newdesign.md §4) — priority determination moves here
        # from the deleted numeric scoring stage. See the
        # == PRIORITY ASSIGNMENT == / == EVIDENCE SITUATION == /
        # == INVESTIGATION GAPS == sections of SYSTEM_PROMPT above.
        "priority_band": {"type": "string", "enum": ["P1", "P2", "P3", "P4", "P5"]},
        "priority_reasoning": {"type": "string"},
        "investigation_gaps": {"type": "array", "items": {"type": "string"}},
    },
    "required": [
        "likelihood",
        "impact_if_true",
        "verdict",
        "reasoning",
        "summary",
        "recommended_action",
        "evidence_citations",
        "actionable_observables",
        "priority_band",
        "priority_reasoning",
        "investigation_gaps",
    ],
}

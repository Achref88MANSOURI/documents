"""Stage 3 prompt + output schema (architecture §8).

Exports: `SYSTEM_PROMPT` (static, architecture §8's "Prompt structure" plus
one clarifying paragraph — see below), `build_user_prompt` (the full
`EnrichedEvidence`, no truncation — deliberately different from Stage 4's
`_summarize_evidence` firewall, which truncates/counts/redacts; Stage 3 is
architecture's one place meant to see everything Stage 1+2 produced), and
`build_contextual_assessment_schema(evidence)`.

**The schema is hand-inlined (`_BASE_SCHEMA`) and must stay that way.**
Do NOT replace it with `ContextualAssessment.model_json_schema()` — Pydantic
represents nested models via `$defs`/`$ref`, and live-testing against the
real Ollama endpoint (`foundation-sec-reasoning:latest` on
`config.LLM_BASE_URL`) showed that a `$ref`-based schema in
`response_format: {"type": "json_schema", ...}` makes the grammar compiler
hang — a request with a `$ref`-based version of this exact schema did not
return after 280+ seconds. The same schema hand-inlined (zero `$defs`)
completed in 68.9s with clean, fully schema-conformant output. This isn't
a style preference; it's the difference between a working call and a call
that never returns. `tests/test_context.py::TestSchemaStaysInSync` guards
against the two schemas silently drifting apart after a future field
change to `ContextualAssessment`.

**Why the schema is built per-call, not a static constant.** A live real
run (2026-08-16, see CLAUDE.md "Observed Stage 3 output quality note") had
the model set `correlation_decision.merge_into_case_id` to an ID that only
existed in Stage 2's `incident_matches` (a RAG-retrieved *similar past
incident*, reference material) — `evidence.open_cases` (TheHive's actual
open cases) was empty on that run, so no real merge target existed at all.
A free `["string", "null"]` type didn't stop this. Fixed by constraining
`merge_into_case_id`'s `enum` to this call's actual `open_cases` case IDs
(plus `null`), and `action`'s `enum` to `["new"]` only when there are no
open cases to merge into. Live-verified 2026-08-16: with the enum forced to
`[null]` (simulating the exact bug scenario), the model complied cleanly —
`action: "new"`, `merge_into_case_id: null` — no error, no degraded
analysis quality. Making the wrong answer structurally unrepresentable
turned out to be reliable where the free-form type wasn't.

**`extracted_observables` (2026-08-16 addition).** One new output field,
`schemas.assessment.ExtractedObservables`, mirroring the type split of
`schemas.alert.Observables` (`external_ips`/`domains`/`urls` as separate
lists, not one combined bucket) plus `process`/`file`/`hash` buckets that
have no `Observables` equivalent — those three are exclusively
LLM-derived, never something n8n's extractor produces. Required in
`_BASE_SCHEMA`; gets a safe, empty default in
`nodes/context.py::_stage_3_fallback` so a downed LLM never fabricates one.

**`evidence_situation` (v5 redesign, `newdesign.md` §3) replaces
`contextual_modifiers`/`confidence`/`llm_criticality_score`.** Those three
fields only ever fed the numeric priority-scoring formula (`scoring.py`),
deleted entirely in v5 in favor of an LLM-direct `priority_band` produced by
Stage 4 (`prompts/analyst_agent.py`). TASK 5 below now asks Stage 3 for a
structured per-source evidence-quality report instead — see
`schemas.assessment.EvidenceSituation`'s docstring for the shape and how
Stage 4 uses it.
"""

from __future__ import annotations

import copy

from schemas import EnrichedEvidence, RawEvidence

SYSTEM_PROMPT = """You are a Tier-2 SOC analyst reviewing an alert investigation package.
You have complete evidence — you do NOT need to call any tools.
Your outputs must be strictly valid JSON matching the provided schema.

Your job has five parts:
1. Refine the MITRE mapping — validate against evidence, add/remove techniques
2. Judge correlation — does this alert merge with existing cases, and is it a kill-chain progression?
3. Identify additional investigation gaps beyond what Stage 1 already found
4. Extract critical observables the automated pipeline missed
5. Assess the evidence situation — what's reliable, what's missing, what the analyst must verify

Two different kinds of prior-case data are in the evidence, and they mean different things:
- open_cases: currently open TheHive cases. These are the ONLY valid merge targets for
  correlation_decision.merge_into_case_id.
- incident_matches: past incidents retrieved by semantic similarity search. These are
  reference context for your reasoning — never a case to merge into, and never something
  to cite as a currently open case.

cortex_results[].verdict is pre-filtered to ONLY "malicious"/"suspicious" — "info"/"safe"
never appear there. EMPTY verdict means no adverse finding, not "clean" and not "no data".
taxonomies[] carries every row verbatim including info/safe — ignore those as noise. Base
extraction and criticality on entries whose verdict is non-empty.

TASK 4 — EXTRACT CRITICAL OBSERVABLES:
Extract observables that are: (1) NOT already in canonical_alert.observables (n8n already
captured those — redundant, not extraction), (2) derived from suspicious behavior
(process ancestry, command-line, file drop location) OR a cortex_results entry with
non-empty verdict, (3) specific and actionable, not a vague description.

EVERY value MUST be copied character-for-character from the evidence JSON above. Never
invent, paraphrase, or reconstruct a plausible-looking hash/IP/command line — if you can't
point to the exact substring it came from, don't report it. An unsupported value is worse
than none: it will be discarded as a hallucination.

Each bucket accepts exactly ONE observable_type: process->"process-path", file->"file",
external_ips->"ip", domains->"domain", urls->"url", hash->"hash". Put each observable in
the bucket matching what it actually is — a URL goes in "urls" not "domains", a hash in
"hash" not "file". The process bucket is specifically the executable's PATH (e.g.
"C:\\Windows\\Temp\\xordump.exe"), the thing an analyst would actually block or quarantine —
not a process name, PID, or command-line fragment.

For each: observable_type, value, rationale, confidence, source ("behavioral_analysis",
"cortex_result", or "command_line_parsing").

Do NOT extract: legitimate system processes absent suspicious context; anything with an
EMPTY cortex verdict; anything already in canonical_alert.observables; anything you can't
quote verbatim. Empty lists are a valid, expected answer on benign alerts.

TASK 5 — EVIDENCE SITUATION ASSESSMENT:

For each of the following 8 evidence sources, assess its status and what that status means
for the reliability of this triage. Produce one entry per source.

Sources to assess: fp_signal, rule_context, open_cases, closed_cases_summary, asset_context,
related_alerts_24h, process_history_24h, opencti_enrichment.

For each source, produce:

- source_name — the name of the source as listed above
- status — one of three values:
  - "present" — the tool ran and returned usable data
  - "empty" — the tool ran but found nothing (this is signal, not a failure)
  - "missing" — the tool failed, timed out, or could not run (this is a reliability gap)
- impact_on_triage — one sentence explaining what this status means for how much the triage
  can be trusted. Be specific to this alert, not generic.

Then produce:

- overall_evidence_reliability — one of "high", "medium", "low":
  - "high": all critical sources present (rule_context, asset_context, cortex status known);
    only minor sources missing
  - "medium": 1-2 significant sources missing but core alert data is present; assessment is
    possible but hedged
  - "low": 3 or more significant sources missing, OR rule_context is missing (cannot
    validate what rule fired)

- analyst_must_verify — a list of specific tasks the analyst MUST perform manually because
  the automated pipeline could not retrieve the data and it is material to the verdict. Not
  everything missing — only what genuinely changes the assessment if found. Each item must
  be a concrete action, not a generic note.

Three critical distinctions you must apply:

For cortex_results: this is a property on canonical_alert, not a Stage 1 tool — but its
status matters for evidence quality.
- cortex_results non-empty with non-empty verdict fields -> analyzers ran, found something
  adverse
- cortex_results non-empty with all verdict fields empty -> analyzers ran, found nothing
  (real exculpatory signal — status "empty", treat as signal)
- cortex_results absent or null -> analyzers never ran (status "missing", treat as a gap)

For any field that is None or an empty list: check investigation_gaps to determine why.
- If a Gap exists for that tool -> status "missing", quote the reason from the Gap
- If no Gap but field is empty -> status "empty", the tool ran but found nothing

Never treat "missing" and "empty" as the same thing. The distinction between "checked and
found nothing" and "could not check" is load-bearing for Stage 4's reliability assessment."""


def build_user_prompt(evidence: EnrichedEvidence) -> str:
    return evidence.model_dump_json(indent=2)


def build_contextual_assessment_schema(evidence: RawEvidence) -> dict:
    """merge_into_case_id and action are constrained to this specific
    alert's real open_cases — see module docstring for the live-verified
    bug this closes. Deep-copies _BASE_SCHEMA so callers never mutate the
    shared template."""
    schema = copy.deepcopy(_BASE_SCHEMA)
    case_ids = [case.case_id for case in evidence.open_cases]
    correlation = schema["properties"]["correlation_decision"]["properties"]
    correlation["merge_into_case_id"]["enum"] = [*case_ids, None]
    correlation["action"]["enum"] = ["new", "merge"] if case_ids else ["new"]
    return schema


# Maps each extracted_observables bucket name to the single observable_type
# value its items must carry — see the enum comment inside _BASE_SCHEMA below.
# "process" -> "process-path" (renamed 2026-08-21, see schemas/assessment.py::
# ExtractedObservable's docstring): the bucket's items are always an
# executable path, and the type label now says so.
_BUCKET_TO_TYPE: dict[str, str] = {
    "process": "process-path",
    "file": "file",
    "external_ips": "ip",
    "domains": "domain",
    "urls": "url",
    "hash": "hash",
}


_BASE_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "refined_mitre_mapping": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "technique_id": {"type": "string"},
                    "technique_name": {"type": "string"},
                    "tactic": {"type": "string"},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                    "basis": {"type": "string"},
                },
                "required": ["technique_id", "technique_name", "tactic", "confidence", "basis"],
            },
        },
        "correlation_decision": {
            "type": "object",
            "properties": {
                # action.enum and merge_into_case_id.enum are placeholders —
                # build_contextual_assessment_schema() overwrites both per
                # call with this alert's real open_cases. Never send
                # _BASE_SCHEMA to the LLM directly.
                "action": {"type": "string", "enum": ["new"]},
                "merge_into_case_id": {"type": ["string", "null"], "enum": [None]},
                "kill_chain_progression_detected": {"type": "boolean"},
                "reasoning": {"type": "string"},
            },
            "required": [
                "action",
                "merge_into_case_id",
                "kill_chain_progression_detected",
                "reasoning",
            ],
        },
        "additional_investigation_gaps": {"type": "array", "items": {"type": "string"}},
        "extracted_observables": {
            "type": "object",
            "properties": {
                bucket: {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            # Constrained to a SINGLE value matching the bucket
                            # name, not the full 6-way enum — live-verified
                            # 2026-08-16: with the full enum shared across all
                            # buckets, the model filled every bucket with a
                            # mismatched type (process bucket -> "file", hash
                            # bucket -> "file", domains bucket -> "url", etc.),
                            # nothing structurally tying bucket identity to
                            # observable_type. See CLAUDE.md.
                            "observable_type": {
                                "type": "string",
                                "enum": [_BUCKET_TO_TYPE[bucket]],
                            },
                            "value": {"type": "string"},
                            "rationale": {"type": "string"},
                            "confidence": {
                                "type": "string",
                                "enum": ["high", "medium", "low"],
                            },
                            "source": {
                                "type": "string",
                                "enum": [
                                    "behavioral_analysis",
                                    "cortex_result",
                                    "command_line_parsing",
                                ],
                            },
                        },
                        "required": [
                            "observable_type",
                            "value",
                            "rationale",
                            "confidence",
                            "source",
                        ],
                    },
                }
                for bucket in ("process", "file", "external_ips", "domains", "urls", "hash")
            },
            "required": ["process", "file", "external_ips", "domains", "urls", "hash"],
        },
        # Hand-inlined flat (no $defs/$ref) — see module docstring's schema
        # note. Mirrors schemas.assessment.EvidenceSource/EvidenceSituation.
        "evidence_situation": {
            "type": "object",
            "properties": {
                "sources": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "source_name": {"type": "string"},
                            "status": {
                                "type": "string",
                                "enum": ["present", "empty", "missing"],
                            },
                            "impact_on_triage": {"type": "string"},
                        },
                        "required": ["source_name", "status", "impact_on_triage"],
                    },
                },
                "overall_evidence_reliability": {
                    "type": "string",
                    "enum": ["high", "medium", "low"],
                },
                "analyst_must_verify": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["sources", "overall_evidence_reliability", "analyst_must_verify"],
        },
    },
    "required": [
        "refined_mitre_mapping",
        "correlation_decision",
        "additional_investigation_gaps",
        "extracted_observables",
        "evidence_situation",
    ],
}

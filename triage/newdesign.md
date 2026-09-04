# SOC-3s v5 — LLM-Direct Priority Redesign
## Full Architecture Specification and Codebase Change Plan

**Status:** Pre-implementation specification  
**Replaces:** SOC-3s v4 scoring system (`scoring.py`, `scoring_config.py`, `nodes/score.py`)  
**Date:** 2026-08-25

---

## 1. Why This Redesign Exists

The v4 scoring system (`scoring.py`) was built around a weighted formula:

```
weighted = (0.40×L + 0.35×I + 0.25×C + 0.15×K) / 1.15
```

A systematic review of this formula against published risk frameworks identified two categories of problems. First, structural problems that cannot be fixed by tuning — addition allows high impact to compensate for low likelihood, confidence entered the formula as a scoring dimension when no published risk framework treats it that way, and `llm_criticality_score` was an uncalibrated number from the same LLM call with no ground truth. Second, every numeric constant in the formula (the weights, the severity table values, the tactic severity values, the asset criticality values, the penalty and bonus magnitudes) was chosen by intuition with no published reference, making the system impossible to defend to a security expert.

A search across nine real SOC triage systems — including CORTEX, AACT, AIP (Microsoft Defender), AlertPro, the AgentKits SOC Triage blueprint, Agentic SOC Triage, Triagewall, SecAlertBench, and the Microsoft Security Copilot Guided Response — found that none of them use a central 0-100 numeric risk score as the primary triage mechanism. All produce either a categorical verdict, a priority tier, or a queue ranking. The numeric score in v4 is an architectural pattern with no real-world precedent in deployed systems.

The v5 redesign removes the scoring stage entirely and moves priority determination into Stage 4's LLM reasoning, guided by a structured evidence-based rubric. This approach is validated by the PiSAs academic benchmark (peer-reviewed, 2026), the AgentKits production blueprint (deployed, open source), and the Sophos/AWS LLM benchmarking study which identified that rubric structure — not model capability — is the key determinant of classification reliability.

---

## 2. What Changes vs. What Stays

### What is removed

| Component | Reason |
|---|---|
| `nodes/score.py` | Entire Stage 5 node — deleted |
| `scoring.py` | All math functions — deleted |
| `scoring_config.py` | All tunable constants — deleted |
| `schemas/result.py` — `PriorityScore` class | No longer produced anywhere |
| `schemas/assessment.py` — `contextual_modifiers` field | Only fed `scoring.py` |
| `schemas/assessment.py` — `llm_criticality_score` field | Only fed `scoring.py` |
| `schemas/assessment.py` — `confidence` field | Replaced by `evidence_situation` |
| `schemas/assessment.py` — `ContextualModifier` class | Only fed `scoring.py` |
| `tests/test_scoring.py` | 93 tests, all deleted with `scoring.py` |
| `tests/test_score_node.py` | Deleted with `nodes/score.py` |
| Task 5 in `prompts/context_agent.py` | Criticality score task — replaced |
| `contextual_modifiers` section in `prompts/context_agent.py` | Removed |
| `contextual_modifiers` reference in `prompts/analyst_agent.py` | Removed |

### What is added

| Component | Purpose |
|---|---|
| `schemas/assessment.py` — `EvidenceSituation` class | New — replaces `confidence` |
| `schemas/assessment.py` — `EvidenceSource` class | New — per-source status entry |
| `schemas/verdict.py` — `priority_band` field | New — P1/P2/P3/P4/P5 directly |
| `schemas/verdict.py` — `priority_reasoning` field | New — rubric match explanation |
| `schemas/verdict.py` — `investigation_gaps` field | New — analyst task list |
| Task 5 in `prompts/context_agent.py` — evidence situation | New — replaces criticality score |
| Priority rubric in `prompts/analyst_agent.py` | New — evidence-grounded rubric |
| Evidence situation instructions in `prompts/analyst_agent.py` | New |
| Deterministic safety backstop in `nodes/analyze.py` | New — post-LLM gate |
| `schemas/result.py` — `TriageResult` simplified | Remove `PriorityScore` field, add `evidence_situation` pass-through |

### What is unchanged

| Component | Status |
|---|---|
| `nodes/gather.py` (Stage 1) | Zero changes |
| `nodes/rag.py` (Stage 2) | Zero changes |
| `nodes/case_action.py` (Stage 6) | Zero changes |
| `main.py` | Zero changes |
| All Stage 1 schemas | Zero changes |
| All Stage 2 schemas | Zero changes |
| `tools/thehive.py` | Zero changes |
| `tools/qdrant.py` | Zero changes |
| `tools/fp_tracking.py` | Zero changes |
| `tools/itop.py` | Zero changes |
| `tools/opencti.py` | Zero changes |
| `alert_builder.py` | Zero changes |
| Two-LLM-call limit | Preserved |
| Firewall boundary (Stage 3 sees all, Stage 4 sees summary) | Preserved |
| `json_schema` response format | Preserved |
| Hand-inlined flat schema requirement | Preserved |
| Dynamic enum constraints on `merge_into_case_id` | Preserved |
| Hallucination guards on observables | Preserved |
| `_extract_first_json_object` parsing | Preserved |
| `_capped_max_tokens` mechanism | Preserved |
| Fallback objects on LLM failure | Preserved (updated values) |

---

## 3. Stage 3 Redesign — `context_analysis()`

### Role (unchanged)

"A Tier-2 SOC analyst reviewing an alert investigation package." Sees the complete `EnrichedEvidence` object — everything Stage 1 and Stage 2 produced — serialized verbatim. This is the one place in the pipeline that sees everything.

### Input (unchanged)

Full `EnrichedEvidence` object via `evidence.model_dump_json(indent=2)`. All fields from Stage 1 (canonical_alert, fp_signal, rule_context, open_cases, closed_cases_summary, asset_context, related_alerts_24h, process_history_24h, opencti_enrichment, investigation_gaps) and Stage 2 (mitre_candidates, cve_matches, incident_matches). No truncation.

### System prompt changes

Tasks 1-4 (MITRE refinement, correlation decision, gap identification, observable extraction) are **unchanged**. The text, instructions, and constraints are identical to v4.

**Task 5 is replaced entirely.** The v4 Task 5 was:

> TASK 5 — CRITICALITY SCORE (0-100): A single holistic judgment...

This is removed. The v5 Task 5 is:

---

**TASK 5 — EVIDENCE SITUATION ASSESSMENT:**

For each of the following 8 evidence sources, assess its status and what that status means for the reliability of this triage. Produce one entry per source.

Sources to assess: `fp_signal`, `rule_context`, `open_cases`, `closed_cases_summary`, `asset_context`, `related_alerts_24h`, `process_history_24h`, `opencti_enrichment`.

For each source, produce:

- `source_name` — the name of the source as listed above
- `status` — one of three values:
  - `"present"` — the tool ran and returned usable data
  - `"empty"` — the tool ran but found nothing (this is signal, not a failure)
  - `"missing"` — the tool failed, timed out, or could not run (this is a reliability gap)
- `impact_on_triage` — one sentence explaining what this status means for how much the triage can be trusted. Be specific to this alert, not generic.

Then produce:

- `overall_evidence_reliability` — one of `"high"`, `"medium"`, `"low"`:
  - `"high"`: all critical sources present (rule_context, asset_context, cortex status known); only minor sources missing
  - `"medium"`: 1-2 significant sources missing but core alert data is present; assessment is possible but hedged
  - `"low"`: 3 or more significant sources missing, OR rule_context is missing (cannot validate what rule fired)

- `analyst_must_verify` — a list of specific tasks the analyst MUST perform manually because the automated pipeline could not retrieve the data and it is material to the verdict. Not everything missing — only what genuinely changes the assessment if found. Each item must be a concrete action, not a generic note.

**Three critical distinctions you must apply:**

For `cortex_results`: this is a property on `canonical_alert`, not a Stage 1 tool — but its status matters for evidence quality.
- `cortex_results` non-empty with non-empty `verdict` fields → analyzers ran, found something adverse
- `cortex_results` non-empty with all `verdict` fields empty → analyzers ran, found nothing (real exculpatory signal — status `"empty"`, treat as signal)
- `cortex_results` absent or null → analyzers never ran (status `"missing"`, treat as a gap)

For any field that is None or an empty list: check `investigation_gaps` to determine why.
- If a Gap exists for that tool → status `"missing"`, quote the reason from the Gap
- If no Gap but field is empty → status `"empty"`, the tool ran but found nothing

Never treat `"missing"` and `"empty"` as the same thing. The distinction between "checked and found nothing" and "could not check" is load-bearing for Stage 4's reliability assessment.

---

### Output schema changes — `ContextualAssessment`

**File: `schemas/assessment.py`**

**Remove:**
```python
class ContextualModifier(BaseModel):
    dimension: Literal["likelihood", "impact"]
    factor_name: str
    direction: Literal["increase", "decrease"]
    strength: Literal["weak", "medium", "strong", "critical"]
    reasoning: str

# In ContextualAssessment:
contextual_modifiers: list[ContextualModifier]
confidence: Literal["high", "medium", "low"]
llm_criticality_score: int  # 0-100
```

**Add:**
```python
class EvidenceSource(BaseModel):
    source_name: str
    status: Literal["present", "empty", "missing"]
    impact_on_triage: str

class EvidenceSituation(BaseModel):
    sources: list[EvidenceSource]
    overall_evidence_reliability: Literal["high", "medium", "low"]
    analyst_must_verify: list[str]

# In ContextualAssessment:
evidence_situation: EvidenceSituation
```

**Final `ContextualAssessment` shape:**
```python
class ContextualAssessment(BaseModel):
    refined_mitre_mapping: list[MitreMapping]
    correlation_decision: CorrelationDecision
    additional_investigation_gaps: list[str]
    extracted_observables: ExtractedObservables
    evidence_situation: EvidenceSituation        # NEW — replaces confidence + contextual_modifiers + llm_criticality_score
    stage_3_duration_ms: int                      # set post-hoc
```

### Fallback changes — `_stage_3_fallback`

**File: `nodes/context.py`**

The fallback no longer sets `contextual_modifiers`, `confidence`, or `llm_criticality_score`. It sets `evidence_situation` deterministically from `investigation_gaps`:

```python
def _stage_3_fallback(evidence: EnrichedEvidence) -> ContextualAssessment:
    # Build evidence_situation from what Stage 1 actually reported
    source_names = [
        "fp_signal", "rule_context", "open_cases", "closed_cases_summary",
        "asset_context", "related_alerts_24h", "process_history_24h", "opencti_enrichment"
    ]
    gap_sources = {g.tool for g in evidence.investigation_gaps}
    sources = []
    for name in source_names:
        if name in gap_sources:
            status = "missing"
            impact = f"{name} unavailable — Stage 3 LLM also failed; cannot assess impact."
        else:
            status = "present"
            impact = f"{name} data available but Stage 3 LLM failed — assessment not performed."
        sources.append(EvidenceSource(source_name=name, status=status, impact_on_triage=impact))

    evidence_situation = EvidenceSituation(
        sources=sources,
        overall_evidence_reliability="low",
        analyst_must_verify=["Stage 3 LLM call failed — complete manual review required. "
                              "All automated evidence interpretation is unavailable."]
    )

    return ContextualAssessment(
        refined_mitre_mapping=_mitre_from_rule_context(evidence),  # unchanged logic
        correlation_decision=_correlation_from_open_cases(evidence),  # unchanged logic
        additional_investigation_gaps=["Stage 3 LLM call failed"],
        extracted_observables=ExtractedObservables(),
        evidence_situation=evidence_situation,
        stage_3_duration_ms=0,
    )
```

### Schema hand-inlining changes

**File: `prompts/context_agent.py`**

`_BASE_SCHEMA` and `build_contextual_assessment_schema()` must be updated to remove `contextual_modifiers`, `confidence`, `llm_criticality_score` and add `evidence_situation` with its nested structure.

`EvidenceSituation` and `EvidenceSource` must be hand-inlined flat (no `$defs`/`$ref`) following the same pattern as all other schemas in this codebase. The `TestSchemaStaysInSync` test must be updated to guard the new fields.

---

## 4. Stage 4 Redesign — `analyst_verdict()`

### Role (unchanged)

"A Tier-2 SOC analyst making the final triage call." Sees a sanitized summary, not raw evidence — the prompt injection firewall boundary is preserved.

### Pre-LLM work (unchanged)

If `correlation_decision.action == "merge"`: fetch existing case observables from TheHive (5s timeout, never raises).

Always: fetch runbook matches from Qdrant using `refined_mitre_mapping` (3s timeout, never raises).

### Input summary changes

**File: `nodes/analyze.py` — `_summarize_evidence()`**

The summary passed to Stage 4's LLM changes in two ways:

**Removed from summary:**
```python
# REMOVED — contextual_modifiers no longer exists
"contextual_modifiers": context.contextual_modifiers,
```

**Replaced:**
```python
# BEFORE (v4):
"investigation_gaps": context.additional_investigation_gaps,

# AFTER (v5):
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
```

All other summary fields (known_observables, extracted_observables, case_observables, runbook_matches, rule_context, asset_context, threat_intel, temporal_context, historical_context, mitre_mapping) are **unchanged**.

### System prompt changes

**File: `prompts/analyst_agent.py`**

Two sections are removed, three sections are added.

**Removed:**
- All references to `contextual_modifiers` (the field no longer exists in the summary)
- Any instructions about interpreting modifier `dimension`, `direction`, `strength`

**Added — PRIORITY RUBRIC section:**

```
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
```

**Added — EVIDENCE SITUATION INSTRUCTIONS section:**

```
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
```

**Added — INVESTIGATION GAPS instructions section:**

```
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
   explanation — process_history_24h was unavailable."
```

### Output schema changes — `TriageVerdict`

**File: `schemas/verdict.py`**

**Add three new fields:**
```python
class TriageVerdict(BaseModel):
    # Existing fields — unchanged:
    likelihood: Literal["unlikely", "possible", "likely", "near_certain"]
    impact_if_true: Literal["minor", "moderate", "significant", "severe"]
    verdict: Literal["true_positive", "false_positive", "needs_review"]
    reasoning: str
    summary: str
    recommended_action: Literal[
        "create_case", "close_fp", "merge_quiet", "merge_and_retier", "needs_review"
    ]
    evidence_citations: list[str]
    actionable_observables: list[ActionableObservable]
    runbook_matches: list[PlaybookMatch]   # set post-hoc
    stage_4_duration_ms: int               # set post-hoc

    # NEW fields:
    priority_band: Literal["P1", "P2", "P3", "P4", "P5"]
    priority_reasoning: str   # which rubric condition fired and why, citing evidence fields
    investigation_gaps: list[str]   # analyst task list
```

`likelihood` and `impact_if_true` remain. They are the LLM's dimensional assessment of the alert, useful for the analyst reading the case and for the audit trail. They are produced in the same reasoning pass as `priority_band`. They are NOT inputs to the rubric — the rubric runs on evidence fields directly. There is no circular dependency.

### Fallback changes — `_stage_4_fallback`

**File: `nodes/analyze.py`**

The fallback now sets `priority_band = "P2"` (upgraded from the implied P3 of previous design) and populates the new fields:

```python
def _stage_4_fallback(...) -> TriageVerdict:
    return TriageVerdict(
        likelihood="possible",
        impact_if_true="moderate",
        verdict="needs_review",
        reasoning="Stage 4 LLM call failed — fallback applied.",
        summary="Automated triage failed. Manual review required.",
        recommended_action="needs_review",
        evidence_citations=[],
        actionable_observables=[],
        runbook_matches=[],
        stage_4_duration_ms=0,
        # NEW:
        priority_band="P2",
        priority_reasoning=(
            "Stage 4 LLM call failed — priority defaulted to P2 to ensure human review. "
            "A failed pipeline cannot safely be treated as low-risk."
        ),
        investigation_gaps=[
            "Stage 4 LLM failed — complete manual triage required. "
            "No automated assessment was produced."
        ],
    )
```

Rationale for P2 as the fallback (not P3): when Stage 4 fails, the pipeline has no verdict. A failed pipeline cannot safely produce a low-priority result. P2 guarantees the alert reaches an analyst this shift.

### Post-LLM deterministic safety backstop

**File: `nodes/analyze.py` — new function, called immediately after parsing Stage 4's output**

```python
def _apply_safety_backstop(
    verdict: TriageVerdict,
    context: ContextualAssessment,
) -> tuple[TriageVerdict, bool]:
    """
    Deterministic safety gate applied after Stage 4 LLM output is parsed.
    
    If evidence reliability is low AND the LLM assigned P4 or P5, escalate
    by one band. This catches cases where the LLM ignored the evidence
    situation instructions in the prompt.
    
    Returns the (possibly modified) verdict and a boolean indicating
    whether the gate fired.
    """
    if context.evidence_situation.overall_evidence_reliability != "low":
        return verdict, False

    escalation_map = {"P5": "P4", "P4": "P3"}
    if verdict.priority_band not in escalation_map:
        return verdict, False

    new_band = escalation_map[verdict.priority_band]
    new_reasoning = (
        verdict.priority_reasoning
        + f"\n\n[SAFETY GATE APPLIED]: Priority escalated from "
        f"{verdict.priority_band} to {new_band}. Evidence reliability was "
        f"'low' — automated triage cannot safely close or defer this alert. "
        f"A human analyst must review."
    )

    updated = verdict.model_copy(update={
        "priority_band": new_band,
        "priority_reasoning": new_reasoning,
    })
    return updated, True
```

This gate runs deterministically in code. It is belt-and-suspenders behind the prompt instruction. It catches the case where the LLM ignores the evidence reliability floor.

### Schema hand-inlining changes

**File: `prompts/analyst_agent.py`**

`_BASE_SCHEMA` and `build_triage_verdict_schema()` must add `priority_band` (enum `["P1","P2","P3","P4","P5"]`), `priority_reasoning` (string), `investigation_gaps` (array of strings), and remove any `contextual_modifiers`-related processing.

`TestSchemaStaysInSync` in `tests/test_analyze.py` must be updated to guard the new fields.

---

## 5. Stage 5 — Deleted Entirely

**File: `nodes/score.py`** → deleted  
**File: `scoring.py`** → deleted  
**File: `scoring_config.py`** → deleted

The pipeline chain in `main.py` currently calls:

```python
context = await context_analysis(evidence)
verdict = await analyst_verdict(context, evidence)
result = priority_scoring(verdict, context, evidence)   # Stage 5 — REMOVE THIS CALL
case_result = await case_action(result, evidence)
```

After removal:

```python
context = await context_analysis(evidence)
verdict = await analyst_verdict(context, evidence)
result = _build_triage_result(verdict, context, evidence)  # new thin builder
case_result = await case_action(result, evidence)
```

`_build_triage_result` is a new thin function in `main.py` (or a new `nodes/result.py`) that assembles `TriageResult` from the Stage 3 and Stage 4 outputs without any math.

---

## 6. `TriageResult` Schema Changes

**File: `schemas/result.py`**

`PriorityScore` is removed entirely. `TriageResult` is simplified:

**Remove from `TriageResult`:**
```python
priority_score: PriorityScore   # the entire numeric score object — gone
```

**Add to `TriageResult`:**
```python
# Priority fields — now come directly from TriageVerdict
priority_band: str              # copied from verdict.priority_band
priority_reasoning: str         # copied from verdict.priority_reasoning
investigation_gaps: list[str]   # copied from verdict.investigation_gaps
safety_gate_applied: bool       # True if backstop escalated the band

# Evidence situation — passed through from Stage 3
evidence_situation: EvidenceSituation
```

**Convenience flat fields that previously came from `PriorityScore`:**
The following fields on `TriageResult` that currently come from `priority_score.*` now come directly from `verdict.*` or `context.*`:

```python
# These move source, not disappear:
likelihood: str             # from verdict.likelihood_label (unchanged)
impact_if_true: str         # from verdict.impact_if_true (unchanged)
verdict_str: str            # from verdict.verdict (unchanged)
```

The `score` (int 0-100), `base_likelihood`, `adjusted_likelihood`, `base_impact`, `adjusted_impact`, `base_confidence`, `velocity_multiplier`, `llm_criticality_score`, `confidence_gate_applied`, `likelihood_modifiers_applied`, `impact_modifiers_applied`, and `final_score_calculation` fields are all **removed with no replacement**. They were artifacts of the formula.

---

## 7. `TriageResponse` — HTTP Output Changes

**File: `main.py` — `POST /triage` response**

The `/triage` response currently includes `priority_score` as a nested object containing the full numeric audit trail. This field is removed.

The response now includes `priority_band`, `priority_reasoning`, `investigation_gaps`, `safety_gate_applied`, and `evidence_situation` at the top level of the response (or nested under a `triage_result` envelope — whichever the current structure uses).

Downstream consumers (n8n, TheHive automation) that read `priority_score.priority` must be updated to read `priority_band` instead. TheHive's severity mapping in `nodes/case_action.py` currently uses:

```python
PRIORITY_TO_HIVE_SEVERITY = {"P1": 4, "P2": 3, "P3": 2, "P4": 1, "P5": 1}
```

This mapping is moved from `scoring_config.py` (which is deleted) into `nodes/case_action.py` directly as a module-level constant. The mapping itself is unchanged.

---

## 8. Stage 6 — Case Action

**File: `nodes/case_action.py`**

Stage 6 reads three things from the triage result to write to TheHive:

1. `recommended_action` → drives create vs. merge branching — **unchanged source field**
2. `actionable_observables` → written as case observables — **unchanged source field**  
3. `priority_band` → mapped to TheHive severity via `PRIORITY_TO_HIVE_SEVERITY` — **source changes from `priority_score.priority` to `verdict.priority_band`**

Only the field access path changes. The logic is unchanged.

Case title, description, and tags constructed in Stage 6 currently include references to the score (`score=69, P2`). These are updated to use `priority_band` and `priority_reasoning` instead:

```python
# BEFORE:
title = f"[{priority_score.priority}] {rule_name} — score {priority_score.score}"
description_header = f"Priority: {priority_score.priority} (score: {priority_score.score})"

# AFTER:
title = f"[{verdict.priority_band}] {rule_name}"
description_header = (
    f"Priority: {verdict.priority_band}\n"
    f"Reasoning: {verdict.priority_reasoning}"
)
```

---

## 9. Final Output — What Reaches TheHive

The seven final outputs you specified, and where each comes from in the new design:

| Required output | Source in new design |
|---|---|
| **Prioritization** | `TriageVerdict.priority_band` (P1-P5) + `TriageVerdict.priority_reasoning` |
| **Summary** | `TriageVerdict.summary` (unchanged) |
| **Correlation decision** | `ContextualAssessment.correlation_decision` (unchanged — merge/new, kill-chain, merge target) |
| **Verdict** | `TriageVerdict.verdict` (TP/FP/needs_review) + `TriageVerdict.likelihood` + `TriageVerdict.impact_if_true` |
| **Actionable observables** | `TriageVerdict.actionable_observables` (unchanged — all observables with disposition + confidence) |
| **Evidence situation** | `ContextualAssessment.evidence_situation` (new — per-source status + overall reliability + must-verify list) |
| **Recommendation** | `TriageVerdict.recommended_action` + `TriageVerdict.runbook_matches` (unchanged) |
| **Investigation gaps** | `TriageVerdict.investigation_gaps` (new — analyst task list consolidating Stage 3 must-verify items + Stage 4 follow-ups) |

---

## 10. Test Suite Changes

### Tests to delete
- `tests/test_scoring.py` — 93 tests, all exercise `scoring.py` functions that no longer exist
- `tests/test_score_node.py` — exercises `nodes/score.py` which is deleted

### Tests to update
- `tests/test_context.py::TestSchemaStaysInSync` — update expected schema to match new `ContextualAssessment` fields
- `tests/test_analyze.py::TestSchemaStaysInSync` — update expected schema to match new `TriageVerdict` fields
- Any test that accesses `result.priority_score.*` — update to `result.priority_band`, `result.priority_reasoning`, etc.
- Any test that accesses `context.contextual_modifiers` — remove or replace
- Any test that accesses `context.llm_criticality_score` — remove
- Any test that accesses `context.confidence` — replace with `context.evidence_situation.overall_evidence_reliability`
- Fallback tests in `test_context.py` — update expected fallback output to match new fallback structure
- Fallback tests in `test_analyze.py` — update expected `priority_band`, `priority_reasoning`, `investigation_gaps` values

### Tests to add
- `tests/test_evidence_situation.py` — test `EvidenceSituation` and `EvidenceSource` construction, status assignment logic, fallback deterministic build from `investigation_gaps`
- `tests/test_priority_backstop.py` — test `_apply_safety_backstop`: fires when reliability=low and band is P4/P5, does not fire when reliability=medium or high, does not fire when band is P1/P2/P3
- `tests/test_analyze.py` — add tests for new `priority_band`, `priority_reasoning`, `investigation_gaps` fields in normal and fallback paths
- `tests/test_triage_result.py` — add tests for new `TriageResult` shape without `PriorityScore`

### Mutation tests to run on new code
Per this project's test discipline, these specific mutations must be verified to turn tests red before the redesign is considered complete:

| Mutation | Should be caught by |
|---|---|
| Change backstop from `< "P3"` to `<= "P3"` (fires on P3 too) | `test_priority_backstop` |
| Change backstop reliability check from `"low"` to `"medium"` (too aggressive) | `test_priority_backstop` |
| Remove `analyst_must_verify` from fallback (empty list on Stage 3 failure) | `test_evidence_situation` |
| Set `priority_band = "P5"` in Stage 4 fallback (too lenient) | `test_analyze — fallback` |
| Drop `investigation_gaps` pass-through into `TriageResult` | `test_triage_result` |

---

## 11. Implementation Order

The order below ensures at each step the system remains runnable and testable.

**Step 1 — Schema changes only (no behavior change yet)**
- Add `EvidenceSource`, `EvidenceSituation` to `schemas/assessment.py`
- Add `priority_band`, `priority_reasoning`, `investigation_gaps` to `schemas/verdict.py`
- Remove `ContextualModifier`, `contextual_modifiers`, `confidence`, `llm_criticality_score` from `schemas/assessment.py`
- Update `TestSchemaStaysInSync` in both test files
- Run full test suite — only schema sync tests should change

**Step 2 — Stage 3 prompt and fallback**
- Replace Task 5 in `prompts/context_agent.py`
- Update `_BASE_SCHEMA` in `prompts/context_agent.py`
- Update `_stage_3_fallback` in `nodes/context.py`
- Add `tests/test_evidence_situation.py`
- Run full test suite — Stage 3 tests update, scoring tests still pass (scoring.py still exists)

**Step 3 — Stage 4 prompt, summary, fallback, and backstop**
- Update `_summarize_evidence()` in `nodes/analyze.py` to pass `evidence_situation`, remove `contextual_modifiers`
- Add priority rubric, evidence situation instructions, investigation gaps instructions to `prompts/analyst_agent.py`
- Update `_BASE_SCHEMA` in `prompts/analyst_agent.py`
- Update `_stage_4_fallback` in `nodes/analyze.py`
- Add `_apply_safety_backstop` in `nodes/analyze.py`, wire it into the post-parse path
- Add `tests/test_priority_backstop.py`
- Update `tests/test_analyze.py`
- Run full test suite — Stage 4 tests update, scoring tests still pass

**Step 4 — Remove Stage 5 and rebuild TriageResult**
- Delete `nodes/score.py`, `scoring.py`, `scoring_config.py`
- Delete `PriorityScore` from `schemas/result.py`, rebuild `TriageResult`
- Add `_build_triage_result()` in `main.py` (or `nodes/result.py`)
- Update `main.py` pipeline chain to remove Stage 5 call
- Update `PRIORITY_TO_HIVE_SEVERITY` in `nodes/case_action.py` (move from deleted `scoring_config.py`)
- Update field access in `nodes/case_action.py` from `priority_score.priority` to `verdict.priority_band`
- Delete `tests/test_scoring.py`, `tests/test_score_node.py`
- Update `tests/test_triage_result.py`
- Run full test suite — should pass with fewer tests total (93 scoring tests gone)

**Step 5 — Integration and live verification**
- Run a real alert end-to-end via `POST /triage`
- Verify `TriageResponse` contains `priority_band`, `priority_reasoning`, `investigation_gaps`, `evidence_situation`
- Verify `priority_band` appears in the TheHive case title and maps correctly to TheHive severity
- Verify `investigation_gaps` appears in the case description
- Verify `safety_gate_applied` field is present and correct

---

## 12. What Is Explicitly Not Changing

These decisions were reviewed and confirmed as correct for this architecture. They are documented here to prevent re-litigation.

**The two-LLM-call limit** is preserved. The priority determination moves inside Stage 4, not into a third call.

**The firewall boundary** is preserved. Stage 4 still sees only a sanitized summary. The evidence situation structured object from Stage 3 passes through the summary — it is deliberately structured (not raw JSON) so it cannot carry prompt-injection payloads from the evidence.

**`likelihood` and `impact_if_true` as Stage 4 outputs** are preserved. They are produced in the same reasoning pass as `priority_band`. They are useful for the analyst and the audit trail. They are not inputs to the rubric and do not create circularity.

**The dynamic enum constraints** on `merge_into_case_id` are preserved unchanged.

**The hallucination guards on observables** (`_validate_extracted_observables`, `_validate_actionable_observables`) are preserved unchanged.

**Stage 6 (`case_action.py`) logic** is preserved. Only the field access path for priority changes.

**The `_extract_first_json_object` parse** is preserved.

**The `_capped_max_tokens` mechanism** is preserved. Stage 4's prompt is now longer (rubric + evidence situation instructions added), so the cap may fire more aggressively. The `STAGE_4_DESIRED_MAX_TOKENS` setting should be reviewed against real prompt sizes after implementation.

---

## 13. Citation Basis for This Design

| Design decision | Source |
|---|---|
| Remove numeric score, use priority band directly | Consensus of 9 reviewed systems — none use a central 0-100 score |
| Three-question rubric structure | PiSAs benchmark (arXiv:2607.05318, 2026) — peer-reviewed severity classification design |
| P5 requires positive exculpatory evidence | AgentKits SOC Triage blueprint (agent-kits.com, 2026) — production open-source |
| Confidence as gate, not formula dimension | NIST SP 800-30 Rev 1 — no published risk framework includes confidence in the risk formula |
| LLM-classifies, formula-scores pattern | POLAR (arXiv:2510.01552) — LLM produces categorical labels, deterministic logic converts |
| Evidence situation as structured assessment | GS Consulting AI Triage Guide (2026) — "confidence score becomes useful only after source health is visible" |
| Rubric structure matters more than model | Sophos/AWS LLM benchmark (sophos.com, 2024) — none of the models exceeded 30% accuracy without structure |
| Safety backstop for low-evidence escalation | L2DHF (arXiv:2506.18462) — deferring uncertain alerts to human review achieves 13-16% higher accuracy |
| Fallback defaults to P2 not P3 | Conservative failure design: degraded pipeline → more human attention, not less |
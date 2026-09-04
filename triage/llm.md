# LLM Usage in SOC-3s

This document collects **everything related to the LLM** in this pipeline: which
stages call it, what model/endpoint config governs each call, what each call's
input and output actually are (with schemas), and the safety/fallback machinery
around each call.

Per `CLAUDE.md`'s hard constraint: **exactly 2 LLM calls per alert, total, in the
whole pipeline** — Stage 3 (`nodes/context.py`) and Stage 4 (`nodes/analyze.py`).
Neither call has tool access; both are single-shot chat-completions requests.
No ReAct loop, no agentic tool-calling, no retries-as-a-loop.

---

## 1. Where the LLM sits in the pipeline

```
Stage 1 (gather.py)   — deterministic tool calls only, no LLM
Stage 2 (rag.py)      — deterministic Qdrant retrieval only, no LLM
Stage 3 (context.py)  — LLM CALL #1 — ContextualAssessment
Stage 4 (analyze.py)  — LLM CALL #2 — TriageVerdict
Stage 5 (score.py)    — pure functions (scoring.py), no LLM
Stage 6 (case_action.py) — TheHive writes, no LLM
```

Stage 3's output (`ContextualAssessment`) feeds Stage 4 as one of its two
inputs. Stage 4's output (`TriageVerdict`) feeds Stage 5's scoring and Stage
6's case-write. **`scoring.py` is the only place in the whole codebase a
numeric score is computed** — neither LLM stage outputs a bare number for
likelihood/impact; they output labeled enums that `scoring.py` maps to
numbers downstream.

---

## 2. Model / endpoint configuration (`config.py`)

Both stages can point at independent backends — in practice this deployment
has run them against the same backend at different times (Ollama,
vLLM/Colab, Gemini — see `CLAUDE.md`'s deployment log for the full history
of backend swaps).

| Variable | Purpose | Default |
|---|---|---|
| `LLM_BASE_URL` | Stage 3's chat-completions endpoint (OpenAI-compatible, `/chat/completions` appended) | required |
| `LLM_MODEL` | Stage 3's model name | required |
| `LLM_API_KEY` | Stage 3's bearer token | `sk-no-auth` |
| `LLM_ANALYZE_BASE_URL` | Stage 4's endpoint | falls back to `LLM_BASE_URL` |
| `LLM_ANALYZE_MODEL` | Stage 4's model | falls back to `LLM_MODEL` |
| `LLM_ANALYZE_API_KEY` | Stage 4's bearer token | falls back to `LLM_API_KEY` |
| `STAGE_3_LLM_TIMEOUT` | httpx timeout (seconds) on the Stage 3 call | `120.0` (this deployment's `.env` sets `600`) |
| `STAGE_4_LLM_TIMEOUT` | httpx timeout (seconds) on the Stage 4 call | `180.0` (this deployment's `.env` sets `600`) |
| `STAGE_3_DESIRED_MAX_TOKENS` | requested completion tokens for Stage 3, before capping | `4000` |
| `STAGE_4_DESIRED_MAX_TOKENS` | requested completion tokens for Stage 4, before capping | `2000` |
| `LLM_MAX_CONTEXT_TOKENS` | model's real context window, used for capping | `8192` |
| `LLM_TOKEN_ESTIMATE_CHARS_PER_TOKEN` | chars-per-token estimate (no local tokenizer available) | `3.2` |
| `LLM_CONTEXT_SAFETY_MARGIN_TOKENS` | reserved headroom subtracted from the window | `400` |
| `LLM_MIN_COMPLETION_TOKENS` | floor so a huge prompt still requests *some* completion room | `500` |
| `STAGE_4_TOOL_TIMEOUT_THEHIVE` | timeout for Stage 4's own non-LLM TheHive fetch (case observables) | `5.0` |
| `STAGE_4_TOOL_TIMEOUT_QDRANT` | timeout for Stage 4's own non-LLM Qdrant fetch (runbooks) | `3.0` |

**This deployment currently runs `foundation-sec-reasoning:latest` for
both stages** (architecture originally specified two different models —
`qwen3.5:4b` for Stage 3, `foundation-sec-reasoning` for Stage 4 — but the
Ollama host here only carries one reasoning-capable model). See
`CLAUDE.md` for the accepted latency trade-off (~60–90s Stage 3, pushing
p95 end-to-end toward ~200s).

### Request shape (both stages)

Both calls are plain OpenAI-compatible chat completions:

```jsonc
POST {base_url}/chat/completions
Authorization: Bearer {api_key}
{
  "model": "...",
  "messages": [
    {"role": "system", "content": "<SYSTEM_PROMPT>"},
    {"role": "user", "content": "<built user prompt, JSON>"}
  ],
  "response_format": {
    "type": "json_schema",
    "json_schema": {"name": "...", "schema": {...}}
  },
  "temperature": 0.1,
  "max_tokens": <capped>,
  "stream": false
}
```

### `max_tokens` capping (`_capped_max_tokens`, duplicated in both node files)

```
estimated_prompt_tokens = len(system_prompt + user_prompt) / LLM_TOKEN_ESTIMATE_CHARS_PER_TOKEN
available = LLM_MAX_CONTEXT_TOKENS - estimated_prompt_tokens - LLM_CONTEXT_SAFETY_MARGIN_TOKENS
max_tokens = max(LLM_MIN_COMPLETION_TOKENS, min(desired, available))
```

Exists because a real evidence-rich alert's prompt + the old fixed
`max_tokens` literal overflowed the model's context window and the backend
rejected the request outright (HTTP 400) — see `CLAUDE.md`'s 2026-08-23
entries for the two live-caught calibration rounds.

### `response_format`: hand-inlined JSON Schema, never `model_json_schema()`

Both `prompts/context_agent.py::_BASE_SCHEMA` and
`prompts/analyst_agent.py::_BASE_SCHEMA` are **hand-written, flat JSON
Schema with zero `$defs`/`$ref`** — never generated from
`ContextualAssessment.model_json_schema()` / `TriageVerdict.model_json_schema()`.

Reason (live-verified 2026-08-16): Ollama's grammar compiler under
`response_format: {"type": "json_schema", ...}` **hung for 280+ seconds**
on a `$ref`-based schema; the identical schema hand-inlined completed in
68.9s with clean output. `tests/test_context.py::TestSchemaStaysInSync` and
`tests/test_analyze.py::TestSchemaStaysInSync` guard against the two
representations drifting apart when a Pydantic model field changes.

Both schemas are also **rebuilt per call**, not static constants — each
call dynamically constrains an enum to the specific alert's real state
(see §3 and §4 below), making certain classes of LLM mistake structurally
unrepresentable rather than merely discouraged.

### Response parsing — `_extract_first_json_object`

Both nodes parse the response with:

```python
json.JSONDecoder().raw_decode(content.strip())[0]
```

i.e. **only the first JSON value in the string is trusted**, never a plain
`json.loads()` on the whole string. Reason (live-verified): under plain
`{"type": "json_object"}` mode, `foundation-sec-reasoning:latest` was
observed emitting one valid JSON object and then continuing —
hallucinated extra prose/JSON "Would you like another?" turns appended
after it. `json_schema` mode didn't reproduce this in testing, but the
defensive parse is kept regardless since nothing guarantees a different
prompt shape can't trigger it.

### Never raises — deterministic fallback on any failure

Neither `context_analysis` nor `analyst_verdict` is built on the shared
`nodes/_guard.py` wrapper (that pattern is for Stage 1/2's *parallel*
tool calls; these are single sequential calls where `httpx`'s own
`timeout=` is the only layer needed). Instead each wraps its own
call+parse+validate in a bare `try/except Exception`, and **any** failure
(connection error, timeout, non-2xx, malformed JSON, failed Pydantic
validation) produces a deterministic fallback object of the exact same
output type — nothing downstream can tell which path ran except by
reading `confidence` / `verdict`.

---

## 3. Stage 3 — `context_analysis` (`nodes/context.py`, `prompts/context_agent.py`)

**"A Tier-2 SOC analyst reviewing an alert investigation package."** Sees
*everything* Stage 1+2 produced — no summarization or firewall (that's
Stage 4's job).

### Input

The full `EnrichedEvidence` object (Stage 1 `RawEvidence` + Stage 2 RAG
enrichment), serialized verbatim via `evidence.model_dump_json(indent=2)`
as the user message. No truncation.

`EnrichedEvidence` (`schemas/evidence.py`) fields:

| Field | Type | Source |
|---|---|---|
| `canonical_alert` | `CanonicalAlert` | alert_builder.py, from raw_alert + hive_alert |
| `fp_signal` | `FPSignal \| None` | `tools/fp_tracking.py` — rule/host FP counts (24h/30d) |
| `rule_context` | `RuleContext \| None` | `detection_rule_lookup` — Sigma/Suricata rule metadata, MITRE tags, falsepositives, status |
| `open_cases` | `list[ShallowCase]` | TheHive currently-open cases — **the only valid merge targets** |
| `closed_cases_summary` | `ClosedCasesSummary` | TP/FP/other counts from closed cases matched by rule/observables |
| `asset_context` | `AssetContext \| None` | iTop CMDB — criticality, owner, etc. |
| `related_alerts_24h` | `list[AlertSummary]` | ES — related alerts in the last 24h |
| `process_history_24h` | `list[ProcessEvent]` | ES — process history for the host |
| `opencti_enrichment` | `list[OpenCTIEnrichment]` | OpenCTI GraphQL — known-indicator graph context |
| `investigation_gaps` | `list[Gap]` | anything Stage 1 couldn't gather, and why |
| `mitre_candidates` | `list[MitreCandidate]` | Qdrant `mitre_techniques` semantic hits |
| `cve_matches` | `list[CveMatch]` | Qdrant `cve_context` hits |
| `incident_matches` | `list[IncidentMatch]` | Qdrant `incident_history` hits — **similar past incidents, reference only, never a merge target** |
| `cortex_results` (property) | `list[CortexResult]` | pre-filtered to only `malicious`/`suspicious` verdicts |

Key system-prompt distinctions the model is told explicitly:
- `open_cases` (real, currently open) vs `incident_matches` (semantically
  similar past incidents, reference-only, never mergeable) — the exact
  confusion that caused a real bug on 2026-08-16 (see §5).
- `cortex_results[].verdict` is pre-filtered — empty means "no adverse
  finding", not "clean" and not "no data".

### Output — `ContextualAssessment` (`schemas/assessment.py`)

```python
class ContextualAssessment(BaseModel):
    refined_mitre_mapping: list[MitreMapping]        # validated/refined ATT&CK techniques
    correlation_decision: CorrelationDecision          # merge vs new
    contextual_modifiers: list[ContextualModifier]     # non-numeric signals scoring.py can't see
    additional_investigation_gaps: list[str]
    confidence: Literal["high", "medium", "low"]
    extracted_observables: ExtractedObservables         # new IOCs the automated pipeline missed
    llm_criticality_score: int                          # 0-100, holistic
    stage_3_duration_ms: int                             # set post-hoc, not by the LLM
```

- `MitreMapping`: `technique_id`, `technique_name`, `tactic`,
  `confidence` (high/medium/low), `basis`.
- `CorrelationDecision`: `action` (`"new" | "merge"`, **enum dynamically
  restricted to `["new"]` when there are no open cases**),
  `merge_into_case_id` (**enum dynamically restricted to this alert's
  real `open_cases` ids + `null`**), `kill_chain_progression_detected`,
  `reasoning`.
- `ContextualModifier`: `dimension` (likelihood/impact), `factor_name`,
  `direction` (increase/decrease), `strength` (weak/medium/strong/critical),
  `reasoning`. Feeds `scoring.py` as an augmenting signal — never a raw
  number.
- `ExtractedObservables`: six typed buckets — `process` (→
  `"process-path"`), `file`, `external_ips` (→ `"ip"`), `domains`, `urls`,
  `hash` — each item has `observable_type` (schema-constrained to match
  its bucket), `value`, `rationale`, `confidence`, `source`
  (`behavioral_analysis` / `cortex_result` / `command_line_parsing`).
- `llm_criticality_score`: a single 0–100 holistic judgment, banded in the
  prompt (0–20 almost-certainly-benign … 81–100 highly critical). Feeds
  `scoring.py` as a fourth weighted, augmenting component — never
  replaces the deterministic formula.

The **fallback** (`_stage_3_fallback`, on any LLM failure):
`confidence="low"`, `refined_mitre_mapping` preserved from
`rule_context.mitre_attack` (never emptied — the v3 "silent severity cap"
bug this deliberately avoids), `correlation_decision` derived directly
from `evidence.open_cases` (merge into first open case if any, else new),
`extracted_observables` empty, `llm_criticality_score=50` (neutral) — a
downed LLM never fabricates an IOC or a criticality judgment.

### Post-parse validation (defense-in-depth, both live-caught bugs)

- `_validate_merge_target` — discards `merge_into_case_id` if it isn't
  actually in `evidence.open_cases` (schema enum is the primary defense;
  this is the backstop for when enforcement doesn't hold).
- `_validate_extracted_observables` — discards any extracted value not
  traceable verbatim to the evidence JSON (hallucination guard) and any
  value that duplicates something `canonical_alert.observables` already
  captured (redundancy guard). Uses `json.dumps(value,
  ensure_ascii=False)[1:-1]` to escape the needle before the substring
  check — a real bug (2026-08-23) where an un-escaped Windows path
  (`C:\Windows\Temp\xordump.exe`) was wrongly discarded because
  `model_dump_json()`'s haystack has `\` doubled.

---

## 4. Stage 4 — `analyst_verdict` (`nodes/analyze.py`, `prompts/analyst_agent.py`)

**"A Tier-2 SOC analyst making the final triage call."** Sees a
*sanitized summary*, not raw evidence — the "prompt injection firewall"
architecture requires. Two non-LLM lookups happen first (never raise,
self-timeout):

1. If `correlation_decision.action == "merge"`:
   `tools.thehive.fetch_case_observables_with_type(merge_into_case_id)` —
   the merge target's existing observables (`STAGE_4_TOOL_TIMEOUT_THEHIVE`).
2. Always: `tools.qdrant.retrieve_playbooks(...)`, queried from Stage 3's
   *refined* MITRE mapping (`STAGE_4_TOOL_TIMEOUT_QDRANT`) — real SOC
   runbook sections, reference procedural guidance only.

### Input — `_summarize_evidence(context, evidence, case_observables, runbook_matches)`

A plain `dict`, JSON-serialized as the user message. Built from
`ContextualAssessment` (Stage 3's output) + `EnrichedEvidence`:

| Key | Content |
|---|---|
| `known_observables` | `canonical_alert.observables` (n8n's own extraction) |
| `extracted_observables` | Stage 3's `extracted_observables` |
| `case_observables` | merge target's existing TheHive observables (`[]` on a `"new"` decision) |
| `runbook_matches` | up to top-k Qdrant runbook hits, `document_text` capped to 1500 chars each |
| `rule_context` | pass-through |
| `asset_context` | pass-through |
| `threat_intel` | per-`CortexResult`: `{observable, type, verdict, details_truncated_300, analyzer}` — **no `score` field** (no `CortexResult` carries a number, by hard constraint) |
| `temporal_context` | `{total_related_alerts: COUNT, host, user}` — count only, never the alert list |
| `historical_context` | `{tp_count, fp_count, avg_severity}` — counts only, never case titles/observables |
| `mitre_mapping` | Stage 3's `refined_mitre_mapping`, pass-through |
| `investigation_gaps` | Stage 3's `additional_investigation_gaps` |
| `contextual_modifiers` | Stage 3's `contextual_modifiers`, pass-through |

**Explicitly excluded** (the firewall boundary): raw log lines, full
command lines, Cortex report bodies beyond 300 chars, anything off the
raw alert not named above.

### Output — `TriageVerdict` (`schemas/verdict.py`)

```python
class TriageVerdict(BaseModel):
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
    runbook_matches: list[PlaybookMatch]   # set post-hoc, not by the LLM
    stage_4_duration_ms: int               # set post-hoc, not by the LLM
```

- `likelihood` / `impact_if_true`: **labels, never numbers** — Stage 5's
  `scoring.py` is the only place these become numeric.
- `verdict`: the actual TP/FP/needs-review call.
- `recommended_action`: **enum dynamically restricted per call** to the
  branch consistent with `correlation_decision.action` — `merge` alerts
  only ever see `["merge_quiet", "merge_and_retier", "close_fp",
  "needs_review"]`; `new` alerts only see `["create_case", "close_fp",
  "needs_review"]`. Mirrors Stage 3's merge-target enum fix exactly.
- `evidence_citations`: short pointers into the summary the LLM was
  actually given (e.g. `"rule_context.severity=high"`) — must be
  traceable, never a paraphrase.
- `actionable_observables` (`ActionableObservable`): Stage 4's judgment on
  **every** observable across `known_observables` ∪
  `extracted_observables` ∪ `case_observables` (not a filtered shortlist —
  a weak signal still gets an entry with `recommended_disposition:
  "monitor"`, `confidence: "low"`). Fields: `observable_type`, `value`,
  `recommended_disposition` (`block`/`quarantine`/`monitor`), `confidence`
  (high/medium/low, **required**), `reasoning`, `observable_id` (**never
  LLM-set** — filled in post-hoc by Stage 6/`case_action.py` once the
  real TheHive write or lookup completes).

The **fallback** (`_stage_4_fallback`, on any LLM failure — architecture's
exact worked example, verbatim): `likelihood="possible"`,
`impact_if_true="moderate"`, `verdict="needs_review"`,
`recommended_action="needs_review"`, empty citations/observables — never
fabricates a verdict, always escalates to human review.

### Post-parse validation (defense-in-depth)

- `_validate_recommended_action` — nulls back to `"needs_review"` if the
  LLM's `recommended_action` is incompatible with
  `correlation_decision.action` (belt-and-suspenders behind the dynamic
  enum). Log-only — `TriageVerdict` has no gap-list field.
- `_validate_actionable_observables` — same hallucination guard as
  Stage 3's, scoped to `known_observables ∪ extracted_observables ∪
  case_observables` (built with the `ensure_ascii=False` escaping fix
  from the start, since the Stage 3 bug was already known by the time
  this was written).

---

## 5. Notable live-caught LLM bugs (all fixed, see `CLAUDE.md` for full write-ups)

| Bug | Cause | Fix |
|---|---|---|
| `merge_into_case_id` conflated with a RAG match | Model treated a similar *past incident* (`incident_matches`) as a mergeable case; free `["string","null"]` type didn't stop it | Per-call enum constrained to real `open_cases` ids + `null`; `action` enum drops `"merge"` when no open cases exist |
| `json_object` mode self-continuation | Model kept generating extra hallucinated JSON/prose turns after a valid object | `json_schema` mode + `_extract_first_json_object`'s `raw_decode`-first-value-only parse |
| `$ref`/`$defs` schema hang | Ollama's grammar compiler never returned (280+s) on a Pydantic-derived nested schema | Hand-inlined, flat schemas in both prompt modules; sync tests guard drift |
| `extracted_observables` false-discard | Hallucination check compared an unescaped LLM value against JSON-escaped evidence text — every backslash-bearing value (e.g. Windows paths) always failed | Escape the needle with `json.dumps(value, ensure_ascii=False)[1:-1]` before the substring check |
| `max_tokens` context overflow (round 1 & 2) | Fixed `max_tokens` literal + real prompt tokens exceeded `LLM_MAX_CONTEXT_TOKENS`; the chars/token estimate was recalibrated twice as real prompts got denser | `_capped_max_tokens` computed per call from estimated prompt size; estimate ratio tightened 3.5 → 3.2, margin 200 → 400 |
| Cloudflare quick-tunnel ~100s proxy timeout | A temporary Colab/vLLM tunnel silently killed calls with a `524` well before `httpx`'s configured client-side timeout ever fired | Documented as a hard ceiling of that temporary backend, not fixable from this codebase |

---

## 6. Where LLM outputs end up

`nodes/score.py::priority_scoring` receives both `TriageVerdict` and
`ContextualAssessment` (plus the underlying `EnrichedEvidence`) and copies
their fields into the final `TriageResult` (`schemas/result.py`) — both
flat convenience fields (`stage_3_reasoning`, `contextual_modifiers`,
`refined_mitre_mapping`, `investigation_gaps`, `extracted_observables`,
`threat_intel`, `runbook_matches`, `likelihood`, `impact_if_true`,
`evidence_citations`, `actionable_observables`) and the complete
underlying objects (`gathered_evidence`, `stage_3_assessment`) for full
audit-trail drill-down. `nodes/case_action.py` (Stage 6) writes
`verdict.actionable_observables` to TheHive as case observables, tagged
with the LLM's own `disposition`/`confidence` judgment — **never** Stage
3's raw `extracted_observables` directly (that was the pre-2026-08-23
behavior, since fixed).

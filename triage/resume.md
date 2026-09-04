# SOC-3s Build Resume

**Date**: 2026-08-19  
**Status**: Phases A & B complete, Phase C findings captured, Phase D (implementation sequencing) awaiting user direction  
**Model**: Haiku 4.5  
**Next reader**: should load `/home/ai-vm/triage/CLAUDE.md` first (hard constraints, fixture discipline, deployment-specific decisions documented)

---

## Executive Summary

This codebase implements **Stages 0–3 of a 6-stage security alert triage pipeline**:
- **Stage 0** (`alert_builder.py`): parse raw alerts, extract engine + rule + context
- **Stage 1** (`nodes/gather.py` + 8 tools): enrich with backend evidence (ES, TheHive, iTop, Qdrant, OpenCTI, etc.)
- **Stage 2** (`nodes/rag.py` + 3 Qdrant collections): retrieve semantic-similar past incidents (playbooks skipped, one collection not used)
- **Stage 3** (`nodes/context.py`): single LLM call, output `ContextualAssessment` (MITRE mapping, modifiers, merge/new decision)

**What exists**: 342 passing tests, real fixtures for Sigma + Suricata alerts, production-like code paths, no HTTP entrypoint.  
**What doesn't exist**: Stage 4 (Analyst Agent LLM), Stage 5 (scoring formula), Stage 6 (audit/feedback), `main.py`/`scoring.py`, or any deployed service.

---

## What Was Built This Session

### Phase A: Suricata Alert Support (✅ complete, tested, mutation-checked)

Stages 1–6 of the plan executed, verified:

1. **Real Suricata fixtures promoted into `tests/fixtures/`**:
   - `suricata-alert-real.json` — real fired alert (SID 2100498, GPL ATTACK_RESPONSE)
   - `so_detection_2100498.json` — real rule doc, no MITRE metadata
   - `so_detection_suricata_mitre_real.json` — real rule doc with MITRE metadata (SID 2001482)

2. **`alert_builder.py` fixed** — `event_dataset` extraction now falls back from nested Sigma path to top-level `raw_alert.event.dataset` when nested path absent. Mutation-tested.

3. **`tools/detection_rules.py` enhanced** — new `_parse_suricata_content()` function parses Suricata's `metadata:` clause (completely different format from Sigma's YAML `tags`), extracts MITRE technique/tactic, severity (with mapping to normalized `level`), routes everything else to `other_tags`. Live-verified against real SIDs 2100498, 2001482, 2016781, etc.

4. **Synthetic fixture fixes** — `SURICATA_ALERT` protocol corrected uppercase `TCP` (matching real data).

5. **Tests added** — `TestRealSuricataPath`, `TestSuricataMetadataParsing`, `TestAgainstRealSuricataResponse`, all mutation-checked.

6. **Documentation** — `CLAUDE.md` updated with two new sections: Suricata support + its verification story, and iTop's structural gap for Suricata (hostname-only lookup).

**Verification**: 342 tests passing, real-fixture-backed extraction verified live.

### Phase B: Comprehensive Pipeline Documentation (✅ complete)

**New file**: `/home/ai-vm/triage/pipeline.md` — 13 sections documenting:
- §1: Mermaid flowchart (green BUILT subgraphs for Stages 0–3, red NOT BUILT for 4–6 + entrypoint)
- §2: Data-contract models (all Pydantic schemas)
- §3–§7: Block-by-block breakdown of each stage (extraction table, tool table, LLM shape, schema story, fallback)
- §8: Config & scoring (what exists, what doesn't)
- §9: Suricata work recap
- §10: Testing & fixture discipline
- §11: Scenario coverage (5 concrete scenarios, explicitly stating what's not possible yet)
- §12: Build inventory with line counts
- §13: Full field-by-field reference for every model (type, role, rationale)

---

## Phase C: Research Findings (✅ complete, findings documented, **code not yet changed**)

Launched 6 parallel forks investigating:
1. **so-alert-reference deep dive** (Sigma) — confirmed engine detection, rule-content parsing, MITRE locations
2. **so-alert-reference deep dive** (Suricata/YARA) — found Suricata metadata format, confirmed YARA has zero MITRE refs
3. **Elasticsearch evidence recheck** — mapped actual indices, field names, real data distributions
4. **TheHive schema audit** — confirmed native `similarCases` primitive, discovered unused feature
5. **Codebase "empty ≠ absent" audit** — identified ~15 structural gaps + deployment state findings

**Key methodological correction** (user-driven): never use "zero current data" as justification to deprioritize a real capability. Security Onion is a fresh test deployment — emptiness means "not yet triggered," not "won't matter."

---

## The 15 Gaps (what they are, consequence, cause)

All gaps are documented in full with explanation, consequence, and root cause below. User explicitly asked for this breakdown and received it. **None have been implemented yet** — sequencing still open.

### Gap 1–3: Schema + gate issues (lightweight, low-risk fixes)

| Gap | What | Consequence | Cause |
|-----|------|-------------|-------|
| **#2: `ProcessEvent` missing privilege fields** | no `integrity_level`/`elevation_level` on history-event records | LLM can't spot privilege-escalation chains in host history | one model kept up-to-date, sibling model never extended |
| **#3: CVE retrieval hardcoded off** | `_has_cve_indicators() → False` always | entire CVE-matching capability switched off; 6,358 real CVE records sit unretrieved | single real fixture's code-signing cert was always Microsoft's, so gate was conservatively hardcoded off |
| **#4: Domain/URL correlation never probed against Suricata index** | didn't check `logs-suricata.alerts-so` for shared domains/URLs | open question until Suricata ingestion gap closes; correlation signal might exist undetected | original probe scoped to tool's own target index (reasonable at time), never circled back once Suricata became real dataset |

### Gap 5–8: Schema completeness issues (moderate, higher effort)

| Gap | What | Consequence | Cause |
|-----|------|-------------|-------|
| **#5: `Process` missing PE metadata; `Network` missing `community_id`** | no version/product/company fields on processes; no flow-correlation key on network events | renamed/masquerading binaries silently pass; future flow-correlation tool (#6) has no join key | PE fields built before Sysmon's renames traced; `community_id` is brand-new requirement surfaced by design work |
| **#6: Suricata flow-correlation tool** | designed but not built; would query `logs-suricata-so` by `community_id` for full DNS/HTTP/TLS context | Suricata alerts arrive with bare rule + IPs only; thinnest-evidence alerts without this tool | target index has zero documents (Suricata configured alert-only, not full EVE firehose); tool designed defensively now, needs zero code changes once config flips |
| **#7: `File` missing Strelka/YARA fields** | no entropy, PE scan metadata, file timestamps, YARA match score | YARA matches lose all evidence analyst would use to judge "real malware or coincidental string" | built from inference before pipeline processor trace; first trace happened this session |
| **#8: No `Registry`/`Pipe`/`Wmi` models** | 6 of Sysmon's 28 event types structurally uncaptured (registry persistence, named-pipe C2, WMI persistence) | persistence/C2 detections fall through to generic description-regex fallback; attacker-controlled values lost | built against one real process-creation fixture, never extended to 27 other Sysmon event types (400 real docs already exist for this shape) |

### Gap 9–12: New discovery + correctness landmines (architectural implications)

| Gap | What | Consequence | Cause |
|-----|------|-------------|-------|
| **#9: Two unknown engines** (Wazuh/OSSEC, `logscan.alert`) | engine detection falls through to `"unknown"` if either fires | least-informed processing path; rule-identity parsing would likely extract garbage | genuinely new discovery from full so-alert-reference read; nobody previously knew these existed |
| **#10: Sysmon dispatch must key on `event.code`, not `event.dataset`** | code trusting documentation alone would silently never dispatch correctly | every Sysmon alert lands in same branch; synthetic fixtures built from same docs also miss it | real divergence between documented pipeline design (intent) and actual Elastic Agent behavior (observed) |
| **#11: `event_data.rule.name` collision** | Sysmon's internal config tag (e.g., "DLL") shares field name with actual fired rule's name | future code reading "rule.name" carelessly gets meaningless internal string instead of detection identity | unfortunate naming coincidence, visible only by reading real live Sysmon alert side-by-side with schema |
| **#12: TheHive `similarCases` unused** | hand-rolled case matching duplicates what built-in primitive does, without overlap-strength score | no way to express *how strongly* related a match is; every match looks equally significant | hand-rolled functions built before checking if TheHive exposed native alternative |

### Gap 13–15: Deployment state (not code gaps, but structural constraints)

| Gap | What | Consequence | Cause |
|-----|------|-------------|-------|
| **#13: Strelka/YARA — no index template** | file-scanning cannot produce a single alert regardless of wait time | requires Fleet config change to enable (disabled deliberately for resource savings on test deployment) | structural constraint, not code-fixable |
| **#14: Suricata EVE — alert-only, not full firehose** | Suricata configured to log only `alert` record type, no DNS/HTTP/TLS/flow metadata alongside it | #6's tool blocked on this config; Suricata alerts arrive bare (rule + IPs only) | config choice, not code |
| **#15: `logs-endpoint.alerts-*` shape diversity unknown** | real index exists but only 43 docs, all identical repeated Atomic Red Team test-firing | building extraction now would repeat "generalize from one sample" mistake; proves engine real, not its range | proves Endpoint engine is real, but doesn't prove what full range of alerts looks like |

---

## Existing Implementation Plan (ready to execute when authorized)

**File**: `/home/ai-vm/.claude/plans/is-there-an-sqlite-melodic-globe.md`  
**Topic**: Fix `correlation_decision.merge_into_case_id` conflating RAG matches with open cases  
**Status**: plan written, live-tested, ready to implement (3 layers: schema constraint, prompt clarification, post-parse validator)

This is a medium-effort, well-scoped fix with zero unknown unknowns — live verification already done. Can be executed immediately if prioritized.

---

## Recommended Next Steps

**User's original question** (awaiting clarification): sequencing. The 15 gaps range from "low-risk, lightweight" (#2–#4) to "moderate effort, medium risk" (#5–#12) to "deployment-level state, code-unfixable" (#13–#15).

**Suggested sequencing** (subject to user prioritization):

1. **Low-hanging fruit** (#2–#4, ~2–4 hours total):
   - Add two fields to `ProcessEvent`
   - Remove the CVE gate hardcode
   - Document the domain/URL question as "open, awaiting Suricata ingestion"

2. **Schema completeness** (#5–#8, ~8–16 hours):
   - Add PE metadata + `community_id` to existing models
   - Stub in `Registry`/`Pipe`/`Wmi` models (empty, ready for real extraction once a fixture arrives)
   - Document `File` Strelka/YARA fields as deferred

3. **Engine support** (#9–#12, ~4–8 hours):
   - Add Wazuh/OSSEC + `logscan.alert` to engine detection
   - Document Sysmon dispatch fix + field-name collision as known landmines
   - Wire in TheHive's native `similarCases` (if benefit justifies the refactor)

4. **Deferred (config-dependent or design-dependent)**:
   - #6 (Suricata flow-correlation): blocked until EVE-log config changes; design is done
   - #13–#15: deployment-level decisions, not code changes

---

## Files & State

**Key files (read, not yet edited from Phase C findings)**:
- `schemas/alert.py`, `evidence.py`, `assessment.py` — all models documented in pipeline.md §13
- `nodes/gather.py` — all 8 Stage-1 tools; Stage 2 collections list (`relevance`, `threat_intel` active; `tactics`, `playbooks` not called)
- `nodes/context.py` — Stage 3 LLM call, output shapes, fallback paths
- `alert_builder.py` — engine detection, rule parsing, field extraction logic
- `tools/detection_rules.py` — rule-lookup logic, content parsing (Sigma verified, Suricata verified, YARA not parsed)
- `CLAUDE.md` — deployment-specific decisions, fixture discipline rules, ground-truth hierarchy, all deferred requirements

**Tests**: 342 passing. Real-fixture-backed: Sigma process-creation, Suricata network events. Synthetic-only: YARA, Sysmon registry/pipe/WMI.

---

## To Resume

1. Review `/home/ai-vm/triage/CLAUDE.md` (hard constraints, deployment decisions, fixture discipline)
2. Review `/home/ai-vm/triage/pipeline.md` (current capabilities, scenario coverage, field reference)
3. Read this file's gap-by-gap breakdown (§"The 15 Gaps")
4. Decide sequencing: which gaps to address first, in what order
5. For gaps #2–#12: discuss implementation approach (schema changes, tool refactors, new tools)
6. For gaps #13–#15: flag to maintainer if they become blockers
7. For the existing plan (merge_into_case_id fix): can be executed immediately if prioritized

**Key principle** (user-established, governs all future work): in a fresh/test Security Onion deployment, zero or low data volume never justifies deferring a real capability — always distinguish structural absence (schema/API proves can't happen) from population artifact (real capability, just not yet triggered).

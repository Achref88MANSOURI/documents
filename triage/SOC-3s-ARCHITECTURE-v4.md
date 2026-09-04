# SOC-3s Agent Service — Build Specification

**This is a NEW project, built from scratch. There is no prior codebase to reference, port, or preserve.**

This document is the complete, authoritative specification for a system that does not exist yet. Every stage, every tool, every schema described here is to be built new, in this repository, from zero.

---

## Read this before writing any code

If you are Claude Code (or any agent) working on this repository:

1. **This is a greenfield build.** There is no "existing repo" for this project. Do not assume any file exists until you have created it in this session.
2. **Do not invent an alternate architecture.** The six-stage pipeline described in §4 onward is the design. Build exactly this, not a simplified or "improved" version of it.
3. **Do not add ReAct loops, tool-calling agents, or multi-turn agent frameworks anywhere in this system.** There are exactly two LLM calls in the entire pipeline (Stage 3 and Stage 4), and neither of them has access to tools. This is a deliberate, load-bearing design decision explained in §2 — not an oversight to "fix" by adding more agent autonomy.
4. **Build one stage at a time.** Do not attempt to write the full pipeline in one pass. Follow the build order in §18. Stop and let the person review after each stage.
5. **Every stage boundary is a typed Pydantic model.** Never pass a raw `dict` between stages. See §12.
6. **When in doubt about a design choice, re-read the relevant section below before improvising.** This document already answers "why" for every non-obvious decision.
7. **Read `SOC-3s-IMPLEMENTATION-GUIDE.md` before writing the first tool function.** It contains two project-specific facts that are easy to get wrong by inference alone (how IOCs actually reach this system, and why only Sigma alerts exist to test against right now), plus the mandatory verify-against-the-real-backend discipline for every tool. This architecture document says *what* to build; that document says *in what order and how to confirm each piece actually works* before moving to the next.

Every section in the technical spec answers three questions:

1. What does this do?
2. Is it really needed, or is it decoration?
3. Can we actually deploy and operate it?

---

## Table of Contents

1. [What this system is (and isn't)](#1-what-this-system-is-and-isnt)
2. [Design rationale — why this shape and not an agent-heavy one](#2-design-rationale--why-this-shape-and-not-an-agent-heavy-one)
3. [Deployment topology](#3-deployment-topology)
4. [The six stages](#4-the-six-stages)
5. [Stage 0 — Ingress validation and dedup](#5-stage-0--ingress-validation-and-dedup)
6. [Stage 1 — Parallel evidence gather](#6-stage-1--parallel-evidence-gather)
7. [Stage 2 — RAG enrichment](#7-stage-2--rag-enrichment)
8. [Stage 3 — Context agent (LLM #1)](#8-stage-3--context-agent-llm-1)
9. [Stage 4 — Analyst agent (LLM #2)](#9-stage-4--analyst-agent-llm-2)
10. [Stage 5 — Hybrid priority scoring](#10-stage-5--hybrid-priority-scoring)
11. [Stage 6 — Audit and feedback](#11-stage-6--audit-and-feedback)
12. [The evidence contract between stages](#12-the-evidence-contract-between-stages)
13. [Every tool, every backend — the honest inventory](#13-every-tool-every-backend--the-honest-inventory)
14. [Explicit non-goals — things NOT to build](#14-explicit-non-goals--things-not-to-build)
15. [Failure modes and degradation](#15-failure-modes-and-degradation)
16. [Deployment checklist](#16-deployment-checklist)
17. [Is this production-ready? — brutal honesty](#17-is-this-production-ready--brutal-honesty)
18. [Repository structure and build order](#18-repository-structure-and-build-order)
19. [Configuration reference](#19-configuration-reference)

---

## 1. What this system is (and isn't)

**What it is:** A machine that turns a Security Onion alert into a prioritized, evidence-backed triage decision that a Tier-1 analyst can act on. Read-only by construction. Human-in-the-loop for containment.

**What it isn't:**

- Not a full autonomous SOC. Every case-modifying action happens in n8n after human review.
- Not a threat hunter. It answers "is this alert worth investigating right now?" — not "what threats are we missing?"
- Not a replacement for analysts. It reduces their queue, doesn't eliminate the need for judgment.
- Not a real-time system. Target latency is 2-3 minutes per alert, not sub-second.

**The one measurable success criterion:** produce a priority score and verdict that a Tier-1 analyst would agree with ≥80% of the time. Everything else is subordinate to that.

**Current engine coverage — stated plainly:** Network and file-extraction sensors are not yet deployed on this Security Onion instance. Only Sigma alerts (against endpoint/Sysmon telemetry) can actually fire and be tested against right now. Suricata and YARA code paths are built per this specification and unit-tested against synthetic fixtures, but cannot be integration-verified until those sensors go live. This is an expected, temporary limitation of the current deployment — not a reason to skip building the non-Sigma code paths, and not a reason to consider the Sigma-only path "incomplete." See `SOC-3s-IMPLEMENTATION-GUIDE.md` §0.1.

---

## 2. Design rationale — why this shape and not an agent-heavy one

The obvious way to build "an AI SOC triage system" is to give an LLM agent a pile of tools (query TheHive, query Elasticsearch, query iTop, query Cortex) and let it decide what to call and when, in a ReAct loop, possibly with multiple such agents talking to each other. Anyone starting this project will be tempted to build that. **Do not build that.** Here is why, stated plainly so the reasoning survives contact with a fresh coding session:

**Reason 1 — the tool sequence is not actually a decision.** For a Sigma endpoint-process alert, a competent triage process *always* wants: the rule's own metadata, the asset's criticality, whether there's an open case sharing entities, recent related alerts, and recent process history on that host. There is no scenario where an agent should "decide" to skip asset lookup. Letting an LLM choose which of a fixed set of tools to call, in what order, is not agentic reasoning — it's an expensive, unreliable way to run a sequence you already know.

**Reason 2 — CPU-only inference makes agent loops operationally impossible.** Each LLM call on commodity CPU hardware (no GPU) takes 30–100+ seconds. A ReAct loop with an 8-call budget means up to 8 sequential LLM round-trips just for one agent — multiplied across multiple agents, real-world testing of this exact kind of pipeline produced 17 LLM calls and 17 minutes per alert. That is not a tuning problem; it is the wrong shape for the hardware.

**Reason 3 — agentic tool orchestration produces silent, hard-to-debug failures.** When an LLM decides which tools to call, "the agent didn't call the tool it should have" is a routine failure mode, and it fails silently — the pipeline doesn't crash, it just produces a worse answer with an empty evidence field. Determinism in evidence-gathering eliminates an entire category of failure.

**Reason 4 — LLMs are measurably unreliable at producing consistent structured output under agent loops.** JSON parsing failures, tool-call malformation, and premature loop termination are common, well-documented failure modes for small/medium local models used as ReAct agents. Removing the loop removes the failure mode.

**The design principle that follows:** separate *evidence gathering* (always deterministic, parallel, timeout-bounded Python) from *evidence interpretation* (exactly two single-shot LLM calls, no tools, each with a deterministic fallback). Gathering is a fixed sequence because the tools needed are known in advance. Interpretation is where genuine judgment — "does this evidence suggest a real attack, how bad would it be, does this correlate with anything else" — actually requires a model. Do not blur this line by giving Stage 3 or Stage 4 any tool-calling capability, and do not introduce a third or fourth LLM-driven agent stage without first re-deriving why deterministic Python cannot do the job.

**The corollary for scoring:** the same reasoning applies to the final priority number. LLMs are unreliable at direct numeric output (documented empirically: alert-prioritization tasks show strong recall but consistently low precision when LLMs are asked to score directly). So the LLM in Stage 4 never outputs a number — it outputs qualitative, bounded, labeled *modifiers* ("this factor increases likelihood, strength: strong, because…"), and a deterministic formula in Stage 5 turns those into the final auditable score. See §10 for the full mechanism.

Six concrete requirements fall out of this reasoning — every one of them is a hard constraint on the build, not a suggestion:

1. **Exactly two LLM calls per alert, total.** Not per-agent, per-pipeline. Two.
2. **Zero tools attached to either LLM call.** Both are single-shot: evidence in, structured judgment out.
3. **Every backend call is explicit, parallel, and timeout-bounded** — never something an LLM decides to invoke or skip.
4. **Every evidence field is either populated or explicitly gapped with a reason** — `{found: false}` must never mean two different things.
5. **Stage boundaries are strict Pydantic contracts** — a field renamed in one stage and misread in the next must fail loudly at import/validation time, not silently produce an empty value downstream.
6. **Priority output is a continuous 0–100 score with full numeric audit trail**, not a 4-bucket table — and the LLM never writes that number directly.

Everything in §4 onward is the concrete architecture that satisfies these six requirements.

---

## 3. Deployment topology

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Security Onion Manager (172.20.24.58)                                  │
│  ├── Elasticsearch (:9200) — alerts, detections, telemetry              │
│  ├── ElastAlert 2 — Sigma rule execution                                │
│  ├── Suricata / Zeek / Strelka — detection engines                      │
│  └── Elastic Agent — endpoint telemetry                                 │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │ webhook (Sigma alert doc)
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  n8n (172.20.24.220:5679)                                               │
│  1. Receive raw SO alert                                                │
│  2. Create TheHive alert + observables                                  │
│  3. Trigger Cortex analyzers on observables (fire-and-forget)           │
│  4. Wait 30s for Cortex to complete                                     │
│  5. POST /triage to agent-service with:                                 │
│     - thehive_alert_id                                                  │
│     - raw SO alert (full payload)                                       │
│     - asset_context (if iTop resolved)                                  │
│  6. Receive TriageResult                                                │
│  7. Switch on triage_result.recommended_action:                         │
│     ├── create_case → PATCH TheHive alert to case                       │
│     ├── close_fp → PATCH alert status=Ignored                           │
│     ├── merge_quiet / merge_and_retier → merge alert into case          │
│     └── needs_review → assign to analyst queue                          │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │ POST /triage
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  agent-service (172.20.24.224:8000)                                     │
│                                                                         │
│  FastAPI + async Python. LangGraph optional (see §14).                  │
│                                                                         │
│  Six stages, each with clear input/output contracts:                    │
│    Stage 0: Validation + Dedup           (Python, <100ms)               │
│    Stage 1: Parallel Evidence Gather     (asyncio, <20s p95)            │
│    Stage 2: RAG Enrichment               (Qdrant, <8s p95)              │
│    Stage 3: Context Agent                (LLM #1, ~30-60s)              │
│    Stage 4: Analyst Agent                (LLM #2, ~60-90s)              │
│    Stage 5: Hybrid Priority Scoring      (Python, <200ms)               │
│    Stage 6: Audit + Feedback             (async, non-blocking)          │
└────────┬─────────────┬──────────┬──────────┬──────────┬─────────────────┘
         │             │          │          │          │
         ▼             ▼          ▼          ▼          ▼
    ┌────────┐   ┌─────────┐  ┌──────┐  ┌────────┐  ┌─────────┐
    │ Ollama │   │ TheHive │  │ iTop │  │  ES    │  │ Qdrant  │
    │  .225  │   │  .221   │  │ .223 │  │  .58   │  │  .224   │
    │        │   │         │  │      │  │        │  │  :6333  │
    └────────┘   └─────────┘  └──────┘  └────────┘  └─────────┘
                     │
                     ▼
                 ┌────────┐
                 │ Cortex │
                 │  .221  │
                 └────────┘

    Local to agent-service host:
    ┌─────────┐  ┌───────┐
    │ SQLite  │  │ Redis │
    │ FP db   │  │ dedup │
    └─────────┘  └───────┘
```

---

## 4. The six stages

| Stage | What it does | LLM? | Duration (p95) | Failure mode |
|---|---|---|---|---|
| **0** | Validate payload, dedup check | No | <100ms | Bad payload → 400 |
| **1** | Parallel backend calls, gather evidence | No | <20s | Per-tool gap, never crash |
| **2** | RAG retrieval (MITRE + conditional playbooks/CVE) | No | <8s | Empty context, log gap |
| **3** | Context agent — interpret evidence, refine MITRE, correlate | Yes (1 call) | 30-60s | Deterministic fallback |
| **4** | Analyst agent — produce verdict with contextual modifiers | Yes (1 call) | 60-90s | needs_review default |
| **5** | Hybrid priority scoring — formula + bounded LLM modifiers | No | <200ms | Never fails |
| **6** | Audit log to ES, FP feedback write | No (async) | non-blocking | Best-effort |

**Total LLM calls per alert: 2** (down from 17 in v3)
**Target p95 end-to-end latency: 180s** (down from 17 minutes in v3)
**n8n timeout budget: 300s** — 40% headroom above p95

---

## 5. Stage 0 — Ingress validation and dedup

### What it does

Rejects malformed requests fast. Prevents duplicate processing of the same alert within a short window.

### Input

```json
{
  "thehive_alert_id": "~1190993992",
  "raw_alert": { ... full Security Onion document ... },
  "asset_context": { ... optional, from n8n's iTop resolution ... }
}
```

Validated via Pydantic `AlertWebhookPayload`. Missing required fields → HTTP 400 with specific error.

### The dedup logic

Fingerprint = `SHA-256(rule.uuid : host.hostname : first_3_sorted_external_ips)`

Stored in Redis with TTL = `DEDUP_WINDOW_SECONDS` (default 300s = 5 minutes).

- **Cache hit** → return `{"recommended_action": "deduplicated", "priority_score": null}` immediately. n8n knows to add to existing incident.
- **Cache miss OR Redis unreachable** → proceed to Stage 1. Redis absence NEVER blocks the pipeline.

### Is this really needed?

**Yes, but only barely.** Security Onion can generate multiple alerts from the same underlying event (Suricata + Sigma + Strelka can all fire on one action). Without dedup, one attack = 3× pipeline runs = 3× LLM cost. Dedup catches these cheap.

**However:** if Redis is down or unset, the pipeline still works — you just pay 3× for a while until Redis comes back. This is the correct failure semantics.

### Deployment reality

Redis is a single container on the agent-service host. If it goes down, you notice within 24 hours from Prometheus metrics but you don't have an outage. Fine.

---

## 6. Stage 1 — Parallel evidence gather

### What it does

Runs all deterministic backend queries in parallel with strict per-tool timeouts. Every backend that's needed for scoring is called here — no LLM decisions about which tools to invoke.

### The parallel calls

```python
async def gather_evidence(alert: CanonicalAlert) -> RawEvidence:
    results = await asyncio.gather(
        _timeout(get_fp_signal(alert.rule.uuid, alert.host.name), 0.1),
        _timeout(detection_rule_lookup(alert.rule.uuid), 3.0),
        _timeout(search_open_cases_by_entities(alert.observables, alert.host, alert.user), 5.0),
        _timeout(search_closed_cases_by_rule(alert.rule.uuid, alert.observables), 5.0),
        _timeout(itop_asset_lookup(alert.host.name), 5.0),
        _timeout(elasticsearch_related_alerts(alert.host, alert.user, alert.observables, hours=24), 3.0),
        _timeout(elasticsearch_process_history(alert.host, alert.user, hours=24), 3.0),
        return_exceptions=True,
    )
    return _build_raw_evidence(results, alert)
```

### Every tool called in Stage 1

#### 1. `get_fp_signal(rule_uuid, host)` — local SQLite

**Purpose:** How often has this rule fired FP on this host historically?

**Returns:**
```json
{
  "short_term_fp_rate": 0.4,       // 24h
  "long_term_fp_rate": 0.85,       // 30d
  "short_term_total": 5,
  "long_term_total": 40
}
```

**How we handle:** Feeds `likelihood` scoring. High long-term FP rate = strong negative signal.

**Is it needed?** Yes. Without it, you can't detect chronically noisy rules. AACT (arXiv:2505.09843) validated: dynamic per-rule FP learning is the single strongest signal for automating alert closure.

**Failure mode:** SQLite file corrupted → returns zeros. Not catastrophic — likelihood scoring degrades but doesn't crash.

---

#### 2. `detection_rule_lookup(rule_uuid)` — Elasticsearch `so-detection` index

**Purpose:** Get the actual rule source (Sigma YAML / Suricata sig / YARA rule) with its MITRE tags, description, and known false positive conditions.

**Returns:**
```json
{
  "found": true,
  "source_engine": "sigma",
  "title": "Suspicious Invoke-WebRequest Execution",
  "description": "...",
  "severity": "high",
  "mitre_attack": ["T1105", "T1059.001"],
  "mitre_tactics": ["command-and-control", "execution"],
  "falsepositives": ["Software update scripts"],
  "level": "high",
  "logsource": { "product": "windows", "category": "process_creation" }
}
```

**How we handle:**
- `severity` → `rule_severity_score` in likelihood formula
- `mitre_attack` → primary MITRE mapping (LLM refines but doesn't override without evidence)
- `falsepositives` → LLM uses to check if this alert matches a known FP condition

**Is it needed?** Absolutely. Rule metadata is ~90% of what a senior analyst reads first. Without it, MITRE mapping falls back to fuzzy Qdrant matching which is worse.

**Failure mode:** ES unreachable → gap logged, MITRE falls back to Qdrant retrieval in Stage 2.

---

#### 3. `search_open_cases_by_entities(observables, host, user)` — TheHive

**Purpose:** Are there open cases sharing entities with this alert? If yes, this alert might merge into one.

**Returns:** List of shallow case dicts (case_id, title, severity, tags, created_at, observables).

**How we handle:**
- Empty → `correlation_mode = "new"`
- Non-empty → passed to Stage 3 for LLM to judge merge/new (with kill-chain progression logic)

**Is it needed?** Yes. Without it, you fragment incidents — each alert becomes its own case, analysts lose the attack narrative.

**Failure mode:** TheHive unreachable → all alerts default to `new`. Real cost: temporary case fragmentation until TheHive recovers. Acceptable degradation.

---

#### 4. `search_closed_cases_by_rule(rule_uuid, observables)` — TheHive

**Purpose:** How was this rule + these entities handled historically? TP or FP?

**Returns:** Up to 20 closed cases with resolution status.

**How we handle:**
- Aggregate by resolution: `{tp_count, fp_count, avg_severity}`
- Feeds `likelihood` scoring (high TP history = boost likelihood)

**Is it needed?** Yes but not urgently. First 30 days of deployment this returns empty. After ~3 months it becomes the second-strongest signal after FP tracker.

**Failure mode:** Empty → likelihood formula ignores this signal, doesn't fail.

---

#### 5. `itop_asset_lookup(hostname)` — iTop CMDB

**Purpose:** What business context does this asset have? Criticality, owner, network zone, data sensitivity.

**Returns:**
```json
{
  "found": true,
  "hostname": "win-kvkmd51ggkq",
  "criticality": "high",
  "owner": "IT Admin Team",
  "organization": "Corporate",
  "services": ["Domain Controller Auth", "File Share"],
  "network_zone": "internal_restricted",
  "data_sensitivity": ["PII", "Financial"]
}
```

**How we handle:** Direct input to `impact` scoring. Criticality is one of the two named inputs to Agent 3's impact assessment per CORTEX design.

**Is it needed?** Yes, and this is the single biggest gap in your current deployment. Without iTop populated, `impact` scoring defaults to `medium` for every asset. That's the same problem as v3's 4-bucket severity.

**Failure mode:** iTop returns nothing / unreachable → `criticality: unknown`, impact scoring uses baseline (medium). Confidence score drops → analyst review escalation.

**Deployment reality — brutal truth:** If iTop isn't populated with real asset data (not just default entries), this scoring dimension is dead weight. **Prerequisite for real deployment:** populate iTop with at minimum: host criticality tier, network zone, business owner. Anything less and you're just adding latency without value.

---

#### 6. `elasticsearch_related_alerts(host, user, observables, hours=24)` — Security Onion ES

**Purpose:** Are there other alerts on the same host/user/IOCs in the last 24h? Attack clusters produce multiple alerts.

**Returns:** Up to 50 alert summaries with `{timestamp, rule_name, severity}`.

**How we handle:**
- Count feeds `velocity_multiplier` in scoring
- Cluster >5 = 1.3× multiplier (attack in progress)
- Distinct rules >3 = kill-chain hypothesis for Stage 3 LLM

**Is it needed?** Yes. Isolated alerts and clustered alerts have very different meaning. Without this you miss active attacks.

**Failure mode:** ES query times out → velocity_multiplier = 1.0. Scoring works but loses temporal context.

---

#### 7. `elasticsearch_process_history(host, user, hours=24)` — Security Onion ES

**Purpose:** For endpoint alerts, what other processes ran on this host in the same window? Parent processes, sibling processes, command lines.

**Returns:** Up to 50 process events with command lines and executables.

**How we handle:**
- Passed to Stage 3 for behavioral context reasoning
- Explicit process chain analysis (e.g., "PowerShell spawned by Excel = macro exec = higher likelihood")

**Is it needed?** Conditionally. Only for Sigma alerts on `endpoint.events.process` dataset. Skip for pure network alerts.

**Failure mode:** Skip if not endpoint alert. If needed but unavailable, gap logged.

---

### Cortex results — NOT called here

**This is a critical design decision.** Cortex analyzer reports are already embedded in the raw alert by n8n before it POSTs to `/triage`. Stage 1 does NOT call Cortex.

**Why:** Cortex jobs take 30-180 seconds each. Running them synchronously in Stage 1 would blow the latency budget. n8n runs them in the workflow before calling us, in parallel with alert creation.

**How this manifests:** `alert_builder.py` reads `alert.observables[].reports` and populates `canonical_alert.cortex_results` with the pre-computed TI verdicts. Stage 1 just accesses them, doesn't fetch.

### Observables/IOCs — same principle, different backend

**Security Onion's raw alert document carries no IOC field.** There is no `ioc`, `observables`, or `indicators` array on a raw Sigma alert (the only engine currently producing live alerts in this deployment) — just `rule.*`, `event.*`, and the matched `event_data.*`. Extraction of IOC-shaped values (URLs, hashes, domains found in command lines) happens entirely in a separate n8n workflow step, before `/triage` is ever called, which writes them onto the TheHive alert as `observables[]`.

`alert_builder.py` therefore never attempts to parse IOCs out of `raw_alert`. It reads `hive_alert.observables` — fetched via the same `get_full_alert_with_analysis` call that retrieves Cortex reports — as the authoritative IOC source. `raw_alert.ioc.indicators` (Security Onion's own `so-ioc-normalize` pipeline output) is consulted as a supplementary, typically-empty-for-Sigma source, kept for when Suricata/network alerts eventually populate it once sensors are deployed.

**Do not build logic in this repo that extracts IOCs from `raw_alert` text fields.** That work already exists, upstream, in n8n. See `SOC-3s-IMPLEMENTATION-GUIDE.md` §0.2 for the full reasoning.

### Stage 1 output — `RawEvidence`

Strict Pydantic model. Every field has a value OR a gap entry explaining why.

```python
class RawEvidence(BaseModel):
    canonical_alert: CanonicalAlert
    fp_signal: Optional[FPSignal]           # gap logged if missing
    rule_context: Optional[RuleContext]     # gap logged if missing
    open_cases: List[ShallowCase]           # empty is valid
    closed_cases_summary: ClosedCasesSummary  # counts, not full list
    asset_context: Optional[AssetContext]   # gap logged if missing
    related_alerts_24h: List[AlertSummary]  # capped at 50
    process_history_24h: List[ProcessEvent] # capped at 50, only for endpoint alerts
    cortex_results: List[CortexResult]      # from raw alert, not fetched here
    investigation_gaps: List[Gap]           # explicit list of what failed and why
    stage_1_duration_ms: int
```

**Every gap has a reason:** `Gap(source="itop", reason="Connection timeout after 5s")` — not `Gap(source="itop", reason="unknown")`.

### Duration budget

- p50: ~5 seconds
- p95: ~15 seconds
- p99: ~20 seconds (worst case: all 7 tools hit their timeouts)

Per-tool timeouts are aggressive on purpose. Slow backends = gap + move on, not block the pipeline.

---

## 7. Stage 2 — RAG enrichment

### What it does

Retrieves semantic context from Qdrant that the LLM will use in Stage 3. Three collections, conditional retrieval.

### The three collections (separate, not one with discriminator)

#### Collection 1: `mitre_techniques`

**Content:** MITRE ATT&CK enterprise technique corpus, ~600 techniques + ~350 sub-techniques.

**Payload per point:**
```json
{
  "technique_id": "T1105",
  "technique_name": "Ingress Tool Transfer",
  "tactic": "command-and-control",
  "description": "...",
  "detection_guidance": "...",
  "mitigations": [...],
  "example_procedures": [...],
  "priority_score_0_5": 4        // from Bitsight-style prevalence scoring
}
```

**Retrieval:** ALWAYS. Query = rule name + description + evidence keywords, top-k=5.

**Ingest source:** MITRE ATT&CK STIX bundle. Refresh monthly via cron.

**Why separate collection:** Score comparison across content types (MITRE vs CVE) is meaningless. Separate collections let you tune HNSW parameters per corpus and interpret scores within a corpus.

---

#### Collection 2: `soc_playbooks`

**Content:** Investigation playbooks. Manually authored for high-frequency alert patterns + generated from closed cases.

**Payload per point:**
```json
{
  "playbook_id": "pb_ps_download_cradle",
  "trigger_patterns": ["PowerShell + Invoke-WebRequest", "certutil download"],
  "alert_types": ["sigma.process_creation"],
  "investigation_steps": [
    "Check parent process for Office/browser origin",
    "Check downloaded URL reputation",
    "Check if downloaded file was executed",
    "Check for credential dumping tools in process tree"
  ],
  "verdict_indicators": {
    "true_positive": ["known-bad URL", "file executed", "credential tool"],
    "false_positive": ["SCCM context", "admin doing patching", "known software update"]
  },
  "mitre_mapping": ["T1105", "T1059.001"]
}
```

**Retrieval:** CONDITIONAL — only when rule matches a known playbook trigger pattern. Query = rule name + primary technique.

**Ingest source:** Two paths:
- **Manual authoring** — SOC lead writes playbooks for top 20 alert patterns (one-time investment, high value)
- **Closed case extraction** — nightly job pulls closed cases from TheHive, LLM-summarizes into playbook format, requires human approval before ingest

**Why bother?** The single strongest input to Stage 3's reasoning. Without playbooks, the LLM has to reason from scratch every time. With playbooks, it has "here's what an analyst would look for."

**Skip condition:** Alert doesn't match any playbook trigger → skip retrieval, save 2-3 seconds. Log this as gap only if evidence is otherwise thin.

---

#### Collection 3: `cve_context`

**Content:** CVEs relevant to Windows endpoint environment, filtered to CVSS ≥ 7.0.

**Payload per point:**
```json
{
  "cve_id": "CVE-2021-36934",
  "description": "HiveNightmare - Windows Elevation of Privilege",
  "cvss_v3_score": 7.8,
  "affected_products": ["Windows 10", "Windows 11"],
  "mitre_technique_ids": ["T1068"],
  "exploit_available": true,
  "cisa_kev": false
}
```

**Retrieval:** CONDITIONAL — only when evidence contains product names, version strings, or explicit exploit indicators. Query = product name + technique + observed behavior.

**Ingest source:** NVD JSON feed, filtered to Windows + endpoint-relevant CVEs. Refresh weekly.

**Why bother?** Adds specificity to impact scoring. "This technique is used but no known Windows CVE matches" is a very different signal than "this technique + CVE-2021-36934 exploitation pattern."

**Skip condition:** No product/CVE indicators in evidence → skip. This is 60%+ of alerts.

---

### Retrieval logic (Python, deterministic)

```python
async def stage_2_rag(evidence: RawEvidence) -> EnrichedEvidence:
    # Always retrieve MITRE
    mitre_query = _build_mitre_query(evidence)
    mitre_results = await qdrant.query("mitre_techniques", mitre_query, top_k=5)
    
    # Conditional playbook retrieval
    playbook_results = []
    if _has_playbook_trigger(evidence):
        pb_query = _build_playbook_query(evidence)
        playbook_results = await qdrant.query("soc_playbooks", pb_query, top_k=3)
    
    # Conditional CVE retrieval
    cve_results = []
    if _has_cve_indicators(evidence):
        cve_query = _build_cve_query(evidence)
        cve_results = await qdrant.query("cve_context", cve_query, top_k=3)
    
    return EnrichedEvidence(
        **evidence.dict(),
        mitre_candidates=mitre_results,
        playbook_matches=playbook_results,
        cve_matches=cve_results,
    )
```

### The embedding model

`BAAI/bge-m3` (1024-dim). Loaded ONCE at service startup as a module-level singleton, cached with `local_files_only=True` after first download. Never re-downloads on each request (this was a v3 bug — 8s wasted per request).

### Is Stage 2 needed?

**MITRE retrieval — yes, always.** LLMs are unreliable at direct MITRE technique ID output. Grounding via retrieval reduces hallucination significantly.

**Playbook retrieval — yes, when it triggers.** Turns "reason from scratch" into "match to known pattern." Highest ROI ingest work.

**CVE retrieval — marginal.** Nice-to-have. Adds impact specificity but rarely changes the verdict. Deploy last, if at all.

### Duration budget

- p50: ~2 seconds (MITRE only)
- p95: ~7 seconds (MITRE + playbook + CVE)

---

## 8. Stage 3 — Context Agent (LLM #1)

### What it does

Single LLM call. NO tools. Interprets the evidence, refines MITRE mapping, judges case correlation, extracts contextual signals that the deterministic formula can't capture.

### Why single-call and not ReAct

Because we already gathered everything in Stage 1. The LLM has no tools to call — its job is interpretation, not orchestration. This eliminates:
- Recursion limit math
- Tool call retry logic
- JSON parsing failures mid-loop
- The v3 bug where perceive made zero tool calls

### Input

`EnrichedEvidence` — the full output of Stage 2. Every backend result, gap-annotated. No raw log strings (those are locked in `canonical_alert` fields, LLM sees structured typed representations).

### Prompt structure

```
SYSTEM:
You are a Tier-2 SOC analyst reviewing an alert investigation package.
You have complete evidence — you do NOT need to call any tools.
Your outputs must be strictly valid JSON matching the provided schema.

Your job is threefold:
1. Refine the MITRE mapping — validate against evidence, add/remove techniques
2. Judge correlation — does this alert merge with existing cases, and is it a kill-chain progression?
3. Identify contextual signals — factors the deterministic scoring formula cannot see

USER:
<EnrichedEvidence JSON>

<Output schema>
```

### Output — `ContextualAssessment`

```json
{
  "refined_mitre_mapping": [
    {
      "technique_id": "T1105",
      "technique_name": "Ingress Tool Transfer",
      "tactic": "command-and-control",
      "confidence": "high",
      "basis": "rule_context.mitre_attack + evidence.process.command_line contains download URL"
    },
    {
      "technique_id": "T1059.001",
      "technique_name": "PowerShell",
      "tactic": "execution",
      "confidence": "high",
      "basis": "evidence.process.name = powershell.exe with explicit invocation"
    }
  ],
  "correlation_decision": {
    "action": "new",
    "merge_into_case_id": null,
    "kill_chain_progression_detected": false,
    "reasoning": "One open case shared source IP but different host and 7 days apart. Weak match."
  },
  "contextual_modifiers": [
    {
      "dimension": "likelihood",
      "factor_name": "credential_dumping_tool_download",
      "direction": "increase",
      "strength": "strong",
      "reasoning": "xordump.exe is a known LSASS credential dumping utility. Downloading via PowerShell with explicit TLS 1.2 downgrade matches T1552 credential harvesting preparation."
    },
    {
      "dimension": "impact",
      "factor_name": "domain_admin_credential_exposure_risk",
      "direction": "increase",
      "strength": "strong",
      "reasoning": "Host is Windows workstation with Administrator privileges. Successful credential extraction from this host exposes domain-wide credentials."
    }
  ],
  "additional_investigation_gaps": [
    "No process execution telemetry found after download — cannot confirm if xordump.exe was run"
  ],
  "confidence": "high"
}
```

### The critical design point: LLM outputs modifiers, not scores

The LLM does NOT output a priority number. It outputs **structured contextual signals** with bounded strength. The formula in Stage 5 applies these as capped adjustments to the base score.

**Why this matters:** LLMs are bad at numeric scoring (research: alert prioritisation proved substantially more challenging across all evaluated LLMs). They're good at identifying qualitative factors. This design plays to LLM strengths, avoids their weaknesses.

### Prompt injection defense

The evidence passed to Stage 3 has been through `alert_builder.py`'s field-typing pass. Attacker-controlled strings (command lines, filenames, URLs) exist as typed values inside structured evidence objects — not as free-text at the top of the prompt where they could inject instructions.

Additionally, Stage 4's `_summarize_evidence` boundary means even if Stage 3 outputs are compromised, Stage 4 sees only the structured modifier schema, not free-text reasoning.

### Fallback path

If LLM raises OR outputs invalid JSON:

```python
def stage_3_fallback(evidence: EnrichedEvidence) -> ContextualAssessment:
    return ContextualAssessment(
        # MITRE from deterministic rule lookup (Stage 1)
        refined_mitre_mapping=[
            {"technique_id": t, "technique_name": "", "tactic": "",
             "confidence": "medium", "basis": "deterministic fallback from rule_context"}
            for t in evidence.rule_context.mitre_attack
        ],
        # Correlation from entity match
        correlation_decision={
            "action": "merge" if evidence.open_cases else "new",
            "merge_into_case_id": evidence.open_cases[0].case_id if evidence.open_cases else None,
            "kill_chain_progression_detected": False,
            "reasoning": "Deterministic fallback: LLM unavailable"
        },
        # No modifiers — formula uses base evidence only
        contextual_modifiers=[],
        additional_investigation_gaps=["Stage 3 LLM unavailable, contextual analysis skipped"],
        confidence="low",
    )
```

**Critical:** The fallback preserves MITRE mapping from Stage 1's rule lookup. It does NOT set `mitre_mapping = []` (that was v3's silent-severity-cap bug).

### Duration budget

- p50: 30 seconds on qwen3.5:4b, CPU
- p95: 60 seconds on qwen3.5:4b, CPU

If using foundation-sec-reasoning here (recommended for accuracy), add ~50%.

---

## 9. Stage 4 — Analyst Agent (LLM #2)

### What it does

Second LLM call. Produces the verdict + likelihood + impact assessments. This is where the actual "is this real and how bad is it" judgment happens.

### Input — sanitized summary, not raw evidence

`_summarize_evidence(context_output, enriched_evidence)` reduces the full package to a typed, counted, truncated view. **This is the prompt injection firewall.**

What Stage 4 sees:
- `rule_context` — pass-through from Stage 1
- `asset_context` — pass-through from Stage 1
- `threat_intel` — per-entry: `{observable, type, verdict, score, details_truncated_300, analyzer}`
- `temporal_context` — COUNTS only: `{total_related_alerts, host, user}`
- `historical_context` — COUNTS only: `{tp_count, fp_count, avg_severity}`
- `mitre_mapping` — from Stage 3 (refined)
- `investigation_gaps` — pass-through, list of what failed
- `contextual_modifiers` — from Stage 3 (pass-through)

What Stage 4 does NOT see:
- Raw log lines
- Full command lines (only presence-checked in Stage 3's typed extraction)
- Cortex report bodies
- Any attacker-controllable free-text

### Output — `TriageVerdict`

```json
{
  "likelihood": "likely",
  "impact_if_true": "severe",
  "verdict": "true_positive",
  "reasoning": "Rule severity is high, TI verdicts return unknown but URL is a public GitHub release for known offensive security tool. Asset criticality is high (admin workstation). No FP indicators from rule falsepositives list. Recommend immediate case creation.",
  "summary": "PowerShell download of credential dumping tool xordump.exe on admin workstation. Likely credential access preparation. Escalate for immediate investigation.",
  "recommended_action": "create_case",
  "evidence_citations": [
    "rule_context.severity=high",
    "asset_context.criticality=high",
    "cortex_results[0].verdict=unknown but url matches known offensive tooling"
  ]
}
```

### Why Stage 4 does NOT output likelihood/impact scores

It outputs the *labels* (`unlikely`/`possible`/`likely`/`near_certain`). Those labels map to numeric ranges in Stage 5's formula. LLMs are OK at labels, terrible at numbers.

### Fallback

Invalid JSON or LLM failure:

```python
def stage_4_fallback(context: ContextualAssessment, evidence: EnrichedEvidence) -> TriageVerdict:
    return TriageVerdict(
        likelihood="possible",
        impact_if_true="moderate",
        verdict="needs_review",
        reasoning="Stage 4 LLM unavailable, defaulting to human review",
        summary="Automated triage failed, analyst review required",
        recommended_action="needs_review",
        evidence_citations=[],
    )
```

**Never fabricates verdict. Always escalates to human on failure.**

### Duration budget

- p50: 60 seconds on foundation-sec-reasoning, CPU
- p95: 90 seconds on foundation-sec-reasoning, CPU

Foundation-sec-reasoning here is recommended over qwen3:8b for the verdict quality on security-domain reasoning.

---

## 10. Stage 5 — Hybrid priority scoring

### What it does

Deterministic scoring formula with bounded LLM modifier adjustments. Produces a numeric priority score 0-100 and a P1-P5 label for queue ordering.

### The formula

```
base_likelihood = (
    rule_severity_score           # 0-90 from Sigma level mapping
    + threat_intel_adjustment      # -40 to +30 from Cortex results
    + fp_rate_penalty              # -40 × long_term_fp_rate
    + historical_pattern_adjustment  # -25 to +15 from closed cases
)

base_impact = (
    asset_criticality_score        # 20 to 95 from iTop
    + mitre_technique_severity     # 0-100 = max(technique.priority_0_5) × 20
    + blast_radius_score           # min(20, related_hosts × 5)
    + data_sensitivity_bonus       # 0-25 from iTop data tags
)

base_confidence = (
    evidence_completeness_pct      # 0-100, % of expected fields populated
    - (gap_count × 10)             # each investigation gap = -10
    + verdict_consistency_bonus    # +20 if LLM verdict matches deterministic prediction
    + source_reliability_bonus     # +15 if source_engine == sigma with MITRE tags
)

# Apply LLM modifiers with bounds
adjusted_likelihood = apply_modifiers(base_likelihood, context.contextual_modifiers, dimension="likelihood")
adjusted_impact = apply_modifiers(base_impact, context.contextual_modifiers, dimension="impact")

# Each single modifier capped at ±25
# Total LLM adjustment per dimension capped at ±30
# This prevents prompt injection / overconfident LLM from dominating

velocity_multiplier = (
    1.3 if temporal_context.related_alerts_1h > 5 else
    1.2 if context.correlation_decision.kill_chain_progression_detected else
    1.15 if temporal_context.recent_similar_tp else
    0.8 if evidence_age_hours > 24 else
    1.0
)

final_score = clamp(0, 100,
    (0.40 × adjusted_likelihood +
     0.35 × adjusted_impact +
     0.25 × adjusted_confidence
    ) × velocity_multiplier
)
```

### Priority mapping

| Score | Priority | Action | SLA |
|---|---|---|---|
| 85-100 | **P1 Critical** | create_case + page on-call | Immediate |
| 65-84 | **P2 High** | create_case + notify SOC | <15 min |
| 40-64 | **P3 Medium** | create_case | <2 hours |
| 20-39 | **P4 Low** | queue for review | Same day |
| 0-19 | **P5 Informational** | close as FP candidate | Weekly review |

### Confidence gate

If `base_confidence < 40`: escalate priority by one level (P3 → P2, etc). **Low confidence means human review.**

### Score breakdown — full audit trail

Every score contains a `breakdown` dict with every intermediate value:

```json
{
  "score": 77,
  "priority": "P2",
  "base_likelihood": 60,
  "adjusted_likelihood": 85,
  "likelihood_modifiers_applied": [
    {"factor": "credential_dumping_tool_download", "adjustment": +15},
    {"factor": "administrator_account_context", "adjustment": +10}
  ],
  "base_impact": 70,
  "adjusted_impact": 85,
  "impact_modifiers_applied": [
    {"factor": "domain_admin_credential_exposure", "adjustment": +15}
  ],
  "base_confidence": 75,
  "confidence_gate_applied": false,
  "velocity_multiplier": 1.0,
  "final_score_calculation": "(0.40 × 85 + 0.35 × 85 + 0.25 × 75) × 1.0 = 77"
}
```

Every priority is fully auditable. Every LLM modifier is bounded and logged.

### Is this really needed?

**Yes, absolutely.** The severity table lookup in v3 produced 4 buckets — useless for queue ordering. Analysts drown in "20 highs, which first?" With continuous scoring, the SOC dashboard sorts by `priority_score DESC` and analysts work top-down.

### The intelligence question — is this actually intelligent?

Look at where reasoning happens vs. where math happens:

| Component | Type | Why this way |
|---|---|---|
| Rule severity mapping | Deterministic | Sigma level is a fixed label, not a judgment |
| TI verdict → score | Deterministic | Cortex output is already structured |
| FP rate | Deterministic | It's a rate, math is correct answer |
| Asset criticality | Deterministic | iTop assigns this, formula reads it |
| MITRE severity | Deterministic | Bitsight-style prevalence score, precomputed |
| **Contextual modifiers** | **LLM** | **This is where reasoning belongs** |
| **Correlation decision** | **LLM** | **Requires understanding of kill-chain semantics** |
| **Verdict** | **LLM** | **Requires synthesizing evidence into judgment** |
| Final math | Deterministic | Math ensures consistency across alerts |

The LLM contributes **judgment about context that the formula can't see**. The formula ensures **consistency and reproducibility across alerts**.

Pure LLM scoring is unreliable (research proven). Pure deterministic scoring lacks context sensitivity. Hybrid is the answer.

### Duration budget

<200ms. Pure Python math + logging.

---

## 11. Stage 6 — Audit and feedback

### What it does

Two things, both async and non-blocking on the response:

1. **Structured audit log to Elasticsearch** — `so-triage-audit` index
2. **FP feedback write to SQLite** — updates the FP tracker

### Audit log payload

```json
{
  "@timestamp": "2026-08-08T10:23:45.678Z",
  "alert_id": "~1190993992",
  "priority_score": 77,
  "priority_label": "P2",
  "verdict": "true_positive",
  "recommended_action": "create_case",
  "stage_durations_ms": {
    "stage_0": 15,
    "stage_1": 5432,
    "stage_2": 2103,
    "stage_3": 34521,
    "stage_4": 61234,
    "stage_5": 45,
    "total": 103350
  },
  "llm_calls": {
    "stage_3": {"model": "qwen3.5:4b", "prompt_tokens": 3421, "completion_tokens": 891, "duration_ms": 34521},
    "stage_4": {"model": "foundation-sec-reasoning", "prompt_tokens": 2103, "completion_tokens": 612, "duration_ms": 61234}
  },
  "investigation_gaps": ["itop_lookup: timeout after 5s"],
  "score_breakdown": { ... },
  "prompt_hashes": {
    "stage_3": "sha256:abc...",
    "stage_4": "sha256:def..."
  }
}
```

**Why full audit:**
- **Analyst dispute** — analyst overrides verdict, we can trace exactly which evidence and which modifier drove the incorrect score
- **Model drift detection** — track priority score distribution over time, alert if it shifts
- **Prompt injection detection** — if modifier reasoning contains unusual patterns, flag
- **Cost/latency monitoring** — token counts + durations per stage

### FP feedback loop

When analyst closes a case as FP, n8n POSTs to `/feedback` endpoint:

```json
{
  "thehive_alert_id": "~1190993992",
  "final_verdict": "false_positive",
  "analyst_reason": "SCCM software deployment"
}
```

Agent-service writes to SQLite:
```sql
INSERT INTO fp_events (rule_uuid, host, is_fp, triage_timestamp, analyst_reason)
VALUES (?, ?, TRUE, NOW(), ?)
```

Next time this rule fires on this host, `get_fp_signal` returns updated rate. **This is the AACT-style learning loop that closes the system.**

### Is this really needed?

**Audit log — yes, non-negotiable.** Without it you have no observability into a production system. Analysts will override verdicts; you need to know why to improve.

**FP feedback — yes.** Without it, the FP tracker never learns. It's the difference between a static rule-based system and an adaptive one.

---

## 12. The evidence contract between stages

Every stage output is a strict Pydantic model. Schema mismatches fail loudly, not silently (v3's biggest bug).

```
AlertWebhookPayload  ─Stage 0→  CanonicalAlert            (alert_builder.py, existing)
CanonicalAlert       ─Stage 1→  RawEvidence               (new)
RawEvidence          ─Stage 2→  EnrichedEvidence          (new — RawEvidence + rag_context)
EnrichedEvidence     ─Stage 3→  ContextualAssessment      (new — LLM output, validated)
ContextualAssessment ─Stage 4→  TriageVerdict             (existing, updated)
                     via _summarize_evidence firewall
TriageVerdict +      ─Stage 5→  PriorityScore + Result    (new — hybrid scoring)
ContextualAssessment
```

Every arrow is a Pydantic transformation with `Field(...)` required guards. Missing required field → 500 with specific error. This eliminates:
- v3's field name mismatch bug (`related_alerts_same_host_24h` vs `related_alerts_24h`)
- Silent evidence loss between agents
- Type confusion causing runtime errors

---

## 13. Every tool, every backend — the honest inventory

| Tool | Backend | Stage | Duration | Really needed? | Failure impact |
|---|---|---|---|---|---|
| `get_fp_signal` | Local SQLite | 1 | <100ms | **Critical** | Scoring degrades, no crash |
| `detection_rule_lookup` | ES `so-detection` | 1 | ~500ms | **Critical** | MITRE via Qdrant fallback |
| `search_open_cases_by_entities` | TheHive | 1 | ~2s | **High** | All alerts default to new case |
| `search_closed_cases_by_rule` | TheHive | 1 | ~2s | **Medium** | No historical prior, formula OK |
| `itop_asset_lookup` | iTop CMDB | 1 | ~2s | **Critical** | Impact scoring degrades to medium |
| `elasticsearch_related_alerts` | Security Onion ES | 1 | ~1s | **High** | No velocity signal, no cluster detection |
| `elasticsearch_process_history` | Security Onion ES | 1 | ~1s | **Medium** (endpoint only) | Less context for Stage 3 |
| Cortex results | Already in `canonical_alert` (via `alert_builder.py` from `hive_alert.observables[].reports`) | (pre-Stage 1) | 0 | **High** | No TI signal, all IOCs "unknown" |
| `qdrant_retrieve_mitre` | Qdrant `mitre_techniques` | 2 | ~1s | **High** | MITRE grounding lost |
| `qdrant_retrieve_playbooks` | Qdrant `soc_playbooks` | 2 | ~1s | **High** (when triggers) | LLM reasons from scratch |
| `qdrant_retrieve_cve` | Qdrant `cve_context` | 2 | ~1s | **Marginal** | Impact scoring slightly less precise |
| Context LLM call | Ollama | 3 | ~60s | **Critical** | Deterministic fallback |
| Analyst LLM call | Ollama | 4 | ~90s | **Critical** | needs_review default |

**Total backend dependencies for full operation: 6** (SQLite, ES, TheHive, iTop, Qdrant, Ollama)

**Backends we removed compared to v3:** Cortex from Stage 2 (now pre-Stage 1 via n8n).

**Backends that MUST be populated with real data before deployment:**
1. **iTop** — needs actual asset criticality, network zones, ownership. Not just default entries.
2. **Qdrant `mitre_techniques`** — needs MITRE ATT&CK STIX ingest.
3. **Qdrant `soc_playbooks`** — needs at least 10 hand-authored playbooks for top alert patterns.

Everything else can be empty on day 1 and populate through usage (FP tracker, closed cases).

---

## 14. Explicit non-goals — things NOT to build

This system was designed by deliberately rejecting a more "agentic" alternative design. If you find yourself about to add any of the following, stop and re-read §2 — it is very likely a step backward, not an improvement:

| Do NOT build | Why it's tempting | Why it's wrong here |
|---|---|---|
| A ReAct agent for evidence gathering | "Let the LLM decide what to look up" feels more flexible | The tool sequence is fixed and known; an agent choosing it adds latency, cost, and a new failure mode for zero benefit |
| Tool-calling on Stage 3 or Stage 4 | "Give the analyst agent the ability to look things up itself" | All evidence is already gathered by Stage 1–2; tool access on the interpreting agents reopens the prompt-injection surface that `_summarize_evidence` exists to close |
| A `tools/registry.py`-style dynamic tool registration system | Feels more "extensible" | There is no dynamic tool selection anywhere in this system — every backend call in Stage 1 is a fixed, named async function call |
| A recursion-limit / step-budget calculation for any agent loop | Copy-pasted instinct from LangGraph ReAct examples | There are no loops. If you're computing a recursion limit, you've built a loop that shouldn't exist |
| A 4-bucket (or any N-bucket) severity lookup table as the final output | Simple, matches how humans first think about severity | Produces no queue ordering; see §10 for why a continuous formula is required instead |
| Direct LLM-authored numeric scores anywhere | Feels natural to just "ask the model for a score 0–100" | Empirically unreliable — LLMs are inconsistent at direct numeric scoring; see §10 |
| A single Qdrant collection with a `collection` discriminator field for MITRE/playbooks/CVE | Seems simpler than managing three collections | Cross-content-type score comparison is meaningless; use three separate collections, §7 |
| More than two LLM calls per alert on this hardware | "One more agent surely helps accuracy" | Every additional LLM call adds 30–100+ seconds on CPU-only inference; the two-call budget is the hard constraint that makes this deployable at all |
| Any write-capable tool wired into the live graph | Convenient to "just let it close obvious false positives automatically" | This system is read-only by construction; all case-modifying actions happen in n8n after human review, full stop |

If a future requirement seems to demand one of the above, that is a signal to bring it back for architectural review — not to quietly add it during implementation.

---

## 15. Failure modes and degradation

Every stage has an explicit failure path. The system NEVER returns 500 to n8n from LLM misbehavior. It NEVER hallucinates a verdict. It degrades to `needs_review` with specific reasons.

| Failure | Detection | Handler | User-visible effect |
|---|---|---|---|
| Bad payload from n8n | Pydantic validation Stage 0 | 400 with error | n8n retries or logs |
| Redis down | Connection refused | Skip dedup, continue | Occasional duplicate processing |
| Backend timeout in Stage 1 | asyncio.wait_for | Gap logged, continue | Scoring degrades, confidence lower |
| Backend down in Stage 1 | Connection error | Gap logged, continue | Same as above |
| Qdrant empty collection | Empty result | Empty rag_context | Stage 3 reasons without RAG |
| Qdrant unreachable | Connection error | Gap logged | Same as above |
| Stage 3 LLM raises | Exception | Deterministic fallback | MITRE from rule_context, no modifiers |
| Stage 3 LLM invalid JSON | Pydantic parse error | Deterministic fallback | Same as above |
| Stage 4 LLM raises | Exception | needs_review default | Analyst manual review |
| Stage 4 LLM invalid JSON | Pydantic parse error | needs_review default | Same as above |
| Score computation error | Try/except | Log + return needs_review | Analyst manual review |
| Audit log write fails | Try/except | Log to stderr | Loss of one audit event |
| FP feedback write fails | Try/except | Log to stderr | FP tracker misses one event |

**Every failure results in a valid TriageResult being returned to n8n. Never a 5xx.**

---

## 16. Deployment checklist

### Prerequisites (must be true before day 1)

- [ ] iTop populated with asset criticality for all hosts SO monitors
- [ ] iTop populated with network zones (`internal_restricted`, `dmz`, `internal_open`)
- [ ] Qdrant `mitre_techniques` ingested (STIX bundle from mitre/cti)
- [ ] Qdrant `soc_playbooks` seeded with 10+ hand-authored playbooks
- [ ] TheHive `so-detection` index accessible for rule lookup
- [ ] Ollama has both models pulled: `qwen3.5:4b` and `foundation-sec-reasoning`
- [ ] Redis running (or explicit acknowledgment that dedup is disabled)
- [ ] Elasticsearch `so-triage-audit` index template created
- [ ] n8n workflow configured with 300s HTTP timeout on `/triage`
- [ ] Firewall allows agent-service → SO ES on 9200

### Configuration validation

- [ ] `python config.py` prints all resolved settings, no missing required vars
- [ ] `curl http://172.20.24.224:8000/health` returns 200
- [ ] Test alert produces valid TriageResult (integration test)

### Monitoring

- [ ] Prometheus metrics scraping enabled
- [ ] Grafana dashboard showing p50/p95/p99 latency per stage
- [ ] Alert on: >30% of triages returning `needs_review`
- [ ] Alert on: >10% of triages with confidence < 40
- [ ] Alert on: Stage 3 or Stage 4 fallback rate > 5%

### First-month operations plan

Week 1: Tier 0 (advisory only)
- Every verdict annotates the case, nothing auto-acts
- Analyst reviews all decisions
- Track agreement rate (Cohen's κ)

Week 2-3: Continue Tier 0, tune formula weights
- Analysts flag disagreements
- Adjust MODIFIER_STRENGTHS if LLM is systematically over/under-weighting
- Do NOT move to Tier 1 without κ > 0.8

Week 4+: Consider Tier 1 for P4/P5 only
- Auto-close P5 as FP after 24h if no analyst action
- P1-P3 always require analyst approval
- Never auto-execute containment

---

## 17. Is this production-ready? — brutal honesty

### What's realistic

**The architecture is deployable.** Every component exists, every integration is proven, latency budget is respected. A solo engineer can build this in 3-4 weeks.

**The scoring is defensible.** Hybrid formula + bounded LLM modifiers is what actual production SOC platforms converge to. Full audit trail meets compliance expectations.

**The failure modes are handled.** No LLM failure produces a wrong verdict. Every degradation path preserves analyst review.

### What's still hard

**iTop population** is the single biggest risk. Without accurate asset criticality, `impact` scoring degrades to a constant. In real SOCs this takes months of CMDB work that isn't glamorous.

**Playbook authoring** requires SOC expertise. If the internship doesn't include a senior analyst to write playbooks, expect Stage 2 playbook retrieval to be empty for most alerts. That's OK — degrades to "LLM reasons from scratch" not failure.

**CPU inference latency is real.** Even with 2 LLM calls, 150s per alert on your hardware. This works for a SOC processing 100-500 alerts per day. It does NOT work for 10,000/day environments. Those need GPU.

**Weight tuning matters.** The default formula weights (0.40 / 0.35 / 0.25) and modifier strengths (5/10/15/25) are educated guesses. Real deployment needs 30-60 days of tuning against analyst feedback.

### What this is NOT

- Not autonomous. Every case-modifying action still requires analyst approval.
- Not scalable to thousands of alerts/hour without GPU.
- Not a replacement for a SIEM. Security Onion is still the SIEM; this reduces its noise.
- Not a threat hunter. Only reactive triage on already-fired alerts.

### The one thing you should read as an internship deliverable

This architecture demonstrates:
- **SOC-domain understanding** — priority scoring, MITRE grounding, FP feedback loops
- **Practical AI engineering** — bounded LLM adjustments, prompt injection defense, hybrid approaches
- **Systems design under constraints** — CPU-only hardware, solo developer, real SOC pressures
- **Honest engineering** — every choice has a "is this really needed" answer

It won't win an academic novelty award. It will demonstrate that you can build something a real SOC would actually run.

That's the right internship deliverable.

---

## 18. Repository structure and build order

### Target repository layout

Build exactly this structure. Nothing here should be imported from, or copied out of, any other project — every file listed is written fresh in this repo.

```
soc-3s/
├── CLAUDE.md                      # agent operating instructions (see below)
├── SOC-3s-ARCHITECTURE.md         # this document
├── .env.example                   # see §19
├── config.py                      # loads + validates all env vars, fails fast on missing required
├── main.py                        # FastAPI app: POST /triage, POST /feedback, GET /health
├── pipeline.py                    # orchestrates Stage 0 → 6 in sequence, owns the top-level try/except
│
├── schemas/
│   ├── __init__.py
│   ├── alert.py                   # AlertWebhookPayload, CanonicalAlert, Observables, Rule, Host, User, Process, Network, File
│   ├── evidence.py                # RawEvidence, EnrichedEvidence, Gap
│   ├── assessment.py              # ContextualAssessment, MitreMapping, CorrelationDecision, ContextualModifier
│   ├── verdict.py                 # TriageVerdict
│   └── result.py                  # PriorityScore, TriageResult
│
├── alert_builder.py                # raw Security Onion alert → CanonicalAlert (pure Python, no LLM)
│
├── nodes/
│   ├── __init__.py
│   ├── validate.py                 # Stage 0: Pydantic validation + Redis dedup
│   ├── gather.py                   # Stage 1: asyncio.gather over all backend tools, timeout-bounded
│   ├── rag.py                      # Stage 2: conditional Qdrant retrieval (mitre / playbooks / cve)
│   ├── context.py                  # Stage 3: single LLM call, no tools, + deterministic fallback
│   ├── analyze.py                  # Stage 4: single LLM call, no tools, + _summarize_evidence firewall + fallback
│   ├── score.py                    # Stage 5: calls into scoring.py, builds TriageResult
│   └── audit.py                    # Stage 6: async ES audit log write + FP feedback write
│
├── scoring.py                      # pure Python: compute_base_priority, apply_llm_modifiers, compute_final_priority
├── scoring_config.py                # weights, modifier strength constants, priority thresholds (see §19)
│
├── tools/
│   ├── __init__.py
│   ├── fp_tracking.py               # SQLite: get_fp_signal, record_triage_outcome
│   ├── detection_rules.py           # ES so-detection: detection_rule_lookup (Sigma/Suricata/YARA parsing)
│   ├── thehive.py                   # search_open_cases_by_entities, search_closed_cases_by_rule, get_full_alert_with_analysis
│   ├── itop.py                      # itop_asset_lookup
│   ├── elasticsearch.py             # elasticsearch_related_alerts, elasticsearch_process_history
│   └── qdrant.py                    # qdrant_retrieve (mitre_techniques / soc_playbooks / cve_context)
│
├── prompts/
│   ├── __init__.py
│   ├── context_agent.py             # Stage 3 system + user prompt builder, output schema
│   └── analyst_agent.py             # Stage 4 system + user prompt builder, output schema, GBNF grammar if applicable
│
├── scripts/
│   ├── ingest_mitre.py               # populate Qdrant mitre_techniques from MITRE ATT&CK STIX bundle
│   ├── ingest_playbooks.py           # populate Qdrant soc_playbooks from authored YAML/JSON playbook files
│   ├── ingest_cve.py                 # populate Qdrant cve_context from NVD feed, filtered
│   └── playbooks/                    # authored playbook source files (see §7)
│
├── data/
│   └── fp_events.db                  # SQLite FP tracker (created on first run)
│
└── tests/
    ├── conftest.py
    ├── test_alert_builder.py
    ├── test_gather.py
    ├── test_rag.py
    ├── test_context.py
    ├── test_analyze.py
    ├── test_scoring.py
    ├── test_pipeline_e2e.py          # full Stage 0→6 with mocked backends
    └── fixtures/                     # sample raw SO alerts (sigma/suricata/yara), sample backend responses
```

### CLAUDE.md — place this file at the repo root before writing any code

```markdown
# SOC-3s — Agent Operating Instructions

This is a greenfield build. Read SOC-3s-ARCHITECTURE.md in full before writing anything.

## Hard constraints
- Exactly 2 LLM calls per alert, in nodes/context.py and nodes/analyze.py. No more, anywhere.
- Neither LLM call has tool access. Both are single-shot completions.
- No ReAct loops, no tool-calling agents, no recursion-limit math. If you're about to write
  one, stop — re-read Architecture doc §2 and §14 first.
- Every stage input/output is a Pydantic model from schemas/. Never pass a raw dict between
  nodes/*.py files.
- Every backend call in nodes/gather.py runs inside asyncio.gather(..., return_exceptions=True)
  with an explicit per-tool timeout. A failed or slow backend produces a logged Gap, never
  an unhandled exception that reaches the caller.
- Stage 4's LLM never outputs a numeric score. It outputs likelihood/impact labels and
  ContextualModifier entries (dimension, factor_name, direction, strength, reasoning).
  scoring.py is the only place a number is computed.
- Build one node at a time, in the order given in Architecture §18. Write tests for each
  node before moving to the next. Stop for review after each node.

## What "done" means for each node
A node is done when: it has a typed Pydantic input and output, it has unit tests covering
the happy path and at least one failure/timeout path, and it never raises an unhandled
exception to its caller (gather.py) or never fails the whole pipeline (context.py /
analyze.py, which fall back to deterministic defaults on any LLM failure).
```

### Build order — one node per work session, in this sequence

1. `schemas/alert.py` + `alert_builder.py` + its tests — the foundation everything else reads. **Do not write `alert_builder.py` from scratch.** A working, 160-test-passing version already exists from prior work on this project and must be carried into this repo as the starting point, then adapted only where its field names need to match the new `schemas/alert.py`. See `SOC-3s-IMPLEMENTATION-GUIDE.md` §1.1 for exactly what to bring over and what small edits are expected. Bring `so-alert-reference/` into the repo root alongside it as build-time-only reference material (§1.2 of the same guide) — never imported at runtime.
2. `schemas/evidence.py` + `tools/fp_tracking.py`, `tools/detection_rules.py`, `tools/thehive.py`, `tools/itop.py`, `tools/elasticsearch.py` — each tool function standalone-tested against a mocked backend before wiring into gather
3. `nodes/gather.py` — wires the above tools into the parallel Stage 1 call, with timeouts and gap-reporting
4. `tools/qdrant.py` + three ingest scripts + `nodes/rag.py` — Stage 2
5. `schemas/assessment.py` + `prompts/context_agent.py` + `nodes/context.py` — Stage 3, including the deterministic fallback path
6. `schemas/verdict.py` + `prompts/analyst_agent.py` + `nodes/analyze.py` — Stage 4, including `_summarize_evidence` and the fallback path
7. `scoring_config.py` + `scoring.py` + `schemas/result.py` + `nodes/score.py` — Stage 5
8. `nodes/audit.py` — Stage 6
9. `nodes/validate.py` — Stage 0 (built last since it only needs the final CanonicalAlert shape and Redis, both stable by now)
10. `pipeline.py` + `main.py` — orchestration and the FastAPI surface
11. `tests/test_pipeline_e2e.py` — full pipeline against fixture alerts, mocked backends
12. Manual integration pass against one real alert per engine (sigma / suricata / yara) through the actual backends

Do not skip ahead. Each step depends on the previous step's tested contract, not on assumptions about what a later step will need.

---

## 19. Configuration reference

```bash
# LLM — two single-shot calls, no tools, on either endpoint
LLM_BASE_URL=http://172.20.24.225:11434/v1
LLM_MODEL=qwen3.5:4b
LLM_API_KEY=sk-no-auth
LLM_ANALYZE_BASE_URL=http://172.20.24.225:11434/v1
LLM_ANALYZE_MODEL=foundation-sec-reasoning
LLM_ANALYZE_API_KEY=sk-no-auth

# Backends
THEHIVE_URL=http://172.20.24.221:9000
THEHIVE_API_KEY=<...>
CORTEX_URL=http://172.20.24.221:9001
CORTEX_API_KEY=<...>
ITOP_URL=http://172.20.24.223
ITOP_USER=<...>
ITOP_KEY=<...>
ES_URL=https://172.20.24.58:9200
ES_API_KEY=<...>
QDRANT_URL=http://172.20.24.224:6333
QDRANT_EMBEDDING_MODEL=BAAI/bge-m3

# Storage
FP_DB_PATH=./data/fp_events.db
REDIS_URL=redis://localhost:6379  # optional — absence disables dedup, never blocks pipeline

# Timeouts (seconds) — Stage 1 tools
STAGE_1_TOOL_TIMEOUT_ITOP=5
STAGE_1_TOOL_TIMEOUT_THEHIVE=5
STAGE_1_TOOL_TIMEOUT_ES=3
STAGE_1_TOOL_TIMEOUT_QDRANT=3
STAGE_3_LLM_TIMEOUT=120
STAGE_4_LLM_TIMEOUT=180

# Scoring weights (tunable, see §10)
WEIGHT_LIKELIHOOD=0.40
WEIGHT_IMPACT=0.35
WEIGHT_CONFIDENCE=0.25
MODIFIER_STRENGTH_WEAK=5
MODIFIER_STRENGTH_MEDIUM=10
MODIFIER_STRENGTH_STRONG=15
MODIFIER_STRENGTH_CRITICAL=25
MODIFIER_MAX_TOTAL_PER_DIMENSION=30

# Dedup
DEDUP_WINDOW_SECONDS=300
```

`config.py` must load all of the above at import time and raise immediately on any missing required variable — no module should be able to import a partially-configured client.

---

*This document is the authoritative build specification. If implementation reveals that something here is wrong or incomplete, update this document as part of that change — do not let code and spec silently diverge.*
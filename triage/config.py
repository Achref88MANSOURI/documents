"""Configuration. Loads and validates every environment variable at import
time and raises immediately on a missing required one (architecture §19) — no
module should be able to import a partially-configured client.

`.env` is parsed with a small stdlib loader rather than python-dotenv, which is
not installed. Real process environment always wins over the file, so container
env vars override a stale `.env` on the host.

Run `python config.py` to print all resolved settings (architecture §16's
configuration-validation checklist item). Secrets are masked in that output.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent
ENV_FILE = REPO_ROOT / ".env"

_SECRET_HINTS = ("KEY", "TOKEN", "PASSWORD", "SECRET", "PWD")


def _load_env_file(path: Path) -> None:
    """Minimal `.env` parser: KEY=VALUE, `#` comments, blank lines, optional
    surrounding quotes. Does NOT overwrite variables already in the real
    environment."""
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.split(" #", 1)[0].strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = value


_load_env_file(ENV_FILE)


class ConfigError(RuntimeError):
    """Raised at import time when a required variable is missing or unusable."""


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(
            f"Required environment variable {name} is missing or empty. "
            f"See .env.example for the full variable set."
        )
    return value


def _optional(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name, "").strip()
    return value or default


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc


def _float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc


# ---------------------------------------------------------------------------
# LLM — both stages run foundation-sec-reasoning in this deployment. See
# CLAUDE.md "Deployment-specific decisions" for the latency trade-off.
# ---------------------------------------------------------------------------
LLM_BASE_URL = _required("LLM_BASE_URL")
LLM_MODEL = _required("LLM_MODEL")
LLM_API_KEY = _optional("LLM_API_KEY", "sk-no-auth")
LLM_ANALYZE_BASE_URL = _optional("LLM_ANALYZE_BASE_URL") or LLM_BASE_URL
LLM_ANALYZE_MODEL = _optional("LLM_ANALYZE_MODEL") or LLM_MODEL
LLM_ANALYZE_API_KEY = _optional("LLM_ANALYZE_API_KEY") or LLM_API_KEY

# Live-caught 2026-08-23 (CLAUDE.md): a real alert's Stage 3 prompt (4193
# real tokens, confirmed by the backend's own 400 error) plus the previous
# fixed max_tokens=4000 exceeded this model's real context window and the
# call failed outright. nodes/context.py and nodes/analyze.py both cap their
# requested max_tokens against this at call time. LLM_MAX_CONTEXT_TOKENS
# defaults to 8192 — this deployment's real max_model_len, confirmed live via
# GET /v1/models — override if a future backend's window differs.
# LLM_TOKEN_ESTIMATE_CHARS_PER_TOKEN: no local tokenizer is available for
# this model (a non-OpenAI BPE vocab), so prompt size is estimated from
# character count.
#
# RECALIBRATED same day, live-caught again: the first fix's 3.5 default
# (this session's early real vLLM usage data measured ~3.7-3.8 chars/token on
# a canonical_alert with mostly-empty process/host/user fields) still
# UNDER-estimated once a real n8n payload bug was fixed and canonical_alert
# started carrying its real content (entity_id GUIDs, hashes, host/user
# identifiers — text that tokenizes far less efficiently than prose). Real
# measured ratio on that alert: 19592 chars / 5799 real tokens = 3.38
# chars/token — confirmed by the backend's own 400 error
# ("...your prompt contains at least 5799 input tokens..."), while the old
# 3.5-based estimate + 200-token margin predicted only 2394 available,
# landing at 5799+2394=8193 — one token over. 3.2 is now the default,
# genuinely conservative against BOTH real measurements taken this session
# (3.38 and ~3.7-3.8), and the margin is doubled to 400 as a second layer of
# defense — a single point estimate from a small number of real samples
# shouldn't be trusted down to single-digit-token precision.
LLM_MAX_CONTEXT_TOKENS = _int("LLM_MAX_CONTEXT_TOKENS", 8192)
LLM_TOKEN_ESTIMATE_CHARS_PER_TOKEN = _float("LLM_TOKEN_ESTIMATE_CHARS_PER_TOKEN", 3.2)
LLM_CONTEXT_SAFETY_MARGIN_TOKENS = _int("LLM_CONTEXT_SAFETY_MARGIN_TOKENS", 400)
# Floor so an unusually large prompt still requests SOME completion room
# rather than a degenerate near-zero value — below this the LLM likely can't
# produce valid schema-conformant JSON anyway; better to attempt and let the
# existing fallback machinery catch total failure than not attempt at all.
LLM_MIN_COMPLETION_TOKENS = _int("LLM_MIN_COMPLETION_TOKENS", 500)

# The `desired` argument nodes/context.py and nodes/analyze.py each pass into
# their own _capped_max_tokens() was a bare literal (4000 / 2000) until
# 2026-08-23 — fine for the foundation-sec-reasoning/Ollama/vLLM deployment
# this repo was built against, but a real blocker once LLM_BASE_URL was
# pointed at Gemini for testing: live-confirmed (GET /v1beta/models/
# gemini-3.6-flash) that model is a "thinking" model — it spends a variable,
# invisible chunk of the SAME max_tokens budget on internal reasoning before
# any visible JSON output, not reflected in completion_tokens. Reproduced
# live: max_tokens=300 truncated mid-object (finish_reason="length",
# ~284 hidden tokens consumed, 1 visible token); max_tokens=2000 completed
# cleanly (~243 hidden tokens that run). Gemini's own real limits (same
# live call): inputTokenLimit=1,048,576, outputTokenLimit=65,536 — both far
# above this deployment's original 8192-token calibration.
# Kept as separate per-stage config (not one shared constant) so Stage 3's
# heavier prompt and Stage 4's lighter one can be tuned independently, same
# pattern as the STAGE_3_LLM_TIMEOUT/STAGE_4_LLM_TIMEOUT split above.
# Defaults (4000/2000) are UNCHANGED from the original hardcoded values —
# raising these is a .env-only override for this Gemini test session, so the
# primary vLLM/Ollama deployment's calibration is undisturbed on revert.
STAGE_3_DESIRED_MAX_TOKENS = _int("STAGE_3_DESIRED_MAX_TOKENS", 4000)
STAGE_4_DESIRED_MAX_TOKENS = _int("STAGE_4_DESIRED_MAX_TOKENS", 2000)

# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------
THEHIVE_URL = _required("THEHIVE_URL").rstrip("/")
THEHIVE_API_KEY = _required("THEHIVE_API_KEY")

ITOP_URL = _required("ITOP_URL").rstrip("/")
ITOP_USER = _required("ITOP_USER")
# iTop REST auth is username + password (`auth_pwd`), not an API key — renamed
# from ITOP_KEY to ITOP_PWD to match. See CLAUDE.md's deployment-decisions log.
ITOP_PWD = _required("ITOP_PWD")

ES_URL = _required("ES_URL").rstrip("/")
ES_API_KEY = _optional("ES_API_KEY")  # empty is valid: an ES with no auth
# The bare SO host redirects to the web UI on 443; Elasticsearch is on 9200.
if ES_URL.count(":") < 2 and not ES_URL.rsplit(":", 1)[-1].isdigit():
    raise ConfigError(
        f"ES_URL={ES_URL!r} has no explicit port. Elasticsearch is on :9200 — "
        f"the bare host redirects (302) to the Security Onion web UI on 443."
    )
# Self-signed certificate on the SO manager.
ES_VERIFY_TLS = _optional("ES_VERIFY_TLS", "false").lower() in ("1", "true", "yes")

QDRANT_URL = _required("QDRANT_URL").rstrip("/")
QDRANT_EMBEDDING_MODEL = _optional("QDRANT_EMBEDDING_MODEL", "BAAI/bge-m3")
# The BAAI/bge-m3 model above is not loaded in-process (architecture §7's
# "loaded ONCE at service startup as a module-level singleton" assumes an
# in-process model). This deployment instead runs it behind its own HTTP
# microservice, colocated on the same host as Qdrant — verified live
# 2026-08-16, POST {"text": "..."} -> {"embedding": [float x 1024]}. See
# tools/qdrant.py.
EMBEDDING_API_URL = _required("EMBEDDING_API_URL").rstrip("/")

# OpenCTI — a deployment-added Stage-1 tool (tools/opencti.py), not in
# architecture v4's original 7-tool list. Direct GraphQL graph enrichment,
# separate from the OpenCTI Cortex analyzer whose taxonomy rows already arrive
# via THEHIVE_URL above. Verified live 2026-08-13 (GraphQL 7.260318.0).
OPENCTI_URL = _required("OPENCTI_URL").rstrip("/")
OPENCTI_TOKEN = _required("OPENCTI_TOKEN")

# ---------------------------------------------------------------------------
# Elasticsearch index names.
# so-detection is pinned EXACTLY — the `so-detection*` wildcard also matches
# so-detectionhistory (345,474 revision docs alongside 74,951 current rules),
# which would return stale rule versions. Verified live 2026-08-08.
# ---------------------------------------------------------------------------
ES_DETECTION_INDEX = _optional("ES_DETECTION_INDEX", "so-detection")
ES_ALERTS_INDEX = _optional("ES_ALERTS_INDEX", "logs-detections.alerts-so*")
ES_PROCESS_INDEX = _optional("ES_PROCESS_INDEX", ".ds-logs-endpoint.events.process-*")
# The real fired-Suricata-alert stream — separate from ES_ALERTS_INDEX, which is
# Sigma-only (100% event.module=sigma, live-verified). elasticsearch_related_alerts
# queries this index instead of ES_ALERTS_INDEX when investigation_profile ==
# "network_threat". Live-confirmed 2026-08-21: 254k+ real docs, growing.
ES_SURICATA_ALERTS_INDEX = _optional("ES_SURICATA_ALERTS_INDEX", "logs-suricata.alerts-so*")
ES_AUDIT_INDEX = _optional("ES_AUDIT_INDEX", "so-triage-audit")

# ---------------------------------------------------------------------------
# Storage. Architecture §19 names this FP_DB_PATH; this deployment standardised
# on FP_TRACKING_DB_PATH. Both are accepted, the deployment name wins.
# ---------------------------------------------------------------------------
FP_TRACKING_DB_PATH = (
    _optional("FP_TRACKING_DB_PATH") or _optional("FP_DB_PATH") or "./data/fp_events.db"
)
# Absent by design in this deployment — dedup no-ops, never blocks (§5).
REDIS_URL = _optional("REDIS_URL")

# ---------------------------------------------------------------------------
# Timeouts (seconds) — Stage 1 per-tool budgets, architecture §6 / §19
# ---------------------------------------------------------------------------
STAGE_1_TOOL_TIMEOUT_ITOP = _float("STAGE_1_TOOL_TIMEOUT_ITOP", 5.0)
STAGE_1_TOOL_TIMEOUT_THEHIVE = _float("STAGE_1_TOOL_TIMEOUT_THEHIVE", 5.0)
STAGE_1_TOOL_TIMEOUT_ES = _float("STAGE_1_TOOL_TIMEOUT_ES", 3.0)
STAGE_1_TOOL_TIMEOUT_QDRANT = _float("STAGE_1_TOOL_TIMEOUT_QDRANT", 3.0)
STAGE_1_TOOL_TIMEOUT_FP = _float("STAGE_1_TOOL_TIMEOUT_FP", 0.1)
STAGE_1_TOOL_TIMEOUT_OPENCTI = _float("STAGE_1_TOOL_TIMEOUT_OPENCTI", 5.0)
STAGE_3_LLM_TIMEOUT = _float("STAGE_3_LLM_TIMEOUT", 120.0)
STAGE_4_LLM_TIMEOUT = _float("STAGE_4_LLM_TIMEOUT", 180.0)
# Distinct from STAGE_1_TOOL_TIMEOUT_THEHIVE (Stage-1-scoped by name/
# convention) — this guards the one TheHive call nodes/analyze.py itself
# makes, fetching the merge target case's existing observables.
STAGE_4_TOOL_TIMEOUT_THEHIVE = _float("STAGE_4_TOOL_TIMEOUT_THEHIVE", 5.0)
# Distinct from STAGE_1_TOOL_TIMEOUT_QDRANT — guards nodes/analyze.py's own
# retrieve_playbooks call, built from Stage 3's refined MITRE mapping.
STAGE_4_TOOL_TIMEOUT_QDRANT = _float("STAGE_4_TOOL_TIMEOUT_QDRANT", 3.0)

# ---------------------------------------------------------------------------
# DEPLOYMENT_MODE — DEAD, kept only so an existing .env setting doesn't
# become an unknown-key surprise. SOC-3s Scoring System v3 (`newscoresystem.md`,
# `scoring_config.py`) is what defined this variable's meaning
# (shadow/live calibration status); v5 (`newdesign.md`) deleted that scoring
# stage entirely — priority now comes directly from Stage 4's LLM output
# (`TriageVerdict.priority_band`), which has no calibration-mode concept.
# Nothing in this codebase reads DEPLOYMENT_MODE any more.
# ---------------------------------------------------------------------------
DEPLOYMENT_MODE = os.getenv("DEPLOYMENT_MODE", "shadow").strip().lower()

DEDUP_WINDOW_SECONDS = _int("DEDUP_WINDOW_SECONDS", 300)

# ---------------------------------------------------------------------------
# Logging — see logging_config.py. LOG_LEVEL governs both the console and
# file handlers (there is only one level, not one per handler — simpler to
# reason about, and nothing in this deployment has needed the split yet).
# LOG_FILE empty/unset disables file logging entirely (console only).
# ---------------------------------------------------------------------------
LOG_LEVEL = _optional("LOG_LEVEL", "INFO")
LOG_FILE = _optional("LOG_FILE", "./logs/soc3s.log")


def _mask(name: str, value: Any) -> str:
    if value is None:
        return "<unset>"
    text = str(value)
    if any(hint in name for hint in _SECRET_HINTS) and text:
        return f"{text[:4]}…{text[-2:]} ({len(text)} chars)" if len(text) > 8 else "<set>"
    return text


def resolved_settings() -> dict[str, Any]:
    return {
        name: value
        for name, value in sorted(globals().items())
        if name.isupper() and not name.startswith("_")
    }


def describe() -> str:
    lines = [f"config.py — loaded from {ENV_FILE if ENV_FILE.is_file() else '<no .env>'}"]
    for name, value in resolved_settings().items():
        lines.append(f"  {name:34s} {_mask(name, value)}")
    return "\n".join(lines)


if __name__ == "__main__":
    print(describe())

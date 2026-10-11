# AI Banking Firewall — Blue-Team AI Firewall & Guardrail Defense

AI Banking Firewall is a **Defense-in-Depth AI security firewall** that intercepts untrusted
user inputs before any core banking action or API is executed.

---

## Architecture & Defense-in-Depth

```
Untrusted Input / Multi-Turn Session Stream
    │
    ▼
┌──────────────────────────────────────────────┐
│  Feature 1 · Multi-Turn Session Guard        │  session_guard.py
│  Context poisoning · Salami slicing defense  │
│  Sliding window state · Cumulative Risk (CRS)│
└─────────────────────┬────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────┐
│  Layer 1 · Deterministic Normalizer          │  normalizer.py
│  Unicode homoglyphs · Base64 · Hex · ROT-13  │
│  L33tspeak · Spaced chars · Invisible chars  │
│  XML delimiter sanitisation                  │
└─────────────────────┬────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────┐
│  Feature 2 · Canary Honeypot & Output Shield │  honey_shield.py
│  Session-bound Canary Tokens · PAN (Luhn)    │
│  IBAN / Routing / SSN exfiltration redaction │
└─────────────────────┬────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────┐
│  Layer 2 · Heuristic Fast-Path               │  evaluator.py
│  28+ regex patterns · Weighted scoring       │
│  Score ≥ 0.75 → Hard block (skip LLM)        │
└─────────────────────┬────────────────────────┘
                      │ (if score < 0.75)
                      ▼
┌──────────────────────────────────────────────┐
│  Layer 3 · Isolated LLM & Consensus Arbiter  │  evaluator.py &
│  Gemini 3.8 Flash · XML isolation wrapper    │  consensus_engine.py
│  Red-Team Auditor vs. Blue-Team Compliance   │
│  Fail-closed on any parse/API error          │
└─────────────────────┬────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────┐
│  Layer 4 · Financial Policy Gate             │  policy_gate.py
│  Transfer ceiling · Step-up auth             │
│  Recipient validation · Score thresholds     │
│  strict_binary_mode coercion                 │
└─────────────────────┬────────────────────────┘
                      │
                      ▼
               FirewallVerdict
          (APPROVED / BLOCKED / CHALLENGE)
```

---

## 🎛️ Blue-Themed Cyber Defense Cockpit (Feature 4)

Launch the interactive Security Operations Center (SOC) dashboard:

```bash
python server.py
```
Open **[http://localhost:8000](http://localhost:8000)** in your browser.
- **One-click presets**: Balance inquiry, P2P transfer, memo prompt injection, Base64 obfuscation, movie roleplay jailbreak, transfer ceiling breach, and multi-turn salami slicing.
- **Visual Layer Stepper**: Shows in real-time which layer neutralized the threat.
- **REST API Endpoint**: `POST /api/v1/firewall/inspect` ready to intercept requests for any downstream banking application.

---

## Files

| File | Layer | Purpose |
|---|---|---|
| `schemas.py` | Contract | All Pydantic models — `FirewallRequest`, `FirewallVerdict`, enums |
| `normalizer.py` | 1 | Deterministic text normalisation (8 passes) |
| `evaluator.py` | 2 + 3 | Heuristic blocklist + isolated LLM semantic analysis |
| `policy_gate.py` | 4 | Financial business rules (cannot be AI-overridden) |
| `firewall.py` | Orchestrator | Wires all 4 layers; single public `evaluate()` entry point |
| `tests/test_firewall.py` | Testing | 10-case adversarial matrix (offline + integration) |

---

## Verdict JSON Contract

```jsonc
{
  "verdict":          "APPROVED" | "BLOCKED" | "CHALLENGE",
  "risk_level":       "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "threat_category":  "NONE" | "DIRECT_PROMPT_INJECTION"
                    | "DELIMITER_LEAK" | "ROLEPLAY_JAILBREAK"
                    | "TOKEN_OBFUSCATION",
  "confidence_score": 0.0,              // float 0.0–1.0
  "rationale":        "Explanation...",
  "sanitized_payload": { ... } | null, // only on APPROVED
  "action_required":  "PROCEED_TO_CORE_API"
                    | "DROP_AND_LOG"
                    | "TRIGGER_STEP_UP_AUTH",
  "session_id":       "string | null"
}
```

---

## Setup

```bash
# 1. Clone and enter the project
cd ai_banking_firewall

# 2. Create a virtual environment
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Mac/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
copy .env.example .env
# Edit .env and add your GEMINI_API_KEY
```

---

## Running the Test Suite

```bash
# Offline (no API key needed — mocked LLM, fully deterministic)
pytest tests/test_firewall.py -v

# Integration tests (requires GEMINI_API_KEY in .env)
pytest tests/test_firewall.py -v -m integration
```

### Test Matrix

| ID | Scenario | Expected Verdict | Category |
|---|---|---|---|
| TC-01 | Standard balance check | `APPROVED` | `NONE` |
| TC-02 | Standard P2P transfer | `APPROVED` | `NONE` |
| TC-03 | Prompt injection via memo | `BLOCKED` | `DIRECT_PROMPT_INJECTION` |
| TC-04 | Base64-obfuscated injection | `BLOCKED` | `TOKEN_OBFUSCATION` |
| TC-05 | ROT-13 obfuscated injection | `BLOCKED` | `TOKEN_OBFUSCATION` |
| TC-06 | Roleplay jailbreak | `BLOCKED` | `ROLEPLAY_JAILBREAK` |
| TC-07 | Delimiter leak tokens | `BLOCKED` | `DELIMITER_LEAK` |
| TC-08 | High-value transfer (high-risk account) | `CHALLENGE` | `NONE` |
| TC-09 | `strict_binary_mode` collapses CHALLENGE | `BLOCKED` | `NONE` |
| TC-10 | Fail-closed on LLM exception | `BLOCKED` | `NONE` |

---

## Key Design Decisions

| Decision | Rationale |
|---|---|
| **XML + JSON-escaped isolation** | `</untrusted_payload>` stripped by Layer 1; payload JSON-escaped in prompt — double protection against delimiter-breaking |
| **Heuristic fast-path before LLM** | Blocks obvious attacks with zero API cost; Layer 3 cannot be exploited for known patterns |
| **`strict_binary_mode`** | Collapses CHALLENGE → BLOCKED for automated judges enforcing binary output |
| **Fail-closed everywhere** | Parse errors, timeouts, missing fields all default to BLOCKED/CRITICAL |
| **Layer 4 as deterministic last word** | Financial rules cannot be overridden by any AI verdict or user input |
| **Mocked tests by default** | All 10 unit tests run offline instantly; `@pytest.mark.integration` opt-in for live API |

---

## Thresholds (configurable via `.env`)

| Variable | Default | Meaning |
|---|---|---|
| `HEURISTIC_BLOCK_THRESHOLD` | `0.75` | Layer 2 score at which LLM is skipped |
| `BLOCK_THRESHOLD` | `0.60` | Combined score that triggers BLOCKED |
| `CHALLENGE_THRESHOLD` | `0.40` | Combined score that triggers CHALLENGE |
| Transfer ceiling (standard) | `$10,000` | Hard cap in `policy_gate.py` |
| Step-up threshold (high-risk) | `$5,000` | Triggers CHALLENGE in `policy_gate.py` |

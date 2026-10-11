"""
Bankism — firewall.py
=====================
Main Orchestration Pipeline

Wires Layers 1–4 together in strict sequence and enforces:
  - FAIL-CLOSED on any unexpected exception at any layer
  - strict_binary_mode: CHALLENGE → BLOCKED coercion (Refinement #1)

Public API:
    evaluate(request: FirewallRequest) -> FirewallVerdict

Sequence:
    FirewallRequest
      │
      ├─ [Layer 1]  normalizer.normalize()        → NormalizerResult
      │
      ├─ [Layer 2]  evaluator.heuristic_check()   → HeuristicResult
      │               └─ hard_blocked? → skip Layer 3, apply policy gate
      │
      ├─ [Layer 3]  evaluator.llm_inspect()       → LLMResult
      │               └─ any error → _llm_fail_closed() → BLOCKED
      │
      ├─ [Layer 4]  policy_gate.apply()           → FirewallVerdict
      │               └─ deterministic business rules (cannot be AI-overridden)
      │
      └─ [Post]     strict_binary_mode coercion   → final FirewallVerdict
"""

from __future__ import annotations

import logging
from typing import Optional

from schemas import (
    ActionRequired,
    FirewallRequest,
    FirewallVerdict,
    HeuristicResult,
    LLMResult,
    RiskLevel,
    ThreatCategory,
    Verdict,
)
import normalizer
import evaluator
import policy_gate
import session_guard
import honey_shield

logger = logging.getLogger("bankism.firewall")


# ---------------------------------------------------------------------------
# Synthetic LLM result for Layer 2 hard-blocks
# ---------------------------------------------------------------------------

def _heuristic_llm_stub(heuristic: HeuristicResult) -> LLMResult:
    """
    When Layer 2 hard-blocks, we skip Layer 3.
    Create a synthetic LLMResult so Layer 4 receives consistent types.
    """
    return LLMResult(
        verdict=Verdict.BLOCKED,
        risk_level=RiskLevel.CRITICAL,
        threat_category=heuristic.threat_category,
        confidence_score=heuristic.score,
        rationale=(
            f"Blocked by heuristic fast-path (Layer 2). "
            f"Matched patterns: {', '.join(heuristic.matched_patterns[:3])}. "
            "Request did not proceed to LLM evaluation."
        ),
        detected_action="UNKNOWN",
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def evaluate(request: FirewallRequest) -> FirewallVerdict:
    """
    Run the full Bankism defense pipeline against a FirewallRequest.

    This function coordinates:
      - Layer 1: Deterministic Normalizer (homoglyphs, encodings, invisible text)
      - Feature 1: Multi-Turn Session Guard (context poisoning & salami slicing)
      - Feature 2: Canary Honeypot Token Generation & PII Output Shield
      - Layer 2: Heuristic Fast-Path (28+ regex patterns)
      - Layer 3: Isolated LLM Evaluator (Gemini with XML boundary defense)
      - Layer 4: Deterministic Financial Policy Gate (limits, accounts, recipients)
      - Fail-Closed Safety & strict_binary_mode coercion
    """
    try:
        verdict = _run_pipeline(request)
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("Unexpected error in firewall pipeline: %s", exc)
        verdict = FirewallVerdict.fail_closed(
            reason=f"Unhandled pipeline exception: {type(exc).__name__}.",
            session_id=request.session_id,
        )

    # ── Refinement #1: strict_binary_mode coercion ───────────────────────────
    if request.strict_binary_mode:
        verdict = verdict.apply_strict_binary_mode()

    return verdict


def _run_pipeline(request: FirewallRequest) -> FirewallVerdict:
    """
    Internal pipeline orchestrating all layers and advanced defense features.
    """

    # ── Feature 1: Multi-Turn Context Poisoning Check ───────────────────────
    is_poisoned, penalty_score, poison_rationale = session_guard.inspect_session(request.session_id)
    if is_poisoned:
        logger.warning("[SessionGuard] Blocked session=%s due to multi-turn poisoning", request.session_id)
        return FirewallVerdict(
            verdict=Verdict.BLOCKED,
            risk_level=RiskLevel.CRITICAL,
            threat_category=ThreatCategory.DIRECT_PROMPT_INJECTION,
            confidence_score=0.95,
            rationale=poison_rationale,
            sanitized_payload=None,
            action_required=ActionRequired.DROP_AND_LOG,
            session_id=request.session_id,
        )

    # ── Layer 1: Deterministic Normalizer ────────────────────────────────────
    logger.debug("[L1] Running normalizer on session=%s", request.session_id)
    norm_result = normalizer.normalize(
        text=request.user_input,
        memo=request.memo,
    )
    logger.debug("[L1] Transformations: %s", norm_result.transformations_applied)

    # ── Feature 2: Generate Canary Token for this Evaluation ────────────────
    canary_token = honey_shield.generate_canary(request.session_id)

    # ── Layer 2: Heuristic Fast-Path ─────────────────────────────────────────
    logger.debug("[L2] Running heuristic check")
    heuristic_result = evaluator.heuristic_check(norm_result)
    logger.debug(
        "[L2] Score=%.4f hard_blocked=%s patterns=%s",
        heuristic_result.score,
        heuristic_result.hard_blocked,
        heuristic_result.matched_patterns[:3],
    )

    if heuristic_result.hard_blocked:
        logger.info(
            "[L2] Hard block triggered (score=%.4f). Skipping LLM. session=%s",
            heuristic_result.score,
            request.session_id,
        )
        llm_result = _heuristic_llm_stub(heuristic_result)
        final_verdict = policy_gate.apply(request, heuristic_result, llm_result)
        session_guard.record_turn(
            request.session_id or "anon",
            request.user_input,
            final_verdict.confidence_score,
            final_verdict.threat_category,
        )
        return final_verdict

    # ── Layer 3: Isolated LLM Evaluator ──────────────────────────────────────
    logger.debug("[L3] Running LLM semantic evaluation with Canary Token")
    llm_result = evaluator.llm_inspect(
        norm=norm_result,
        heuristic=heuristic_result,
        amount=request.amount,
        recipient=request.recipient,
        session_id=request.session_id,
        canary_token=canary_token,
    )

    # ── Layer 4: Financial Policy Gate ───────────────────────────────────────
    logger.debug("[L4] Applying financial policy gate")
    verdict = policy_gate.apply(request, heuristic_result, llm_result)

    # ── Feature 2 Check: Output Exfiltration Shield on Sanitized Payload ────
    if verdict.sanitized_payload and "user_input" in verdict.sanitized_payload:
        masked_text, exfil_detected = honey_shield.mask_financial_exfiltration(
            verdict.sanitized_payload["user_input"]
        )
        if exfil_detected:
            verdict.sanitized_payload["user_input"] = masked_text
            verdict.sanitized_payload["exfiltration_warnings"] = exfil_detected

    # Record turn state for multi-turn defense
    session_guard.record_turn(
        request.session_id or "anon",
        request.user_input,
        verdict.confidence_score,
        verdict.threat_category,
        detected_action=llm_result.detected_action,
    )

    logger.info(
        "[VERDICT] session=%s verdict=%s risk=%s score=%.4f category=%s",
        request.session_id,
        verdict.verdict,
        verdict.risk_level,
        verdict.confidence_score,
        verdict.threat_category,
    )
    return verdict

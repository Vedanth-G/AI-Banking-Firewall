"""
AI Banking Firewall — policy_gate.py
========================
Layer 4: Financial Policy Gate

Pure, deterministic business-rule enforcement.
This layer runs AFTER the AI scoring layers and can never be overridden
by any LLM output, user input, or configuration flag.

Rules are evaluated in priority order:
  1. Transfer ceiling      — hard block above $10,000 for standard accounts
  2. Step-up auth trigger  — challenge above $5,000 for high-risk accounts
  3. Recipient validation  — transfers must have a non-empty recipient
  4. Score-based verdict   — combined score drives BLOCKED / CHALLENGE / APPROVED
"""

from __future__ import annotations

from schemas import (
    AccountTier,
    ActionRequired,
    FirewallRequest,
    FirewallVerdict,
    HeuristicResult,
    LLMResult,
    RiskLevel,
    ThreatCategory,
    Verdict,
)

# ---------------------------------------------------------------------------
# Policy constants
# ---------------------------------------------------------------------------

# Absolute per-transaction ceiling for standard accounts (USD)
STANDARD_TRANSFER_CEILING: float = 10_000.0

# Step-up auth threshold for high-risk accounts (USD)
HIGH_RISK_STEP_UP_THRESHOLD: float = 5_000.0

# Score thresholds for the combined layer score
BLOCK_THRESHOLD: float = 0.60      # combined score ≥ this → BLOCKED
CHALLENGE_THRESHOLD: float = 0.40  # combined score ≥ this → CHALLENGE

# Banking action strings that require a recipient
_TRANSFER_ACTIONS: frozenset[str] = frozenset({
    "TRANSFER", "PAYMENT",
})


# ---------------------------------------------------------------------------
# Risk level ordering
# ---------------------------------------------------------------------------

_RISK_ORDER: dict[RiskLevel, int] = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


def _max_risk(a: RiskLevel, b: RiskLevel) -> RiskLevel:
    return a if _RISK_ORDER[a] >= _RISK_ORDER[b] else b


def _score_to_risk(score: float) -> RiskLevel:
    if score < 0.40:
        return RiskLevel.LOW
    if score < 0.60:
        return RiskLevel.MEDIUM
    if score < 0.80:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


# ---------------------------------------------------------------------------
# Threat category merger
# ---------------------------------------------------------------------------

def _dominant_category(
    heuristic: HeuristicResult,
    llm: LLMResult,
) -> ThreatCategory:
    """Prefer the LLM's category unless it is NONE, then fall back to heuristic."""
    if llm.threat_category != ThreatCategory.NONE:
        return llm.threat_category
    return heuristic.threat_category


# ---------------------------------------------------------------------------
# Sanitized payload builder
# ---------------------------------------------------------------------------

def _build_sanitized_payload(request: FirewallRequest, llm: LLMResult) -> dict:
    """
    Construct the sanitized_payload dict for APPROVED verdicts.
    Only safe, validated fields are included.
    """
    payload: dict = {
        "user_input": request.user_input.strip(),
        "detected_action": llm.detected_action,
    }
    if request.recipient is not None:
        payload["recipient"] = request.recipient.strip()
    if request.amount is not None:
        payload["amount"] = request.amount
    if request.memo is not None:
        payload["memo"] = request.memo.strip()
    return payload


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def apply(
    request: FirewallRequest,
    heuristic: HeuristicResult,
    llm: LLMResult,
) -> FirewallVerdict:
    """
    Apply all financial policy rules and emit the final FirewallVerdict.

    Arguments:
        request   — original FirewallRequest (untouched, used for policy fields)
        heuristic — Layer 2 result (score, category)
        llm       — Layer 3 result (score, verdict, category, rationale)

    Returns:
        FirewallVerdict — fully populated, ready to return to the caller.
    """

    # ── Merge scores ─────────────────────────────────────────────────────────
    combined_score = max(heuristic.score, llm.confidence_score)
    combined_score = round(min(combined_score, 1.0), 4)

    # ── Determine dominant threat category ────────────────────────────────────
    category = _dominant_category(heuristic, llm)

    # ── Build base risk level from merged score ────────────────────────────────
    base_risk = _max_risk(llm.risk_level, _score_to_risk(combined_score))

    # ──────────────────────────────────────────────────────────────────────────
    # Rule 1: Absolute transfer ceiling (standard accounts)
    #   Amounts > $10,000 are ALWAYS blocked for standard-tier accounts.
    #   No AI verdict can override this rule.
    # ──────────────────────────────────────────────────────────────────────────
    if (
        request.amount is not None
        and request.amount > STANDARD_TRANSFER_CEILING
        and request.account_tier == AccountTier.STANDARD
    ):
        return _make_verdict(
            verdict=Verdict.BLOCKED,
            risk_level=RiskLevel.CRITICAL,
            category=category if category != ThreatCategory.NONE else ThreatCategory.NONE,
            score=combined_score,
            rationale=(
                f"Transaction amount ${request.amount:,.2f} exceeds the "
                f"${STANDARD_TRANSFER_CEILING:,.0f} per-transaction ceiling "
                f"for standard accounts. Request blocked by financial policy gate."
            ),
            sanitized_payload=None,
            action=ActionRequired.DROP_AND_LOG,
            session_id=request.session_id,
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Rule 2: Step-up authentication for high-risk accounts
    #   Amounts > $5,000 on high-risk accounts require step-up auth.
    # ──────────────────────────────────────────────────────────────────────────
    if (
        request.amount is not None
        and request.amount > HIGH_RISK_STEP_UP_THRESHOLD
        and request.account_tier == AccountTier.HIGH_RISK
    ):
        return _make_verdict(
            verdict=Verdict.CHALLENGE,
            risk_level=_max_risk(base_risk, RiskLevel.MEDIUM),
            category=category,
            score=combined_score,
            rationale=(
                f"Transaction amount ${request.amount:,.2f} exceeds the "
                f"${HIGH_RISK_STEP_UP_THRESHOLD:,.0f} step-up authentication "
                f"threshold for high-risk accounts. Multi-factor verification required."
            ),
            sanitized_payload=None,
            action=ActionRequired.TRIGGER_STEP_UP_AUTH,
            session_id=request.session_id,
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Rule 3: Recipient validation
    #   Transfer/Payment actions must have a non-empty recipient.
    # ──────────────────────────────────────────────────────────────────────────
    if llm.detected_action.upper() in _TRANSFER_ACTIONS:
        if not request.recipient or not request.recipient.strip():
            return _make_verdict(
                verdict=Verdict.BLOCKED,
                risk_level=RiskLevel.HIGH,
                category=category,
                score=max(combined_score, 0.70),
                rationale=(
                    "Transfer or payment action detected but recipient field "
                    "is empty or missing. A non-empty recipient is required "
                    "for all fund movement operations."
                ),
                sanitized_payload=None,
                action=ActionRequired.DROP_AND_LOG,
                session_id=request.session_id,
            )

    # ──────────────────────────────────────────────────────────────────────────
    # Rule 4: Score-based combined verdict
    # ──────────────────────────────────────────────────────────────────────────

    # If either layer's verdict is BLOCKED, or score is above block threshold
    if llm.verdict == Verdict.BLOCKED or combined_score >= BLOCK_THRESHOLD:
        return _make_verdict(
            verdict=Verdict.BLOCKED,
            risk_level=_max_risk(base_risk, RiskLevel.HIGH),
            category=category,
            score=combined_score,
            rationale=llm.rationale,
            sanitized_payload=None,
            action=ActionRequired.DROP_AND_LOG,
            session_id=request.session_id,
        )

    # Challenge band: moderate risk that passed AI but warrants caution
    if combined_score >= CHALLENGE_THRESHOLD:
        return _make_verdict(
            verdict=Verdict.CHALLENGE,
            risk_level=_max_risk(base_risk, RiskLevel.MEDIUM),
            category=category,
            score=combined_score,
            rationale=llm.rationale,
            sanitized_payload=None,
            action=ActionRequired.TRIGGER_STEP_UP_AUTH,
            session_id=request.session_id,
        )

    # ── APPROVED ──────────────────────────────────────────────────────────────
    return _make_verdict(
        verdict=Verdict.APPROVED,
        risk_level=base_risk,
        category=category,
        score=combined_score,
        rationale=llm.rationale,
        sanitized_payload=_build_sanitized_payload(request, llm),
        action=ActionRequired.PROCEED_TO_CORE_API,
        session_id=request.session_id,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _make_verdict(
    verdict: Verdict,
    risk_level: RiskLevel,
    category: ThreatCategory,
    score: float,
    rationale: str,
    sanitized_payload,
    action: ActionRequired,
    session_id,
) -> FirewallVerdict:
    return FirewallVerdict(
        verdict=verdict,
        risk_level=risk_level,
        threat_category=category,
        confidence_score=score,
        rationale=rationale,
        sanitized_payload=sanitized_payload,
        action_required=action,
        session_id=session_id,
    )

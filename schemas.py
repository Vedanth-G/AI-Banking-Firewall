"""
AI Banking Firewall — schemas.py
====================
Single source of truth for all data contracts.

All downstream modules import from here; nothing else defines types.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Verdict(str, Enum):
    """Terminal decision returned by the firewall pipeline."""

    APPROVED = "APPROVED"
    BLOCKED = "BLOCKED"
    CHALLENGE = "CHALLENGE"  # collapsed → BLOCKED when strict_binary_mode=True


class RiskLevel(str, Enum):
    """Severity tier of the identified risk."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatCategory(str, Enum):
    """
    Taxonomy of adversarial patterns targeted by AI Banking Firewall.
    NONE is reserved for clean, benign requests.
    """

    NONE = "NONE"
    DIRECT_PROMPT_INJECTION = "DIRECT_PROMPT_INJECTION"
    DELIMITER_LEAK = "DELIMITER_LEAK"
    ROLEPLAY_JAILBREAK = "ROLEPLAY_JAILBREAK"
    TOKEN_OBFUSCATION = "TOKEN_OBFUSCATION"


class ActionRequired(str, Enum):
    """Instruction to the downstream caller on how to proceed."""

    PROCEED_TO_CORE_API = "PROCEED_TO_CORE_API"
    DROP_AND_LOG = "DROP_AND_LOG"
    TRIGGER_STEP_UP_AUTH = "TRIGGER_STEP_UP_AUTH"


class AccountTier(str, Enum):
    """
    Risk classification of the authenticated user's account.
    Drives Layer 4 step-up auth thresholds.
    """

    STANDARD = "standard"
    HIGH_RISK = "high_risk"


# ---------------------------------------------------------------------------
# Request model
# ---------------------------------------------------------------------------


class FirewallRequest(BaseModel):
    """
    Payload submitted to the AI Banking Firewall firewall.
    All text fields are treated as UNTRUSTED until normalised and evaluated.
    """

    user_input: str = Field(
        ...,
        min_length=1,
        max_length=2000,
        description="Raw user-facing text sent to the banking LLM agent.",
        examples=["Send $200 to Alice"],
    )
    memo: Optional[str] = Field(
        default=None,
        max_length=500,
        description=(
            "Payment memo / reference note. "
            "Inspected independently — a common attack surface."
        ),
    )
    amount: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Transaction amount in USD.",
    )
    recipient: Optional[str] = Field(
        default=None,
        max_length=200,
        description="Payee identifier (username, account number, email, etc.).",
    )
    account_tier: AccountTier = Field(
        default=AccountTier.STANDARD,
        description="Risk tier of the requesting account; drives Layer 4 thresholds.",
    )
    session_id: Optional[str] = Field(
        default=None,
        description="Opaque session identifier echoed in the verdict for audit trails.",
    )

    # ── Strict binary mode toggle (Refinement #1) ──────────────────────────
    strict_binary_mode: bool = Field(
        default=False,
        description=(
            "When True, any CHALLENGE verdict is collapsed to BLOCKED with a "
            "fixed rationale. Ensures 100% binary output for automated judges."
        ),
    )

    @field_validator("user_input", "memo", "recipient", mode="before")
    @classmethod
    def _strip(cls, v: Any) -> Any:
        return v.strip() if isinstance(v, str) else v

    @field_validator("amount", mode="before")
    @classmethod
    def _coerce_amount(cls, v: Any) -> Any:
        if v is None:
            return v
        try:
            val = float(v)
        except (TypeError, ValueError) as exc:
            raise ValueError("amount must be a non-negative number") from exc
        if val < 0:
            raise ValueError("amount must be ≥ 0")
        return val


# ---------------------------------------------------------------------------
# Intermediate pipeline artefacts (internal, not exposed to callers)
# ---------------------------------------------------------------------------


class NormalizerResult(BaseModel):
    """Output of Layer 1 — carries cleaned text alongside a transformation log."""

    normalized_input: str
    normalized_memo: Optional[str] = None
    transformations_applied: list[str] = Field(default_factory=list)


class HeuristicResult(BaseModel):
    """Output of the Layer 2 keyword / regex fast-path."""

    score: float = Field(ge=0.0, le=1.0)
    matched_patterns: list[str] = Field(default_factory=list)
    hard_blocked: bool = False          # True when score ≥ HEURISTIC_BLOCK_THRESHOLD
    threat_category: ThreatCategory = ThreatCategory.NONE


class LLMResult(BaseModel):
    """Parsed output of the Layer 3 Gemini evaluator."""

    verdict: Verdict
    risk_level: RiskLevel
    threat_category: ThreatCategory
    confidence_score: float = Field(ge=0.0, le=1.0)
    rationale: str
    detected_action: str = "UNKNOWN"


# ---------------------------------------------------------------------------
# Verdict model (public, machine-readable output)
# ---------------------------------------------------------------------------


class FirewallVerdict(BaseModel):
    """
    Machine-readable firewall decision.

    Strict JSON contract — every field is always present.
    Downstream services MUST honour BLOCKED and CHALLENGE verdicts
    and never proceed to core API execution without APPROVED.
    """

    verdict: Verdict
    risk_level: RiskLevel
    threat_category: ThreatCategory
    confidence_score: float = Field(ge=0.0, le=1.0)
    rationale: str
    sanitized_payload: Optional[dict[str, Any]] = Field(
        default=None,
        description="Cleaned request fields — populated ONLY for APPROVED verdicts.",
    )
    action_required: ActionRequired
    session_id: Optional[str] = None

    model_config = {"use_enum_values": True}

    # ── Fail-closed factory ─────────────────────────────────────────────────

    @classmethod
    def fail_closed(cls, reason: str, session_id: Optional[str] = None) -> "FirewallVerdict":
        """
        Return a BLOCKED/CRITICAL verdict when any layer fails unexpectedly.
        Ambiguity NEVER becomes approval.
        """
        return cls(
            verdict=Verdict.BLOCKED,
            risk_level=RiskLevel.CRITICAL,
            threat_category=ThreatCategory.NONE,
            confidence_score=1.0,
            rationale=f"[FAIL-CLOSED] {reason} All ambiguous inputs default to BLOCKED.",
            sanitized_payload=None,
            action_required=ActionRequired.DROP_AND_LOG,
            session_id=session_id,
        )

    # ── Strict binary mode coercion (Refinement #1) ────────────────────────

    def apply_strict_binary_mode(self) -> "FirewallVerdict":
        """
        If strict_binary_mode is active, collapse CHALLENGE → BLOCKED.
        Called by firewall.py after the verdict is built.
        Returns a new instance (verdicts are immutable once built).
        """
        if self.verdict != Verdict.CHALLENGE:
            return self
        return self.model_copy(update={
            "verdict": Verdict.BLOCKED,
            "action_required": ActionRequired.DROP_AND_LOG,
            "rationale": (
                "Step-up authentication required (transfer limit exceeded). "
                "[strict_binary_mode] CHALLENGE collapsed to BLOCKED."
            ),
        })

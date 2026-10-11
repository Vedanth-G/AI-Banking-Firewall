"""
Bankism — consensus_engine.py
=============================
Feature 3: Dual-Perspective Adversarial Consensus Engine.

Uses a split-role evaluator model architecture:
  1. Red-Team Exploitation Auditor: Specifically tasked with unmasking covert
     directives, cognitive exploits, indirect instructions, or policy subversions.
  2. Blue-Team Compliance Auditor: Validates that the request maps cleanly to a
     recognized, benign banking operation within normal parameters.

The Consensus Arbiter fuses both evaluations:
  - If Red-Team finds a HIGH/CRITICAL exploit -> FAIL-CLOSED (verdict = BLOCKED)
  - If both agree it's safe -> APPROVED
  - If there is divergence or ambiguity -> CHALLENGE or BLOCKED based on risk margin
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Optional

from schemas import LLMResult, RiskLevel, ThreatCategory, Verdict

logger = logging.getLogger("bankism.consensus")


@dataclass
class PerspectiveResult:
    perspective: str  # "RED_TEAM" or "BLUE_TEAM"
    risk_score: float
    threat_category: ThreatCategory
    rationale: str


def arbitrate_consensus(
    blue_result: LLMResult,
    red_perspective: Optional[PerspectiveResult] = None,
) -> LLMResult:
    """
    Synthesize evaluations from dual perspectives.
    Fails closed if the red-team perspective flags a covert attack.
    """
    if not red_perspective:
        return blue_result

    logger.debug(
        "[Consensus] Blue risk=%.2f (%s) | Red risk=%.2f (%s)",
        blue_result.confidence_score,
        blue_result.threat_category,
        red_perspective.risk_score,
        red_perspective.threat_category,
    )

    # If Red-Team identifies high-confidence exploit missed by standard evaluator:
    if red_perspective.risk_score >= 0.70 and red_perspective.threat_category != ThreatCategory.NONE:
        return LLMResult(
            verdict=Verdict.BLOCKED,
            risk_level=RiskLevel.HIGH if red_perspective.risk_score < 0.85 else RiskLevel.CRITICAL,
            threat_category=red_perspective.threat_category,
            confidence_score=red_perspective.risk_score,
            rationale=(
                f"[Dual-Perspective Consensus] Adversarial Red-Team audit uncovered covert exploit: "
                f"{red_perspective.rationale}"
            ),
            detected_action=blue_result.detected_action,
        )

    # If both perspectives agree on low risk:
    if blue_result.confidence_score < 0.40 and red_perspective.risk_score < 0.40:
        return blue_result

    # If divergent/ambiguous: take the more conservative (higher) risk score
    merged_score = max(blue_result.confidence_score, red_perspective.risk_score)
    merged_cat = (
        red_perspective.threat_category
        if red_perspective.threat_category != ThreatCategory.NONE
        else blue_result.threat_category
    )

    return LLMResult(
        verdict=Verdict.BLOCKED if merged_score >= 0.60 else Verdict.CHALLENGE,
        risk_level=RiskLevel.HIGH if merged_score >= 0.60 else RiskLevel.MEDIUM,
        threat_category=merged_cat,
        confidence_score=merged_score,
        rationale=f"[Consensus Arbiter] Elevated risk due to perspective divergence. {blue_result.rationale}",
        detected_action=blue_result.detected_action,
    )

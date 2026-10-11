"""
AI Banking Firewall — honey_shield.py
=========================
Feature 2: Financial Honeypot Canary Tokens & Output Exfiltration Shield.

1. Canary Token System:
   Generates a cryptographically randomized, high-entropy canary token per evaluation.
   If untrusted text or downstream prompt responses leak or mention the canary token,
   an immediate tripwire alert is fired (direct system-prompt leakage proof).

2. PII & Financial Exfiltration Masking:
   Detects and neutralizes attempts to extract:
   - Primary Account Numbers (PAN / Credit Cards) via Luhn algorithm
   - International Bank Account Numbers (IBAN)
   - US Bank Routing Transit Numbers (ABA Routing)
   - Social Security Numbers (SSN)
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from typing import Optional

_SECRET_SALT = os.getenv("CANARY_SALT", secrets.token_hex(16))

# Financial Data Exfiltration regexes
_CC_REGEX = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_IBAN_REGEX = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b")
_ROUTING_REGEX = re.compile(r"\b(?:0[1-9]|[1-2][0-9]|3[0-2]|6[1-9]|7[0-2]|80)\d{7}\b")
_SSN_REGEX = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def generate_canary(session_id: Optional[str] = None) -> str:
    """Generate a high-entropy, session-bound canary token for prompt boundary protection."""
    seed = f"{session_id or 'anon'}-{time_epoch_bucket()}"
    token_hash = hmac.new(_SECRET_SALT.encode(), seed.encode(), hashlib.sha256).hexdigest()[:16]
    return f"CANARY_TXN_{token_hash.upper()}"


def time_epoch_bucket() -> int:
    """Bucket time to allow validation within reasonable windows."""
    import time
    return int(time.time() // 300)  # 5-minute bucket


def detect_canary_leak(text: str, session_id: Optional[str] = None) -> tuple[bool, str]:
    """Check if any canary token or system instructions appear in the text."""
    canary = generate_canary(session_id)
    if canary in text:
        return True, f"Canary token tripwire triggered! Secret canary '{canary}' was echoed/leaked in output."
    
    # Generic canary pattern search
    if "CANARY_TXN_" in text:
        return True, "Canary token leak pattern detected in text stream."

    return False, ""


def mask_financial_exfiltration(text: str) -> tuple[str, list[str]]:
    """
    Sanitize text to block data exfiltration of card numbers, routing numbers, and PII.
    Returns: (masked_text, list_of_detected_leak_types)
    """
    detected = []
    sanitized = text

    # SSN Masking
    if _SSN_REGEX.search(sanitized):
        sanitized = _SSN_REGEX.sub("[REDACTED_SSN]", sanitized)
        detected.append("SOCIAL_SECURITY_NUMBER")

    # Credit Card (Luhn checked)
    def _mask_cc(match: re.Match) -> str:
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19 and _luhn_checksum(digits):
            detected.append("PAYMENT_CARD_PAN")
            return f"[REDACTED_CARD_ENDING_{digits[-4:]}]"
        return match.group(0)

    sanitized = _CC_REGEX.sub(_mask_cc, sanitized)

    # IBAN Masking
    if _IBAN_REGEX.search(sanitized):
        sanitized = _IBAN_REGEX.sub("[REDACTED_IBAN]", sanitized)
        detected.append("INTERNATIONAL_BANK_ACCOUNT")

    # Routing Transit Number
    if _ROUTING_REGEX.search(sanitized):
        sanitized = _ROUTING_REGEX.sub("[REDACTED_ROUTING_NUMBER]", sanitized)
        detected.append("BANK_ROUTING_NUMBER")

    return sanitized, list(set(detected))


def _luhn_checksum(card_number: str) -> bool:
    """Validate credit card using Luhn formula."""
    try:
        digits = [int(d) for d in card_number]
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        checksum = sum(odd_digits)
        for d in even_digits:
            doubled = d * 2
            checksum += doubled if doubled < 10 else doubled - 9
        return checksum % 10 == 0
    except Exception:
        return False

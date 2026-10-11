"""
AI Banking Firewall — normalizer.py
=======================
Layer 1: Deterministic Normalizer

Produces a canonical, attack-free representation of untrusted input
BEFORE any scoring or LLM inspection occurs. All operations are:
  • Pure functions — no side effects, no I/O
  • Deterministic — same input always yields the same output
  • Cheap — runs in microseconds with no external dependencies

Pipeline (applied in order):
  1. Invisible / zero-width character removal
  2. Unicode homoglyph normalisation (NFKD + Cyrillic→Latin map)
  3. Base64 payload detection and decode
  4. Hex-encoded string detection and decode
  5. ROT-13 detection and decode
  6. L33tspeak → plaintext substitution
  7. Spaced-character collapse  (e.g., "t r a n s f e r" → "transfer")
  8. XML delimiter sanitisation — strips/escapes </untrusted_payload>
     to prevent delimiter-breaking attacks (Refinement #2)
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Zero-width / invisible Unicode code points
# ---------------------------------------------------------------------------

_INVISIBLE_CODEPOINTS: frozenset[str] = frozenset({
    "\u200b",  # Zero Width Space
    "\u200c",  # Zero Width Non-Joiner
    "\u200d",  # Zero Width Joiner
    "\u200e",  # Left-to-Right Mark
    "\u200f",  # Right-to-Left Mark
    "\u202a",  # Left-to-Right Embedding
    "\u202b",  # Right-to-Left Embedding
    "\u202c",  # Pop Directional Formatting
    "\u202d",  # Left-to-Right Override
    "\u202e",  # Right-to-Left Override
    "\ufeff",  # Zero Width No-Break Space (BOM)
    "\u2060",  # Word Joiner
    "\u2061",  # Function Application
    "\u2062",  # Invisible Times
    "\u2063",  # Invisible Separator
    "\u2064",  # Invisible Plus
    "\u00ad",  # Soft Hyphen
})

# ---------------------------------------------------------------------------
# Cyrillic / Greek → Latin homoglyph map (most common substitutions)
# ---------------------------------------------------------------------------

_HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ё": "e", "ю": "io",
    # Greek
    "α": "a", "β": "b", "γ": "y", "δ": "d", "ε": "e",
    "ζ": "z", "η": "n", "θ": "0", "ι": "i", "κ": "k",
    "λ": "l", "μ": "m", "ν": "v", "ο": "o", "π": "p",
    "ρ": "r", "σ": "s", "τ": "t", "υ": "u", "φ": "f",
    "χ": "x", "ψ": "ps", "ω": "w",
}

_HOMOGLYPH_TABLE = str.maketrans(_HOMOGLYPH_MAP)

# ---------------------------------------------------------------------------
# L33tspeak substitution table
# ---------------------------------------------------------------------------

# Common leetspeak substitutions (excluding '$' and '|' to preserve delimiters and currency)
_LEET_MAP: dict[str, str] = {
    "@": "a", "!": "i", "+": "t", "(": "c",
}

_LEET_TABLE = str.maketrans(_LEET_MAP)

# ---------------------------------------------------------------------------
# Base64 detection — long runs (≥ 20 chars) with optional padding
# ---------------------------------------------------------------------------

_BASE64_RE = re.compile(r"(?<!\w)([A-Za-z0-9+/]{20,}={0,2})(?!\w)")

# ---------------------------------------------------------------------------
# Hex detection — 0x-prefixed or raw even-length hex strings (≥ 16 hex chars)
# ---------------------------------------------------------------------------

_HEX_RE = re.compile(
    r"(?:0x[0-9a-fA-F]{8,}|(?<!\w)(?:[0-9a-fA-F]{2}){8,}(?!\w))"
)

# ---------------------------------------------------------------------------
# Spaced-character collapse — e.g., "t r a n s f e r" → "transfer"
#   matches: at least 4 single-char + space groups ending with a single char
# ---------------------------------------------------------------------------

_SPACED_RE = re.compile(r"\b(?:[a-zA-Z]\s){3,}[a-zA-Z]\b")

# ---------------------------------------------------------------------------
# XML delimiter sanitisation (Refinement #2)
#   Strip or escape any closing </untrusted_payload> tags to prevent the
#   attacker from breaking out of the XML isolation wrapper.
# ---------------------------------------------------------------------------

_XML_CLOSING_TAG_RE = re.compile(
    r"<\s*/\s*untrusted_payload\s*>",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# ROT-13 detection heuristic
#   If the decoded ROT-13 of the string contains a high density of known
#   English attack keywords, treat the original as a ROT-13 payload.
# ---------------------------------------------------------------------------

_ROT13_TRIGGER_WORDS = {
    "ignore", "instructions", "bypass", "override", "transfer",
    "system", "admin", "jailbreak", "pretend", "roleplay",
    "disregard", "forget", "wire", "funds", "inject",
}


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class NormalizerResult:
    """
    Carries the cleaned text alongside an audit log of every
    transformation applied. Passed to Layer 2 and Layer 3.
    """

    normalized_input: str
    normalized_memo: str | None = None
    transformations_applied: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Individual normalisation steps (pure functions)
# ---------------------------------------------------------------------------


def _strip_invisible(text: str, log: list[str]) -> str:
    cleaned = "".join(ch for ch in text if ch not in _INVISIBLE_CODEPOINTS)
    if cleaned != text:
        log.append("invisible_chars_stripped")
    return cleaned


def _normalise_homoglyphs(text: str, log: list[str]) -> str:
    # Step 1: NFKD decomposition collapses many lookalikes
    nfkd = unicodedata.normalize("NFKD", text)
    # Step 2: Manual map for characters that NFKD doesn't handle
    mapped = nfkd.translate(_HOMOGLYPH_TABLE)
    if mapped != text:
        log.append("unicode_homoglyphs_normalised")
    return mapped


def _decode_base64_spans(text: str, log: list[str]) -> str:
    """
    Replace each base64 span with its decoded plaintext (if valid UTF-8).
    Malformed spans are left as-is to avoid masking other patterns.
    """
    found: list[str] = []

    def _replace(m: re.Match) -> str:  # type: ignore[type-arg]
        candidate = m.group(1)
        try:
            decoded = base64.b64decode(candidate + "==").decode("utf-8", errors="strict")
            # Only substitute if the decoded text is printable ASCII/UTF-8
            if decoded.isprintable():
                found.append(candidate[:12] + "…")
                return f"[BASE64_DECODED: {decoded}]"
        except Exception:
            pass
        return m.group(0)

    result = _BASE64_RE.sub(_replace, text)
    if found:
        log.append(f"base64_decoded({', '.join(found)})")
    return result


def _decode_hex_spans(text: str, log: list[str]) -> str:
    """Replace hex-encoded spans with decoded plaintext."""
    found: list[str] = []

    def _replace(m: re.Match) -> str:  # type: ignore[type-arg]
        raw = m.group(0).replace("0x", "").replace(" ", "")
        try:
            decoded = binascii.unhexlify(raw).decode("utf-8", errors="strict")
            if decoded.isprintable():
                found.append(raw[:12] + "…")
                return f"[HEX_DECODED: {decoded}]"
        except Exception:
            pass
        return m.group(0)

    result = _HEX_RE.sub(_replace, text)
    if found:
        log.append(f"hex_decoded({', '.join(found)})")
    return result


def _decode_rot13(text: str, log: list[str]) -> str:
    """
    Attempt ROT-13 decoding. Only substitute if the decoded version
    contains a meaningful density of English attack keywords —
    avoiding false positives on random-looking strings.
    """
    decoded = codecs.decode(text, "rot_13")
    words = set(re.findall(r"[a-z]{4,}", decoded.lower()))
    hits = words & _ROT13_TRIGGER_WORDS
    if len(hits) >= 2:  # at least 2 trigger words must match
        log.append(f"rot13_decoded(triggers={sorted(hits)})")
        return f"[ROT13_DECODED: {decoded}]"
    return text


def _normalise_leet(text: str, log: list[str]) -> str:
    translated = text.translate(_LEET_TABLE)
    if translated != text:
        log.append("leet_normalised")
    return translated


def _collapse_spaced_chars(text: str, log: list[str]) -> str:
    found: list[str] = []

    def _replace(m: re.Match) -> str:  # type: ignore[type-arg]
        collapsed = m.group(0).replace(" ", "")
        found.append(collapsed)
        return collapsed

    result = _SPACED_RE.sub(_replace, text)
    if found:
        log.append(f"spaced_chars_collapsed({found})")
    return result


def _sanitise_xml_delimiters(text: str, log: list[str]) -> str:
    """
    Strip any </untrusted_payload> closing tags from user input.
    This prevents delimiter-breaking attacks that would escape the
    XML isolation wrapper used in Layer 3.

    The tag is replaced with the benign literal string
    '[SANITIZED_DELIMITER]' so the change is visible in logs.
    """
    sanitised, count = _XML_CLOSING_TAG_RE.subn("[SANITIZED_DELIMITER]", text)
    if count:
        log.append(f"xml_delimiter_sanitised(count={count})")
    return sanitised


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def normalize(text: str, memo: str | None = None) -> NormalizerResult:
    """
    Apply the full Layer 1 normalisation pipeline to `text` and `memo`.

    Returns a NormalizerResult containing:
      - normalized_input   : cleaned user input text
      - normalized_memo    : cleaned memo (if provided)
      - transformations_applied : audit log of every step that changed the text
    """
    log: list[str] = []

    def _pipeline(raw: str) -> str:
        t = _strip_invisible(raw, log)
        t = _normalise_homoglyphs(t, log)
        t = _decode_base64_spans(t, log)
        t = _decode_hex_spans(t, log)
        t = _decode_rot13(t, log)
        t = _normalise_leet(t, log)
        t = _collapse_spaced_chars(t, log)
        t = _sanitise_xml_delimiters(t, log)
        return t

    norm_input = _pipeline(text)
    norm_memo: str | None = None
    if memo:
        norm_memo = _pipeline(memo)

    return NormalizerResult(
        normalized_input=norm_input,
        normalized_memo=norm_memo,
        transformations_applied=log,
    )

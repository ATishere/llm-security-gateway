"""Heuristic prompt-injection detection; not a substitute for a classifier."""

import logging
import re
import unicodedata

logger = logging.getLogger(__name__)

_ZERO_WIDTH = str.maketrans("", "", "\u200b\u200c\u200d\ufeff")
_PATTERNS = (
    re.compile(
        r"\b(?:ignore|disregard)\s+(?:all\s+)?(?:previous|above|prior)\s+"
        r"(?:instructions?|rules?|prompts?)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\brepeat\s+(?:the\s+)?(?:text|words|prompt)\s+(?:above|before)\b", re.I),
    re.compile(r"\b(?:reveal|show|print|repeat)\b.{0,100}\b(?:system|hidden)\s+prompt\b", re.I),
    re.compile(r"\b(?:system|developer)\s+prompt\b", re.IGNORECASE),
    re.compile(r"<\|[^|]{1,40}\|>|\[/?INST\]|<<\s*/?\s*SYS\s*>>", re.IGNORECASE),
    re.compile(r"\b(?:do\s+anything\s+now|jailbreak)\b", re.IGNORECASE),
)


class InjectionDetector:
    def detect(self, text: str) -> tuple[bool, str | None]:
        normalized = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)
        for pattern in _PATTERNS:
            if pattern.search(normalized):
                return True, pattern.pattern
        return False, None

    def inspect(self, text: str) -> list[str]:
        detected, matched_pattern = self.detect(text)
        if not detected:
            return []
        logger.warning(
            "Prompt injection signal detected",
            extra={"matched_pattern": matched_pattern, "prompt_len": len(text)},
        )
        return ["prompt_injection_signal"]


def inspect_prompt(prompt: str) -> list[str]:
    return InjectionDetector().inspect(prompt)

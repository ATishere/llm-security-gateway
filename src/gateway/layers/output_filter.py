import re

from gateway.layers.pii import PiiHandler, detect_pii

CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_output(text: str) -> str:
    """Remove non-printing control characters while preserving normal text."""
    return CONTROL_CHARACTERS.sub("", text)


def inspect_output(text: str) -> tuple[str, list[str]]:
    return sanitize_output(text), [f"output_{finding}" for finding in detect_pii(text)]


def inspect_output_with_handler(
    text: str, pii_handler: PiiHandler
) -> tuple[str, list[str]]:
    sanitized = sanitize_output(text)
    _, findings = pii_handler.mask(sanitized)
    return sanitized, [f"output_{finding}" for finding in findings]

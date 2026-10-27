from dataclasses import dataclass
from enum import StrEnum


class GatewayMode(StrEnum):
    SHADOW = "shadow"
    ENFORCE = "enforce"


@dataclass(frozen=True)
class Decision:
    blocked: bool
    would_block: bool


def decide(mode: GatewayMode, findings: list[str]) -> Decision:
    would_block = any(
        finding in {"prompt_injection_signal", "rate_limit_exceeded"}
        or finding.startswith("output_")
        for finding in findings
    )
    return Decision(
        blocked=mode is GatewayMode.ENFORCE and would_block,
        would_block=would_block,
    )

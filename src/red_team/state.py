"""State schema for the bounded local red-team workflow."""

from operator import add
from typing import Annotated, TypedDict


class AgentState(TypedDict, total=False):
    target_url: str
    authorization_reference: str
    probes_to_run: list[str]
    probes_run: Annotated[list[str], add]
    vulnerabilities: Annotated[list[dict[str, str | float]], add]
    errors: Annotated[list[str], add]
    report: dict[str, object]

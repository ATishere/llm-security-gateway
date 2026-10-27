from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Finding:
    title: str
    description: str
    severity: str
    evidence_reference: str


def report(findings: list[Finding]) -> list[dict[str, str]]:
    """Return structured findings without inferring CVSS scores."""
    return [asdict(finding) for finding in findings]

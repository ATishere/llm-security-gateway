import re
from typing import Protocol

EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE_PATTERN = re.compile(r"(?<!\w)(?:\+?\d[\d ()-]{7,}\d)(?!\w)")


class PiiHandler(Protocol):
    def mask(self, text: str) -> tuple[str, list[str]]:
        ...


class RegexPiiHandler:
    """Small development baseline; use Presidio for broader entity coverage."""

    def mask(self, text: str) -> tuple[str, list[str]]:
        return redact_pii(text)


class PIIHandler:
    """Microsoft Presidio-backed PII analysis and typed-entity masking."""

    DEFAULT_ENTITIES = (
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "CREDIT_CARD",
        "IBAN_CODE",
        "US_SSN",
        "IP_ADDRESS",
        "PERSON",
        "LOCATION",
    )

    def __init__(
        self,
        entities: tuple[str, ...] | None = None,
        score_threshold: float = 0.5,
    ) -> None:
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_anonymizer import AnonymizerEngine
            from presidio_anonymizer.entities import OperatorConfig
        except ImportError as exc:
            raise RuntimeError(
                "Presidio is selected but not installed; install the 'pii' extra"
            ) from exc

        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        self.entities = entities or self.DEFAULT_ENTITIES
        self.score_threshold = score_threshold
        self.operators = {
            entity: OperatorConfig("replace", {"new_value": f"<{entity}>"})
            for entity in self.entities
        }

    def mask(self, text: str) -> tuple[str, list[str]]:
        if not text:
            return text, []
        results = self.analyzer.analyze(
            text=text,
            entities=list(self.entities),
            language="en",
            score_threshold=self.score_threshold,
        )
        findings = sorted({f"pii_{result.entity_type.lower()}" for result in results})
        if not results:
            return text, findings
        anonymized = self.anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators=self.operators,
        )
        return anonymized.text, findings


def detect_pii(text: str) -> list[str]:
    findings = []
    if EMAIL_PATTERN.search(text):
        findings.append("email_detected")
    if PHONE_PATTERN.search(text):
        findings.append("phone_detected")
    return findings


def redact_pii(text: str) -> tuple[str, list[str]]:
    findings = detect_pii(text)
    redacted = EMAIL_PATTERN.sub("[REDACTED_EMAIL]", text)
    redacted = PHONE_PATTERN.sub("[REDACTED_PHONE]", redacted)
    return redacted, findings

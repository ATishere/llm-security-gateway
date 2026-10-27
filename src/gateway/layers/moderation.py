from typing import Protocol


class ModerationProvider(Protocol):
    async def classify(self, text: str) -> list[str]:
        """Return provider-defined moderation labels for the supplied text."""
        ...


class ModerationNotConfigured(RuntimeError):
    """Raised when moderation is required but no provider has been configured."""

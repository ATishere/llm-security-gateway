"""Environment-backed gateway configuration."""

from functools import lru_cache
from typing import Literal
from urllib.parse import urlparse

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GATEWAY_",
        env_file=".env",
        extra="ignore",
    )

    mode: Literal["shadow", "enforce"] = "shadow"
    llm_base_url: str = "https://api.anthropic.com/v1/messages"
    llm_api_key: SecretStr = SecretStr("")
    llm_model: str = "claude-3-5-sonnet-20241022"
    llm_timeout_seconds: float = Field(default=60.0, gt=0, le=300)
    max_prompt_chars: int = Field(default=32_000, ge=1, le=1_000_000)
    enable_pii: bool = True
    pii_backend: Literal["regex", "presidio"] = "regex"
    pii_score_threshold: float = Field(default=0.5, ge=0, le=1)
    rate_limit_requests: int = Field(default=60, ge=1)
    rate_limit_window_seconds: int = Field(default=60, ge=1)
    log_level: str = "INFO"

    @field_validator("llm_base_url")
    @classmethod
    def validate_llm_base_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            raise ValueError("llm_base_url must be an absolute HTTP(S) URL")
        if parsed.scheme == "http" and parsed.hostname not in {
            "localhost",
            "127.0.0.1",
            "::1",
        }:
            raise ValueError("llm_base_url must use HTTPS except for loopback development")
        if parsed.username or parsed.password:
            raise ValueError("llm_base_url must not include credentials")
        return value


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()

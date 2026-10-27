"""LLM Security Gateway — FastAPI entrypoint."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from gateway.config import Settings, get_settings
from gateway.layers.injection import InjectionDetector
from gateway.layers.output_filter import inspect_output_with_handler
from gateway.layers.pii import PIIHandler, PiiHandler, RegexPiiHandler
from gateway.layers.rate_limit import InMemoryRateLimiter
from gateway.shadow_mode import GatewayMode, decide

logger = logging.getLogger("gateway")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    logging.basicConfig(level=settings.log_level.upper())
    if settings.enable_pii:
        pii_handler: PiiHandler
        if settings.pii_backend == "presidio":
            pii_handler = PIIHandler(score_threshold=settings.pii_score_threshold)
        else:
            pii_handler = RegexPiiHandler()
    else:
        pii_handler = RegexPiiHandler()

    app.state.settings = settings
    app.state.injection_detector = InjectionDetector()
    app.state.pii_handler = pii_handler
    app.state.rate_limiter = InMemoryRateLimiter(
        limit=settings.rate_limit_requests,
        window_seconds=settings.rate_limit_window_seconds,
    )
    app.state.http_client = httpx.AsyncClient(timeout=settings.llm_timeout_seconds)
    logger.info("Gateway started", extra={"mode": settings.mode})
    try:
        yield
    finally:
        await app.state.http_client.aclose()
        logger.info("Gateway shutdown")


app = FastAPI(title="LLM Security Gateway", version="0.2.0", lifespan=lifespan)


class InspectRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=1_000_000)


class ChatRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=1_000_000)
    model: str | None = Field(default=None, min_length=1, max_length=128)
    temperature: float = Field(default=0.7, ge=0, le=1)


class InspectResponse(BaseModel):
    mode: GatewayMode
    blocked: bool
    would_block: bool
    sanitized_prompt: str
    findings: list[str]


class ChatResponse(BaseModel):
    status: str
    safe_prompt: str
    response: str
    blocked: bool
    would_block: bool
    findings: list[str]
    mode: GatewayMode


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _inspect_input(
    prompt: str,
    request: Request,
) -> tuple[str, list[str], bool]:
    settings: Settings = request.app.state.settings
    rate_allowed = request.app.state.rate_limiter.allow(_client_key(request))
    if not rate_allowed and settings.mode == GatewayMode.ENFORCE.value:
        return prompt, ["rate_limit_exceeded"], True

    findings = request.app.state.injection_detector.inspect(prompt)
    pii_handler: PiiHandler = request.app.state.pii_handler
    if settings.enable_pii:
        safe_prompt, pii_findings = pii_handler.mask(prompt)
    else:
        safe_prompt, pii_findings = prompt, []
    findings.extend(pii_findings)

    if not rate_allowed:
        findings.append("rate_limit_exceeded")
    decision = decide(GatewayMode(settings.mode), findings)
    return safe_prompt, findings, decision.blocked


def _raise_if_blocked(findings: list[str], blocked: bool) -> None:
    if not blocked:
        return
    is_rate_limited = "rate_limit_exceeded" in findings
    raise HTTPException(
        status_code=429 if is_rate_limited else 400,
        detail={
            "blocked": True,
            "would_block": True,
            "findings": findings,
        },
    )


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/inspect", response_model=InspectResponse)
async def inspect(body: InspectRequest, request: Request) -> InspectResponse:
    settings: Settings = request.app.state.settings
    safe_prompt, findings, blocked = _inspect_input(body.prompt, request)
    _raise_if_blocked(findings, blocked)
    decision = decide(GatewayMode(settings.mode), findings)
    return InspectResponse(
        mode=GatewayMode(settings.mode),
        blocked=False,
        would_block=decision.would_block,
        sanitized_prompt=safe_prompt,
        findings=findings,
    )


@app.post("/v1/chat/completions", response_model=ChatResponse)
async def proxy_chat(body: ChatRequest, request: Request) -> ChatResponse:
    settings: Settings = request.app.state.settings
    if len(body.prompt) > settings.max_prompt_chars:
        raise HTTPException(
            status_code=413,
            detail=f"Prompt too large (maximum {settings.max_prompt_chars} characters)",
        )

    safe_prompt, findings, blocked = _inspect_input(body.prompt, request)
    _raise_if_blocked(findings, blocked)

    api_key = settings.llm_api_key.get_secret_value()
    if not api_key:
        raise HTTPException(
            status_code=503,
            detail="LLM upstream is not configured; set GATEWAY_LLM_API_KEY",
        )

    http_client: httpx.AsyncClient = request.app.state.http_client
    try:
        response_text = await _call_upstream_llm(
            http_client,
            settings,
            safe_prompt,
            body.model or settings.llm_model,
            body.temperature,
        )
    except httpx.HTTPError as exc:
        logger.exception("Upstream LLM request failed")
        raise HTTPException(status_code=502, detail="Upstream LLM request failed") from exc
    except UpstreamResponseError as exc:
        logger.error("Upstream LLM returned an invalid response")
        raise HTTPException(status_code=502, detail="Invalid response from LLM upstream") from exc

    sanitized_response, output_findings = inspect_output_with_handler(
        response_text,
        request.app.state.pii_handler,
    )
    findings.extend(output_findings)
    decision = decide(GatewayMode(settings.mode), findings)
    if decision.blocked:
        raise HTTPException(
            status_code=502,
            detail={
                "blocked": True,
                "would_block": True,
                "findings": findings,
            },
        )

    return ChatResponse(
        status="success",
        safe_prompt=safe_prompt,
        response=sanitized_response,
        blocked=False,
        would_block=decision.would_block,
        findings=findings,
        mode=GatewayMode(settings.mode),
    )


class UpstreamResponseError(Exception):
    """Raised when an upstream response cannot be interpreted safely."""


async def _call_upstream_llm(
    client: httpx.AsyncClient,
    settings: Settings,
    prompt: str,
    model: str,
    temperature: float,
) -> str:
    payload = {
        "model": model,
        "max_tokens": 1024,
        "temperature": temperature,
        "messages": [{"role": "user", "content": prompt}],
    }
    response = await client.post(
        settings.llm_base_url,
        headers={
            "x-api-key": settings.llm_api_key.get_secret_value(),
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json=payload,
    )
    response.raise_for_status()
    try:
        data = response.json()
    except ValueError as exc:
        raise UpstreamResponseError("Upstream response was not valid JSON") from exc
    if not isinstance(data, dict) or not isinstance(data.get("content"), list):
        raise UpstreamResponseError("Upstream response had an unexpected shape")
    parts = [
        item["text"]
        for item in data["content"]
        if isinstance(item, dict)
        and item.get("type") == "text"
        and isinstance(item.get("text"), str)
    ]
    if not parts:
        raise UpstreamResponseError("Upstream response did not contain text")
    return "".join(parts)

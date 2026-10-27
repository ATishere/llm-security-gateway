# LLM Security Gateway + Controlled Red-Teaming

A defensive FastAPI gateway and bounded local evaluation scaffold for learning and
portfolio demonstration. It includes heuristic prompt inspection, PII masking,
an Anthropic Messages API adapter, output inspection, shadow/enforce modes, and an
optional Garak/LangGraph runner. It is not a production-certified platform and
does not claim full OWASP LLM Top 10 or MITRE ATLAS coverage.

## What is implemented

### Gateway

- `POST /v1/inspect` checks a prompt without calling an LLM.
- `POST /v1/chat/completions` applies input checks and optional PII masking,
  calls a configured Anthropic Messages-compatible endpoint, then inspects its
  response.
- Heuristic prompt-injection patterns with NFKC and zero-width character
  normalization.
- Regex PII baseline; optional Microsoft Presidio masking with typed placeholders.
- Output control-character cleanup and email/phone leakage detection.
- Shadow mode is the default. Enforce mode blocks injection/rate-limit signals
  and responses where the configured PII detector finds a leak.
- Process-local in-memory rate limiting and configurable request size and timeout.

### Red-team harness

- Optional LangGraph workflow and Garak CLI adapter.
- Literal loopback IPs only, one exact gateway route, two allowlisted probes,
  explicit local authorization confirmation, and bounded execution time.
- Parses evaluated Garak JSONL attempts into structured findings. It does not
  infer a CVSS score from detector confidence.
- CI runs unit tests and static lint only; it does not launch a scan on pull
  requests.

## Quick start (PowerShell)

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
Copy-Item .env.example .env
pytest
ruff check .
uvicorn gateway.main:app --reload --app-dir src
```

Set `GATEWAY_LLM_API_KEY` in your environment or local `.env` to enable chat
requests. Do not commit credentials. Without an upstream API key, chat returns
HTTP 503 rather than a mock model response.

Inspect a prompt without calling the LLM:

```powershell
Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8000/v1/inspect `
  -ContentType "application/json" `
  -Body '{"prompt":"Contact alice@example.com"}'
```

Send a chat request after configuring the upstream:

```powershell
Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8000/v1/chat/completions `
  -ContentType "application/json" `
  -Body '{"prompt":"Summarize this text"}'
```

## Optional Presidio support

```powershell
python -m pip install -e ".[dev,pii]"
python -m spacy download en_core_web_lg
$env:GATEWAY_PII_BACKEND = "presidio"
```

The regex PII detector is the default development backend. Presidio and its
language model must be installed before selecting the `presidio` backend.

## Optional authorized local red-team scan

Install the opt-in dependencies:

```powershell
python -m pip install -e ".[red-team]"
```

Start a local gateway that you own, then run the constrained scan:

```powershell
python -m red_team `
  --target http://127.0.0.1:8000/v1/chat/completions `
  --authorization-reference LOCAL-APPROVAL-123 `
  --confirm-local-target `
  --probes promptinject,encoding `
  --output red_team_report.json `
  --fail-on HIGH
```

Keep generated reports private if they contain prompts or model responses.
Garak/LangGraph are optional and have not been run as part of the default CI job.

## Configuration

Settings use the `GATEWAY_` prefix. See [.env.example](./.env.example) for a
non-secret template.

| Variable | Default | Description |
|---|---|---|
| `GATEWAY_MODE` | `shadow` | `shadow` or `enforce` |
| `GATEWAY_LLM_BASE_URL` | Anthropic Messages URL | HTTP(S) upstream URL; non-loopback HTTP is rejected |
| `GATEWAY_LLM_API_KEY` | empty | Upstream credential; chat returns 503 when empty |
| `GATEWAY_LLM_MODEL` | `claude-3-5-sonnet-20241022` | Default upstream model |
| `GATEWAY_LLM_TIMEOUT_SECONDS` | `60` | Upstream request timeout |
| `GATEWAY_MAX_PROMPT_CHARS` | `32000` | Chat prompt size limit |
| `GATEWAY_ENABLE_PII` | `true` | Enable input PII masking |
| `GATEWAY_PII_BACKEND` | `regex` | `regex` or `presidio` |
| `GATEWAY_PII_SCORE_THRESHOLD` | `0.5` | Presidio recognizer threshold |
| `GATEWAY_RATE_LIMIT_REQUESTS` | `60` | Requests per client key |
| `GATEWAY_RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate limit window |
| `GATEWAY_LOG_LEVEL` | `INFO` | Python logging level |

## Project layout

```text
src/
  gateway/
    config.py               # Validated env settings
    layers/                 # Injection, PII, rate limit, output inspection
    main.py                 # FastAPI app and upstream adapter
    shadow_mode.py          # Shadow/enforce decisions
  red_team/
    tools/                  # Garak adapter and evaluation seams
    agent.py                # Bounded LangGraph workflow
    __main__.py              # Explicitly confirmed local scan CLI
    reporter.py             # Structured findings
tests/
docs/
```

## Limitations and production-readiness gaps

- Injection and regex PII checks are heuristics, not robust classifiers; this
  starter does not include Llama Guard or provider-backed moderation.
- Rate limiting is in-memory and per-process, not Redis-backed or per-user.
- The upstream adapter is non-streaming and Anthropic-shaped; it does not
  implement tool calls, conversation history, or provider retry/circuit-breaker
  behavior.
- Authentication/authorization, distributed rate limits, concurrency controls,
  centralized secrets, audit/retention policy, readiness checks, and egress
  controls are not implemented.
- Shadow mode intentionally does not enforce blocks. Review findings before
  enabling enforce mode.
- OWASP/MITRE mappings need a versioned, reviewed control matrix before making
  coverage claims.

Red-team integrations must only target systems you own or have explicit written
permission to assess. CI does not scan external targets or execute attack
campaigns. See [docs/portfolio.md](./docs/portfolio.md) for a factual resume
summary.

## License

This project is distributed under the MIT License. See [LICENSE](./LICENSE).

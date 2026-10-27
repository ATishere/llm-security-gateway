"""Garak CLI adapter restricted to an explicitly authorized local gateway."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

ALLOWED_PROBES = frozenset({"promptinject", "encoding"})
MAX_PROBES_PER_RUN = 2
MAX_TIMEOUT_SECONDS = 120
MAX_REPORT_BYTES = 25_000_000


@dataclass(frozen=True)
class GarakAttempt:
    probe: str
    payload: str
    response: str
    detector: str
    passed: bool
    score: float


@dataclass
class GarakResult:
    probe_name: str
    attempts: list[GarakAttempt] = field(default_factory=list)
    error: str | None = None

    @property
    def vulnerabilities(self) -> list[GarakAttempt]:
        return [attempt for attempt in self.attempts if not attempt.passed]


def validate_local_gateway_url(target_url: str) -> None:
    parsed = urlparse(target_url)
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
    except ValueError as exc:
        raise ValueError("Garak scans require a literal loopback IP address") from exc

    if not address.is_loopback:
        raise ValueError("Garak scans are restricted to loopback targets")
    if parsed.scheme != "http":
        raise ValueError("The local gateway scan target must use HTTP")
    if parsed.path != "/v1/chat/completions":
        raise ValueError("Target must be the local gateway /v1/chat/completions endpoint")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Target URL must not contain credentials, query, or fragment")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Target URL must include a valid local port") from exc
    if port is None or not 1 <= port <= 65535:
        raise ValueError("Target URL must include a valid local port")


class GarakRunner:
    """Run a small allowlisted probe set against a local gateway only."""

    def __init__(self, target_url: str, timeout_seconds: int = 120) -> None:
        validate_local_gateway_url(target_url)
        if not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
            raise ValueError(f"timeout_seconds must be between 1 and {MAX_TIMEOUT_SECONDS}")
        self.target_url = target_url
        self.timeout = timeout_seconds

    def _generator_config(self) -> dict[str, object]:
        return {
            "rest": {
                "RestGenerator": {
                    "uri": self.target_url,
                    "method": "post",
                    "headers": {"content-type": "application/json"},
                    "req_template_json_object": {
                        "prompt": "$INPUT",
                        "temperature": 0,
                    },
                    "response_json": True,
                    "response_json_field": "response",
                    "request_timeout": self.timeout,
                    "skip_codes": [400, 401, 403, 413, 429, 500, 502, 503],
                }
            }
        }

    async def run_probe(self, probe_name: str) -> GarakResult:
        if probe_name not in ALLOWED_PROBES:
            raise ValueError(f"Probe is not allowlisted: {probe_name}")

        report_prefix = f"garak_{uuid.uuid4().hex}"
        with tempfile.TemporaryDirectory(prefix="garak_local_") as temporary_directory:
            workdir = Path(temporary_directory)
            generator_config = workdir / "rest_generator.json"
            generator_config.write_text(
                json.dumps(self._generator_config()),
                encoding="utf-8",
            )
            command = [
                sys.executable,
                "-m",
                "garak",
                "--target_type",
                "rest",
                "--generator_option_file",
                str(generator_config),
                "--spec",
                f"probes.{probe_name}",
                "--report_prefix",
                report_prefix,
            ]
            logger.info("Starting authorized local Garak probe", extra={"probe": probe_name})
            try:
                process = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                    cwd=str(workdir),
                )
            except FileNotFoundError:
                return GarakResult(probe_name, error="Garak is not installed")

            try:
                await asyncio.wait_for(process.wait(), timeout=self.timeout)
            except TimeoutError:
                process.kill()
                await process.wait()
                return GarakResult(
                    probe_name,
                    error=f"Garak probe timed out after {self.timeout} seconds",
                )

            if process.returncode != 0:
                return GarakResult(
                    probe_name,
                    error=f"Garak exited with status {process.returncode}",
                )

            reports = list(workdir.glob(f"{report_prefix}*.report.jsonl"))
            if len(reports) != 1:
                return GarakResult(
                    probe_name,
                    error="Garak did not produce exactly one report",
                )
            try:
                if reports[0].stat().st_size > MAX_REPORT_BYTES:
                    return GarakResult(probe_name, error="Garak report exceeds size limit")
                attempts = self.parse_report(reports[0])
                if not attempts:
                    return GarakResult(
                        probe_name,
                        error="No evaluated attempts; verify the Garak REST configuration",
                    )
                return GarakResult(
                    probe_name,
                    attempts=attempts,
                )
            except (OSError, ValueError) as exc:
                logger.exception("Could not parse Garak report")
                return GarakResult(probe_name, error=f"Invalid Garak report: {exc}")

    @staticmethod
    def parse_report(report_path: Path) -> list[GarakAttempt]:
        attempts: list[GarakAttempt] = []
        with report_path.open("r", encoding="utf-8") as report_file:
            for line_number, line in enumerate(report_file, start=1):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"malformed JSON on line {line_number}") from exc
                if not isinstance(entry, dict) or entry.get("entry_type") != "attempt":
                    continue
                if entry.get("status") != 2:
                    continue

                detector_results = entry.get("detector_results")
                if not isinstance(detector_results, dict):
                    continue
                prompt = entry.get("prompt")
                turns = prompt.get("turns", []) if isinstance(prompt, dict) else []
                first_turn = turns[0] if turns and isinstance(turns[0], dict) else {}
                payload = first_turn.get("content", "")
                outputs = entry.get("outputs", [])
                response = outputs[0] if outputs and isinstance(outputs[0], str) else ""
                probe = entry.get("probe_classname", "")

                for detector_name, detector_scores in detector_results.items():
                    scores = (
                        detector_scores
                        if isinstance(detector_scores, list)
                        else [detector_scores]
                    )
                    for score in scores:
                        if isinstance(score, bool) or not isinstance(score, (int, float)):
                            continue
                        numeric_score = float(score)
                        if not 0 <= numeric_score <= 1:
                            raise ValueError(f"detector score out of range on line {line_number}")
                        attempts.append(
                            GarakAttempt(
                                probe=str(probe),
                                payload=str(payload)[:500],
                                response=response[:500],
                                detector=str(detector_name),
                                passed=numeric_score < 0.5,
                                score=numeric_score,
                            )
                        )
        return attempts

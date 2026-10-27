import json

import pytest

from red_team.agent import AuthorizedTarget, planner, reporter, run_evaluation, should_fail
from red_team.state import AgentState
from red_team.tools.garak_runner import (
    ALLOWED_PROBES,
    GarakRunner,
    validate_local_gateway_url,
)


def test_target_rejects_non_loopback_http() -> None:
    target = AuthorizedTarget("http://example.com", "approval-123", 1)
    with pytest.raises(ValueError, match="HTTPS or loopback"):
        target.validate()


@pytest.mark.asyncio
async def test_budget_is_enforced_before_evaluation() -> None:
    class Case:
        id = "case-1"
        prompt = "benign test prompt"

    class Evaluator:
        async def evaluate(self, target, case):
            raise AssertionError("must not execute over budget")

    target = AuthorizedTarget("http://127.0.0.1", "approval-123", 1)
    with pytest.raises(ValueError, match="request budget"):
        await run_evaluation(target, [Case(), Case()], Evaluator())


@pytest.mark.parametrize(
    "target",
    [
        "http://example.com:8000/v1/chat/completions",
        "https://127.0.0.1:8000/v1/chat/completions",
        "http://127.0.0.1:8000/other",
        "http://127.0.0.1:8000/v1/chat/completions?x=1",
        "http://user:pass@127.0.0.1:8000/v1/chat/completions",
        "http://127.0.0.1:invalid/v1/chat/completions",
    ],
)
def test_garak_rejects_non_local_or_malformed_targets(target: str) -> None:
    with pytest.raises(ValueError):
        validate_local_gateway_url(target)


@pytest.mark.parametrize(
    "target",
    [
        "http://127.0.0.1:8000/v1/chat/completions",
        "http://[::1]:8000/v1/chat/completions",
    ],
)
def test_garak_accepts_loopback_gateway_targets(target: str) -> None:
    validate_local_gateway_url(target)
    runner = GarakRunner(target)
    assert runner.target_url == target


def test_garak_probe_is_allowlisted() -> None:
    runner = GarakRunner("http://127.0.0.1:8000/v1/chat/completions")
    assert ALLOWED_PROBES == {"promptinject", "encoding"}
    config = runner._generator_config()["rest"]["RestGenerator"]
    assert config["uri"] == runner.target_url
    assert config["req_template_json_object"] == {
        "prompt": "$INPUT",
        "temperature": 0,
    }
    assert config["response_json_field"] == "response"
    with pytest.raises(ValueError, match="not allowlisted"):
        import asyncio

        asyncio.run(runner.run_probe("unlisted"))


def test_garak_report_parser_only_uses_evaluated_attempts(tmp_path) -> None:
    report_path = tmp_path / "garak.report.jsonl"
    entries = [
        {"entry_type": "init", "status": 2},
        {"entry_type": "attempt", "status": 1, "detector_results": {"d": [1.0]}},
        {
            "entry_type": "attempt",
            "status": 2,
            "probe_classname": "promptinject.Test",
            "prompt": {"turns": [{"content": "attack"}]},
            "outputs": ["model response"],
            "detector_results": {"detector.one": [0.0, 0.9]},
        },
    ]
    report_path.write_text(
        "\n".join(json.dumps(entry) for entry in entries),
        encoding="utf-8",
    )

    attempts = GarakRunner.parse_report(report_path)
    assert len(attempts) == 2
    assert attempts[0].passed is True
    assert attempts[1].passed is False
    assert attempts[1].score == 0.9
    assert attempts[1].payload == "attack"


def test_garak_report_parser_rejects_bad_json_and_invalid_scores(tmp_path) -> None:
    report_path = tmp_path / "bad.report.jsonl"
    report_path.write_text("{bad json}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="malformed JSON"):
        GarakRunner.parse_report(report_path)

    report_path.write_text(
        json.dumps(
            {
                "entry_type": "attempt",
                "status": 2,
                "detector_results": {"detector.one": [1.5]},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="out of range"):
        GarakRunner.parse_report(report_path)


def test_planner_caps_and_validates_probe_names() -> None:
    state: AgentState = {"probes_to_run": ["promptinject"]}
    assert planner(state) == {"probes_to_run": ["promptinject"]}
    with pytest.raises(ValueError, match="allowlisted"):
        planner({"probes_to_run": ["arbitrary"]})
    with pytest.raises(ValueError, match="between"):
        planner({"probes_to_run": ["promptinject", "encoding", "promptinject"]})


def test_reporter_does_not_infer_cvss_from_detector_score() -> None:
    state: AgentState = {
        "target_url": "http://127.0.0.1:8000/v1/chat/completions",
        "probes_run": ["promptinject"],
        "vulnerabilities": [{"score": 0.9, "probe": "probe", "payload": "sample"}],
        "errors": [],
    }
    result = reporter(state)["report"]
    assert result["by_severity"] == {"HIGH": 1, "MEDIUM": 0, "LOW": 0}
    assert "not a CVSS" in result["cvss_note"]
    assert should_fail(result, "HIGH")
    assert should_fail(result, "LOW")
    assert not should_fail(
        {"by_severity": {"HIGH": 0, "MEDIUM": 0, "LOW": 1}},
        "HIGH",
    )

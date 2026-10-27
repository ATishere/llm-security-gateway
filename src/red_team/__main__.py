"""Run a bounded Garak scan against an explicitly authorized local gateway."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from red_team.agent import build_graph, should_fail
from red_team.tools.garak_runner import ALLOWED_PROBES, MAX_PROBES_PER_RUN


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        required=True,
        help="Loopback gateway URL, e.g. http://127.0.0.1:8000/v1/chat/completions",
    )
    parser.add_argument(
        "--authorization-reference",
        required=True,
        help="Non-secret reference for the local test authorization",
    )
    parser.add_argument(
        "--confirm-local-target",
        action="store_true",
        help="Confirm the target is a local system you own or are authorized to test",
    )
    parser.add_argument(
        "--probes",
        default="promptinject,encoding",
        help="Comma-separated allowlisted probes (maximum two)",
    )
    parser.add_argument("--output", default="red_team_report.json")
    parser.add_argument("--fail-on", default="HIGH", choices=["LOW", "MEDIUM", "HIGH"])
    args = parser.parse_args()

    if not args.confirm_local_target:
        parser.error("Pass --confirm-local-target after confirming authorization")

    probes = [probe.strip() for probe in args.probes.split(",") if probe.strip()]
    if not 1 <= len(probes) <= MAX_PROBES_PER_RUN:
        parser.error(f"Choose between 1 and {MAX_PROBES_PER_RUN} probes")
    if len(set(probes)) != len(probes) or any(probe not in ALLOWED_PROBES for probe in probes):
        parser.error(f"Probes must be unique and selected from {sorted(ALLOWED_PROBES)}")

    state = {
        "target_url": args.target,
        "authorization_reference": args.authorization_reference,
        "probes_to_run": probes,
        "probes_run": [],
        "vulnerabilities": [],
        "errors": [],
        "report": {},
    }
    try:
        final_state = asyncio.run(build_graph().ainvoke(state))
    except (ValueError, RuntimeError) as exc:
        print(f"Red-team scan not started: {exc}", file=sys.stderr)
        return 2

    report = final_state["report"]
    output_path = Path(args.output)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report["by_severity"], indent=2))
    print(f"Report written to {output_path}")
    if report["errors"]:
        print(f"Scan completed with {len(report['errors'])} probe error(s).", file=sys.stderr)
        return 2
    return 1 if should_fail(report, args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())

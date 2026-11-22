"""Command line: run the whole pipeline and save the JSON report.

    python -m recon                                    scan the default lab target
    python -m recon --target http://localhost:3001     another allowlisted spelling
    python -m recon --output report.json               choose where to save

Exit codes: 0 all scanners ok, 1 some scanner failed (partial report),
            2 target rejected, 3 lab not reachable.
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

from recon.config import DEFAULT_TARGET
from recon.lab import LabUnreachableError
from recon.pipeline import run_pipeline
from recon.targets import TargetError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m recon", description="Scan the local Juice Shop lab.")
    parser.add_argument("--target", default=DEFAULT_TARGET, help=f"allowlisted lab URL (default {DEFAULT_TARGET})")
    parser.add_argument("--output", type=Path, help="report path (default output/report_<time>.json)")
    parser.add_argument("-v", "--verbose", action="store_true", help="also log the exact commands run")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    try:
        report = run_pipeline(args.target)
    except TargetError as exc:
        logging.error("Target rejected: %s", exc)
        return 2
    except LabUnreachableError as exc:
        logging.error("%s", exc)
        return 3

    output = args.output or Path("output") / f"report_{datetime.now():%Y%m%d_%H%M%S}.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")

    summary = report["summary"]
    print(f"\nReport saved to {output}")
    print(f"Status: {report['status']} in {report['duration_seconds']}s")
    for name in ("nmap", "httpx", "nuclei"):
        section = report[name]
        detail = f"{len(section['results'])} result(s)" if section["status"] == "ok" else section["error"]
        print(f"  {name:<7} {section['status']:<6} {detail}")
    print(f"Open ports (inside lab network): {summary['open_ports']}")
    print(f"Title: {summary['http_title']}")
    print(f"Findings: {summary['findings_total']} {summary['findings_by_severity']}")

    return 0 if report["status"] == "complete" else 1


if __name__ == "__main__":
    sys.exit(main())

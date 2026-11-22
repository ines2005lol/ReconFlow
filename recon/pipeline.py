"""The pipeline: validate -> check lab -> Nmap -> httpx -> Nuclei -> one JSON report.

Two kinds of failure are treated differently:
  - a bad target or an unreachable lab STOPS the pipeline (exception), because
    nothing useful can come out of scanning;
  - a failing scanner does NOT: its section is marked "error" with the reason, and
    the remaining scanners still run, so one broken tool never loses the others' results.
"""

import logging
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Callable

from recon.lab import check_lab
from recon.runner import ScannerError
from recon.scanners.httpx_probe import run_httpx
from recon.scanners.nmap import run_nmap
from recon.scanners.nuclei import SEVERITY_ORDER, run_nuclei
from recon.targets import Target, validate_target

logger = logging.getLogger(__name__)

Scanner = Callable[[Target], list[dict]]

# Run in this order. A dict keeps insertion order, so the report follows it too.
DEFAULT_SCANNERS: dict[str, Scanner] = {
    "nmap": run_nmap,
    "httpx": run_httpx,
    "nuclei": run_nuclei,
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run_pipeline(raw_target: str, scanners: dict[str, Scanner] | None = None) -> dict:
    """Scan `raw_target` with every scanner and return the combined report.

    Raises TargetError (from validate_target) or LabUnreachableError (from check_lab)
    before any scanner runs. `scanners` can be replaced, which is how tests run the
    pipeline with fakes instead of real tools.
    """
    scanners = DEFAULT_SCANNERS if scanners is None else scanners

    target = validate_target(raw_target)  # 1. allowlist
    check_lab(target)  # 2. is the lab up?

    report: dict = {"target": target.url, "started_at": _now(), "lab_reachable": True}
    start = time.monotonic()

    for name, scanner in scanners.items():  # 3-5. each scanner, isolated
        report[name] = _run_one(name, scanner, target)

    report["finished_at"] = _now()
    report["duration_seconds"] = round(time.monotonic() - start, 1)
    report["status"] = "complete" if all(report[n]["status"] == "ok" for n in scanners) else "partial"
    report["summary"] = _summarize(report)
    return report


def _run_one(name: str, scanner: Scanner, target: Target) -> dict:
    logger.info("[%s] starting", name)
    start = time.monotonic()
    try:
        results = scanner(target)
    except ScannerError as exc:
        logger.error("[%s] failed: %s", name, exc)
        return _section("error", start, error=str(exc))
    except Exception as exc:  # a bug in our own parsing code
        # Logged with the full traceback, but the other scanners still run.
        logger.exception("[%s] crashed unexpectedly", name)
        return _section("error", start, error=f"Unexpected error: {type(exc).__name__}: {exc}")
    logger.info("[%s] done: %d result(s)", name, len(results))
    return _section("ok", start, results=results)


def _section(status: str, start: float, results: list | None = None, error: str | None = None) -> dict:
    return {
        "status": status,
        "error": error,
        "duration_seconds": round(time.monotonic() - start, 1),
        "results": results or [],
    }


def _summarize(report: dict) -> dict:
    """A few headline numbers, computed only from scanners that succeeded."""
    nmap = report.get("nmap", {}).get("results", [])
    httpx = report.get("httpx", {}).get("results", [])
    nuclei = report.get("nuclei", {}).get("results", [])

    severities = Counter(f["severity"] for f in nuclei)
    return {
        "open_ports": [p["port"] for h in nmap for p in h["ports"] if p["state"] == "open"],
        "http_title": httpx[0].get("title") if httpx else None,
        "technologies": httpx[0].get("technologies", []) if httpx else [],
        "findings_total": len(nuclei),
        "findings_by_severity": {s: severities[s] for s in SEVERITY_ORDER if severities[s]},
    }

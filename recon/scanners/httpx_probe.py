"""ProjectDiscovery httpx: is the web app reachable, and what is it?

Named httpx_probe.py (not httpx.py) so it can never be confused with, or shadow,
the unrelated `httpx` Python library.
"""

import json
import logging

from recon import config
from recon.runner import ScannerError, docker_scanner_command, run_command
from recon.targets import Target

logger = logging.getLogger(__name__)


def build_httpx_args(target: Target) -> list[str]:
    """httpx arguments for probing the single lab URL.

      -u <url>                one target URL (no lists, no crawling)
      -json                   one JSON object per line (JSONL) on stdout
      -silent -no-color       only results on stdout, no banner or colour codes
      -disable-update-check   never phone home to check for a new version
      -probe                  also emit a result when the request FAILS (failed: true),
                              instead of printing nothing
      -status-code -title -tech-detect -web-server -content-type
                              the metadata we want in the report
      -timeout 10 -retries 1  per-request limits
    """
    return [
        "-u", target.scanner_url,
        "-json", "-silent", "-no-color", "-disable-update-check",
        "-probe",
        "-status-code", "-title", "-tech-detect", "-web-server", "-content-type",
        "-timeout", "10", "-retries", "1",
    ]


def run_httpx(target: Target) -> list[dict]:
    """Probe the validated target with httpx and return the parsed results."""
    args = docker_scanner_command(config.HTTPX_IMAGE, build_httpx_args(target))
    logger.info("Running httpx against %s", target.url)
    result = run_command(args, timeout=config.HTTPX_TIMEOUT)
    results = parse_httpx_jsonl(result.stdout)
    for r in results:  # report the URL you can open (3001), not the in-lab one (3000)
        r["url"] = target.to_host_url(r["url"])
    return results


def parse_httpx_jsonl(text: str) -> list[dict]:
    """Turn httpx's JSONL output into a list of probe results.

    JSONL = one JSON document per line. Each line is parsed on its own, so one broken
    line is skipped (and logged) instead of losing the whole result.
    """
    results = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("Skipping malformed httpx line %d: %.100s", line_number, line)
            continue
        if not isinstance(record, dict):
            logger.warning("Skipping non-object httpx line %d", line_number)
            continue
        results.append(_extract(record))

    if not results:
        # With -probe, even a failed request produces a line, so no lines at all
        # means httpx itself misbehaved.
        raise ScannerError("httpx produced no parsable results.")
    return results


def _extract(record: dict) -> dict:
    """Keep the fields we report; httpx emits many more (hashes, word counts, ...)."""
    failed = bool(record.get("failed", False))
    return {
        "url": record.get("url") or record.get("input"),
        "reachable": not failed,
        "status_code": record.get("status_code") or None,  # httpx uses 0 for "none"
        "title": record.get("title"),
        "web_server": record.get("webserver"),
        "content_type": record.get("content_type"),
        "content_length": record.get("content_length"),
        "technologies": record.get("tech") or [],
        "response_time": record.get("time"),
        "error": record.get("error") if failed else None,
    }

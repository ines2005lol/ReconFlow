"""Nuclei: template-based checks for known vulnerabilities and misconfigurations."""

import json
import logging

from recon import config
from recon.runner import ScannerError, docker_scanner_command, run_command
from recon.targets import Target

logger = logging.getLogger(__name__)

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


def build_nuclei_docker_args() -> list[str]:
    # Templates come from a named volume, mounted read-only (:ro) so a scan can
    # never modify them.
    return ["-v", f"{config.NUCLEI_TEMPLATES_VOLUME}:/root/nuclei-templates:ro"]


def build_nuclei_args(target: Target) -> list[str]:
    """Nuclei arguments for a safe, web-only scan of the lab URL.

      -u <url>                 the single lab URL
      -jsonl -silent -no-color one finding per line on stdout, nothing else
      -disable-update-check    no network calls to check for updates
      -no-interactsh           never make the target call out to public OAST servers
                               (that would send lab data to the internet)
      -omit-raw                leave full requests/responses out of each finding
      -type http               web templates only (no code/network/dns/file templates)
      -exclude-tags ...        no DoS, intrusive, fuzzing or brute-force templates
      -rate-limit/-concurrency/-timeout/-retries   bound speed and waiting time
    """
    return [
        "-u", target.scanner_url,
        "-jsonl", "-silent", "-no-color",
        "-disable-update-check",
        "-no-interactsh",
        "-omit-raw",
        "-type", "http",
        "-exclude-tags", ",".join(config.NUCLEI_EXCLUDED_TAGS),
        "-rate-limit", "150", "-concurrency", "25",
        "-timeout", "10", "-retries", "1",
    ]


def run_nuclei(target: Target) -> list[dict]:
    """Run Nuclei against the validated target and return the parsed findings."""
    args = docker_scanner_command(
        config.NUCLEI_IMAGE, build_nuclei_args(target), docker_args=build_nuclei_docker_args()
    )
    logger.info("Running Nuclei against %s (this takes a couple of minutes)", target.url)
    try:
        result = run_command(args, timeout=config.NUCLEI_TIMEOUT)
    except ScannerError as exc:
        # An empty template volume makes Nuclei exit 1 with "no templates provided".
        if "no templates" in str(exc):
            raise ScannerError(
                f"{exc} -- download them first: docker run --rm -v "
                f"{config.NUCLEI_TEMPLATES_VOLUME}:/root/nuclei-templates "
                f"{config.NUCLEI_IMAGE} -update-templates"
            ) from exc
        raise
    findings = parse_nuclei_jsonl(result.stdout)
    for f in findings:  # report the URL you can open (3001), not the in-lab one (3000)
        f["matched_at"] = target.to_host_url(f["matched_at"])
    return findings


def parse_nuclei_jsonl(text: str) -> list[dict]:
    """Turn Nuclei's JSONL output into findings, most severe first.

    Unlike httpx, empty output is a normal result here: it means no template matched.
    """
    findings = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("Skipping malformed Nuclei line %d: %.100s", line_number, line)
            continue
        if not isinstance(record, dict) or "template-id" not in record:
            logger.warning("Skipping Nuclei line %d: not a finding", line_number)
            continue
        findings.append(_extract(record))

    findings.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]))
    if not findings:
        logger.info("Nuclei finished with no findings.")
    return findings


def _extract(record: dict) -> dict:
    info = record.get("info") or {}
    classification = info.get("classification") or {}

    severity = str(info.get("severity", "unknown")).lower()
    if severity not in SEVERITY_ORDER:
        severity = "unknown"

    return {
        "template_id": record["template-id"],
        "name": info.get("name"),
        "severity": severity,
        "matched_at": record.get("matched-at"),
        # Some templates produce several findings (e.g. one per missing header);
        # matcher_name tells them apart.
        "matcher_name": record.get("matcher-name"),
        "description": (info.get("description") or "").strip() or None,
        "references": _as_list(info.get("reference")),
        "tags": _as_list(info.get("tags")),
        "cve_ids": _as_list(classification.get("cve-id")),
        "cwe_ids": _as_list(classification.get("cwe-id")),
        "cvss_score": classification.get("cvss-score"),
        "extracted_results": _as_list(record.get("extracted-results")),
    }


def _as_list(value) -> list:
    """Nuclei writes some fields as a list, a comma-separated string, or null."""
    if value is None:
        return []
    if isinstance(value, list):
        return [v for v in value if v is not None]
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return [value]

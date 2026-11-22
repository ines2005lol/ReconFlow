"""Nuclei tests use saved output instead of running Nuclei.

fixtures/nuclei_juice_shop.jsonl: real scan of the lab (Nuclei v3.11.1, 19 findings)."""

import json
from pathlib import Path

import pytest

from recon.runner import ScannerError
from recon.scanners import nuclei
from recon.scanners.nuclei import build_nuclei_args, parse_nuclei_jsonl
from recon.targets import validate_target

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def findings():
    return parse_nuclei_jsonl((FIXTURES / "nuclei_juice_shop.jsonl").read_text(encoding="utf-8"))


def test_parses_all_real_findings_most_severe_first(findings):
    assert len(findings) == 19
    assert findings[0]["severity"] == "medium"
    assert all(f["severity"] == "info" for f in findings[1:])


def test_extracts_full_details_of_a_finding(findings):
    metrics = findings[0]

    assert metrics["template_id"] == "prometheus-metrics"
    assert metrics["name"] == "Prometheus Metrics - Detect"
    assert metrics["matched_at"] == "http://127.0.0.1:3000/metrics"
    assert metrics["description"] == "Prometheus metrics page was detected."
    assert "https://hackerone.com/reports/1026196" in metrics["references"]
    assert metrics["cwe_ids"] == ["cwe-200"]
    assert metrics["cve_ids"] == []  # null in Nuclei's output
    assert metrics["cvss_score"] == 5.3


def test_matcher_name_separates_findings_from_one_template(findings):
    headers = [f["matcher_name"] for f in findings if f["template_id"] == "http-missing-security-headers"]

    assert len(headers) == 8
    assert "content-security-policy" in headers


def test_missing_optional_fields_become_empty_values():
    line = json.dumps({"template-id": "x", "info": {"name": "X", "severity": "low"}})
    [finding] = parse_nuclei_jsonl(line)

    assert finding["description"] is None
    assert finding["references"] == []
    assert finding["matched_at"] is None


def test_reference_as_comma_separated_string():
    line = json.dumps({"template-id": "x", "info": {"severity": "high", "reference": "https://a, https://b"}})
    assert parse_nuclei_jsonl(line)[0]["references"] == ["https://a", "https://b"]


def test_unknown_severity_is_normalised():
    line = json.dumps({"template-id": "x", "info": {"severity": "SuperBad"}})
    assert parse_nuclei_jsonl(line)[0]["severity"] == "unknown"


@pytest.mark.parametrize("text", ["", "\n\n"])
def test_empty_output_means_no_findings(text):
    assert parse_nuclei_jsonl(text) == []


def test_malformed_and_non_finding_lines_are_skipped():
    good = json.dumps({"template-id": "x", "info": {"severity": "info"}})
    text = "\n".join(["{broken", "[1, 2]", '{"no": "template id"}', good])

    assert [f["template_id"] for f in parse_nuclei_jsonl(text)] == ["x"]


def test_safe_flags_are_always_present():
    args = build_nuclei_args(validate_target("http://127.0.0.1:3001"))

    assert args[args.index("-u") + 1] == "http://127.0.0.1:3000"
    assert args[args.index("-type") + 1] == "http"
    assert args[args.index("-exclude-tags") + 1] == "dos,intrusive,fuzz,bruteforce"
    assert "-no-interactsh" in args
    assert "-disable-update-check" in args


def test_run_nuclei_reports_host_urls(monkeypatch):
    fixture = (FIXTURES / "nuclei_juice_shop.jsonl").read_text(encoding="utf-8")
    monkeypatch.setattr(nuclei, "run_command", lambda args, timeout: type("R", (), {"stdout": fixture})())

    findings = nuclei.run_nuclei(validate_target("http://127.0.0.1:3001"))

    assert findings[0]["matched_at"] == "http://127.0.0.1:3001/metrics"
    assert all(":3000" not in f["matched_at"] for f in findings)


def test_missing_templates_gives_setup_hint(monkeypatch):
    def fail(args, timeout):
        raise ScannerError("'docker' exited with code 1: [FTL] Could not run nuclei: no templates provided for scan")

    monkeypatch.setattr(nuclei, "run_command", fail)

    with pytest.raises(ScannerError, match="-update-templates"):
        nuclei.run_nuclei(validate_target("http://127.0.0.1:3001"))

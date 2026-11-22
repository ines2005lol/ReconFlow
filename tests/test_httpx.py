"""httpx tests use saved output instead of running httpx.

fixtures/httpx_juice_shop.jsonl: real probe of the lab (httpx v1.12.0).
fixtures/httpx_failed.jsonl:     real probe of a closed port (-probe, connection refused)."""

from pathlib import Path

import pytest

from recon.runner import ScannerError, docker_scanner_command
from recon.scanners.httpx_probe import build_httpx_args, parse_httpx_jsonl
from recon.targets import validate_target

FIXTURES = Path(__file__).parent / "fixtures"


def read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_parses_real_juice_shop_probe():
    [result] = parse_httpx_jsonl(read("httpx_juice_shop.jsonl"))

    assert result["url"] == "http://127.0.0.1:3000"
    assert result["reachable"] is True
    assert result["status_code"] == 200
    assert result["title"] == "OWASP Juice Shop"
    assert result["content_type"] == "text/html"
    assert result["content_length"] == 80117
    assert "jQuery:2.2.4" in result["technologies"]
    assert result["web_server"] is None  # Juice Shop sends no Server header
    assert result["error"] is None


def test_parses_failed_probe():
    [result] = parse_httpx_jsonl(read("httpx_failed.jsonl"))

    assert result["reachable"] is False
    assert result["status_code"] is None  # httpx reports 0, we normalise to None
    assert "connection refused" in result["error"]
    assert result["technologies"] == []


def test_malformed_lines_are_skipped_not_fatal():
    text = "this is not json\n\n[1, 2]\n" + read("httpx_juice_shop.jsonl")
    results = parse_httpx_jsonl(text)

    assert len(results) == 1
    assert results[0]["title"] == "OWASP Juice Shop"


@pytest.mark.parametrize("bad_output", ["", "\n\n", "not json at all", "{broken"])
def test_no_parsable_results_raises(bad_output):
    with pytest.raises(ScannerError, match="no parsable results"):
        parse_httpx_jsonl(bad_output)


def test_command_probes_only_the_lab_url():
    target = validate_target("http://127.0.0.1:3001")
    cmd = docker_scanner_command("projectdiscovery/httpx:v1.12.0", build_httpx_args(target))

    assert cmd[:6] == [
        "docker", "run", "--rm",
        "--network", "container:recon-lab-juice-shop-1",
        "projectdiscovery/httpx:v1.12.0",
    ]
    assert cmd[cmd.index("-u") + 1] == "http://127.0.0.1:3000"
    assert "-probe" in cmd and "-json" in cmd

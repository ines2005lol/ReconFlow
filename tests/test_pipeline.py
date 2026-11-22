"""Pipeline tests run the orchestration with fake scanners and a fake lab check,
so no Docker, no lab and no scan are needed."""

import json

import pytest

from recon import __main__ as cli
from recon import pipeline
from recon.lab import LabUnreachableError
from recon.runner import ScannerError
from recon.targets import TargetError

NMAP_RESULT = [{"address": "127.0.0.1", "status": "up",
                "ports": [{"port": 3000, "state": "open"}, {"port": 22, "state": "closed"}]}]
HTTPX_RESULT = [{"title": "OWASP Juice Shop", "technologies": ["jQuery:2.2.4"]}]
NUCLEI_RESULT = [{"template_id": "prometheus-metrics", "severity": "medium"},
                 {"template_id": "robots-txt", "severity": "info"},
                 {"template_id": "security-txt", "severity": "info"}]


def fake_scanners(**overrides):
    scanners = {
        "nmap": lambda target: NMAP_RESULT,
        "httpx": lambda target: HTTPX_RESULT,
        "nuclei": lambda target: NUCLEI_RESULT,
    }
    scanners.update(overrides)
    return scanners


@pytest.fixture(autouse=True)
def lab_is_up(monkeypatch):
    monkeypatch.setattr(pipeline, "check_lab", lambda target: None)


def test_complete_report_has_every_section_and_summary():
    report = pipeline.run_pipeline("http://127.0.0.1:3001", fake_scanners())

    assert report["target"] == "http://127.0.0.1:3001"
    assert report["status"] == "complete"
    assert report["lab_reachable"] is True
    for name in ("nmap", "httpx", "nuclei"):
        assert report[name]["status"] == "ok"
        assert report[name]["error"] is None
    assert report["nuclei"]["results"] == NUCLEI_RESULT
    assert report["summary"] == {
        "open_ports": [3000],
        "http_title": "OWASP Juice Shop",
        "technologies": ["jQuery:2.2.4"],
        "findings_total": 3,
        "findings_by_severity": {"medium": 1, "info": 2},
    }
    json.dumps(report)  # the report must be serialisable as-is


def test_failing_scanner_gives_partial_report_and_others_still_run():
    def broken(target):
        raise ScannerError("'docker' exited with code 125: no such container")

    report = pipeline.run_pipeline("http://127.0.0.1:3001", fake_scanners(httpx=broken))

    assert report["status"] == "partial"
    assert report["httpx"] == {"status": "error", "error": "'docker' exited with code 125: no such container",
                               "duration_seconds": report["httpx"]["duration_seconds"], "results": []}
    assert report["nmap"]["status"] == "ok"
    assert report["nuclei"]["status"] == "ok"  # ran after the failure
    assert report["summary"]["http_title"] is None


def test_unexpected_crash_in_a_scanner_is_contained():
    def buggy(target):
        raise KeyError("ports")

    report = pipeline.run_pipeline("http://127.0.0.1:3001", fake_scanners(nmap=buggy))

    assert report["nmap"]["status"] == "error"
    assert "KeyError" in report["nmap"]["error"]
    assert report["status"] == "partial"
    assert report["nuclei"]["status"] == "ok"


def test_rejected_target_stops_before_lab_check_and_scanners(monkeypatch):
    calls = []
    monkeypatch.setattr(pipeline, "check_lab", lambda target: calls.append("lab"))
    spy = {name: (lambda target, n=name: calls.append(n) or []) for name in ("nmap", "httpx", "nuclei")}

    with pytest.raises(TargetError):
        pipeline.run_pipeline("http://scanme.nmap.org:80", spy)
    assert calls == []


def test_unreachable_lab_stops_before_scanners(monkeypatch):
    def lab_down(target):
        raise LabUnreachableError("Lab at http://127.0.0.1:3001 is not reachable")

    monkeypatch.setattr(pipeline, "check_lab", lab_down)
    ran = []
    spy = {name: (lambda target, n=name: ran.append(n) or []) for name in ("nmap", "httpx", "nuclei")}

    with pytest.raises(LabUnreachableError):
        pipeline.run_pipeline("http://127.0.0.1:3001", spy)
    assert ran == []


# --- command line -----------------------------------------------------------

def test_cli_writes_report_and_exits_0(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "run_pipeline", lambda raw: pipeline.run_pipeline(raw, fake_scanners()))
    out = tmp_path / "report.json"

    assert cli.main(["--output", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["status"] == "complete"
    assert "Findings: 3" in capsys.readouterr().out


def test_cli_partial_report_exits_1(monkeypatch, tmp_path):
    def broken(target):
        raise ScannerError("timeout")

    monkeypatch.setattr(cli, "run_pipeline", lambda raw: pipeline.run_pipeline(raw, fake_scanners(nuclei=broken)))
    assert cli.main(["--output", str(tmp_path / "r.json")]) == 1


def test_cli_rejected_target_exits_2_and_writes_nothing(tmp_path):
    out = tmp_path / "r.json"
    assert cli.main(["--target", "http://8.8.8.8:3001", "--output", str(out)]) == 2
    assert not out.exists()


def test_cli_unreachable_lab_exits_3(monkeypatch, tmp_path):
    def lab_down(target):
        raise LabUnreachableError("down")

    monkeypatch.setattr(pipeline, "check_lab", lab_down)
    assert cli.main(["--output", str(tmp_path / "r.json")]) == 3

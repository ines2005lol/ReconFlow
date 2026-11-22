"""API tests call the endpoint functions directly and replace run_nmap with a fake,
so no server and no scan are needed."""

import pytest
from fastapi import HTTPException

from recon import api
from recon.runner import ScannerError


def test_health():
    assert api.health() == {"status": "ok"}


def test_root_redirects_to_docs():
    response = api.root()
    assert response.status_code == 307
    assert response.headers["location"] == "/docs"


def test_scan_returns_parsed_hosts(monkeypatch):
    fake_hosts = [{"address": "127.0.0.1", "status": "up", "ports": []}]
    monkeypatch.setattr(api, "run_nmap", lambda target: fake_hosts)

    result = api.scan_nmap(api.ScanRequest(target="http://127.0.0.1:3001"))

    assert result == {"target": "http://127.0.0.1:3001", "scanner": "nmap", "hosts": fake_hosts}


def test_disallowed_target_is_400_and_never_scans(monkeypatch):
    def must_not_run(target):
        raise AssertionError("run_nmap must not be called for a rejected target")

    monkeypatch.setattr(api, "run_nmap", must_not_run)

    with pytest.raises(HTTPException) as exc_info:
        api.scan_nmap(api.ScanRequest(target="http://8.8.8.8:3001"))
    assert exc_info.value.status_code == 400


def test_httpx_scan_returns_results(monkeypatch):
    fake = [{"url": "http://127.0.0.1:3000", "reachable": True, "title": "OWASP Juice Shop"}]
    monkeypatch.setattr(api, "run_httpx", lambda target: fake)

    result = api.scan_httpx(api.ScanRequest(target="http://localhost:3001"))

    assert result == {"target": "http://localhost:3001", "scanner": "httpx", "results": fake}


def test_httpx_disallowed_target_is_400(monkeypatch):
    monkeypatch.setattr(api, "run_httpx", lambda target: pytest.fail("must not scan"))

    with pytest.raises(HTTPException) as exc_info:
        api.scan_httpx(api.ScanRequest(target="http://example.com:3001"))
    assert exc_info.value.status_code == 400


def test_nuclei_scan_returns_count_and_findings(monkeypatch):
    fake = [{"template_id": "prometheus-metrics", "severity": "medium"}]
    monkeypatch.setattr(api, "run_nuclei", lambda target: fake)

    result = api.scan_nuclei(api.ScanRequest(target="http://127.0.0.1:3001"))

    assert result["count"] == 1
    assert result["findings"] == fake


def test_full_scan_returns_pipeline_report(monkeypatch):
    monkeypatch.setattr(api, "run_pipeline", lambda raw: {"target": raw, "status": "complete"})
    assert api.scan_all(api.ScanRequest(target="http://127.0.0.1:3001"))["status"] == "complete"


def test_full_scan_lab_down_is_503(monkeypatch):
    def down(raw):
        raise api.LabUnreachableError("Lab is not reachable")

    monkeypatch.setattr(api, "run_pipeline", down)
    with pytest.raises(HTTPException) as exc_info:
        api.scan_all(api.ScanRequest(target="http://127.0.0.1:3001"))
    assert exc_info.value.status_code == 503


def test_full_scan_rejected_target_is_400():
    # The real pipeline: validation fails before the lab check or any scanner.
    with pytest.raises(HTTPException) as exc_info:
        api.scan_all(api.ScanRequest(target="http://10.0.0.1:3001"))
    assert exc_info.value.status_code == 400


def test_scanner_failure_is_502(monkeypatch):
    def broken(target):
        raise ScannerError("'docker' was not found")

    monkeypatch.setattr(api, "run_nmap", broken)

    with pytest.raises(HTTPException) as exc_info:
        api.scan_nmap(api.ScanRequest(target="http://127.0.0.1:3001"))
    assert exc_info.value.status_code == 502
    assert "docker" in exc_info.value.detail

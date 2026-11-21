"""API tests call the endpoint functions directly and replace run_nmap with a fake,
so no server and no scan are needed."""

import pytest
from fastapi import HTTPException

from recon import api
from recon.runner import ScannerError


def test_health():
    assert api.health() == {"status": "ok"}


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


def test_scanner_failure_is_502(monkeypatch):
    def broken(target):
        raise ScannerError("'docker' was not found")

    monkeypatch.setattr(api, "run_nmap", broken)

    with pytest.raises(HTTPException) as exc_info:
        api.scan_nmap(api.ScanRequest(target="http://127.0.0.1:3001"))
    assert exc_info.value.status_code == 502
    assert "docker" in exc_info.value.detail

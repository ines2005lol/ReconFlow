"""Tests for the LLM triage step. Ollama is mocked: no model needed to run them."""

import json
import urllib.error

import pytest

from recon import triage
from recon.triage import TriageError

FINDING = {
    "template_id": "prometheus-metrics",
    "name": "Prometheus Metrics - Detect",
    "severity": "medium",
    "matched_at": "http://127.0.0.1:3001/metrics",
    "description": "Prometheus metrics page was detected.",
    "references": ["https://example.com/very-long-reference"],
    "tags": ["exposure"],
    "cwe_ids": ["cwe-200"],
    "cvss_score": 5.3,
}

GOOD_ANSWER = json.dumps({
    "verdict": "likely_true_positive",
    "confidence": "high",
    "explanation": "The /metrics endpoint is publicly reachable.",
    "risk": "Leaks internal metrics.",
    "remediation": "Restrict /metrics to the monitoring network.",
})


def make_report(findings):
    return {
        "httpx": {"status": "ok", "results": [{"technologies": ["jQuery:2.2.4"]}]},
        "nuclei": {"status": "ok", "results": findings},
    }


def test_messages_contain_finding_as_data_without_references():
    messages = triage.build_messages(FINDING, ["jQuery:2.2.4"])
    assert messages[0]["role"] == "system"
    assert "untrusted data" in messages[0]["content"]
    payload = json.loads(messages[1]["content"])
    assert payload["finding"]["template_id"] == "prometheus-metrics"
    assert "references" not in payload["finding"]
    assert payload["detected_technologies"] == ["jQuery:2.2.4"]


def test_parse_valid_answer():
    result = triage.parse_triage(GOOD_ANSWER)
    assert result["verdict"] == "likely_true_positive"
    assert result["confidence"] == "high"


@pytest.mark.parametrize("bad", ["not json", "[1, 2]", json.dumps({"verdict": "definitely_hacked"})])
def test_parse_rejects_bad_answers(bad):
    with pytest.raises(TriageError):
        triage.parse_triage(bad)


def test_unknown_confidence_becomes_low():
    answer = json.loads(GOOD_ANSWER) | {"confidence": "100%"}
    assert triage.parse_triage(json.dumps(answer))["confidence"] == "low"


def test_bad_model_answer_becomes_needs_review(monkeypatch):
    monkeypatch.setattr(triage, "ask_ollama", lambda messages, model: "garbage")
    result = triage.triage_finding(FINDING, [], "test-model")
    assert result["verdict"] == "needs_review"


def test_triage_report_adds_triage_and_summary(monkeypatch):
    monkeypatch.setattr(triage, "ask_ollama", lambda messages, model: GOOD_ANSWER)
    report = triage.triage_report(make_report([dict(FINDING), dict(FINDING)]), "test-model")
    assert all(f["triage"]["verdict"] == "likely_true_positive" for f in report["nuclei"]["results"])
    assert report["triage_summary"] == {"model": "test-model", "findings": 2, "likely_true_positive": 2,
                                        "likely_false_positive": 0, "needs_review": 0}


def test_report_without_nuclei_results_is_rejected():
    with pytest.raises(TriageError):
        triage.triage_report({"nuclei": {"status": "error", "results": []}})


def test_ollama_down_stops_with_clear_error(monkeypatch):
    def refuse(*args, **kwargs):
        raise urllib.error.URLError("connection refused")
    monkeypatch.setattr(triage.urllib.request, "urlopen", refuse)
    with pytest.raises(TriageError, match="not reachable"):
        triage.triage_report(make_report([dict(FINDING)]), "test-model")


def test_ollama_url_is_local_only():
    assert triage.config.OLLAMA_URL.startswith("http://127.0.0.1:")

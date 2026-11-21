import pytest

from recon.targets import Target, TargetError, validate_target


@pytest.mark.parametrize("raw, host", [
    ("http://127.0.0.1:3001", "127.0.0.1"),
    ("http://127.0.0.1:3001/", "127.0.0.1"),
    ("http://localhost:3001", "localhost"),
    ("http://LOCALHOST:3001", "localhost"),  # hostnames are case-insensitive
])
def test_allowed_targets_are_accepted(raw, host):
    assert validate_target(raw) == Target(host=host, port=3001)


def test_scanner_url_uses_container_port_and_ipv4():
    target = validate_target("http://localhost:3001")
    assert target.url == "http://localhost:3001"
    assert target.scanner_url == "http://127.0.0.1:3000"


@pytest.mark.parametrize("raw", [
    # external hosts, domains and other private IPs
    "http://8.8.8.8:3001",
    "http://example.com:3001",
    "http://192.168.1.10:3001",
    "http://0.0.0.0:3001",
    # tricks that resolve to loopback but are not literally allowlisted
    "http://127.1:3001",
    "http://2130706433:3001",
    "http://[::1]:3001",
    "http://localhost.example.com:3001",
    "http://127.0.0.1.nip.io:3001",
    # allowed host, wrong or missing port
    "http://127.0.0.1:3000",
    "http://127.0.0.1:22",
    "http://127.0.0.1",
    "http://127.0.0.1:abc",
    "http://127.0.0.1:99999",
    # wrong scheme or no scheme
    "https://127.0.0.1:3001",
    "ftp://127.0.0.1:3001",
    "127.0.0.1:3001",
    "127.0.0.1",
    # extra URL parts
    "http://127.0.0.1:3001/admin",
    "http://127.0.0.1:3001/?q=1",
    "http://127.0.0.1:3001/#x",
    "http://user:pass@127.0.0.1:3001",
    "http://example.com@127.0.0.1:3001",
    # shell-injection style input and junk
    "http://127.0.0.1:3001; rm -rf /",
    "http://127.0.0.1:3001 && calc",
    " http://127.0.0.1:3001",
    "http://127.0.0.1:3001\n",
    "",
    "http://" + "a" * 200 + ":3001",
])
def test_invalid_targets_are_rejected(raw):
    with pytest.raises(TargetError):
        validate_target(raw)


def test_non_string_is_rejected():
    with pytest.raises(TargetError):
        validate_target(None)  # type: ignore[arg-type]

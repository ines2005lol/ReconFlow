"""Nmap tests use saved XML instead of running Nmap.

fixtures/nmap_juice_shop.xml is real output from scanning the lab (Nmap 7.98).
The small inline documents below cover cases the lab doesn't produce."""

from pathlib import Path

import pytest

from recon.runner import ScannerError, docker_scanner_command
from recon.scanners.nmap import build_nmap_args, parse_nmap_xml
from recon.targets import validate_target

FIXTURES = Path(__file__).parent / "fixtures"


def test_parses_real_juice_shop_scan():
    hosts = parse_nmap_xml((FIXTURES / "nmap_juice_shop.xml").read_text(encoding="utf-8"))

    assert len(hosts) == 1
    host = hosts[0]
    assert host["address"] == "127.0.0.1"
    assert host["status"] == "up"
    assert host["ports"] == [{
        "port": 3000,
        "protocol": "tcp",
        "state": "open",
        "reason": "syn-ack",
        "service": "ppp",
        "product": None,
        "version": None,
        "extra_info": None,
        "detection_method": "table",
        "unrecognized": True,
    }]


def test_parses_identified_service_and_closed_port():
    xml = """<?xml version="1.0"?>
    <nmaprun scanner="nmap">
      <host>
        <status state="up"/>
        <address addr="127.0.0.1" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack"/>
            <service name="http" product="nginx" version="1.25.3" method="probed" conf="10"/>
          </port>
          <port protocol="tcp" portid="22">
            <state state="closed" reason="conn-refused"/>
          </port>
        </ports>
      </host>
    </nmaprun>"""
    ports = parse_nmap_xml(xml)[0]["ports"]

    assert ports[0]["service"] == "http"
    assert ports[0]["product"] == "nginx"
    assert ports[0]["version"] == "1.25.3"
    assert ports[0]["detection_method"] == "probed"
    assert ports[0]["unrecognized"] is False
    # A port without <service> must not crash the parser.
    assert ports[1]["state"] == "closed"
    assert ports[1]["service"] is None


def test_no_hosts_returns_empty_list():
    assert parse_nmap_xml('<nmaprun scanner="nmap"></nmaprun>') == []


@pytest.mark.parametrize("bad_output, message", [
    ("", "no output"),
    ("   \n", "no output"),
    ("<nmaprun><host>", "not valid XML"),
    ("Starting Nmap... something went wrong", "not valid XML"),
    ("<html></html>", "Unexpected Nmap XML root"),
    ('<nmaprun><host><ports><port portid="abc"/></ports></host></nmaprun>', "Malformed port"),
])
def test_bad_output_raises_scanner_error(bad_output, message):
    with pytest.raises(ScannerError, match=message):
        parse_nmap_xml(bad_output)


def test_command_targets_only_the_lab_port_inside_the_lab_network():
    target = validate_target("http://localhost:3001")
    cmd = docker_scanner_command("instrumentisto/nmap:7.98", build_nmap_args(target))

    assert cmd == [
        "docker", "run", "--rm",
        "--network", "container:recon-lab-juice-shop-1",
        "instrumentisto/nmap:7.98",
        "-sT", "-Pn", "-sV", "-p", "3000", "-oX", "-", "127.0.0.1",
    ]

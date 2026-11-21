"""Nmap: which port is open on the lab and what service/version answers there."""

import logging
import xml.etree.ElementTree as ET

from recon import config
from recon.runner import ScannerError, docker_scanner_command, run_command
from recon.targets import Target

logger = logging.getLogger(__name__)


def build_nmap_args(target: Target) -> list[str]:
    """Nmap arguments for one polite, single-port scan of the lab.

      -sT        TCP connect scan: a normal connection, no raw packets or root needed
      -Pn        skip host discovery (we already know the host is up)
      -sV        connect to the service and identify product/version
      -p <port>  scan only the lab port, nothing else on the host
      -oX -      write the report as XML to stdout, so Python can read it
    """
    return [
        "-sT", "-Pn", "-sV",
        "-p", str(target.scanner_port),
        "-oX", "-",
        target.scanner_host,
    ]


def run_nmap(target: Target) -> list[dict]:
    """Run Nmap against the validated target and return the parsed hosts."""
    args = docker_scanner_command(config.NMAP_IMAGE, build_nmap_args(target))
    logger.info("Running Nmap against %s", target.url)
    result = run_command(args, timeout=config.NMAP_TIMEOUT)
    return parse_nmap_xml(result.stdout)


def parse_nmap_xml(xml_text: str) -> list[dict]:
    """Turn Nmap's XML report into a list of hosts, each with its ports.

    Example result:
      [{"address": "127.0.0.1", "status": "up",
        "ports": [{"port": 3000, "protocol": "tcp", "state": "open",
                   "service": "ppp", "product": None, "version": None, ...}]}]
    """
    if not xml_text or not xml_text.strip():
        raise ScannerError("Nmap produced no output.")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ScannerError(f"Nmap output is not valid XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise ScannerError(f"Unexpected Nmap XML root element <{root.tag}>.")

    hosts = []
    for host in root.findall("host"):
        address = host.find("address")
        status = host.find("status")
        try:
            ports = [_parse_port(port) for port in host.findall("ports/port")]
        except ValueError as exc:  # e.g. portid="abc"
            raise ScannerError(f"Malformed port in Nmap XML: {exc}") from exc
        hosts.append({
            "address": address.get("addr") if address is not None else None,
            "status": status.get("state") if status is not None else None,
            "ports": ports,
        })

    if not hosts:
        logger.warning("Nmap finished but reported no hosts.")
    return hosts


def _parse_port(port: ET.Element) -> dict:
    # <state> and <service> are optional in Nmap's XML, so every lookup tolerates
    # a missing element instead of crashing on one odd port.
    state = port.find("state")
    service = port.find("service")

    def svc(attr: str) -> str | None:
        return service.get(attr) if service is not None else None

    return {
        "port": int(port.get("portid", 0)),
        "protocol": port.get("protocol"),
        "state": state.get("state") if state is not None else None,
        "reason": state.get("reason") if state is not None else None,
        "service": svc("name"),
        "product": svc("product"),
        "version": svc("version"),
        "extra_info": svc("extrainfo"),
        # "probed" = Nmap identified the service from its responses.
        # "table"  = just the default name for that port number (a guess).
        "detection_method": svc("method"),
        # Nmap got a response but no signature matched it; it then attaches a
        # raw fingerprint (servicefp). Useful to flag that "service" is unreliable.
        "unrecognized": service is not None and service.get("servicefp") is not None,
    }

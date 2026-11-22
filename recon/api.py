"""REST API in front of the scanners.

Start it (from the project folder):
    .\\.venv\\Scripts\\python.exe -m uvicorn recon.api:app --host 127.0.0.1 --port 8000

Then open http://127.0.0.1:8000/docs for the interactive Swagger UI.

Bind to 127.0.0.1 only: this API starts scans, so it must not be reachable from
other machines. There is no authentication because it never leaves localhost.
"""

import logging

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from recon.runner import ScannerError
from recon.scanners.httpx_probe import run_httpx
from recon.scanners.nmap import run_nmap
from recon.targets import Target, TargetError, validate_target

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(
    title="AI-Assisted Recon & Vulnerability Triage Tool",
    description="Scans the local OWASP Juice Shop lab only. Targets outside the allowlist are rejected.",
    version="0.1.0",
)


class ScanRequest(BaseModel):
    # The example is what Swagger pre-fills in the "Try it out" box.
    target: str = Field(examples=["http://127.0.0.1:3001"], description="Allowlisted lab URL")


@app.get("/health")
def health() -> dict:
    """Is the API process up? (Does not check the lab.)"""
    return {"status": "ok"}


def _validated(raw_target: str) -> Target:
    try:
        return validate_target(raw_target)
    except TargetError as exc:
        # 400: the client asked for something we refuse to do.
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _scanner_failed(name: str, exc: ScannerError) -> HTTPException:
    # 502: the request was fine, but a tool we depend on failed.
    logger.error("%s failed: %s", name, exc)
    return HTTPException(status_code=502, detail=f"{name} failed: {exc}")


# Plain `def` (not `async def`) on purpose: scans block for seconds while waiting on
# a subprocess. FastAPI runs plain-def endpoints in a worker thread, so one running
# scan doesn't freeze the whole server.
@app.post("/scans/nmap")
def scan_nmap(request: ScanRequest) -> dict:
    """Run an Nmap service scan against the lab and return the parsed results."""
    target = _validated(request.target)
    try:
        hosts = run_nmap(target)
    except ScannerError as exc:
        raise _scanner_failed("Nmap", exc) from exc
    return {"target": target.url, "scanner": "nmap", "hosts": hosts}


@app.post("/scans/httpx")
def scan_httpx(request: ScanRequest) -> dict:
    """Probe the lab with ProjectDiscovery httpx: reachability, status, title, technologies."""
    target = _validated(request.target)
    try:
        results = run_httpx(target)
    except ScannerError as exc:
        raise _scanner_failed("httpx", exc) from exc
    return {"target": target.url, "scanner": "httpx", "results": results}

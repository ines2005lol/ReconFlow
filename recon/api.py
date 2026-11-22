"""REST API in front of the scanners.

Start it (from the project folder):
    .\\.venv\\Scripts\\python.exe -m uvicorn recon.api:app --host 127.0.0.1 --port 8000

Then open http://127.0.0.1:8000/docs for the interactive Swagger UI.

Bind to 127.0.0.1 only: this API starts scans, so it must not be reachable from
other machines. There is no authentication because it never leaves localhost.
"""

import logging

from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from recon import config
from recon.lab import LabUnreachableError, check_lab
from recon.pipeline import run_pipeline
from recon.runner import ScannerError
from recon.scanners.httpx_probe import run_httpx
from recon.scanners.nmap import run_nmap
from recon.scanners.nuclei import run_nuclei
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


# include_in_schema=False keeps this helper route out of the Swagger page itself.
@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    """Opening http://127.0.0.1:8000/ sends the browser to the Swagger UI."""
    return RedirectResponse(url="/docs")


@app.get("/health")
def health() -> dict:
    """Status of the API and of the lab.

    Always HTTP 200 while the API runs; the body says whether the lab answers, so a
    green /health no longer hides a stopped Juice Shop.
    """
    try:
        check_lab(validate_target(config.DEFAULT_TARGET))
        lab = {"status": "ok", "detail": None}
    except LabUnreachableError as exc:
        lab = {"status": "unreachable", "detail": str(exc)}
    return {"api": "ok", "lab": lab}


def _ready_target(raw_target: str) -> Target:
    """Validate the target and make sure the lab answers, before any scanner starts."""
    try:
        target = validate_target(raw_target)
    except TargetError as exc:
        # 400: the client asked for something we refuse to do.
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        check_lab(target)
    except LabUnreachableError as exc:
        # 503: the service we need (the lab) is currently unavailable.
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return target


def _scanner_failed(name: str, exc: ScannerError) -> HTTPException:
    # 502: the request was fine, but a tool we depend on failed.
    logger.error("%s failed: %s", name, exc)
    return HTTPException(status_code=502, detail=f"{name} failed: {exc}")


# Plain `def` (not `async def`) on purpose: scans block for seconds while waiting on
# a subprocess. FastAPI runs plain-def endpoints in a worker thread, so one running
# scan doesn't freeze the whole server.
@app.post("/scans")
def scan_all(request: ScanRequest) -> dict:
    """Full pipeline: Nmap -> httpx -> Nuclei, combined into one report (about 2 minutes).

    A failing scanner doesn't fail the request: its section has status "error" and the
    report status is "partial".
    """
    try:
        return run_pipeline(request.target)
    except TargetError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LabUnreachableError as exc:
        # 503: the service we need (the lab) is currently unavailable.
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/scans/nmap")
def scan_nmap(request: ScanRequest) -> dict:
    """Run an Nmap service scan against the lab and return the parsed results."""
    target = _ready_target(request.target)
    try:
        hosts = run_nmap(target)
    except ScannerError as exc:
        raise _scanner_failed("Nmap", exc) from exc
    return {"target": target.url, "scanner": "nmap", "hosts": hosts}


@app.post("/scans/httpx")
def scan_httpx(request: ScanRequest) -> dict:
    """Probe the lab with ProjectDiscovery httpx: reachability, status, title, technologies."""
    target = _ready_target(request.target)
    try:
        results = run_httpx(target)
    except ScannerError as exc:
        raise _scanner_failed("httpx", exc) from exc
    return {"target": target.url, "scanner": "httpx", "results": results}


@app.post("/scans/nuclei")
def scan_nuclei(request: ScanRequest) -> dict:
    """Run a safe, web-only Nuclei scan of the lab (takes about 2 minutes)."""
    target = _ready_target(request.target)
    try:
        findings = run_nuclei(target)
    except ScannerError as exc:
        raise _scanner_failed("Nuclei", exc) from exc
    return {"target": target.url, "scanner": "nuclei", "count": len(findings), "findings": findings}

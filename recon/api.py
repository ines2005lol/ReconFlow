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
from recon.scanners.nmap import run_nmap
from recon.targets import TargetError, validate_target

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


# A plain `def` (not `async def`) on purpose: run_nmap() blocks for several seconds
# while it waits for the subprocess. FastAPI runs plain-def endpoints in a worker
# thread, so one running scan doesn't freeze the whole server.
@app.post("/scans/nmap")
def scan_nmap(request: ScanRequest) -> dict:
    """Run an Nmap service scan against the lab and return the parsed results."""
    try:
        target = validate_target(request.target)
    except TargetError as exc:
        # 400: the client asked for something we refuse to do.
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        hosts = run_nmap(target)
    except ScannerError as exc:
        # 502: our request was fine, but the tool we depend on failed.
        logger.error("Nmap failed: %s", exc)
        raise HTTPException(status_code=502, detail=f"Nmap failed: {exc}") from exc

    return {"target": target.url, "scanner": "nmap", "hosts": hosts}

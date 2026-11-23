# ReconFlow

**ReconFlow** is a Python reconnaissance pipeline that scans a local, intentionally vulnerable lab
([OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)) and turns raw scanner
output into structured JSON, exposed through a FastAPI REST API.

> ⚠️ **Authorized use only.** This tool is hard-restricted to a lab running on your own
> machine. It rejects every other host, and it must never be pointed at systems you
> do not own or have written permission to test.

## How it works

```
Swagger UI / curl
      │  POST /scans/nmap {"target": "http://127.0.0.1:3001"}
      ▼
FastAPI (127.0.0.1:8000)
      │
      ├─ validate_target()   allowlist check, rejects everything else (400)
      │
      ├─ run_command()       subprocess, argument list, timeout
      │     │
      │     ▼
      │   docker run --rm --network container:recon-lab-juice-shop-1 nmap ...
      │     │
      │     ▼  (inside the lab's network: 127.0.0.1:3000)
      │   OWASP Juice Shop container   ◀── also published to your PC on 127.0.0.1:3001
      │
      └─ parse_nmap_xml()    XML ──▶ JSON response
```

1. **Validate**: the target must be exactly an allowlisted lab URL (`http://127.0.0.1:3001`
   or `http://localhost:3001`). Anything else is rejected before any program starts.
2. **Scan**: each scanner runs in its own throwaway container (`docker run --rm`) attached
   to Juice Shop's network (`--network container:recon-lab-juice-shop-1`). Inside that
   network the lab is `127.0.0.1:3000`.
3. **Parse**: raw scanner output (XML / JSONL) is parsed into plain Python dicts.
4. **Serve**: FastAPI returns the result as JSON, with interactive docs at `/docs`.

Why run scanners in Docker? Windows Smart App Control blocks unsigned binaries such as
self-built Go tools. Running the scanners as pinned container images avoids that without
weakening Windows security, and makes the toolchain reproducible: Docker is the only
requirement.

## Tech stack

| Area | Technology |
|---|---|
| Language | Python 3.13 (standard library for subprocess, XML/JSON parsing, logging) |
| API | FastAPI + Uvicorn |
| Scanners | Nmap 7.98 (`instrumentisto/nmap`), ProjectDiscovery httpx v1.12.0 and Nuclei v3.11.1 |
| Lab | OWASP Juice Shop v17.3.0 in Docker Compose |
| Tests | pytest, using saved real scanner output (no live scans needed) |

## Security design

- **Strict target allowlist** ([recon/config.py](recon/config.py), [recon/targets.py](recon/targets.py)):
  exact host and port match, `http` only, no paths, queries, credentials or whitespace.
  Inputs that merely *resolve* to loopback (`127.1`, `2130706433`, `127.0.0.1.nip.io`) are
  rejected too. The allowlist can only be changed by editing code, not from the API.
- **No shell** ([recon/runner.py](recon/runner.py)): every external program is started with
  `subprocess.run([...])` and an argument list, never `shell=True`, so input can never
  become a second command. Every call has a timeout, and all failures become one
  `ScannerError` type.
- **Localhost-only exposure**: Juice Shop is published on `127.0.0.1:3001` and the API on
  `127.0.0.1:8000`, so neither is reachable from other devices on the network.
- **Polite scanning**: Nmap scans a single port with a TCP connect scan (`-sT -Pn -sV -p 3000`).
- **Safe Nuclei profile** ([recon/scanners/nuclei.py](recon/scanners/nuclei.py)): web templates
  only (`-type http`), `dos`/`intrusive`/`fuzz`/`bruteforce` tags excluded, interactsh
  disabled so the lab never calls out to public OAST servers, templates mounted read-only.
- **Pinned versions** for every image and Python dependency.

## Getting started (Windows / PowerShell)

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (running)
- Python 3.11+

You do **not** need to install Nmap, httpx or Nuclei: they run as containers.
Do not `pip install httpx` for this project; that is an unrelated Python HTTP library.

### 1. Clone and install

```powershell
git clone https://github.com/ines2005lol/recon.git
cd recon
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 2. Start the lab

```powershell
docker compose up -d
```

Wait 10–20 seconds, then open http://127.0.0.1:3001. You should see the Juice Shop store.

Download Nuclei's templates once (about 14,500 files, into a Docker volume):

```powershell
docker run --rm -v recon-nuclei-templates:/root/nuclei-templates projectdiscovery/nuclei:v3.11.1 -update-templates
```

### 3. Run the tests

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

### 4. Run the full pipeline from the command line

```powershell
.\.venv\Scripts\python.exe -m recon
```

This validates the target, checks the lab is up, runs Nmap → httpx → Nuclei (about 2
minutes) and saves a JSON report to `output\report_<time>.json`. Add `-v` to log the
exact commands, or `--output my_report.json` to choose the file.
Exit codes: `0` complete, `1` partial (a scanner failed), `2` target rejected, `3` lab down.

### 5. Start the API

```powershell
.\.venv\Scripts\python.exe -m uvicorn recon.api:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000/docs, expand **POST /scans/nmap**, click **Try it out**, then
**Execute**. The first scan downloads the Nmap image, so it takes a little longer.

Or from PowerShell:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/scans/nmap -ContentType 'application/json' -Body '{"target":"http://127.0.0.1:3001"}' | ConvertTo-Json -Depth 5
```

## API

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | API process is up |
| `POST` | `/scans` | **Full pipeline** (about 2 min): Nmap → httpx → Nuclei in one report. Body: `{"target": "http://127.0.0.1:3001"}` |
| `POST` | `/scans/nmap` | Nmap service scan only. Same body |
| `POST` | `/scans/httpx` | httpx probe: reachable, status code, title, detected technologies. Same body |
| `POST` | `/scans/nuclei` | Safe Nuclei scan (about 2 min): findings with severity, URL, description, references. Same body |

Status codes: `200` scan finished, `400` target not in the allowlist (no scan is run),
`422` malformed request body, `502` the scanner failed (for example Docker not running),
`503` the lab is not reachable (`/scans` only). On `/scans`, a single failing scanner does
not fail the request: its section has `"status": "error"` and the report is `"partial"`.

Example response:

```json
{
  "target": "http://127.0.0.1:3001",
  "scanner": "nmap",
  "hosts": [
    {
      "address": "127.0.0.1",
      "status": "up",
      "ports": [
        {
          "port": 3000,
          "protocol": "tcp",
          "state": "open",
          "reason": "syn-ack",
          "service": "ppp",
          "product": null,
          "version": null,
          "extra_info": null,
          "detection_method": "table",
          "unrecognized": true
        }
      ]
    }
  ]
}
```

`detection_method: "table"` and `unrecognized: true` mean Nmap received an HTTP response
but matched no signature, so `"ppp"` is only the default name for port 3000. The report
flags this instead of presenting a guess as a fact. Identifying the web stack is the job
of the httpx step.

## Watching the lab's logs

Juice Shop writes every HTTP request to an access log, mounted into `./lab-logs`:

```powershell
Get-Content .\lab-logs\access.log.* -Wait -Tail 10
```

Scanner traffic comes from `127.0.0.1` (it shares the lab's network), while your browser
shows up as Docker's gateway (`172.x.x.1`). An Nmap service scan leaves only one line,
its well-known `GET /nice ports,/Trinity.txt.bak` probe.

## Project structure

```
├─ docker-compose.yml        Juice Shop lab, bound to 127.0.0.1:3001
├─ requirements.txt          pinned Python dependencies
├─ recon/
│  ├─ config.py              allowlist, port mapping, images, timeouts
│  ├─ targets.py             target validation
│  ├─ runner.py              safe subprocess helper + docker run builder
│  ├─ lab.py                 checks the lab answers before scanning
│  ├─ pipeline.py            validate → lab check → Nmap → httpx → Nuclei → report
│  ├─ __main__.py            command line: python -m recon
│  ├─ api.py                 FastAPI app
│  └─ scanners/
│     ├─ nmap.py             run + parse Nmap XML
│     ├─ httpx_probe.py      run + parse httpx JSONL
│     └─ nuclei.py           run + parse Nuclei JSONL
└─ tests/
   ├─ fixtures/              real scanner output used by the tests
   └─ test_*.py
```

## Features

- Dockerized Juice Shop lab, localhost only
- Target allowlist and safe subprocess runner
- Nmap scan and XML parsing
- FastAPI endpoint with interactive docs
- ProjectDiscovery httpx: status, title, technologies
- Nuclei: template ID, name, severity, matched URL, references (no intrusive/DoS templates)
- One command for the full pipeline: Nmap → httpx → Nuclei → JSON report

## Stopping the lab

```powershell
docker compose down
```

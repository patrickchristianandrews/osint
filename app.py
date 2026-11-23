"""Sherlock Web: a local-first browser UI for the official Sherlock Project CLI."""
from __future__ import annotations

import csv
import importlib.metadata
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field, field_validator

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("SHERLOCK_DATA_DIR", ROOT / "data"))
SCAN_DIR = DATA_DIR / "scans"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.?{}][A-Za-z0-9_.?{}-]{0,63}$")
SITE_RE = re.compile(r"^[A-Za-z0-9 _.'+&()!-]{1,90}$")
MAX_ACTIVE = int(os.environ.get("SHERLOCK_MAX_ACTIVE", "2"))
MAX_JOBS = 50
AUTH_TOKEN = os.environ.get("SHERLOCK_WEB_TOKEN", "")

app = FastAPI(title="Sherlock Web", description="Web interface for the official Sherlock OSINT engine", version="1.0.0")
# Permit the public Random Candy Land frontend to access the separately hosted API.
# Override SHERLOCK_WEB_CORS_ORIGINS if deploying with another trusted origin.
CORS_ORIGINS = [origin.strip() for origin in os.environ.get(
    "SHERLOCK_WEB_CORS_ORIGINS",
    "https://randomcandyland.com,https://www.randomcandyland.com",
).split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "X-Sherlock-Token"],
)
JOBS: dict[str, "ScanJob"] = {}
JOBS_LOCK = threading.RLock()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def engine_command() -> list[str] | None:
    """Prefer package in same Python environment, optionally allow pipx executable."""
    custom = os.environ.get("SHERLOCK_EXECUTABLE", "").strip()
    if custom:
        resolved = shutil.which(custom)
        return [resolved] if resolved else None
    if importlib.util.find_spec("sherlock_project") is None:
        return None
    return [sys.executable, "-u", "-m", "sherlock_project"]


def engine_version() -> str | None:
    try:
        return importlib.metadata.version("sherlock-project")
    except importlib.metadata.PackageNotFoundError:
        return None


CATALOG_CACHE_TTL = 600
CATALOG_CACHE: dict = {}
CATALOG_LOCK = threading.RLock()

def get_catalog() -> dict:
    """Follow Sherlock's current live catalog, not just the bundled snapshot."""
    now = time.monotonic()
    with CATALOG_LOCK:
        if CATALOG_CACHE and now - CATALOG_CACHE["fetched_at"] < CATALOG_CACHE_TTL:
            return CATALOG_CACHE
    # The upstream CLI uses these same two data sources.
    from importlib.resources import files
    bundled = json.loads(files("sherlock_project").joinpath("resources", "data.json").read_text(encoding="utf-8"))
    entries = {k: v for k, v in bundled.items() if not k.startswith("$") and isinstance(v, dict)}
    source = "bundled fallback"
    try:
        import requests
        response = requests.get("https://data.sherlockproject.xyz", timeout=8)
        response.raise_for_status()
        live = response.json()
        loaded = {k: v for k, v in live.items() if not k.startswith("$") and isinstance(v, dict)}
        if len(loaded) >= 100:
            entries, source = loaded, "official live catalog"
    except Exception:
        pass
    exclusions = set()
    try:
        import requests
        response = requests.get("https://raw.githubusercontent.com/sherlock-project/sherlock/refs/heads/exclusions/false_positive_exclusions.txt", timeout=5)
        response.raise_for_status()
        exclusions = {v.strip() for v in response.text.splitlines() if v.strip() and not v.startswith("#")}
    except Exception:
        pass
    result = {"entries": entries, "exclusions": exclusions, "source": source, "fetched_at": now}
    with CATALOG_LOCK:
        CATALOG_CACHE.clear()
        CATALOG_CACHE.update(result)
        return CATALOG_CACHE


def discover_sites(nsfw: bool = False, ignore_exclusions: bool = False) -> list[str]:
    data = get_catalog()
    return sorted((name for name, meta in data["entries"].items()
                   if (ignore_exclusions or name not in data["exclusions"])
                   and (nsfw or not meta.get("isNSFW", False))), key=str.casefold)


async def require_auth(x_sherlock_token: str | None = Header(default=None)) -> None:
    if AUTH_TOKEN and x_sherlock_token != AUTH_TOKEN:
        raise HTTPException(401, "Access token is required or incorrect.")


class ScanRequest(BaseModel):
    usernames: list[str] = Field(min_length=1, max_length=8)
    sites: list[str] = Field(default_factory=list, max_length=600)
    timeout: int = Field(default=30, ge=5, le=120)
    nsfw: bool = False
    local: bool = False
    ignore_exclusions: bool = False

    @field_validator("usernames")
    @classmethod
    def validate_usernames(cls, value: list[str]) -> list[str]:
        cleaned = [item.strip() for item in value]
        if not all(USERNAME_RE.fullmatch(name) for name in cleaned):
            raise ValueError("Use 1–64 characters: letters, numbers, _, -, ., or Sherlock {?} wildcard.")
        if len(set(cleaned)) != len(cleaned):
            raise ValueError("Duplicate usernames are not allowed.")
        return cleaned

    @field_validator("sites")
    @classmethod
    def validate_sites(cls, value: list[str]) -> list[str]:
        cleaned = [item.strip() for item in value if item.strip()]
        if not all(SITE_RE.fullmatch(site) for site in cleaned):
            raise ValueError("Invalid site name. Use names from the official Sherlock catalog.")
        if len(set(cleaned)) != len(cleaned):
            raise ValueError("Duplicate site names are not allowed.")
        return cleaned


@dataclass
class ScanJob:
    id: str
    request: ScanRequest
    folder: Path
    created_at: str = field(default_factory=utc_now)
    started_at: str | None = None
    finished_at: str | None = None
    status: Literal["queued", "running", "completed", "failed", "cancelled"] = "queued"
    error: str | None = None
    log: deque = field(default_factory=lambda: deque(maxlen=160))
    results: list[dict] = field(default_factory=list)
    process: subprocess.Popen | None = None
    cancelled: bool = False
    events_seen: int = 0
    current_username: str = ""
    target_sites: int | None = None
    lock: threading.RLock = field(default_factory=threading.RLock)

    def snapshot(self) -> dict:
        with self.lock:
            found = sum(row["status"] == "found" for row in self.results)
            not_found = sum(row["status"] == "not_found" for row in self.results)
            unknown = sum(row["status"] not in {"found", "not_found"} for row in self.results)
            return {
                "id": self.id, "status": self.status,
                "usernames": self.request.usernames, "sites": self.request.sites,
                "created_at": self.created_at, "started_at": self.started_at,
                "finished_at": self.finished_at, "error": self.error,
                "log": list(self.log), "results": list(self.results), "events_seen": self.events_seen,
                "current_username": self.current_username,
                "summary": {"found": found, "not_found": not_found,
                            "unknown": unknown, "checked": len(self.results),
                            "target_sites": self.target_sites},
            }


def normalize_status(raw: str) -> str:
    raw = str(raw).strip().casefold()
    if raw in {"claimed", "found", "true", "querystatus.claimed"}:
        return "found"
    if raw in {"available", "not_found", "not found", "false", "querystatus.available"}:
        return "not_found"
    if raw in {"waf", "querystatus.waf"}:
        return "waf"
    if raw in {"illegal", "querystatus.illegal"}:
        return "illegal"
    return "unknown"


def parse_csv_results(folder: Path) -> list[dict]:
    rows = []
    for path in sorted(folder.glob("*.csv")):
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            for item in csv.DictReader(handle):
                site = item.get("name", "").strip()
                username = item.get("username", "").strip()
                if not site or not username:
                    continue
                rows.append({
                    "username": username,
                    "site": site,
                    "url": item.get("url_user", "").strip(),
                    "homepage": item.get("url_main", "").strip(),
                    "status": normalize_status(item.get("exists", "")),
                    "raw_status": item.get("exists", "").strip(),
                    "http_status": item.get("http_status", "").strip(),
                    "response_time": item.get("response_time_s", "").strip(),
                })
    return rows


def record_cli_event(job: ScanJob, line: str) -> None:
    """Record partial Sherlock results even before its CSV files exist."""
    started = re.match(r"^\[\*\] Checking username (.+?) on:", line)
    if started:
        with job.lock:
            job.current_username = started.group(1)
        return
    event = re.match(r"^\[([+-])\](?: \[\d+ms\])? (.+?): (.*)$", line)
    if not event:
        return
    symbol, site, detail = event.groups()
    with job.lock:
        username = job.current_username
    if not site or not username:
        return
    status = ("found" if symbol == "+" else
              "not_found" if detail.startswith("Not Found!") else
              "waf" if "Blocked by bot detection" in detail else
              "illegal" if "Illegal Username Format" in detail else "unknown")
    row = {"username": username, "site": site, "url": detail if status == "found" else "",
           "homepage": "", "status": status,
           "raw_status": {"found": "Claimed", "not_found": "Available", "waf": "WAF", "illegal": "Illegal", "unknown": "Unknown"}[status],
           "http_status": "", "response_time": "", "reason": detail}
    with job.lock:
        index = next((i for i, value in enumerate(job.results)
                      if (value["username"], value["site"]) == (username, site)), None)
        if index is not None:
            job.results[index] = row
        else:
            job.results.append(row)
        job.events_seen += 1


def run_scan(job: ScanJob) -> None:
    with job.lock:
        if job.cancelled:
            job.status = "cancelled"
            job.finished_at = utc_now()
            return
        job.status = "running"
        job.started_at = utc_now()
        job.log.append("Starting official Sherlock engine…")

    prefix = engine_command()
    if not prefix:
        with job.lock:
            job.status = "failed"
            job.error = "The Sherlock engine is missing. Install dependencies with: pip install -r requirements.txt"
            job.finished_at = utc_now()
        return
    try:
        job.target_sites = len(job.request.sites) if job.request.sites else len(discover_sites(nsfw=job.request.nsfw, ignore_exclusions=job.request.ignore_exclusions))
    except Exception:
        job.target_sites = None
    job.folder.mkdir(parents=True, exist_ok=True)
    cmd = prefix + ["--no-color", "--print-all", "--csv", "--xlsx", "--txt",
                    "--folderoutput", str(job.folder), "--timeout", str(job.request.timeout)]
    for site in job.request.sites:
        cmd.extend(["--site", site])
    if job.request.nsfw:
        cmd.append("--nsfw")
    if job.request.local:
        cmd.append("--local")
    if job.request.ignore_exclusions:
        cmd.append("--ignore-exclusions")
    cmd.extend(job.request.usernames)

    try:
        proc = subprocess.Popen(
            cmd, cwd=str(job.folder), stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
            bufsize=1, env={**os.environ, "PYTHONUNBUFFERED": "1", "NO_COLOR": "1"},
        )
        with job.lock:
            job.process = proc
            if job.cancelled:
                proc.terminate()
        assert proc.stdout is not None
        with proc.stdout:
            for line in proc.stdout:
                value = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
                if value:
                    with job.lock:
                        job.log.append(value[:600])
                    record_cli_event(job, value)
        code = proc.wait()
        with job.lock:
            final_rows = parse_csv_results(job.folder)
            if final_rows:
                reasons = {(r["username"], r["site"]): r.get("reason", "") for r in job.results}
                for row in final_rows:
                    row["reason"] = reasons.get((row["username"], row["site"]), "")
                job.results = final_rows
            if job.cancelled:
                job.status = "cancelled"
                job.error = "Scan stopped by user."
            elif code != 0:
                job.status = "failed"
                job.error = f"Sherlock exited with code {code}. Check activity log for details."
            elif not list(job.folder.glob("*.csv")):
                job.status = "failed"
                job.error = "Sherlock finished without a CSV report. Check activity log."
            else:
                job.status = "completed"
            job.finished_at = utc_now()
            job.process = None
    except Exception as exc:
        with job.lock:
            job.status = "cancelled" if job.cancelled else "failed"
            job.error = "Scan stopped." if job.cancelled else f"Unable to run Sherlock: {exc}"
            job.finished_at = utc_now()
            job.process = None


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/")
def homepage():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/assets/style.css")
def css():
    return FileResponse(ROOT / "static" / "style.css", media_type="text/css")


@app.get("/assets/app.js")
def js():
    return FileResponse(ROOT / "static" / "app.js", media_type="application/javascript")


@app.get("/api/meta")
def meta():
    try:
        default_count = len(discover_sites())
        all_count = len(discover_sites(nsfw=True, ignore_exclusions=True))
        data = get_catalog()
        catalog = {"site_count": default_count, "catalog_count": all_count,
                   "nsfw_count": sum(bool(v.get("isNSFW")) for v in data["entries"].values()),
                   "excluded_count": sum(v in data["entries"] for v in data["exclusions"]),
                   "catalog_source": data["source"]}
    except Exception:
        catalog = {"site_count": None, "catalog_count": None, "catalog_source": "unavailable"}
    return {"engine_ready": bool(engine_command()), "engine_version": engine_version(),
            "auth_required": bool(AUTH_TOKEN), "max_usernames": 8, "max_active": MAX_ACTIVE, **catalog}


@app.get("/api/sites", dependencies=[Depends(require_auth)])
def sites():
    data = get_catalog()
    all_sites = discover_sites(nsfw=True, ignore_exclusions=True)
    return {"sites": all_sites,
            "default_count": len(discover_sites()),
            "catalog_count": len(all_sites),
            "excluded": sorted(data["exclusions"].intersection(data["entries"])),
            "nsfw": sorted(name for name, val in data["entries"].items() if val.get("isNSFW")),
            "source": data["source"]}


@app.post("/api/scans", status_code=202, dependencies=[Depends(require_auth)])
def start_scan(request: ScanRequest):
    if not engine_command():
        raise HTTPException(status_code=503, detail="Sherlock engine not installed. Run: pip install -r requirements.txt")
    with JOBS_LOCK:
        active = sum(job.status in ("queued", "running") for job in JOBS.values())
        if active >= MAX_ACTIVE:
            raise HTTPException(429, f"At most {MAX_ACTIVE} active scans. Stop or finish an existing scan first.")
        if len(JOBS) >= MAX_JOBS:
            finished = [job for job in JOBS.values() if job.status not in ("queued", "running")]
            if not finished:
                raise HTTPException(429, "Too many active scans.")
            oldest = min(finished, key=lambda x: x.created_at)
            JOBS.pop(oldest.id, None)
        job_id = uuid.uuid4().hex
        job = ScanJob(job_id, request, SCAN_DIR / job_id)
        JOBS[job.id] = job
        threading.Thread(target=run_scan, args=(job,), daemon=True, name=f"sherlock-{job.id[:8]}").start()
    return {"id": job.id, "status": job.status}


def get_job(job_id: str) -> ScanJob:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "Scan not found. Past scans are kept only while the server is running.")
    return job


@app.get("/api/scans", dependencies=[Depends(require_auth)])
def scan_history():
    with JOBS_LOCK:
        jobs = sorted(JOBS.values(), key=lambda job: job.created_at, reverse=True)
    return [{k: v for k, v in job.snapshot().items() if k not in ("results", "log")} for job in jobs]


@app.get("/api/scans/{job_id}", dependencies=[Depends(require_auth)])
def scan_details(job_id: str):
    return get_job(job_id).snapshot()


@app.delete("/api/scans/{job_id}", dependencies=[Depends(require_auth)])
def stop_scan(job_id: str):
    job = get_job(job_id)
    with job.lock:
        if job.status not in ("running", "queued"):
            return {"status": job.status}
        job.cancelled = True
        if job.process is not None and job.process.poll() is None:
            job.process.terminate()
        if job.status == "queued":
            job.status = "cancelled"
            job.finished_at = utc_now()
    return {"status": "cancelling"}


def safe_cell(value: str) -> str:
    """Prevent spreadsheet formula injection when re-exporting usernames/site names."""
    return "'" + value if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else value


@app.get("/api/scans/{job_id}/export/{format}", dependencies=[Depends(require_auth)])
def export_scan(job_id: str, format: Literal["json", "csv", "txt", "xlsx"]):
    job = get_job(job_id)
    if job.status != "completed":
        raise HTTPException(409, "Export available after a completed scan.")
    data = job.snapshot()["results"]
    name = f"sherlock-{job.id[:8]}"
    if format == "json":
        output = json.dumps({"usernames": job.request.usernames, "generated_at": utc_now(), "results": data}, indent=2)
        return Response(output, media_type="application/json", headers={"Content-Disposition": f'attachment; filename="{name}.json"'})
    if format == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["username", "site", "url", "homepage", "status", "raw_status", "http_status", "response_time"])
        writer.writeheader()
        for item in data:
            writer.writerow({key: safe_cell(str(item.get(key, ""))) for key in writer.fieldnames})
        return Response(output.getvalue(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{name}.csv"'})
    if format == "txt":
        output = "\n".join(f'{item["username"]} | {item["site"]} | {item["url"]}' for item in data if item["status"] == "found")
        return Response(output + "\n", media_type="text/plain; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{name}.txt"'})
    files = list(job.folder.glob("*.xlsx"))
    if len(files) == 1 and len(job.request.usernames) == 1:
        return FileResponse(files[0], media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", filename=files[0].name)
    # For multiple usernames, combine all Sherlock CSV records in one usable workbook.
    # The upstream XLSX uses formulas; reading those with data_only=True would lose links.
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Alignment, Font, PatternFill
        wb = Workbook()
        ws = wb.active
        ws.title = "Sherlock Results"
        headers = ["Username", "Platform", "Profile URL", "Site URL", "Status", "Raw status", "HTTP status", "Response time (s)"]
        ws.append(headers)
        for item in data:
            ws.append([safe_cell(str(item.get(k, ""))) for k in (
                "username", "site", "url", "homepage", "status", "raw_status", "http_status", "response_time")])
            for col in (3, 4):
                cell = ws.cell(ws.max_row, col)
                if cell.value.startswith(("https://", "http://")):
                    cell.hyperlink = cell.value
                    cell.font = Font(color="0563C1", underline="single")
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = ws.dimensions
        for cell in ws[1]:
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill("solid", fgColor="203D33")
        for col, width in {"A":24,"B":27,"C":53,"D":39,"E":18,"F":18,"G":16,"H":19}.items():
            ws.column_dimensions[col].width = width
        stream = io.BytesIO()
        wb.save(stream)
        return StreamingResponse(io.BytesIO(stream.getvalue()), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers={"Content-Disposition": f'attachment; filename="{name}.xlsx"'})
    except ImportError:
        raise HTTPException(501, "Install openpyxl for XLSX downloads, or use CSV.")



@app.get("/health")
def health():
    return {"status": "ok", "engine_ready": bool(engine_command())}

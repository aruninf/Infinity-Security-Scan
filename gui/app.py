"""Local web GUI for nuclei (Enhanced FastAPI backend with process control & job history).

Run:
    pip install -r requirements.txt
    python app.py            # -> http://127.0.0.1:9057
    # optional: NUCLEI_BIN=/path/to/nuclei python app.py
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from postman_to_openapi import convert as postman_convert

REPO_ROOT = Path(__file__).resolve().parent.parent
JOBS_DIR = Path(__file__).resolve().parent / "jobs"
JOBS_DIR.mkdir(exist_ok=True)

INPUT_MODES = ["auto", "list", "openapi", "swagger", "http", "burp", "yaml", "jsonl", "postman"]
DOWNLOADABLE = {"findings.txt", "results.json", "report.sarif", "report.pdf", "run.log", "input.used"}

jobs: dict[str, dict] = {}
lock = threading.Lock()


def find_nuclei() -> str | None:
    env = os.environ.get("NUCLEI_BIN")
    if env and Path(env).exists():
        return env
    for cand in (REPO_ROOT / "bin" / "nuclei", REPO_ROOT / "bin" / "nuclei.exe"):
        if cand.exists():
            return str(cand)
    return shutil.which("nuclei")


def detect_mode(filename: str, content: bytes) -> str:
    sample = content[:500_000].decode("utf-8", "ignore").lower()
    name = filename.lower()
    try:
        doc = json.loads(content[:500_000] or b"{}")
    except Exception:
        doc = None
    if isinstance(doc, dict):
        if "info" in doc and "item" in doc:
            return "postman"
        if isinstance(doc.get("openapi"), str) and "paths" in doc:
            return "openapi"
        if "swagger" in doc and "paths" in doc:
            return "swagger"
    if "openapi" in sample and ("paths" in sample or "servers" in sample):
        return "openapi"
    if '"swagger"' in sample or "swagger: " in sample:
        return "swagger"
    if name.endswith((".yaml", ".yml")) and ("openapi" in sample or "swagger" in sample):
        return "openapi" if "openapi" in sample else "swagger"
    if "<request" in sample and "burp" in sample:
        return "burp"
    if "###" in sample and "http/1." in sample:
        return "http"
    return "list"


def parse_results_file(path: Path) -> list[dict]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    text = path.read_text(encoding="utf-8", errors="ignore").strip()
    if not text:
        return []
    if text.startswith("["):
        try:
            data = json.loads(text)
            return data if isinstance(data, list) else [data]
        except Exception:
            pass
    out = []
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if not line or line in "[]":
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def sanitize_spec(spec: dict, default_server: str | None = None) -> int:
    fixed = 0

    def visit(node):
        nonlocal fixed
        if isinstance(node, dict):
            for key, val in list(node.items()):
                if (key == "schema" and isinstance(val, dict)
                        and isinstance(val.get("examples"), dict)):
                    ex = val.pop("examples")
                    if "examples" not in node:
                        node["examples"] = ex
                    fixed += 1
                else:
                    visit(val)
        elif isinstance(node, list):
            for v in node:
                visit(v)

    visit(spec)
    if not spec.get("servers") and default_server:
        spec["servers"] = [{"url": default_server}]
        fixed += 1
    return fixed


def fetch_spec_url(url: str) -> tuple[bytes, str]:
    import urllib.request

    req = urllib.request.Request(
        url,
        headers={"Accept": "application/json, */*", "User-Agent": "nuclei-gui/2.0"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        content = resp.read(10 * 1024 * 1024)
    name = url.rstrip("/").rsplit("/", 1)[-1] or "spec.json"
    if "." not in name:
        name += ".json"
    return content, name


def run_scan(job_id: str, cmd: list[str]) -> None:
    job = jobs[job_id]
    log_path = job["dir"] / "run.log"
    try:
        with open(log_path, "w") as log:
            log.write(f"$ {' '.join(shlex.quote(c) for c in cmd)}\n\n")
            log.flush()
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=str(job["dir"]),
            )
            job["proc"] = proc
            for line in proc.stdout or []:
                log.write(line)
                log.flush()
            proc.wait()
            job["returncode"] = proc.returncode
            if job.get("status") != "stopped":
                job["status"] = "done" if proc.returncode == 0 else "failed"
            job["finished"] = time.time()
    except Exception as e:
        with open(log_path, "a") as log:
            log.write(f"\n[gui error] {e}\n")
        job["status"] = "failed"
        job["error"] = str(e)
        job["finished"] = time.time()


def get_job_summary(job_id: str) -> dict:
    job = jobs.get(job_id)
    job_dir = JOBS_DIR / job_id
    if not job_dir.exists():
        raise HTTPException(404, "job directory not found")

    if job:
        status = job["status"]
        effective_mode = job.get("effective_mode", "unknown")
        filename = job.get("filename", "")
        started = job.get("started", job_dir.stat().st_mtime)
        finished = job.get("finished")
        returncode = job.get("returncode")
        error = job.get("error")
        spec_fixes = job.get("spec_fixes", 0)
    else:
        # Reconstruct from disk
        started = job_dir.stat().st_mtime
        finished = None
        log_path = job_dir / "run.log"
        results_path = job_dir / "results.json"
        status = "unknown"
        effective_mode = "unknown"
        filename = ""
        returncode = None
        error = None
        spec_fixes = 0

        if log_path.exists():
            log_text = log_path.read_text(encoding="utf-8", errors="ignore")
            first_line = log_text.splitlines()[0] if log_text.splitlines() else ""
            m = re.search(r"-im\s+([a-zA-Z0-9]+)", first_line)
            if m:
                effective_mode = m.group(1)
            if "Scan completed" in log_text or results_path.exists():
                status = "done"
            elif "[ERR]" in log_text or "[FTL]" in log_text:
                status = "failed"

        inp_path = job_dir / "input.used"
        if inp_path.exists():
            first_inp = inp_path.read_text(encoding="utf-8", errors="ignore").strip().splitlines()
            if first_inp:
                filename = first_inp[0][:80]

    findings = parse_results_file(job_dir / "results.json")
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in findings:
        sev = (item.get("info", {}).get("severity") or "info").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
        else:
            sev_counts["info"] += 1

    return {
        "id": job_id,
        "status": status,
        "effective_mode": effective_mode,
        "filename": filename,
        "started": started,
        "finished": finished,
        "duration": (finished - started) if (started and finished) else None,
        "returncode": returncode,
        "error": error,
        "spec_fixes": spec_fixes,
        "findings_count": len(findings),
        "severities": sev_counts,
    }


app = FastAPI(title="nuclei Modern GUI")
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")


@app.get("/", response_class=HTMLResponse)
def index():
    return (Path(__file__).parent / "static" / "index.html").read_text()


@app.get("/api/nuclei-status")
def nuclei_status():
    bin_path = find_nuclei()
    if not bin_path:
        return {"ok": False, "hint": "nuclei binary not found — run `make build` in the repo root first."}
    try:
        r = subprocess.run([bin_path, "-version"], capture_output=True, text=True, timeout=10)
        out = (r.stdout or r.stderr).strip()
        version = "v3"
        for line in out.splitlines():
            line_str = line.strip()
            if "Nuclei Engine Version:" in line_str:
                version = line_str.split(":", 1)[1].strip()
                break
            if line_str.startswith("v3.") or line_str.startswith("v2."):
                version = line_str
                break
        return {"ok": True, "binary": bin_path, "version": version, "full": out}
    except Exception as e:
        return {"ok": False, "binary": bin_path, "hint": str(e)}


@app.get("/api/jobs")
def list_jobs():
    out = []
    if not JOBS_DIR.exists():
        return out
    for p in sorted(JOBS_DIR.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        if p.is_dir():
            try:
                out.append(get_job_summary(p.name))
            except Exception:
                continue
    return out


@app.post("/api/scan")
async def start_scan(
    input_file: UploadFile | None = File(default=None),
    pasted_targets: str = Form(default=""),
    input_mode: str = Form(default="auto"),
    dast: bool = Form(default=True),
    skip_format_validation: bool = Form(default=True),
    concurrency: int = Form(default=25),
    rate_limit: int = Form(default=150),
    templates: str = Form(default=""),
    tags: str = Form(default=""),
    severity: str = Form(default=""),
    headers: str = Form(default=""),
    vars: str = Form(default=""),
):
    if input_mode not in INPUT_MODES:
        raise HTTPException(400, f"input_mode must be one of {INPUT_MODES}")
    if input_file is None and not pasted_targets.strip():
        raise HTTPException(400, "Please upload a file or enter target URLs / spec endpoints")

    bin_path = find_nuclei()
    if not bin_path:
        raise HTTPException(500, "nuclei binary not found — run `make build` in the repo root first.")

    job_id = uuid.uuid4().hex[:10]
    job_dir = JOBS_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    (job_dir / "md").mkdir(parents=True, exist_ok=True)

    raw = await input_file.read() if input_file else b""
    filename = input_file.filename if input_file else "targets.txt"
    pasted = pasted_targets.strip()

    fetched_from_url: str | None = None
    if not raw and pasted and len(pasted.splitlines()) == 1 and pasted.lower().startswith(("http://", "https://")):
        try:
            raw, filename = fetch_spec_url(pasted)
            fetched_from_url = pasted
            pasted = ""
        except Exception:
            pass

    mode = input_mode
    if mode == "auto":
        if pasted and not raw:
            mode = "list"
        else:
            mode = detect_mode(filename, raw)

    sanitized = 0
    if pasted and not raw:
        (job_dir / "input.used").write_text(pasted + "\n")
        effective_mode = "list"
    elif mode == "postman":
        try:
            collection = json.loads(raw.decode("utf-8"))
        except Exception:
            raise HTTPException(400, "Postman file is not valid JSON")
        spec = postman_convert(collection)
        if not spec.get("paths"):
            raise HTTPException(400, "No convertible requests found in Postman collection")
        (job_dir / "input.used").write_text(json.dumps(spec, indent=2))
        effective_mode = "openapi"
    elif mode in ("openapi", "swagger"):
        try:
            spec = json.loads(raw.decode("utf-8"))
            base = None
            if fetched_from_url:
                from urllib.parse import urlparse
                p = urlparse(fetched_from_url)
                base = f"{p.scheme}://{p.hostname}" + (f":{p.port}" if p.port else "")
            sanitized = sanitize_spec(spec, default_server=base)
            if not spec.get("servers"):
                raise HTTPException(
                    400,
                    "OpenAPI spec defines no `servers` — provide target server or include `servers` in the specification",
                )
            (job_dir / "input.used").write_text(json.dumps(spec))
        except HTTPException:
            raise
        except Exception:
            (job_dir / "input.used").write_bytes(raw)
        effective_mode = mode
    else:
        (job_dir / "input.used").write_bytes(raw)
        effective_mode = mode

    cmd = [
        bin_path,
        "-l",
        str(job_dir / "input.used"),
        "-im",
        effective_mode,
        "-nc",
        "-o",
        str(job_dir / "findings.txt"),
        "-je",
        str(job_dir / "results.json"),
        "-se",
        str(job_dir / "report.sarif"),
        "-pe",
        str(job_dir / "report.pdf"),
        "-me",
        str(job_dir / "md"),
    ]

    # Always use skip-format-validation for openapi/swagger unless explicitly turned off
    if skip_format_validation or effective_mode in ("openapi", "swagger"):
        cmd.append("-sfv")

    if dast:
        cmd.append("-dast")

    if concurrency and concurrency > 0:
        cmd += ["-c", str(concurrency)]

    if rate_limit and rate_limit > 0:
        cmd += ["-rl", str(rate_limit)]

    if templates.strip():
        cmd += ["-t", templates.strip()]

    if tags.strip():
        cmd += ["-tags", tags.strip()]

    if severity.strip():
        cmd += ["-severity", severity.strip()]

    for line in headers.splitlines():
        line = line.strip()
        if line and ":" in line:
            cmd += ["-H", line]

    for line in vars.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip()
        if not key or not all(c.isalnum() or c in "_.-" for c in key):
            raise HTTPException(400, f"Invalid variable line: {line[:60]}")
        cmd += ["-V", line]

    with lock:
        jobs[job_id] = {
            "id": job_id,
            "dir": job_dir,
            "status": "running",
            "cmd": cmd,
            "started": time.time(),
            "finished": None,
            "proc": None,
            "requested_mode": input_mode,
            "effective_mode": effective_mode,
            "filename": filename or (pasted.splitlines()[0][:60] if pasted else ""),
            "returncode": None,
            "error": None,
            "fetched_from_url": fetched_from_url,
            "spec_fixes": sanitized if effective_mode in ("openapi", "swagger") else 0,
        }

    threading.Thread(target=run_scan, args=(job_id, cmd), daemon=True).start()
    return {
        "job_id": job_id,
        "effective_mode": effective_mode,
        "fetched_from_url": fetched_from_url,
        "spec_fixes": jobs[job_id]["spec_fixes"],
    }


@app.get("/api/jobs/{job_id}")
def job_status(job_id: str):
    return get_job_summary(job_id)


@app.post("/api/jobs/{job_id}/stop")
def stop_job(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "unknown job")
    proc = job.get("proc")
    if proc and proc.poll() is None:
        try:
            proc.terminate()
            time.sleep(0.3)
            if proc.poll() is None:
                proc.kill()
            job["status"] = "stopped"
            job["finished"] = time.time()
            return {"ok": True, "message": "Scan process stopped"}
        except Exception as e:
            raise HTTPException(500, f"Failed to stop process: {e}")
    return {"ok": True, "message": "Job is not running"}


@app.delete("/api/jobs/{job_id}")
def delete_job(job_id: str):
    job = jobs.get(job_id)
    if job and job.get("proc") and job["proc"].poll() is None:
        try:
            job["proc"].kill()
        except Exception:
            pass
    target = JOBS_DIR / job_id
    if target.exists() and target.is_dir():
        shutil.rmtree(target, ignore_errors=True)
    with lock:
        if job_id in jobs:
            del jobs[job_id]
    return {"ok": True}


@app.post("/api/jobs/clear")
def clear_all_jobs():
    cleared = 0
    for p in list(JOBS_DIR.iterdir()):
        if p.is_dir():
            jid = p.name
            if jid in jobs and jobs[jid].get("status") == "running":
                continue
            shutil.rmtree(p, ignore_errors=True)
            with lock:
                if jid in jobs:
                    del jobs[jid]
            cleared += 1
    return {"ok": True, "cleared": cleared}


@app.get("/api/jobs/{job_id}/log")
def job_log(job_id: str, offset: int = 0):
    job = jobs.get(job_id)
    job_dir = JOBS_DIR / job_id
    log_path = job_dir / "run.log"
    status = job["status"] if job else ("done" if (job_dir / "results.json").exists() else "unknown")

    if not log_path.exists():
        return {"status": status, "log": "", "offset": 0}

    data = log_path.read_bytes()
    chunk = data[offset:offset + 200_000].decode("utf-8", "ignore")
    return {"status": status, "log": chunk, "offset": len(data)}


@app.get("/api/jobs/{job_id}/results")
def job_results(job_id: str):
    job = jobs.get(job_id)
    job_dir = JOBS_DIR / job_id
    status = job["status"] if job else "done"
    return {"status": status, "results": parse_results_file(job_dir / "results.json")}


@app.get("/api/jobs/{job_id}/download")
def job_download(job_id: str, file: str):
    job_dir = JOBS_DIR / job_id
    if not job_dir.exists():
        raise HTTPException(404, "job not found")

    if file.startswith("md/"):
        target = job_dir / file
        if not str(target.resolve()).startswith(str(job_dir.resolve())):
            raise HTTPException(400, "invalid path")
    elif file in DOWNLOADABLE:
        target = job_dir / file
    else:
        raise HTTPException(400, f"downloadable files: {sorted(DOWNLOADABLE)} + md/<file>")

    if not target.exists():
        raise HTTPException(404, "file not generated yet")
    return FileResponse(target, filename=target.name)


@app.get("/api/jobs/{job_id}/files")
def job_files(job_id: str):
    job_dir = JOBS_DIR / job_id
    if not job_dir.exists():
        raise HTTPException(404, "job not found")

    files = [p.name for p in job_dir.iterdir() if p.is_file() and p.name != "input.used"]
    md_dir = job_dir / "md"
    if md_dir.exists():
        files += [f"md/{p.name}" for p in md_dir.iterdir() if p.is_file()]

    job = jobs.get(job_id)
    status = job["status"] if job else "done"
    return {"status": status, "files": sorted(files)}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=9057)

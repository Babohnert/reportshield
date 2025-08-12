# app.py — ReportShield API (FastAPI, v6.9.1) — adds /diag
import os, re, requests, json
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import PlainTextResponse, Response
from pydantic import BaseModel, HttpUrl
from engine import run_audit

MAX_MB = int(os.getenv("MAX_MB", "25"))

app = FastAPI(title="ReportShield Compliance Audit API", version="6.9.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://reportshield.ai",
        "https://www.reportshield.ai",
    ],
    allow_origin_regex=(
        r"^https://([a-zA-Z0-9-]+\.)*(wixsite|editorx)\.com$"
        r"|^https://([a-zA-Z0-9-]+\.)*(wixstatic|wixmp|wixcdn)\.com$"
        r"|^https://video\.wixstatic\.com$"
        r"|^https://files\.usr\.files\.wixcdn\.net$"
        r"|^https://editor\.wix\.com$"
        r"|^https://create\.wix\.com$"
    ),
    allow_methods=["GET", "POST", "OPTIONS", "HEAD"],
    allow_headers=["*"],
)

def _text(body: str, status: int = 200) -> Response:
    return PlainTextResponse(body, status_code=status, headers={
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    })

@app.get("/", response_class=PlainTextResponse)
async def root():
    return "ReportShield Compliance Audit API"

@app.get("/health", response_class=PlainTextResponse)
async def health():
    return "ok"

@app.get("/version", response_class=PlainTextResponse)
async def version():
    return "engine=v6.9.1; rules=v2.9; schematic=v6.6"

# quick diagnostics (no secrets)
@app.get("/diag", response_class=PlainTextResponse)
async def diag():
    seen_openai = bool(os.getenv("OPENAI_API_KEY") or os.getenv("OPEN_API_KEY"))
    seen_azure = bool(os.getenv("AZURE_FORMRECOGNIZER_ENDPOINT") and os.getenv("AZURE_FORMRECOGNIZER_KEY"))
    from pathlib import Path
    sysdir = Path(__file__).parent / "system"
    files = sorted([p.name for p in sysdir.glob("*")])
    msg = {
        "OPENAI_KEY_present": seen_openai,
        "AZURE_creds_present": seen_azure,
        "system_dir": str(sysdir),
        "system_files": files
    }
    return _text(json.dumps(msg, indent=2))

class UrlIn(BaseModel):
    url: HttpUrl
    name: str | None = None

ALLOWED_MEDIA = re.compile(
    r"^https://(?:(?:static|video)\.wixstatic\.com/.*|files\.usr\.files\.wixcdn\.net/.*|.*\.wixstatic\.com/.*|.*\.wixcdn\.com/.*)$",
    re.IGNORECASE,
)

@app.post("/audit", response_class=PlainTextResponse)
async def audit(file: UploadFile = File(...)):
    data = await file.read()
    return _text(run_audit(data))

@app.post("/audit-by-url", response_class=PlainTextResponse)
async def audit_by_url(payload: UrlIn):
    url = str(payload.url)
    if not ALLOWED_MEDIA.match(url):
        return _text("Invalid URL. Only Wix-hosted media URLs are permitted.", status=400)
    try:
        with requests.get(url, stream=True, timeout=30) as r:
            r.raise_for_status()
            chunks, total = [], 0
            cap = MAX_MB * 1024 * 1024
            for chunk in r.iter_content(chunk_size=65536):
                if not chunk: continue
                chunks.append(chunk); total += len(chunk)
                if total > cap:
                    return _text(run_audit(b""))  # engine will format error
            data = b"".join(chunks)
    except Exception:
        return _text("Download failed from Wix media. Please retry the upload.", status=502)
    return _text(run_audit(data))

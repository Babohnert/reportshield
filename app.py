# app.py — ReportShield API (FastAPI, v6.9.2) — aligned with engine v6.9.2
import os, re, requests, json
from pathlib import Path
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import PlainTextResponse, Response
from pydantic import BaseModel, HttpUrl
from engine import run_audit, SCHEMATIC_VERSION_REQUIRED, RULES_VERSION_REQUIRED, MAX_MODEL_CHARS

MAX_MB = int(os.getenv("MAX_MB", "25"))
WIX_FETCH_TIMEOUT = int(os.getenv("WIX_FETCH_TIMEOUT", "30"))

app = FastAPI(title="ReportShield Compliance Audit API", version="6.9.2")

# CORS: site + Wix surfaces/CDNs
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
    return f"engine=v6.9.2; rules={RULES_VERSION_REQUIRED}; schematic={SCHEMATIC_VERSION_REQUIRED}"

@app.get("/limits", response_class=PlainTextResponse)
async def limits():
    return f"MAX_MB={MAX_MB}, MAX_MODEL_CHARS={MAX_MODEL_CHARS}, WIX_FETCH_TIMEOUT={WIX_FETCH_TIMEOUT}"

# quick diagnostics (no secrets)
@app.get("/diag", response_class=PlainTextResponse)
async def diag():
    seen_openai = bool(os.getenv("OPENAI_API_KEY") or os.getenv("OPEN_API_KEY"))
    seen_azure = bool(os.getenv("AZURE_FORMRECOGNIZER_ENDPOINT") and os.getenv("AZURE_FORMRECOGNIZER_KEY"))
    sysdir = Path(__file__).parent / "system"
    files = sorted([p.name for p in sysdir.glob("*")])
    msg = {
        "OPENAI_KEY_present": seen_openai,
        "AZURE_creds_present": seen_azure,
        "system_dir": str(sysdir),
        "system_files": files,
        "MAX_MB": MAX_MB,
        "MAX_MODEL_CHARS": MAX_MODEL_CHARS,
        "WIX_FETCH_TIMEOUT": WIX_FETCH_TIMEOUT,
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
    # Optional pre-check to avoid large in-memory read when size is available
    try:
        if getattr(file, "size", None) and file.size > MAX_MB * 1024 * 1024:
            return _text(run_audit(b""))  # engine emits formatted size error
    except Exception:
        pass
    data = await file.read()
    return _text(run_audit(data))

@app.post("/audit-by-url", response_class=PlainTextResponse)
async def audit_by_url(payload: UrlIn):
    url = str(payload.url)
    if not ALLOWED_MEDIA.match(url):
        return _text("Invalid URL. Only Wix-hosted media URLs are permitted.", status=400)
    try:
        with requests.get(url, stream=True, timeout=WIX_FETCH_TIMEOUT) as r:
            r.raise_for_status()
            chunks, total = [], 0
            cap = MAX_MB * 1024 * 1024
            for chunk in r.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total > cap:
                    return _text(run_audit(b""))  # engine will format 'file too large'
            data = b"".join(chunks)
    except Exception:
        return _text("Download failed from Wix media. Please retry the upload.", status=502)
    return _text(run_audit(data))

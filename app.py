# app.py — FastAPI for ReportShield (Render-ready)
import os, re, requests
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import PlainTextResponse
from pydantic import BaseModel, HttpUrl
from engine import run_audit  # v6.6 engine entrypoint

MAX_MB = int(os.getenv("MAX_MB", "25"))
MAX_DOWNLOAD_MB = MAX_MB  # keep same cap for remote fetch

app = FastAPI(title="ReportShield API")

# CORS: explicit origins + regex to cover Wix preview/editor/CDNs
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://reportshield.ai",
        "https://www.reportshield.ai",
        # add your live site domain here if you have one
    ],
    allow_origin_regex=(
        r"^https://([a-zA-Z0-9-]+\.)*(wixsite|editorx)\.com$"
        r"|^https://([a-zA-Z0-9-]+\.)*(wixstatic|wixmp)\.com$"
        r"|^https://editor\.wix\.com$"
        r"|^https://create\.wix\.com$"
    ),
    allow_methods=["GET", "POST", "OPTIONS", "HEAD"],
    allow_headers=["*"],
)

@app.get("/", response_class=PlainTextResponse)
async def root():
    return "ReportShield Compliance Audit API"

@app.get("/health", response_class=PlainTextResponse)
async def health_get():
    return "ok"

@app.head("/health")
async def health_head():
    return PlainTextResponse("", status_code=200)

@app.get("/version", response_class=PlainTextResponse)
async def version():
    return "engine=v6.6; rules=v2.9"

@app.get("/limits", response_class=PlainTextResponse)
async def limits():
    return f"MAX_MB={MAX_MB}"

# Optional: debug
@app.post("/echo", response_class=PlainTextResponse)
async def echo(file: UploadFile = File(None)):
    if not file:
        return "received file=False"
    data = await file.read()
    return f"received file=True name={file.filename} size={len(data)}"

@app.post("/audit", response_class=PlainTextResponse)
async def audit(file: UploadFile = File(...)):
    try:
        data = await file.read()
        if not data or not data.startswith(b"%PDF"):
            raise HTTPException(status_code=400, detail="Please upload a PDF.")
        if len(data) > MAX_MB * 1024 * 1024:
            raise HTTPException(status_code=413, detail=f"File too large (>{MAX_MB} MB).")
        return run_audit(data)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audit failed: {e}")

# ---- New: audit-by-url (server fetches Wix media) ----
ALLOWED_MEDIA = re.compile(
    r"^https://static\.wixstatic\.com/.*|^https://video\.wixstatic\.com/.*|^https://files\.usr\.files\.wixcdn\.net/.*",
    re.IGNORECASE,
)

class UrlIn(BaseModel):
    url: HttpUrl
    name: str | None = None

@app.post("/audit-by-url", response_class=PlainTextResponse)
async def audit_by_url(payload: UrlIn):
    url = str(payload.url)
    if not ALLOWED_MEDIA.match(url):
        raise HTTPException(status_code=400, detail="URL not allowed")

    try:
        with requests.get(url, stream=True, timeout=30) as r:
            r.raise_for_status()
            # enforce size cap while streaming
            chunks = []
            total = 0
            for chunk in r.iter_content(chunk_size=1024 * 64):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_DOWNLOAD_MB * 1024 * 1024:
                    raise HTTPException(status_code=413, detail=f"Remote file too large (>{MAX_DOWNLOAD_MB} MB).")
            data = b"".join(chunks)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Download failed: {e}")

    if not data.startswith(b"%PDF"):
        raise HTTPException(status_code=400, detail="Remote file is not a PDF.")
    try:
        return run_audit(data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audit failed: {e}")

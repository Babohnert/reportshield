# app.py — ReportShield API (FastAPI, v6.9) — Azure → OpenAI → five-section text/plain
import os, re, requests
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import PlainTextResponse, Response
from pydantic import BaseModel, HttpUrl
from engine import run_audit

MAX_MB = int(os.getenv("MAX_MB", "25"))

app = FastAPI(title="ReportShield Compliance Audit API", version="6.9")

# CORS: your domains + Wix editors/CDNs. Add more origins if needed.
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
    return "engine=v6.9; rules=v2.9; schematic=v6.6"

@app.get("/limits", response_class=PlainTextResponse)
async def limits():
    return f"MAX_MB={MAX_MB}"

class UrlIn(BaseModel):
    url: HttpUrl
    name: str | None = None

# Accept Wix public CDNs
ALLOWED_MEDIA = re.compile(
    r"^https://(?:"
    r"(?:static|video)\.wixstatic\.com/.*|"
    r"(?:files\.usr\.files\.wixcdn\.net/.*)|"
    r"(?:.*\.wixstatic\.com/.*)|"
    r"(?:.*\.wixcdn\.com/.*)"
    r")$",
    re.IGNORECASE,
)

@app.post("/audit", response_class=PlainTextResponse)
async def audit(file: UploadFile = File(...)):
    data = await file.read()
    # run_audit ALWAYS returns five-section text (even on error)
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
                if not chunk: 
                    continue
                chunks.append(chunk); total += len(chunk)
                if total > cap:
                    # engine will produce 'file too large' structured text
                    return _text(run_audit(b""))
            data = b"".join(chunks)
    except Exception:
        return _text("Download failed from Wix media. Please retry the upload.", status=502)
    return _text(run_audit(data))

# app.py — ReportShield API (FastAPI, v6.7)
import os, re, requests
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import PlainTextResponse, Response
from pydantic import BaseModel, HttpUrl
from engine import run_audit  # five-section text always

MAX_MB = int(os.getenv("MAX_MB", "25"))

app = FastAPI(title="ReportShield Compliance Audit API", version="6.7")

# CORS: allow your production domains + Wix editors/CDNs
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://reportshield.ai",
        "https://www.reportshield.ai",
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

def _text_response(body: str, status: int = 200) -> Response:
    return PlainTextResponse(
        body,
        status_code=status,
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )

@app.get("/", response_class=PlainTextResponse)
async def root():
    return "ReportShield Compliance Audit API"

@app.get("/health", response_class=PlainTextResponse)
async def health_get():
    return "ok"

@app.get("/version", response_class=PlainTextResponse)
async def version():
    return "engine=v6.7; rules=v2.9; schematic=v6.6"

@app.get("/limits", response_class=PlainTextResponse)
async def limits():
    return f"MAX_MB={MAX_MB}"

# Direct upload from a browser (if you wire CORS for it)
@app.post("/audit", response_class=PlainTextResponse)
async def audit(file: UploadFile = File(...)):
    data = await file.read()
    if not data or not data.startswith(b"%PDF"):
        return _text_response(run_audit(data), status=200)  # engine will return error-structured text
    if len(data) > MAX_MB * 1024 * 1024:
        return _text_response(run_audit(data), status=200)
    out = run_audit(data)
    return _text_response(out, status=200)

# Server-side fetch for Wix uploads
ALLOWED_MEDIA = re.compile(
    r"^https://([a-z0-9-]+\.)?(wixstatic|wixcdn)\.com/.*",
    re.IGNORECASE,
)

class UrlIn(BaseModel):
    url: HttpUrl
    name: str | None = None

@app.post("/audit-by-url", response_class=PlainTextResponse)
async def audit_by_url(payload: UrlIn):
    url = str(payload.url)
    if not ALLOWED_MEDIA.match(url):
        return _text_response(
            "Invalid URL. Only Wix-hosted media URLs are permitted.",
            status=400,
        )

    try:
        with requests.get(url, stream=True, timeout=30) as r:
            r.raise_for_status()
            chunks = []
            total = 0
            cap = MAX_MB * 1024 * 1024
            for chunk in r.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total > cap:
                    return _text_response(run_audit(b""))  # engine returns 'file too large' structure
            data = b"".join(chunks)
    except Exception as e:
        return _text_response(
            "Download failed from Wix media. Please retry the upload.",
            status=502,
        )

    out = run_audit(data)
    return _text_response(out, status=200)

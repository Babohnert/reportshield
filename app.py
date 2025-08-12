# app.py — FastAPI for ReportShield (Render-ready)
import os
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import PlainTextResponse
from engine import run_audit  # v6.6 engine entrypoint

MAX_MB = int(os.getenv("MAX_MB", "25"))

app = FastAPI(title="ReportShield API")

# CORS: explicit origins + regex to cover Wix preview/editor/CDNs
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://reportshield.ai",
        "https://www.reportshield.ai",
        # If you have a custom live site domain, add it here too.
        # e.g., "https://yourbrand.com",
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

# Optional: debug endpoint to confirm multipart from Wix
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
        result = run_audit(data)  # returns plain text with emojis
        return result
    except HTTPException:
        raise
    except Exception as e:
        # Keep the error human-readable; the engine also formats errors if it raises
        raise HTTPException(status_code=500, detail=f"Audit failed: {e}")

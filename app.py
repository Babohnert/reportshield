import os
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import PlainTextResponse
from engine import run_audit  # v6.6 engine

MAX_MB = int(os.getenv("MAX_MB", "25"))

app = FastAPI()

# Allow your live Wix + site
allowed_origins = [
    "https://reportshield.ai",
    "https://www.reportshield.ai",   # harmless even if unused
    "https://*.wixsite.com",         # Wix preview
    "https://*.wixmp.com"            # Wix static CDN
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
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

@app.post("/audit", response_class=PlainTextResponse)
async def audit(file: UploadFile = File(...)):
    try:
        data = await file.read()
        if not data or not data.startswith(b"%PDF"):
            raise HTTPException(status_code=400, detail="Please upload a PDF.")
        if len(data) > MAX_MB * 1024 * 1024:
            raise HTTPException(status_code=413, detail=f"File too large (>{MAX_MB} MB).")
        result = run_audit(data)
        return result  # plain text (UTF-8) with emojis
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audit failed: {e}")

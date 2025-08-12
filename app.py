"""
app.py — Compliance Audit API (v6.6, with /audit and /audit_url)

Endpoints
- POST /audit      : multipart/form-data ({ file }) -> text/plain audit
- POST /audit_url  : JSON { url } -> text/plain audit (downloads PDF)
- GET  /health     : liveness
- GET  /ready      : readiness (Azure reachable + rules/schematic present)
- GET  /version    : versions only
- GET  /           : tiny banner (optional)

Notes
- Always return text/plain for /audit and /audit_url bodies (never JSON).
- Adds headers: X-Rules-Version, X-Schematic-Version, X-Output-Mode on success.
- No persistence; request-scoped processing.
- Simple per-IP rate limit (in-memory).
- Run with ASGI worker:
  gunicorn -k uvicorn.workers.UvicornWorker app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120
"""
from __future__ import annotations

import os
import time
import io
from typing import Dict

from fastapi import FastAPI, File, UploadFile, Response, HTTPException, Request, Body
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import PlainTextResponse, JSONResponse
from pypdf import PdfReader
import requests

# Engine (rule-locked logic)
from engine.__init__ import (
    run_audit,
    OUTPUT_RULES_PATH,
    SCHEMATIC_PATH,
    PUBLIC_MODE,
    MAX_MB,
    MAX_PAGES,
)

# -----------------------------
# App setup
# -----------------------------
app = FastAPI(title="Compliance Audit API", version="6.6")

# Optional CORS (configure origins via env, comma-separated)
CORS_ORIGINS = os.getenv("CORS_ALLOW_ORIGINS", "").split(",") if os.getenv("CORS_ALLOW_ORIGINS") else []
if CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in CORS_ORIGINS if o.strip()],
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Versions (kept in sync with engine)
RULES_VERSION = "v2.9"
SCHEMATIC_VERSION = "v6.6"

# Simple in-memory rate limiter (best-effort; reset every minute)
RATE_LIMIT_RPM = int(os.getenv("RATE_LIMIT_RPM", "60"))
_rate_bucket: Dict[str, Dict[str, int]] = {}


def _rate_limited(ip: str) -> bool:
    now_min = int(time.time() // 60)
    b = _rate_bucket.setdefault(ip, {"min": now_min, "count": 0})
    if b["min"] != now_min:
        b["min"] = now_min
        b["count"] = 0
    if b["count"] >= RATE_LIMIT_RPM:
        return True
    b["count"] += 1
    return False


def _short_fail(msg: str, status: int = 500) -> PlainTextResponse:
    return PlainTextResponse(f"Audit failed: {msg}", status_code=status, media_type="text/plain; charset=utf-8")


# -----------------------------
# Routes
# -----------------------------
@app.get("/")
async def root() -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "Compliance Audit API", "schematic": SCHEMATIC_VERSION})


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse({"status": "ok"})


@app.get("/ready")
async def ready() -> JSONResponse:
    rules_ok = os.path.exists(OUTPUT_RULES_PATH)
    schematic_ok = os.path.exists(SCHEMATIC_PATH)
    azure_ok = bool(os.getenv("AZURE_FORMRECOGNIZER_ENDPOINT") and os.getenv("AZURE_FORMRECOGNIZER_KEY"))
    status = "ready" if (rules_ok and schematic_ok and azure_ok) else "not_ready"
    return JSONResponse({
        "status": status,
        "rules": RULES_VERSION if rules_ok else None,
        "schematic": SCHEMATIC_VERSION if schematic_ok else None,
    })


@app.get("/version")
async def version() -> JSONResponse:
    return JSONResponse({"rules": RULES_VERSION, "schematic": SCHEMATIC_VERSION})


@app.post("/audit")
async def audit(request: Request, file: UploadFile = File(...)) -> Response:
    # Rate limit
    client_ip = request.client.host if request.client else "unknown"
    if _rate_limited(client_ip):
        return _short_fail("rate limit exceeded", status=429)

    # Content-type guard (best-effort)
    if (file.content_type or "").lower() not in {"application/pdf", "application/x-pdf", "binary/octet-stream"}:
        return _short_fail("unsupported file type", status=400)

    try:
        data = await file.read()
    except Exception:
        return _short_fail("could not read the uploaded file", status=400)

    # Basic size check
    size_mb = len(data) / (1024 * 1024)
    if size_mb > MAX_MB:
        return _short_fail("file too large", status=400)

    # Magic bytes
    if not data.startswith(b"%PDF"):
        return _short_fail("unsupported file type", status=400)

    # Page count + JS/embedded checks
    try:
        reader = PdfReader(io.BytesIO(data))
        num_pages = len(reader.pages)
        if num_pages > MAX_PAGES:
            return _short_fail("too many pages", status=400)
        catalog = reader.trailer.get("/Root", {})
        if "/Names" in catalog and getattr(catalog["/Names"], "get", lambda *_: None)("/JavaScript"):
            return _short_fail("PDF contains JavaScript", status=400)
        if "/Names" in catalog and getattr(catalog["/Names"], "get", lambda *_: None)("/EmbeddedFiles"):
            return _short_fail("PDF contains embedded files", status=400)
    except HTTPException:
        raise
    except Exception:
        # proceed; engine will attempt Azure and fail clearly if needed
        pass

    # Run engine (returns plain text)
    try:
        text = run_audit(data)
    except RuntimeError as e:
        msg = str(e)
        if not msg.startswith("Audit failed:"):
            msg = "Audit failed: processing error"
        return PlainTextResponse(msg, status_code=500, media_type="text/plain; charset=utf-8")
    except Exception:
        return _short_fail("processing error", status=500)

    headers = {
        "X-Rules-Version": RULES_VERSION,
        "X-Schematic-Version": SCHEMATIC_VERSION,
        "X-Output-Mode": "public" if PUBLIC_MODE else "private",
        "Content-Type": "text/plain; charset=utf-8",
    }
    return Response(content=text, media_type="text/plain; charset=utf-8", headers=headers)


@app.post("/audit_url")
async def audit_url(request: Request, payload: dict = Body(...)) -> Response:
    """Accepts JSON {"url": "https://...pdf"} and fetches the PDF, then runs the audit."""
    # Rate limit
    client_ip = request.client.host if request.client else "unknown"
    if _rate_limited(client_ip):
        return _short_fail("rate limit exceeded", status=429)

    url = (payload or {}).get("url")
    if not url:
        return _short_fail("missing 'url' in JSON body", status=400)

    try:
        r = requests.get(url, timeout=20)
    except Exception:
        return _short_fail("could not fetch the URL", status=400)

    if r.status_code != 200:
        return _short_fail("non-200 response from URL", status=400)

    data = r.content or b""
    if not data.startswith(b"%PDF"):
        return _short_fail("URL did not return a PDF", status=400)

    try:
        text = run_audit(data)
    except RuntimeError as e:
        msg = str(e)
        if not msg.startswith("Audit failed:"):
            msg = "Audit failed: processing error"
        return PlainTextResponse(msg, status_code=500, media_type="text/plain; charset=utf-8")
    except Exception:
        return _short_fail("processing error", status=500)

    headers = {
        "X-Rules-Version": RULES_VERSION,
        "X-Schematic-Version": SCHEMATIC_VERSION,
        "X-Output-Mode": "public" if PUBLIC_MODE else "private",
        "Content-Type": "text/plain; charset=utf-8",
    }
    return Response(content=text, media_type="text/plain; charset=utf-8", headers=headers)


# Optional: run locally with `python app.py`
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))

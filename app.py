import io
import os
import sys
import traceback
from typing import Optional

from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import requests

# Our analyzer
from engine import run_audit, ENGINE_VERSION

# ----------------------------
# App + CORS
# ----------------------------
app = Flask(__name__)
# Permissive CORS (Wix dev + prod). Lock down later if you want.
CORS(app, resources={r"/*": {"origins": "*"}})

# Limits / knobs
MAX_DOWNLOAD_MB = int(os.getenv("MAX_DOWNLOAD_MB", "25"))
REQUESTS_TIMEOUT = int(os.getenv("REQUESTS_TIMEOUT", "30"))

def _log(s: str):
    try:
        print(s, flush=True)
    except Exception:
        pass

# ----------------------------
# Helpers
# ----------------------------
def _download_bytes(url: str, max_mb: int) -> bytes:
    """
    Stream-download a file from URL into memory with a hard size cap.
    """
    if not url or not isinstance(url, str):
        raise ValueError("Missing or invalid 'url'.")

    _log(f"[DL] fetching: {url}")
    with requests.get(url, stream=True, timeout=REQUESTS_TIMEOUT, allow_redirects=True) as r:
        if r.status_code >= 400:
            raise RuntimeError(f"Download failed: HTTP {r.status_code}")
        total = 0
        buf = io.BytesIO()
        for chunk in r.iter_content(chunk_size=1024 * 256):
            if not chunk:
                continue
            buf.write(chunk)
            total += len(chunk)
            if total > max_mb * 1024 * 1024:
                raise RuntimeError(f"File exceeds {max_mb}MB limit.")
        return buf.getvalue()

def _safe_audit(file_like, style: Optional[str]) -> str:
    """
    Wrap run_audit to always return a clean text or raise an Exception.
    """
    try:
        return run_audit(file_like, style_override=style)
    except Exception as ex:
        # Surface concise error + log traceback
        tb = traceback.format_exc()
        _log(f"[AUDIT ERROR] {ex}\n{tb}")
        raise

# ----------------------------
# Routes
# ----------------------------
@app.get("/")
def root():
    return Response(
        f"ReportShield API OK (engine v{ENGINE_VERSION})\n",
        status=200,
        content_type="text/plain; charset=utf-8",
    )

@app.get("/health")
def health():
    return jsonify({
        "ok": True,
        "engine": ENGINE_VERSION,
        "message": "healthy"
    }), 200

@app.post("/audit")
def audit_upload():
    """
    Form-data upload: field name 'file'. Optional query param ?style=analyst|v27
    Returns plain text (so legacy Wix front-ends that do res.text() still work).
    On error: still 200 with 'ERROR: ...' text.
    """
    style = (request.args.get("style") or "").strip() or None
    try:
        if "file" not in request.files:
            return Response("ERROR: Missing 'file' in form-data.", status=200, content_type="text/plain; charset=utf-8")

        f = request.files["file"]  # werkzeug.FileStorage
        if not f or not getattr(f, "filename", ""):
            return Response("ERROR: Empty upload.", status=200, content_type="text/plain; charset=utf-8")

        # Let the engine read the stream directly
        report = _safe_audit(f, style)
        return Response(report or "", status=200, content_type="text/plain; charset=utf-8")

    except Exception as ex:
        return Response(f"ERROR: {ex}", status=200, content_type="text/plain; charset=utf-8")

@app.post("/audit_url")
def audit_by_url():
    """
    JSON body: { "url": "<https...>", "style": "analyst|v27" }
    Returns JSON: { ok: true, result: "..." } or { ok: false, error: "..." }
    Always HTTP 200 so Wix doesn't fail the fetch.
    """
    try:
        data = request.get_json(silent=True) or {}
        url = (data.get("url") or "").strip()
        style = (data.get("style") or "").strip() or None
        if not url:
            return jsonify({"ok": False, "error": "Missing 'url' in JSON body."}), 200

        raw = _download_bytes(url, MAX_DOWNLOAD_MB)
        # Use BytesIO so engine sees a file-like
        report = _safe_audit(io.BytesIO(raw), style)
        return jsonify({"ok": True, "result": report or ""}), 200

    except Exception as ex:
        return jsonify({"ok": False, "error": str(ex)}), 200

# ----------------------------
# Local dev entry
# ----------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    _log(f"Starting dev server on :{port}")
    app.run(host="0.0.0.0", port=port, debug=True)

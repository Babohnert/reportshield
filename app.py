# app.py
import io
import os
import re
import socket
import ipaddress
import urllib.parse as urlparse

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import requests

from engine import run_audit  # your engine/__init__.py public entry

# ----------------------------
# Config
# ----------------------------
def _split_env_list(val: str | None) -> list[str]:
    if not val:
        return []
    return [x.strip() for x in val.split(",") if x.strip()]

FRONTEND_ORIGINS = _split_env_list(os.getenv("FRONTEND_ORIGINS")) or [
    "https://*.wixsite.com",
    "https://*.editorx.io",
    "https://*.dev.wix-code.com",
    "https://*.wix.com",
    "https://reportshield.ai",
    "https://www.reportshield.ai",
    "https://reportshield.onrender.com",
]

# If you know exactly what Wix gives you, keep these narrow.
ALLOWED_DOWNLOAD_HOSTS = _split_env_list(os.getenv("ALLOWED_DOWNLOAD_HOSTS")) or [
    "wixstatic.com",
    "wixmp.com",
    "filesusr.com",
    "wixsite.com",
]

MAX_CONTENT_MB = float(os.getenv("MAX_CONTENT_MB", "12"))
MAX_CONTENT_LENGTH = int(MAX_CONTENT_MB * 1024 * 1024)

# Requests timeouts (connect, read)
TIMEOUTS = (int(os.getenv("HTTP_CONNECT_TIMEOUT", "6")),
            int(os.getenv("HTTP_READ_TIMEOUT", "20")))

USER_AGENT = os.getenv("HTTP_USER_AGENT", "ReportShield/1.0 (+render)")

# ----------------------------
# App / CORS
# ----------------------------
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

CORS(
    app,
    origins=FRONTEND_ORIGINS,
    supports_credentials=False,
    methods=["POST", "OPTIONS", "GET"],
    allow_headers=["Content-Type", "Authorization"],
)

# ----------------------------
# Helpers
# ----------------------------
def _json_error(message: str, code: int = 400, req_id: str | None = None):
    resp = jsonify({"ok": False, "error": message, "req": req_id})
    return make_response(resp, code)

def _mk_req_id() -> str:
    try:
        import secrets
        return secrets.token_hex(4)
    except Exception:
        return "req"

def _host_in_allowlist(hostname: str) -> bool:
    hostname = hostname.lower()
    for allowed in ALLOWED_DOWNLOAD_HOSTS:
        allowed = allowed.lower()
        if hostname == allowed or hostname.endswith("." + allowed):
            return True
    return False

def _is_private_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
        )
    except Exception:
        return True  # be safe

def _resolve_and_check(hostname: str) -> None:
    # Resolve hostname; block private/loopback/etc.
    try:
        infos = socket.getaddrinfo(hostname, None)
    except Exception as e:
        raise ValueError(f"Could not resolve host: {hostname} ({e})")
    ips = set()
    for fam, _stype, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        ips.add(ip)
    for ip in ips:
        if _is_private_ip(ip):
            raise ValueError(f"Blocked private IP: {ip}")

def _filename_from_url(u: str) -> str:
    path = urlparse.urlparse(u).path
    base = os.path.basename(path) or "upload.pdf"
    # Ensure a .pdf suffix if none
    if not re.search(r"\.pdf(\b|$)", base, re.IGNORECASE):
        base += ".pdf"
    return base

def _download_url_to_bytes(u: str, max_bytes: int) -> bytes:
    # Scheme & host checks
    parsed = urlparse.urlparse(u)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http/https URLs are allowed.")
    if not parsed.netloc:
        raise ValueError("URL must include a host.")
    host = parsed.hostname or ""
    if not _host_in_allowlist(host):
        # If not on allowlist, try DNS safety check
        _resolve_and_check(host)

    headers = {"User-Agent": USER_AGENT}

    # Try HEAD for content-length first (not all servers provide it)
    try:
        h = requests.head(u, timeout=TIMEOUTS, allow_redirects=True, headers=headers)
        if h.status_code >= 400:
            raise ValueError(f"HEAD failed: {h.status_code}")
        cl = h.headers.get("Content-Length")
        if cl:
            if int(cl) > max_bytes:
                raise ValueError("Remote file is larger than allowed limit.")
    except Exception:
        # HEAD might be blocked; continue with GET streaming
        pass

    r = requests.get(u, stream=True, timeout=TIMEOUTS, headers=headers)
    if r.status_code >= 400:
        raise ValueError(f"GET failed: {r.status_code}")

    ctype = (r.headers.get("Content-Type") or "").lower()
    if ("pdf" not in ctype) and ("application/octet-stream" not in ctype):
        # Some Wix links are octet-stream; allow that.
        # Still protect from images/HTML, etc.
        if not u.lower().endswith(".pdf"):
            raise ValueError(f"Unexpected content-type: {ctype}")

    buf = io.BytesIO()
    read_total = 0
    for chunk in r.iter_content(8192):
        if not chunk:
            continue
        buf.write(chunk)
        read_total += len(chunk)
        if read_total > max_bytes:
            raise ValueError("Downloaded file exceeded size limit.")
    return buf.getvalue()

class NamedBytesIO(io.BytesIO):
    """BytesIO with a .filename attribute so engine can surface a file name."""
    def __init__(self, data: bytes, filename: str = "upload.pdf"):
        super().__init__(data)
        self.filename = filename

# ----------------------------
# Routes
# ----------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True})

@app.get("/version")
def version():
    # Import lazily to read engine constants without hard coupling
    from engine import ENGINE_VERSION
    return jsonify({"ok": True, "engine": ENGINE_VERSION})

@app.post("/audit")
def audit_upload():
    """
    Multipart form upload: field name 'file'.
    Returns: text/plain (the report body).
    """
    req_id = _mk_req_id()
    file = request.files.get("file")
    if not file:
        return _json_error("Missing 'file' in multipart form-data.", 400, req_id)
    style = (request.args.get("style") or request.form.get("style") or "analyst").strip().lower()

    # Basic type/size hints (Flask enforces MAX_CONTENT_LENGTH already)
    ctype = (file.content_type or "").lower()
    if ("pdf" not in ctype) and ("application/octet-stream" not in ctype):
        # Let engine still try, but nudge the hint
        pass

    try:
        result = run_audit(file, style_override=style)
        resp = make_response(result, 200)
        resp.mimetype = "text/plain; charset=utf-8"
        resp.headers["X-Request-Id"] = req_id
        return resp
    except Exception as e:
        return _json_error(f"Processing failed: {e}", 422, req_id)

@app.post("/audit_url")
def audit_url():
    """
    JSON body: { "url": "https://...", "style": "analyst|v27|va" }
    Downloads the URL server-side with SSRF guards, then runs the audit.
    Returns JSON: { ok: true, result: "<report>" }
    """
    req_id = _mk_req_id()
    try:
        data = request.get_json(force=True, silent=False)
    except Exception:
        return _json_error("Invalid JSON.", 400, req_id)

    if not isinstance(data, dict):
        return _json_error("JSON body must be an object.", 400, req_id)

    url = (data.get("url") or "").strip()
    style = (data.get("style") or "analyst").strip().lower()
    if not url:
        return _json_error("Missing 'url' in body.", 400, req_id)

    try:
        raw = _download_url_to_bytes(url, MAX_CONTENT_LENGTH)
    except Exception as e:
        return _json_error(f"Download blocked/failed: {e}", 400, req_id)

    try:
        named = NamedBytesIO(raw, filename=_filename_from_url(url))
        report = run_audit(named, style_override=style)
        return make_response(jsonify({"ok": True, "result": report, "req": req_id}), 200)
    except Exception as e:
        return _json_error(f"Processing failed: {e}", 422, req_id)

# Optional: a minimal index for sanity (kept 404 to match your logs previously)
@app.get("/")
def index():
    return make_response("ReportShield API", 200)

# ----------------------------
# Local run
# ----------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)

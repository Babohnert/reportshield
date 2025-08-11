from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from dotenv import load_dotenv
import os, io, requests

# Load .env if present
load_dotenv()

from engine import run_audit  # still just this

app = Flask(__name__)
CORS(app)  # during testing this is fine; lock down origins later

# Optional: cap upload size to avoid huge files
app.config['MAX_CONTENT_LENGTH'] = 12 * 1024 * 1024  # 12MB

@app.errorhandler(413)
def too_large(e):
    return Response("File too large (max 12MB). Try a smaller PDF.", status=413, mimetype="text/plain")

@app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200

@app.post("/audit")
def audit():
    if "file" not in request.files:
        return Response("No file uploaded.", status=400, mimetype="text/plain")

    up = request.files["file"]
    if not up or up.filename == "":
        return Response("Empty file.", status=400, mimetype="text/plain")

    # Optional: style override ?style=analyst or ?style=v27
    style = request.args.get("style")

    try:
        result_text = run_audit(up, style_override=style)
        return Response(result_text, status=200, mimetype="text/plain")
    except Exception as e:
        msg = str(e)
        if "Encrypted" in msg:
            return Response("PDF is password-protected. Remove the password and try again.", status=400, mimetype="text/plain")
        return Response(f"Audit failed: {msg}", status=500, mimetype="text/plain")

# NEW: Wix-friendly endpoint that accepts a URL (from Wix Upload Button)
@app.post("/audit_url")
def audit_url():
    try:
        payload = request.get_json(force=True, silent=False) or {}
        url = (payload.get("url") or "").strip()
        style = (payload.get("style") or "").strip() or None
        if not url:
            return jsonify({"error": "Missing 'url'"}), 400

        # Download file bytes with a guard
        r = requests.get(url, stream=True, timeout=25)
        r.raise_for_status()

        max_len = 20 * 1024 * 1024  # 20MB guard before handing to engine (engine compresses if needed)
        buf = io.BytesIO()
        total = 0
        for chunk in r.iter_content(chunk_size=8192):
            if not chunk:
                continue
            total += len(chunk)
            if total > max_len:
                return jsonify({"error": "File too large"}), 413
            buf.write(chunk)
        buf.seek(0)
        # give the buffer a filename for nicer downstream handling
        buf.filename = os.path.basename(url.split("?")[0]) or "upload.pdf"

        result_text = run_audit(buf, style_override=style)
        return jsonify({"result": result_text})
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Fetch failed: {e}"}), 502
    except Exception as e:
        msg = str(e)
        if "Encrypted" in msg:
            return jsonify({"error": "PDF is password-protected. Remove the password and try again."}), 400
        return jsonify({"error": f"Audit failed: {msg}"}), 500

if __name__ == "__main__":
    # HTTPS strongly recommended for Wix (use a proper domain or a tunnel with TLS)
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)

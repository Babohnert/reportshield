# ReportShield Compliance Audit API (v6.7)

A minimal, rule-locked FastAPI service that ingests appraisal PDFs, runs Azure Document Intelligence
(prebuilt-document) extraction, evaluates compliance checks, and returns a five-section **plain-text** audit.
Errors also return the same five-section structure (no JSON).

## Endpoints
- `GET /health` → "ok"
- `POST /audit` → multipart upload (`file`) — returns **text/plain**
- `POST /audit-by-url` → `{ "url": "<Wix media URL>", "name": "report.pdf" }` — returns **text/plain**

## Required files (server-side)
Place these in `/system` (filenames are fixed):
- `SYSTEM EXECUTION SCHEMATIC – Compliance Audit (v6.6).txt`
- `OUTPUT RULES – Compliance Audit (v2.9).txt`
- Optional: `state-hooks.json`, `fair-housing.json`

## Environment
Set these on Render (example values shown for clarity only):
- `AZURE_FORMRECOGNIZER_ENDPOINT=https://<subdomain>.cognitiveservices.azure.com/`
- `AZURE_FORMRECOGNIZER_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`
- `PUBLIC_MODE=true`
- `MAX_MB=25`
- `AZURE_MODEL=prebuilt-document`
- `AZURE_FALLBACK_PDF_TEXT=true`
- (Build hint) `PIP_PREFER_BINARY=1`

## Deploy on Render
- **Start command** (also in `Procfile`):
  ```
  web: gunicorn -k uvicorn.workers.UvicornWorker -w 2 -t 120 app:app --bind 0.0.0.0:$PORT
  ```
- Health check: `GET /health`.

## Wix (Velo) snippet
See `wix/velo-snippet.js`. Update `API_BASE` to your service URL (Render URL or custom domain).

## Notes
- Output is always **text/plain** five-section format — even on error.
- The API never stores PDFs; it processes bytes in-memory per request.
- CORS is configured for your domain and Wix editors/CDNs only.

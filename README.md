# Compliance Audit API (Final)

A minimal, rule-locked API that analyzes appraisal PDFs with Azure Document Intelligence and produces a five-section, plain-text compliance audit suitable for Wix or any frontend.

## 1) Quick Start (Local)

```bash
python -m venv .venv
# Windows
.\.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt

# Create .env in project root with:
# AZURE_FORMRECOGNIZER_ENDPOINT=https://<your-subdomain>.cognitiveservices.azure.com/
# AZURE_FORMRECOGNIZER_KEY=<your-key>
# (OPENAI_API_KEY is optional)

python app.py
```

Test in a separate terminal:

```bash
curl -X POST "http://127.0.0.1:5000/audit" -F "file=@/path/to/YourSample.pdf"
```

You should receive a five-section plain-text response.

## 2) Environment Variables

- `AZURE_FORMRECOGNIZER_ENDPOINT` – required
- `AZURE_FORMRECOGNIZER_KEY` – required
- `OPENAI_API_KEY` – optional (not used by the current rules engine)
- `PORT` – optional (defaults to 5000)

## 3) Deploy (Render example)

- Add `Procfile` and `runtime.txt` (already included).
- Use `web: waitress-serve --port=$PORT app:app` as the start command.
- Set environment variables in Render dashboard.
- Health check: `GET /health`.

## 4) Notes

- The API does not persist uploads; files are read in-memory per request.
- Output follows `OUTPUT RULES – Compliance Audit (v2.7)` exactly.
- Execution flow per `SYSTEM EXECUTION SCHEMATIC – Compliance Audit (v5.9)`.
- To add additional checks, extend `check_flags()` in `engine/__init__.py`.

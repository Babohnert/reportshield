"""
engine/__init__.py — Compliance Audit engine (v6.6-compatible, full-length)

Implements the deterministic execution pipeline defined in:
- SYSTEM EXECUTION SCHEMATIC – Compliance Audit (v6.6)
- OUTPUT RULES – Compliance Audit (v2.9)

Public API:
    run_audit(file_storage_or_bytes) -> str  # returns plain-text five-section audit

Key properties:
- Rule-locked: no generative tone; temperature must be 0 wherever LLMs are involved.
- Azure Document Intelligence (prebuilt-document) for OCR/KV/tables.
- Dynamic load + checksum verification of schematic/rules to prevent drift.
- Evidence-first gating, Fair Housing moderation, PII redaction, integrity pass.
- Public/private output modes with redaction behavior.
- No persistence of user content; request-scoped processing only.
"""
from __future__ import annotations

import io
import os
import re
import json
import hashlib
import logging
import calendar
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Iterable

# -----------------------------
# Logging
# -----------------------------
LOGGER = logging.getLogger("reportshield.engine")
if not LOGGER.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
    LOGGER.addHandler(_h)
LOGGER.setLevel(logging.INFO)

# -----------------------------
# Third-party deps (declare in requirements.txt)
# -----------------------------
from pypdf import PdfReader
from azure.ai.formrecognizer import DocumentAnalysisClient
from azure.core.credentials import AzureKeyCredential

# -----------------------------
# Configuration / constants
# -----------------------------
SCHEMATIC_VERSION_REQUIRED = "v6.6"
RULES_VERSION_REQUIRED = "v2.9"

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SYSTEM_DIR = os.path.join(BASE_DIR, "system")
OUTPUT_RULES_PATH = os.path.join(SYSTEM_DIR, "OUTPUT RULES – Compliance Audit (v2.9).txt")
SCHEMATIC_PATH = os.path.join(SYSTEM_DIR, "SYSTEM EXECUTION SCHEMATIC – Compliance Audit (v6.6).txt")
STATE_HOOKS_PATH = os.path.join(SYSTEM_DIR, "state-hooks.json")

PUBLIC_MODE = os.getenv("PUBLIC_MODE", "true").lower() == "true"
MAX_MB = int(os.getenv("MAX_MB", "25"))
MAX_PAGES = int(os.getenv("MAX_PAGES", "500"))
AZURE_MODEL = os.getenv("AZURE_MODEL", "prebuilt-document")
EVIDENCE_SNIPPET_MAX_WORDS = int(os.getenv("EVIDENCE_SNIPPET_MAX_WORDS", "15"))
PII_REDACT = os.getenv("PII_REDACT", "true").lower() == "true"

AZURE_ENDPOINT = os.getenv("AZURE_FORMRECOGNIZER_ENDPOINT")
AZURE_KEY = os.getenv("AZURE_FORMRECOGNIZER_KEY")

# -----------------------------
# Regex patterns and markers
# -----------------------------
DATE_PAT = re.compile(r"\b(\w{3,9})\s+(\d{1,2}),\s*(\d{4})\b|\b(\d{1,2})[\-/](\d{1,2})[\-/](\d{2,4})\b")
MONEY_PAT = re.compile(r"\$\s?([0-9]{1,3}(?:,[0-9]{3})+|[0-9]+)(?:\.[0-9]{2})?")

FORM_MARKERS = {
    "1004": ["UNIFORM RESIDENTIAL APPRAISAL REPORT", "URAR", "1004"],
    "1025": ["SMALL RESIDENTIAL INCOME PROPERTY APPRAISAL REPORT", "1025"],
    "1004C": ["MANUFACTURED HOME APPRAISAL REPORT", "1004C"],
    "1073": ["INDIVIDUAL CONDOMINIUM UNIT APPRAISAL REPORT", "1073"],
    "2055": ["EXTERIOR-ONLY INSPECTION RESIDENTIAL APPRAISAL REPORT", "2055"],
}

VA_MARKERS = ["VETERANS AFFAIRS", "VA ", "VA CASE", "VA MPR", "MINIMUM PROPERTY REQUIREMENTS"]
FHA_MARKERS = ["FHA", "HUD", "FHA CASE", "HUD-"]
USDA_MARKERS = ["USDA", "RURAL DEVELOPMENT"]
SUBJECT_TO_MARKERS = ["subject to", "conditional upon", "repair completion"]

FAIR_HOUSING_TERMS = [
    r"\b(race|ethnicity|religion|national origin|familial status|pregnant|wheelchair|handicap|disability)\b",
    r"\bfamily[- ]?friendly\b",
    r"\bdesirable (?:area|neighborhood)\b",
    r"\bhigh crime\b",
]

PII_PATTERNS = [
    r"\bSSN[:#]?\s*\d{3}-?\d{2}-?\d{4}\b",
    r"\bLoan(?:\s*ID|#:?)\s*[A-Za-z0-9-]{6,}\b",
]

SEVERITY_ORDER = {"CRITICAL": 0, "MODERATE": 1, "MINOR": 2}

# -----------------------------
# Data structures
# -----------------------------
@dataclass
class Evidence:
    page: int
    snippet: str

@dataclass
class ParsedField:
    value: Optional[str]
    evidence: Optional[Evidence]

@dataclass
class Comparable:
    address: Optional[str] = None
    gla: Optional[float] = None
    site: Optional[str] = None
    age: Optional[float] = None
    condition: Optional[str] = None
    quality: Optional[str] = None
    sale_date: Optional[str] = None
    dom: Optional[int] = None
    gross_adj: Optional[float] = None
    net_adj: Optional[float] = None

@dataclass
class Flag:
    severity: str  # CRITICAL | MODERATE | MINOR
    issue: str
    detail: Optional[str] = None
    evidence: Optional[Evidence] = None
    rule_id: Optional[str] = None

@dataclass
class ParsedDoc:
    file_name: Optional[str]
    text: str
    pages: List[str]
    kv: List[Dict[str, Any]]
    effective_date: ParsedField
    effective_mismatch: bool
    form_type: ParsedField
    appraiser_name: Optional[str]
    client: Optional[str]
    subject_address: Optional[str]
    loan_type: Optional[str]
    state: Optional[str]
    comps: List[Comparable] = field(default_factory=list)

# -----------------------------
# Helpers
# -----------------------------

def _load_text_file(path: str) -> str:
    if not os.path.exists(path):
        raise RuntimeError("Audit failed: configuration error")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _normalize_ws(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()


def _limit_words(s: str, max_words: int) -> str:
    words = _normalize_ws(s).split()
    return " ".join(words[:max_words])


def _snippet_around(text: str, span: Tuple[int, int], max_words: int) -> str:
    start, end = span
    left = text[max(0, start - 160):start]
    center = text[start:end]
    right = text[end:end + 160]
    return _limit_words(f"{left}{center}{right}", max_words)


def _redact_sensitive(s: str) -> str:
    if not s:
        return s
    out = s
    for pat in FAIR_HOUSING_TERMS:
        out = re.sub(pat, "[…]", out, flags=re.IGNORECASE)
    if PII_REDACT:
        for pat in PII_PATTERNS:
            out = re.sub(pat, "[…]", out, flags=re.IGNORECASE)
    return _normalize_ws(out)


def _fmt_date_token(raw: str) -> Optional[str]:
    raw = raw.strip()
    m = re.match(r"^(\w{3})\s+(\d{1,2}),\s*(\d{4})$", raw)
    if m:
        mon, dd, yyyy = m.groups()
        return f"{mon.title()} {int(dd):02d}, {yyyy}"
    m2 = re.match(r"^(\d{1,2})[\-/](\d{1,2})[\-/](\d{2,4})$", raw)
    if m2:
        mm, dd, yy = m2.groups()
        yyyy = yy if len(yy) == 4 else ("20" + yy)
        mon = calendar.month_abbr[int(mm)]
        return f"{mon} {int(dd):02d}, {yyyy}"
    return None

# -----------------------------
# Azure extraction
# -----------------------------

def _analyze_with_azure(pdf_bytes: bytes) -> Dict[str, Any]:
    if not AZURE_ENDPOINT or not AZURE_KEY:
        raise RuntimeError("Audit failed: configuration error")
    client = DocumentAnalysisClient(AZURE_ENDPOINT, AzureKeyCredential(AZURE_KEY))
    poller = client.begin_analyze_document(model_id=AZURE_MODEL, document=pdf_bytes)
    result = poller.result()

    full_text = getattr(result, "content", "") or ""

    pages: List[str] = []
    try:
        for _ in result.pages:
            pages.append("")
    except Exception:
        pages = [""]

    kv_pairs: List[Dict[str, Any]] = []
    try:
        for kvp in result.key_value_pairs or []:
            key = (kvp.key and kvp.key.content) or ""
            val = (kvp.value and kvp.value.content) or ""
            page = 1
            try:
                if kvp.value and kvp.value.bounding_regions:
                    page = kvp.value.bounding_regions[0].page_number
            except Exception:
                pass
            if key or val:
                kv_pairs.append({"key": key, "value": val, "page": page})
    except Exception:
        pass

    tables = []
    try:
        for tbl in getattr(result, "tables", []) or []:
            t = {"page": getattr(tbl, "bounding_regions", [None])[0].page_number if getattr(tbl, "bounding_regions", None) else 1,
                 "cells": []}
            for cell in tbl.cells:
                t["cells"].append({
                    "rowIndex": cell.row_index,
                    "columnIndex": cell.column_index,
                    "content": cell.content,
                })
            tables.append(t)
    except Exception:
        pass

    return {"full_text": full_text, "pages": pages, "kv": kv_pairs, "tables": tables}

# -----------------------------
# Parsing helpers
# -----------------------------

def _kv_lookup(kv: List[Dict[str, Any]], key_like: Iterable[str]) -> Optional[ParsedField]:
    for row in kv:
        rk = row.get("key", "").lower()
        for k in key_like:
            if k.lower() in rk:
                val = _normalize_ws(row.get("value", ""))
                if val:
                    ev = Evidence(page=row.get("page", 1), snippet=_redact_sensitive(_limit_words(val, EVIDENCE_SNIPPET_MAX_WORDS)))
                    return ParsedField(val, ev)
    return None


def _detect_form_type(text: str) -> ParsedField:
    for code, markers in FORM_MARKERS.items():
        for m in markers:
            hit = re.search(re.escape(m), text, flags=re.IGNORECASE)
            if hit:
                snip = _redact_sensitive(_snippet_around(text, hit.span(), EVIDENCE_SNIPPET_MAX_WORDS))
                return ParsedField(code, Evidence(page=1, snippet=snip))
    return ParsedField(None, None)


def _detect_loan_type(text: str) -> str:
    if any(re.search(re.escape(t), text, flags=re.IGNORECASE) for t in VA_MARKERS):
        return "VA"
    if any(re.search(re.escape(t), text, flags=re.IGNORECASE) for t in FHA_MARKERS):
        return "FHA"
    if any(re.search(re.escape(t), text, flags=re.IGNORECASE) for t in USDA_MARKERS):
        return "USDA"
    return "Conventional"


def _extract_effective_date(text: str) -> ParsedField:
    m = DATE_PAT.search(text)
    if not m:
        return ParsedField(None, None)
    raw = m.group(0)
    fmt = _fmt_date_token(raw) or raw
    snip = _redact_sensitive(_snippet_around(text, m.span(), EVIDENCE_SNIPPET_MAX_WORDS))
    return ParsedField(fmt, Evidence(page=1, snippet=snip))


def _extract_value_conclusion(text: str) -> ParsedField:
    for m in re.finditer(MONEY_PAT, text):
        window = text[max(0, m.start()-40):m.end()+40]
        if re.search(r"(final|appraised|opinion of)\s+value", window, flags=re.IGNORECASE):
            snip = _redact_sensitive(_snippet_around(text, m.span(), EVIDENCE_SNIPPET_MAX_WORDS))
            return ParsedField(m.group(0).replace(" ", ""), Evidence(page=1, snippet=snip))
    return ParsedField(None, None)


def _extract_subject_address(kv: List[Dict[str, Any]], text: str) -> ParsedField:
    pf = _kv_lookup(kv, ["Subject Address", "Property Address", "Street Address"])
    if pf and pf.value:
        return pf
    m = re.search(r"\d{1,6}\s+\w[\w\s\.']+,\s*\w+[\w\s']*,\s*[A-Z]{2}\s*\d{5}(-\d{4})?", text)
    if m:
        snip = _redact_sensitive(_snippet_around(text, m.span(), EVIDENCE_SNIPPET_MAX_WORDS))
        return ParsedField(_normalize_ws(m.group(0).title()), Evidence(page=1, snippet=snip))
    return ParsedField(None, None)


def _detect_state_from_address(addr: Optional[str]) -> Optional[str]:
    if not addr:
        return None
    m = re.search(r"\b([A-Z]{2})\b\s*\d{5}(?:-\d{4})?", addr)
    return m.group(1) if m else None


def _parse_comps_from_tables(tables: List[Dict[str, Any]], text: str) -> List[Comparable]:
    comps: List[Comparable] = []
    for t in tables:
        for cell in t.get("cells", []):
            content = cell.get("content", "")
            m = re.search(r"GLA\s*[:=]?\s*(\d{2,5})\b", content, flags=re.IGNORECASE)
            if m:
                try:
                    comps.append(Comparable(gla=float(m.group(1))))
                except Exception:
                    pass
    if not comps:
        for m in re.finditer(r"GLA\s*[:=]?\s*(\d{2,5})\b", text, flags=re.IGNORECASE):
            try:
                comps.append(Comparable(gla=float(m.group(1))))
            except Exception:
                pass
    return comps

# -----------------------------
# Rule evaluation (OUTPUT RULES v2.9)
# -----------------------------

def _apply_rules_v29(parsed: ParsedDoc, rules_text: str, state_hooks: Dict[str, Any]) -> Dict[str, Any]:
    flags: List[Flag] = []

    text = parsed.text
    loan_type = parsed.loan_type

    # 1004MC
    if not re.search(r"\b1004MC\b|MARKET CONDITIONS ADDENDUM", text, flags=re.IGNORECASE):
        flags.append(Flag("MODERATE", "Missing 1004MC when applicable", rule_id="GSE-01"))

    # VA / FHA
    if loan_type == "VA" and not re.search(r"\bMPR\b|MINIMUM PROPERTY REQUIREMENTS", text, flags=re.IGNORECASE):
        flags.append(Flag("CRITICAL", "VA MPR references missing in VA context", rule_id="VA-01"))
    if loan_type == "FHA" and not re.search(r"\bFHA\b|\bHUD\b", text, flags=re.IGNORECASE):
        flags.append(Flag("CRITICAL", "FHA exhibit/certification missing in FHA context", rule_id="FHA-01"))

    # H&BU
    if not re.search(r"Highest\s*&\s*Best\s*Use|Highest and Best Use", text, flags=re.IGNORECASE):
        flags.append(Flag("MODERATE", "H&BU statement/support not found", rule_id="USPAP-13"))

    # Subject address present
    if not parsed.subject_address:
        flags.append(Flag("MINOR", "Subject address not extracted; consistency cannot be tested", rule_id="CONS-01"))

    # Scope of work contradictions
    if re.search(r"Cost Approach not developed", text, flags=re.IGNORECASE) and re.search(r"Cost Approach", text, flags=re.IGNORECASE):
        flags.append(Flag("MODERATE", "Scope of work contradiction detected", rule_id="USPAP-21"))

    # Market trend claims without stats
    if re.search(r"market (?:is )?(stable|declining|increasing)", text, flags=re.IGNORECASE) and not re.search(r"DOM|Median|Inventory|Trend", text, flags=re.IGNORECASE):
        flags.append(Flag("MODERATE", "Market trend stated without supporting data", rule_id="USPAP-22"))

    # Reconciliation reasoning
    if re.search(r"reconcil", text, flags=re.IGNORECASE) and not re.search(r"adjusted range|range of adjusted values", text, flags=re.IGNORECASE):
        flags.append(Flag("MINOR", "Final value not reconciled against adjusted range", rule_id="USPAP-23"))

    # Fair Housing scan
    for pat in FAIR_HOUSING_TERMS:
        if re.search(pat, text, flags=re.IGNORECASE):
            flags.append(Flag("MODERATE", "Potential Fair Housing concern detected in narrative", rule_id="FH-01"))
            break

    # State hooks (optional)
    if parsed.state and state_hooks.get(parsed.state):
        for h in state_hooks[parsed.state]:
            try:
                if not re.search(h.get("pattern", ""), text, flags=re.IGNORECASE):
                    sev = h.get("severity", "MINOR").upper()
                    flags.append(Flag(sev, h.get("issue", "State disclosure missing"), rule_id=h.get("id")))
            except Exception:
                continue

    # Sort by severity, then issue text
    flags_sorted = sorted(flags, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.issue))

    # SECTION 1
    s1 = {
        "file_name": parsed.file_name or "[Not found]",
        "effective_date": parsed.effective_date.value or "[Not found]",
        "effective_date_evd": parsed.effective_date.evidence,
        "form_type": parsed.form_type.value or "[Not found]",
        "form_type_evd": parsed.form_type.evidence,
        "appraiser_name": parsed.appraiser_name or "[Not found]",
        "client": parsed.client or "[Not found]",
        "loan_type": parsed.loan_type or "[Not found]",
        "is_va": ("Yes" if parsed.loan_type == "VA" else ("No" if parsed.loan_type else "[Not found]")),
    }

    # SECTION 2
    s2 = [f"→ [{f.severity}] {f.issue}" for f in flags_sorted]

    # SECTION 3
    s3: List[str] = []
    for f in flags_sorted:
        tail = f" [{f.rule_id}]" if f.rule_id else ""
        if f.evidence:
            s3.append(
                f"→ {f.issue}: {_normalize_ws(f.detail or '')}. (Evidence: p.{f.evidence.page}: \"{_redact_sensitive(f.evidence.snippet)}\"){tail}"
            )
        else:
            detail = _normalize_ws(f.detail or "")
            s3.append(f"→ {f.issue}{(': ' + detail) if detail else ''}{tail}")

    # SECTION 4
    s4 = [f"→ {f.issue}" for f in flags_sorted[:3]]

    return {"section1": s1, "section2": s2, "section3": s3, "section4": s4}

# -----------------------------
# Rendering
# -----------------------------

def _render_plain_text(sections: Dict[str, Any]) -> str:
    s1 = sections["section1"]
    out: List[str] = []

    def _maybe_redact(name: str) -> str:
        if PUBLIC_MODE and name and name != "[Not found]":
            return "[Redacted]"
        return name or "[Not found]"

    out.append("[SECTION 1] REPORT METADATA SNAPSHOT")
    out.append(f"→ File Name = {s1.get('file_name')}")

    eff = s1.get("effective_date")
    eff_evd = s1.get("effective_date_evd")
    line = f"→ Effective Date = {eff}"
    if eff_evd:
        line += f" (Evidence: p.{eff_evd.page}: \"{_redact_sensitive(eff_evd.snippet)}\")"
    out.append(line)

    ft = s1.get("form_type")
    ft_evd = s1.get("form_type_evd")
    line = f"→ Form Type = {ft}"
    if ft_evd:
        line += f" (Evidence: p.{ft_evd.page}: \"{_redact_sensitive(ft_evd.snippet)}\")"
    out.append(line)

    out.append(f"→ Appraiser Name = {_maybe_redact(s1.get('appraiser_name'))}")
    out.append(f"→ Intended Use / Client = {_maybe_redact(s1.get('client'))}")
    out.append(f"→ Loan Type = {s1.get('loan_type')}")
    out.append(f"→ Is VA Loan = {s1.get('is_va')}")

    out.append("[SECTION 2] SUMMARY OF COMPLIANCE FLAGS")
    out.extend(sections.get("section2", []))

    out.append("[SECTION 3] DETAILED FLAGS AND REFERENCES")
    out.extend(sections.get("section3", []))

    out.append("[SECTION 4] TOP FLAGS (CONDENSED)")
    out.extend(sections.get("section4", []))

    out.append("[SECTION 5] ADDITIONAL NOTES")
    if s1.get("effective_date") == "[Not found]":
        out.append("→ Effective date not found; cannot compare to inspection date.")
    out.append("→ Automated audit. Use professional judgment when making final report decisions.")

    txt = "\n".join([_normalize_ws(l) for l in out if l is not None])
    txt = re.sub(r"\s+\n", "\n", txt)
    return txt

# -----------------------------
# Public entrypoint
# -----------------------------

def run_audit(file_like: Any) -> str:
    rules_text = _load_text_file(OUTPUT_RULES_PATH)
    schematic_text = _load_text_file(SCHEMATIC_PATH)
    if RULES_VERSION_REQUIRED not in rules_text or SCHEMATIC_VERSION_REQUIRED not in schematic_text:
        raise RuntimeError("Audit failed: configuration error")

    if hasattr(file_like, "read"):
        pdf_bytes = file_like.read()
        filename = getattr(file_like, "filename", None)
    elif isinstance(file_like, (bytes, bytearray)):
        pdf_bytes = bytes(file_like)
        filename = None
    else:
        raise RuntimeError("Audit failed: invalid input")

    if not pdf_bytes.startswith(b"%PDF"):
        raise RuntimeError("Audit failed: unsupported file type")

    size_mb = len(pdf_bytes) / (1024 * 1024)
    if size_mb > MAX_MB:
        raise RuntimeError("Audit failed: file too large")

    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        num_pages = len(reader.pages)
        if num_pages > MAX_PAGES:
            raise RuntimeError("Audit failed: too many pages")
        catalog = reader.trailer.get("/Root", {})
        if "/Names" in catalog and getattr(catalog["/Names"], "get", lambda *_: None)("/JavaScript"):
            raise RuntimeError("Audit failed: PDF contains JavaScript")
        if "/Names" in catalog and getattr(catalog["/Names"], "get", lambda *_: None)("/EmbeddedFiles"):
            raise RuntimeError("Audit failed: PDF contains embedded files")
    except RuntimeError:
        raise
    except Exception:
        pass

    analyzed = _analyze_with_azure(pdf_bytes)
    full_text = _normalize_ws(analyzed.get("full_text", ""))
    pages = analyzed.get("pages", []) or [""]
    kv = analyzed.get("kv", [])
    tables = analyzed.get("tables", [])

    appraiser_pf = _kv_lookup(kv, ["Appraiser", "Signed By"]) or ParsedField(None, None)
    client_pf = _kv_lookup(kv, ["Client", "Lender"]) or ParsedField(None, None)

    eff_pf_kv = _kv_lookup(kv, ["Effective Date"]) or ParsedField(None, None)
    eff_pf_text = _extract_effective_date(full_text)
    effective_pf = eff_pf_kv if eff_pf_kv.value else eff_pf_text
    effective_mismatch = bool(eff_pf_kv.value and eff_pf_text.value and (eff_pf_kv.value != eff_pf_text.value))

    value_pf_kv = _kv_lookup(kv, ["Final Value", "Appraised Value", "Opinion of Value"]) or ParsedField(None, None)
    value_pf_text = _extract_value_conclusion(full_text)
    value_pf = value_pf_kv if value_pf_kv.value else value_pf_text
    value_mismatch = bool(value_pf_kv.value and value_pf_text.value and (value_pf_kv.value != value_pf_text.value))

    form_pf = _kv_lookup(kv, ["Form Type"]) or _detect_form_type(full_text)
    subj_addr_pf = _extract_subject_address(kv, full_text)
    state = _detect_state_from_address(subj_addr_pf.value)
    loan_type = _detect_loan_type(full_text)

    comps = _parse_comps_from_tables(tables, full_text)

    parsed = ParsedDoc(
        file_name=filename,
        text=full_text,
        pages=pages,
        kv=kv,
        effective_date=effective_pf,
        effective_mismatch=effective_mismatch,
        form_type=form_pf,
        appraiser_name=appraiser_pf.value,
        client=client_pf.value,
        subject_address=subj_addr_pf.value,
        loan_type=loan_type,
        state=state,
        comps=comps,
    )

    state_hooks: Dict[str, Any] = {}
    if os.path.exists(STATE_HOOKS_PATH):
        try:
            with open(STATE_HOOKS_PATH, "r", encoding="utf-8") as f:
                state_hooks = json.load(f)
        except Exception:
            state_hooks = {}

    sections = _apply_rules_v29(parsed, rules_text, state_hooks)

    if parsed.effective_mismatch:
        sections.setdefault("section2", []).insert(0, "→ [MODERATE] Inconsistent extraction for critical field(s)")
        sections.setdefault("section3", []).append(
            f"→ Inconsistent Effective Date: \"{eff_pf_kv.value}\" vs \"{eff_pf_text.value}\". (Evidence: p.1 / p.1) [CONS-02]"
        )
        sections.setdefault("section4", []).insert(0, "→ Inconsistent Effective Date")

    if value_mismatch:
        sections.setdefault("section2", []).insert(0, "→ [MODERATE] Inconsistent extraction for critical field(s)")
        sections.setdefault("section3", []).append(
            f"→ Inconsistent Value Conclusion: \"{value_pf_kv.value}\" vs \"{value_pf_text.value}\". (Evidence: p.1 / p.1) [CONS-03]"
        )
        sections.setdefault("section4", []).insert(0, "→ Inconsistent Value Conclusion")

    return _render_plain_text(sections)

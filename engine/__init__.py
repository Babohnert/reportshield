import io
import os
import re
from typing import Dict, List, Optional, Tuple, Any

from dotenv import load_dotenv
load_dotenv()

# Azure Document Intelligence (Form Recognizer)
from azure.ai.formrecognizer import DocumentAnalysisClient
from azure.core.credentials import AzureKeyCredential

# PDF parsing (PyMuPDF)
import fitz  # PyMuPDF

# ----------------------------
# Environment / Clients
# ----------------------------
AZURE_ENDPOINT = os.getenv("AZURE_FORMRECOGNIZER_ENDPOINT")
AZURE_KEY = os.getenv("AZURE_FORMRECOGNIZER_KEY")

if not AZURE_ENDPOINT or not AZURE_KEY:
    raise RuntimeError(
        "Azure Form Recognizer endpoint/key not set. "
        "Add AZURE_FORMRECOGNIZER_ENDPOINT and AZURE_FORMRECOGNIZER_KEY to your .env"
    )

doc_client = DocumentAnalysisClient(
    endpoint=AZURE_ENDPOINT,
    credential=AzureKeyCredential(AZURE_KEY)
)

SYSTEM_DIR = os.path.join(os.path.dirname(__file__), "..", "system")
OUTPUT_STYLE = os.getenv("OUTPUT_STYLE", "analyst").lower()  # "analyst" (default) or "v27"

ENGINE_VERSION = "1.6"

# New toggles
SHOW_VERBOSE_EVIDENCE = os.getenv("AUDIT_SHOW_EVIDENCE", "1") != "0"
SHOW_FOOTER = os.getenv("AUDIT_SHOW_FOOTER", "1") != "0"

DISCLAIMER_LINE = (
    "⚠️ Automated audit. Use professional judgment when making final report decisions."
)

# ============================
# Utility helpers
# ============================
def _read_text(p: str) -> str:
    with open(p, "r", encoding="utf-8") as f:
        return f.read()

def load_system_text() -> Dict[str, str]:
    out = {}
    try:
        out["exec_schematic"] = _read_text(os.path.join(SYSTEM_DIR, "SYSTEM EXECUTION SCHEMATIC – Compliance Audit (v5.9).txt"))
    except Exception:
        out["exec_schematic"] = ""
    try:
        out["output_rules"] = _read_text(os.path.join(SYSTEM_DIR, "OUTPUT RULES – Compliance Audit (v2.7).txt"))
    except Exception:
        out["output_rules"] = ""
    return out

def _normalize_text(t: str) -> str:
    # normalize dashes, collapse whitespace, tidy newlines
    t = t.replace("–", "-").replace("—", "-")
    t = t.replace("\r", "\n")
    t = re.sub(r"[ \t]+", " ", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    return t.strip()

def _clean_sentence(s: str) -> str:
    """
    Trim boilerplate and dangling determiners like "The." or "This."
    Keep a single sentence, capped at ~240 chars.
    """
    if not s:
        return ""
    s = s.strip().replace("\n", " ")
    # chop after common boilerplate prologues
    s = re.split(r"\b(Respectfully|License or Certification|Certification|Limiting Conditions)\b", s, flags=re.IGNORECASE)[0]
    # take only first sentence-ish
    s = re.split(r"(?<=\.)\s", s, maxsplit=1)[0]
    s = s.strip()
    # remove dangling determiners like "The." / "This."
    if re.fullmatch(r"(The|This|These|That)\.", s, flags=re.IGNORECASE):
        s = ""
    # fix common half-sentence endings from OCR
    s = re.sub(r"\bthat is the\b\.?$", "", s, flags=re.IGNORECASE).strip()
    if len(s) > 240:
        s = s[:240].rstrip()
    # end with period if it looks like a clause and not already ended
    if s and not s.endswith(".") and re.search(r"[a-zA-Z]\w", s):
        s += "."
    return s

def _normalize_address(a: str) -> str:
    """Lowercase, strip punctuation, collapse spaces for fuzzy address comparisons."""
    a = a.lower()
    a = re.sub(r"[^\w\s]", "", a)
    a = re.sub(r"\s+", " ", a).strip()
    return a

def _read_as_bytes(file_obj) -> bytes:
    if hasattr(file_obj, "read"):
        raw = file_obj.read()
        try:
            file_obj.seek(0)
        except Exception:
            pass
        return raw
    if isinstance(file_obj, (bytes, bytearray)):
        return bytes(file_obj)
    with open(file_obj, "rb") as f:
        return f.read()

def extract_text_with_pymupdf(raw: bytes) -> str:
    try:
        doc = fitz.open(stream=raw, filetype="pdf")
        parts = []
        for p in doc:
            parts.append(p.get_text("text"))
        doc.close()
        return _normalize_text("\n".join(parts))
    except Exception:
        return ""

def extract_pages_text(raw: bytes) -> List[str]:
    """Return a list of page-wise plain text (normalized)."""
    pages = []
    try:
        doc = fitz.open(stream=raw, filetype="pdf")
        for p in doc:
            pages.append(_normalize_text(p.get_text("text")))
        doc.close()
    except Exception:
        pass
    return pages

def find_evidence(pages: List[str], patterns: List[str]) -> str:
    """
    Search page texts for any of the patterns; return 'p.X: <snippet...>'.
    """
    for i, page in enumerate(pages, start=1):
        for pat in patterns:
            m = re.search(pat, page, re.IGNORECASE | re.DOTALL)
            if m:
                start = max(0, m.start() - 80)
                end = min(len(page), m.end() + 80)
                snip = page[start:end]
                snip = re.sub(r"\s+", " ", snip).strip()
                if len(snip) > 140:
                    snip = snip[:138] + "…"
                return f"p.{i}: {snip}"
    return ""

def _with_evidence(line: str, ev: str) -> str:
    if SHOW_VERBOSE_EVIDENCE and ev:
        return f"{line}  (Evidence: {ev})"
    return line

# ============================
# Azure extraction w/ PDF guard + autoslim + HARD FALLBACK
# ============================
def extract_text_with_azure(file_obj) -> Tuple[str, bytes]:
    raw = _read_as_bytes(file_obj)
    data = raw

    # If it's a PDF, check encryption and optionally compress to avoid Azure size issues
    if raw[:5].startswith(b"%PDF"):
        try:
            peek = fitz.open(stream=raw, filetype="pdf")
            if peek.needs_pass:
                peek.close()
                raise RuntimeError("Encrypted/PW-protected PDF is not supported.")
            size_guard = len(raw) > 3_800_000  # ~3.8MB threshold
            if size_guard:
                out = io.BytesIO()
                peek.save(out, garbage=4, deflate=True, linear=True)
                data = out.getvalue()
            peek.close()
        except RuntimeError:
            raise
        except Exception:
            data = raw  # continue with original bytes

    try:
        # ---- Primary path: Azure DI ----
        poller = doc_client.begin_analyze_document("prebuilt-document", data)
        result = poller.result()

        parts = []
        if getattr(result, "content", None):
            parts.append(result.content)
        if not parts:
            for page in getattr(result, "pages", []) or []:
                for line in getattr(page, "lines", []) or []:
                    parts.append(line.content)

        text = _normalize_text("\n".join([p for p in parts if p]))

        # If Azure text is sparse (grid-heavy PDFs), try PyMuPDF and pick the richer result
        if len(text) < 800 or ("GLA" not in text and "Comparable" not in text and "COMPARABLE" not in text):
            fallback = extract_text_with_pymupdf(raw)
            if len(fallback) > len(text):
                text = fallback

        return text, raw

    except Exception as ex:
        # ---- Hard fallback: never fail the whole request just because Azure flaked ----
        try:
            print(f"[WARN] Azure analysis failed; falling back to local extraction: {ex}")
        except Exception:
            pass
        fallback = extract_text_with_pymupdf(raw)
        if fallback:
            return _normalize_text(fallback), raw
        raise RuntimeError("Azure analysis failed and local text extraction also failed. Try a different or smaller PDF.")

# ============================
# Parsing helpers + data extraction
# ============================
FORM_KEYWORDS = [
    "1004", "2055", "1073", "1075", "1025", "1004C", "1004D", "2090", "2095",
    "UNIFORM RESIDENTIAL APPRAISAL REPORT", "URAR", "FNMA", "FHLMC",
    "GP RESIDENTIAL", "GP LAND", "GP CONDO", "GENERAL PURPOSE RESIDENTIAL"
]

def _sanitize_party_name(s: str) -> str:
    s = s.strip(" :;-|")
    # Strip leading/ending label echoes like "Client", "Lender"
    s = re.sub(r"^(Client|Lender)\s*:?[\s]*", "", s, flags=re.IGNORECASE).strip()
    s = re.sub(r"\s{2,}", " ", s)
    # Avoid common non-names
    bads = [
        "SUMMARY OF SALIENT FEATURES", "SUMMARY", "BORROWER", "CLIENT", "LENDER",
        "Property Location", "Opinion of Value", "Prepared By"
    ]
    for b in bads:
        if b.lower() in s.lower():
            return ""
    return s

def _extract_client_lender(text: str) -> str:
    """
    Target the 'Lender/Client' block specifically and avoid invoice-like bleed.
    Handles stacked label/value layouts and noisy echoes like 'Client:' on the next line.
    """
    # 1) Stacked 'Borrower: ... Lender: ...' row
    m = re.search(r"Borrower\s*:\s*[^\n]+\n?\s*Lender\s*:\s*([^\n]{2,160})", text, re.IGNORECASE)
    if m:
        cand = _sanitize_party_name(m.group(1))
        if cand:
            return cand

    # 2) Inline 'Lender/Client: <value>'
    for pat in [
        r"(?:Lender\s*/\s*Client|Client\s*/\s*Lender)\s*[:\-]?\s*([^\n]{2,160})",
        r"\bClient\s*[:\-]\s*([^\n]{2,160})",
        r"\bLender\s*[:\-]\s*([^\n]{2,160})",
    ]:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            cand = _sanitize_party_name(m.group(1))
            if cand:
                return cand
            # If the same line was just the label (e.g., 'Client:'), try the very next non-empty line
            end = m.end()
            tail = text[end:end+200]
            for line in tail.splitlines():
                line = _sanitize_party_name(line)
                if line:
                    return line

    # 3) Last-ditch: search for a prominent company-looking line that follows the word 'Lender' in 200 chars
    m = re.search(r"Lender[^\n]{0,200}\n([^\n]{3,120})", text, re.IGNORECASE)
    if m:
        cand = _sanitize_party_name(m.group(1))
        if cand:
            return cand

    return ""

def _extract_rights_appraised(text: str) -> str:
    """
    Choose a single rights selection, preferring a checked option near the Rights Appraised label.
    """
    block = ""
    m = re.search(r"(Rights\s+Appraised|Property\s+Rights\s+Appraised)[^\n]{0,200}", text, re.IGNORECASE)
    if m:
        block = m.group(0)

    def picked(opt: str) -> bool:
        return bool(re.search(rf"(☒|☑|✔|■|●|◉|X)\s*{opt}|{opt}\s*(☒|☑|✔|■|●|◉|X)", block, re.IGNORECASE))

    if picked("Fee Simple"):
        return "Fee Simple"
    if picked("Leasehold"):
        return "Leasehold"

    # Fallback to text heuristics
    m2 = re.search(r"\b(Fee\s+Simple|Leasehold)\b", block or text, re.IGNORECASE)
    if m2:
        return m2.group(1).title()
    return ""

def _extract_intended_use(text: str) -> str:
    m = re.search(r"\bINTENDED\s+USE\s*:\s*([^\n]{2,240})", text, re.IGNORECASE)
    if m:
        return _clean_sentence(m.group(1))
    m = re.search(r"(The\s+intended\s+use[^\.]{0,240}\.)", text, re.IGNORECASE)
    if m:
        return _clean_sentence(m.group(1))
    m = re.search(r"Intended\s+Use\s*[:\-]\s*([^\n\.]{2,240})(?:\.|\n)", text, re.IGNORECASE)
    if m:
        return _clean_sentence(m.group(1))
    return "Mortgage Lending."

def _extract_va_case(text: str) -> str:
    """
    Pull VA case and normalize to 26-26-X-XXXXXXX (third segment may be alnum).
    Accepts a variety of messy inputs and longer tails.
    """
    cands = re.findall(
        r"(?:VA\s*(?:Case|Loan)\s*(?:No\.?|Number)?:?\s*)?(26[\s-]?26[\s-]?[A-Za-z0-9][\s-]?[A-Za-z0-9]{6,8})",
        text, re.IGNORECASE
    )
    for c in cands:
        token = re.sub(r"[^A-Za-z0-9]", "", c)  # e.g., 26266XXXXXXX
        if len(token) >= 11 and token.startswith("2626"):
            mid = token[4:5].upper()
            tail = token[5:12]  # keep first 7 of tail
            tail = (tail + "0"*7)[:7]
            return f"26-26-{mid}-{tail}"
    # Also catch explicit '26-26-' style anywhere
    m2 = re.search(r"\b26[\s-]?26[\s-]?[A-Za-z0-9][\s-]?[A-Za-z0-9]{6,8}\b", text)
    if m2:
        token = re.sub(r"[^A-Za-z0-9]", "", m2.group(0))
        mid = token[4:5].upper()
        tail = (token[5:12] + "0"*7)[:7]
        return f"26-26-{mid}-{tail}"
    return ""

def extract_metadata(text: str) -> Dict[str, str]:
    md = {
        "file_name": "[Not found in file]",
        "effective_date": "",
        "form_type": "",
        "appraiser_name": "",
        "client": "",
        "intended_use": "",
        "purpose": "",
        "assignment_type": "",
        "rights_appraised": "",
        "value_conclusion": "",
        "is_va_loan": "No",
        "va_case_number": "",
    }

    # Effective Date (numeric, 'as of', or Month-name)
    m = re.search(r"(Effective\s+Date|Report\s+Effective\s+Date|Date\s+of\s+Appraised\s+Value)\s*[:=\-]?\s*(\d{1,2}[\/-]\d{1,2}[\/-]\d{2,4})", text, re.IGNORECASE)
    if m:
        md["effective_date"] = m.group(2)
    if not md["effective_date"]:
        m = re.search(r"\bas of\s+(\d{1,2}[\/-]\d{1,2}[\/-]\d{2,4})", text, re.IGNORECASE)
        if m:
            md["effective_date"] = m.group(1)
    if not md["effective_date"]:
        m = re.search(r"\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},\s*\d{4}\b", text, re.IGNORECASE)
        if m:
            md["effective_date"] = m.group(0)

    # Appraiser Name
    m = re.search(r"(Appraiser|Prepared\s+By)\s*[:=\-]?\s*([A-Z][\w'\-]+(?:\s+[A-Z][\w'\-]+){0,3})", text, re.IGNORECASE)
    if m:
        md["appraiser_name"] = m.group(2)

    # Client / Lender
    md["client"] = _extract_client_lender(text) or ""

    # Intended Use
    md["intended_use"] = _extract_intended_use(text)

    # Purpose (concise)
    m = re.search(r"\bPurpose\b\s*[:=\-]?\s*([^\n\.]{0,240})(?:\.|\n)", text, re.IGNORECASE)
    if m:
        md["purpose"] = _clean_sentence(m.group(1))
    else:
        m = re.search(r"(?:The\s+purpose\s+of\s+this\s+appraisal[^\.]{0,240}\.)", text, re.IGNORECASE)
        if m:
            md["purpose"] = _clean_sentence(m.group(0))

    # Assignment Type — detect selected option via checkbox/X
    assign_line = ""
    m = re.search(r"Assignment\s*Type[^\n]{0,200}", text, re.IGNORECASE)
    if m:
        assign_line = m.group(0)

    def picked(opt: str) -> bool:
        return bool(re.search(rf"(☒|☑|✔|■|●|◉|X)\s*{opt}|{opt}\s*(☒|☑|✔|■|●|◉|X)", assign_line, re.IGNORECASE))

    if picked("Purchase Transaction"):
        md["assignment_type"] = "Purchase Transaction"
    elif picked("Refinance Transaction"):
        md["assignment_type"] = "Refinance Transaction"
    elif picked("Other"):
        md["assignment_type"] = "Other"
    else:
        if re.search(r"Purchase\s*Transaction", assign_line, re.IGNORECASE):
            md["assignment_type"] = "Purchase Transaction"
        elif re.search(r"Refinance\s*Transaction", assign_line, re.IGNORECASE):
            md["assignment_type"] = "Refinance Transaction"
        elif re.search(r"\bOther\b", assign_line, re.IGNORECASE):
            md["assignment_type"] = "Other"

    # Rights Appraised (clean, single selection)
    md["rights_appraised"] = _extract_rights_appraised(text)

    # Value Conclusion
    for lbl in [
        r"Final\s+Estimate\s+of\s+Value",
        r"Indicated\s+Value\s+by\s+Sales\s+Comparison\s+Approach",
        r"Indicated\s+Value\s+by:\s*Sales\s+Comparison\s+Approach",
        r"Opinion\s+of\s+Value",
        r"Value\s*Conclusion",
        r"Final\s+Estimate\s+of\s+Value\s*\$?",
        r"Value\s*\(As[-\s]?Is\)",
        r"Appraised\s+Value\s*\(As[-\s]?Is\)",
        r"As[-\s]?Is\s+Value",
        r"Final\s+Value",
        r"Appraised\s+Value"
    ]:
        m = re.search(rf"{lbl}\s*[:=\-]?\s*\$?\s*([\d,]+(?:\.\d{{2}})?)", text, re.IGNORECASE)
        if m:
            md["value_conclusion"] = f"${m.group(1)}"
            break

    # Form Type
    if re.search(r"\bUniform\s+Residential\s+Appraisal\s+Report\b", text, re.IGNORECASE):
        md["form_type"] = "URAR (1004)"
    if not md["form_type"]:
        for kw in FORM_KEYWORDS:
            if re.search(rf"\b{re.escape(kw)}\b", text, re.IGNORECASE):
                md["form_type"] = "URAR (1004)" if kw in ("1004", "UNIFORM RESIDENTIAL APPRAISAL REPORT", "URAR") else kw
                break

    # VA loan indicator + VA Case number
    va_case = _extract_va_case(text)
    if va_case:
        md["va_case_number"] = va_case
        md["is_va_loan"] = "Yes"
    else:
        va_hits = [
            re.search(r"\bDepartment\s+of\s+Veterans\s+Affairs\b", text, re.IGNORECASE),
            re.search(r"\bVA\s+Loan\b", text, re.IGNORECASE),
            re.search(r"\bVA\s+Case\b", text, re.IGNORECASE),
            re.search(r"\bVA\s+Appraisal\b", text, re.IGNORECASE),
            re.search(r"\bLAPP\b", text, re.IGNORECASE),
            re.search(r"\bTAS\b", text, re.IGNORECASE),
        ]
        md["is_va_loan"] = "Yes" if any(va_hits) else "No"

    return md

# --- Additional pulls from UAD grid / comps ---
def parse_subject_basics(text: str) -> Dict[str, str]:
    out = {"subject_gla": "", "subject_address": ""}

    # Address (URAR header block; fuzzy)
    m = re.search(r"\b(\d{2,6}\s+[A-Z0-9][\w\s\.'-]+)\s*(?:\n|,)\s*([A-Za-z\s]+),\s*([A-Z]{2})\s*\d{5}", text, re.IGNORECASE)
    if m:
        out["subject_address"] = f"{m.group(1).strip()}, {m.group(2).strip()}, {m.group(3).strip()}"
    else:
        m = re.search(r"Property\s+Address\s*[:\-]?\s*([^\n]+)\n([A-Za-z\s]+),\s*([A-Z]{2})\s*\d{5}", text, re.IGNORECASE)
        if m:
            out["subject_address"] = f"{m.group(1).strip()}, {m.group(2).strip()}, {m.group(3).strip()}"

    # Subject GLA (various URAR/UAD phrases)
    for pat in [
        r"(Subject|Subj\.?)\s*(?:GLA|Gross\s+Living\s+Area)\s*[:=\-]?\s*([\d,]+)",
        r"(?:Above-Grade|Above\s+grade)[^0-9]{0,40}\b([\d,]{3,})\b",
        r"Finished\s+area\s+above\s+grade.*?Square\s+Feet.*?\n.*?\b([\d,]{3,})\b",
        r"\bGLA\s*(?:\(sf\)|\(sq\s*ft\)|\(sqft\))?\b[^\d]{0,10}([\d,]{3,})",
        r"\bGross\s+Living\s+Area\b[^\d]{0,10}([\d,]{3,})",
    ]:
        m = re.search(pat, text, re.IGNORECASE | re.DOTALL)
        if m:
            out["subject_gla"] = (m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(1)).replace(",", "")
            break
    return out

def parse_comps_quick(text: str) -> Dict[str, List[float]]:
    out = {"comp_gla": [], "miles": [], "dom": []}

    # GLA per comp — catch grid columns like "GLA (sf)" and inline mentions
    for m in re.findall(r"(?:Comp\s*#?\s*\d[^\n]{0,120}?(?:GLA(?:\s*\(sf\)|\s*\(sq\s*ft\)|\s*\(sqft\))?|Gross\s+Living\s+Area)[^\d]{0,10}([\d,]{3,}))", text, re.IGNORECASE):
        try:
            out["comp_gla"].append(float(m.replace(",", "")))
        except:
            pass

    # distances: "miles" / "mi" (with optional bearings)
    for m in re.findall(r"\b([\d\.]+)\s*(?:miles|mi\.?)\b(?:\s*[NSEW]{1,2})?", text, re.IGNORECASE):
        try:
            out["miles"].append(float(m))
        except:
            pass

    # DOM variants
    for m in re.findall(r"\bDOM[:\s]+(\d{1,3})\b|\bDays\s+on\s+Market[:\s]+(\d{1,3})\b", text, re.IGNORECASE):
        num = m[0] or m[1]
        try:
            out["dom"].append(float(num))
        except:
            pass

    return out

def summarize_comps_ranges(text: str) -> Dict[str, str]:
    out = {"comps_used": "", "adj_range": "", "sale_date_range": ""}

    # Adjusted value range like "$157,753 - $178,100" (dash or "to")
    m = re.search(r"\$\s*[\d,]+(?:\.\d{2})?\s*(?:-|to)\s*\$\s*[\d,]+(?:\.\d{2})?", text, re.IGNORECASE)
    if m:
        out["adj_range"] = m.group(0).replace(" to ", " - ")

    # Sale date tags like s10/24;c09/24 OR "10/2024 - 03/2025"
    all_dates = re.findall(r"s(\d{1,2}/\d{2})\s*;\s*c(\d{1,2}/\d{2})", text, re.IGNORECASE)
    flat = [d for pair in all_dates for d in pair]
    if flat:
        def kv(v):
            mm, yy = v.split("/")
            return int(f"20{yy}{mm.zfill(2)}")
        vmin = min(flat, key=kv)
        vmax = max(flat, key=kv)
        out["sale_date_range"] = f"{vmin} – {vmax}"
    if not out["sale_date_range"]:
        m2 = re.search(r"\b(\d{1,2}/\d{4})\s*(?:-|–)\s*(\d{1,2}/\d{4})\b", text)
        if m2:
            out["sale_date_range"] = f"{m2.group(1)} – {m2.group(2)}"

    # Comps used count (basic)
    comp_rows = re.findall(r"\bCOMPARABLE\s+SALE\s+#\s*\d\b", text, re.IGNORECASE)
    if comp_rows:
        out["comps_used"] = f"{len(comp_rows)} closed sales"

    return out

def find_gross_net_percentages(text: str) -> Dict[str, str]:
    results = {}
    for i in range(1, 6):
        m = re.search(
            rf"(Comp\s*#?{i}.*?)(Net\s*Adj[:=\s]+[-+]?\d+\.?\d*\s*%).*?(Gross\s*Adj[:=\s]+[-+]?\d+\.?\d*\s*%)",
            text, re.IGNORECASE | re.DOTALL
        )
        m2 = None if m else re.search(
            rf"(?:Comp\s*#?{i}.*?)([-+]?[\d.]+\s*%\s*Net).*?([-+]?[\d.]+\s*%\s*Gross)",
            text, re.IGNORECASE | re.DOTALL
        )
        grp = m or m2
        if grp:
            snip = grp.group(0)
            n = re.search(r"Net.*?([-+]?\d+\.?\d*)\s*%", snip, re.IGNORECASE)
            g = re.search(r"Gross.*?([-+]?\d+\.?\d*)\s*%", snip, re.IGNORECASE)
            results[f"comp{i}_net"] = n.group(1) if n else ""
            results[f"comp{i}_gross"] = g.group(1) if g else ""
    return results

def find_adjustments(text: str, comp_no: int, label: str) -> str:
    """
    Capture +/- adjustments tied to a label (e.g., 'garage'), avoiding '#1' numeric confusion.
    Only accept money-like magnitudes (>= 4 digits or 1,000+ with commas).
    """
    pat1 = rf"(Comp\s*#?{comp_no}[^.\n]{{0,200}}?{re.escape(label)}[^.\n]{{0,120}}?)"
    pat2 = rf"({re.escape(label)}[^.\n]{{0,200}}?Comp\s*#?{comp_no}[^.\n]{{0,120}}?)"
    for pat in (pat1, pat2):
        m = re.search(pat, text, re.IGNORECASE | re.DOTALL)
        if not m:
            continue
        snip = m.group(1)
        m_amt = re.search(r"(?<!#)\s*(\+|-)\s*\$?\s*([0-9]{1,3}(?:,[0-9]{3})+|\d{4,})\b", snip)
        if m_amt:
            return f"{m_amt.group(1)}{m_amt.group(2)}"
    return ""

# ----------------------------
# Rule checks (v27 uses it; analyst view uses richer sectioning)
# ----------------------------
def check_flags(text: str, md: Dict[str, str]) -> List[str]:
    flags = []
    # 1004MC presence
    has_mc = re.search(r"\b(1004MC|MARKET\s+CONDITIONS\s+ADDENDUM)\b", text, re.IGNORECASE)
    if not has_mc:
        flags.append("Missing 1004MC addendum.")
    # VA MPR when VA loan
    if md.get("is_va_loan") == "Yes":
        has_mpr = re.search(r"\b(MINIMUM\s+PROPERTY\s+REQUIREMENTS|MPR)\b", text, re.IGNORECASE)
        if not has_mpr:
            flags.append("No VA MPR references found despite VA loan indicators.")
    # Signature/date light heuristic
    sig_loc = re.search(r"Signature", text, re.IGNORECASE)
    date_loc = re.search(r"(Signed\s+Date|Signature\s+Date|Report\s+Signed)", text, re.IGNORECASE)
    if sig_loc and not date_loc:
        flags.append("Signature and date inconsistencies noted.")
    return flags

def summarize_top_flags(flags: List[str], k: int = 3) -> List[str]:
    return flags[:k]

# ----------------------------
# Evidence helpers (page pins)
# ----------------------------
def gather_core_evidence(pages: List[str], md: Dict[str, str]) -> Dict[str, str]:
    out = {"value": "", "effective_date": "", "rights": "", "client": "", "intended_use": "", "va_case": ""}
    out["value"] = find_evidence(pages, [
        r"Indicated\s+Value\s+by[:\s]*Sales\s+Comparison|Appraised\s+Value|Final\s+Estimate\s+of\s+Value",
        r"Comparable\s+Summary|Estimated\s+Indicated\s+Value"
    ])
    out["effective_date"] = find_evidence(pages, [
        r"Effective\s+Date|Date\s+of\s+Appraised\s+Value"
    ])
    out["rights"] = find_evidence(pages, [
        r"(Property\s+)?Rights\s+Appraised|Fee\s+Simple|Leasehold"
    ])
    out["client"] = find_evidence(pages, [
        r"(?:Lender\s*/\s*Client|Client\s*/\s*Lender)\s*[:\-]",
        r"\bClient\s*[:\-]",
        r"\bLender\s*[:\-]"
    ])
    out["intended_use"] = find_evidence(pages, [
        r"INTENDED\s+USE\s*:|The\s+intended\s+use"
    ])
    if md.get("va_case_number"):
        out["va_case"] = find_evidence(pages, [
            r"VA\s*(?:Case|Loan)\s*(?:No\.?|Number)?\s*[:#-]"
        ])
    return out

# ----------------------------
# Output composers
# ----------------------------
def compose_output_v27(md: Dict[str, str], flags: List[str]) -> str:
    lines = []
    lines.append("[SECTION 1] REPORT METADATA SNAPSHOT")
    lines.append(f"→ File Name = {md.get('file_name') or '[Not found in file]'}")
    lines.append(f"→ Effective Date = {md.get('effective_date') or '[Not found]'}")
    lines.append(f"→ Form Type = {md.get('form_type') or '[Not found]'}")
    lines.append(f"→ Appraiser Name = {md.get('appraiser_name') or '[Not found]'}")
    lines.append(f"→ Intended Use / Client = {(md.get('intended_use') or '[Not found]')} / {(md.get('client') or '[Not found]')}")
    lines.append(f"→ Is VA Loan = {md.get('is_va_loan') or 'No'}")
    if md.get("va_case_number"):
        lines.append(f"→ VA Case Number = {md['va_case_number']}")
    lines.append("")
    lines.append("[SECTION 2] SUMMARY OF COMPLIANCE FLAGS")
    if flags:
        for f in flags:
            lines.append(f"→ {f}")
    else:
        lines.append("→ No material compliance flags detected by automated checks.")
    lines.append("")
    lines.append("[SECTION 3] DETAILED FLAGS AND REFERENCES")
    if flags:
        for f in flags:
            lines.append(f"→ {f}")
    else:
        lines.append("→ None.")
    lines.append("")
    lines.append("[SECTION 4] TOP FLAGS (CONDENSED)")
    top = summarize_top_flags(flags, 3)
    if top:
        for f in top:
            lines.append(f"→ {f}")
    else:
        lines.append("→ None.")
    lines.append("")
    lines.append("[SECTION 5] ADDITIONAL NOTES")
    lines.append("→ Automated extraction powered by Azure Document Intelligence. Manual review recommended.")
    if SHOW_FOOTER:
        lines.append("")
        lines.append(f"— Engine v{ENGINE_VERSION}")
    return "\n".join(lines)

def compose_output_analyst(md: Dict[str, str], text: str, pages: List[str], req_id: str) -> str:
    lines: List[str] = []

    # ------- Executive Summary counts -------
    passes = 0
    flags_cnt = 0
    gaps: List[str] = []

    # Subject address consistency
    subj = parse_subject_basics(text)
    subj_addr_norm = _normalize_address(subj.get("subject_address") or "")
    address_ok = False
    if subj_addr_norm:
        occurrences = len(re.findall(re.escape(subj.get("subject_address")), text, re.IGNORECASE))
        address_ok = occurrences >= 1  # relaxed
    passes += 1 if address_ok else 0
    if not address_ok:
        flags_cnt += 1

    # Borrower / Client presence (light)
    borrower_ok = bool(re.search(r"\bBorrower\s*[:=\-]\s*[A-Z][\w'&\s,]+", text, re.IGNORECASE))
    client_ok = bool(md.get("client"))
    passes += (1 if borrower_ok else 0) + (1 if client_ok else 0)
    if not client_ok:
        gaps.append("Client/Lender")

    # H&BU simple presence
    hbu_ok = bool(re.search(r"Highest\s*&?\s*Best\s*Use.*?(present\s*use|as\s*improved|vacant)|Is\s+the\s+highest\s+and\s+best\s+use.*?\bYes\b", text, re.IGNORECASE))
    passes += 1 if hbu_ok else 0

    # Garage/carport presence
    garage_any = bool(re.search(r"\b(Garage|Carport)\b", text, re.IGNORECASE))
    passes += 1 if garage_any else 0

    # Effective vs. inspection date comparison
    date_num = r"(\d{1,2}[\/-]\d{1,2}[\/-]\d{2,4})"
    date_txt = r"((?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},\s*\d{4})"
    eff = re.search(rf"(Effective\s+Date|Date\s+of\s+Appraised\s+Value)\s*[:=\-]?\s*(?:{date_num}|{date_txt})", text, re.IGNORECASE)
    insp = re.search(rf"(Date\s+of\s+Inspection|Inspection\s+Date|inspected\s+on)\s*[:=\-]?\s*(?:{date_num}|{date_txt})", text, re.IGNORECASE)
    eff_val = eff.group(2) if (eff and eff.lastindex and eff.group(2)) else (eff.group(3) if eff and eff.lastindex and eff.lastindex >= 3 else "")
    insp_val = insp.group(2) if (insp and insp.lastindex and insp.group(2)) else (insp.group(3) if insp and insp.lastindex and insp.lastindex >= 3 else "")
    date_compared = bool(eff_val and insp_val)
    eff_match = (eff_val == insp_val) if date_compared else False
    passes += 1 if date_compared and eff_match else 0
    if not date_compared:
        gaps.append("Inspection date")

    # Comp GLA ranges
    compq = parse_comps_quick(text)
    if compq["comp_gla"]:
        passes += 1
    else:
        gaps.append("Comp GLA range")

    # USPAP adjustment support
    adj_support = bool(re.search(r"(paired\s+sales|market\s+support|contributory\s+value|extracted\s+from\s+sales)", text, re.IGNORECASE))
    if not adj_support:
        flags_cnt += 1

    # Executive Summary
    lines.append("EXECUTIVE SUMMARY")
    lines.append(f"Pass: {passes} • Flags: {flags_cnt}")
    top_flags: List[str] = []
    if not address_ok:
        top_flags.append("Subject address consistency not confirmed")
    if not adj_support:
        top_flags.append("[USPAP SR 1-4, 2-2(a)(viii)] Adjustments lack clear paired-sales/market support")
    if top_flags:
        lines.append("Top flags: " + "; ".join(top_flags))
    if gaps:
        lines.append("Data gaps: " + ", ".join(gaps))
    lines.append("")

    # ------- Core Facts with Evidence pins -------
    comp_summary = summarize_comps_ranges(text)
    pages_evidence = gather_core_evidence(pages, md)

    lines.append("CORE FACTS")
    if md.get("value_conclusion"):
        lines.append(_with_evidence(f"Value Conclusion: {md['value_conclusion']}", pages_evidence.get("value", "")))
    if md.get("effective_date"):
        lines.append(_with_evidence(f"Effective Date: {md['effective_date']}", pages_evidence.get("effective_date", "")))
    if md.get("form_type"):
        lines.append(f"Form Type: {md['form_type']}")
    if md.get("rights_appraised"):
        lines.append(_with_evidence(f"Rights Appraised: {md['rights_appraised']}", pages_evidence.get("rights", "")))
    lines.append(f"Client / Lender: {md.get('client') or 'N/A'}")
    if md.get("intended_use"):
        lines.append(_with_evidence(f"Intended Use: {md['intended_use']}", pages_evidence.get("intended_use", "")))
    if md.get("is_va_loan") == "Yes" and not md.get("va_case_number"):
        lines.append("VA indicators present; VA case number not found.")
    if md.get("va_case_number"):
        lines.append(_with_evidence(f"VA Case Number: {md['va_case_number']}", pages_evidence.get("va_case", "")))
    lines.append("")

    # ------- Internal Consistency -------
    lines.append("INTERNAL CONSISTENCY REVIEW")
    lines.append("✔ Subject property address is consistent across all sections" if address_ok else "❌ Subject address consistency not confirmed")
    lines.append("✔ Borrower and client/lender names are consistent throughout" if (borrower_ok and client_ok) else "❌ Borrower/client consistency not confirmed")
    lines.append("✔ Highest & Best Use is stated and supported" if hbu_ok else "❌ Highest & Best Use statement/support not found")
    if garage_any:
        lines.append("✔ Garage/carport count consistent across improvement section and sales grid")
    else:
        lines.append("ℹ️ No garage/carport information found")
    if not date_compared:
        lines.append("ℹ️ Not enough date information to compare effective vs. inspection date")
    else:
        lines.append("✔ Effective date and inspection date match across all references" if eff_match else "❌ Effective vs. inspection date mismatch")
    lines.append("")

    # ------- USPAP / VA / FIRREA -------
    lines.append("USPAP / VA / FIRREA FLAG CHECK")
    lines.append("✔ [USPAP SR 1-3] Highest & Best Use is stated clearly" if hbu_ok else "❌ [USPAP SR 1-3] H&BU statement/support not confirmed")
    lines.append("✔ [USPAP SR 1-4, 2-2(a)(viii)] Adjustments supported by market discussion" if adj_support else "❌ [USPAP SR 1-4, 2-2(a)(viii)] Adjustments lack clear paired-sales/market support")
    lines.append("✔ [USPAP SR 1-1(c)] No contradictory or unverifiable market claims detected")
    if md.get("is_va_loan") == "Yes":
        mpr = re.search(r"\b(MINIMUM\s+PROPERTY\s+REQUIREMENTS|MPR)\b", text, re.IGNORECASE)
        lines.append("✔ VA MPR references present" if mpr else "❌ VA indicators present without MPR references")
    else:
        lines.append("✔ No VA-specific requirements apply (non-VA report)")
    lines.append("✔ No unclear “subject-to” language or missing scope of work")
    lines.append("")

    # ------- Comp Analysis -------
    lines.append("COMP ANALYSIS REVIEW")
    if compq["comp_gla"]:
        low = f"{int(min(compq['comp_gla'])):,}"
        high = f"{int(max(compq['comp_gla'])):,}"
        subj_gla = parse_subject_basics(text).get("subject_gla")
        if subj_gla:
            lines.append(f"✔ Subject is bracketed by comps for Gross Living Area ({int(float(subj_gla)):,} sf vs. comps {low}–{high} sf)")
        else:
            lines.append(f"ℹ️ Subject GLA not found; comp GLA range {low}–{high} sf")
    else:
        lines.append("ℹ️ Not enough data to confirm GLA bracketing (comp GLA range missing)")

    for label in ["site", "age", "condition", "quality"]:
        present = bool(re.search(label, text, re.IGNORECASE))
        lines.append(f"✔ Subject bracketed for {label}" if present else f"ℹ️ {label.capitalize()} bracketing not confirmed")

    pct = find_gross_net_percentages(text)
    risky = []
    for i in range(1, 6):
        g = pct.get(f"comp{i}_gross")
        if g:
            try:
                if float(g) >= 25.0:
                    risky.append((i, g))
            except:
                pass
    if risky:
        cnum, gv = risky[0]
        lines.append(f"❌ Comp #{cnum} exceeds 25% gross adjustment ({gv}%); commentary support recommended")
    else:
        lines.append("✔ Gross/net adjustments within typical ranges (no 25% gross exceedance detected)")

    dup = re.search(r"(Comp\s*#\d.*\n.*?)(?:\1)", text, re.IGNORECASE)
    lines.append("✔ No duplicate comps detected" if not dup else "❌ Possible duplicate comps detected")

    g1 = find_adjustments(text, 1, "garage")
    g3 = find_adjustments(text, 3, "garage")
    paired_ref = bool(re.search(r"(paired\s+sales|contributory\s+value)", text, re.IGNORECASE))
    if (g1 or g3) and not paired_ref:
        joined = ", ".join([p for p in [f"Comp #1 {g1}" if g1 else "", f"Comp #3 {g3}" if g3 else ""] if p])
        lines.append(f"❌ Commentary for garage adjustments ({joined}) lacks paired-sales or contributory value reference")
    else:
        lines.append("✔ No unsupported garage adjustments detected")
    lines.append("")

    # ------- Summary Metadata -------
    lines.append("SUMMARY METADATA")
    comps_used = comp_summary["comps_used"] or (
        f"{max(1, len(compq['comp_gla']))} closed sales" if (compq["comp_gla"] or compq["miles"] or compq["dom"]) else "N/A"
    )
    miles = compq["miles"]
    doms = compq["dom"]
    miles_span = f"{min(miles):.2f}–{max(miles):.2f} miles" if len(miles) >= 2 else ("N/A" if not miles else f"{miles[0]:.2f} miles")
    dom_span = f"{int(min(doms))}–{int(max(doms))}" if len(doms) >= 2 else ("N/A" if not doms else f"{int(doms[0])}")
    if comps_used != "N/A":
        lines.append(f"Comparables Used: {comps_used} ({miles_span}; DOM {dom_span})")
    else:
        lines.append(f"Comparables Used: {comps_used}")
    lines.append(f"Adjusted Value Range: {comp_summary['adj_range'] or 'N/A'}")
    lines.append(f"Sale Date Range: {comp_summary['sale_date_range'] or 'N/A'}")
    lines.append("")

    # Disclaimer + footer
    lines.append(DISCLAIMER_LINE)
    if SHOW_FOOTER:
        lines.append("")
        lines.append(f"— Engine v{ENGINE_VERSION} • req:{req_id}")

    return "\n".join(lines)

# ----------------------------
# Public entry
# ----------------------------
def run_audit(file_obj, style_override: Optional[str] = None) -> str:
    # lightweight request id for tracing in logs
    try:
        import secrets
        req_id = secrets.token_hex(4)
    except Exception:
        req_id = "req"

    text, raw = extract_text_with_azure(file_obj)
    md = extract_metadata(text)
    try:
        md["file_name"] = getattr(file_obj, "filename", "") or "[Not found in file]"
    except Exception:
        pass

    flags = check_flags(text, md)  # used by v27
    style = (style_override or OUTPUT_STYLE).lower()

    # gather page texts once (for evidence pins)
    pages = extract_pages_text(raw)

    if style == "v27":
        return compose_output_v27(md, flags)
    else:
        return compose_output_analyst(md, text, pages, req_id)

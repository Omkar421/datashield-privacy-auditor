import hashlib
import io
import json
import re
import sqlite3
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

APP_DIR = Path(__file__).parent
DB_PATH = APP_DIR / "datashield.db"

st.set_page_config(page_title="DataShield", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.main { background:#f8fafc; }
.hero { background:linear-gradient(120deg,#0f172a,#0f766e); color:white; padding:1.6rem 2rem; border-radius:16px; margin-bottom:1.2rem; }
.hero h1 { margin:0; font-size:2.2rem; }
.hero p { margin:.4rem 0 0; opacity:.9; }
div[data-testid="stMetric"] { background:white; border:1px solid #e5e7eb; border-radius:12px; padding:.8rem; }
</style>
""", unsafe_allow_html=True)

# ----------------------------- Storage -----------------------------
def connect():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with connect() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            file_type TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            findings INTEGER NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            scanned_at TEXT NOT NULL
        )""")
        conn.commit()


def save_scan(result):
    with connect() as conn:
        conn.execute("INSERT INTO scans (filename,file_type,sha256,findings,risk_score,risk_level,scanned_at) VALUES (?,?,?,?,?,?,?)", (
            result["filename"], result["file_type"], result["sha256"], len(result["findings"]), result["risk_score"], result["risk_level"], datetime.now().isoformat(timespec="seconds")))
        conn.commit()


def history():
    with connect() as conn:
        return pd.read_sql_query("SELECT * FROM scans ORDER BY id DESC", conn)


init_db()

# ----------------------------- Detection engine -----------------------------
PATTERNS = {
    "Email address": (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", 8),
    "Phone number": (r"(?<![A-Za-z0-9])(?:\+?\d[\d ()-]{8,}\d)(?![A-Za-z0-9])", 7),
    "Credit-card-like number": (r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)", 25),
    "IPv4 address": (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", 5),
    "API key or token": (r"\b(?:sk|pk|api|token|secret)[_-]?[A-Za-z0-9_-]{12,}\b", 25),
    "Password-like field": (r"(?i)\b(?:password|passwd|pwd|secret)\s*[:=]\s*[^\s,;]{4,}", 22),
    "Government ID-like value": (r"\b[A-Z]{2,5}[ -]?\d{4,12}\b", 15),
    "AWS access key": (r"\bAKIA[0-9A-Z]{16}\b", 30),
    "Private key marker": (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", 35),
}


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def mask_value(value):
    if len(value) <= 6:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def scan_text(text, filename, file_type, raw_bytes):
    findings = []
    redacted = text
    for category, (pattern, weight) in PATTERNS.items():
        matches = list(re.finditer(pattern, text))
        for match in matches:
            value = match.group(0)
            findings.append({"type": category, "value": value, "masked_value": mask_value(value), "line": text[:match.start()].count("\n") + 1, "weight": weight})
        redacted = re.sub(pattern, lambda m: f"[{category.upper()} REDACTED]", redacted)
    counts = pd.Series([f["type"] for f in findings]).value_counts().to_dict() if findings else {}
    raw_score = sum(f["weight"] for f in findings)
    score = min(100, raw_score)
    level = "High" if score >= 60 else "Medium" if score >= 25 else "Low"
    return {"filename": filename, "file_type": file_type, "sha256": sha256_bytes(raw_bytes), "findings": findings, "counts": counts, "risk_score": score, "risk_level": level, "redacted": redacted}


def scan_upload(uploaded):
    raw = uploaded.getvalue()
    name = uploaded.name.lower()
    if name.endswith(".csv"):
        try:
            df = pd.read_csv(io.BytesIO(raw), dtype=str).fillna("")
            text = df.to_csv(index=False)
            file_type = "CSV"
        except Exception:
            text, file_type = raw.decode("utf-8", errors="replace"), "Text"
    elif name.endswith(".json"):
        try:
            text = json.dumps(json.loads(raw.decode("utf-8")), indent=2)
            file_type = "JSON"
        except Exception:
            text, file_type = raw.decode("utf-8", errors="replace"), "Text"
    else:
        text, file_type = raw.decode("utf-8", errors="replace"), "Text/Log"
    return scan_text(text, uploaded.name, file_type, raw)


def make_report(result):
    lines = [
        "DATASHIELD PRIVACY AUDIT REPORT",
        "=" * 34,
        f"File: {result['filename']}",
        f"SHA-256: {result['sha256']}",
        f"Risk level: {result['risk_level']}",
        f"Risk score: {result['risk_score']}/100",
        f"Findings: {len(result['findings'])}",
        "",
        "Finding summary:",
    ]
    for key, value in result["counts"].items():
        lines.append(f"- {key}: {value}")
    lines += ["", "Note: This report uses pattern-based detection and requires human review."]
    return "\n".join(lines)


# ----------------------------- Navigation -----------------------------
st.sidebar.title("🛡️ DataShield")
st.sidebar.caption("Privacy auditing and data-leakage detection")
page = st.sidebar.radio("Navigation", ["Privacy Scanner", "Audit History", "About Project"])
st.sidebar.divider()
st.sidebar.info("Analyze only authorized files. The app processes uploaded data in memory and stores scan metadata, not the original file contents.")

if page == "Privacy Scanner":
    st.markdown('<div class="hero"><h1>DataShield</h1><p>A smart sensitive data leakage detection and privacy auditing system.</p></div>', unsafe_allow_html=True)
    st.write("Upload a text, CSV, JSON, or log file. DataShield detects common personally identifiable information and exposed secrets, then creates a redacted copy.")
    uploaded = st.file_uploader("Upload an authorized file", type=["txt", "csv", "json", "log"])
    if uploaded:
        if st.button("Scan file", type="primary"):
            result = scan_upload(uploaded)
            save_scan(result)
            st.session_state["result"] = result
    result = st.session_state.get("result")
    if result:
        st.divider()
        a, b, c, d = st.columns(4)
        a.metric("Findings", len(result["findings"]))
        b.metric("Risk score", f"{result['risk_score']}/100")
        c.metric("Risk level", result["risk_level"])
        d.metric("SHA-256", result["sha256"][:12] + "...")
        st.progress(result["risk_score"] / 100, text=f"Privacy risk: {result['risk_score']}/100")
        if result["risk_level"] == "High":
            st.error("High privacy risk: sensitive information or secrets require immediate review and redaction.")
        elif result["risk_level"] == "Medium":
            st.warning("Medium privacy risk: review detected personal or operational information before sharing.")
        else:
            st.success("Low privacy risk based on the configured detection patterns.")
        left, right = st.columns([1, 1])
        with left:
            st.subheader("Finding summary")
            summary = pd.DataFrame([{"Data type": k, "Matches": v} for k, v in result["counts"].items()])
            if summary.empty:
                st.info("No configured sensitive-data patterns were detected.")
            else:
                st.dataframe(summary, use_container_width=True, hide_index=True)
                st.subheader("Detected values (masked)")
                details = pd.DataFrame([{ "Type": f["type"], "Masked value": f["masked_value"], "Line": f["line"] } for f in result["findings"]])
                st.dataframe(details, use_container_width=True, hide_index=True)
        with right:
            st.subheader("Privacy audit report")
            st.code(make_report(result), language="text")
            st.download_button("Download audit report", make_report(result), "datashield_audit_report.txt", "text/plain")
            st.download_button("Download redacted file", result["redacted"], f"redacted_{result['filename']}", "text/plain")
        st.caption("Detection is pattern-based and may produce false positives or miss novel formats. Always perform human review before sharing a file.")

elif page == "Audit History":
    st.title("Privacy Audit History")
    df = history()
    if df.empty:
        st.info("No scan records yet. Upload a file from the Privacy Scanner page.")
    else:
        a, b, c, d = st.columns(4)
        a.metric("Total scans", len(df))
        b.metric("High risk", int((df["risk_level"] == "High").sum()))
        c.metric("Medium risk", int((df["risk_level"] == "Medium").sum()))
        d.metric("Low risk", int((df["risk_level"] == "Low").sum()))
        st.dataframe(df.rename(columns={"id":"ID", "filename":"File", "file_type":"Type", "sha256":"SHA-256", "findings":"Findings", "risk_score":"Score", "risk_level":"Risk Level", "scanned_at":"Scanned At"}), use_container_width=True, hide_index=True)
        st.download_button("Download history CSV", df.to_csv(index=False), "datashield_audit_history.csv", "text/csv")

else:
    st.title("About DataShield")
    st.markdown("""
    ### Project scope
    DataShield is a cybersecurity and privacy project that detects sensitive information in authorized files. It supports privacy audits, data-loss prevention demonstrations, secure redaction, and evidence integrity verification.

    ### Detection categories
    - Email addresses and phone numbers
    - Credit-card-like numbers
    - IP addresses
    - Password-like fields and API tokens
    - AWS access keys and private-key markers
    - Government-ID-like values

    ### Security and privacy design
    - Original file content is not saved to the database
    - SHA-256 hash provides an integrity fingerprint
    - Detected values are masked in the interface
    - Redacted output is available for controlled download
    - Audit history stores metadata and risk results

    ### Ethical use
    Scan only files you own or are authorized to audit. This is an educational pattern-based analyzer, not a legal compliance certification or a guarantee that a file contains no sensitive data.
    """)
    st.info("For production use, add authentication, encryption at rest, managed secrets, retention controls, malware scanning, and organization-specific detection rules.")

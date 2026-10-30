# DataShield: A Smart Sensitive Data Leakage Detection and Privacy Auditing System

DataShield is a cybersecurity-focused Streamlit application that scans authorized text, CSV, JSON, and log files for common sensitive-data patterns, calculates privacy risk, masks detected values, and produces an audit report.

## Features

- Detects emails, phone numbers, credit-card-like numbers, IP addresses, API tokens, passwords, government-ID-like values, AWS keys, and private-key markers
- Explainable Low, Medium, and High privacy-risk score
- SHA-256 integrity hash for every scanned file
- Masked findings view so sensitive values are not displayed in plain text
- Redacted file download
- Text audit-report download
- SQLite audit history storing metadata, not original file contents
- CSV history export

## Run locally

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

## Deploy on Streamlit Community Cloud

1. Create a GitHub repository.
2. Upload `app.py`, `requirements.txt`, and `README.md`.
3. Open [share.streamlit.io](https://share.streamlit.io/) and sign in with GitHub.
4. Select **Create app**.
5. Choose your repository and branch.
6. Set the main file path to `app.py`.
7. Click **Deploy**.

## Security and privacy scope

DataShield processes uploaded files in memory and stores scan metadata and SHA-256 hashes rather than the original file contents. Detection is pattern-based and may produce false positives or miss novel formats; it is not a legal compliance certification. Scan only files you own or are authorized to audit.

For production deployment, add authentication, encryption at rest, managed secrets, retention controls, malware scanning, organization-specific detection rules, and a managed database.

## Technology stack

Python · Streamlit · SQLite · Pandas · hashlib · regular expressions

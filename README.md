# AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

Working prototype for **SIH26106**. Upload a raw `.eml` file and get:

- A fraud score (0-100) from a TF-IDF + Logistic Regression NLP/ML classifier
  combined with rule-based social-engineering signal detection
- SPF / DKIM / DMARC header forensics
- Origin IP extraction from the `Received:` header chain, with
  GeoLocation (country/city/ISP) + WHOIS + VPN/hosting detection
- A downloadable PDF forensic report with a confidence-scored verdict

## Project Structure

```
email-forensics-prototype/
├── app/
│   ├── main.py              # Flask app (routes + dashboard)
│   ├── parser.py             # .eml parsing, header/IP extraction
│   ├── auth_check.py         # SPF/DKIM/DMARC verification
│   ├── nlp_detector.py       # ML + rule-based fraud scoring
│   ├── geolocation.py        # IP geolocation + WHOIS + VPN detection
│   ├── scoring.py            # Combines everything into one case
│   └── report_generator.py   # PDF forensic report generation
├── templates/                # HTML (upload page + dashboard)
├── static/style.css
├── sample_emails/             # 1 phishing + 1 legitimate test email
└── requirements.txt
```

## Setup (Step by Step)

**1. Make sure Python 3.10+ is installed**
```bash
python3 --version
```

**2. (Recommended) Create a virtual environment**
```bash
cd email-forensics-prototype
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Run the app**
```bash
python3 -m app.main
```

**5. Open the dashboard**
Go to **http://127.0.0.1:5000** in your browser.

**6. Test it**
Upload one of the sample files in `sample_emails/`:
- `phishing_sample.eml` → should score high (~90+/100, verdict FRAUDULENT/PHISHING)
- `legitimate_sample.eml` → should score low (~15/100, verdict LIKELY LEGITIMATE)

You can also drag in any real `.eml` file you export from Gmail/Outlook
("Show original" / "Download message" → save as `.eml`).

## How Each Piece Works

| Stage | File | What it does |
|---|---|---|
| 1. Ingestion | `parser.py` | Reads the raw email, extracts headers, body, URLs, attachments, and the full `Received:` hop chain |
| 2. Content detection | `nlp_detector.py` | TF-IDF + Logistic Regression model (trained on an embedded sample dataset) scores phishing probability; a rule-based layer flags urgency/BEC phrases for explainability |
| 3. Header forensics | `auth_check.py` | Reads the `Authentication-Results` header (what Gmail/Outlook already checked) and can also do a live DNS lookup of SPF/DMARC records as a fallback |
| 4. Origin trace | `geolocation.py` | Extracts the oldest public IP from the Received chain, geolocates it (ip-api.com), runs WHOIS on the sender domain, and flags known VPN/hosting providers |
| 5. Scoring | `scoring.py` | Combines all four signals into one 0-100 fraud score + plain-English reasons |
| 6. Reporting | `report_generator.py` | Renders everything into a downloadable PDF with a forensic disclaimer |

## Important Notes

- **Internet access is required** for live geolocation, WHOIS, and DNS-based
  SPF/DMARC fallback lookups. If you're offline, those sections will show
  `"error"` values gracefully instead of crashing — the ML/content scoring
  and header-forensics-from-existing-headers still work fully offline.
- The bundled ML model is trained on a **small embedded demo dataset**
  (~50 examples) purely to show a working pipeline. For a real deployment,
  retrain `nlp_detector.py` on a proper corpus (e.g. Nazario Phishing Corpus
  + Enron ham dataset) for production-grade accuracy.
- Geolocation is **confidence-scored, not absolute** — if the origin IP
  belongs to a VPN/hosting provider, the report explicitly flags that the
  traced location is unreliable. This is intentional: over-claiming
  attribution is a real risk in a forensic tool.
- This is a hackathon-scope prototype (single-process Flask dev server,
  in-memory case store). For production: add a real database, auth on the
  dashboard, a maintained VPN/hosting IP-range feed instead of keyword
  matching, and swap the dev server for gunicorn/uwsgi behind nginx.

## Extending It

- **Graph-based campaign correlation** (linking multiple emails/domains to
  one attacker) — add a Neo4j-backed module that stores each case's
  IP/domain/sender and queries for overlaps across cases.
- **Mail server integration** — replace the manual upload with an IMAP/API
  listener so incoming mail is scored automatically.
- **Better geolocation** — swap `ip-api.com` for MaxMind GeoLite2 (offline
  database, more reliable at scale, no rate limits).

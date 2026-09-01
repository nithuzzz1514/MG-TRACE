"""
scoring.py
Pulls together parser + auth_check + nlp_detector + geolocation into
one case object: a fraud score, a confidence-scored attribution, and
a human-readable list of "why we think this" reasons for the analyst.
"""

import uuid
from datetime import datetime, timezone

from . import parser, auth_check, nlp_detector, geolocation


def build_case(eml_path: str = None, eml_bytes: bytes = None) -> dict:
    if eml_path:
        parsed = parser.parse_email_file(eml_path)
    elif eml_bytes:
        parsed = parser.parse_email_bytes(eml_bytes)
    else:
        raise ValueError("Provide either eml_path or eml_bytes")

    # ---- 1. Header / protocol forensics ----
    auth_result = auth_check.run_full_auth_check(
        parsed["from"], parsed["auth_results_header"]
    )

    reply_to_mismatch = False
    if parsed["reply_to"]:
        from_domain = auth_check.extract_domain(parsed["from"])
        reply_domain = auth_check.extract_domain(parsed["reply_to"])
        reply_to_mismatch = bool(from_domain and reply_domain and from_domain != reply_domain)

    # ---- 2. Content / NLP-ML fraud scoring ----
    nlp_result = nlp_detector.score_email_text(parsed["subject"], parsed["body"])

    # ---- 3. Geolocation + WHOIS ----
    geo_result = {}
    whois_result = {}
    if parsed["origin_ip"]:
        geo_result = geolocation.geolocate_ip(parsed["origin_ip"])

    from_domain = auth_check.extract_domain(parsed["from"])
    if from_domain:
        whois_result = geolocation.whois_lookup(from_domain)

    # ---- 4. Combine into one fraud score (0-100) ----
    score = 0
    reasons = []

    score += nlp_result["combined_score"] * 45
    if nlp_result["rule_hits"]:
        reasons.append(
            f"Urgency/social-engineering phrases detected: {', '.join(nlp_result['rule_hits'][:5])}"
        )

    if auth_result["spf"] in ("fail", "softfail", "no_record"):
        score += 15
        reasons.append(f"SPF check: {auth_result['spf']}")
    if auth_result["dkim"] in ("fail",):
        score += 15
        reasons.append(f"DKIM check: {auth_result['dkim']}")
    if auth_result["dmarc"] in ("fail",):
        score += 10
        reasons.append(f"DMARC check: {auth_result['dmarc']}")

    if reply_to_mismatch:
        score += 10
        reasons.append("Reply-To domain differs from From domain")

    if geo_result.get("likely_hosting_or_vpn"):
        score += 5
        reasons.append("Origin IP belongs to a known hosting/VPN provider (identity likely masked)")

    if parsed["attachments"]:
        score += 5
        reasons.append(f"Contains attachment(s): {', '.join(parsed['attachments'])}")

    score = round(min(score, 100), 1)

    if score >= 70:
        verdict = "FRAUDULENT / PHISHING"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY LEGITIMATE"

    case = {
        "case_id": str(uuid.uuid4())[:8].upper(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "email_summary": {
            "subject": parsed["subject"],
            "from": parsed["from"],
            "to": parsed["to"],
            "reply_to": parsed["reply_to"],
            "date": parsed["date"],
            "urls_found": parsed["urls"],
            "attachments": parsed["attachments"],
        },
        "content_analysis": nlp_result,
        "header_forensics": {
            **auth_result,
            "reply_to_mismatch": reply_to_mismatch,
        },
        "origin_trace": {
            "origin_ip": parsed["origin_ip"],
            "geolocation": geo_result,
            "attribution_confidence": geolocation.confidence_from_geo(geo_result) if geo_result else "unknown",
            "whois": whois_result,
        },
        "fraud_score": score,
        "verdict": verdict,
        "reasons": reasons,
    }
    return case

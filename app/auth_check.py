"""
auth_check.py
Two layers of authentication checking:

1. PASSIVE (always works, no network needed): parse the
   'Authentication-Results' header that receiving mail servers
   (Gmail, Outlook, etc.) already stamp onto every email with the
   SPF/DKIM/DMARC verdict THEY computed at delivery time.

2. ACTIVE (needs internet/DNS): look up the sender domain's live
   SPF and DMARC records ourselves, for cases where the header is
   missing or the email is being re-analyzed later.
"""

import re

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


def parse_authentication_results(auth_header: str) -> dict:
    """
    Parses a header like:
    'mx.google.com; spf=pass ... dkim=pass ... dmarc=pass (p=REJECT) ...'
    into a clean dict. Returns 'unknown' for any check not present.
    """
    result = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
    if not auth_header:
        return result

    for check in ("spf", "dkim", "dmarc"):
        match = re.search(rf"{check}=(\w+)", auth_header, re.IGNORECASE)
        if match:
            result[check] = match.group(1).lower()
    return result


def lookup_spf_record(domain: str) -> str | None:
    """Active DNS TXT lookup for the domain's SPF record. Needs network."""
    if not DNS_AVAILABLE:
        return None
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        for rdata in answers:
            txt = b"".join(rdata.strings).decode(errors="ignore")
            if txt.startswith("v=spf1"):
                return txt
    except Exception:
        return None
    return None


def lookup_dmarc_record(domain: str) -> str | None:
    """Active DNS TXT lookup for _dmarc.<domain>. Needs network."""
    if not DNS_AVAILABLE:
        return None
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        for rdata in answers:
            txt = b"".join(rdata.strings).decode(errors="ignore")
            if "v=DMARC1" in txt:
                return txt
    except Exception:
        return None
    return None


def extract_domain(email_address: str) -> str | None:
    match = re.search(r"@([\w.-]+)", email_address or "")
    return match.group(1).lower() if match else None


def dmarc_policy_from_record(record: str) -> str:
    if not record:
        return "none"
    match = re.search(r"p=(\w+)", record, re.IGNORECASE)
    return match.group(1).lower() if match else "none"


def run_full_auth_check(from_address: str, auth_results_header: str) -> dict:
    """
    Combines passive header parsing with an active DNS fallback
    (only attempted if the passive header is missing/incomplete).
    Returns a normalized verdict + a risk contribution used by the
    scoring engine.
    """
    passive = parse_authentication_results(auth_results_header)
    domain = extract_domain(from_address)

    spf, dkim, dmarc = passive["spf"], passive["dkim"], passive["dmarc"]

    active_dmarc_policy = None
    if dmarc == "unknown" and domain and DNS_AVAILABLE:
        record = lookup_dmarc_record(domain)
        if record is not None:
            active_dmarc_policy = dmarc_policy_from_record(record)
            dmarc = "pass" if active_dmarc_policy in ("none",) else "policy_present"

    if spf == "unknown" and domain and DNS_AVAILABLE:
        record = lookup_spf_record(domain)
        spf = "record_found" if record else "no_record"

    failures = sum(1 for v in (spf, dkim, dmarc) if v in ("fail", "softfail", "no_record"))

    return {
        "domain": domain,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "dmarc_policy": active_dmarc_policy,
        "failure_count": failures,
        "dns_lookups_available": DNS_AVAILABLE,
    }

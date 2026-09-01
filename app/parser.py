"""
parser.py
Parses a raw .eml file: pulls out headers, body text, links,
attachments list, and the chain of "Received:" hops so we can
later extract the originating IP address.
"""

import email
import re
from email import policy


IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")

# Private / reserved ranges we should NOT treat as the "origin" —
# these are internal hops, not the attacker's real-world server.
PRIVATE_IP_PREFIXES = (
    "10.", "127.", "169.254.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
)


def is_private_ip(ip: str) -> bool:
    return ip.startswith(PRIVATE_IP_PREFIXES)


def load_email(path: str):
    """Load a .eml file from disk and return an email.message.EmailMessage."""
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)
    return msg


def load_email_from_bytes(raw_bytes: bytes):
    """Load a .eml file from raw bytes (e.g. an uploaded file)."""
    return email.message_from_bytes(raw_bytes, policy=policy.default)


def get_body_text(msg) -> str:
    """Return the best-effort plain-text body of the email."""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain":
                try:
                    return part.get_content()
                except Exception:
                    continue
        # fall back to html if no plain text part found
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                try:
                    return re.sub("<[^<]+?>", " ", part.get_content())
                except Exception:
                    continue
        return ""
    else:
        try:
            return msg.get_content()
        except Exception:
            return ""


def get_attachments(msg):
    names = []
    if msg.is_multipart():
        for part in msg.walk():
            filename = part.get_filename()
            if filename:
                names.append(filename)
    return names


def get_urls(body_text: str):
    return list(dict.fromkeys(URL_PATTERN.findall(body_text)))  # de-dup, keep order


def get_received_chain(msg):
    """
    Return all 'Received:' header lines, oldest hop LAST in the header
    block but note: email headers list Received top-to-bottom as
    newest-first (closest to you) to oldest-last (closest to sender).
    We reverse so index 0 = oldest = closest to the true origin.
    """
    received = msg.get_all("Received") or []
    return list(reversed(received))


def extract_origin_ip(msg):
    """
    Walk the Received chain from oldest hop onward and return the
    first PUBLIC IP address found. That is our best-effort guess at
    the true originating server.
    """
    chain = get_received_chain(msg)
    for hop in chain:
        ips = IP_PATTERN.findall(hop)
        for ip in ips:
            if not is_private_ip(ip):
                return ip, hop
    # fallback: sometimes the origin IP only appears in X-Originating-IP
    xoip = msg.get("X-Originating-IP")
    if xoip:
        ips = IP_PATTERN.findall(xoip)
        if ips:
            return ips[0], xoip
    return None, None


def parse_email_file(path: str) -> dict:
    msg = load_email(path)
    return _build_summary(msg)


def parse_email_bytes(raw_bytes: bytes) -> dict:
    msg = load_email_from_bytes(raw_bytes)
    return _build_summary(msg)


def _build_summary(msg) -> dict:
    body = get_body_text(msg)
    origin_ip, origin_hop = extract_origin_ip(msg)

    return {
        "subject": msg.get("Subject", ""),
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "reply_to": msg.get("Reply-To", ""),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "return_path": msg.get("Return-Path", ""),
        "body": body,
        "urls": get_urls(body),
        "attachments": get_attachments(msg),
        "received_chain": get_received_chain(msg),
        "origin_ip": origin_ip,
        "origin_hop_raw": origin_hop,
        "auth_results_header": msg.get("Authentication-Results", ""),
        "raw_message": msg,
    }

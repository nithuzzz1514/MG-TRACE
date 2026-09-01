"""
geolocation.py
Resolves an IP address to a country/city/ISP using a free lookup API
(ip-api.com — no key needed for light/non-commercial use), with a
local fallback so the app degrades gracefully if there's no internet
access or the request fails/rate-limits.

Also does a best-effort WHOIS lookup for the sender's domain, and
flags IPs that belong to known VPN/hosting/cloud providers -- since
those substantially lower our confidence in the traced location.
"""

import re
import socket

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import whois as whois_lib
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

# python-whois opens a raw socket to the registry's WHOIS server with
# no timeout of its own, so on a restricted/offline network it can
# hang indefinitely instead of failing fast. Cap it globally.
WHOIS_SOCKET_TIMEOUT_SECONDS = 5


# A short illustrative list of well-known cloud/hosting ASN name
# fragments. Real deployments should pull a maintained hosting/VPN
# IP-range feed instead of matching on org name text.
HOSTING_KEYWORDS = [
    "amazon", "aws", "google cloud", "microsoft azure", "digitalocean",
    "linode", "ovh", "hetzner", "vultr", "nordvpn", "expressvpn",
    "cloudflare", "tor exit", "m247", "choopa",
]


def geolocate_ip(ip: str) -> dict:
    """
    Looks up country/city/ISP/lat-long for an IP via ip-api.com.
    Returns a dict with an 'error' key set if the lookup fails
    (no internet, rate limited, private IP, etc.) so callers can
    show an honest "location unknown" state instead of guessing.
    """
    if not ip:
        return {"error": "no_ip_provided"}

    if not REQUESTS_AVAILABLE:
        return {"error": "requests_library_not_available"}

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,country,regionName,city,isp,org,lat,lon,query"},
            timeout=5,
        )
        data = resp.json()
        if data.get("status") != "success":
            return {"error": data.get("message", "lookup_failed")}

        org_text = f"{data.get('isp', '')} {data.get('org', '')}".lower()
        is_hosting = any(kw in org_text for kw in HOSTING_KEYWORDS)

        return {
            "ip": data.get("query", ip),
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
            "likely_hosting_or_vpn": is_hosting,
        }
    except Exception as e:
        return {"error": f"lookup_exception: {e}"}


def whois_lookup(domain: str) -> dict:
    if not domain:
        return {"error": "no_domain_provided"}
    if not WHOIS_AVAILABLE:
        return {"error": "whois_library_not_available"}

    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(WHOIS_SOCKET_TIMEOUT_SECONDS)
        w = whois_lib.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        return {
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": str(creation_date) if creation_date else None,
            "country": w.country,
            "name_servers": w.name_servers,
        }
    except Exception as e:
        return {"error": f"whois_exception: {e}"}
    finally:
        socket.setdefaulttimeout(old_timeout)


def confidence_from_geo(geo_result: dict) -> str:
    """
    Turns the raw geolocation result into a plain-language confidence
    label for the forensic report -- this is the honesty layer that
    stops the tool from over-claiming attribution.
    """
    if geo_result.get("error"):
        return "unknown"
    if geo_result.get("likely_hosting_or_vpn"):
        return "low (VPN/hosting/cloud IP -- likely not attacker's real location)"
    return "moderate-high (residential/ISP-assigned IP)"

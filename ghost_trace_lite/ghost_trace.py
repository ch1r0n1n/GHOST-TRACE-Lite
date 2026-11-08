"""IOC syntax validation, IP classification, and opt-in VirusTotal enrichment."""

import ipaddress
import json
import re
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
PRIVATE_V4 = tuple(map(ipaddress.ip_network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))
UNIQUE_LOCAL = ipaddress.ip_network("fc00::/7")
SHARED = ipaddress.ip_network("100.64.0.0/10")
DOCUMENTATION = tuple(map(ipaddress.ip_network, (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "3fff::/20",
)))
LOCAL_DOMAIN_SUFFIXES = (
    "localhost", "local", "internal", "test", "invalid", "example", "onion",
    "example.com", "example.net", "example.org",
)
MAX_RESPONSE_BYTES = 1024 * 1024


def normalize_domain(value):
    domain = value.strip().removesuffix(".")
    labels = domain.split(".")
    if (
        len(domain) > 253
        or len(labels) < 2
        or labels[-1].isdigit()
        or any(not LABEL.fullmatch(label) for label in labels)
    ):
        raise ValueError("expected a dotted ASCII hostname (use Punycode for IDNs)")
    return domain.lower()


def parse_ip(value):
    if "%" in value:
        raise ValueError("IPv6 zone identifiers are unsupported")
    return ipaddress.ip_address(value.strip())


def ip_scope(address):
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.is_unspecified:
        return "unspecified"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if address.is_multicast:
        return "multicast"
    if any(address in network for network in DOCUMENTATION):
        return "documentation"
    if address in SHARED:
        return "shared_address_space"
    if address in UNIQUE_LOCAL or any(address in network for network in PRIVATE_V4):
        return "private"
    if address.is_global and not address.is_reserved:
        return "public"
    return "special_use"


def inspect_ioc(value):
    try:
        address = parse_ip(value)
    except ValueError:
        return {"value": normalize_domain(value), "type": "domain"}
    return {"value": str(address), "type": f"ipv{address.version}", "scope": ip_scope(address)}


class NoRedirect(HTTPRedirectHandler):
    """Keep the API key on the original HTTPS origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def is_public_indicator(ioc):
    if ioc["type"] != "domain":
        return ioc["scope"] == "public"
    value = ioc["value"]
    return all(
        value != suffix and not value.endswith("." + suffix)
        for suffix in LOCAL_DOMAIN_SUFFIXES
    )


def validate_api_key(api_key, env_var):
    key = (api_key or "").strip()
    if not key:
        raise ValueError(f"Enter an API key in the menu or set {env_var}.")
    if not key.isascii() or any(not 33 <= ord(char) <= 126 for char in key):
        raise ValueError("The API key must contain only visible ASCII characters without spaces.")
    return key


def request_report(request, provider, summarize):
    try:
        with build_opener(NoRedirect()).open(request, timeout=10) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            return {"status": "error", "message": f"{provider} response exceeded the size limit."}
        return {"status": "ok", **summarize(json.loads(raw))}
    except HTTPError as error:
        code = error.code
        error.close()
        if code == 404:
            return {"status": "not_found", "message": f"{provider} has no report for this indicator."}
        messages = {
            401: f"{provider} rejected the API key.",
            403: f"{provider} denied access. Check the key and account permissions.",
            429: f"{provider} rate limit reached. Try again later.",
        }
        return {"status": "error", "message": messages.get(code, f"{provider} returned HTTP {code}.")}
    except (URLError, OSError, HTTPException):
        return {"status": "error", "message": f"{provider} could not be reached."}
    except (AttributeError, KeyError, TypeError, ValueError, RecursionError):
        return {"status": "error", "message": f"{provider} returned an unexpected response."}


def virustotal_summary(payload):
    stats = payload["data"]["attributes"].get("last_analysis_stats", {})
    if not isinstance(stats, dict):
        raise ValueError("expected an object for last_analysis_stats")
    return {"last_analysis_stats": {
        key: stats[key] for key in ("malicious", "suspicious", "harmless", "undetected", "timeout")
        if key in stats and type(stats[key]) is int and stats[key] >= 0
    }}


def virustotal_lookup(ioc, api_key):
    if not is_public_indicator(ioc):
        return {"status": "skipped", "message": "Lookup requires a public indicator."}
    try:
        key = validate_api_key(api_key, "VT_API_KEY")
    except ValueError as error:
        return {"status": "error", "message": str(error)}
    endpoint = "domains" if ioc["type"] == "domain" else "ip_addresses"
    url = f"https://www.virustotal.com/api/v3/{endpoint}/{quote(ioc['value'], safe='')}"
    request = Request(url, headers={"Accept": "application/json", "x-apikey": key})
    return request_report(request, "VirusTotal", virustotal_summary)

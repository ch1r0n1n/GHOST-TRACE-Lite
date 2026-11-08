"""Provider selection and concise reports for explicit public IOC lookups."""

import os
from urllib.parse import quote, urlencode
from urllib.request import Request

from .ghost_trace import is_public_indicator, request_report, validate_api_key, virustotal_lookup

PROVIDERS = {
    "virustotal": ("VirusTotal", "VT_API_KEY"),
    "shodan": ("Shodan", "SHODAN_API_KEY"),
    "otx": ("AlienVault OTX", "OTX_API_KEY"),
}
OTX_TYPES = {"ipv4": "IPv4", "ipv6": "IPv6", "domain": "domain"}


def lookup_key(provider, session_keys):
    return session_keys.get(provider) or os.getenv(PROVIDERS[provider][1], "")


def shodan_summary(payload):
    ports = payload["ports"]
    if not isinstance(ports, list):
        raise ValueError("expected a list of ports")
    summary = {"ports": sorted({port for port in ports if type(port) is int and 0 <= port <= 65535})}
    for field in ("org", "asn", "country_code", "last_update"):
        value = payload.get(field)
        if isinstance(value, str):
            summary[field] = value[:160]
    return summary


def otx_summary(payload):
    count = payload["pulse_info"]["count"]
    if type(count) is not int or count < 0:
        raise ValueError("expected a nonnegative pulse count")
    return {"pulse_count": count}


def enrich_indicator(ioc, provider, api_key):
    if provider == "virustotal":
        return virustotal_lookup(ioc, api_key)
    if provider == "shodan" and ioc["type"] == "domain":
        return {"status": "skipped", "message": "Shodan host lookup requires a public IP address."}
    if not is_public_indicator(ioc):
        return {"status": "skipped", "message": "Lookup requires a public indicator."}
    name, env_var = PROVIDERS[provider]
    try:
        key = validate_api_key(api_key, env_var)
    except ValueError as error:
        return {"status": "error", "message": str(error)}

    value = quote(ioc["value"], safe="")
    headers = {"Accept": "application/json"}
    if provider == "shodan":
        query = urlencode({"key": key, "minify": "true"})
        request = Request(f"https://api.shodan.io/shodan/host/{value}?{query}", headers=headers)
        return request_report(request, name, shodan_summary)
    indicator_type = OTX_TYPES[ioc["type"]]
    url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{value}/general"
    request = Request(url, headers={**headers, "X-OTX-API-KEY": key})
    return request_report(request, name, otx_summary)

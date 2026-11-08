"""Inspect one saved HTTP request header block with conservative redaction."""

import ipaddress
import re

from .ghost_trace import normalize_domain

TOKEN = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
HEADER_NAME = re.compile(TOKEN)
MEDIA_TYPE = re.compile(rf"{TOKEN}/{TOKEN}")
REQUEST_LINE = re.compile(r"([A-Z]{1,24}) [^\s]+ HTTP/(?:1\.0|1\.1|2(?:\.0)?|3(?:\.0)?)")
HOST = re.compile(r"(\[[0-9a-fA-F:.]+\]|[0-9a-zA-Z.-]+)(?::([0-9]{1,5}))?")
REDACTED = "[redacted]"


def safe_host(value):
    match = HOST.fullmatch(value)
    if not match:
        return REDACTED
    host, port = match.groups()
    if port and not 1 <= int(port) <= 65535:
        return REDACTED
    try:
        if host.startswith("["):
            host = f"[{ipaddress.IPv6Address(host[1:-1])}]"
        else:
            try:
                host = str(ipaddress.IPv4Address(host))
            except ValueError:
                host = normalize_domain(host)
    except ValueError:
        return REDACTED
    return f"{host}:{int(port)}" if port else host


def inspect_headers(path):
    method = None
    headers = []
    with path.open(encoding="utf-8-sig", newline=None) as source:
        for row, raw_line in enumerate(source, start=1):
            line = raw_line.rstrip("\r\n")
            if not line:
                break
            request = REQUEST_LINE.fullmatch(line) if row == 1 else None
            if request:
                method = request[1]
                continue
            name, separator, value = line.partition(":")
            if not separator or not HEADER_NAME.fullmatch(name):
                raise ValueError(f"{path.name}:{row}: expected a header name and colon")
            name = name.lower()
            value = value.strip()
            safe_value = REDACTED
            if name == "host":
                safe_value = safe_host(value)
            elif name == "content-type":
                media_type = value.split(";", 1)[0].strip().lower()
                if MEDIA_TYPE.fullmatch(media_type):
                    safe_value = media_type
            headers.append({"name": name, "value": safe_value})
    return {
        "method": method,
        "headers": headers,
        "redacted_count": sum(header["value"] == REDACTED for header in headers),
    }

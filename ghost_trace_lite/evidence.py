"""Typed evidence and validation shared by the CSV analysis modules."""

import csv
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from .ghost_trace import normalize_domain, parse_ip

AUTH_FIELDS = ("timestamp", "user", "host", "host_ip", "src_ip", "outcome")
FLOW_FIELDS = ("timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "bytes")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}")


@dataclass(frozen=True)
class AuthEvent:
    row: int
    timestamp: datetime
    user: str
    host: str
    host_ip: str
    src_ip: str
    outcome: str

    @property
    def evidence_id(self):
        return f"auth:{self.row}"

    @property
    def login_key(self):
        return self.user, self.host, self.host_ip, self.src_ip


@dataclass(frozen=True)
class FlowEvent:
    row: int
    timestamp: datetime
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    bytes: int
    dst_domain: str

    @property
    def evidence_id(self):
        return f"flow:{self.row}"


def clean_identifier(value, field):
    if not IDENTIFIER.fullmatch(value):
        raise ValueError(f"{field} must be 1–128 letters, digits, or . _ @ - and start alphanumeric")
    return value


def utc_timestamp(value):
    try:
        if "T" not in value and " " not in value:
            raise ValueError
        result = datetime.fromisoformat(value)
        if result.utcoffset() is None:
            raise ValueError
        return result.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise ValueError("timestamp must be ISO 8601 with an explicit UTC offset or Z") from None


def auth_event(row, values):
    outcome = values["outcome"].lower()
    if outcome not in {"success", "failure"}:
        raise ValueError("outcome must be success or failure")
    return AuthEvent(
        row=row,
        timestamp=utc_timestamp(values["timestamp"]),
        user=clean_identifier(values["user"], "user"),
        host=clean_identifier(values["host"], "host"),
        host_ip=str(parse_ip(values["host_ip"])),
        src_ip=str(parse_ip(values["src_ip"])),
        outcome=outcome,
    )


def flow_event(row, values):
    try:
        port = int(values["dst_port"])
        size = int(values["bytes"])
    except ValueError:
        raise ValueError("dst_port and bytes must be integers") from None
    if not 0 <= port <= 65535 or size < 0:
        raise ValueError("dst_port must be 0–65535 and bytes must be nonnegative")
    protocol = values["protocol"].lower()
    if protocol not in {"tcp", "udp"}:
        raise ValueError("protocol must be tcp or udp")
    domain = values.get("dst_domain", "")
    return FlowEvent(
        row=row,
        timestamp=utc_timestamp(values["timestamp"]),
        src_ip=str(parse_ip(values["src_ip"])),
        dst_ip=str(parse_ip(values["dst_ip"])),
        dst_port=port,
        protocol=protocol,
        bytes=size,
        dst_domain=normalize_domain(domain) if domain else "",
    )


def read_events(path, required_fields, parse_event):
    events = []
    with path.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.reader(source, strict=True)
        try:
            fields = next(reader, [])
            missing = set(required_fields).difference(fields)
            if missing:
                raise ValueError(f"{path.name}: missing columns {', '.join(sorted(missing))}")
            if len(fields) != len(set(fields)):
                raise ValueError(f"{path.name}: duplicate column names")
            while True:
                row = reader.line_num + 1
                cells = next(reader, None)
                if cells is None:
                    break
                if not cells:
                    continue
                if len(cells) != len(fields):
                    raise ValueError(f"{path.name}:{row}: unexpected number of columns")
                try:
                    events.append(parse_event(row, dict(zip(fields, map(str.strip, cells)))))
                except ValueError as error:
                    raise ValueError(f"{path.name}:{row}: {error}") from None
        except csv.Error as error:
            raise ValueError(f"{path.name}:{reader.line_num}: malformed CSV ({error})") from None
    return sorted(events, key=lambda event: (event.timestamp, event.row))


def load_auth(path):
    return read_events(path, AUTH_FIELDS, auth_event)


def load_flows(path):
    return read_events(path, FLOW_FIELDS, flow_event)

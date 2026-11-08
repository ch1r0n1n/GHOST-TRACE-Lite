"""Detect bursts of failed logins for one user, target host, and source IP."""

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta

from .evidence import AuthEvent


@dataclass(frozen=True)
class Alert:
    failures: tuple[AuthEvent, ...]
    window_minutes: int

    @property
    def trigger(self):
        return self.failures[-1]

    @property
    def alert_id(self):
        return f"failed-logins:{self.trigger.row}"


def detect_failed_logins(events, threshold=3, window_minutes=5):
    window = timedelta(minutes=window_minutes)
    pending = defaultdict(deque)
    alerts = []
    for event in events:
        key = event.login_key
        if event.outcome == "success":
            pending.pop(key, None)
            continue
        failures = pending[key]
        while failures and event.timestamp - failures[0].timestamp > window:
            failures.popleft()
        failures.append(event)
        if len(failures) == threshold:
            alerts.append(Alert(tuple(failures), window_minutes))
            del pending[key]
    return alerts


def alert_record(alert):
    event = alert.trigger
    return {
        "id": alert.alert_id,
        "rule": "repeated_failed_logins",
        "user": event.user,
        "host": event.host,
        "host_ip": event.host_ip,
        "source_ip": event.src_ip,
        "first_failure": alert.failures[0].timestamp.isoformat(),
        "triggered_at": event.timestamp.isoformat(),
        "failure_count": len(alert.failures),
        "window_minutes": alert.window_minutes,
        "evidence_ids": [failure.evidence_id for failure in alert.failures],
    }

"""Link alerts to subsequent successful logins and nearby host traffic."""

from bisect import bisect_right
from collections import defaultdict
from datetime import timedelta


def auth_record(event):
    return {
        "id": event.evidence_id,
        "timestamp": event.timestamp.isoformat(),
        "type": f"login_{event.outcome}",
        "user": event.user,
        "host": event.host,
        "host_ip": event.host_ip,
        "source_ip": event.src_ip,
    }


def flow_record(flow):
    return {
        "id": flow.evidence_id,
        "timestamp": flow.timestamp.isoformat(),
        "type": "network_flow",
        "source_ip": flow.src_ip,
        "destination_ip": flow.dst_ip,
        "destination_port": flow.dst_port,
        "destination_domain": flow.dst_domain or None,
        "protocol": flow.protocol,
        "bytes": flow.bytes,
    }


def correlate(alerts, auth, flows, window_minutes=10):
    window = timedelta(minutes=window_minutes)
    successes_by_key = defaultdict(list)
    flows_by_source = defaultdict(list)
    for event in auth:
        if event.outcome == "success":
            successes_by_key[event.login_key].append(event)
    for flow in flows:
        flows_by_source[flow.src_ip].append(flow)

    # When bursts share a success, use the closest preceding burst for that login.
    by_success = {}
    for alert in alerts:
        trigger = alert.trigger
        successes = successes_by_key[trigger.login_key]
        index = bisect_right(successes, (trigger.timestamp, trigger.row),
                             key=lambda event: (event.timestamp, event.row))
        if index < len(successes):
            success = successes[index]
            if success.timestamp - trigger.timestamp <= window:
                by_success[success] = alert

    correlations = []
    timeline = {}
    for success, alert in sorted(by_success.items(), key=lambda pair: (pair[0].timestamp, pair[0].row)):
        candidates = flows_by_source[success.host_ip]
        start = bisect_right(candidates, success.timestamp, key=lambda flow: flow.timestamp)
        stop = bisect_right(candidates, window, key=lambda flow: flow.timestamp - success.timestamp)
        related_flows = candidates[start:stop]
        correlations.append({
            "alert_id": alert.alert_id,
            "success_evidence_id": success.evidence_id,
            "flow_evidence_ids": [flow.evidence_id for flow in related_flows],
        })
        for event in (*alert.failures, success):
            timeline[event.evidence_id] = auth_record(event)
        for flow in related_flows:
            timeline[flow.evidence_id] = flow_record(flow)
    return {
        "window_minutes": window_minutes,
        "correlations": correlations,
        "timeline": sorted(timeline.values(), key=lambda event: event["timestamp"]),
    }

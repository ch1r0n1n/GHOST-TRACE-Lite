"""Run the investigation and export a shared case as JSON, Markdown, and Mermaid."""

import json
from contextlib import suppress
from pathlib import Path

from .evidence import load_auth, load_flows
from .ghost_trace import inspect_ioc
from .ghost_vision import summarize_traffic
from .kage_ai import advise_case
from .kage_core import explain_alerts
from .phantom_hunter import correlate
from .sentinel import alert_record, detect_failed_logins
from .shadow_proxy import inspect_headers
from .shadow_recon import check_scope, load_scope
from .specter_map import observed_relationships, render_mermaid


def build_case(folder, threshold=3, detection_window=5, hunt_window=10):
    auth = load_auth(folder / "auth.csv")
    flows = load_flows(folder / "flows.csv")
    headers = inspect_headers(folder / "headers.txt")
    rules = load_scope(folder / "scope.txt")

    ips = {ip for event in auth for ip in (event.src_ip, event.host_ip)}
    ips.update(ip for flow in flows for ip in (flow.src_ip, flow.dst_ip))
    domains = {flow.dst_domain for flow in flows if flow.dst_domain}
    alerts = detect_failed_logins(auth, threshold, detection_window)

    case = {
        "schema_version": 1,
        "inputs": {"authentication_events": len(auth), "network_flows": len(flows)},
        "indicators": [inspect_ioc(value) for value in sorted(ips | domains)],
        "scope_checks": [check_scope(domain, rules) for domain in sorted(domains)],
        "detection_settings": {"threshold": threshold, "window_minutes": detection_window},
        "alerts": [alert_record(alert) for alert in alerts],
        "explanations": explain_alerts(alerts),
        "traffic": summarize_traffic(flows),
        "hunt": correlate(alerts, auth, flows, hunt_window),
        "headers": headers,
        "relationships": observed_relationships(auth, flows),
    }
    case["next_steps"] = advise_case(case)
    return case


def markdown_report(case, graph):
    hunt = case["hunt"]
    lines = [
        "# GHOST TRACE Lite case report", "",
        f"Reviewed {case['inputs']['authentication_events']} authentication events and "
        f"{case['inputs']['network_flows']} network flows.", "",
        f"Failed-login bursts **{len(case['alerts'])}** · "
        f"Correlated successful logins **{len(hunt['correlations'])}**", "",
        "## Detection", "",
    ]
    for explanation in case["explanations"]:
        evidence = ", ".join(explanation["evidence_ids"])
        lines.append(f"- **{explanation['alert_id']}**. {explanation['summary']} See {evidence}.")
    if not case["explanations"]:
        lines.append("No failed-login burst met the configured threshold.")
    lines.extend([
        "",
        "## Correlated timeline (UTC)", "",
        "Timing and a shared host IP identify leads for review. Confirm the activity with other evidence.",
        "",
    ])
    if hunt["timeline"]:
        lines.extend(["| UTC timestamp | Evidence | Observation |", "| --- | --- | --- |"])
        for event in hunt["timeline"]:
            if event["type"] == "network_flow":
                destination = event["destination_ip"]
                if event["destination_domain"]:
                    destination += f" ({event['destination_domain']})"
                details = (
                    f"`{event['source_ip']}` to `{destination}` over "
                    f"{event['protocol'].upper()} port {event['destination_port']} ({event['bytes']:,} bytes)"
                )
            else:
                outcome = event["type"].removeprefix("login_")
                details = f"Login {outcome} for `{event['user']}` on `{event['host']}` from `{event['source_ip']}`"
            lines.append(f"| {event['timestamp']} | `{event['id']}` | {details} |")
    else:
        lines.append("No matching successful login followed an alert within the configured window.")

    lines.extend(["", "## Network and indicators", ""])
    lines.append(f"The captured flows account for **{case['traffic']['total_bytes']:,} bytes**.")
    if case["traffic"]["top_sources"]:
        sources = ", ".join(
            f"`{source['ip']}` ({source['bytes']:,} bytes)" for source in case["traffic"]["top_sources"]
        )
        lines.extend(["", f"The highest-volume sources were {sources}."])
    lines.append("")
    for ioc in case["indicators"]:
        lines.append(f"- `{ioc['value']}` ({ioc.get('scope', 'domain')})")
    if not case["indicators"]:
        lines.append("No IP addresses or domains were present in the input CSVs.")

    lines.extend(["", "## Scope checks", ""])
    for check in case["scope_checks"]:
        status = "in scope" if check["in_scope"] else "out of scope"
        lines.append(f"- `{check['domain']}` — {status}")
    if not case["scope_checks"]:
        lines.append("No destination domains were available for scope checking.")

    lines.extend([
        "", "## HTTP evidence", "",
        f"Read {len(case['headers']['headers'])} headers. Redacted {case['headers']['redacted_count']} values.",
        "The sanitized headers are in `case.json`.",
        "", "## Next steps", "",
    ])
    for step in case["next_steps"]:
        evidence = ", ".join(step["evidence_ids"])
        suffix = f" See {evidence}." if evidence else ""
        lines.append(f"- {step['action']}{suffix}")
    lines.extend([
        "", "## Observed relationships", "",
        "The graph shows observed links across the input evidence.", "",
        "```mermaid", graph.rstrip(), "```", "",
    ])
    return "\n".join(lines)


def export_case(case, output: Path):
    # Prepare all content before claiming the output directory.
    graph = render_mermaid(case["relationships"])
    files = {
        "case.json": json.dumps(case, indent=2) + "\n",
        "case.md": markdown_report(case, graph),
        "relationships.mmd": graph,
    }
    output.mkdir(parents=True, exist_ok=False)
    try:
        for name, contents in files.items():
            (output / name).write_text(contents, encoding="utf-8", newline="\n")
    except (OSError, KeyboardInterrupt):
        for name in files:
            with suppress(OSError):
                (output / name).unlink(missing_ok=True)
        with suppress(OSError):
            output.rmdir()
        raise

"""Command-line entry points for the ten GHOST TRACE Lite modules."""

import argparse
import json
import sys
from pathlib import Path

from .enrichment import PROVIDERS, enrich_indicator, lookup_key
from .evidence import load_auth, load_flows
from .ghost_trace import inspect_ioc
from .ghost_vision import summarize_traffic
from .kage_core import explain_alerts
from .menu import run_menu
from .phantom_hunter import correlate
from .ronin_soc import build_case, export_case
from .sentinel import alert_record, detect_failed_logins
from .shadow_proxy import inspect_headers
from .shadow_recon import check_scope, load_scope
from .specter_map import observed_relationships, render_mermaid

DEMO_DIR = Path(__file__).with_name("demo_data")


def positive_int(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("expected a positive integer") from None
    if not 1 <= number <= 10080:
        raise argparse.ArgumentTypeError("expected an integer between 1 and 10080")
    return number


def add_detection_options(parser):
    parser.add_argument("--threshold", type=positive_int, default=3, help="failed logins required (default 3)")
    parser.add_argument("--window", type=positive_int, default=5, help="detection window in minutes (default 5)")


def add_hunt_options(parser):
    add_detection_options(parser)
    parser.add_argument("--hunt-window", type=positive_int, default=10, help="pivot window in minutes (default 10)")


def build_parser():
    parser = argparse.ArgumentParser(prog="ghost-trace", description="GHOST TRACE Lite investigation toolkit")
    commands = parser.add_subparsers(dest="command", required=True)

    ioc = commands.add_parser("ioc", help="GHOST TRACE — validate and classify an IP or domain")
    ioc.add_argument("value")
    lookup = ioc.add_mutually_exclusive_group()
    lookup.add_argument("--provider", choices=PROVIDERS, help="look up a public IOC with this provider")
    lookup.add_argument("--virustotal", dest="provider", action="store_const", const="virustotal",
                        help="alias for --provider virustotal")

    scope = commands.add_parser("scope", help="SHADOW RECON — check a hostname against scope rules")
    scope.add_argument("value")
    scope.add_argument("--rules", required=True, type=Path)

    detect = commands.add_parser("detect", help="SENTINEL — detect failed-login bursts")
    detect.add_argument("auth", type=Path)
    add_detection_options(detect)

    traffic = commands.add_parser("traffic", help="GHOST VISION — summarize network flows")
    traffic.add_argument("flows", type=Path)

    hunt = commands.add_parser("hunt", help="PHANTOM HUNTER — correlate successful logins and network flows")
    hunt.add_argument("auth", type=Path)
    hunt.add_argument("flows", type=Path)
    add_hunt_options(hunt)

    explain = commands.add_parser("explain", help="KAGE CORE — explain failed-login alerts")
    explain.add_argument("auth", type=Path)
    add_detection_options(explain)

    graph = commands.add_parser("map", help="SPECTER MAP — print an observed relationship graph")
    graph.add_argument("auth", type=Path)
    graph.add_argument("flows", type=Path)

    headers = commands.add_parser("headers", help="SHADOW PROXY — inspect and redact saved HTTP headers")
    headers.add_argument("path", type=Path)

    investigate = commands.add_parser("investigate", help="RONIN SOC — run a case and export reports")
    investigate.add_argument("folder", type=Path)
    investigate.add_argument("--out", type=Path, default=Path("ghost-trace-case"))
    add_hunt_options(investigate)

    advise = commands.add_parser("advise", help="KAGE AI — suggest next steps from local evidence")
    advise.add_argument("folder", type=Path)
    add_hunt_options(advise)

    demo = commands.add_parser("demo", help="run the bundled investigation offline")
    demo.add_argument("--out", type=Path, default=Path("ghost-trace-demo"))
    commands.add_parser("menu", help="open the interactive toolkit and API-key menu")
    return parser


def print_json(value):
    print(json.dumps(value, indent=2))


def run_command(args, session_keys):
    command = args.command
    if command == "ioc":
        indicator = inspect_ioc(args.value)
        if args.provider:
            key = lookup_key(args.provider, session_keys)
            indicator[args.provider] = enrich_indicator(indicator, args.provider, key)
        print_json(indicator)
        return int(bool(args.provider and indicator[args.provider]["status"] == "error"))
    if command == "scope":
        result = check_scope(args.value, load_scope(args.rules))
        print_json(result)
        return int(not result["in_scope"])
    if command == "traffic":
        print_json(summarize_traffic(load_flows(args.flows)))
    elif command == "headers":
        print_json(inspect_headers(args.path))
    elif command == "map":
        graph = observed_relationships(load_auth(args.auth), load_flows(args.flows))
        print(render_mermaid(graph), end="")
    elif command in {"detect", "explain", "hunt"}:
        auth = load_auth(args.auth)
        alerts = detect_failed_logins(auth, args.threshold, args.window)
        if command == "detect":
            print_json([alert_record(alert) for alert in alerts])
        elif command == "explain":
            print_json(explain_alerts(alerts))
        else:
            print_json(correlate(alerts, auth, load_flows(args.flows), args.hunt_window))
    else:
        if command == "demo":
            case = build_case(DEMO_DIR)
        else:
            case = build_case(args.folder, args.threshold, args.window, args.hunt_window)
        if command == "advise":
            print_json(case["next_steps"])
        else:
            export_case(case, args.out)
            print_json({
                "output": str(args.out),
                "alerts": len(case["alerts"]),
                "correlated_logins": len(case["hunt"]["correlations"]),
                "reports": ["case.md", "case.json", "relationships.mmd"],
            })
    return 0


def execute_command(args, session_keys):
    try:
        return run_command(args, session_keys)
    except (OSError, ValueError) as error:
        print(f"ghost-trace: {error}", file=sys.stderr)
        return 2


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "menu":
        def execute_menu_command(argv, session_keys):
            return execute_command(parser.parse_args(argv), session_keys)

        return run_menu(DEMO_DIR, execute_menu_command)
    return execute_command(args, {})

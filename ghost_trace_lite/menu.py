"""Interactive prompts for the existing CLI commands and in-memory API keys."""

import getpass
import warnings

from .enrichment import PROVIDERS, lookup_key
from .ghost_trace import validate_api_key

TOOLS = {
    "1": ("GHOST TRACE", "IOC validation and enrichment", "ioc"),
    "2": ("SHADOW RECON", "Check authorized scope", "scope"),
    "3": ("SENTINEL", "Detect failed logins", "detect"),
    "4": ("GHOST VISION", "Summarize network traffic", "traffic"),
    "5": ("PHANTOM HUNTER", "Correlate login and network evidence", "hunt"),
    "6": ("KAGE CORE", "Explain alerts", "explain"),
    "7": ("SPECTER MAP", "Build a Mermaid graph", "map"),
    "8": ("SHADOW PROXY", "Inspect and redact HTTP headers", "headers"),
    "9": ("RONIN SOC", "Investigate and export a case", "investigate"),
    "10": ("KAGE AI", "Suggest next investigation steps", "advise"),
}
PROVIDER_CHOICES = {str(number): provider for number, provider in enumerate(PROVIDERS, start=1)}


def prompt(text, default=""):
    suffix = f" [{default}]" if default else ""
    return input(f"{text}{suffix}: ").strip() or default


def path_prompt(text, default=""):
    value = prompt(text, default)
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    return value or default


def sample_path(label, demo_dir, filename=""):
    value = path_prompt(f"{label} (Enter for bundled sample)")
    return value or str(demo_dir / filename)


def choose_provider(session_keys, zero_label):
    print(f"  0. {zero_label}")
    for number, provider in PROVIDER_CHOICES.items():
        name, env_var = PROVIDERS[provider]
        source = "session key" if provider in session_keys else f"from {env_var}"
        status = source if lookup_key(provider, session_keys).strip() else "key needed"
        print(f"  {number}. {name} [{status}]")
    choice = prompt("Provider", "0")
    while choice != "0" and choice not in PROVIDER_CHOICES:
        print("Choose one of the listed numbers.")
        choice = prompt("Provider", "0")
    return PROVIDER_CHOICES.get(choice)


def manage_keys(session_keys):
    provider = choose_provider(session_keys, "Back to menu")
    if not provider:
        return
    name, env_var = PROVIDERS[provider]
    action = prompt(f"{name}: set session key [s], clear session key [c], or back [Enter]").lower()
    if action == "c":
        session_keys.pop(provider, None)
        print(f"Session key cleared. The menu can still use {env_var} if it is set.")
    elif action == "s":
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                key = getpass.getpass(f"{name} API key (hidden): ").strip()
            if not key:
                return
            session_keys[provider] = validate_api_key(key, env_var)
        except (getpass.GetPassWarning, OSError):
            print("Masked entry is unavailable here. Use a terminal or set the environment variable.")
        except ValueError as error:
            print(error)
        else:
            print(f"{name} key set for this session.")


def command_arguments(command, demo_dir, session_keys):
    if command == "ioc":
        value = prompt("IP address or domain")
        if not value:
            return None
        provider = choose_provider(session_keys, "Offline classification")
        if provider is None:
            return ["ioc", "--", value]
        name = PROVIDERS[provider][0]
        if prompt(f"Send this public, non-sensitive indicator to {name}? [y/N]").lower() == "y":
            return ["ioc", "--provider", provider, "--", value]
        return None
    if command == "scope":
        value = prompt("Domain")
        if not value:
            return None
        rules = sample_path("Scope rules file", demo_dir, "scope.txt")
        return ["scope", f"--rules={rules}", "--", value]
    if command in {"detect", "explain", "hunt", "map"}:
        auth = sample_path("Authentication CSV", demo_dir, "auth.csv")
        if command in {"hunt", "map"}:
            flows = sample_path("Network flows CSV", demo_dir, "flows.csv")
            return [command, "--", auth, flows]
        return [command, "--", auth]
    if command == "traffic":
        return [command, "--", sample_path("Network flows CSV", demo_dir, "flows.csv")]
    if command == "headers":
        return [command, "--", sample_path("Saved HTTP headers file", demo_dir, "headers.txt")]
    if command == "demo":
        return [command, f"--out={path_prompt('Output folder', 'ghost-trace-demo')}"]
    folder = sample_path("Evidence directory", demo_dir)
    if command == "investigate":
        output = path_prompt("Output folder", "ghost-trace-case")
        return [command, f"--out={output}", "--", folder]
    return [command, "--", folder]


def run_menu(demo_dir, execute):
    session_keys = {}
    while True:
        print("\nGHOST TRACE Lite")
        for number, (name, description, _) in TOOLS.items():
            print(f"  {number:>2}. {name} | {description}")
        print("  11. Run the offline demo")
        print("  12. Manage enrichment API keys")
        print("   0. Exit")
        try:
            choice = prompt("Select an option")
            if choice == "0":
                return 0
            if choice == "12":
                manage_keys(session_keys)
            elif choice in TOOLS or choice == "11":
                command = "demo" if choice == "11" else TOOLS[choice][2]
                args = command_arguments(command, demo_dir, session_keys)
                if args:
                    execute(args, session_keys)
            else:
                print("Choose one of the listed numbers.")
        except EOFError:
            print()
            return 0
        except KeyboardInterrupt:
            print("\nCancelled.")
            return 130

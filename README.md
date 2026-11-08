# GHOST TRACE Lite

**One Python CLI for IOC triage, detection, and case reporting.** Run a synthetic SOC investigation from authentication logs and network flows through alert explanation, a relationship graph, and an evidence-linked report. The demo runs offline with the Python standard library.

## Open the menu

Requires Python 3.11 or newer. Open a terminal in the extracted `ghost-trace-lite` folder. In PyCharm, open that folder as a project and use its Terminal tab with a Python 3.11+ interpreter.

**Windows PowerShell**

```powershell
py -3 main.py
```

**macOS or Linux**

```bash
python3 main.py
```

Choose **11** to run the offline demo or pick one of the ten tools. At file prompts, press Enter to use the bundled evidence. Choose **12** to manage API keys, then use **1** to choose an IOC enrichment provider. Use the PyCharm **Terminal** tab for masked key entry.

The direct commands are available through `python -m ghost_trace_lite`. Run `python -m ghost_trace_lite demo` to start the demo directly, or `ghost-trace menu` after installation to open the menu.

The demo finds three failed logins from a single source, one later successful login to the same workstation, and two candidate flows originating from that workstation after the login. Compare the evidence IDs in the report with the bundled CSV rows. Use `--out demo-second-run` to pick a fresh output folder for a second run.

| Demo output | What it contains |
| --- | --- |
| `ghost-trace-demo/case.md` | A human-readable investigation report and recommended pivots |
| `ghost-trace-demo/case.json` | Structured alerts, timeline, scope checks, sanitized HTTP headers, and relationships |
| `ghost-trace-demo/relationships.mmd` | A Mermaid diagram of observed relationships in the supplied logs |

## Ten projects in one CLI

| Project | Command | Lite feature |
| --- | --- | --- |
| GHOST TRACE | `ioc` | Normalize IPs and domains, classify IP scope, and optionally look up a public IOC with a selected provider. |
| SHADOW RECON | `scope` | Check a hostname against exact and wildcard authorized scope rules. |
| SENTINEL | `detect` | Detect failed-login bursts for a specific user, host, and source IP. |
| GHOST VISION | `traffic` | Summarize bytes, top sources, and destination ports from a network-flow CSV. |
| PHANTOM HUNTER | `hunt` | Pivot from an alert to a matching successful login and nearby traffic from the host IP. |
| KAGE CORE | `explain` | Explain which observations triggered each alert and cite their CSV row IDs. |
| SPECTER MAP | `map` | Print a Mermaid graph of observed relationships between users, hosts, IPs, and domains. |
| SHADOW PROXY | `headers` | Inspect a saved HTTP header block and redact values outside an allowlist. |
| RONIN SOC | `investigate` | Run a case end to end and export Markdown, JSON, and Mermaid. |
| KAGE AI | `advise` | Suggest next steps using deterministic local rules and case evidence. |

The source runs directly with `python -m ghost_trace_lite`. To install the `ghost-trace` command into your active environment, run `python -m pip install .`.

```text
ghost-trace ioc 192.0.2.44
ghost-trace scope updates.ronin.test --rules ghost_trace_lite/demo_data/scope.txt
ghost-trace hunt ghost_trace_lite/demo_data/auth.csv ghost_trace_lite/demo_data/flows.csv
ghost-trace investigate ghost_trace_lite/demo_data --out my-case
ghost-trace --help
```

## Run your own case

Pass an evidence directory to `investigate` or `advise`. All four UTF-8 files are required for a case. Commands such as `detect` and `traffic` accept a single input.

| File | Format |
| --- | --- |
| `auth.csv` | Columns `timestamp,user,host,host_ip,src_ip,outcome`. Use `success` or `failure` for outcome. User and host labels accept ASCII letters, digits, dots, underscores, @, and hyphens, starting with a letter or digit. |
| `flows.csv` | Columns `timestamp,src_ip,dst_ip,dst_port,protocol,bytes`. Use `tcp` or `udp` and a nonnegative byte count. Add `dst_domain` when the source observed a destination hostname. |
| `headers.txt` | One request header block. An optional first request line supplies the method. The blank line ends the block. Values retained are a validated `Host` and the `Content-Type` media type without parameters. |
| `scope.txt` | One ASCII hostname or wildcard per line. `*.ronin.test` matches descendants of `ronin.test`. List `ronin.test` separately to include the apex. Use `#` for comments. |

CSV timestamps need a UTC offset or `Z`, such as `2026-01-15T14:03:05Z`. The CLI sorts rows in UTC and preserves original physical line numbers in references such as `auth:5`. It accepts IPv4 and IPv6 and expects dotted ASCII hostnames. For internationalized domain names, use their Punycode form.

**Detection and correlation.** By default, three failures within five minutes produce an alert. A qualifying burst consumes those failure rows, and a successful login resets the pending failures for the same user, host, host IP, and source IP. The hunt selects a later successful login with the same fields within ten minutes of the alert, then looks for flows originating from the logged-in host IP within ten minutes after success. Correlation identifies leads for review. Use `--threshold`, `--window`, and `--hunt-window` to adjust this behavior.

**Data handling.** Use synthetic or approved data for public demos. Reports include account labels, IPs, domains, and sanitized header names. The scope check compares hostnames against the rules you supply. The CLI analyzes local files and performs no active scanning.

## Optional IOC enrichment

In menu option **12**, pick a provider and press **s** to enter a key. The terminal hides the entry and the key is held in memory for that session. Press **c** to clear the session key. If a provider has no session key, GHOST TRACE Lite uses its environment variable if set.

| Provider | IOC type | Environment variable | Returned fields |
| --- | --- | --- | --- |
| [VirusTotal](https://docs.virustotal.com/reference/ip-info) | Public IP or domain | `VT_API_KEY` | Analysis counts |
| [Shodan](https://help.shodan.io/developer-fundamentals/looking-up-ip-info) | Public IP | `SHODAN_API_KEY` | Observed ports and host metadata. This lookup requires an eligible Shodan membership. |
| [AlienVault OTX](https://otx.alienvault.com/api) | Public IP or domain | `OTX_API_KEY` | Threat intelligence pulse count |

Choose **1** in the main menu, enter an IOC, and choose **0** to classify it offline or select a provider and confirm the lookup. Use public, non-sensitive indicators you are authorized to share. A provider receives the normalized IOC when you select it. VirusTotal explains how queried indicators can enter its shared dataset in its [IP report documentation](https://docs.virustotal.com/reference/ip-info) and [domain report documentation](https://docs.virustotal.com/reference/domain-info).

For the direct CLI, set the provider's environment variable and use `ghost-trace ioc YOUR_PUBLIC_IOC --provider virustotal` (or `shodan` or `otx`). The `--virustotal` flag is also available. A `not_found` status indicates no provider record. An `error` status includes a short diagnostic alongside the local classification.

## Tests

```bash
python -m unittest discover -s tests -v
```

The suite checks IOC validation, wildcard boundaries, detection and correlation windows, header redaction, menu navigation, the offline case, and mocked provider responses. The included GitHub Actions workflow runs the tests and an installed CLI smoke test on Windows and Linux.

## RONIN Python Academy

The `ioc` command is the Phase 1 learning slice. Start with Mission **05J** and use `ghost_trace_lite/ghost_trace.py` as the reference after attempting the lab. The other commands show how the same evidence can feed detection, correlation, and reporting.

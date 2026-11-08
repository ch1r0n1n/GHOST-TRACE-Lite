"""Check a hostname against explicit exact and wildcard scope rules."""

from .ghost_trace import normalize_domain


def load_scope(path):
    rules = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        rule = line.split("#", 1)[0].strip()
        if not rule:
            continue
        wildcard = rule.startswith("*.")
        try:
            domain = normalize_domain(rule.removeprefix("*."))
        except ValueError as error:
            raise ValueError(f"{path.name}:{line_number}: invalid scope rule") from error
        rules.add(f"*.{domain}" if wildcard else domain)
    return sorted(rules)


def check_scope(value, rules):
    domain = normalize_domain(value)
    matches = [
        rule for rule in rules
        if (domain.endswith(rule[1:]) if rule.startswith("*.") else domain == rule)
    ]
    return {"domain": domain, "in_scope": bool(matches), "matched_rules": matches}

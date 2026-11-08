"""Suggest evidence-based next steps with local rules."""

from .ghost_trace import ip_scope, parse_ip


def advise_case(case):
    recommendations = []
    if case["alerts"]:
        recommendations.append({
            "action": "Check MFA, device identity, and expected user activity for the affected logins.",
            "evidence_ids": [evidence_id for alert in case["alerts"] for evidence_id in alert["evidence_ids"]],
        })
    follow_ups = case["hunt"]["correlations"]
    if follow_ups:
        recommendations.append({
            "action": "Review identity and endpoint logs around the successful login. Verify whether the login was expected.",
            "evidence_ids": [link["success_evidence_id"] for link in follow_ups],
        })
    correlated_flows = [
        evidence_id for link in follow_ups for evidence_id in link["flow_evidence_ids"]
    ]
    if correlated_flows:
        recommendations.append({
            "action": "Use endpoint telemetry to identify the process behind the associated flows. Compare the destinations with the host baseline.",
            "evidence_ids": list(dict.fromkeys(correlated_flows)),
        })
    outside = [
        result["domain"] for result in case["scope_checks"] if not result["in_scope"]
    ]
    if outside:
        recommendations.append({
            "action": "Keep the listed domains outside active testing unless the authorized scope changes.",
            "domains": outside,
            "evidence_ids": [],
        })
    if not case["alerts"]:
        recommendations.append({
            "action": "Check authentication log coverage and test the detection threshold against a known-good baseline.",
            "evidence_ids": [],
        })
    public_destinations = sorted({
        event["destination_ip"] for event in case["hunt"]["timeline"]
        if event["type"] == "network_flow" and ip_scope(parse_ip(event["destination_ip"])) == "public"
    })
    if public_destinations:
        recommendations.append({
            "action": "Review public destination reputation using approved sources.",
            "indicators": public_destinations,
            "evidence_ids": [],
        })
    return recommendations

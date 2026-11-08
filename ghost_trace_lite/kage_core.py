"""Explain alerts from rule inputs and source evidence."""

from .sentinel import alert_record


def explain_alerts(alerts):
    explanations = []
    for alert in alerts:
        record = alert_record(alert)
        summary = (
            f"{record['failure_count']} failed logins for {record['user']} on "
            f"{record['host']} from {record['source_ip']} within "
            f"{record['window_minutes']} minutes."
        )
        explanations.append({
            "alert_id": record["id"],
            "summary": summary,
            "evidence_ids": record["evidence_ids"],
            "limitation": "A failed-login burst is a triage signal. Corroborate it with identity and endpoint logs.",
        })
    return explanations

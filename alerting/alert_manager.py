SEVERITY_ORDER = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}

SEVERITY_COLORS = {
    'CRITICAL': '🔴',
    'HIGH':     '🟠',
    'MEDIUM':   '🟡',
    'LOW':      '🟢',
}


def format_alerts(findings: list[dict]) -> list[dict]:
    """Sort findings by severity and attach display metadata."""
    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.get(f.get('severity', 'LOW'), 0),
        reverse=True
    )

    alerts = []
    for i, finding in enumerate(sorted_findings, start=1):
        severity = finding.get('severity', 'LOW')
        alerts.append({
            **finding,
            'alert_id': f"ALERT-{i:03d}",
            'icon': SEVERITY_COLORS.get(severity, '⚪'),
            'severity': severity,
        })

    return alerts


def print_alerts(alerts: list[dict]) -> None:
    """Pretty-print alerts to stdout."""
    print("\n" + "="*60)
    print("  SOC ANALYST ASSISTANT — ALERT SUMMARY")
    print("="*60)

    if not alerts:
        print("  ✅ No threats detected.")
        return

    for alert in alerts:
        icon = alert['icon']
        print(f"\n{icon} [{alert['severity']}] {alert['alert_id']} — {alert['rule']}")
        print(f"   {alert['description']}")
        if 'source_ip' in alert:
            print(f"   Source IP : {alert['source_ip']}")
        if 'actor' in alert:
            print(f"   Actor     : {alert['actor']}")
        if 'timestamp' in alert:
            print(f"   Time      : {alert['timestamp']}")
        elif 'first_seen' in alert:
            print(f"   First seen: {alert['first_seen']}")
            print(f"   Last seen : {alert.get('last_seen', 'N/A')}")
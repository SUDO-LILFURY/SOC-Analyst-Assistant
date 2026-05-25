from collections import Counter

RESPONSE_PLAYBOOKS = {
    'BRUTE_FORCE': [
        "Block source IP at firewall/security group level.",
        "Review auth logs for any successful logins from this IP.",
        "Check if targeted accounts have MFA enabled.",
        "Consider implementing account lockout policy after N failures.",
    ],
    'MALICIOUS_IP': [
        "Immediately block IP at perimeter firewall.",
        "Search all logs for any historical connections from this IP.",
        "Escalate to Tier 2 / threat intel team for attribution.",
        "Check for data exfiltration indicators (large outbound transfers).",
    ],
    'PRIVILEGE_ESCALATION': [
        "Verify with the user/team if the escalation was authorized.",
        "Review commands executed during the elevated session.",
        "Check for new cron jobs, user accounts, or SSH keys added.",
        "If unauthorized: isolate host, reset credentials, begin IR process.",
    ],
}


def generate(alerts: list[dict], total_events: int) -> None:
    """Print a structured incident triage report."""
    severity_counts = Counter(a['severity'] for a in alerts)
    rule_counts = Counter(a['rule'] for a in alerts)
    involved_ips = list({a['source_ip'] for a in alerts if a.get('source_ip')})

    print("\n" + "="*60)
    print("  INCIDENT TRIAGE REPORT")
    print("="*60)

    print(f"\n📋 OVERVIEW")
    print(f"   Total log events analysed : {total_events}")
    print(f"   Total alerts generated    : {len(alerts)}")
    print(f"   Unique IPs involved       : {len(involved_ips)}")

    print(f"\n📊 SEVERITY BREAKDOWN")
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = severity_counts.get(sev, 0)
        if count:
            print(f"   {sev:<10} : {count}")

    print(f"\n🔍 DETECTION RULES TRIGGERED")
    for rule, count in rule_counts.items():
        print(f"   {rule:<30} : {count} finding(s)")

    # Recommended actions per triggered rule
    triggered_rules = list(rule_counts.keys())
    if triggered_rules:
        print(f"\n🛡️  RECOMMENDED RESPONSE ACTIONS")
        for rule in triggered_rules:
            if rule in RESPONSE_PLAYBOOKS:
                print(f"\n   [{rule}]")
                for action in RESPONSE_PLAYBOOKS[rule]:
                    print(f"   → {action}")

    print("\n" + "="*60)
    print("  END OF REPORT")
    print("="*60 + "\n")
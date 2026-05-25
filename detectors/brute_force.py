from collections import defaultdict

BRUTE_FORCE_THRESHOLD = 5  # failed attempts before triggering


def detect(events: list[dict]) -> list[dict]:
    """
    Detect brute-force login attempts.
    Fires when a single IP exceeds the failure threshold.
    """
    failures_by_ip = defaultdict(list)

    for event in events:
        if event['event_type'] == 'AUTH_FAILURE' and event['source_ip']:
            failures_by_ip[event['source_ip']].append(event)

    findings = []
    for ip, failed_events in failures_by_ip.items():
        if len(failed_events) >= BRUTE_FORCE_THRESHOLD:
            targeted_users = list({e['user'] for e in failed_events if e['user']})
            findings.append({
                'rule': 'BRUTE_FORCE',
                'source_ip': ip,
                'count': len(failed_events),
                'targeted_users': targeted_users,
                'first_seen': failed_events[0]['timestamp'],
                'last_seen': failed_events[-1]['timestamp'],
                'severity': 'HIGH' if len(failed_events) >= 8 else 'MEDIUM',
                'description': (
                    f"IP {ip} made {len(failed_events)} failed login attempts "
                    f"targeting: {', '.join(targeted_users) or 'unknown'}"
                ),
            })

    return findings
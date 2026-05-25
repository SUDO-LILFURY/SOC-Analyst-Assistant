# Simulated threat intel blocklist — in production this would load from a feed or DB
MALICIOUS_IPS = {
    "45.33.32.156": "Known SSH scanner (Shodan research node / abuse reports)",
    "203.0.113.99": "TEST-NET-3 — used here to simulate flagged threat actor IP",
    "198.51.100.42": "Known C2 infrastructure",
    "185.220.101.1": "Tor exit node with abuse history",
}


def detect(events: list[dict]) -> list[dict]:
    """
    Flag any event where the source IP is on the malicious IP blocklist.
    """
    findings = []
    seen = set()  # avoid duplicate alerts for same IP

    for event in events:
        ip = event.get('source_ip')
        if ip and ip in MALICIOUS_IPS and ip not in seen:
            seen.add(ip)
            findings.append({
                'rule': 'MALICIOUS_IP',
                'source_ip': ip,
                'reason': MALICIOUS_IPS[ip],
                'first_seen': event['timestamp'],
                'severity': 'CRITICAL',
                'description': (
                    f"Traffic from known-malicious IP {ip}: {MALICIOUS_IPS[ip]}"
                ),
            })

    return findings
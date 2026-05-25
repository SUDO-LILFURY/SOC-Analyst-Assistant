from detectors import brute_force, malicious_ip, privilege_escalation

# Registry of all detection modules — add new ones here, nothing else changes
DETECTORS = [
    brute_force,
    malicious_ip,
    privilege_escalation,
]


def run(events: list[dict]) -> list[dict]:
    """
    Feed parsed events through every registered detector.
    Returns a flat list of all findings with their source rule tagged.
    """
    all_findings = []

    for detector in DETECTORS:
        findings = detector.detect(events)
        all_findings.extend(findings)

    return all_findings


def correlate(findings: list[dict]) -> list[dict]:
    """
    Cross-reference findings to enrich context.
    Example: if an IP triggers both BRUTE_FORCE and MALICIOUS_IP, escalate severity.
    """
    malicious_ips = {
        f['source_ip'] for f in findings if f['rule'] == 'MALICIOUS_IP'
    }

    for finding in findings:
        ip = finding.get('source_ip')
        if ip and ip in malicious_ips and finding['rule'] == 'BRUTE_FORCE':
            finding['severity'] = 'CRITICAL'
            finding['correlated'] = True
            finding['description'] += ' [CORRELATED: IP also on malicious IP blocklist]'

    return findings
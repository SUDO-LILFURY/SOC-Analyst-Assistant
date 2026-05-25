import re

# High-risk commands that should trigger elevated severity
HIGH_RISK_COMMANDS = ['/bin/bash', '/usr/bin/passwd', '/bin/su', '/usr/sbin/useradd']


def detect(events: list[dict]) -> list[dict]:
    """
    Detect privilege escalation events (sudo, su, root session acquisition).
    Escalates severity if high-risk commands are involved.
    """
    findings = []

    for event in events:
        if event['event_type'] != 'PRIVILEGE_ESCALATION':
            continue

        msg = event['message']
        command = _extract_command(msg)
        is_high_risk = any(cmd in (command or '') for cmd in HIGH_RISK_COMMANDS)

        # Extract acting user
        actor = _extract_actor(msg) or event.get('user') or 'unknown'

        findings.append({
            'rule': 'PRIVILEGE_ESCALATION',
            'actor': actor,
            'command': command,
            'timestamp': event['timestamp'],
            'host': event['host'],
            'severity': 'CRITICAL' if is_high_risk else 'HIGH',
            'description': (
                f"Privilege escalation by '{actor}' on {event['host']} "
                f"— command: {command or 'N/A'}"
            ),
        })

    return findings


def _extract_command(message: str) -> str | None:
    match = re.search(r'COMMAND=(.+)', message)
    return match.group(1).strip() if match else None


def _extract_actor(message: str) -> str | None:
    # sudo format: "username : TTY=..."
    match = re.search(r'^(\S+)\s*:', message)
    if match:
        return match.group(1)
    # su format: "Successful su for root by username"
    match = re.search(r'by (\S+)', message)
    return match.group(1) if match else None
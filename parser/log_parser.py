import re
from datetime import datetime

# Regex to parse a standard syslog-style line
LOG_PATTERN = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+'
    r'(?P<host>\S+)\s+(?P<process>\S+):\s+(?P<message>.+)'
)

IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
USER_PATTERN = re.compile(r'for (?:invalid user |user )?(\S+) from')


def parse_line(line: str) -> dict | None:
    """Parse a single log line into a structured dict. Returns None if unparseable."""
    line = line.strip()
    if not line:
        return None

    match = LOG_PATTERN.match(line)
    if not match:
        return None

    message = match.group('message')
    ips = IP_PATTERN.findall(message)
    users = USER_PATTERN.findall(message)

    return {
        'raw': line,
        'timestamp': f"{match.group('month')} {match.group('day')} {match.group('time')}",
        'host': match.group('host'),
        'process': match.group('process'),
        'message': message,
        'source_ip': ips[0] if ips else None,
        'user': users[0] if users else None,
        'event_type': classify_event(message),
    }


def classify_event(message: str) -> str:
    """Assign a coarse event type label based on message content."""
    msg = message.lower()
    if 'failed password' in msg:
        return 'AUTH_FAILURE'
    if 'accepted password' in msg or 'accepted publickey' in msg:
        return 'AUTH_SUCCESS'
    if 'sudo' in msg:
        return 'PRIVILEGE_ESCALATION'
    if 'successful su' in msg or msg.startswith('su'):
        return 'PRIVILEGE_ESCALATION'
    return 'UNKNOWN'


def parse_log_file(filepath: str) -> list[dict]:
    """Read a log file and return a list of parsed event dicts."""
    events = []
    with open(filepath, 'r') as f:
        for line in f:
            parsed = parse_line(line)
            if parsed:
                events.append(parsed)
    return events
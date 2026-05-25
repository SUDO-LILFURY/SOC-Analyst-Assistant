import sys
import os

# Allow imports from project root
sys.path.insert(0, os.path.dirname(__file__))

from parser.log_parser import parse_log_file
from engine.correlation_engine import run, correlate
from alerting.alert_manager import format_alerts, print_alerts
from triage.triage_report import generate

DEFAULT_LOG = os.path.join(os.path.dirname(__file__), 'sample_logs', 'auth.log')


def main(log_path: str = DEFAULT_LOG):
    print(f"\n[*] SOC Analyst Assistant starting...")
    print(f"[*] Ingesting log file: {log_path}")

    # Step 1: Parse
    events = parse_log_file(log_path)
    print(f"[*] Parsed {len(events)} events.")

    # Step 2: Detect
    findings = run(events)

    # Step 3: Correlate
    findings = correlate(findings)

    # Step 4: Format & display alerts
    alerts = format_alerts(findings)
    print_alerts(alerts)

    # Step 5: Triage report
    generate(alerts, total_events=len(events))


if __name__ == '__main__':
    log_file = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_LOG
    main(log_file)
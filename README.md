# SOC Analyst Assistant — Python Threat Detection Tool

A modular Python tool that simulates SOC analyst workflows by ingesting raw security logs, running detection rules, correlating findings, and producing structured triage reports.

## Features
- Brute-force detection — flags IPs exceeding failed login thresholds
- Malicious IP lookup — checks source IPs against a threat intel blocklist
- Privilege escalation detection — catches sudo/su/root session events
- Event correlation — escalates severity when multiple rules fire on the same indicator
- Triage report — structured incident summary with recommended response actions per rule

## Project Structure
soc/
├── alerting/alert_manager.py
├── detectors/brute_force.py
├── detectors/malicious_ip.py
├── detectors/privilege_escalation.py
├── engine/correlation_engine.py
├── parser/log_parser.py
├── triage/triage_report.py
├── sample_logs/auth.log
└── main.py

## Usage
```bash
python main.py
```

## Tech Stack
- Python 3.10+ — no external dependencies
- Detection logic modelled on SIEM rule patterns
- Correlation engine mirrors alert enrichment in Splunk ES / Microsoft Sentinel
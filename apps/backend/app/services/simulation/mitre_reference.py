"""Static ATT&CK technique reference for the detection-coverage report.

Deliberately not a live MITRE API client — the technique set this project
cares about is small and fixed, and a network dependency here would just be
one more thing that can fail during a demo. `covered_by` links a technique
back to the rule that detects it; techniques with `covered_by=None` are
known gaps, not bugs — listed so the coverage report can show what this
detection suite does *not* catch, not just what it does.
"""

TECHNIQUES = {
    "T1110": {
        "technique": "Brute Force",
        "tactic": "Credential Access",
        "covered_by": "LDR-WEB-001",
    },
    "T1110.004": {
        "technique": "Credential Stuffing",
        "tactic": "Credential Access",
        "covered_by": "LDR-WEB-002",
    },
    "T1595.002": {
        "technique": "Vulnerability Scanning",
        "tactic": "Discovery",
        "covered_by": "LDR-WEB-003",
    },
    "T1595.003": {
        "technique": "Wordlist Scanning",
        "tactic": "Reconnaissance",
        "covered_by": "LDR-WEB-004",
    },
    "T1078": {
        "technique": "Valid Accounts",
        "tactic": "Initial Access",
        "covered_by": "LDR-WEB-005",
    },
    "T1589.001": {
        "technique": "Gather Victim Identity Information: Credentials",
        "tactic": "Reconnaissance",
        "covered_by": "LDR-WEB-006",
    },
    "T1190": {
        "technique": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "covered_by": None,
    },
    "T1071.001": {
        "technique": "Web Protocols",
        "tactic": "Command and Control",
        "covered_by": None,
    },
    "T1499": {
        "technique": "Endpoint Denial of Service",
        "tactic": "Impact",
        "covered_by": None,
    },
}

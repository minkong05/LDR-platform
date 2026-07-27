# Detection Coverage Report

Generated: 2026-07-27T13:18:17.673619+00:00

**6/6 rules fired** during this simulation run.

## Rules exercised

| Rule ID | Name | Severity | ATT&CK Technique | Fired? |
| --- | --- | --- | --- | --- |
| LDR-WEB-001 | Brute force login failures from single IP | high | T1110 (Brute Force) | yes |
| LDR-WEB-002 | Credential stuffing — high 401 rate from single IP | high | T1110.004 (Credential Stuffing) | yes |
| LDR-WEB-003 | Admin panel probing from single IP | medium | T1595.002 (Vulnerability Scanning) | yes |
| LDR-WEB-004 | Path scanning — 404 storm from single IP | medium | T1595.003 (Wordlist Scanning) | yes |
| LDR-WEB-005 | Successful login after repeated failures | low | T1078 (Valid Accounts) | yes |
| LDR-WEB-006 | Account enumeration via repeated login failures | high | T1589.001 (Gather Victim Identity Information: Credentials) | yes |

## Known gaps (ATT&CK techniques not covered by any rule)

| Technique | Name | Tactic |
| --- | --- | --- |
| T1071.001 | Web Protocols | Command and Control |
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1499 | Endpoint Denial of Service | Impact |

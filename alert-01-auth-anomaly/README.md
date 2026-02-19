## Alert Summary
- Alert ID: AUTH-001
- Alert Name: Multiple Failed Login Attempts
- Severity: Medium
- Source: Authentication Logs

## Initial Assessment
Alert triggered due to multiple failed authentication attempts for a single user account from an external IP address.

## Log Fields Reviewed
- Timestamp
- Username
- Source IP
- Action (Login Failed)
- Event count

## Preliminary Analysis
Repeated failures suggest possible automated login attempts. No successful authentication observed in alert data.

## Scope Determination
- Affected User: jdoe
- Affected Systems: Authentication service
- Spread: Single user, single source IP

## Next Steps
- Validate IP reputation
- Check for successful logins
- Determine false positive vs escalation

## Identity Context
- User Type: Standard employee
- MFA Status: Enabled
- Normal Login Region: United States
- Observed Region: Unknown / External
- Risk Assessment: Activity inconsistent with baseline user behavior

## Indicators of Compromise (IOCs)
- Source IP: 185.203.118.44
- Reputation Check: VirusTotal (0/66 detections)
- Reputation Status: No known malicious reputation at time of analysis

## Threat Intelligence Correlation
Open-source threat intelligence did not identify the source IP as malicious. Activity may represent low-volume scanning or benign failed authentication attempts. Lack of successful login reduces likelihood of compromise.


## Final Assessment & Closure
- Classification: False Positive
- Reasoning: Authentication failures observed without evidence of compromise or malicious reputation
- Recommended Action: Continue monitoring; review alert thresholds if repeated activity observed
- Case Status: Closed


# Alert 02 – Suspicious PowerShell Execution

## Alert Summary
- Alert ID: ENDPT-002
- Alert Name: Suspicious PowerShell Command Execution
- Severity: High
- Source: Endpoint Detection & Response (EDR)

---

## Initial Assessment

Alert triggered due to execution of an encoded PowerShell command on a user workstation. Encoded commands are commonly used to obfuscate malicious activity.

---

## Log Fields Reviewed

- Timestamp
- Hostname
- Username
- Process Name
- Parent Process
- Command Line
- SHA256 Hash
- Network Connections

---

## Preliminary Analysis

PowerShell was executed with the `-EncodedCommand` flag.  
Parent process was `winword.exe`, which may indicate malicious macro execution.

---

## Scope Determination

- Affected User: jsmith
- Affected Host: FINANCE-PC-22
- Spread: Single endpoint (no lateral movement observed)

---

## Identity Context

- User Role: Finance Department
- Privilege Level: Standard User
- MFA: Enabled

---

## Indicators of Compromise (IOCs)

- Suspicious Command:
  `powershell.exe -EncodedCommand SQBFAFgA...`
- Parent Process: winword.exe
- External IP: 45.83.21.19

---

## MITRE ATT&CK Mapping

- T1059.001 – PowerShell
- T1204 – User Execution
- T1027 – Obfuscated Files or Information

---

## Investigation Outcome

Determined to be malicious macro execution attempt.  
Endpoint isolated and malware scan initiated.

---

## Closure Decision

Escalated to Incident Response team for deeper forensic review.


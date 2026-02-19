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

## Command-Line Analysis

The PowerShell process was executed with the following flags:

- `-nop` (No profile execution)
- `-w hidden` (Hidden window execution)
- `-enc` (Encoded command)

These flags are commonly associated with malicious activity to avoid detection and obscure command intent.

The parent process `winword.exe` suggests potential malicious macro execution.

---

## Network Analysis

The PowerShell process initiated an outbound HTTPS connection to:

185.203.118.44:443

This IP address is external and not part of the organization's known infrastructure.

Outbound encrypted traffic combined with encoded PowerShell execution increases the likelihood of malicious activity, potentially indicating command-and-control communication.

---

## MITRE ATT&CK Mapping

The observed behavior aligns with the following MITRE ATT&CK techniques:

- T1059.001 – Command and Scripting Interpreter: PowerShell
- T1204 – User Execution (malicious macro in Word)
- T1027 – Obfuscated Files or Information
- T1071.001 – Application Layer Protocol (Web Protocols – HTTPS C2)

These mappings indicate potential initial access followed by command-and-control communication.

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

---
## Final Assessment

High confidence malicious activity observed.

Indicators include:
- Encoded PowerShell execution
- Suspicious parent process (winword.exe)
- External HTTPS connection to unknown IP
- Obfuscation techniques

This behavior is consistent with malicious macro execution leading to potential command-and-control communication.

---

## Containment & Response

- Endpoint isolated from network
- EDR scan initiated
- Incident escalated to Tier 2 / Incident Response team
- User notified and credentials reset as precaution

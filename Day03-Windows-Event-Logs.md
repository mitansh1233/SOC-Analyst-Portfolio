# SOC Incident Triage Report — Day 03 (Windows Event Analysis & Sysmon)

## 1. Executive Summary
Deployed Microsoft Sysmon configured with SwiftOnSecurity auditing rules to monitor endpoint process creation. Executed simulated host discovery commands (`whoami`, `net user`, `ipconfig`) and inspected corresponding process execution telemetry in Windows Event Viewer.

## 2. Key Telemetry Findings (Sysmon Event ID 1)

### Process Creation Event Details
- **Event ID:** 1 (Process Create)[cite: 7]
- **Log Source:** Microsoft-Windows-Sysmon/Operational[cite: 7]
- **Target Process (Image):** `C:\Windows\System32\whoami.exe`[cite: 7]
- **Command Line:** `whoami`[cite: 7]
- **Parent Process (ParentImage):** `C:\Windows\System32\cmd.exe`[cite: 7]
- **User Context:** `Rheagar1o1\mitan`[cite: 7]
- **Process Hash (SHA256):** `23240EF9F8B0A9A324110B1C2331DE31DC1B0E08F5359CB707E51A939AF56CD3`[cite: 7]

## 3. Threat Hunting & SOC Context
- **Technique Mapped:** MITRE ATT&CK T1033 (System Owner/User Discovery) & T1087 (Account Discovery).
- **Detection Logic:** Attackers execute discovery commands immediately after obtaining code execution. Monitoring parent-child relationships (e.g., `cmd.exe` or `powershell.exe` spawning discovery utilities in short intervals) allows SOC analysts to detect initial access before privilege escalation occurs.

## 4. Remediation & Best Practices
- Ensure command-line process auditing is centrally forwarded to a SIEM (e.g., Splunk, Microsoft Sentinel).
- Establish baseline alerts for abnormal parent processes (e.g., web servers like `w3wp.exe` or Office applications spawning `cmd.exe` or `powershell.exe`).

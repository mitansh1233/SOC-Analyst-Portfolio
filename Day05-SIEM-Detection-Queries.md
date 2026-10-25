# SOC Detection Engineering Report — Day 05 (SIEM Querying: KQL & XPath)

## 1. Executive Summary
Transitioned from single-endpoint Event Viewer triage to enterprise-scale SIEM querying using **Kusto Query Language (KQL)** in Azure Data Explorer (`help/SecurityLogs` & `help/Samples`) and local **XPath CLI filtering (`wevtutil`)**. Engineered and executed aggregation queries to detect brute-force authentication anomalies (`Event ID 4625` / `AuthenticationEvents`) and command-shell process execution bursts (`Sysmon Event ID 1` / `ProcessEvents`).

---

## 2. KQL Pipeline Fundamentals (`help/Samples`)
Validated the core SIEM detection engineering pipeline (**Filter -> Aggregate -> Threshold -> Sort**) against the `StormEvents` dataset:

    StormEvents
    | where State == "TEXAS"
    | summarize TotalEvents = count() by EventType
    | where TotalEvents >= 100
    | order by TotalEvents desc

* **Execution Result:** Filtered 27 distinct event categories in Texas down to the top 8 high-volume incident types exceeding the `>= 100` threshold (led by `Hail` at 1,326 events and `Flash Flood` at 1,199 events).

---

## 3. Detection Rule 01: Brute-Force Authentication Hunting (`AuthenticationEvents`)
**Objective:** Identify external and internal IP addresses generating 5 or more failed authentication attempts to suppress benign single-typo false positives (Alert Fatigue) and surface active brute-force and password-spraying sources.

### Executed KQL Query (`help/SecurityLogs`)

    AuthenticationEvents
    | where result == "Failed Login"
    | summarize FailedAttempts = count() by src_ip
    | where FailedAttempts >= 5
![Brute Force KQL Results](Screenshot%202026-10-25%20210907.png)
![Process Events KQL Results](Screenshot%202026-10-25%20211649.png)
### Live Telemetry Findings (6 Offending IPs Isolated)
| Source IP (`src_ip`) | Failed Attempts (`FailedAttempts`) | Triage Verdict |
| :--- | :--- | :--- |
| `88.150.11.111` | `10` | **High Severity:** External IP brute-force threshold exceeded |
| `149.124.195.189` | `6` | **Medium Severity:** External repeated authentication failure |
| `192.168.3.17` | `6` | **Internal Anomaly:** Potential lateral movement / password guessing |
| `192.168.2.199` | `6` | **Internal Anomaly:** Potential lateral movement / password guessing |
| `192.168.3.97` | `5` | **Internal Anomaly:** Threshold boundary reached |
| `192.168.2.209` | `5` | **Internal Anomaly:** Threshold boundary reached |

### Equivalent Microsoft Sentinel Production Rule (Windows Security Event ID 4625)

    SecurityEvent
    | where EventID == 4625 and LogonType == 3
    | summarize FailedAttempts = count(), TargetedUsers = make_set(TargetUserName) by IpAddress, bin(TimeGenerated, 5m)
    | where FailedAttempts >= 5
    | order by FailedAttempts desc

### Equivalent Splunk Production Rule (SPL)

    index=windows LogName=Security EventCode=4625 Logon_Type=3
    | bin _time span=5m
    | stats count as FailedAttempts values(Account_Name) as TargetedUsers by src_ip, _time
    | where FailedAttempts >= 5
    | sort - FailedAttempts

---

## 4. Detection Rule 02: Command Shell Process Spawning (`ProcessEvents`)
**Objective:** Hunt across endpoints for instances where `cmd.exe` acts as the parent process (`parent_process_name`) spawning multiple child processes (`>= 2`), aggregating the exact command lines executed per host using `make_set()`.

### Executed KQL Query (`help/SecurityLogs`)

    ProcessEvents
    | where parent_process_name == "cmd.exe"
    | summarize CommandsRun = count(), ExactCommands = make_set(process_commandline) by hostname
    | where CommandsRun >= 2
    | order by CommandsRun desc

### Live Telemetry Findings
* **Records Matched:** `65` endpoints identified executing `>= 2` child commands via `cmd.exe` (query completed in `1.683s`).
* **Top Flagged Endpoints (`CommandsRun = 3`):** `URNV-DESKTOP`, `EYHX-MACHINE`, `5CYJ-MACHINE`, `IJBP-LAPTOP`, `E2Z5-MACHINE`, `WFIJ-DESKTOP`, `7S1D-MACHINE`, `ZE5Q-LAPTOP`.
* **Analyst Baseline Note:** Reviewing `ExactCommands` allowed rapid differentiation between benign system/browser invocations (e.g., `conhost.exe`, `eventvwr.msc`, `chrome.exe`) and hands-on-keyboard reconnaissance utilities (`whoami.exe`, `net.exe`, `ipconfig.exe`).

### Equivalent Microsoft Defender XDR / Sentinel Production Rule

    DeviceProcessEvents
    | where InitiatingProcessFileName in~ ("cmd.exe", "powershell.exe")
    | where FileName in~ ("whoami.exe", "net.exe", "net1.exe", "ipconfig.exe", "systeminfo.exe")
    | summarize ReconCommandsRun = make_set(ProcessCommandLine), UniqueToolsCount = dcount(FileName) by DeviceName, AccountName, bin(Timestamp, 10m)
    | where UniqueToolsCount >= 3

---

## 5. Local Endpoint CLI XPath Verification (`wevtutil`)
Verified raw XML telemetry extraction via Administrator Command Prompt to replicate how SIEM forwarder agents query local Windows Event channels:

* **Sysmon Process Creation (`Event ID 1`):**
  `wevtutil qe Microsoft-Windows-Sysmon/Operational /q:*[System[(EventID=1)]] /c:1 /rd:true /f:text`

* **Windows Security Failed Logon (`Event ID 4625`):**
  `wevtutil qe Security /q:*[System[(EventID=4625)]] /c:1 /rd:true /f:text`

---

## 6. Key SOC Analyst Takeaways
1. **Alert Fatigue Mitigation:** Alerting on every individual `Event ID 4625` floods the SOC queue with benign user password typos (`LogonType 2`). Filtering specifically for network logons (`LogonType 3`) and applying time-bucket thresholds (`>= 5` attempts) isolates genuine brute-force and password-spraying attacks.
2. **Parent-Child Process Context:** Inspecting `parent_process_name == "cmd.exe"` with `make_set(process_commandline)` allows analysts to immediately see the full sequence of commands executed on a host in a single row rather than pivoting through dozens of individual logs.

# 🛠️ Threat Hunt Report: Remote Support Misdirection — *“The Un-Help Desk”*

<p align="center">
  <img src="./images/Unhelp_Desk.png" alt="Unhelp Desk" width="80%">
</p>

**Analyst:** Peter Van Rossum (SecOpsPete)  
**Date Completed:** October 2025  
**Environment Investigated:** Microsoft Defender for Endpoint (MDE) + Microsoft Sentinel (Log Analytics Workspace)  
**Timeframe Analyzed:** 2025-10-01 → 2025-10-16 (UTC)  
**Duration of investigation window:** ~1 hour

---

## 🧠 Scenario Overview

A routine support request should have ended with a reset and reassurance. Instead, the so-called “help” left behind a trail of anomalies that don’t add up.

What was framed as troubleshooting looked more like an audit of the system itself — probing, cataloging, leaving subtle traces in its wake. Actions chained together in suspicious sequence: first gaining a foothold, then expanding reach, then preparing to linger long after the session ended.

And just when the activity should have raised questions, a neat explanation appeared — a story planted in plain sight, designed to justify the very behavior that demanded scrutiny.

This wasn’t remote assistance. It was a misdirection. My mission was to reconstruct the timeline, connect the scattered remnants of this “support session”, and decide what was legitimate and what was staged. The evidence is here. The question is whether I saw through the story or believed it.

---

## 🎯 Executive Summary

I investigated suspicious activity beginning with processes spawned from user Download folders across multiple machines. Using MDE and Sentinel telemetry I identified a most-suspicious host (gab-intern-vm), confirmed PowerShell execution with an execution-policy bypass, observed quick clipboard probes, mapped storage surfaces, and noted staged artifacts placed in a public folder for easy retrieval. I also observed scheduled tasks and fallback autoruns that would allow re-execution after the session ended.

Key takeaways:
- Execution with `-ExecutionPolicy Bypass` and in-memory short-lived commands indicates deliberate defense evasion and minimal artifact footprint.
- Staging artifacts in public locations (C:\Users\Public) lowers friction for exfiltration and should be prioritized for monitoring.
- Short, opportunistic reconnaissance (clipboard reads, tasklist snapshots) often precedes collection and can be missed without tight parent-process correlation and minute-level time-window hunting.
- Planted narrative artifacts (e.g., support logs) are classic misdirection; timeline correlation matters more than content alone.

---

## ✅ Completed Flags (Quick Reference)

| Flag # | Objective | Value |
|--------|-----------|-------|
| Flag0  | Entry point / compromised host | gab-intern-vm |
| Flag1  | Initial execution parameter | -ExecutionPolicy |
| Flag2  | Defender tamper artifact | DefenderTamperArtifact.lnk |
| Flag3  | Quick clipboard probe | powershell clipboard read |
| Flag4  | Recon timestamp | 2025-10-09T12:51:44.3425653Z |
| Flag5  | Storage mapping command | wmic logicaldisk query |
| Flag6  | Parent process (session check) | RuntimeBroker.exe |
| Flag7  | Initiating process unique ID | 2533274790397065 |
| Flag8  | Runtime application inventory | tasklist.exe |
| Flag9  | Privilege mapping timestamp | 2025-10-09T12:52:14.3135459Z |
| Flag10 | Connectivity check / C2 probe | www[.]msftconnecttest[.]com |
| Flag11 | Data staging location | C:\Users\Public\ReconArtifacts.zip |
| Flag12 | Outbound destination (simulated upload) | 100.29.147.161 |
| Flag13 | Scheduled task persistence | SupportToolUpdater |
| Flag14 | Registry autorun fallback | RemoteAssistUpdater |
| Flag15 | Planted narrative / cover artifact | SupportChat_log.lnk |

---

## 🔍 Flag‑by‑Flag Findings (detailed)

---

### Flag 0 — Entry point / Compromised Host
**Objective:** Entry point / compromised host  
**Flag:** gab-intern-vm

**KQL (Entry point discovery):**
```kusto
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-16))
| where FileName contains "SupportTool.ps1" or FileName has_any ("desk","help","support","tool")
| project TimeGenerated, DeviceName, FileName, FolderPath
| order by TimeGenerated asc
```

**What I found / narrative:**  
Processes originating from Downloads folders were seen across multiple hosts. The earliest obvious script write and execution I found was on gab-intern-vm — an intern-operated VM consistent with the starting intel. This host anchors the timeline and is the logical hunting start point.

**Evidence:**  
![Flag0](images/0.png)

---

### Flag 1 — Initial Execution Detection (Execution parameter)
**Objective:** Initial execution parameter used during suspicious program execution  
**Flag:** -ExecutionPolicy

**KQL (Process pivot):**
```kusto
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:00:00Z) .. datetime(2025-10-09T13:00:00Z))
| where ProcessCommandLine contains "-ExecutionPolicy"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessAccountName
| order by TimeGenerated asc
```

**What I found / narrative:**  
I detected a PowerShell invocation that explicitly included `-ExecutionPolicy Bypass`, which bypasses local execution policy restrictions and is commonly used by operators to run scripts without changing local policy settings permanently.

**Evidence:**  
![Flag1](images/1.png)

---

### Flag 2 — Defense Disabling (Artifact tampering)
**Objective:** Defender tamper artifact  
**Flag:** DefenderTamperArtifact.lnk

**KQL (LNK discovery):**
```kusto
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where FileName endswith ".lnk" and FolderPath has "Shortcuts" or FolderPath has "Recent"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
```

**What I found / narrative:**  
A `.lnk` shortcut named DefenderTamperArtifact.lnk was created in a user-accessible area. The presence of a manually-accessed shortcut suggests an attempt to obscure or hand-off execution logic; treat such artifacts as indicators of intent to tamper even if Defender configuration does not show permanent changes.

**Evidence:**  
![Flag2](images/2.png)
<br>

![Flag15](images/2a.png)

---

### Flag 3 — Quick Data Probe (Clipboard access)
**Objective:** Quick clipboard probe  
**Flag:** powershell.exe -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"

**KQL (Clipboard probe):**
```kusto
DeviceProcessEvents
| where DeviceName == "gab-intern-vm" and FileName == "powershell.exe"
| where ProcessCommandLine contains "Get-Clipboard" or ProcessCommandLine contains "Get-Clipboard -"
| project TimeGenerated, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessAccountName
| order by TimeGenerated asc
```

**What I found / narrative:**  
I observed a short-lived PowerShell process invoking `Get-Clipboard`. Clipboard reads are noisy but transient — they can capture tokens, URLs, or credentials that a user recently copied, making them a high-value quick probe for an operator.

**Evidence:**  
![Flag3](images/3.png)

---

### Flag 4 — Host Context Recon (timestamp)
**Objective:** Recon timestamp  
**Flag:** 2025-10-09T12:51:44.3425653Z

**What I found / narrative:**  
This precise timestamp anchors a sequence of reconnaissance commands I used to pull surrounding telemetry (parent process, subsequent file writes). Use it as a pivot to query ±2 minutes for adjacent activities (clipboard checks, netstat-like calls, and tasklist snapshots).

**Evidence:**  
![Flag4](images/4.png)

---

### Flag 5 — Storage Surface Mapping
**Objective:** Storage mapping command  
**Flag:** cmd.exe /c wmic logicaldisk get name,freespace,size

**KQL (Storage mapping):**
```kusto
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "wmic logicaldisk get name"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessAccountName
| order by TimeGenerated asc
```

**What I found / narrative:**  
I observed a `wmic logicaldisk` invocation that enumerated drive letters and free space. This is consistent with an operator mapping the host’s storage surface and deciding where to stage or collect data.

**Evidence:**  
![Flag5](images/5.png)

---

### Flag 6 — Connectivity & Name Resolution Check
**Objective:** Parent process (session check)  
**Flag:** RuntimeBroker.exe

**KQL (Parent process / session probe):**
```kusto
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessFileName == "RuntimeBroker.exe" or ProcessCommandLine contains "nslookup" or ProcessCommandLine contains "ipconfig"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

**What I found / narrative:**  
The initiating parent process matched RuntimeBroker.exe, suggesting the operator either leveraged an existing session agent or invoked functionality that looked like a session check. This aligns with a session visibility probe prior to collection attempts.

**Evidence:**  
![Flag6](images/6.png)

---

### Flag 7 — Interactive Session Discovery
**Objective:** Initiating process unique ID  
**Flag:** 2533274790397065

**KQL (Session discovery):**
```kusto
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessId == 2533274790397065 or ProcessCommandLine contains "query user" or ProcessCommandLine contains "qwinsta"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessId, InitiatingProcessAccountName
| order by TimeGenerated asc
```

**What I found / narrative:**  
I extracted an initiating process ID tied to an interactive-session check. The presence of session enumeration commands supports the idea that the operator wanted to know who was logged in and whether it was safe to perform noisy actions.

**Evidence:**  
![Flag7](images/7.png)

---

### Flag 8 — Runtime Application Inventory
**Objective:** Runtime application inventory  
**Flag:** tasklist.exe

**KQL (Process inventory):**
```kusto
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where FileName in ("tasklist.exe","tasklist.exe")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

**What I found / narrative:**  
I observed `tasklist.exe` snapshots that captured running processes. These quick inventories are useful for avoiding noisy or protected processes and identifying candidate artifacts for collection.

**Evidence:**  
![Flag8](images/8.png)

---

### Flag 9 — Privilege Surface Check
**Objective:** Privilege mapping timestamp  
**Flag:** 2025-10-09T12:52:14.3135459Z

**KQL (Privilege checks):**
```kusto
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "whoami" or ProcessCommandLine contains "net user" or ProcessCommandLine contains "qwinsta"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessAccountName
| order by TimeGenerated asc
```

**What I found / narrative:**  
This timestamp marks the earliest privilege-mapping attempts I found. Privilege context informed the operator’s next steps and indicated whether elevation attempts were necessary.

**Evidence:**  
![Flag9](images/9.png)

---

### Flag 10 — Proof-of-Access & Egress Validation
**Objective:** Connectivity check / C2 probe  
**Flag:** www.msftconnecttest.com

**KQL (Connectivity checks / outbound):**
```kusto
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where RemoteUrl has "msftconnecttest" or RemoteIP in ("100.29.147.161","185.92.220.87")
| project TimeGenerated, RemoteIP, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**What I found / narrative:**  
The host contacted `www.msftconnecttest.com` — a common connectivity probe used by systems but also abused by operators to test outbound reachability without raising immediate suspicion. I used the surrounding telemetry to find simultaneous evidence of screenshots and data-gathering that suggest proof‑of‑access activity.

**Evidence:**  
![Flag10](images/10.png)

---

### Flag 11 — Bundling / Staging Artifacts
**Objective:** Data staging location  
**Flag:** C:\Users\Public\ReconArtifacts.zip

**KQL (Staging detection):**
```kusto
DeviceFileEvents
| where DeviceName == "gab-intern-vm" and FileName has "ReconArtifacts" or FileName endswith ".zip"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
```

**What I found / narrative:**  
I observed a zip archive created in C:\Users\Public. Staging in a public folder simplifies later retrieval and is a strong indicator of preparation for exfiltration.

**Evidence:**  
![Flag11](images/11.png)

---

### Flag 12 — Outbound Transfer Attempt (Simulated)
**Objective:** Outbound destination (simulated upload)  
**Flag:** 100.29.147.161

**KQL (Outbound upload destination):**
```kusto
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where RemoteIP == "100.29.147.161" or RemoteUrl contains "httpbin" or RemoteUrl contains "upload"
| project TimeGenerated, RemoteIP, RemoteUrl, InitiatingProcessFileName, ProcessCommandLine
| order by TimeGenerated asc
```

**What I found / narrative:**  
I observed outbound attempts to 100.29.147.161 (simulated upload). Even if the transfer failed, the attempt is proof of intent and reveals possible egress vectors to block or monitor.

**Evidence:**  
![Flag12](images/12.png)

---

### Flag 13 — Scheduled Re‑Execution Persistence
**Objective:** Scheduled task persistence  
**Flag:** SupportToolUpdater

**KQL (Scheduled task detection):**
```kusto
DeviceProcessEvents
| where DeviceName == "gab-intern-vm" and ProcessCommandLine contains "schtasks" or FileName contains "schtasks.exe"
| project TimeGenerated, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

**What I found / narrative:**  
I found evidence of a scheduled task named SupportToolUpdater. This provides the actor a way to re-run their tooling without interactive access, extending the threat window beyond the initial session.

**Evidence:**  
![Flag13](images/13.png)

---

### Flag 14 — Autorun Fallback Persistence
**Objective:** Registry autorun fallback  
**Flag:** RemoteAssistUpdater

**KQL (Registry autorun detection):**
```kusto
DeviceRegistryEvents
| where DeviceName == "gab-intern-vm"
| where RegistryKey contains "Run" and RegistryValueName contains "RemoteAssistUpdater"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```

**What I found / narrative:**  
A registry Run key named RemoteAssistUpdater was present as a fallback persistence mechanism. Redundant persistence increases resilience and should be removed and monitored.

**Evidence:**  
![Flag14](images/14.png)

---

### Flag 15 — Planted Narrative / Cover Artifact
**Objective:** Planted narrative / cover artifact  
**Flag:** SupportChat_log.lnk

**KQL (Cover artifact detection):**
```kusto
DeviceFileEvents
| where DeviceName == "gab-intern-vm" and FileName has "SupportChat" or FileName has "SupportChat_log"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
```

**What I found / narrative:**  
An explanatory file (SupportChat_log.lnk) was left near the time of suspicious actions. The artifact appears timed to justify the operator’s activities — a classic example of narrative control. Focus on timing and parent processes rather than accepting the content at face value.

**Evidence:**  
I first queried `DeviceFileEvents` for `.txt`, `.docx`, and `.pdf` files created during attacker activity and surfaced `SupportChat_log.txt`, which appeared to be a user-facing artifact opened via Notepad. 

![Flag15](images/15a.png)
<br>

When submitting that filename returned an error “Almost… but not quite,” I realized the challenge was rejecting the visible file and likely pointing to a disguised or alternate version. 

![Flag15](images/15aa.png)
<br>

Expanding the query to include other extensions including `.lnk` files revealed `SupportChat_log.lnk` — a shortcut opened from the Recent folder — confirming it as the true planted narrative artifact.

![Flag15](images/15b.png)

---

## 🧭 Analyst Reasoning & Logical Flow

0 → 1: An unfamiliar script surfaced in the user’s Downloads directory. I confirmed SupportTool.ps1 as the likely entry vector.  
1 → 2: Initial execution with bypass suggested an attempt to avoid local policy restrictions; I looked for tamper indicators.  
2 → 3: With protections probed, I searched for quick data checks like clipboard reads that might yield ready-to-use secrets.  
3 → 4: I expanded to system-level reconnaissance and captured timestamps needed to pivot into surrounding telemetry.  
4 → 5: I verified storage mapping to determine suitable staging locations and assessed free space to pick likely targets.  
5 → 6: I checked network posture and DNS resolution to ensure egress would be feasible.  
6 → 7: I enumerated sessions to find interactive users that might be monitored or targeted.  
7 → 8: I collected a runtime inventory to see what processes were running and which could be exploited or avoided.  
8 → 9: I checked privileges to determine whether elevation would be required for collection.  
9 → 10: I correlated outbound checks with evidence of capture to identify proof-of-access and early exfil attempts.  
10 → 11: I found staged artifacts placed in public folders for later retrieval.  
11 → 12: I observed outbound attempts to a remote endpoint used for simulated uploads.  
12 → 13: I identified scheduled tasks that would re-run the tooling.  
13 → 14: I found a registry Run key as a fallback.  
14 → 15: I discovered a planted support log left as a narrative cover.

---

## ✅ Recommended Immediate Actions

1. Remove scheduled task `SupportToolUpdater` and the `RemoteAssistUpdater` Run key. Investigate the creator account and associated timestamps.  
2. Quarantine `gab-intern-vm` and collect a full host forensic image for deeper analysis. (If quarantine is not possible, collect EDR forensic snapshots.)  
3. Search for other instances of `SupportTool.ps1` across endpoints and take action on any discovered artifacts.  
4. Monitor file creation in `C:\Users\Public` and alert on `.zip` creations or unusual owner accounts.  
5. Block or monitor connections to `100.29.147.161` and similar endpoints; surface and hunt for `msftconnecttest` anomalies.  
6. Implement detection rules for short-lived `Get-Clipboard` calls, parent-process correlation, and `-ExecutionPolicy` usage in PowerShell invocations.

---

## 📎 Appendix

- Key KQL snippets are included inline above for rapid reuse.  
- Image placeholders reference `images/flag#.png` and will render once you add your images to the `images` folder.  
- If you want, I can generate a polished PDF export or push this file into your repo under `/remote-support-backdoor/README.md`.

---

*Report complete.*

# 🔍 Suspicious Insider Exfiltration Attempt

## 🧭 Investigation Scenario
**Context:** An employee named *John Doe*, recently placed on a performance improvement plan (PIP), displayed hostile behavior. Management suspects John may attempt to steal proprietary company data. As a security analyst, my goal was to investigate John’s actions on his assigned device (`pvr-hunting`) using Microsoft Defender for Endpoint (MDE).

### 🎯 Hypothesis
Given John’s elevated privileges, he may:
- Compress sensitive data
- Exfiltrate it to a cloud drive or external destination

---

## 📊 Step 1: File Archiving Detection
Starting with the data archiving hypothesis, this step identifies the creation of ZIP files on the target system, focusing on filenames that suggest potential staging of sensitive data. By querying DeviceFileEvents and filtering by .zip extensions, I began to establish a baseline of archiving activity and flag any anomalies for further investigation:

```kql
DeviceFileEvents
| where DeviceName == "pvr-hunting"
| where FileName endswith ".zip"
| order by Timestamp desc 
```

![ZIP File Creation Event](images/zipDeviceFileEvents1.png)

I found a ZIP archive that was created with a name matching a sensitive dataset: `employee-data-20250527135920.csv`. This initial finding confirms that file archiving activity occurred and helps anchor my timeline for deeper investigation into related processes and network behavior.

---

## 🧮 Step 2: Process Timeline Correlation
Using the ZIP file's creation time (`2025-05-27T13:59:31Z`), I then searched for correlated processes within ±1 minute using the DeviceProcessEvents table:

```kql
let specificTime = datetime(2025-05-27T13:59:31.421716Z);
let VMName = "pvr-hunting";
DeviceProcessEvents
| where Timestamp between ((specificTime - 1m) .. (specificTime + 1m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

```

![Timeline of PowerShell and Zip Activity](images/Query2rev2.png)

This query establishes the timeline of processes running on the endpoint around the time of the suspicious ZIP archive creation. By narrowing the window to one minute before and after the .zip archive event, I begin to reveal a chain of activity that involved a powershell scipt silently install 7zip and used it to archive employee data. This step is critical to correlating user actions with file manipulation and prepares the foundation for identifying potential exfiltration behavior.
<br>

---
## 🎯 Step 3: Isolating Key Processes

After identifying the ZIP file creation and surrounding activity, this step focuses on three key processes likely involved in data staging or exfiltration. By filtering for powershell.exe, 7z.exe, and 7z2408-x64.exe, I isolate the tools used to script actions, install utilities, and compress data — revealing the attacker’s method and intent.

```kql
DeviceProcessEvents
| where Timestamp between ((specificTime - 1m) .. (specificTime + 1m))
| where DeviceName == VMName
| where FileName in ("powershell.exe", "7z.exe", "7z2408-x64.exe")
| project Timestamp, DeviceName, ActionType, FileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

![Command Line Activity of Involved Processes](images/ProcessesIsolated3.png)

The event sequence confirms a tightly coupled execution chain: scripting via PowerShell, installation of 7-Zip, and compression using 7z.exe. This coordinated flow strengthens the case for an intentional data staging and exfiltration attempt.

---

## 🌐 Step 4: Suspicious Network Connection
To assess potential exfiltration, this step investigates outbound network activity originating from the same system and timeframe. The presence of an HTTPS connection to raw.githubusercontent.com — a domain commonly used for script delivery and covert data transfer — provides a strong indication of command-and-control communication or data exfiltration using web protocols:

```kql
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == "pvr-hunting"
| where RemoteIP == "185.199.111.133"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

![PowerShell Establishing Connection to Github's Raw Content Delivery Network](images/PossibleDataExfil4.png)

The outbound HTTPS connection to GitHub’s raw content delivery domain strongly suggests a channel was established for data exfiltration or remote command retrieval.

---

## 🧠 MITRE ATT&CK Mappings

| Technique ID | Technique Name | Explanation |
|--------------|----------------|-------------|
| **T1560.001** | Archive Collected Data: Archive via Utility | `7z.exe` used to compress sensitive data, preparing it for exfiltration. |
| **T1048** | Exfiltration Over Alternative Protocol | Evidence suggests potential use of HTTPS to GitHub for data transfer. |
| **T1059.001** | Command and Scripting Interpreter: PowerShell | PowerShell with `-ExecutionPolicy Bypass` used for automation and execution of exfiltration scripts. |
| **T1071.001** | Application Layer Protocol: Web Protocols | PowerShell communicating over HTTPS to `raw.githubusercontent.com`. |
| **T1070.004** | Indicator Removal on Host: File Deletion | Although not explicitly shown, attackers often delete staging files after exfil — worth deeper inspection. |
| **T1027** | Obfuscated Files or Information | Use of compressed `.zip` files to conceal contents during transfer. |
| **T1105** | Ingress Tool Transfer | Silent install of `7z2408-x64.exe`, likely downloaded from a public source. |

---

## ✅ Summary of Findings
- 📦 Confirmed creation of an archive containing sensitive employee data.
- 💻 Correlated PowerShell script installation and use of `7z.exe`.
- 🌍 Verified outbound connection to GitHub's CDN within minutes of archiving.
- 🧾 Commands and behavior align with known MITRE ATT&CK techniques.

## 🔧 Recommendations

I forwarded the findings to management and recommended expanding the scope of the investigation to capture other data exfiltration incidents associated with this user (USB exfil, malware delivery, etc.). I also recommended the following:

- Immediately isolate the system.
- Consider implementing alerts for excessive .zip activity.
- Escalate the incident to the Incident Response (IR) team.
- Preserve evidence: scripts, command lines, ZIP files, and timelines.
- Audit similar behavior across other endpoints.

---

## 🔁 Process Improvements
- 🚫 Block unauthorized scripting and compression utilities.
- 🕵️‍♂️ Enable alerting on archive creation + outbound HTTPS events to unknown IPs.
- 📉 Limit user permissions on sensitive systems.
- 🔄 Incorporate this hunting pattern into automated detection rules.

---

> 👤 **Analyst Note:**  
> This lab demonstrated how file creation, process command lines, and network telemetry can be correlated to detect and confirm malicious insider activity.

# 🕵️‍♂️ Threat Hunting Lab: Zero-Day Ransomware (PwnCrypt) Outbreak

## 🧪 Investigation Scenario

### 🔐 Goal:
Investigate a newly discovered ransomware strain known as **PwnCrypt**. This strain uses a PowerShell-based payload to encrypt files on infected systems, prepending `.pwncrypt` to the original file extensions. For example, `hello.txt` becomes `hello.pwncrypt.txt`.

The CISO has raised concerns about potential spread within the corporate environment due to immature defenses and lack of user training. Your task is to determine whether the ransomware has affected any systems, how it was delivered, and whether it established persistence.

---

## 🔬 1. Preparation

- **Objective:** Define hunting hypotheses based on known IoCs and threat intelligence.
- **Threat Hypothesis:** PwnCrypt ransomware may have infiltrated the network via user execution of PowerShell-based droppers. Known indicators include:
  - `.pwncrypt.` in filenames
  - Scripts like `pwncrypt.ps1`
  - Usage of `Invoke-WebRequest`, `ExecutionPolicy Bypass`, etc.

---

## 📥 2. Data Collection

- **Target Tables:**
  - `DeviceProcessEvents`
  - `DeviceFileEvents`
- **Goal:** Confirm these tables contain logs for the timeframe around suspicious activity.

---

## 📊 3. Data Analysis

### 🔎 Check for IoC Matches in File System
```kql
let VMName = "pvr-hunting2";
DeviceFileEvents
| where DeviceName == VMName
| where FileName contains "pwncrypt"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### 🖼️ File Discovery via DeviceFileEvents
![File Discovery via DeviceFileEvents](./images/1.png)

---

### 📆 Timeline Analysis of Known Execution Time
```kql
let VMName = "windows-target-1";
let specificTime = datetime(2024-10-16T05:24:46.8334943Z);
DeviceProcessEvents
| where DeviceName == VMName
| where Timestamp between ((specificTime - 3m) .. (specificTime + 3m))
| order by Timestamp desc
```

### 🖼️ Timeline Analysis of Process Activity
![Timeline Analysis of Process Activity](./images/2.png)

---

### 🧹 Focused Hunt to Reduce Noise
```kql
let VMName = "pvr-hunting2";
let specificTime = datetime(2025-05-28T20:20:14.5912032Z);
DeviceProcessEvents
| where DeviceName == VMName
| where Timestamp between ((specificTime - 3m) .. (specificTime + 3m))
| where FileName endswith ".exe" or FileName endswith ".ps1"
    or ProcessCommandLine has_any ("pwncrypt", "bypass", "Invoke-WebRequest", "DownloadString", "Base64", "-EncodedCommand")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, FolderPath, AccountName
| order by Timestamp desc
```

### 🖼️ Focused Process Filtering Around IOC Time
![Focused Process Filtering Around IOC Time](./images/3.png)

---

## 🔥 Ransomware Execution Chain Identified

### 🧩 Key Malicious Sequence

| Time (UTC)  | Process Chain            | Command Summary                                              |
|-------------|---------------------------|--------------------------------------------------------------|
| 13:20:14    | `cmd.exe` → `powershell.exe` | `Invoke-WebRequest` downloads `pwncrypt.ps1` from GitHub     |
| 13:20:17    | `powershell.exe`         | `-ExecutionPolicy Bypass -File C:\programdata\pwncrypt.ps1` |

✅ This confirms download & execution of the ransomware payload.

---

## 🚨 Malicious Events to Prioritize

| Time       | Process           | Detail                                                 | Meaning                                |
|------------|-------------------|---------------------------------------------------------|----------------------------------------|
| 13:20:14   | powershell.exe     | `Invoke-WebRequest -Uri https://...pwncrypt.ps1`        | 🚨 Script downloaded                    |
| 13:20:17   | powershell.exe     | `-ExecutionPolicy Bypass -File pwncrypt.ps1`            | 🚨 Ransomware executed                  |
| 13:20:13   | powershell.exe     | `-ExecutionPolicy Unrestricted -File script0.ps1`       | ⚠️ Possibly a test/staging script       |

💡 This matches `DeviceFileEvents` activity where `.pwncrypt` files were created shortly after execution.

---

## 📂 4. Confirm File Impact (Trace from pwncrypt.ps1)

```kql
let VMName = "pvr-hunting2";
DeviceFileEvents
| where DeviceName == VMName
| where InitiatingProcessCommandLine has "pwncrypt.ps1"
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### 🖼️ File Impact Traced from pwncrypt.ps1
![File Impact Traced from pwncrypt.ps1](./images/4.png)

---

## 🗂️ Ransomware Execution Timeline

**Host:** `pvr-hunting2`

- 🔹 **13:20:14 UTC** – `powershell.exe` downloads `pwncrypt.ps1`
- 🔹 **13:20:17 UTC** – Execution via `ExecutionPolicy Bypass`
- 🔹 **13:20:30+ UTC** – Files encrypted with `_pwncrypt.csv` suffix
- 🔹 **Files Dropped to Desktop:**
  - `3698_EmployeeRecords_pwncrypt.csv`
  - `8955_CompanyFinancials_pwncrypt.csv`
  - `9543_ProjectList_pwncrypt.csv`
  - `________decryption-instructions` (ransom note)
- 🔹 **Process Chain:** `cmd.exe` → `powershell.exe`
- 🔹 **Affected Files:** EmployeeRecords, ProjectList, CompanyFinancials

---

## 🔍 5. Scan for Ransom Note Dropping Behavior

```kql
DeviceFileEvents
| where DeviceName == "pvr-hunting2"
| where FileName has "decrypt" or FileName contains "instruction"
| project Timestamp, FolderPath, FileName, InitiatingProcessFileName
```

### 🖼️ Scan for Dropped Ransom Notes
<!--![Scan for Dropped Ransom Notes](./images/5.png)--->

✅ **Confirmed:** Ransom note file named `________decryption-instructions` was dropped on the desktop alongside encrypted files.

---

## 🧩 MITRE ATT&CK Mapping

| Technique | ID | Description |
|----------|----|-------------|
| **Command and Scripting Interpreter: PowerShell** | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Execution of malicious PowerShell scripts (`pwncrypt.ps1`) via `Invoke-WebRequest` and `-ExecutionPolicy Bypass`. |
| **Ingress Tool Transfer** | [T1105](https://attack.mitre.org/techniques/T1105/) | Use of `Invoke-WebRequest` to download payload from GitHub. |
| **User Execution** | [T1204](https://attack.mitre.org/techniques/T1204/) | Likely user-initiated execution of the PowerShell script via `cmd.exe`. |
| **Data Encrypted for Impact** | [T1486](https://attack.mitre.org/techniques/T1486/) | Encryption of files on disk using ransomware payload. |
| **Masquerading** | [T1036](https://attack.mitre.org/techniques/T1036/) | Ransomware script possibly disguised as a generic PowerShell file in `ProgramData`. |
| **Execution Guardrails** | [T1480.001](https://attack.mitre.org/techniques/T1480/001/) | Use of `-ExecutionPolicy Bypass` to evade policy controls. |

---

## 📌 Conclusion & Lessons Learned

### ✅ Summary of Findings:
- **Confirmed**: Download and execution of `pwncrypt.ps1`
- **Detected**: File encryption events post-execution
- **Confirmed**: Ransom note dropped to desktop
- **Delivery Method**: PowerShell from `cmd.exe` with bypass flag
- **No Persistence**: No evidence of registry or scheduled task persistence

---

## 🛡️ 6. Response

- 🔒 Isolate the endpoint from the network
- 📤 Export artifacts and commands used
- 🧼 Remediate: Remove `pwncrypt.ps1`, decrypt if possible, and harden PowerShell usage

---

## 🔁 7. Improvement Recommendations

- 🚧 Disable or tightly restrict PowerShell execution for standard users
- 📊 Enable comprehensive logging across endpoints (Defender for Endpoint telemetry)
- 🧑‍🏫 Conduct user training to spot social engineering or suspicious files
- 🔐 Apply allowlisting (AppLocker or WDAC) to limit script execution
- ⚙️ Consider EDR rules for `Invoke-WebRequest` + `ExecutionPolicy Bypass` detection combo

---

> 🧠 **Reflection:** This lab reinforces the importance of endpoint visibility, command-line logging, and early detection of file encryption behavior. Dropped artifacts — like the desktop ransom note — offer strong indicators for rapid triage and containment.
